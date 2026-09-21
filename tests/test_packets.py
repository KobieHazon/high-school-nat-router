"""Real Scapy packets and NAT state in an offline, unprivileged Linux container."""
import os
import socket
import sys
import unittest
import new

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), 'src'))
import Main
import SendRecieve
from scapy.all import Ether, IP, TCP, UDP, ICMP, DNS, DNSQR, Raw
from scapy.utils import checksum
ARP_CACHE_CLASS = Main.ARPCache


class PacketTests(unittest.TestCase):
    def setUp(self):
        Main.InterfaceList = ['lo', 'wan', 'lan']
        Main.get_inf_ip = lambda interface: {'wan': '10.8.8.1', 'lan': '10.10.10.1'}[interface]
        Main.get_inf_mac = lambda interface: {'wan': '02:00:00:00:00:01', 'lan': '02:00:00:00:00:02'}[interface]
        # Fixed lab neighbors replace only interface/ARP discovery, not the NAT implementation.
        cache = new.instance(ARP_CACHE_CLASS)
        cache.mac_adr = {'10.8.8.2': '02:00:00:00:00:03', '10.10.10.2': '02:00:00:00:00:04', '10.10.10.3': '02:00:00:00:00:05'}
        Main.ARPCache = cache
        Main.TcpTable = Main.TcpNat()
        Main.UdpTable = Main.UdpNat()
        self.sent = []
        self.original_sendp = SendRecieve.sendp
        SendRecieve.sendp = lambda packet, **kwargs: self.sent.append(Ether(str(packet)))

    def tearDown(self):
        SendRecieve.sendp = self.original_sendp

    def test_udp_outbound_reply_and_state_cleanup(self):
        request = Ether()/IP(src='10.10.10.2', dst='10.8.8.2')/UDP(sport=12345, dport=53)/DNS(id=42, qd=DNSQR(qname='example.test'))
        outgoing = Main.packet_manipulator(str(request))
        translated = Ether(outgoing)
        self.assertEqual(translated[IP].src, '10.8.8.1')
        self.assertNotEqual(translated[UDP].sport, 12345)
        SendRecieve.send_udp(outgoing)
        self.assertEqual(self.sent[-1][DNS].id, 42)
        reply = Ether()/IP(src='10.8.8.2', dst='10.8.8.1')/UDP(sport=53, dport=translated[UDP].sport)/DNS(id=42, qr=1, qd=DNSQR(qname='example.test'))
        incoming = Ether(Main.packet_manipulator(str(reply)))
        self.assertEqual((incoming[IP].dst, incoming[UDP].dport), ('10.10.10.2', 12345))
        self.assertEqual(Main.UdpTable.get_src_ip_port(translated[UDP].sport), 0)

    def test_distinct_clients_do_not_share_port_mapping(self):
        ports = []
        for client in ('10.10.10.2', '10.10.10.3'):
            request = Ether()/IP(src=client, dst='10.8.8.2')/TCP(sport=23456, dport=80, flags='S', seq=7)
            outgoing = Main.packet_manipulator(str(request))
            translated = Ether(outgoing)
            ports.append(translated[TCP].sport)
            SendRecieve.send_tcp(outgoing)
            rebuilt = self.sent[-1]
            self.assertEqual(rebuilt[TCP].seq, 7)
            self.assertEqual(checksum(str(rebuilt[IP])[:20]), 0)
            reply = Ether()/IP(src='10.8.8.2', dst='10.8.8.1')/TCP(sport=80, dport=ports[-1], flags='SA', seq=9, ack=8)
            incoming = Ether(Main.packet_manipulator(str(reply)))
            self.assertEqual((incoming[IP].dst, incoming[TCP].dport), (client, 23456))
        self.assertNotEqual(ports[0], ports[1])

    def test_icmp_sender_preserves_translated_source_and_payload(self):
        packet = Ether(src='02:00:00:00:00:01', dst='02:00:00:00:00:03')/IP(src='10.8.8.1', dst='10.8.8.2')/ICMP(id=42, seq=3)/Raw(load='echo-payload')
        SendRecieve.send_icmp(str(packet))
        rebuilt = self.sent[-1]
        self.assertEqual(rebuilt[IP].src, '10.8.8.1')
        self.assertEqual(rebuilt[Ether].src, '02:00:00:00:00:01')
        self.assertEqual(rebuilt[Raw].load, 'echo-payload')
        self.assertEqual(checksum(str(rebuilt[IP])[:20]), 0)


if __name__ == '__main__':
    unittest.main()
