
"""
##################################################################
# Created By: Kobie Hazon                                        #
# Date: 04/05/2017                                               #
# Name: SendRecieve                                              #
# Version: 1.0                                                   #
# Linux Tested Versions: Centos 7 64 bit                         #
# Python Tested Versions: 2.7.10 32-bit                          #
# Python Environment  : PyCharm 2017.1.1                         #
##################################################################
"""

from scapy.all import *
from IpHandler import *
from IcmpHandler import *
from TcpHandler import *
from UdpHandler import *
from scapy.layers.inet import Ether, IP, ICMP, TCP, Raw, UDP
from scapy.layers.dns import *


class PortManager:

    def __init__(self):
        self.PortAr = [True for i in range(55500)]

    def get_open_port(self):
        for i in range(55500):
            if self.PortAr[i]:
                self.PortAr[i] = False
                return i + 1000

    def print_all_open(self):
        print "~~~~~~~"
        for i in range(55500):
            if self.PortAr[i]:
                print i + 1000


def send_icmp(pkt):
    sendp(Ether(dst=get_dst_mac(pkt)) / IP(dst=get_dst_adr(pkt), ttl=get_ttl(pkt), id=int(get_ip_id(pkt), 16)) /
          ICMP(type=icmp_type(pkt), id=get_icmp_id(pkt), seq=get_icmp_sq_num(pkt)) / Raw(load=pkt[42:]),
          verbose=False)


def send_tcp(pkt):
    sendp(Ether(dst=get_dst_mac(pkt)) /
          IP(src=get_src_adr(pkt), dst=get_dst_adr(pkt), ttl=(get_ttl(pkt)), id=int(get_ip_id(pkt), 16), flags='DF') /
          TCP(sport=get_src_port(pkt), dport=get_dst_port(pkt), seq=get_tcp_sq_num(pkt), ack=get_ack_num(pkt),
              flags=get_tcp_flags(pkt), options=get_tcp_options(pkt), window=get_window_size(pkt)) /
          Raw(load=get_tcp_raw_load(pkt).decode('unicode_escape')), verbose=False)


def send_udp(pkt):
    x = dns_forward(pkt)
    sendp(x, iface='eth1', verbose=False)


def summary_dump(pkt):
    return Ether(pkt).summary()


def get_type(pkt):
    if ord(pkt[23]) == 1:
        return 'ICMP'
    elif ord(pkt[23]) == 6:
        return 'TCP'
    elif ord(pkt[23]) == 17:
        return 'UDP'
