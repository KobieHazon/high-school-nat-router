
"""
##################################################################
# Created By: Kobie Hazon                                        #
# Date: 04/05/2017                                               #
# Name: Main                                                     #
# Version: 1.0                                                   #
# Linux Tested Versions: Centos 7 64 bit                         #
# Python Tested Versions: 2.7.10 32-bit                          #
# Python Environment  : PyCharm 2017.1.1                         #
##################################################################
"""

import socket
import os
import Queue
import time
from subprocess import PIPE, Popen
import threading
from LoggingSystem import *
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from SendRecieve import *
from NATmonitor import *


class ARPCache:  # Responsible for starting the ARP Cache and Managing it.

    def __init__(self):
        self.mac_adr = {}
        self.self_check()
        self.initiallize_arp()

    def initiallize_arp(self):
        print "Initiallizing...\n"
        for ip in range(1, 3):
            for subnet in range(0, 2):
                if subnet == 0:
                    process = subprocess.Popen(["ping", "-c", "1", "10.10.10." + str(ip)], stdout=subprocess.PIPE)
                    process.wait()
                else:
                    process = subprocess.Popen(["ping", "-c", "1", "10.8.8." + str(ip)], stdout=subprocess.PIPE)
                    process.wait()

        print "Started."
        logging.debug('ARP Cache started successfully')

    def self_check(self):  # Loads the values of the two web interfaces to the ARP Cache
        self.mac_adr[get_inf_ip(InterfaceList[2])] = get_inf_mac(InterfaceList[2])
        self.mac_adr[get_inf_ip(InterfaceList[1])] = get_inf_mac(InterfaceList[1])

    def update_cache(self, ip, mac):  # Updates ARP Cache with given values
        self.mac_adr[ip] = mac

    def is_present(self, ip):
        if ip in self.mac_adr:
            return True
        else:
            return False

    def add_ip_to_arp(self, ip):  # Add Value to ARP Cache by ip, works by console
        pid = Popen(["arp", "-n", ip], stdout=PIPE)
        s = pid.communicate()[0]
        self.update_cache(ip, re.search(r"(([a-f\d]{1,2}\:){5}[a-f\d]{1,2})", s).groups()[0])

    def return_value(self, ip):  # Returns the mac address with given IP
        if ip in self.mac_adr:
            return self.mac_adr[ip]
        else:
            self.add_ip_to_arp(ip)
            return self.mac_adr[ip]

    def print_cache(self):  # Prints the content of ARP Cache Dictionary
        for key, value in self.mac_adr.items():
            print "-->" + key
            print value


class IPSniff(threading.Thread):  # Responsible for sniffing packet arriving to given interface
    def __init__(self, interface_name, sniff_func):
        threading.Thread.__init__(self)

        self.interface_name = interface_name
        self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_IP))
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2 ** 30)
        self.socket.bind((self.interface_name, ETH_P_IP))

        self.my_mac = [get_if_hwaddr(i) for i in get_if_list()]
        self.func_to_run = sniff_func

    def receive_raw_packets(self):  # Recieves raw packets arriving at the given interface using socket module
        while True:
            pkt, dummy = self.socket.recvfrom(MTU)
            if len(pkt) > 0:
                try:
                    if self.interface_name == InterfaceList[2]:
                        if self.if_in_project(self.interface_name, pkt):
                            logging.debug("%s interface recieved packet: \n%s", self.interface_name, summary_dump(pkt))
                            gui_entry('Incoming', gui_parse(pkt))
                            if not ARPCache.is_present(get_src_adr(pkt)):
                                ARPCache.update_cache(get_src_adr(pkt), get_src_mac(pkt))
                            ArrivedPackets.put(pkt)
                    else:
                        if self.if_in_project(self.interface_name, pkt):
                            logging.debug("%s interface recieved packet: \n%s", self.interface_name, summary_dump(pkt))
                            gui_entry('Incoming', gui_parse(pkt))
                            if not ARPCache.is_present(get_src_adr(pkt)):
                                ARPCache.update_cache(get_src_adr(pkt), get_src_mac(pkt))

                            ReturnedPackets.put(pkt)
                except Exception, message:
                    log.error(message)

    def run(self):
        getattr(self, self.func_to_run)()

    def if_in_project(self, interface, pkt):  # Checks if given IP is within the test conditions of the project
        pkt = str(pkt)
        if interface == InterfaceList[2]:
            if get_src_adr(pkt)[:8] == '10.10.10' and \
                    (get_dst_adr(pkt)[:8] == '10.10.10' or get_dst_adr(pkt)[:6] == '10.8.8'):
                return True
        elif interface == InterfaceList[1]:
            if get_src_adr(pkt)[:6] == '10.8.8' and \
                    (get_dst_adr(pkt)[:8] == '10.10.10' or get_dst_adr(pkt)[:6] == '10.8.8'):
                return True
        return False

    def sniff_packets_scapy(self):  # Scapy sniffing method: NOT USED!
        sniff(iface="eth0", lfilter=self.scapy_filter(), prn=lambda x: PacketList.append(x))

    def scapy_filter(self, pkt):  # Scapy filter for scapy sniffer: NOT USED!
        return pkt[Ether].src != [get_if_hwaddr(i) for i in get_if_list()]


class PacketSender(threading.Thread):  # Responsible for sending out the waiting-in-line packets for given interface

    def __init__(self, interface_name):
        threading.Thread.__init__(self)
        self.interface_name = interface_name
        self.func_to_run = 'send_packets'

    def run(self):
        getattr(self, self.func_to_run)()

    def send_packets(self):  # Sends out packets waiting in the given interface
        if self.interface_name == InterfaceList[2]:
            while True:
                try:
                    if not ArrivedPackets.empty():
                        pkt = ArrivedPackets.get()
                        if ord(pkt[23]) == 1:
                            ICMPNat.add_packet(pkt)
                        pkt = packet_manipulator(pkt)
                        if pkt != '':
                            logging.debug('Interface %s sent packet: \n%s', self.interface_name, summary_dump(pkt))
                            gui_entry('Outgoing', gui_parse(pkt))
                            if ord(pkt[23]) == 1:
                                send_icmp(pkt, iface=InterfaceList[1])
                            elif ord(pkt[23]) == 6:
                                send_tcp(pkt, iface=InterfaceList[1])
                            elif ord(pkt[23]) == 17:
                                send_udp(pkt, iface=InterfaceList[1])
                except Exception, message:
                    logging.error(message)

        elif self.interface_name == InterfaceList[1]:
            while True:
                try:
                    if not ReturnedPackets.empty():
                        pkt = ReturnedPackets.get()
                        pkt = packet_manipulator(pkt)
                        if pkt != '':
                            logging.debug('Interface %s sent packet: \n%s', self.interface_name, summary_dump(pkt))
                            gui_entry('Outgoing', gui_parse(pkt))
                            if ord(pkt[23]) == 1:
                                send_icmp(pkt, iface=InterfaceList[2])
                                ICMPNat.remove_packet(pkt)  #Change Location
                            elif ord(pkt[23]) == 6:
                                send_tcp(pkt, iface=InterfaceList[2])
                            elif ord(pkt[23]) == 17:
                                send_udp(pkt, iface=InterfaceList[2])
                except Exception, message:
                    logging.error(message)


class IcmpNat:  # Stores dictionary for NAT Table for ICMP type packets by storing ICMP ID and Address

    def __init__(self):
        self.IcmpTable = {}
        logging.debug('ICMP Nat table started successfully')

    def add_packet(self, pkt):
        if get_icmp_id(pkt) not in self.IcmpTable:
            self.IcmpTable[get_icmp_id(pkt)] = get_src_adr(pkt)

    def remove_packet(self, pkt):
        del self.IcmpTable[get_icmp_id(pkt)]

    def get_dst_adr(self, pkt):
        return self.IcmpTable.get(get_icmp_id(pkt))

    def printdict(self):
        for key, value in self.IcmpTable.items():
            print "-->" + str(key)
            print(value)


class TcpNat:  # Stores dictionary for NAT Table for TCP type packets by storing outgoing port and Source Address, port

    def __init__(self):
        self.TcpTable = {}
        logging.debug('TCP Nat table started successfully')

    def add_packet(self, pkt):
        for i in range(1, 55500):
            if i not in self.TcpTable or self.TcpTable[i] == (get_src_adr(pkt), get_src_port(pkt)):
                self.TcpTable[i] = (get_src_adr(pkt), get_src_port(pkt))
                break
        return i + 1024

    def remove_packet(self, port):
        del self.TcpTable[port - 1024]

    def remove_by_val(self, SrIp, SrPrt):
        for i in range(0, 55500):
            if self.TcpTable.has_key(i):
                if self.TcpTable[i] == (SrIp, SrPrt):
                    del self.TcpTable[i]

    def get_src_ip_port(self, port):
        if (port - 1024) in self.TcpTable:
            return self.TcpTable[port - 1024]
        return 0


class UdpNat:  # Stores dictionary for NAT Table for UDP type packets by storing outgoing port and Source Address, port

    def __init__(self):
        self.UdpTable = {}
        logging.debug('UDP Nat table started successfully')

    def add_packet(self, pkt):
        for i in range(1, 55500):
            if i not in self.UdpTable or self.UdpTable[i] == (get_src_adr(pkt), get_src_port(pkt)):
                self.UdpTable[i] = (get_src_adr(pkt), get_src_port(pkt))
                break
        return i + 1024

    def remove_packet(self, port):
        del self.UdpTable[port - 1024]

    def remove_by_val(self, SrIp, SrPrt):
        for i in range(0, 55500):
            if i in self.UdpTable:
                if self.UdpTable[i] == (SrIp, SrPrt):
                    del self.UdpTable[i]

    def get_src_ip_port(self, port):
        if (port - 1024) in self.UdpTable:
            return self.UdpTable[port - 1024]
        return 0

    def get_and_delete(self, port):
        x = 0
        if (port - 1024) in self.UdpTable:
            x = self.UdpTable[port - 1024]
            self.remove_by_val(x[0], x[1])
        return x

    def printdict(self):
        for key, value in self.UdpTable.items():
            print "-->" + str(key)
            print value[0] + ": " + str(value[1])


def gui_parse(pkt):
    if get_type(pkt) == 'ICMP':
        returnable = (get_type(pkt), get_src_adr(pkt), '-', get_dst_adr(pkt), '-')
    else:
        returnable = (get_type(pkt), get_src_adr(pkt), str(get_src_port(pkt)), get_dst_adr(pkt), str(get_dst_port(pkt)))

    return returnable


def packet_manipulator(pkt):    # Responsible for manipulating given packet so it can be sent out according to its
                                # arrival interface and protocol
    newp = pkt

    if get_dst_adr(pkt) != get_inf_ip(InterfaceList[1]):
        # From Lan to Wan
        newp = change_dst_mac(newp, ARPCache.return_value(get_dst_adr(pkt)))
        newp = reset_ip_chk_sum(newp)
        newp = reset_frag(newp)

        if ord(pkt[23]) == 1:  # ICMP Protocol
            newp = change_src_adr(newp, get_inf_ip(InterfaceList[1]))
            newp = change_src_mac(newp, get_inf_mac(InterfaceList[1]))
            newp = reset_icmp_check(newp)  #Store ICMP detailes

        elif ord(pkt[23]) == 6:  # TCP Protocol
            newp = change_src_port(newp, TcpTable.add_packet(newp))
            newp = change_src_adr(newp, get_inf_ip(InterfaceList[1]))
            newp = change_src_mac(newp, get_inf_mac(InterfaceList[1]))

        elif ord(pkt[23]) == 17:  # UDP Protocol
            newp = change_src_port(newp, UdpTable.add_packet(newp))
            newp = change_src_adr(newp, get_inf_ip(InterfaceList[1]))
            newp = change_src_mac(newp, get_inf_mac(InterfaceList[1]))
            newp = reset_udp_check(newp)

            #DNS SPOOF
            #newp = change_dst_mac(newp, get_src_mac(newp))
            #newp = change_src_mac(newp, ARPCache.return_value('10.8.8.2'))

    else:
        # From Wan to Lan

        newp = change_src_mac(newp, get_inf_mac(InterfaceList[2]))
        newp = reset_ip_chk_sum(newp)
        newp = reset_frag(newp)

        if ord(pkt[23]) == 1:  # ICMP Protocol
            newp = reset_icmp_check(newp)
            newp = change_dst_adr(newp, ICMPNat.get_dst_adr(newp))
            newp = change_dst_mac(newp, ARPCache.return_value(get_dst_adr(newp)))

        elif ord(pkt[23]) == 6:  # TCP Protocol
            if TcpTable.get_src_ip_port(get_dst_port(newp)) != 0:
                newp = change_dst_adr(newp, TcpTable.get_src_ip_port(get_dst_port(newp))[0])
                newp = change_dst_mac(newp, ARPCache.return_value(get_dst_adr(newp)))
                newp = change_dst_port(newp, TcpTable.get_src_ip_port(get_dst_port(newp))[1])
                newp = change_src_adr(newp, '10.8.8.2')

                if 'F' in get_tcp_flags(newp):
                    TcpTable.remove_by_val(get_dst_adr(newp), get_dst_port(newp))

            else:
                newp = ''

        elif ord(pkt[23]) == 17:  # UDP Protocol
            newp = change_dst_adr(newp, UdpTable.get_src_ip_port(get_dst_port(newp))[0])
            newp = change_dst_mac(newp, ARPCache.return_value(get_dst_adr(newp)))
            newp = change_dst_port(newp, UdpTable.get_and_delete(get_dst_port(newp))[1])

    return newp


def start_packet_sniffer(interface_name, sniff_method):  # Starts packet sniffer on interface using the IPSniffer class
    packet_sniffer = IPSniff(interface_name, sniff_method)
    packet_sniffer.setDaemon(True)
    packet_sniffer.start()
    logging.debug('Packet sniffer on interface %s started successfully', interface_name)


def start_packet_sender(interface_name):  # Starts packet sender on interface using the IPSniffer class
    packet_sender = PacketSender(interface_name)
    packet_sender.setDaemon(True)
    packet_sender.start()
    logging.debug('Packet sender on interface %s started successfully', interface_name)


if __name__ == "__main__":
    print '(You can always type EXIT to close application)'
    LogSystem = LoggingManager()
    try:
        ArrivedPackets = Queue.Queue(5000)  # Arrive packets queue for interface eth0
        InterfaceList = os.listdir('/sys/class/net/')  # Returns list of all networks interfaces of machine
        ARPCache = ARPCache()  # Starts ARPCache
        ICMPNat = IcmpNat()  # Loads ICMP Nat Table
        TcpTable = TcpNat()  # Loads TCP Nat Table
        UdpTable = UdpNat()  # Loads UDP Nat Table
        ReturnedPackets = Queue.Queue(5000)  # Arrive packets queue for interface eth1
    except Exception, message:
        logging.error(message)

    start_packet_sniffer(InterfaceList[2], 'receive_raw_packets')  # Starts packet sniffers and senders
    start_packet_sniffer(InterfaceList[1], 'receive_raw_packets')
    start_packet_sender(InterfaceList[2])
    start_packet_sender(InterfaceList[1])

    if LogSystem.options['loglevel'] != 'DEBUG' and LogSystem.options['loglevel'] != 'ERROR':
        start_nat_monitor()

    while True:
        response = raw_input()
        if response == 'EXIT':
            os._exit(1)
