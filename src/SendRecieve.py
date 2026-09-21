
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


def send_packet(pkt, protocol, iface=None):
    # Preserve translated addresses, payload and protocol options; recompute checksums.
    packet = Ether(pkt)
    del packet[IP].chksum
    del packet[protocol].chksum
    sendp(packet, iface=iface, verbose=False)


def send_icmp(pkt, iface=None):
    send_packet(pkt, ICMP, iface)


def send_tcp(pkt, iface=None):
    send_packet(pkt, TCP, iface)


def send_udp(pkt, iface=None):
    send_packet(pkt, UDP, iface)


def summary_dump(pkt):
    return Ether(pkt).summary()


def get_type(pkt):
    if ord(pkt[23]) == 1:
        return 'ICMP'
    elif ord(pkt[23]) == 6:
        return 'TCP'
    elif ord(pkt[23]) == 17:
        return 'UDP'
