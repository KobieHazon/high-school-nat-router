
"""
##################################################################
# Created By: Kobie Hazon                                        #
# Date: 04/05/2017                                               #
# Name: UdpHandler                                               #
# Version: 1.0                                                   #
# Linux Tested Versions: Centos 7 64 bit                         #
# Python Tested Versions: 2.7.10 32-bit                          #
# Python Environment  : PyCharm 2017.1.1                         #
##################################################################
"""
import dpkt
from scapy.layers.inet import Ether, IP, ICMP, TCP, Raw, UDP
from scapy.layers.dns import *


def get_src_port(pkt):
    return int(pkt[34:36].encode('hex'), 16)


def get_dst_port(pkt):
    return int(pkt[36:38].encode('hex'), 16)


def change_src_port(pkt, newp):
    newp = format(newp, 'x').zfill(4)
    for i in range(34, 36):
        temp = newp[:2]
        pkt = pkt[:i] + chr(int(temp[:2], 16)) + pkt[i + 1:]
        newp = newp[2:]
    return pkt


def change_dst_port(pkt, newp):
    newp = format(newp, 'x').zfill(4)
    for i in range(36, 38):
        temp = newp[:2]
        pkt = pkt[:i] + chr(int(temp[:2], 16)) + pkt[i + 1:]
        newp = newp[2:]
    return pkt


def reset_udp_check(pkt):
    for i in range(40, 42):
        pkt = pkt[:i] + str(chr(0)) + pkt[i+1:]
    return pkt


def dns_forward(pkt):
    eth = dpkt.ethernet.Ethernet(pkt)
    ip = eth.data
    udp = ip.data
    dns = dpkt.dns.DNS(udp.data)
    x = Ether(str(eth))
    return x


def dns_spoof(pkt):
    eth = dpkt.ethernet.Ethernet(pkt)
    ip = eth.data
    udp = ip.data
    dns = dpkt.dns.DNS(udp.data)
    # transform DNS query into response
    dns.op = dpkt.dns.DNS_RA
    dns.rcode = dpkt.dns.DNS_RCODE_NOERR
    dns.qr = dpkt.dns.DNS_R

    # construct our fake answer RR
    arr = dpkt.dns.DNS.RR()
    arr.cls = dpkt.dns.DNS_IN
    arr.type = dpkt.dns.DNS_A
    arr.name = 'wan.kobie.com'
    arr.ip = socket.inet_aton('10.8.8.2')

    dns.an.append(arr)

    # fix up IP and UDP layers
    udp.sport, udp.dport = udp.dport, udp.sport
    ip.src, ip.dst = ip.dst, ip.src
    udp.data = dns
    udp.ulen = len(udp)
    ip.len = len(ip)
    x = Ether(str(eth))
    return x
