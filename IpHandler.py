
"""
##################################################################
# Created By: Kobie Hazon                                        #
# Date: 04/05/2017                                               #
# Name: IpHandler                                                #
# Version: 1.0                                                   #
# Linux Tested Versions: Centos 7 64 bit                         #
# Python Tested Versions: 2.7.10 32-bit                          #
# Python Environment  : PyCharm 2017.1.1                         #
##################################################################
"""

import socket
import struct
import fcntl


def get_src_adr(pkt):
    return socket.inet_ntoa(pkt[26:30])


def get_dst_adr(pkt):
    return socket.inet_ntoa(pkt[30:34])


def change_src_adr(pkt, ip_str):
    new_packet = pkt[:26] + socket.inet_aton(ip_str) + pkt[30:]
    return new_packet


def change_dst_adr(pkt, ip_str):
    new_packet = pkt[:30] + socket.inet_aton(ip_str) + pkt[34:]
    return new_packet


def get_src_mac(pkt):
    return str(hex(ord(pkt[6])))[2:] + ":" + str(hex(ord(pkt[7])))[2:] + ":" + str(
        hex(ord(pkt[8])))[2:] + ":" + str(hex(ord(pkt[9])))[2:] + ":" + str(
        hex(ord(pkt[10])))[2:] + ":" + str(hex(ord(pkt[11])))[2:]


def get_dst_mac(pkt):
    return str(hex(ord(pkt[0])))[2:] + ":" + str(hex(ord(pkt[1])))[2:] + ":" + str(
        hex(ord(pkt[2])))[2:] + ":" + str(hex(ord(pkt[3])))[2:] + ":" + str(
        hex(ord(pkt[4])))[2:] + ":" + str(hex(ord(pkt[5])))[2:]


def get_inf_mac(interface):
    with open('/sys/class/net/%s/address' % interface) as f:
        mac = f.read()
    return mac


def get_inf_ip(interface):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s', interface[:15]))[20:24])


def reset_frag(pkt):
    for i in range(20, 22):
        pkt = pkt[:i] + str(chr(0)) + pkt[i+1:]
    return pkt


def get_chk_sum(pkt):
    return '0x' + str(hex(ord(pkt[24])))[2:] + str(hex(ord(pkt[25])))[2:]


def reset_ip_chk_sum(pkt):
    for i in range(24, 26):
        pkt = pkt[:i] + str(chr(0)) + pkt[i+1:]
    return pkt


def get_ttl(pkt):
    return int(str(ord(pkt[22])), 10)


def get_ip_id(pkt):
    return (str(hex(int(str(hex(ord(pkt[18])))[2:] + str(hex(ord(pkt[19])))[2:], 16))))[2:]


def get_ip_flags(pkt):
    temp = str(bin(int(str(int(pkt[18:20].encode('hex'), 16))))[2:].zfill(16))[:3]
    FlagTuple = ()
    if temp[1] == '1':
        FlagTuple = list(FlagTuple)
        FlagTuple.insert(len(FlagTuple), ('DF'))
        FlagTuple = tuple(FlagTuple)
    elif temp[2] == '1':
        pass
    return ''.join(FlagTuple)


def change_src_mac(pkt, new_mac):
    new_mac += ":"
    for i in range(6, 12):
        temp = new_mac[:new_mac.index(":")]
        pkt = pkt[:i] + chr(int(temp[:2], 16)) + pkt[i + 1:]
        new_mac = new_mac[new_mac.index(":") + 1:]
    return pkt


def change_dst_mac(pkt, new_mac):
    new_mac += ":"
    for i in range(0, 6):
        temp = new_mac[:new_mac.index(":")]
        pkt = pkt[:i] + chr(int(temp[:2], 16)) + pkt[i + 1:]
        new_mac = new_mac[new_mac.index(":") + 1:]
    return pkt
