
"""
##################################################################
# Created By: Kobie Hazon                                        #
# Date: 04/05/2017                                               #
# Name: TcpHandler                                               #
# Version: 1.0                                                   #
# Linux Tested Versions: Centos 7 64 bit                         #
# Python Tested Versions: 2.7.10 32-bit                          #
# Python Environment  : PyCharm 2017.1.1                         #
##################################################################
"""

import ast
from StringIO import StringIO
import sys
from scapy.layers.inet import Ether


def show_dump(pkt):
    capture = StringIO()
    save_stdout = sys.stdout
    sys.stdout = capture
    Ether(pkt).show()
    sys.stdout = save_stdout

    # capture.getvalue() is a string with the output of 'pack.show()'
    return capture.getvalue()


def get_tcp_options(pkt):
    if 'Raw' not in show_dump(pkt):
        options = show_dump(pkt)[show_dump(pkt).find("options", show_dump(pkt).find("sport")):][12:]
    else:
        options = show_dump(pkt)[show_dump(pkt).find
        ("options", show_dump(pkt).find("sport")):show_dump(pkt).find('Raw') - 6][12:]
    return ast.literal_eval(options)


def get_tcp_raw_load(pkt):
    str_raw = show_dump(pkt)
    if 'load' in str_raw:
        str_raw = show_dump(pkt)[show_dump(pkt).find("load") + 13:show_dump(pkt).rfind("'")]
    else:
        str_raw = ''
    return str_raw


def get_tcp_sq_num(pkt):
    return int(pkt[38:42].encode('hex'), 16)


def get_ack_num(pkt):
    return int(pkt[42:46].encode('hex'), 16)


def get_data_off(pkt):
    return str(bin(int(str(int(pkt[46:48].encode('hex'), 16))))[2:].zfill(4))[0:2]


def get_tcp_flags(pkt):
    temp = str(bin(int(str(int(pkt[46:48].encode('hex'), 16))))[2:].zfill(16))[7:]
    flag_tuple = ()
    if temp[0] == '1':
        flag_tuple = list(flag_tuple)
        flag_tuple.insert(len(flag_tuple), 'N')
        flag_tuple = tuple(flag_tuple)
    if temp[1] == '1':
        flag_tuple = list(flag_tuple)
        flag_tuple.insert(len(flag_tuple), 'C')
        flag_tuple = tuple(flag_tuple)
    if temp[2] == '1':
        flag_tuple = list(flag_tuple)
        flag_tuple.insert(len(flag_tuple), 'E')
        flag_tuple = tuple(flag_tuple)
    if temp[3] == '1':
        flag_tuple = list(flag_tuple)
        flag_tuple.insert(len(flag_tuple), 'U')
        flag_tuple = tuple(flag_tuple)
    if temp[4] == '1':
        flag_tuple = list(flag_tuple)
        flag_tuple.insert(len(flag_tuple), 'A')
        flag_tuple = tuple(flag_tuple)
    if temp[5] == '1':
        flag_tuple = list(flag_tuple)
        flag_tuple.insert(len(flag_tuple), 'P')
        flag_tuple = tuple(flag_tuple)
    if temp[6] == '1':
        flag_tuple = list(flag_tuple)
        flag_tuple.insert(len(flag_tuple), 'R')
        flag_tuple = tuple(flag_tuple)
    if temp[7] == '1':
        flag_tuple = list(flag_tuple)
        flag_tuple.insert(len(flag_tuple), 'S')
        flag_tuple = tuple(flag_tuple)
    if temp[8] == '1':
        flag_tuple = list(flag_tuple)
        flag_tuple.insert(len(flag_tuple), 'F')
        flag_tuple = tuple(flag_tuple)
    return ''.join(flag_tuple)


def reset_tcp_check(pkt):
    for i in range(40, 42):
        pkt = pkt[:i] + str(chr(0)) + pkt[i+1:]
    return pkt


def get_window_size(pkt):
    return int(pkt[48:50].encode('hex'), 16)


def get_src_port(pkt):
    return int(pkt[34:36].encode('hex'), 16)


def get_dst_port(pkt):
    return int(pkt[36:38].encode('hex'), 16)


def change_src_port(pkt, new_packet):
    new_packet = format(new_packet, 'x').zfill(4)
    for i in range(34, 36):
        temp = new_packet[:2]
        pkt = pkt[:i] + chr(int(temp[:2], 16)) + pkt[i + 1:]
        new_packet = new_packet[2:]
    return pkt


def change_dst_port(pkt, new_packet):
    new_packet = format(new_packet, 'x').zfill(4)
    for i in range(36, 38):
        temp = new_packet[:2]
        pkt = pkt[:i] + chr(int(temp[:2], 16)) + pkt[i + 1:]
        new_packet = new_packet[2:]
    return pkt
