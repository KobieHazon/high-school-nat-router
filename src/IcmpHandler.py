
"""
##################################################################
# Created By: Kobie Hazon                                        #
# Date: 04/05/2017                                               #
# Name: IcmpHandler                                              #
# Version: 1.0                                                   #
# Linux Tested Versions: Centos 7 64 bit                         #
# Python Tested Versions: 2.7.10 32-bit                          #
# Python Environment  : PyCharm 2017.1.1                         #
##################################################################
"""

import os

REFERENCE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data", "ICMPTypes.txt")


def get_icmp_id(pkt):
    return int((str(hex(int(str(hex(ord(pkt[38])))[2:] + str(hex(ord(pkt[39])))[2:], 16))))[2:], 16)


def get_icmp_sq_num(pkt):
    return int(pkt[40:42].encode('hex'), 16)


def icmp_type(pkt):
    with open(REFERENCE_FILE, 'r') as type_file:
        for line in type_file.readlines():
            if line.find(str(hex(ord(pkt[34])))[2:]) != -1:
                return line[line.find(':') + 1:line.index("\n")]


def reset_icmp_check(pkt):
    for i in range(36, 38):
        pkt = pkt[:i] + str(chr(0)) + pkt[i+1:]
    return pkt
