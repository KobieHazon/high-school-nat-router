#!/bin/bash

trap "" HUP

iptables -A FORWARD -j DROP
iptables -A OUTPUT -p tcp -s 10.8.8.1 -d 10.8.8.2 --dport 80 -j DROP
/sbin/service iptables save > /dev/null
systemctl restart iptables

trap - HUP
echo -e "Enter NAT program parameters:"
read parameters
python Main.py $parameters
