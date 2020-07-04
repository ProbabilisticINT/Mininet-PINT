#!/usr/bin/env python
import time
import random
from subprocess import Popen, PIPE
import re
from scapy.all import sendp, get_if_list, get_if_hwaddr,sendpfast
from scapy.all import Ether, IP, UDP, TCP,Raw,conf

def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        exit(1)
    return iface

def get_dst_mac(ip):
    try:
        pid = Popen(["arp", "-n", ip], stdout=PIPE)
        s = pid.communicate()[0]
        mac = re.search(r"(([a-f\d]{1,2}\:){5}[a-f\d]{1,2})", s).groups()[0]
        return mac
    except:
        return None

def main():
	f=open("config","r")
	for line in f:
		data=line.strip().split("=")
		type=data[0]
		value=data[1]
		if type=="receiver_ip":
			receiver_ip=value
		if type=="sender_ip":
			sender_ip=value
		if type=="common_log":
			common_log=value
		if type=="total_packets":
			total_packets=int(value)
		if type=="iterations":
			iterations=int(value)
	f.close()

	iface = get_if()

	seen_timestamps=set()
	current_time=""
	last_time=0
	total_sent=0
	all_pkt_id=set()
	while True:
		pkt_id=random.randint(1,60000)
		if pkt_id not in all_pkt_id:
			all_pkt_id.add(pkt_id)
		if len(all_pkt_id)==total_packets:
			break

	ether_dst='{0:0{1}X}'.format(0,12)
	ether_src='{0:0{1}X}'.format(0,12)
	ether_dst=':'.join([ether_dst[i:i+2] for i in range(0, len(ether_dst), 2)])
	pkt_list=[]
	for pkt_id in all_pkt_id:
		pkt =  Ether(src=ether_src, dst=ether_dst)
		pkt = pkt /IP(dst=receiver_ip,ttl=255,id=pkt_id) / UDP()
		pkt_list.append(pkt)
		total_sent=total_sent+1

	for i in range(0,iterations):
		random.shuffle(pkt_list)
		sendp(pkt_list,iface=iface,verbose=False,inter=0.005)

if __name__ == '__main__':
    main()
