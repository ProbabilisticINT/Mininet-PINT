import time
import zlib
from scapy.all import *
import multiprocessing
import sys

def listener(queue,trial_number,stop_total_packets):
	k=0
	total_packets=0
	distance_metric={}
	fw=open(trial_number,"w")
	fw.close()
	while True:
		data=queue.get()
		k=data[0]
		pkt_id=data[1]
		switch_id=data[2]
		digest=data[3]
		checksum=data[4]
		final_results={}
		total_packets=total_packets+1
		if total_packets==1:
			start_time=time.time()
		fw=open(trial_number,"a")
		fw.write(str(total_packets)+","+str(k)+","+str(pkt_id)+","+str(switch_id)+","+str(digest)+","+str(checksum)+"\n")
		fw.close()
	return



def parent_callback(queue):
	def pkt_callback(pkt):
		ethernet_header=pkt.getlayer(Ether)
		src_mac=ethernet_header.src
		dst_mac=ethernet_header.dst
		ip_header=pkt.getlayer(IP)
		src_ip=ip_header.src
		dst_ip=ip_header.dst
		ecn=ip_header.tos
		pkt_id=ip_header.id
		ttl=ip_header.ttl
		chksum=ip_header.chksum
		if ecn==1:
			k=ttl
			src_mac_int = int(src_mac.translate(None, ":.- "), 16)
			dst_mac_int = int(dst_mac.translate(None, ":.- "), 16)
			checksum=int(ip_header.chksum)
			queue.put((k,pkt_id,src_mac_int,dst_mac_int,checksum))
	return pkt_callback

manager = multiprocessing.Manager()
queue = manager.Queue()
pool = multiprocessing.Pool(1)

f=open("config","r")
for line in f:
	line=line.strip().split("=")
	type=line[0]
	data=line[1]
	if type=="max_bit_range":
		max_bit_range=int(data)
	if type=="global_hash_range":
		global_hash_range=int(data)
	if type=="receiver_interface":
		receiver_interface=data
	if type=="receiver_ip":
		receiver_ip=data
	if type=="common_log":
		common_log=data
	if type=="total_packets":
		total_packets=int(data)
	if type=="iterations":
		iterations=int(data)
f.close()

trial_number=sys.argv[1]
watcher = pool.apply_async(listener,(queue,trial_number+"_"+str(global_hash_range),total_packets*iterations))
sniff(iface=receiver_interface, prn=parent_callback(queue), filter="dst net "+receiver_ip, store=0)
