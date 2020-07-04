import operator
import glob
import struct
import time
import zlib
import multiprocessing
import sys
import socket
import os
import numpy as np

exp_name=sys.argv[1]

path = []
for i in range(0,int(exp_name)):
	path.append("s"+str(i))

f=open("config","r")
for line in f:
	line=line.strip().split("=")
	type=line[0]
	data=line[1]
	if type=="global_hash_range":
			global_hash_range=int(data)
	if type=="receiver_interface":
			receiver_interface=data
	if type=="receiver_ip":
			receiver_ip=data
	if type=="common_log":
			common_log=data
	if type=="total_packets":
		total_packets_1=int(data)
f.close()

def ip2int(addr):
	return struct.unpack("!I", socket.inet_aton(addr))[0]


max_cutoff=4000
for max_bit_range in [255,8,1]:
	final_results_avg={}
	final_results_median={}
	final_results_tail={}
	os.system("mkdir -p final_results/"+exp_name+"/avg")
	os.system("mkdir -p final_results/"+exp_name+"/median")
	os.system("mkdir -p final_results/"+exp_name+"/tail")

	iterations=len(path)
	while True:
		if iterations==1:
			break
		new_path=path[:iterations][::-1]
		distance_metric={}
		xor_locations={}
		hop_location={}
		packet_count=0
		results=[]

		f=open("experiments/"+exp_name+"/"+str(len(new_path))+"/255_1000000","r")
		for line in f:
			packet_count=packet_count+1
			try:
				data=line.strip().split(",")
				data=[int(x) for x in data]
				total_packets=data[0]
				ttl=data[1]
				pkt_id=int(data[2])
				digest=int(data[4])
				actual_switch_id=int(data[5])
			except:
				continue

			final_results={}
			k=255-ttl
			k_val=k+1
			current_path=new_path[:k_val]
			host=current_path[-1]

			decider_hash=(zlib.crc32(struct.pack("!H",pkt_id))& 0xffffffff)%100
			if decider_hash<50:
				old_digest=digest
				digest='{:048b}'.format(digest)
				digest_1=int(digest[0:16],2)
				digest_2=int(digest[16:32],2)
				digest_3=int(digest[32:],2)

				if max_bit_range==255:
					digest=digest_1
				if max_bit_range==8:
					digest=digest_2
				if max_bit_range==1:
					digest=digest_3

				global_hash_check=(zlib.crc32(struct.pack("!HI",pkt_id, k_val))& 0xffffffff)%global_hash_range
				while global_hash_check>global_hash_range/k_val:
					k_val=k_val-1
					global_hash_check=(zlib.crc32(struct.pack("!HI",pkt_id, k_val))& 0xffffffff)%global_hash_range

				if k_val not in distance_metric:
					distance_metric[k_val]=set()

				distance_metric[k_val].add((digest,pkt_id,actual_switch_id))

				hop_location={}
				for k_val,all_data in distance_metric.iteritems():
					set_list=[]
					for data in all_data:
						digest=data[0]
						pkt_id=data[1]
						actual_switch=data[2]
						temp_list=set()
						for switch_id in new_path:
							switch_id=int(switch_id.replace("s",""))
							specific_hash_check=(zlib.crc32(struct.pack("!IH", switch_id,pkt_id))& 0xffffffff)%max_bit_range
							if specific_hash_check==digest:
								temp_list.add(switch_id)
						set_list.append(temp_list)
					if len(set.intersection(*set_list))==1:
						hop_location[k_val]=list(set.intersection(*set_list))[0]

				if len(hop_location)==k:
					results.append(packet_count)
					packet_count=0
					distance_metric={}
					hop_location={}
					xor_locations={}


				if packet_count==max_cutoff:
					bin_dis={}
					missing_distance=set()
					disagreement=set()
					results.append(0)
					packet_count=0
					distance_metric={}

			if decider_hash>=50:
				digest='{:048b}'.format(digest)
				digest_1=int(digest[0:16],2)
				digest_2=int(digest[16:32],2)
				digest_3=int(digest[32:],2)
				if max_bit_range==255:
					digest=digest_1
				if max_bit_range==8:
					digest=digest_2
				if max_bit_range==1:
					digest=digest_3

				k=255-ttl
				k_val=k+1

				current_path=new_path[:k_val]
				host=current_path[-1]

				temp=[]
				while k_val!=1:
					k_val=k_val-1
					global_hash_check=(zlib.crc32(struct.pack("!HI",pkt_id, k_val))& 0xffffffff)%1000000
					if global_hash_check<=100000 and int(digest)!=0:
						temp.append((k_val,digest))

				if len(temp)!=0:
					if len(temp) not in xor_locations:
						xor_locations[len(temp)]=[]
					xor_locations[len(temp)].append(temp)

				sorted_xor_locations=sorted(xor_locations.items(),key=operator.itemgetter(0))
				for item in sorted_xor_locations:
					for k_val_set in item[1]:
						found=0
						total=len(k_val_set)
						for k_value_digest in k_val_set:
							k_value=k_value_digest[0]
							remaining_digest=k_value_digest[1]
							if k_value in hop_location:
								found=found+1
						if total-found==1:
							for k_value_digest in k_val_set:
								k_value=k_value_digest[0]
								if k_value in hop_location:
									current_switch=hop_location[k_value]
									remaining_digest='{0:048b}'.format(int(remaining_digest))
									current_switch='{0:048b}'.format(int(current_switch))
									remaining_digest=int(remaining_digest, 2)^int(current_switch,2)
								else:
									missing_k=k_value
							final_switch_id=int(bin(remaining_digest)[2:].zfill(48),2)
							hop_location[missing_k]=final_switch_id
				if len(hop_location)==255-ttl:
					results.append(packet_count)
					hop_location={}
					xor_locations={}
					packet_count=0
					distance_metric={}
		f.close()
		final_results_avg[len(new_path)]=["0"]
		final_results_median[len(new_path)]=["0"]
		final_results_tail[len(new_path)]=["0"]
		final_results_avg[len(new_path)][0]=str(round(sum(results)/float(len(results)),2))
		final_results_median[len(new_path)][0]=str(round(np.median(results),2))
		final_results_tail[len(new_path)][0]=str(round(np.percentile(results, 99),2))
		iterations=iterations-1
	bit_map={255: "PINT8", 8: "PINT4", 1: "PINT1"}
	final_results_avg = sorted(final_results_avg.items(), key=operator.itemgetter(0))
	fw = open("final_results/"+exp_name+"/avg/"+str(bit_map[max_bit_range]),"w")
	for item in final_results_avg:
		fw.write(str(item[0])+","+",".join(item[1])+"\n")
	fw.close()

	final_results_median = sorted(final_results_median.items(), key=operator.itemgetter(0))
	fw = open("final_results/"+exp_name+"/median/"+str(bit_map[max_bit_range]),"w")
	for item in final_results_median:
		fw.write(str(item[0])+","+",".join(item[1])+"\n")
	fw.close()

	final_results_tail = sorted(final_results_tail.items(), key=operator.itemgetter(0))
	fw = open("final_results/"+exp_name+"/tail/"+str(bit_map[max_bit_range]),"w")
	for item in final_results_tail:
		fw.write(str(item[0])+","+",".join(item[1])+"\n")
	fw.close()
