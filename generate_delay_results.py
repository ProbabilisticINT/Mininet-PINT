import math
import time
import sys
import numpy as np
import operator
import random
import os
from kll import KLL

random.seed(30)

import glob


sketch_size=100
packets_range=list(range(100,1100,100))
pint_packets={}
all_packets={}
approx={}
all_approx=set()
approx_map={}
for packets in packets_range:
	approx[packets]={}
for packets in packets_range:
	for bits in [4,8]:
		if bits==4:
			ap=0.42
		if bits==8:
			ap=0.022
		approx[packets][ap]=[]
		all_approx.add(ap)
		approx_map[ap]=bits
packet_results_avg={}
packet_results_median={}
packet_results_tail={}
all=[]
f=open("experiments/delays/processed_data","r")
for line in f:
	digest_1=int(line.strip())
	if digest_1 <0:
		continue
	all.append(digest_1)
f.close()

all=sorted(all)
all_median=np.median(all)
all_avg=sum(all)/float(len(all))
all_tail=np.percentile(all,99)

for packets in packets_range:
	if packets not in packet_results_avg:
		packet_results_avg[packets]={}
	if packets not in packet_results_median:
		packet_results_median[packets]={}
	if packets not in packet_results_tail:
		packet_results_tail[packets]={}

	pint_packets[packets]=[]
	all_packets[packets]=[]
	pint=[]

	f=open("experiments/delays/processed_data","r")
	for line in f:
		digest_1=int(line.strip())
		if digest_1 <0:
			continue
		if random.randint(1, 2) == 1:
			pint.append(digest_1)
			for ap in all_approx:
					if digest_1==0:
						approx[packets][ap].append(digest_1)
						continue

					range_1=int(math.log(digest_1, (1+ap)**2))
					range_2=int(math.log(digest_1, (1+ap)**2)+0.5)

					approx_value_1=(1+ap)**(2*range_1)
					approx_value_2=(1+ap)**(2*range_2)

					diff_1=digest_1-approx_value_1
					if diff_1<0:
						diff_1=-1*diff_1

					diff_2=digest_1-approx_value_2
					if diff_2<0:
						diff_2=-1*diff_2

					if diff_1<=diff_2:
						approx[packets][ap].append(int(approx_value_1))
					if diff_1>diff_2:
						approx[packets][ap].append(int(approx_value_2))

		if len(pint)==packets:
			all_medianp=np.median(pint)
			all_avgp=sum(all)/float(len(pint))
			all_tailp=np.percentile(pint,99)

			for item in all_approx:
				value=sorted(approx[packets][item])
				if len(value)<=1:
					continue

				#Using sketch to store digests
				kll = KLL(sketch_size)
				for v in value:
					kll.update(v)

				min_diff_50 = 1000
				min_diff_99 = 1000
				pint_median = 0
				pint_tail = 0
				for (ii, quantile) in kll.cdf():
				    diff = quantile - 0.5
				    if diff < 0:
				        diff = diff * -1
				    if diff<min_diff_50:
				        min_diff_50 = diff
				        pint_median = ii

				    diff = quantile - 0.99
				    if diff < 0:
				        diff = diff * -1
				    if diff<min_diff_99:
				        min_diff_99 = diff
				        pint_tail = ii

				pint_avg=sum(value)/float(len(value))

				if all_median!=0:
					error_median=(all_median-pint_median)/float(all_median)*100
				if all_median==0:
					error_median=0

				error_avg=(all_avg-pint_avg)/float(all_avg)*100
				error_tail=(all_tail-pint_tail)/float(all_tail)*100
				if error_median<0:
					error_median=error_median*-1
				if error_avg<0:
					error_avg=error_avg*-1
				if error_tail<0:
					error_tail=error_tail*-1

				if item not in packet_results_avg[packets]:
					packet_results_avg[packets][item]=[]
				packet_results_avg[packets][item].append(error_avg)

				if item not in packet_results_median[packets]:
					packet_results_median[packets][item]=[]
				packet_results_median[packets][item].append(error_median)

				if item not in packet_results_tail[packets]:
					packet_results_tail[packets][item]=[]
				packet_results_tail[packets][item].append(error_tail)

			approx={}
			for packets_1 in packets_range:
				approx[packets_1]={}
			for packets_1 in packets_range:
				for bits in [4,8]:
					if bits==4:
						ap=0.42
					if bits==8:
						ap=0.022
					approx[packets_1][ap]=[]
			pint=[]
	f.close()

packet_results_avg=sorted(packet_results_avg.items(),key=operator.itemgetter(0))
os.system("mkdir -p final_results/delays/")
fw=open("final_results/delays/avg_delay","w")
fw.write("# of packets,PINT4,value,PINT8,value\n")
for item in packet_results_avg:
	packets=item[0]
	v=item[1]
	write_string=str(packets)
	for k,v1 in v.items():
		write_string=write_string+","+"PINT"+str(approx_map[k])+","+str(round(sum(v1)/float(len(v1)),2))
	fw.write(write_string+"\n")
fw.close()


packet_results_median=sorted(packet_results_median.items(),key=operator.itemgetter(0))
fw=open("final_results/delays/median_delay","w")
fw.write("# of packets,PINT4,value,PINT8,value\n")
for item in packet_results_median:
	packets=item[0]
	v=item[1]
	write_string=str(packets)
	for k,v1 in v.items():
		write_string=write_string+","+"PINT"+str(approx_map[k])+","+str(round(sum(v1)/float(len(v1)),2))
	fw.write(write_string+"\n")
fw.close()


packet_results_tail=sorted(packet_results_tail.items(),key=operator.itemgetter(0))
fw=open("final_results/delays/tail_delay","w")
fw.write("# of packets,PINT4,value,PINT8,value\n")
for item in packet_results_tail:
	packets=item[0]
	v=item[1]
	write_string=str(packets)
	for k,v1 in v.items():
		write_string=write_string+","+"PINT"+str(approx_map[k])+","+str(round(sum(v1)/float(len(v1)),2))
	fw.write(write_string+"\n")
fw.close()
