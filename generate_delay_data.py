import sys
import os
file_name=sys.argv[1]

os.system("mkdir -p experiments/delays/")

f=open(file_name,"r")
data={}
for line in f:
	time = int(line.strip().split(" ")[0])
	if "Enqu" in line:
		pkt = line.strip().split("Enqu")[1]
		data[pkt]=[time, 0]
	if "Dequ" in line:
		pkt = line.strip().split("Dequ")[1]
		data[pkt][1]=time
f.close()
all=[]
pint_4=[]
pint_8=[]
for key,value in data.items():
	all.append(value[1] - value[0])

fw=open("experiments/delays/processed_data","w")
for item in all:
	fw.write(str(item)+"\n")
fw.close()
