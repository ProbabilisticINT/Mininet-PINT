from subprocess import Popen
import os
import time
import sys
import networkx as nx

from p4utils.utils.topology import Topology


class Experiment:
	def __init__(
		self,
		length,
		exp_ranges,
	):
		self.length = length
		self.exp_ranges = exp_ranges
		self.original_path = []
		self.all_switches = set()
		self.all_links = set()
		self.G = nx.Graph()
		self.host_ips={}
		self.switch_mapper={}
		self.thrift_port={}

		for i in range(0,length):
			self.all_switches.add("s"+str(i))
			self.original_path.append("s"+str(i))
		for i in range(0,length-1):
			self.all_links.add(("s"+str(i),"s"+str(i+1)))

		self.exp_count=0
		self.max_bit_range=255
		self.all_done=set()
		self.global_hash_range=1000000


	def update_graph(self):
		for switch in self.all_switches:
			host=switch.replace("s","h")
			self.G.add_node(switch)
			self.G.add_node(host)

		for link in self.all_links:
			node_1=link[0]
			node_2=link[1]
			self.G.add_edge(node_1,node_2)

	def obtain_mininet_topo(self):
		topo = Topology(db="topology.db")
		for switch in self.all_switches:
			if switch not in self.switch_mapper:
					self.switch_mapper[switch]={}

			host=switch.replace("s","h")
			host_details=topo.node(host)
			ip_address=host_details[switch]["ip"].split("/")[0]
			self.host_ips[host]=ip_address

			switch_details=topo.node(switch)
			self.thrift_port[switch]=switch_details["thrift_port"]

			for interface,port in switch_details["interfaces_to_port"].iteritems():
				if interface!="lo":
					node=switch_details["interfaces_to_node"][interface]
					self.switch_mapper[switch][node]=port


	def generate_rules(self):
		for switch in self.all_switches:
			host=switch.replace("s","h")
			fw=open("rules/"+switch+"-commands.txt","w")
			fw.write("table_clear dmac\n")
			fw.write("table_clear ttl_rules\n\n")
			fw.write("table_add dmac forward " + self.host_ips[host] +
				" => " + str(self.switch_mapper[switch][host])+"\n")
			for switch_1 in self.all_switches:
				if switch == switch_1:
					continue
				destination_host = switch_1.replace("s","h")
				try:
					p = nx.shortest_path(self.G, source=switch, target=switch_1)
				except:
					continue
				fw.write("table_add dmac forward " + self.host_ips[destination_host]
				+ " => " + str(self.switch_mapper[switch][p[1]])+"\n")

			switch_id=switch.replace("s","")
			ttl=255
			max_ttl=30
			fw.write("\n\n")
			while ttl>0:
					approx=self.global_hash_range/(256-ttl)
					fw.write("table_add ttl_rules copy_to_metadata "
					+str(ttl)+" => "+str(approx)+" "+str(switch_id)+" "
					+str(self.max_bit_range)+"\n")
					ttl=ttl-1
			fw.close()

		for node,port in self.thrift_port.iteritems():
			os.system("simple_switch_CLI --thrift-port "
			+str(port)+" < rules/"+str(node)
			+"-commands.txt > /dev/null")

	def gen_config(self, receiver_interface, receiver_ip, sender_ip):
		fw=open("config","w")
		fw.write("receiver_interface="+receiver_interface+"\n")
		fw.write("max_bit_range="+str(self.max_bit_range)+"\n")
		fw.write("global_hash_range=1000000\n")
		fw.write("receiver_ip="+receiver_ip+"\n")
		fw.write("sender_ip="+sender_ip+"\n")
		fw.write("common_log=common_log\n")
		fw.write("total_packets=5000\n")
		fw.write("iterations=1")
		fw.close()

	def run(self):
		while True:
			for exp_range in self.exp_ranges:
				path=self.original_path[:exp_range]
				exp_name=str(len(path))
				total_runs=len(path)

				self.generate_rules()

				while True:
					if total_runs==1:
						break
					new_path=path[:total_runs]
					sender=new_path[0].replace("s","h")
					receiver=new_path[-1].replace("s","h")
					receiver_interface=receiver+"-eth0"
					receiver_ip="10.0.0."+str(receiver.replace("h",""))
					sender_ip="10.0.0."+str(sender.replace("h",""))

					self.gen_config(receiver_interface, receiver_ip, sender_ip)

					start_time=time.time()
					os.system("mkdir -p experiments/"+exp_name+"/"+str(total_runs))
					os.system("sudo pkill -9 -f recv.py")
					os.system("sudo pkill -9 -f send.py")

					#Start Receiver
					simple_controller="mx {0} sudo python recv.py {1}"
					recv_job=Popen(simple_controller.format(receiver,
					"experiments/"+exp_name+"/"+str(total_runs)+"/"
					+str(self.max_bit_range)), shell=True)

					time.sleep(2)

					#Start sender
					sender_="mx {0} sudo python send.py"
					send_job=Popen(sender_.format(sender), shell=True)

					while True:
						if send_job.poll() is None:
							time.sleep(3)
						else:
							break

					os.system("sudo pkill -9 -f recv.py")
					self.exp_count=self.exp_count+1
					print "Exp range",exp_range,"Total runs",str(self.exp_count)+"/"+str(exp_range-1)+" Time",time.time()-start_time
					total_runs=total_runs-1
				if total_runs==1:
					self.all_done.add(exp_range)
			if len(self.all_done)==len(exp_ranges):
				break

length=int(sys.argv[1])
exp_ranges=str(sys.argv[1])
exp_ranges=[int(x) for x in exp_ranges.split(",")]

exp = Experiment(length, exp_ranges)
exp.update_graph()
exp.obtain_mininet_topo()
exp.run()
