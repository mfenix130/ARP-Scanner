import argparse				#For parsing arguments
import threading			#For threading
import time				#For calculating scan time
from scapy.all import *			#For using scapy functions
from queue import Queue			#For putting IPs in Queue
from netaddr import IPNetwork		#For iterating IPs in CIDR

parser = argparse.ArgumentParser()
parser.add_argument('interface', help='Network Interface to use for scanning')
parser.add_argument('ip', help='The range of IPs or IP to scan')
args = parser.parse_args()


print_lock = threading.Lock()


def scanJob(ip):
	ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), iface = args.interface, timeout=1,  inter = 0.1, verbose =0)
	with print_lock:
		for snd,rcv in ans:
			print("{} - {}".format(rcv.src, rcv.psrc))

def threader():
	while True:
		ip = q.get()
		scanJob(ip)
		q.task_done()

q = Queue()

for _ in range (30):
	t = threading.Thread(target = threader)
	t.daemon = True
	t.start()

print("Starting Scan")
start_time = time.time()
print("MAC - IP")

# IPs can be given in 3 different ways
# 1. In a hyphenated range
# 2. CIDR notification
# 3. Single IP

if (args.ip.find('-') != -1):
	base,offset = args.ip.split('-')
	first,second,third,fourth = base.split('.')
	for i in range(int(fourth),int(offset)+1):
		ip = "{}.{}.{}.{}".format(first,second,third,str(i))
		q.put(ip)
elif(args.ip.find('/') != -1):
	for i in IPNetwork(args.ip).iter_hosts():
		q.put(str(i))
else:
	q.put(args.ip)


q.join()

print('Scan Duration:',time.time() - start_time)
