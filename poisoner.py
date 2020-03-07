
from scapy.all import *

hosts_dict = {}

def poison(iface=None, hosts=None, expression=None):
	retval = 0
	global hosts_dict
	if hosts:
		for line in hosts:
			rule = line.split(' ')
			name = rule[1]
			ip = rule[0]
			hosts_dict[name.encode()] = ip
	else:
		ip = get_if_addr(conf.iface) if not iface else get_if_addr(iface)
		hosts_dict["*all*"] = ip
	retval = parse_interface(iface, expression)
	return retval

def parse_interface(iface, expression):
    print("Reading packets from interface...")
    try:
        if iface:
            sniff(filter=expression, prn=identify_pkt, iface=iface)
        else:
            sniff(filter=expression, prn=identify_pkt)
    except KeyboardInterrupt:
        print("Finished reading packets from interface.")

def identify_pkt(packet):
    if packet.haslayer(HTTPRequest):
        print(decode_HTTP(packet))
    elif packet.haslayer(TLSClientHello) and packet.haslayer(ServerName):
        print(decode_TLS(packet))
    else:
        pass