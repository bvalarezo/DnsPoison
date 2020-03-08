CSE363 HW2
Bryan Valarezo
110362410

DnsPoison.py | A dns poisoner used to intercept DNS traffic using python3 and scapy

Requirements
  -python3
  -scapy
  
Usage

dnspoison.py [-i interface] [-f hostnames] expression

  -i      Read packets from a specific network interface (e.g., eth0) indefinitely. If not
          specified, the program will select the default interface. (Requires root permissions to sniff)

  -f      Read a list of IP address and hostname pairs specifying the hostnames to be hijacked. If '-f' is not specified,
          dnspoison should forge replies to all observed requests with the local machine's IP address as an answer.
  
  -h      Prints out the usage information
 
  <expression> a filter expression that specifies a subset of the traffic to be monitored (using BPF format).
  
If neither flag is specified, dnspoison.py will sniff packets from a network interface and forge dns responses with the local machine's IP address as an answer.

To see results, see test directory and dns.pcap
  
Example output:

$ sudo python3 dnspoison.py -f test/evil.txt
Spoofing DNS packets from interface...
Spoofing www.google.com with 192.168.168.4
Spoofing www.google.com with 192.168.168.4
Spoofing www.reddit.com with 192.168.168.4
Spoofing www.chase.com with 192.168.168.4
Spoofing www.facebook.com with 192.168.168.4
Spoofing foo.example.com with 10.6.6.6
Spoofing bar.example.com with 10.6.6.6
Spoofing www.cs.stonybrook.edu with 192.168.168.4
Spoofing www.chase.com with 192.168.168.4
Spoofing www.chase.com with 192.168.168.4
Spoofing www.reddit.com with 192.168.168.4
Spoofing www.reddit.com with 192.168.168.4
Spoofing www.facebook.com with 192.168.168.4
Spoofing www.facebook.com with 192.168.168.4
^CFinished spoofing packets from interface.




  
