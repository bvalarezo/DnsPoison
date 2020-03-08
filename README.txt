CSE363 HW1
Bryan Valarezo
110362410

Sniffer.py | A websniffer used to parse HTTP and TLS traffic using python3 and scapy.

Requirements
  -python3
  -scapy
  
Usage

sniffer.py [-i interface] [-r tracefile] expression

  -i      Read packets from a specific network interface (e.g., eth0) indefinitely. If not
          specified, the program will select the default interface. (Requires root permissions to sniff)

  -f      Read packets from a tracefile.
  
  -h      Prints out the usage information
 
  <expression> a filter expression that specifies a subset of the traffic to be monitored (using BPF format).
  
If neither flag is specified, sniffer.py will sniff packets from a network interface

To see results, see test directory
  
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




  
