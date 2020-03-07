#!/usr/bin/env python3

import sys, getopt
from poisoner import poison

#PREDEFINED 
OPTIONS = "i:f:h"
HOSTFILE = None
INTERFACE = None
EXPRESSION = ""
hosts = ""

def usage(name, status=2):
    print("Usage: %s [-i interface] [-f hostnames] [expression]" % name, file=sys.stderr)
    sys.exit(status)

def main(argv):
    global HOSTFILE, INTERFACE, EXPRESSION, hosts
    try:
        opts, args = getopt.getopt(argv[1:], OPTIONS)
    except getopt.GetoptError as e:
        print(e)
        usage(argv[0])
    for opt, optarg in opts:
        if opt == "-i":
            INTERFACE = optarg
        elif opt == "-f":
            HOSTFILE = optarg
        elif opt == "-h":
            print("DnsPoison: A dns poisoner used to intercept DNS traffic")
            usage(argv[0], 0)
        else:
            usage(argv[0])
    EXPRESSION = " ".join(map(str, args))
    #open hostfile and put it into dictionary
    try:
    	if HOSTFILE:
	    	with open(HOSTFILE, "r") as f:
	    		hosts = f.readlines()
    	poison(iface=INTERFACE, hosts=hosts, expression=EXPRESSION)
    	raise KeyboardInterrupt
    except KeyboardInterrupt:
        print("Finished spoofing packets from interface.")
        retval = 0
    except (OSError, IOError) as e:
    	print(e, file=sys.stderr)
    	print("DnsPoison: Unable to read the hostnames file '%s'" % HOSTFILE, file=sys.stderr)
    	retval = 1
    except PermissionError as e:
        print(e, file=sys.stderr)
        print("DnsPoison: Please run %s with root permissions" % argv[0], file=sys.stderr)
        retval = 1
    except BaseException as e:
        print("DnsPoison: Fatal error has occured...", file=sys.stderr)
        print(e, file=sys.stderr)
        print("Exiting...", file=sys.stderr)
        retval = 1
    finally:
    	sys.exit(retval)

if __name__ == "__main__":
    main(sys.argv)