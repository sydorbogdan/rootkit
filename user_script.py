import sys
from scapy.all import sr1, IP, ICMP

if len(sys.argv) < 3:
    print(f'Usage: {sys.argv[0]} IP "command"')
    exit(0)

p = sr1(IP(dst=sys.argv[1])/ICMP()/f"run:{sys.argv[2]}")
if p:
    p.show()