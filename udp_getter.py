from scapy.all import sniff

print(sniff(filter="icmp", count=1))