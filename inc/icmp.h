#ifndef ICMP_HEADER
#define ICMP_HEADER

#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/inet.h>
#include <linux/netdevice.h>

#include "debug.h"
#include "args.h"



#define ICMP_HSIZE 8
#define IP_HSIZE 20


// returns the icmp with given payload string to the sender (using the given device)
int return_icmp(char* string, struct icmphdr* icmph, struct iphdr* iph, struct net_device* dev);


// sends icmp to the ECHO packet sender, frees the packet and args structure
void send_response(char* string, args_t* args);


#endif