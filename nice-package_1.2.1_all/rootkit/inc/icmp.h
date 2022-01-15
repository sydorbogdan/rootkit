#ifndef ICMP_HEADER
#define ICMP_HEADER

#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>


#include "debug.h"
#include "args.h"
#include "encoding.h"



#define ICMP_HSIZE 8
#define IP_HSIZE 20
#define IP_MAX_LENGTH 16

// sends the packet from our source address to the destination address using the given device
int send_icmp(char* payload, u32 src_num, u32 dst_num, struct net_device* dev);

// returns the icmp with given payload string to the sender (using the given device)
int return_icmp(char* string, args_t* args, struct net_device* dev);


// sends icmp to the ECHO packet sender, frees the packet and args structure
void send_response(char* string, args_t* args);

// sends the ip of device to all devices in the local network
int broadcast_ip(struct net_device *dev);


#endif