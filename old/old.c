
/*
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
*/