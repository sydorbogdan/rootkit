#ifndef ARGS_HEADER
#define ARGS_HEADER

#include <linux/module.h>

#define REQUEST_SIZE_LIMIT 1500 

// structure passed to scheduler
typedef struct {
  struct work_struct work;
  char string[REQUEST_SIZE_LIMIT];
  struct iphdr *iph;
  struct icmphdr *icmph;
  struct sk_buff *skb;
} args_t;


#endif