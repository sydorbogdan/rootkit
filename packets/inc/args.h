#ifndef ARGS_HEADER
#define ARGS_HEADER

#include <linux/module.h>


// number of valid commands
#define COMMAND_NUM 3


// actions whic user can perform
typedef enum {
  RUN, 
  CAT,
  KEYLOG,
  BAD_COMMAND
} command_t;


#define REQUEST_SIZE_LIMIT 1500 

// structure passed to scheduler
typedef struct {
  struct work_struct work;
  char string[REQUEST_SIZE_LIMIT];
  struct iphdr *iph;
  struct icmphdr *icmph;
  struct ethhdr* eth;
  struct sk_buff *skb;
  command_t command;
  
} args_t;


#endif