#ifndef DEBUG_HEADER
#define DEBUG_HEADER

#include "linux/module.h"


#define DEBUG

#ifdef DEBUG
#define DEBUG_PRINTF(format, ...) printk(KERN_INFO format, __VA_ARGS__);
#define DEBUG_PUTS(string) printk(KERN_INFO string);
#else
#define DEBUG_PRINTF(format, ...) 
#define DEBUG_PUTS(string)
#endif

#endif