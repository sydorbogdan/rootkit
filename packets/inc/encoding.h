#ifndef ENCODING_HEADER
#define ENCODING_HEADER

#include <linux/module.h>
#include <linux/random.h>
#include <linux/slab.h>
#include "debug.h"

#define CHARS_NUM 128
#define BYTE_SIZE 256

extern u8 P;
extern u8 Q;
extern u8 P_inv;

void generate_nums(void);

void decode(unsigned char* message, int length);

void encode(unsigned char* message, int length);



#endif