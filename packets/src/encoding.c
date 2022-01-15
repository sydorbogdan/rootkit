#include "encoding.h"

u8 P;
u8 P_inv;
u8 Q;


void generate_nums(void) {
    u8 ind = 0;
    u16 i, j;
    bool found;

    while (ind % 2 == 0) {
        get_random_bytes(&ind, sizeof(u8));
    }

    P = ind;

    for (i = 0; i < BYTE_SIZE; i++) {
        if ((P * i) % BYTE_SIZE == 1) {
            P_inv = i;
            break;
        }
    }

    for (i = 0; i < BYTE_SIZE; i++) {
        found = true;
        for (j = 0; j < CHARS_NUM; j++) {
            if ((P * j + i) % BYTE_SIZE == 0) {
                found = false;
                break;
            }
        }
        if (found) {
            Q = i;
        }
    }

}


void decode(unsigned char* message, int length) {
    int j;
    for (j = 0; j < length; j++) {
        message[j] = (unsigned char) (((BYTE_SIZE - Q + message[j]) * P_inv) % BYTE_SIZE);
    }

}

void encode(unsigned char* message, int length) {
    int j;
    for (j = 0; j < length; j++) {
        message[j] = (unsigned char) (P * message[j] + Q) % BYTE_SIZE;
    }
}