#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <asm/unistd.h>
#include <linux/kthread.h>
#include <linux/kprobes.h>
#include <linux/fprobe.h>

static struct kretprobe kretp = {
        .maxactive = 20
};

struct getdent64_arguments {
    unsigned long fd;
    unsigned long buffer_ptr;
    unsigned long count;
};

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
    args->buffer_ptr = regs->si; // 1
    args->count = regs->dx; // 2

    pr_info("getdents64(fd=%ld, buffer_ptr=%ld, count=%ld)\n", args->fd, args->buffer_ptr, args->count);
    return 0;
}

static int handle_post(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct getdent64_arguments* args = (struct getdent64_arguments*) ri->data;
    unsigned long retval = regs_return_value(regs);
    pr_info("getdents64 fd=%ld return = %ld\n", args->fd, retval);
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