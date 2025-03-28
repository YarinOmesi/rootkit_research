#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <asm/unistd.h>
#include <linux/kthread.h>
#include <linux/kprobes.h>
#include <linux/fprobe.h>

static struct kprobe kp;

static int __kprobes handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    // syscall wrappers __x64_sys_* gets only ptr to regs
    regs = ((struct pt_regs*)regs->di);

    unsigned long syscall = regs->orig_ax;
    unsigned long fd = regs->di; // 0
    unsigned long buffer_ptr = regs->si; // 1
    unsigned long count = regs->dx; // 2

    pr_info("getdents64(fd=%ld, buffer_ptr=%ld, count=%ld)\n",fd, buffer_ptr, count);
    return 0;
}

static void __kprobes handle_post(struct kprobe * p, struct pt_regs * regs,
                       unsigned long flags)
{
    regs = ((struct pt_regs*)regs->di);
    unsigned long count = regs->dx;
    pr_info("getdents64 return = %ld\n", count);
}

static int __init entrypoint(void)
{
    kp.pre_handler = handler_pre;
    kp.post_handler = handle_post;
    kp.symbol_name = "__x64_sys_getdents64";

    if (register_kprobe(&kp) < 0) {
        pr_info("register_kprobe failed\n");
        return -1;
    }
    pr_info("kprobe registered\n");
    pr_info("Yarin Module end\n");
    return 0;
}

static void __exit cleanup(void){
    unregister_kprobe(&kp);
    pr_info("Yarin Module cleanup\n");
}

module_init(entrypoint)
module_exit(cleanup)
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Yarin");
MODULE_DESCRIPTION("Test Module");