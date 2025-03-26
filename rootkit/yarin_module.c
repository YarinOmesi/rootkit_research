#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <asm/unistd.h>
#include <linux/kthread.h>
#include <linux/kprobes.h>
#include <linux/fprobe.h>

static struct kprobe kp;

static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    //
    unsigned long n = regs->ax;
    regs = ((struct pt_regs*)regs->di);
    // Access the third argument of the getdents64 syscall on x86_64

    unsigned long number = regs->ax;
    unsigned long count = regs->dx;
    printk("kprobe: getdents64 called with count = %ld, syscall = %ld, %ld\n", count, number, n);
    return 0;
}

static void handle_post(struct kprobe * p, struct pt_regs * regs,
                       unsigned long flags)
{
    regs = ((struct pt_regs*)regs->di);
    unsigned long count = regs->dx;
    printk("kprobe: getdents64 return = %ld\n", count);
    return 0;
}

static int __init entrypoint(void)
{
    kp.pre_handler = handler_pre;
    kp.post_handler = handle_post;
    kp.symbol_name = "__x64_sys_getdents64";

    if (register_kprobe(&kp) < 0) {
        printk("register_kprobe failed\n");
        return -1;
    }
    printk("kprobe registered\n");
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