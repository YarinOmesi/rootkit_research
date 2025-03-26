#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fprobe.h>
#include <linux/ftrace.h>
#include <linux/kprobes.h>

static char symbol[KSYM_NAME_LEN] = "kernel_clone";


static struct kprobe kp = {
        .symbol_name	= symbol,
};

static int __kprobes handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    pr_info("<%s> p->addr = 0x%p, ip = %lx, flags = 0x%lx\n",
            p->symbol_name, p->addr, regs->ip, regs->flags);

    return 0;
}

static void __kprobes handler_post(struct kprobe *p, struct pt_regs *regs,
                                   unsigned long flags)
{
    pr_info("<%s> p->addr = 0x%p, flags = 0x%lx\n",
            p->symbol_name, p->addr, regs->flags);
}

static int __init entrypoint(void){
    int ret;
    pr_info("Yarin Module EntryPoint\n");
    kp.pre_handler = handler_pre;
    kp.post_handler = handler_post;

    ret = register_kprobe(&kp);
    if (ret < 0) {
        pr_err("register_kprobe failed, returned %d\n", ret);
        return ret;
    }
    pr_info("Planted kprobe at %p\n", kp.addr);
    return 0;
}

static void __exit cleanup(void){
    unregister_kprobe(&kp);
    pr_info("kprobe at %p unregistered\n", kp.addr);
}

module_init(entrypoint)
module_exit(cleanup)
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Yarin");
MODULE_DESCRIPTION("Test Module");