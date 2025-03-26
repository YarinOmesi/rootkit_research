#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fprobe.h>
#include <linux/ftrace.h>


static int my_entry_handler(struct fprobe *fp, unsigned long entry_ip,
                      unsigned long ret_ip, struct pt_regs *regs,
                      void *entry_data){

    struct ftrace_regs* ftraceRegs = (struct ftrace_regs* ) regs;
    unsigned long syscall_name = ftrace_regs_get_argument(ftraceRegs, 0);
    //char* value = syscall_name;

    pr_info("YarinModule: entry %ld\n", syscall_name);
    return 0;
}

static void my_exit_handler(struct fprobe *fp, unsigned long entry_ip,
                           unsigned long ret_ip, struct pt_regs *regs,
                           void *entry_data){

    pr_info("YarinModule: exit\n");
}
static struct fprobe fp = {
        .entry_handler= my_entry_handler,
        .exit_handler= my_exit_handler
};


static int __init entrypoint(void){
    pr_info("Yarin Module EntryPoint\n");
    register_fprobe(&fp, "syscall", "");
    return 0;
}

static void __exit cleanup(void){
    pr_info("Yarin Module cleanup\n");
    unregister_fprobe(&fp);
}

module_init(entrypoint)
module_exit(cleanup)
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Yarin");
MODULE_DESCRIPTION("Test Module");