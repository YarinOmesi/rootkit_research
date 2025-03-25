#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>

static int __init entrypoint(void){
    pr_info("Yarin Module EntryPoint");
    return 0;
}

static void __exit cleanup(void){
    pr_info("Yarin Module cleanup");
}

module_init(entrypoint)
module_exit(cleanup)
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Yarin");
MODULE_DESCRIPTION("Test Module");