#include <linux/module.h>
#include <linux/kernel.h>

static int __init entrypoint(void){
    return 0;
}

static void __exit cleanup(void){

}

module_init(entrypoint)
module_exit(cleanup)
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Yarin");
MODULE_DESCRIPTION("Test Module");