#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_arp.h>
#include <uapi/linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/icmp.h>
#include <linux/udp.h>
#include <linux/if_arp.h>

extern char selected_ip[];
extern bool filter_arp;

static unsigned int netfilter_ip_hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    // struct ethhdr *eth = eth_hdr(skb);
    struct iphdr *ip = ip_hdr(skb);

    // printk("caller: %s\n", current->comm);
    // printk("mac: %pM\n", eth->h_source);
    // printk("ip protocol: %d\n", ip->protocol);
    // printk("ip protocol: %d\n", ip->protocol);
    // printk("%pI4 -> %pI4\n", &ip->saddr, &ip->daddr);

    uint32_t ip_source = ip->saddr;
    uint32_t my_ip = *((uint32_t*)&selected_ip);

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

    if(!filter_arp){
        return NF_ACCEPT;
    }

    // only ARP IP request
    if(op != ARPOP_REQUEST || ntohs(arp->ar_pro) != ETH_P_IP){
        return NF_ACCEPT;
    }

    // copy to buffer
    if(skb_copy_bits(skb, sizeof(struct arphdr), (void*)&arp_request, sizeof(struct arp_ip_request)) < 0){
        pr_warn("Cannot copy from packet\n");
        return NF_ACCEPT;
    }

//    pr_info("ARP from %pI4 Searching %pI4\n", arp_request.sender_ip_addr, arp_request.target_ip_addr);

    uint32_t *my_ip = (uint32_t *) selected_ip;
    uint32_t *sender_ip = (uint32_t * ) & arp_request.sender_ip_addr;

    if (*sender_ip == *my_ip) {
        pr_info("DROPING ARP from %pI4 Searching %pI4\n", arp_request.sender_ip_addr, arp_request.target_ip_addr);
        return NF_DROP;
    }

    return NF_ACCEPT;
}


const int net_hook_count = 2;
struct nf_hook_ops net_hooks[2] = {
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
