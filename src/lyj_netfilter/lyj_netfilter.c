#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include "to_string.h"

static struct nf_hook_ops nfho;
static char str_buf[2048] = {};

#define str_to_ip(a, b, c, d) htonl((a << 24) | (b << 16) | (c << 8) | d)

static unsigned int capture_packet(const struct nf_hook_ops *ops,
			       struct sk_buff *skb,
			       const struct net_device *in,
			       const struct net_device *out,
#ifndef __GENKSYMS__
			       const struct nf_hook_state *state
#else
			       int (*okfn)(struct sk_buff *)
#endif
			       )
{
    struct ethhdr *mac_header;
    struct iphdr *ip_header;
    struct tcphdr* tcp_header;
    struct udphdr* udp_header;
    int pos = 0;
    
    if (skb->protocol == htons(ETH_P_IP) ) 
    {
        mac_header = (struct ethhdr *)skb_mac_header(skb);
        ip_header = (struct iphdr *)skb_network_header(skb);
        str_buf[0] = 0;
        pos = 0;
        pos += mac_to_string(str_buf + pos, 2048 - pos, mac_header);
        str_buf[pos++] = '\n';
        pos += ip_to_string(str_buf + pos, 2048 - pos, ip_header);
        str_buf[pos++] = '\n';
        if(ip_header->protocol == 6)
        {
            tcp_header = (struct tcphdr*)skb_transport_header(skb);
            if(ntohs(tcp_header->source) != 22 && ntohs(tcp_header->dest) != 22)
            {
                pos += tcp_to_string(str_buf + pos, 2048 - pos, tcp_header);
                str_buf[pos++] = '\n';
                str_buf[pos] = 0;
                printk(KERN_INFO "%s", str_buf);
            }
        }
        else if(ip_header->protocol == 0x11)
        {
            udp_header = (struct udphdr*)skb_transport_header(skb);
            if(ntohs(udp_header->source) != 22 && ntohs(udp_header->dest) != 22)
            {
                pos += udp_to_string(str_buf + pos, 2048 - pos, udp_header);
                str_buf[pos++] = '\n';
                str_buf[pos] = 0;
                printk(KERN_INFO "%s", str_buf);
            }
        }
    }
 
    return NF_ACCEPT;
}

static int __init hello_init(void)
{
    nfho.hook = capture_packet;
    nfho.hooknum = NF_INET_PRE_ROUTING;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;
    nf_register_hook(&nfho);
    printk(KERN_INFO "lyj hook Hello World!\n");
    return 0;
}

static void __exit hello_exit(void)
{
    nf_unregister_hook(&nfho);
    printk(KERN_INFO "lyj hook Goodbye World!\n");
}

module_init(hello_init);
module_exit(hello_exit);
MODULE_LICENSE("GPL");