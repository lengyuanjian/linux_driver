#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include "to_string.h"


static struct nf_hook_ops nfho_pre_routing;

static struct nf_hook_ops nfho_local_out;

 

#define str_to_ip(a, b, c, d) htonl((a << 24) | (b << 16) | (c << 8) | d)

 

static int netfilter_event_input_tcp(struct ethhdr *mac_header, struct iphdr *ip_header, struct tcphdr* tcp_header)
{
    if(ntohs(tcp_header->dest) == 22 || ntohs(tcp_header->source) == 22)
    {
        return NF_ACCEPT;
    }
    printk(KERN_INFO "tcp [%u.%u.%u.%u:%d] -> ip[%u.%u.%u.%u:%d] ip len[%u]\n"
            ,ip_header->saddr & 0xFF, (ip_header->saddr >> 8) & 0xFF,(ip_header->saddr >> 16) & 0xFF,(ip_header->saddr >> 24) & 0xFF 
            , ntohs(tcp_header->source)
            ,ip_header->daddr & 0xFF,(ip_header->daddr >> 8) & 0xFF,(ip_header->daddr >> 16) & 0xFF,(ip_header->daddr >> 24) & 0xFF  
            , ntohs(tcp_header->dest) 
            , ntohs(ip_header->tot_len)
        );
    return NF_ACCEPT;
}
static int netfilter_event_output_tcp(struct ethhdr *mac_header, struct iphdr *ip_header, struct tcphdr* tcp_header)
{
    if(ntohs(tcp_header->dest) == 22 || ntohs(tcp_header->source) == 22)
    {
        return NF_ACCEPT;
    }
    printk(KERN_INFO "tcp [%u.%u.%u.%u:%d] <- ip[%u.%u.%u.%u:%d] ip len[%u]\n"
            ,ip_header->daddr & 0xFF,(ip_header->daddr >> 8) & 0xFF,(ip_header->daddr >> 16) & 0xFF,(ip_header->daddr >> 24) & 0xFF  
            , ntohs(tcp_header->dest) 
            ,ip_header->saddr & 0xFF, (ip_header->saddr >> 8) & 0xFF,(ip_header->saddr >> 16) & 0xFF,(ip_header->saddr >> 24) & 0xFF 
            , ntohs(tcp_header->source)
            , ntohs(ip_header->tot_len)
        );
    return NF_ACCEPT;
}
static int netfilter_event_input_udp(struct ethhdr *mac_header, struct iphdr *ip_header, struct udphdr* udp_header)
{
    printk(KERN_INFO "tcp [%u.%u.%u.%u:%d] -> ip[%u.%u.%u.%u:%d] ip len[%u] udp len[%u]\n"
            ,ip_header->saddr & 0xFF, (ip_header->saddr >> 8) & 0xFF,(ip_header->saddr >> 16) & 0xFF,(ip_header->saddr >> 24) & 0xFF 
            , ntohs(udp_header->source)
            ,ip_header->daddr & 0xFF,(ip_header->daddr >> 8) & 0xFF,(ip_header->daddr >> 16) & 0xFF,(ip_header->daddr >> 24) & 0xFF  
            , ntohs(udp_header->dest) 
            , ntohs(ip_header->tot_len), ntohs(udp_header->len)
        );
    return NF_ACCEPT;
}
static int netfilter_event_output_udp(struct ethhdr *mac_header, struct iphdr *ip_header, struct udphdr* udp_header)
{
    printk(KERN_INFO "tcp [%u.%u.%u.%u:%d] <- ip[%u.%u.%u.%u:%d] ip len[%u] udp len[%u]\n"
            ,ip_header->daddr & 0xFF,(ip_header->daddr >> 8) & 0xFF,(ip_header->daddr >> 16) & 0xFF,(ip_header->daddr >> 24) & 0xFF  
            , ntohs(udp_header->dest) 
            ,ip_header->saddr & 0xFF, (ip_header->saddr >> 8) & 0xFF,(ip_header->saddr >> 16) & 0xFF,(ip_header->saddr >> 24) & 0xFF 
            , ntohs(udp_header->source)
            , ntohs(ip_header->tot_len), ntohs(udp_header->len)
        );
    return NF_ACCEPT;
}

static unsigned int capture_packet_pre_routing(const struct nf_hook_ops *ops,
			       struct sk_buff *skb, const struct net_device *in, const struct net_device *out,
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
         
    if (skb->protocol == htons(ETH_P_IP) ) 
    {
        mac_header = (struct ethhdr *)skb_mac_header(skb);
        ip_header = (struct iphdr *)skb_network_header(skb);

        if(ip_header->protocol == 6)
        {
            tcp_header = (struct tcphdr*)skb_transport_header(skb);
            return netfilter_event_input_tcp(mac_header, ip_header, tcp_header);
        }
        else if(ip_header->protocol == 0x11)
        {
            udp_header = (struct udphdr*)skb_transport_header(skb);
            return netfilter_event_input_udp(mac_header, ip_header, udp_header);
        }
    }
 
    return NF_ACCEPT;
}

static unsigned int capture_packet_local_out(const struct nf_hook_ops *ops,
			       struct sk_buff *skb, const struct net_device *in, const struct net_device *out,
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
    
    
    if (skb->protocol == htons(ETH_P_IP) ) 
    {
        mac_header = (struct ethhdr *)skb_mac_header(skb);
        ip_header = (struct iphdr *)skb_network_header(skb);
       
        if(ip_header->protocol == 6)
        {
            tcp_header = (struct tcphdr*)skb_transport_header(skb);
            return netfilter_event_output_tcp(mac_header, ip_header, tcp_header);
        }
        else if(ip_header->protocol == 0x11)
        {
            udp_header = (struct udphdr*)skb_transport_header(skb);
            return netfilter_event_output_udp(mac_header, ip_header, udp_header);
        }
    }
 
    return NF_ACCEPT;
}


static int __init hello_init(void)
{
    nfho_pre_routing.hook = capture_packet_pre_routing;
    nfho_pre_routing.hooknum = NF_INET_PRE_ROUTING;
    nfho_pre_routing.pf = PF_INET;
    nfho_pre_routing.priority = NF_IP_PRI_FIRST;
    nf_register_hook(&nfho_pre_routing);

     

    nfho_local_out.hook = capture_packet_local_out;
    nfho_local_out.hooknum = NF_INET_LOCAL_OUT;
    nfho_local_out.pf = PF_INET;
    nfho_local_out.priority = NF_IP_PRI_FIRST;
    nf_register_hook(&nfho_local_out);
 
    printk(KERN_INFO "lyj hook Hello World!\n");
    return 0;
}

static void __exit hello_exit(void)
{
    nf_unregister_hook(&nfho_pre_routing);
 
    nf_unregister_hook(&nfho_local_out);
 
    printk(KERN_INFO "lyj hook Goodbye World!\n");
}

module_init(hello_init);
module_exit(hello_exit);
MODULE_LICENSE("GPL");