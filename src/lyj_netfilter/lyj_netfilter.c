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
static char buff[2048]={};
static char str_buf[2048] = {};
#define str_to_ip(a, b, c, d) htonl((a << 24) | (b << 16) | (c << 8) | d)
static void to_string(struct iphdr head) 
{
    char buff[1024] = {};
    ip_to_string(buff, 2048,&head);
    printk(KERN_INFO "strings ip: %s\n", buff);
}
static void tcp_hdr_to_string(const struct tcphdr *tcp) {
    
    snprintf(buff,2048,"-Source Port: %u\n"
           "Destination Port: %u\n"
           "Sequence Number: %u\n"
           "Acknowledgment Number: %u\n"
           "Data Offset: %u\n"
           "Flags: [FIN:%u, SYN:%u, RST:%u, PSH:%u, ACK:%u, URG:%u]\n"
           "Window Size: %u\n"
           "Checksum: 0x%04X\n"
           "Urgent Pointer: %u\n",
           ntohs(tcp->source),
           ntohs(tcp->dest),
           ntohl(tcp->seq),
           ntohl(tcp->ack_seq),
           tcp->doff,
           tcp->fin,
           tcp->syn,
           tcp->rst,
           tcp->psh,
           tcp->ack,
           tcp->urg,
           ntohs(tcp->window),
           ntohs(tcp->check),
           ntohs(tcp->urg_ptr));
           printk(KERN_INFO "%s\n", buff);
}

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
    struct iphdr *ip_header;
    struct tcphdr* tcp_header;
    static int cout=0;
    int tcp_data_len = 0;
    int i = 0;
    
    /* Check if the packet is an IP packet */
    if (skb->protocol == htons(ETH_P_IP) ) {
        /* Get a pointer to the IP header */
        ip_header = (struct iphdr *)skb_network_header(skb);
        if(ip_header->protocol == 6)
        {
            tcp_header = (struct tcphdr*)skb_transport_header(skb);
            //if(ntohs(tcp_header->source) == 12345 || ntohs(tcp_header->dest) == 12345)
            {
                printk(KERN_INFO "****seq:%d************\n", cout++);
                printk(KERN_INFO "Captured packet: %pI4 -> %pI4  len:%d\n", 
                    &ip_header->saddr, &ip_header->daddr,cpu_to_be16(ip_header->tot_len));
                to_string(*ip_header);
                tcp_hdr_to_string(tcp_header);
                tcp_data_len = ntohs(ip_header->tot_len) - ip_header->ihl * 4 - tcp_header->doff * 4;
                
                for(i = 0; i < tcp_data_len; ++i)
                {
                    str_buf[i] = ((char *)(tcp_header))[tcp_header->doff * 4 + i];
                    str_buf[i+1] = 0;
                }
                printk(KERN_INFO "data:len[%d][%s]\n", tcp_data_len, str_buf);
                str_buf[0] = 0;
 
                printk(KERN_INFO "[%d]mac[%08x] ip[%08x] tcp[%08x] head[%08x]data[%08x]\n",(skb->len), skb_mac_header(skb),skb_network_header(skb),skb_transport_header(skb),
                skb->head, skb->data);
                printk(KERN_INFO "len[%d] mac_len[%d] hdr_len[%d] data_len[%d]\n",skb->len, skb->mac_len, skb->hdr_len, skb->data_len);
                 printk(KERN_INFO "[%d][%d][%d] tail[%d]end[%d]\n",    
                    skb->transport_header,
				    skb->network_header,
				    skb->mac_header,
                    skb->tail,
                    skb->end
                    );
			 
            }
        }
    }
    
    /* Continue processing the packet */
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