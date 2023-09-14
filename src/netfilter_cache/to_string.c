#include "to_string.h"
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>


int mac_to_string(char *buf, const int size, const struct ethhdr *head)
{
    int ret = 0;

    ret = snprintf(buf, size, "mac[%02X:%02X:%02X:%02X:%02X:%02X] -> mac[%02X:%02X:%02X:%02X:%02X:%02X] type[%04X]"
        , head->h_source[0],head->h_source[1],head->h_source[2],head->h_source[3],head->h_source[4],head->h_source[5]
        , head->h_dest[0],head->h_dest[1],head->h_dest[2],head->h_dest[3],head->h_dest[4],head->h_dest[5]
        , ntohs(head->h_proto) );
    
    return ret;
}

int ip_to_string(char *buf, const int size, const struct iphdr *head)
{
    int ret = 0;
    
    ret = snprintf(buf, size,
           "ip [%u.%u.%u.%u] -> ip[%u.%u.%u.%u] head:[%d*4] total:[%d] "
           "ver:%d tos:%d 16bit:%d fmgt off:0x%04x "
           "ttl:%d pro:[%d] check:0x%04X "
           ,head->saddr & 0xFF, (head->saddr >> 8) & 0xFF,(head->saddr >> 16) & 0xFF,(head->saddr >> 24) & 0xFF
           ,head->daddr & 0xFF,(head->daddr >> 8) & 0xFF,(head->daddr >> 16) & 0xFF,(head->daddr >> 24) & 0xFF 
           ,head->ihl
           ,ntohs(head->tot_len)
           ,head->version
           ,head->tos
           ,ntohs(head->id)
           ,ntohs(head->frag_off)
           //head.frag_off ,
           ,head->ttl
           ,head->protocol
           ,ntohs(head->check)
            );

    return ret;
}

int tcp_to_string(char * buf, const int size,const struct tcphdr * head)
{
    int ret = 0;
    
    ret = snprintf(buf, size,"tcp port[%u] -> port[%u] "
           "seq:%u ask seq:%u "
           "Data Offset:%u "
           "BIT:[FIN:%u, SYN:%u, RST:%u, PSH:%u, ACK:%u, URG:%u] "
           "window:%u "
           "cksum:0x%04X ptr:%u\n",
           ntohs(head->source),
           ntohs(head->dest),
           ntohl(head->seq),
           ntohl(head->ack_seq),
           head->doff,
           head->fin,
           head->syn,
           head->rst,
           head->psh,
           head->ack,
           head->urg,
           ntohs(head->window),
           ntohs(head->check),
           ntohs(head->urg_ptr));

    return ret;
}

int udp_to_string(char *buf, const int size, const struct udphdr *head)
{
    int ret = 0;
    
    ret = snprintf(buf, size,"udp port[%u] -> port[%u] len[%u] check[%u]",
           ntohs(head->source),
           ntohs(head->dest),
           ntohs(head->len),
           ntohs(head->check));

    return ret;
}

/*
    struct iphdr
    {
    #if defined(__LITTLE_ENDIAN_BITFIELD)
        __u8	ihl:4, //首部长度
            version:4; //协议版本
    #elif defined (__BIG_ENDIAN_BITFIELD)
        __u8	version:4,
            ihl:4;
    #else
    #error	"Please fix <asm/byteorder.h>"
    #endif
        __u8	tos;
        __be16	tot_len;
        __be16	id;
        __be16	frag_off;
        __u8	ttl;
        __u8	protocol;
        __sum16	check;
        __be32	saddr;
        __be32	daddr;

    };
*/
/*
    struct tcphdr {
    __be16	source;
    __be16	dest;
    __be32	seq;
    __be32	ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u16	res1:4,
        doff:4,
        fin:1,
        syn:1,
        rst:1,
        psh:1,
        ack:1,
        urg:1,
        ece:1,
        cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
    __u16	doff:4,
        res1:4,
        cwr:1,
        ece:1,
        urg:1,
        ack:1,
        psh:1,
        rst:1,
        syn:1,
        fin:1;
#else
#error	"Adjust your <asm/byteorder.h> defines"
#endif
    __be16	window;
    __sum16	check;
    __be16	urg_ptr;
};
struct udphdr {
	__be16	source;
	__be16	dest;
	__be16	len;
	__sum16	check;
};
*/