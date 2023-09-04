#include "to_string.h"
#include <linux/ip.h>
#include <linux/tcp.h>

void ip_to_string(char * buf,const int size,const struct iphdr * head) 
{
    snprintf(buf, size,
           "Version: %d\n"
           "IHL: %d\n"
           "TOS: %d\n"
           "Total Length: %d\n"
           "ID: %d\n"
           "Fragment Offset: 0x%04x\n"
           "TTL: %d\n"
           "Protocol: %d\n"
           "Checksum: 0x%04X\n"
           "Source IP: %u.%u.%u.%u\n"
           "Destination IP: %u.%u.%u.%u\n",
           head->version,
           head->ihl,
           head->tos,
           ntohs(head->tot_len),
           ntohs(head->id),
           ntohs(head->frag_off),
           //head.frag_off ,
           head->ttl,
           head->protocol,
           ntohs(head->check),
            head->saddr & 0xFF, (head->saddr >> 8) & 0xFF,(head->saddr >> 16) & 0xFF,(head->saddr >> 24) & 0xFF,
            head->daddr & 0xFF,(head->daddr >> 8) & 0xFF,(head->daddr >> 16) & 0xFF,(head->daddr >> 24) & 0xFF );
}