#ifndef _TO_STRING_H_
#define _TO_STRING_H_
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/if_ether.h>
#include <linux/udp.h>
extern int mac_to_string(char * buf, const int size, const struct ethhdr * head);
extern int ip_to_string(char  * buf, const int size, const struct iphdr  * head);
extern int tcp_to_string(char * buf, const int size, const struct tcphdr * head);
extern int udp_to_string(char * buf, const int size, const struct udphdr * head);

#endif