#ifndef _PRIVATE_DATA_H_
#define _PRIVATE_DATA_H_

struct sh_rule
{
    int                 id;
    char                proc_type;
    unsigned int        src_ip;
    unsigned short      src_port;
    unsigned int        dec_ip;
    unsigned short      dec_port;
    struct sh_rule *    prev;
    struct sh_rule *    next;
};

#endif