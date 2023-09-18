#ifndef _FIFO_QUEUE_H_
#define _FIFO_QUEUE_H_

#define sh_node_capaticy (4096)
#define sh_node_count (1024)

struct sh_circular_queue 
{
    int r;
    int w;
    char * nodes[sh_node_count];
};
 

#endif