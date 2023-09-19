#ifndef _FIFO_QUEUE_H_
#define _FIFO_QUEUE_H_

#define sh_node_capaticy (4096)
#define sh_node_count (1024)

struct sh_node
{
    char *  buff;
    int     capaticy;
    int     data_len;
};

struct sh_circular_queue 
{
    int r;
    int w;
    sh_node * nodes[sh_node_count];
};


int sh_queue_init(struct sh_circular_queue * p_queue)
{
    return 0;
}

sh_node * sh_queue_get_free_node(struct sh_circular_queue * p_queue)
{
    return p_queue->nodes[p_queue->w];
}

void sh_queue_push_node()
{
    p_queue->w++;
}

sh_node * sh_queue_get_free_node(struct sh_circular_queue * p_queue)
{
    return p_queue->nodes[p_queue->r];
}

void sh_queue_pop_node()
{
    p_queue->r++;
}

#endif