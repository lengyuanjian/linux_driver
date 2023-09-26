#ifndef _FIFO_QUEUE_H_
#define _FIFO_QUEUE_H_
#include <linux/slab.h> // 包含内存分配函数的头文件

#define sh_node_capaticy (4096)
#define sh_node_count (1024)

//#define SH_ATOMIC_READ(x) (*(volatile typeof(x) *)&(x))

struct sh_node
{
    union{
        char block[sh_node_capaticy];
        struct{
            int     total_size;
            int     data_size;
            char    buff[0];
        };
    };
};

struct sh_circular_queue 
{
    int total_size;
    int node_count;
    int r;
    int w;
    struct sh_node nodes[0];
};

struct sh_circular_queue * sh_queue_create(int node_count)
{
    int i = 0;
    struct sh_circular_queue * queue_head = (struct sh_circular_queue *)kmalloc(sizeof(struct sh_node) * node_count + sizeof(struct sh_circular_queue), GFP_KERNEL);
    
    if (!queue_head)
    {
        //printk(KERN_ALERT "Failed to allocate memory for the queue.\n");
        return NULL; // 内存分配失败
    }

    queue_head->total_size = sizeof(struct sh_node) * node_count + sizeof(struct sh_circular_queue);
    queue_head->node_count = node_count;
    queue_head->r = 0;
    queue_head->w = 0;

    for(i = 0; i < node_count; ++i)
    {
        queue_head->nodes[i].total_size = sh_node_capaticy;
        queue_head->nodes[i].data_size = 0;
    }
    return queue_head;
}

int sh_queue_is_full(struct sh_circular_queue * p_queue)
{
    int next_w = (p_queue->w + 1) % p_queue->node_count;
    if(next_w == p_queue->w)
    {
        return 0;
    }
    else
    {
        return 1;
    }
}

int sh_queue_is_empty(struct sh_circular_queue * p_queue)
{
    if(p_queue->r == p_queue->w)
    {
        return 0;
    }
    else
    {
        return 1;
    }
}

struct sh_node * sh_queue_get_free_node(struct sh_circular_queue * p_queue)
{
    return p_queue->nodes + p_queue->w;
}

void sh_queue_push_node(struct sh_circular_queue * p_queue)
{
    p_queue->w++;
    p_queue->w %= p_queue->node_count;
}

struct sh_node * sh_queue_front_node(struct sh_circular_queue * p_queue)
{
    return p_queue->nodes + p_queue->r;
}

void sh_queue_pop_node(struct sh_circular_queue * p_queue)
{
    p_queue->r++;
    p_queue->r %= p_queue->node_count;
}

void sh_queue_close(struct sh_circular_queue * p_queue)
{
    kfree(p_queue);
}
#endif