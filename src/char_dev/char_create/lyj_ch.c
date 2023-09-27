#include <linux/fs.h>       //register_chrdev()
#include <linux/module.h>   //module_init()
#include <linux/device.h>   // class_create()
#include <linux/slab.h> // 包含内存分配函数的头文件
#include <linux/delay.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/mutex.h>

#include "sh_private_data.h"

static int major = 0;
static struct class * device_class = NULL;
static struct device * device_node = NULL;

const char * driver_name = "lyj_char_deiver_name";
const char * class_name = "lyj_char_class_name";

struct sh_rule rule_head={};
static DEFINE_MUTEX(open_mutex);

static struct task_struct *my_thread = NULL;

static int my_thread_func(void *data)
{
    struct sh_rule * rule_rule = rule_head.next;
    char buf[128];
    int i = 0;
    while (!kthread_should_stop())
     {
        // 在这里执行内核线程的工作
        // 例如，处理系统级任务或驱动程序工作
        memset(buf,0, sizeof(buf));
        i = 0;
        mutex_lock(&open_mutex);
        rule_rule = rule_head.next;
        while(rule_rule)
        {
            i += snprintf(buf + i, sizeof(buf) - i, "id[%d] ", rule_rule->id);
            rule_rule = rule_rule->next;
        }
        mutex_unlock(&open_mutex);
        if(i > 0)
        {
            printk(KERN_INFO "%s\n",buf);
        }
        msleep(1000);
    }
    return 0;
}

static int char_device_open(struct inode *inode, struct file *file)
{
    // 处理设备打开操作
    static int rule_id = 0;
    struct sh_rule * rule_rule = NULL;
    struct sh_rule * rule = (struct sh_rule *)kzalloc(sizeof(struct sh_rule), GFP_KERNEL);
    mutex_lock(&open_mutex);
    file->private_data = rule;
    rule_id = (rule_id + 1) % 65536;
    rule->id = rule_id;
    rule_rule = &rule_head;
    while(rule_rule->next)
    {
        rule_rule = rule_rule->next;
    }
    rule_rule->next = rule;
    rule->prev = rule_rule;
    rule->next= NULL;
    printk(KERN_INFO "lyj function: %s rule_id[%d] prev[%x] rule[%x]\n", __func__, rule->id, rule_rule,rule);
    mutex_unlock(&open_mutex);
    return 0;
}

static int char_device_release(struct inode *inode, struct file *file)
{
    struct sh_rule * rule;
    mutex_lock(&open_mutex);
    rule =(struct sh_rule *)file->private_data;
    if(rule)
    {   
        printk(KERN_INFO "lyj function: %s rule_id[%d] prev[%x] rule[%x] next[%x]\n", __func__, rule->id, rule->prev ,rule ,rule->next);
        rule->prev->next = rule->next;
        if(rule->next)
        {
            rule->next->prev =  rule->prev;
        }
        //rule->next = NULL;
        kfree(rule);
    }
    file->private_data = NULL;
    mutex_unlock(&open_mutex);
    // 处理设备关闭操作
    return 0;
}

static ssize_t char_device_read(struct file *file, char __user *buf, size_t len, loff_t *offset)
{
    printk(KERN_INFO "lyj function: %s\n", __func__);
    // 处理读取操作
    return 0;
}

static ssize_t char_device_write(struct file *file, const char __user *buf, size_t len, loff_t *offset)
{
    printk(KERN_INFO "lyj function: %s\n", __func__);
    // 处理写入操作
    return len; // 返回写入的字节数
}
static long char_device_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    // switch (cmd) 
    // {
    //     case 0:
    //         break;
    //     default:
    //     printk(KERN_INFO "Device my_device_ioctl ENOTTY\n");
    //         return -ENOTTY; // 不支持的命令
    // }
    
    return 0; // 返回0表示成功
}
static int char_mmap(struct file *file, struct vm_area_struct *vma)
{
    return 0;
}
struct file_operations _fs = {
    .owner = THIS_MODULE,
    .open = char_device_open,
    .release = char_device_release,
    .read = char_device_read,
    .write = char_device_write,
    .unlocked_ioctl = char_device_ioctl,
    .mmap = char_mmap,
};

static int __init char_device_init(void)
{
    major = register_chrdev(0, driver_name, &_fs);
    if(major < 0)
    {
        printk(KERN_INFO "register_chrdev failed. driver name[%s] major[%d]\n", driver_name, major);
        return -EINVAL;
    }
    device_class = class_create(THIS_MODULE, class_name);
    if(IS_ERR(device_class))
    {
        unregister_chrdev(major, driver_name);
        printk(KERN_INFO "class_create failed. class name[%s]\n", class_name);
        return PTR_ERR(device_class);
    }
    device_node = device_create(device_class, NULL, MKDEV(major,0), NULL, driver_name);
    if(IS_ERR(device_node))
    {
        class_destroy(device_class);
        unregister_chrdev(major, driver_name);
        printk(KERN_INFO "device_create failed. major[%d] class name[%s] driver name[%s]\n", major, class_name, driver_name);
        return PTR_ERR(device_node);
    }
    rule_head.next = NULL;
    rule_head.prev = NULL;
    // 创建内核线程
    my_thread = kthread_run(my_thread_func, NULL, "my_thread");
    if (IS_ERR(my_thread)) 
    {
        pr_err("Failed to create kernel thread\n");
        return PTR_ERR(my_thread);
    }
    printk(KERN_INFO "lyj char_device_init!\n");
    return 0;
}

static void __exit char_device_exit(void)
{
    // struct sh_rule * rule_rule = rule_head.next;
    // struct sh_rule * free_rule;
    // while(rule_rule)
    // {
    //     free_rule = rule_rule;
    //     rule_rule = rule_rule->next;
    //     printk(KERN_INFO "free id[%d]!\n", free_rule->id);
    //     kfree(free_rule);
    // }

    // 停止内核线程
    if (my_thread) {
        kthread_stop(my_thread);
        my_thread = NULL;
    }

    device_destroy(device_class, MKDEV(major,0));
    class_destroy(device_class);
    unregister_chrdev(major, driver_name);
    printk(KERN_INFO "lyj char_device_exit!\n");
}


module_init(char_device_init);
module_exit(char_device_exit);

MODULE_LICENSE("GPL");