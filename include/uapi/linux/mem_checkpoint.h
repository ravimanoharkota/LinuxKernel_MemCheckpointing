#ifndef _UAPI_LINUX_MEM_CHECKPOINT_H
#define _UAPI_LINUX_MEM_CHECKPOINT_H

#include <linux/kernel.h>

struct page_info
{
    /* use physical start address as ideneity of a page */
    unsigned long index;
    /* the offset of current page in this file */
    __u8 offset; 
};

struct file_index
{
    /* number of pages */
    __u8 num; 
};

#define MAX_FILE_NUM 512
#define MAX_NAME_LEN 512

#endif