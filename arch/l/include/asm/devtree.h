#ifndef _ASM_L_DEVTREE_H
#define _ASM_L_DEVTREE_H
#include <linux/types.h>
int device_tree_init(void);
void get_dtb_from_boot(u8*, u32);
u32 get_dtb_size(void);
extern int devtree_detected;

#ifdef CONFIG_DTB_L_TEST
extern unsigned char test_blob[];
#endif

#endif /* _ASM_L_DEVTREE_H */
