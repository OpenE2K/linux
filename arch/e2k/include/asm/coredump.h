#ifndef _E2K_COREDUMP_H
#define _E2K_COREDUMP_H
/*
 * For coredump
 */
extern void clear_delayed_free_hw_stacks(struct mm_struct *mm);
extern void create_delayed_free_hw_stacks(void);

#endif /* _E2K_COREDUMP_H */

