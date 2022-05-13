/*
 * arch/e2k/include/asm/kvm/ctx_signal_stacks.h
 *
 * This file contains interfaces for managing of separate signal stacks
 * for guest's contexts
 *
 * Copyright 2022 Andrey Alekhin (Andrey.I.Alekhin@mcst.ru)
 */

#ifndef CTX_SIGNAL_STACKS
#define CTX_SIGNAL_STACKS

#include <linux/rhashtable-types.h>

#include <asm/thread_info.h>

enum {
	CTX_STACK_READY = 0U, /* Stack is free to take */
	CTX_STACK_BUSY = 1U, /* Stack is currently busy by thread */
	CTX_STACK_COPYING = 2U /* Stack is being copied in fork() */
};

struct rhashtable *alloc_gst_ctx_sig_stacks_ht(void);
void free_gst_ctx_sig_stacks_ht(struct rhashtable *ht);
struct rhashtable *copy_gst_ctx_sig_stacks_ht(void);
int add_gst_ctx_signal_stack(struct rhashtable *ht,
			struct signal_stack *signal_stack,
			u64 key, int state);
void remove_gst_ctx_signal_stack(u64 key);
int switch_gst_ctx_signal_stack(u64 to_key);
int update_curr_gst_signal_stack(void);

#endif /* CTX_SIGNAL_STACKS */
