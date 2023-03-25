#ifndef _E2K_ASM_GETSP_ADJ_H
#define _E2K_ASM_GETSP_ADJ_H

#include <linux/slab.h>

#include <asm/thread_info.h>

/*
 * bug #101468: if user allocated more than 4Gb of stack then %cr1_hi.ussz
 * field would overflow. In this case we remember all such over/underflows
 * in software and apply corresponding corrections to %usd.lo.base manually
 * from exc_last_wish handler.
 *
 * All under/overflows are kept in a single list.
 */
struct getsp_adj {
	struct list_head list_entry;
	unsigned long frame_index;
	int correction;
};


static inline int __copy_getsp_adj(struct list_head *dst,
				 const struct list_head *src)
{
	const struct getsp_adj *p;
	struct getsp_adj *new;

	list_for_each_entry(p, src, list_entry) {
		new = kmalloc(sizeof(*new), GFP_KERNEL);
		if (!new)
			return -ENOMEM;

		new->correction = p->correction;
		new->frame_index = p->frame_index;
		list_add_tail(&new->list_entry, dst);
	}

	return 0;
}

static inline int copy_getsp_adj(struct thread_info *new_ti,
				 const struct thread_info *old_ti)
{
	return __copy_getsp_adj(&new_ti->getsp_adj, &old_ti->getsp_adj);
}

static inline void free_getsp_adj(struct list_head *getsp_adj_list)
{
	struct getsp_adj *p, *tmp;

	list_for_each_entry_safe(p, tmp, getsp_adj_list, list_entry) {
		list_del(&p->list_entry);
		kfree(p);
	}
}

static inline s64 getsp_adj_get_correction(unsigned long frame)
{
	unsigned long frame_index = frame - (u64) CURRENT_PCS_BASE();
	struct getsp_adj *p;

	list_for_each_entry(p, &current_thread_info()->getsp_adj, list_entry) {
		if (p->frame_index == frame_index)
			return (s64) p->correction;
	}

	return 0;
}

static inline int getsp_adj_set_correction(int correction, unsigned long frame)
{
	unsigned long frame_index = frame - (u64) CURRENT_PCS_BASE();
	struct getsp_adj *new, *p;

	list_for_each_entry(p, &current_thread_info()->getsp_adj, list_entry) {
		if (p->frame_index == frame_index) {
			if (correction) {
				p->correction = correction;
			} else {
				list_del(&p->list_entry);
				kfree(p);
			}
			return 0;
		}
	}

	if (!correction)
		return 0;

	new = kmalloc(sizeof(*new), GFP_KERNEL);
	if (!new)
		return -ENOMEM;

	new->correction = correction;
	new->frame_index = frame_index;
	list_add(&new->list_entry, &current_thread_info()->getsp_adj);

	return 0;
}

static inline void getsp_adj_apply(struct pt_regs *regs)
{
	unsigned long frame, frame_index;
	struct getsp_adj *p;

	frame = AS(regs->stacks.pcsp_lo).base + AS(regs->stacks.pcsp_hi).ind;
	frame_index = frame - (u64) CURRENT_PCS_BASE();

	list_for_each_entry(p, &current_thread_info()->getsp_adj, list_entry) {
		if (p->frame_index == frame_index)
			goto found;
	}

	return;

found:
	AS(regs->stacks.usd_lo).base += p->correction * 0x100000000ULL;
	list_del(&p->list_entry);
	kfree(p);
}

#endif
