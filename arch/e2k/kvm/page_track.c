/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Support KVM guest page tracking
 *
 * This feature allows to track page access in guest. Currently, only
 * write access is tracked.
 *
 * Based on arch/x86/kvm/page_track.c of Intel Corporation.
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 */

#include <linux/kvm_host.h>
#include <asm/kvm_host.h>
#include <asm/kvm/page_track.h>

#include "mmu.h"

void kvm_page_track_free_memslot(struct kvm_memory_slot *free)
{
	int i;

	for (i = 0; i < KVM_PAGE_TRACK_MAX; i++) {
		kvfree(free->arch.gfn_track[i]);
		free->arch.gfn_track[i] = NULL;
	}
}

int kvm_page_track_create_memslot(struct kvm_memory_slot *slot,
				  unsigned long npages)
{
	int  i;

	for (i = 0; i < KVM_PAGE_TRACK_MAX; i++) {
		slot->arch.gfn_track[i] = kvzalloc(npages *
					    sizeof(*slot->arch.gfn_track[i]),
					    GFP_KERNEL);
		if (!slot->arch.gfn_track[i])
			goto track_free;
	}

	return 0;

track_free:
	kvm_page_track_free_memslot(slot);
	return -ENOMEM;
}

static inline bool page_track_mode_is_valid(enum kvm_page_track_mode mode)
{
	if (mode < 0 || mode >= KVM_PAGE_TRACK_MAX)
		return false;

	return true;
}

static void update_gfn_track(struct kvm *kvm, struct kvm_memory_slot *slot,
			gfn_t gfn, enum kvm_page_track_mode mode, short count)
{
	int index, val;

	index = mmu_pt_gfn_to_index(kvm, gfn, slot->base_gfn, PT_PAGE_TABLE_LEVEL);

	val = slot->arch.gfn_track[mode][index];

	if (WARN_ON(val + count < 0 || val + count > USHRT_MAX))
		return;

	slot->arch.gfn_track[mode][index] += count;
}

/*
 * add guest page to the tracking pool so that corresponding access on that
 * page will be intercepted.
 *
 * It should be called under the protection both of mmu-lock and kvm->srcu
 * or kvm->slots_lock.
 *
 * @kvm: the guest instance we are interested in.
 * @slot: the @gfn belongs to.
 * @gfn: the guest page.
 * @mode: tracking mode, currently only write track is supported.
 */
void kvm_slot_page_track_add_page(struct kvm *kvm,
				  struct kvm_memory_slot *slot, gfn_t gfn,
				  enum kvm_page_track_mode mode)
{

	if (WARN_ON(!page_track_mode_is_valid(mode)))
		return;

	update_gfn_track(kvm, slot, gfn, mode, 1);

	/*
	 * new track stops large page mapping for the
	 * tracked page.
	 */
	mmu_pt_gfn_disallow_lpage(kvm, slot, gfn);

	if (mode == KVM_PAGE_TRACK_WRITE)
		if (mmu_pt_slot_gfn_write_protect(kvm, slot, gfn))
			kvm_flush_remote_tlbs(kvm);
}

/*
 * remove the guest page from the tracking pool which stops the interception
 * of corresponding access on that page. It is the opposed operation of
 * kvm_slot_page_track_add_page().
 *
 * It should be called under the protection both of mmu-lock and kvm->srcu
 * or kvm->slots_lock.
 *
 * @kvm: the guest instance we are interested in.
 * @slot: the @gfn belongs to.
 * @gfn: the guest page.
 * @mode: tracking mode, currently only write track is supported.
 */
void kvm_slot_page_track_remove_page(struct kvm *kvm,
				     struct kvm_memory_slot *slot, gfn_t gfn,
				     enum kvm_page_track_mode mode)
{
	if (WARN_ON(!page_track_mode_is_valid(mode)))
		return;

	update_gfn_track(kvm, slot, gfn, mode, -1);

	/*
	 * allow large page mapping for the tracked page
	 * after the tracker is gone.
	 */
	mmu_pt_gfn_allow_lpage(kvm, slot, gfn);
}

/*
 * check if the corresponding access on the specified guest page is tracked.
 */
bool kvm_page_track_is_active(struct kvm *kvm, struct kvm_memory_slot *slot,
			      gfn_t gfn, enum kvm_page_track_mode mode)
{
	int index;

	if (WARN_ON(!page_track_mode_is_valid(mode)))
		return false;

	if (!slot)
		return false;

	index = mmu_pt_gfn_to_index(kvm, gfn, slot->base_gfn, PT_PAGE_TABLE_LEVEL);
	return !!READ_ONCE(slot->arch.gfn_track[mode][index]);
}

void kvm_page_track_cleanup(struct kvm *kvm)
{
	struct kvm_page_track_notifier_head *head;

	head = &kvm->arch.track_notifier_head;
	cleanup_srcu_struct(&head->track_srcu);
}

void kvm_page_track_init(struct kvm *kvm)
{
	struct kvm_page_track_notifier_head *head;

	head = &kvm->arch.track_notifier_head;
	init_srcu_struct(&head->track_srcu);
	INIT_HLIST_HEAD(&head->track_notifier_list);
}

/*
 * register the notifier so that event interception for the tracked guest
 * pages can be received.
 */
void
kvm_page_track_register_notifier(struct kvm *kvm,
				 struct kvm_page_track_notifier_node *n)
{
	struct kvm_page_track_notifier_head *head;

	head = &kvm->arch.track_notifier_head;

	spin_lock(&kvm->mmu_lock);
	hlist_add_head_rcu(&n->node, &head->track_notifier_list);
	spin_unlock(&kvm->mmu_lock);
}

/*
 * stop receiving the event interception. It is the opposed operation of
 * kvm_page_track_register_notifier().
 */
void
kvm_page_track_unregister_notifier(struct kvm *kvm,
				   struct kvm_page_track_notifier_node *n)
{
	struct kvm_page_track_notifier_head *head;

	head = &kvm->arch.track_notifier_head;

	spin_lock(&kvm->mmu_lock);
	hlist_del_rcu(&n->node);
	spin_unlock(&kvm->mmu_lock);
	synchronize_srcu(&head->track_srcu);
}

/*
 * Notify the node that write access is intercepted and write emulation is
 * finished at this time.
 *
 * The node should figure out if the written page is the one that node is
 * interested in by itself.
 */
void kvm_page_track_write(struct kvm_vcpu *vcpu, struct gmm_struct *gmm,
		gpa_t gpa, const u8 *new, int bytes, unsigned long flags)
{
	struct kvm_page_track_notifier_head *head;
	struct kvm_page_track_notifier_node *n;
	int idx;

	head = &vcpu->kvm->arch.track_notifier_head;

	if (hlist_empty(&head->track_notifier_list))
		return;

	idx = srcu_read_lock(&head->track_srcu);
	hlist_for_each_entry_rcu(n, &head->track_notifier_list, node)
		if (n->track_write)
			n->track_write(vcpu, gmm, gpa, new, bytes, flags);
	srcu_read_unlock(&head->track_srcu, idx);
}

/*
 * Notify the node that memory slot is being removed or moved so that it can
 * drop write-protection for the pages in the memory slot.
 *
 * The node should figure out it has any write-protected pages in this slot
 * by itself.
 */
void kvm_page_track_flush_slot(struct kvm *kvm, struct kvm_memory_slot *slot)
{
	struct kvm_page_track_notifier_head *head;
	struct kvm_page_track_notifier_node *n;
	int idx;

	head = &kvm->arch.track_notifier_head;

	if (hlist_empty(&head->track_notifier_list))
		return;

	idx = srcu_read_lock(&head->track_srcu);
	hlist_for_each_entry_rcu(n, &head->track_notifier_list, node)
		if (n->track_flush_slot)
			n->track_flush_slot(kvm, slot, n);
	srcu_read_unlock(&head->track_srcu, idx);
}
