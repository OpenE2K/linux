#ifndef _ASM_E2K_KVM_PAGE_TRACK_H
#define _ASM_E2K_KVM_PAGE_TRACK_H

enum kvm_page_track_mode {
	KVM_PAGE_TRACK_WRITE,
	KVM_PAGE_TRACK_MAX,
};

/*
 * @flags argument of track_write() function to clarify the possible
 * reason fow writing at protected area
 */
#define	THP_INVALIDATE_WR_TRACK		0x0001UL	/* to invalidate PT huge */
							/* entry at THP mode */
#define	NUMA_BALANCING_WR_TRACK		0x0010UL	/* to migrate from one */
							/* NUMA node to other */

#ifdef	CONFIG_KVM_HV_MMU

/*
 * The notifier represented by @kvm_page_track_notifier_node is linked into
 * the head which will be notified when guest is triggering the track event.
 *
 * Write access on the head is protected by kvm->mmu_lock, read access
 * is protected by track_srcu.
 */
struct kvm_page_track_notifier_head {
	struct srcu_struct track_srcu;
	struct hlist_head track_notifier_list;
};

struct kvm_page_track_notifier_node {
	struct hlist_node node;

	/*
	 * It is called when guest is writing the write-tracked page
	 * and write emulation is finished at that time.
	 *
	 * @vcpu: the vcpu where the write access happened.
	 * @gpa: the physical address written by guest.
	 * @new: the data was written to the address.
	 * @bytes: the written length.
	 */
	void (*track_write)(struct kvm_vcpu *vcpu, struct gmm_struct *gmm,
			gpa_t gpa, const u8 *new, int bytes, unsigned long flags);
	/*
	 * It is called when memory slot is being moved or removed
	 * users can drop write-protection for the pages in that memory slot
	 *
	 * @kvm: the kvm where memory slot being moved or removed
	 * @slot: the memory slot being moved or removed
	 * @node: this node
	 */
	void (*track_flush_slot)(struct kvm *kvm, struct kvm_memory_slot *slot,
			    struct kvm_page_track_notifier_node *node);
};

void kvm_page_track_init(struct kvm *kvm);
void kvm_page_track_cleanup(struct kvm *kvm);

void kvm_page_track_free_memslot(struct kvm_memory_slot *free,
				 struct kvm_memory_slot *dont);
int kvm_page_track_create_memslot(struct kvm_memory_slot *slot,
				  unsigned long npages);

void kvm_slot_page_track_add_page(struct kvm *kvm,
				  struct kvm_memory_slot *slot, gfn_t gfn,
				  enum kvm_page_track_mode mode);
void kvm_slot_page_track_remove_page(struct kvm *kvm,
				     struct kvm_memory_slot *slot, gfn_t gfn,
				     enum kvm_page_track_mode mode);
bool kvm_page_track_is_active(struct kvm *kvm, struct kvm_memory_slot *slot,
			gfn_t gfn, enum kvm_page_track_mode mode);

void
kvm_page_track_register_notifier(struct kvm *kvm,
				 struct kvm_page_track_notifier_node *n);
void
kvm_page_track_unregister_notifier(struct kvm *kvm,
				   struct kvm_page_track_notifier_node *n);
void kvm_page_track_write(struct kvm_vcpu *vcpu, struct gmm_struct *gmm,
		gpa_t gpa, const u8 *new, int bytes, unsigned long flags);
void kvm_page_track_flush_slot(struct kvm *kvm, struct kvm_memory_slot *slot);
#else	/* ! CONFIG_KVM_HV_MMU */
static inline void kvm_page_track_init(struct kvm *kvm)
{
	return; /* not used */
}
static inline void kvm_page_track_cleanup(struct kvm *kvm)
{
	return; /* not used */
}
#endif	/* CONFIG_KVM_HV_MMU */

#endif	/* _ASM_E2K_KVM_PAGE_TRACK_H */
