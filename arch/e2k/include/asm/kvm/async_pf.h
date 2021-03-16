#ifndef ASYNC_PF_E2K_H
#define ASYNC_PF_E2K_H

#ifdef CONFIG_KVM_ASYNC_PF

/* No async page fault occured */
#define KVM_APF_NO		0
/* Physical page was swapped out by host */
#define KVM_APF_PAGE_IN_SWAP	1
/* Physical page is loaded from swap and ready for access */
#define KVM_APF_PAGE_READY	2

#define KVM_APF_HASH_BITS 8
/* Number of hash buckets in apf cache */
#define KVM_APF_CACHE_SIZE (1 << KVM_APF_HASH_BITS)

/*
 * Type of irq controller which will be used
 * by host to notify guest that page is ready
 */
enum {
	EPIC_CONTROLLER = 1,
	APIC_CONTROLLER = 2
};

u32 pv_apf_read_and_reset_reason(void);

void pv_apf_wait(void);
void pv_apf_wake(void);

#endif /* CONFIG_KVM_ASYNC_PF */

#endif /* ASYNC_PF_H */
