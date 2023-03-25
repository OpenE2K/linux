#ifndef __KVM_E2K_COMPLETE_H
#define __KVM_E2K_COMPLETE_H

#include <linux/types.h>
#include <linux/sched/debug.h>

extern void __sched kvm_wait_for_completion(struct completion *x);
extern unsigned long kvm_wait_for_completion_timeout(struct completion *x,
							unsigned long timeout);
extern int kvm_wait_for_completion_interruptible(struct completion *x);

#endif	/* __KVM_E2K_COMPLETE_H */
