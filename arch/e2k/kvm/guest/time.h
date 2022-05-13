#ifndef __ASM_KVM_TIME_H
#define __ASM_KVM_TIME_H

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/clocksource.h>

struct clock_event_device;

extern u64 kvm_clocksource_read(void);
extern void kvm_timer_resume(void);
extern void clockevents_shutdown(struct clock_event_device *dev);

extern int arch_dup_task_struct(struct task_struct *dst,
					struct task_struct *src);

#endif	/* __KERNEL__ */

#endif	/* __ASM_KVM_TIME_H */
