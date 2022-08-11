#ifndef __KVM_E2K_RUNSTATE_H
#define __KVM_E2K_RUNSTATE_H

#if	defined(CONFIG_VIRTUALIZATION) && !defined(CONFIG_KVM_GUEST_KERNEL)
/* it is host kernel with virtualization support */
/* or paravirtualized host and guest kernel */

#include <linux/kvm_host.h>
#include <linux/irqflags.h>

/*
 * VCPU state structure contains virtual CPU running state info.
 * The structure is common for host and guest and can (and should)
 * be accessed by both.
 * Guest access do through global pointer which should be load on some global
 * register (GUEST_VCPU_STATE_GREG) or on special CPU register GD.
 * But GD can be used only if guest kernel run as protected task
 */

/*
 * Basic accessing functions to/from virtual CPU running state info structure
 * (see asm/kvm/guest.h) on host.
 */
static inline kvm_runstate_info_t *
kvm_get_vcpu_runstate(struct kvm_vcpu *vcpu)
{
	kvm_runstate_info_t *runstate;

	runstate = &(vcpu->arch.kmap_vcpu_state->runstate);
	return runstate;
}
static inline int
kvm_get_guest_vcpu_runstate(struct kvm_vcpu *vcpu)
{
	return kvm_get_vcpu_runstate(vcpu)->state;
}
static inline void
kvm_set_guest_vcpu_runstate(struct kvm_vcpu *vcpu, int state)
{
	kvm_get_vcpu_runstate(vcpu)->state = state;
}
static inline uint64_t
kvm_get_guest_vcpu_runstate_entry_time(struct kvm_vcpu *vcpu)
{
	return kvm_get_vcpu_runstate(vcpu)->state_entry_time;
}
static inline void
kvm_set_guest_vcpu_runstate_entry_time(struct kvm_vcpu *vcpu, uint64_t time)
{
	kvm_get_vcpu_runstate(vcpu)->state_entry_time = time;
}
static inline uint64_t
kvm_get_guest_vcpu_runstate_time(struct kvm_vcpu *vcpu, int runstate_type)
{
	return kvm_get_vcpu_runstate(vcpu)->time[runstate_type];
}
static inline void
kvm_set_guest_vcpu_runstate_time(struct kvm_vcpu *vcpu,
					int runstate_type, uint64_t time)
{
	kvm_get_vcpu_runstate(vcpu)->time[runstate_type] = time;
}
static inline uint64_t
kvm_get_guest_vcpu_runstate_running_time(struct kvm_vcpu *vcpu)
{
	return kvm_get_guest_vcpu_runstate_time(vcpu, RUNSTATE_running);
}
static inline void
kvm_set_guest_vcpu_runstate_running_time(struct kvm_vcpu *vcpu, uint64_t time)
{
	kvm_set_guest_vcpu_runstate_time(vcpu, RUNSTATE_running, time);
}
static inline uint64_t
kvm_get_guest_vcpu_runstate_runnable_time(struct kvm_vcpu *vcpu)
{
	return kvm_get_guest_vcpu_runstate_time(vcpu, RUNSTATE_runnable);
}
static inline void
kvm_set_guest_vcpu_runstate_runnable_time(struct kvm_vcpu *vcpu, uint64_t time)
{
	kvm_set_guest_vcpu_runstate_time(vcpu, RUNSTATE_runnable, time);
}
static inline uint64_t
kvm_get_guest_vcpu_runstate_blocked_time(struct kvm_vcpu *vcpu)
{
	return kvm_get_guest_vcpu_runstate_time(vcpu, RUNSTATE_blocked);
}
static inline void
kvm_set_guest_vcpu_runstate_blocked_time(struct kvm_vcpu *vcpu, uint64_t time)
{
	kvm_set_guest_vcpu_runstate_time(vcpu, RUNSTATE_blocked, time);
}
static inline uint64_t
kvm_get_guest_vcpu_runstate_offline_time(struct kvm_vcpu *vcpu)
{
	return kvm_get_guest_vcpu_runstate_time(vcpu, RUNSTATE_offline);
}
static inline void
kvm_set_guest_vcpu_runstate_offline_time(struct kvm_vcpu *vcpu, uint64_t time)
{
	kvm_set_guest_vcpu_runstate_time(vcpu, RUNSTATE_offline, time);
}
static inline uint64_t
kvm_get_guest_vcpu_runstate_in_hcall_time(struct kvm_vcpu *vcpu)
{
	return kvm_get_guest_vcpu_runstate_time(vcpu, RUNSTATE_in_hcall);
}
static inline void
kvm_set_guest_vcpu_runstate_in_hcall_time(struct kvm_vcpu *vcpu, uint64_t time)
{
	kvm_set_guest_vcpu_runstate_time(vcpu, RUNSTATE_in_hcall, time);
}
static inline uint64_t
kvm_get_guest_vcpu_runstate_in_QEMU_time(struct kvm_vcpu *vcpu)
{
	return kvm_get_guest_vcpu_runstate_time(vcpu, RUNSTATE_in_QEMU);
}
static inline void
kvm_set_guest_vcpu_runstate_in_QEMU_time(struct kvm_vcpu *vcpu, uint64_t time)
{
	kvm_set_guest_vcpu_runstate_time(vcpu, RUNSTATE_in_QEMU, time);
}
static inline uint64_t
kvm_get_guest_vcpu_runstate_in_trap_time(struct kvm_vcpu *vcpu)
{
	return kvm_get_guest_vcpu_runstate_time(vcpu, RUNSTATE_in_trap);
}
static inline void
kvm_set_guest_vcpu_runstate_in_trap_time(struct kvm_vcpu *vcpu, uint64_t time)
{
	kvm_set_guest_vcpu_runstate_time(vcpu, RUNSTATE_in_trap, time);
}
static inline uint64_t
kvm_get_guest_vcpu_runstate_in_intercept_time(struct kvm_vcpu *vcpu)
{
	return kvm_get_guest_vcpu_runstate_time(vcpu, RUNSTATE_in_intercept);
}
static inline void
kvm_set_guest_vcpu_runstate_in_intercept_time(struct kvm_vcpu *vcpu,
						uint64_t time)
{
	kvm_set_guest_vcpu_runstate_time(vcpu, RUNSTATE_in_intercept, time);
}

/*
 * Interrupts should be disabled by caller
 */
static inline void
kvm_do_update_guest_vcpu_runstate(struct kvm_vcpu *vcpu,
					int new_state, uint64_t entry_time)
{
	int old_state = kvm_get_guest_vcpu_runstate(vcpu);
	uint64_t old_entry_time = kvm_get_guest_vcpu_runstate_entry_time(vcpu);
	uint64_t old_time;
	uint64_t old_time_add;

	if (entry_time > old_entry_time) {
		old_time = kvm_get_guest_vcpu_runstate_time(vcpu, old_state);
		old_time_add = entry_time - old_entry_time;
		old_time += old_time_add;
		kvm_set_guest_vcpu_runstate_time(vcpu, old_state, old_time);
	}

	kvm_set_guest_vcpu_runstate(vcpu, new_state);
	kvm_set_guest_vcpu_runstate_entry_time(vcpu, entry_time);
}
static inline void
kvm_update_guest_vcpu_runstate(struct kvm_vcpu *vcpu,
					int new_state, uint64_t entry_time)
{
	unsigned long flags;

	raw_local_irq_save(flags);
	kvm_do_update_guest_vcpu_runstate(vcpu, new_state, entry_time);
	raw_local_irq_restore(flags);
}
/* Interrupts should be disabled by caller */
static inline void
kvm_do_update_guest_vcpu_current_runstate(struct kvm_vcpu *vcpu, int new_state)
{
	uint64_t cur_time;

	cur_time = nsecs_2cycles(ktime_to_ns(ktime_get()));
	kvm_do_update_guest_vcpu_runstate(vcpu, new_state, cur_time);
}
static inline void
kvm_update_guest_vcpu_current_runstate(struct kvm_vcpu *vcpu, int new_state)
{
	unsigned long flags;

	raw_local_irq_save(flags);
	kvm_do_update_guest_vcpu_current_runstate(vcpu, new_state);
	raw_local_irq_restore(flags);
}

/* Interrupts should be disabled by caller */
static inline void
kvm_do_init_guest_vcpu_runstate(struct kvm_vcpu *vcpu, int init_state)
{
	uint64_t cur_time;

	cur_time = nsecs_2cycles(ktime_to_ns(ktime_get()));
	kvm_set_guest_vcpu_runstate(vcpu, init_state);
	kvm_set_guest_vcpu_runstate_entry_time(vcpu, cur_time);
	kvm_set_guest_vcpu_runstate_time(vcpu, init_state, 0);
}
static inline void
kvm_init_guest_vcpu_runstate(struct kvm_vcpu *vcpu, int init_state)
{
	unsigned long flags;

	raw_local_irq_save(flags);
	kvm_do_init_guest_vcpu_runstate(vcpu, init_state);
	raw_local_irq_restore(flags);
}

static inline long
kvm_do_get_guest_vcpu_stolen_time(struct kvm_vcpu *vcpu)
{
	s64 running, blocked, runnable, offline, stolen, in_hcall, in_intercept;
	int runstate;
	uint64_t entry_time;
	s64 now;

	now = nsecs_2cycles(ktime_to_ns(ktime_get()));
	entry_time = kvm_get_guest_vcpu_runstate_entry_time(vcpu);
	BUG_ON(now < entry_time);

	runstate = kvm_get_guest_vcpu_runstate(vcpu);

	running = kvm_get_guest_vcpu_runstate_running_time(vcpu);
	if (runstate == RUNSTATE_running)
		running += (now - entry_time);
	in_hcall = kvm_get_guest_vcpu_runstate_in_hcall_time(vcpu);
	if (runstate == RUNSTATE_in_hcall)
		in_hcall += (now - entry_time);
	blocked = kvm_get_guest_vcpu_runstate_blocked_time(vcpu);
	if (runstate == RUNSTATE_blocked)
		blocked += (now - entry_time);
	in_intercept = kvm_get_guest_vcpu_runstate_in_intercept_time(vcpu);
	if (runstate == RUNSTATE_in_intercept)
		in_intercept += (now - entry_time);

	/* work out how much time the VCPU has not been runn*ing*  */
	runnable = kvm_get_guest_vcpu_runstate_runnable_time(vcpu) +
			kvm_get_guest_vcpu_runstate_in_QEMU_time(vcpu) +
			kvm_get_guest_vcpu_runstate_in_trap_time(vcpu);
	if (runstate == RUNSTATE_runnable || runstate == RUNSTATE_in_trap ||
		runstate == RUNSTATE_in_QEMU)
		runnable += (now - entry_time);
	offline = kvm_get_guest_vcpu_runstate_offline_time(vcpu);
	if (runstate == RUNSTATE_offline)
		offline += (now - entry_time);

	stolen = runnable + offline;

	BUG_ON(now < stolen + running + in_hcall + blocked + in_intercept);

	return stolen;
}
static inline long
kvm_get_guest_vcpu_stolen_time(struct kvm_vcpu *vcpu)
{
	s64 stolen_time;
	unsigned long flags;

	raw_local_irq_save(flags);
	stolen_time = kvm_do_get_guest_vcpu_stolen_time(vcpu);
	raw_local_irq_restore(flags);

	return stolen_time;
}

static inline long
kvm_do_get_guest_vcpu_running_time(struct kvm_vcpu *vcpu)
{
	s64 running, in_hcall, blocked, in_intercept;
	int runstate;
	uint64_t entry_time;
	s64 now;

	do {
		entry_time = kvm_get_guest_vcpu_runstate_entry_time(vcpu);
		runstate = kvm_get_guest_vcpu_runstate(vcpu);
		running = kvm_get_guest_vcpu_runstate_running_time(vcpu);
		in_hcall = kvm_get_guest_vcpu_runstate_in_hcall_time(vcpu);
		blocked = kvm_get_guest_vcpu_runstate_blocked_time(vcpu);
		in_intercept =
			kvm_get_guest_vcpu_runstate_in_intercept_time(vcpu);
		now = nsecs_2cycles(ktime_to_ns(ktime_get()));
	} while (entry_time != kvm_get_guest_vcpu_runstate_entry_time(vcpu));

	BUG_ON(now < entry_time);
	if (now > entry_time) {
		if (runstate == RUNSTATE_running)
			running += (now - entry_time);
		if (runstate == RUNSTATE_in_hcall)
			in_hcall += (now - entry_time);
		if (runstate == RUNSTATE_blocked)
			blocked += (now - entry_time);
		if (runstate == RUNSTATE_in_intercept)
			in_intercept += (now - entry_time);
	}

	BUG_ON(now < in_hcall + blocked + running + in_intercept);

	return running + in_hcall + blocked + in_intercept;
}
static inline long
kvm_get_guest_vcpu_running_time(struct kvm_vcpu *vcpu)
{
	s64 running_time;
	unsigned long flags;

	raw_local_irq_save(flags);
	running_time = kvm_do_get_guest_vcpu_running_time(vcpu);
	raw_local_irq_restore(flags);

	return running_time;
}

/* Runstate time is measured with ktime_get() cycles, it has to be monotonic across all CPUs */
static inline unsigned long
kvm_get_host_runstate_ktime(void)
{
	return nsecs_2cycles(ktime_to_ns(ktime_get()));
}

/*
 * IRQs should be disabled by caller
 * It always is true while caller is light hypercall
 */
static inline unsigned long
kvm_get_guest_running_time(struct kvm_vcpu *vcpu)
{
	cycles_t running;

	running = kvm_do_get_guest_vcpu_running_time(vcpu);
	return running;
}

#define	CONFIG_DEBUG_VCPU_RUNSTATE
#ifndef	CONFIG_DEBUG_VCPU_RUNSTATE
/* guest VCPU run state should be updated in traps and interrupts */
static inline void
kvm_set_guest_runstate_in_user_trap(void)
{
	thread_info_t *ti = current_thread_info();
	struct kvm_vcpu *vcpu;

	if (!test_ti_thread_flag(ti, TIF_VIRTUALIZED_GUEST))
		return;
	vcpu = ti->vcpu;
	BUG_ON(vcpu == NULL);
	BUG_ON(!irqs_disabled());
	BUG_ON(kvm_get_guest_vcpu_runstate(vcpu) != RUNSTATE_running);
	kvm_do_update_guest_vcpu_current_runstate(vcpu, RUNSTATE_in_trap);
}
static inline void
kvm_set_guest_runstate_out_user_trap(void)
{
	thread_info_t *ti = current_thread_info();
	struct kvm_vcpu *vcpu;

	if (!test_ti_thread_flag(ti, TIF_VIRTUALIZED_GUEST))
		return;
	vcpu = ti->vcpu;
	BUG_ON(vcpu == NULL);
	BUG_ON(!irqs_disabled());
	BUG_ON(kvm_get_guest_vcpu_runstate(vcpu) != RUNSTATE_in_trap);
	kvm_do_update_guest_vcpu_current_runstate(vcpu, RUNSTATE_running);
}
static inline int
kvm_set_guest_runstate_in_kernel_trap(void)
{
	thread_info_t *ti = current_thread_info();
	struct kvm_vcpu *vcpu;
	int cur_runstate;

	if (!test_ti_thread_flag(ti, TIF_VIRTUALIZED_GUEST))
		return -1;
	vcpu = ti->vcpu;
	if (vcpu == NULL)
		return -1;	/* It is VIRQ VCPU: run state is unused */
	BUG_ON(!irqs_disabled());
	cur_runstate = kvm_get_guest_vcpu_runstate(vcpu);
	BUG_ON(cur_runstate != RUNSTATE_running);
	kvm_do_update_guest_vcpu_current_runstate(vcpu, RUNSTATE_in_trap);
	return cur_runstate;
}
static inline void
kvm_set_guest_runstate_out_kernel_trap(int saved_runstate)
{
	thread_info_t *ti = current_thread_info();
	struct kvm_vcpu *vcpu;

	if (!test_ti_thread_flag(ti, TIF_VIRTUALIZED_GUEST))
		return;
	vcpu = ti->vcpu;
	if (vcpu == NULL)
		return;	/* It is VIRQ VCPU: run state is unused */
	BUG_ON(!irqs_disabled());
	BUG_ON(kvm_get_guest_vcpu_runstate(vcpu) != RUNSTATE_in_trap);
	kvm_do_update_guest_vcpu_current_runstate(vcpu, saved_runstate);
}
#else	/* CONFIG_DEBUG_VCPU_RUNSTATE */
extern void kvm_set_guest_runstate_in_user_trap(void);
extern void kvm_set_guest_runstate_out_user_trap(void);
extern int kvm_set_guest_runstate_in_kernel_trap(void);
extern void kvm_set_guest_runstate_out_kernel_trap(int saved_runstate);
#endif	/* ! CONFIG_DEBUG_VCPU_RUNSTATE */

#define	SET_RUNSTATE_IN_USER_TRAP()	kvm_set_guest_runstate_in_user_trap()
#define	SET_RUNSTATE_OUT_USER_TRAP()	kvm_set_guest_runstate_out_user_trap()
#define	SET_RUNSTATE_IN_KERNEL_TRAP(cur_runstate)			\
		(cur_runstate = kvm_set_guest_runstate_in_kernel_trap())
#define	SET_RUNSTATE_OUT_KERNEL_TRAP(cur_runstate)			\
		kvm_set_guest_runstate_out_kernel_trap(cur_runstate)

#else	/* ! CONFIG_VIRTUALIZATION || CONFIG_KVM_GUEST_KERNEL */
/* it is native kernel without virtualization support */
/* or pure guest kernel (not paravirtualized based on pv_ops) */
#define	SET_RUNSTATE_IN_USER_TRAP()
#define	SET_RUNSTATE_OUT_USER_TRAP()
#define	SET_RUNSTATE_IN_KERNEL_TRAP(cur_runstate)
#define	SET_RUNSTATE_OUT_KERNEL_TRAP(cur_runstate)
#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is pure guest kernel (not paravirtualized based on pv_ops) */

/* FIXME: follow function(s) should not be used on pure guest kernel mode */
static inline int
kvm_get_guest_vcpu_runstate(struct kvm_vcpu *vcpu)
{
	return -1;	/* guest can not support own guests */
}
static inline long
kvm_do_get_guest_vcpu_running_time(struct kvm_vcpu *vcpu)
{
	return -1;	/* guest can not support own guests */
}
static inline long
kvm_get_guest_vcpu_running_time(struct kvm_vcpu *vcpu)
{
	return -1;	/* guest can not support own guests */
}
static inline unsigned long
kvm_get_guest_running_time(struct kvm_vcpu *vcpu)
{
	return -1;	/* guest can not support own guests */
}
static inline uint64_t
kvm_get_guest_vcpu_runstate_entry_time(struct kvm_vcpu *vcpu)
{
	return -1;	/* guest can not support own guests */
}
static inline void
kvm_do_update_guest_vcpu_current_runstate(struct kvm_vcpu *vcpu, int new_state)
{
	/* guest can not support own guests */
}
static inline void
kvm_update_guest_vcpu_current_runstate(struct kvm_vcpu *vcpu, int new_state)
{
	/* guest can not support own guests */
}
static inline void
kvm_do_init_guest_vcpu_runstate(struct kvm_vcpu *vcpu, int init_state)
{
	/* guest can not support own guests */
}
static inline unsigned long
kvm_get_host_runstate_ktime(void)
{
	return -1;	/* guest can not support own guests */
}
#endif	/* CONFIG_KVM_GUEST_KERNEL */
#endif	/* CONFIG_VIRTUALIZATION && ! CONFIG_KVM_GUEST_KERNEL */

#endif	/* __KVM_E2K_RUNSTATE_H */
