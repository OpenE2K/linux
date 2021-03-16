#ifndef _E2K_PARAVIRT_REGS_STATE_H
#define _E2K_PARAVIRT_REGS_STATE_H

#include <linux/types.h>
#include <asm/paravirt/pv_ops.h>
#include <asm/kvm/guest/regs_state.h>

#define	PV_INIT_G_REGS()	\
({ \
	if (!paravirt_enabled()) { \
		NATIVE_INIT_G_REGS(regs); \
	} else { \
		KVM_INIT_G_REGS(regs); \
	} \
})

static inline void
pv_save_local_glob_regs(local_gregs_t *l_gregs)
{
	pv_cpu_ops.save_local_glob_regs(l_gregs);
}
static inline void
pv_restore_local_glob_regs(local_gregs_t *l_gregs)
{
	pv_cpu_ops.restore_local_glob_regs(l_gregs);
}
static inline void
pv_get_all_user_glob_regs(struct global_regs *gregs)
{
	pv_cpu_ops.get_all_user_glob_regs(gregs);
}
static inline void
pv_restore_kernel_gregs_in_syscall(struct thread_info *ti)
{
	pv_cpu_ops.restore_kernel_gregs_in_syscall(ti);
}

/* Save stack registers on guest kernel mode */

#define PV_SAVE_STACK_REGS(regs, ti, user, trap) \
		PREFIX_SAVE_STACK_REGS(PV, regs, ti, user, trap)

#ifdef	CONFIG_PARAVIRT_GUEST
/* it is paravirtualized host and guest kernel */

#define	INIT_G_REGS()	PV_INIT_G_REGS()

static inline void
save_local_glob_regs(local_gregs_t *l_gregs)
{
	pv_save_local_glob_regs(l_gregs);
}
static inline void
restore_local_glob_regs(local_gregs_t *l_gregs)
{
	pv_restore_local_glob_regs(l_gregs);
}
static inline void
get_all_user_glob_regs(struct global_regs *gregs)
{
	pv_get_all_user_glob_regs(gregs);
}

#define	RESTORE_KERNEL_GREGS_IN_SYSCALL(thread_info)	\
		pv_restore_kernel_gregs_in_syscall(thread_info)

#define SAVE_STACK_REGS(regs, ti, user, trap) \
		PV_SAVE_STACK_REGS(regs, ti, user, trap)
#define RESTORE_HS_REGS(regs) \
({ \
	if (!paravirt_enabled()) { \
		NATIVE_RESTORE_HS_REGS(regs); \
	} else { \
		KVM_RESTORE_HS_REGS(regs); \
	} \
})
#define RESTORE_USER_STACK_REGS(regs, restore_hs) \
({ \
	if (!paravirt_enabled()) { \
		NATIVE_RESTORE_USER_STACK_REGS(regs, restore_hs); \
	} else { \
		KVM_RESTORE_USER_STACK_REGS(regs, restore_hs); \
	} \
})
#endif	/* CONFIG_PARAVIRT_GUEST */
#endif /* _E2K_PARAVIRT_REGS_STATE_H */

