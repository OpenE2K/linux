#ifndef _E2K_KVM_GUEST_REGS_STATE_H
#define _E2K_KVM_GUEST_REGS_STATE_H

#include <linux/types.h>
#include <linux/sched.h>
#include <linux/signal.h>
#include <linux/irqflags.h>

#ifndef __ASSEMBLY__
#include <asm/e2k_api.h>
#include <asm/cpu_regs_access.h>
#include <asm/mmu.h>
#include <asm/mmu_regs.h>
#include <asm/system.h>
#include <asm/ptrace.h>
#include <asm/tags.h>
#include <asm/gregs.h>
#include <asm/kvm/gregs.h>
#endif /* __ASSEMBLY__ */

extern void kvm_save_glob_regs(global_regs_t *gregs);
extern void kvm_save_glob_regs_dirty_bgr(global_regs_t *gregs);
extern void kvm_save_local_glob_regs(local_gregs_t *l_gregs, bool is_signal);
extern void kvm_restore_glob_regs(const global_regs_t *gregs);
extern void kvm_restore_local_glob_regs(const local_gregs_t *l_gregs,
					bool is_signal);
extern void kvm_get_all_user_glob_regs(global_regs_t *gregs);

static inline void
guest_save_glob_regs_v3(global_regs_t *gregs)
{
	kvm_guest_save_gregs_v3(gregs);
}

static inline void
guest_save_glob_regs_v5(global_regs_t *gregs)
{
	kvm_guest_save_gregs_v5(gregs);
}

static inline void
guest_save_glob_regs_dirty_bgr_v3(global_regs_t *gregs)
{
	kvm_guest_save_gregs_v3(gregs);
}

static inline void
guest_save_glob_regs_dirty_bgr_v5(global_regs_t *gregs)
{
	kvm_guest_save_gregs_v5(gregs);
}

static inline void
guest_save_local_glob_regs_v3(local_gregs_t *l_gregs, bool is_signal)
{
	kvm_guest_save_local_gregs_v3(l_gregs, is_signal);
	if (KERNEL_GREGS_MAX_MASK & LOCAL_GREGS_USER_MASK)
		copy_k_gregs_to_l_gregs(l_gregs,
				&current_thread_info()->k_gregs);
}

static inline void
guest_save_local_glob_regs_v5(local_gregs_t *l_gregs, bool is_signal)
{
	kvm_guest_save_local_gregs_v5(l_gregs, is_signal);
	if (KERNEL_GREGS_MAX_MASK & LOCAL_GREGS_USER_MASK)
		copy_k_gregs_to_l_gregs(l_gregs,
				&current_thread_info()->k_gregs);
}

static inline void
guest_restore_glob_regs_v3(const global_regs_t *gregs)
{
	kvm_guest_restore_gregs_v3(gregs);
}

static inline void
guest_restore_glob_regs_v5(const global_regs_t *gregs)
{
	kvm_guest_restore_gregs_v5(gregs);
}

static inline void
guest_restore_local_glob_regs_v3(const local_gregs_t *l_gregs, bool is_signal)
{
	kvm_guest_restore_local_gregs_v3(l_gregs, is_signal);
	if (KERNEL_GREGS_MAX_MASK & LOCAL_GREGS_USER_MASK)
		get_k_gregs_from_l_regs(&current_thread_info()->k_gregs,
					l_gregs);
}

static inline void
guest_restore_local_glob_regs_v5(const local_gregs_t *l_gregs, bool is_signal)
{
	kvm_guest_restore_local_gregs_v5(l_gregs, is_signal);
	if (KERNEL_GREGS_MAX_MASK & LOCAL_GREGS_USER_MASK)
		get_k_gregs_from_l_regs(&current_thread_info()->k_gregs,
					l_gregs);
}

static inline void
guest_get_all_user_glob_regs(global_regs_t *gregs)
{
	machine.save_gregs(gregs);
	copy_k_gregs_to_gregs(gregs, &current_thread_info()->k_gregs);
}

#ifdef CONFIG_GREGS_CONTEXT
#define	KVM_INIT_G_REGS() \
({ \
	unsigned long vcpu_base; \
	/* VCPU state base can be on global register, so save & restore */ \
	KVM_SAVE_VCPU_STATE_BASE(vcpu_base); \
	NATIVE_INIT_G_REGS(); \
	KVM_RESTORE_VCPU_STATE_BASE(vcpu_base); \
})
#define BOOT_KVM_INIT_G_REGS() \
({ \
	unsigned long vcpu_base; \
	/* VCPU state base can be on global register, so save & restore */ \
	KVM_SAVE_VCPU_STATE_BASE(vcpu_base); \
	NATIVE_BOOT_INIT_G_REGS(); \
	KVM_RESTORE_VCPU_STATE_BASE(vcpu_base); \
})

#else	/* ! CONFIG_GREGS_CONTEXT */
#define	KVM_INIT_G_REGS()
#define	BOOT_KVM_INIT_G_REGS()	NATIVE_BOOT_INIT_G_REGS()
#endif	/* CONFIG_GREGS_CONTEXT */

#define KVM_GET_GREGS_FROM_THREAD(g_user, gtag_user, gbase)		\
({									\
	u64 *greg_vals = (u64 *) g_user;				\
	u8 *greg_tags = (u8 *) gtag_user;				\
	u64 *glob_regs = (u64 *) gbase;					\
	int greg_no;							\
									\
	for (greg_no = 0; greg_no < E2K_GLOBAL_REGS_NUM; greg_no++) {	\
		load_value_and_tagd((void *) glob_regs,			\
					greg_vals, greg_tags);		\
		glob_regs += 4;						\
		greg_vals++;						\
		greg_tags++;						\
	}								\
})

#define KVM_SET_GREGS_TO_THREAD(gbase, g_user, gtag_user)		\
({									\
	u64 *greg_vals = (u64 *) g_user;				\
	u8 *greg_tags = (u8 *) gtag_user;				\
	u64 *glob_regs = (u64 *) gbase;					\
	int greg_no;							\
	u32 greg_tag;							\
									\
	for (greg_no = 0; greg_no < E2K_GLOBAL_REGS_NUM; greg_no++) {	\
		greg_tag = (u32) greg_tags[greg_no];			\
		store_tagged_dword((void *) glob_regs,			\
				greg_vals[greg_no], greg_tag);		\
		glob_regs += 4;						\
	}								\
})

/* ptrace related guys: we do not use them on switching. */
# define GET_GREGS_FROM_THREAD(g_user, gtag_user, gbase)		\
({									\
	if (likely(IS_HV_GM()))						\
		NATIVE_GET_GREGS_FROM_THREAD(g_user, gtag_user, gbase);	\
	else								\
		KVM_GET_GREGS_FROM_THREAD(g_user, gtag_user, gbase);	\
})

# define SET_GREGS_TO_THREAD(gbase, g_user, gtag_user)			\
({									\
	if (likely(IS_HV_GM()))						\
		NATIVE_SET_GREGS_TO_THREAD(gbase, g_user, gtag_user);	\
	else								\
		KVM_SET_GREGS_TO_THREAD(gbase, g_user, gtag_user);	\
})

/* Save stack registers on guest kernel mode */
#define KVM_SAVE_STACK_REGS(regs, ti, from_ti, trap) \
do { \
	if (IS_HV_GM()) { \
		NATIVE_SAVE_STACK_REGS(regs, ti, from_ti, trap); \
	} else if (!(regs)->stack_regs_saved) { \
		PREFIX_SAVE_STACK_REGS(KVM, regs, ti, from_ti, trap); \
	} else { \
		/* registers were already saved */ \
		; \
	} \
} while (false)

/* Save hardware stack registers on guest kernel mode */
#define KVM_SAVE_HW_STACKS_AT_TI(ti) \
do { \
	struct hw_stacks *stacks = &(ti)->tmp_user_stacks; \
 \
	stacks->psp_lo = KVM_READ_PSP_LO_REG(); \
	stacks->psp_hi = KVM_READ_PSP_HI_REG(); \
	stacks->pshtp = KVM_READ_PSHTP_REG(); \
	stacks->pcsp_lo = KVM_READ_PCSP_LO_REG(); \
	stacks->pcsp_hi = KVM_READ_PCSP_HI_REG(); \
	stacks->pcshtp = KVM_READ_PCSHTP_REG_SVALUE(); \
} while (0)

#define KVM_DO_RESTORE_HS_REGS(regs, updated)				\
({									\
	PREFIX_RESTORE_HS_REGS(KVM, regs);				\
	UPDATE_CPU_REGS_FLAGS(updated, HS_REGS_UPDATED_CPU_REGS);	\
	PUT_UPDATED_CPU_REGS_FLAGS(updated);				\
})
#define KVM_DO_RESTORE_USER_STACK_REGS(regs, in_syscall, updated)	\
({									\
	PREFIX_RESTORE_USER_STACK_REGS(KVM, regs, in_syscall);		\
	UPDATE_CPU_REGS_FLAGS(updated, USD_UPDATED_CPU_REGS);		\
	UPDATE_CPU_REGS_FLAGS(updated, CRS_UPDATED_CPU_REGS);		\
	PUT_UPDATED_CPU_REGS_FLAGS(updated);				\
})

/* it is paravirtualized guest or native guest kernel */
#define	UPDATE_CPU_REGS_FLAGS(__updated, flags)				\
		((__updated) |= (flags))
#define	KVM_RESTORE_HS_REGS(regs)					\
({									\
	u64 updated = 0;						\
									\
	KVM_DO_RESTORE_HS_REGS(regs, updated);				\
})
#define KVM_RESTORE_USER_STACK_REGS(regs, in_syscall)			\
({									\
	u64 updated = 0;						\
									\
	KVM_DO_RESTORE_USER_STACK_REGS(regs, in_syscall, updated);	\
})
#define KVM_RESTORE_USER_TRAP_STACK_REGS(regs)				\
		KVM_RESTORE_USER_STACK_REGS(regs, false)
#define KVM_RESTORE_USER_SYSCALL_STACK_REGS(regs)			\
		KVM_RESTORE_USER_STACK_REGS(regs, true)
#define	KVM_RESTORE_USER_CUT_REGS(ti, regs)	/* CUTD is set by host */

#define KVM_RESTORE_COMMON_REGS(regs)	/* should be restored by host */

#define	KVM_SAVE_TRAP_CELLAR(regs, trap)				\
({									\
	kernel_trap_cellar_t *kernel_tcellar =				\
		(kernel_trap_cellar_t *)KERNEL_TRAP_CELLAR;		\
	kernel_trap_cellar_ext_t *kernel_tcellar_ext =			\
		(kernel_trap_cellar_ext_t *)				\
		((void *) KERNEL_TRAP_CELLAR + TC_EXT_OFFSET);		\
	trap_cellar_t *tcellar = (trap)->tcellar;			\
	int cnt, cs_req_num = 0, cs_a4 = 0, max_cnt;			\
	u64 kstack_pf_addr = 0;						\
	bool end_flag = false, is_qp;					\
									\
	max_cnt = KVM_READ_MMU_TRAP_COUNT();				\
	if (max_cnt < 3) {						\
		max_cnt = 3 * HW_TC_SIZE;				\
		end_flag = true;					\
	}								\
	(trap)->curr_cnt = -1;						\
	(trap)->ignore_user_tc = 0;					\
	(trap)->tc_called = 0;						\
	(trap)->is_intc = false;					\
	(trap)->from_sigreturn = 0;					\
	CLEAR_CLW_REQUEST_COUNT(regs);					\
	BUG_ON(max_cnt > 3 * HW_TC_SIZE);				\
	for (cnt = 0; 3 * cnt < max_cnt; cnt++) {			\
		tc_opcode_t opcode;					\
		tc_cond_t condition;					\
									\
		if (end_flag)						\
			if (AW(kernel_tcellar[cnt].condition) == -1)	\
				break;					\
									\
		tcellar[cnt].address = kernel_tcellar[cnt].address;	\
		condition = kernel_tcellar[cnt].condition;		\
		tcellar[cnt].condition = condition;			\
		AW(opcode) = AS(condition).opcode;			\
		is_qp = (AS(opcode).fmt == LDST_QP_FMT ||		\
			 cpu_has(CPU_FEAT_QPREG) && AS(condition).fmtc && \
			 AS(opcode).fmt == LDST_QWORD_FMT);		\
		if (AS(condition).clw) {				\
			if (GET_CLW_REQUEST_COUNT(regs) == 0) {		\
				SET_CLW_FIRST_REQUEST(regs, cnt);	\
			}						\
			INC_CLW_REQUEST_COUNT(regs);			\
		}							\
		if (is_qp)						\
			tcellar[cnt].mask = kernel_tcellar_ext[cnt].mask; \
		if (AS(condition).store) {				\
			e2k_addr_t kt =					\
				(e2k_addr_t)&(kernel_tcellar[cnt].data); \
			e2k_addr_t t =					\
				(e2k_addr_t)&(tcellar[cnt].data);	\
			e2k_addr_t ktx =				\
				(e2k_addr_t)&(kernel_tcellar_ext[cnt].data); \
			e2k_addr_t tx =					\
				(e2k_addr_t)&(tcellar[cnt].data_ext); \
			kvm_move_tagged_dword(kt, t);			\
			if (is_qp) {					\
				kvm_move_tagged_dword(ktx, tx);		\
			}						\
		} else if (AS(condition).s_f && AS(condition).sru) {	\
			if (cs_req_num == 0)				\
				cs_a4 = tcellar[cnt].address & (1 << 4); \
			cs_req_num++;					\
		}							\
		tcellar[cnt].flags = 0;					\
	}								\
	(trap)->tc_count = cnt * 3;					\
	kstack_pf_addr;							\
})

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* It is pure guest kernel */

#define	INIT_G_REGS()		KVM_INIT_G_REGS()
#define	BOOT_INIT_G_REGS()	BOOT_KVM_INIT_G_REGS()

#define SAVE_HW_STACKS_AT_TI(ti)	KVM_SAVE_HW_STACKS_AT_TI(ti)
#define SAVE_STACK_REGS(regs, ti, from_ti, trap) \
		KVM_SAVE_STACK_REGS(regs, ti, from_ti, trap)
#define RESTORE_HS_REGS(regs) \
		KVM_RESTORE_HS_REGS(regs)
#define RESTORE_USER_STACK_REGS(regs, in_syscall) \
		KVM_RESTORE_USER_STACK_REGS(regs, in_syscall)
#define RESTORE_USER_TRAP_STACK_REGS(regs) \
		RESTORE_USER_STACK_REGS(regs, false)
#define RESTORE_USER_SYSCALL_STACK_REGS(regs) \
		RESTORE_USER_STACK_REGS(regs, true)
#define	RESTORE_USER_CUT_REGS(ti, regs, in_sys_call) \
		KVM_RESTORE_USER_CUT_REGS(ti, regs)
#define RESTORE_COMMON_REGS(regs) \
		KVM_RESTORE_COMMON_REGS(regs)

#define CLEAR_DAM			\
({					\
	if (IS_HV_GM())			\
		NATIVE_CLEAR_DAM;	\
})

static inline void
save_glob_regs_v3(global_regs_t *gregs)
{
	if (IS_HV_GM()) {
		guest_save_glob_regs_v3(gregs);
	} else {
		kvm_save_glob_regs(gregs);
	}
}

static inline void
save_glob_regs_v5(global_regs_t *gregs)
{
	if (IS_HV_GM()) {
		guest_save_glob_regs_v5(gregs);
	} else {
		kvm_save_glob_regs(gregs);
	}
}

static inline void
save_glob_regs_dirty_bgr_v3(global_regs_t *gregs)
{
	if (IS_HV_GM()) {
		guest_save_glob_regs_dirty_bgr_v3(gregs);
	} else {
		kvm_save_glob_regs_dirty_bgr(gregs);
	}
}

static inline void
save_glob_regs_dirty_bgr_v5(global_regs_t *gregs)
{
	if (IS_HV_GM()) {
		kvm_guest_save_gregs_dirty_bgr_v5(gregs);
	} else {
		kvm_save_glob_regs_dirty_bgr(gregs);
	}
}

static inline void
save_local_glob_regs_v3(local_gregs_t *l_gregs, bool is_signal)
{
	if (IS_HV_GM()) {
		guest_save_local_glob_regs_v3(l_gregs, is_signal);
	} else {
		kvm_save_local_glob_regs(l_gregs, is_signal);
	}
}

static inline void
save_local_glob_regs_v5(local_gregs_t *l_gregs, bool is_signal)
{
	if (IS_HV_GM()) {
		guest_save_local_glob_regs_v5(l_gregs, is_signal);
	} else {
		kvm_save_local_glob_regs(l_gregs, is_signal);
	}
}

static inline void
restore_glob_regs_v3(const global_regs_t *gregs)
{
	if (IS_HV_GM()) {
		guest_restore_glob_regs_v3(gregs);
	} else {
		kvm_restore_glob_regs(gregs);
	}
}

static inline void
restore_glob_regs_v5(const global_regs_t *gregs)
{
	if (IS_HV_GM()) {
		guest_restore_glob_regs_v5(gregs);
	} else {
		kvm_restore_glob_regs(gregs);
	}
}

static inline void
restore_local_glob_regs_v3(const local_gregs_t *l_gregs, bool is_signal)
{
	if (IS_HV_GM())
		guest_restore_local_glob_regs_v3(l_gregs, is_signal);
	else
		kvm_restore_local_glob_regs(l_gregs, is_signal);
}

static inline void
restore_local_glob_regs_v5(const local_gregs_t *l_gregs, bool is_signal)
{
	if (IS_HV_GM())
		guest_restore_local_glob_regs_v5(l_gregs, is_signal);
	else
		kvm_restore_local_glob_regs(l_gregs, is_signal);
}

static inline void
save_local_glob_regs(local_gregs_t *l_gregs, bool is_signal)
{
	machine.save_local_gregs(l_gregs, is_signal);
}
static inline void
restore_local_glob_regs(const local_gregs_t *l_gregs, bool is_signal)
{
	machine.restore_local_gregs(l_gregs, is_signal);
}

static inline void
get_all_user_glob_regs(global_regs_t *gregs)
{
	if (IS_HV_GM())
		guest_get_all_user_glob_regs(gregs);
	else
		kvm_get_all_user_glob_regs(gregs);
}
#endif	/* CONFIG_KVM_GUEST_KERNEL */
#endif /* _E2K_KVM_GUEST_REGS_STATE_H */

