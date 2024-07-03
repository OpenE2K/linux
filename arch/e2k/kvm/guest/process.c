/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Guest processes management
 */
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/ftrace.h>
#include <linux/notifier.h>
#include <linux/irqflags.h>
#include <linux/vmalloc.h>
#include <linux/compat.h>
#include <asm/ucontext.h>
#include <asm/cpu_regs.h>
#include <asm/system.h>
#include <asm/process.h>
#include <asm/mmu_context.h>
#include <asm/switch_to.h>
#include <asm/kvm/guest/process.h>
#include <asm/copy-hw-stacks.h>
#include <asm/signal.h>
#include <asm/stacks.h>
#include <asm/setup.h>
#include <asm/kvm/guest/host_printk.h>

#include "process.h"
#include "traps.h"
#include "time.h"

#undef	DEBUG_PROCESS_MODE
#undef	DebugKVM
#define DEBUG_PROCESS_MODE	0
#define	DebugKVM(fmt, args...)						\
({									\
	if (DEBUG_PROCESS_MODE)						\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_SWITCH_MODE
#undef	DebugKVMSW
#define	DEBUG_KVM_SWITCH_MODE	0	/* KVM switching debugging */
#define	DebugKVMSW(fmt, args...)					\
({									\
	if (DEBUG_KVM_SWITCH_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KERNEL_STACKS_MODE
#undef	DebugKVMKS
#define DEBUG_KERNEL_STACKS_MODE	0
#define	DebugKVMKS(fmt, args...)					\
({									\
	if (DEBUG_KERNEL_STACKS_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_SWITCH_KERNEL_STACKS_MODE
#undef	DebugSWSTK
#define DEBUG_SWITCH_KERNEL_STACKS_MODE	0 /* switch to new kernel stacks */
#define	DebugSWSTK(fmt, args...)					\
({									\
	if (DEBUG_SWITCH_KERNEL_STACKS_MODE)				\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_EXEC_MODE
#undef	DebugKVMEX
#define DEBUG_KVM_EXEC_MODE	0
#define	DebugKVMEX(fmt, args...)					\
({									\
	if (DEBUG_KVM_EXEC_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_OLD_MODE
#undef	DebugOLD
#define DEBUG_KVM_OLD_MODE	0
#define	DebugOLD(fmt, args...)					\
({									\
	if (DEBUG_KVM_OLD_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_USER_STACKS_MODE
#undef	DebugKVMUS
#define DEBUG_USER_STACKS_MODE	0
#define	DebugKVMUS(fmt, args...)					\
({									\
	if (DEBUG_USER_STACKS_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

bool debug_clone_guest = false;
#undef	DEBUG_KVM_CLONE_USER_MODE		/* sys_clone() */
#undef	DebugKVMCLN
#define	DEBUG_KVM_CLONE_USER_MODE	0	/* KVM thread clone debug */
#define	DebugKVMCLN(fmt, args...)					\
({									\
	if (DEBUG_KVM_CLONE_USER_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_COPY_USER_MODE
#undef	DebugKVMCPY
#define	DEBUG_KVM_COPY_USER_MODE	0	/* KVM process copy debugging */
#define	DebugKVMCPY(fmt, args...)					\
({									\
	if (DEBUG_KVM_COPY_USER_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_GMM_MODE
#undef	DebugGMM
#define	DEBUG_KVM_GMM_MODE	0	/* GMM creation debug */
#define	DebugGMM(fmt, args...)						\
({									\
	if (DEBUG_KVM_GMM_MODE)						\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_UNHOST_STACKS_MODE
#undef	DebugKVMUH
#define DEBUG_UNHOST_STACKS_MODE	0
#define	DebugKVMUH(fmt, args...)					\
({									\
	if (DEBUG_UNHOST_STACKS_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_SIGNAL_MODE
#undef	DebugSIG
#define DEBUG_SIGNAL_MODE	0
#define	DebugSIG(fmt, args...)						\
({									\
	if (DEBUG_SIGNAL_MODE)						\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_GUEST_HS_MODE
#undef	DebugGHS
#define	DEBUG_GUEST_HS_MODE	0	/* Hard Stack expantions */
#define	DebugGHS(fmt, args...)						\
({									\
	if (DEBUG_GUEST_HS_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_SHUTDOWN_MODE
#undef	DebugKVMSH
#define	DEBUG_KVM_SHUTDOWN_MODE	1	/* KVM shutdown debugging */
#define	DebugKVMSH(fmt, args...)					\
({									\
	if (DEBUG_KVM_SHUTDOWN_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_IDLE_MODE
#undef	DebugKVMIDLE
#define	DEBUG_KVM_IDLE_MODE	0	/* KVM idle debugging */
#define	DebugKVMIDLE(fmt, args...)					\
({									\
	if (DEBUG_KVM_IDLE_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

static long kvm_finish_switch_to_new_process(void);

/*
 * in Makefile -D__builtin_return_address=__e2k_kernel_return_address
 */
void *kvm_nested_kernel_return_address(int n)
{
	e2k_addr_t	ret = 0UL;
	e2k_cr0_hi_t	cr0_hi;
	u64		base;
	u64		size;
	s64		cr_ind;

	NATIVE_FLUSHC;
	NATIVE_FLUSHC;
	E2K_WAIT_ALL;
	ATOMIC_GET_HW_PCS_SIZES_AND_BASE(cr_ind, size, base);
	cr0_hi = NATIVE_NV_READ_CR0_HI_REG();
	ret = AS_STRUCT(cr0_hi).ip << 3;
	DebugKVM("base 0x%llx ind 0x%llx\n", base, cr_ind);
	n++;
	while (n--) {
		cr_ind = cr_ind  - SZ_OF_CR;
		if (cr_ind < 0) {
			dump_stack();
			return NULL;
		}
		AS_WORD(cr0_hi) = *((u64 *)(base + cr_ind + CR0_HI_I));
		ret = AS_STRUCT(cr0_hi).ip << 3;
		DebugKVM("IP 0x%lx\n", ret);
	}

	return (void *)ret;
}

/*
 * Procedure chain stacks can be mapped to user (user processes)
 * or kernel space (kernel threads). But mapping is always to privileged area
 * and directly can be accessed only by host kernel.
 * SPECIAL CASE: access to current procedure chain stack:
 *	1. Current stack frame must be locked (resident), so access is
 * safety and can use common load/store operations
 *	2. Top of stack can be loaded to the special hardware register file and
 * must be spilled to memory before any access.
 *	3. If items of chain stack are not updated, then spilling is enough to
 * their access
 *	4. If items of chain stack are updated, then interrupts and
 * any calling of function should be disabled in addition to spilling,
 * because of return (done) will fill some part of stack from memory and can be
 * two copy of chain stack items: in memory and in registers file.
 * We can update only in memory and following spill recover not updated
 * value from registers file.
 * So guest kernel can access to items of procedure chain stacks only through
 * host kernel hypercall
 */
static inline unsigned long
kvm_get_active_cr_mem_value(e2k_addr_t base, e2k_addr_t cr_ind,
						e2k_addr_t cr_item)
{
	unsigned long cr_value;
	int error;

	error = HYPERVISOR_get_active_cr_mem_item(&cr_value,
						base, cr_ind, cr_item);
	if (error) {
		panic("could not get active procedure chain stack item: "
			"base 0x%lx index 0x%lx item offset 0x%lx, error %d\n",
			base, cr_ind, cr_item, error);
	}
	return cr_value;
}
static inline void
kvm_put_active_cr_mem_value(unsigned long cr_value, e2k_addr_t base,
				e2k_addr_t cr_ind, e2k_addr_t cr_item)
{
	int error;

	error = HYPERVISOR_put_active_cr_mem_item(cr_value,
						base, cr_ind, cr_item);
	if (error) {
		panic("could not put active procedure chain stack item: "
			"base 0x%lx index 0x%lx item offset 0x%lx, error %d\n",
			base, cr_ind, cr_item, error);
	}
}
unsigned long
kvm_get_active_cr0_lo_value(e2k_addr_t base, e2k_addr_t cr_ind)
{
	return kvm_get_active_cr_mem_value(base, cr_ind, CR0_LO_I);
}
unsigned long
kvm_get_active_cr0_hi_value(e2k_addr_t base, e2k_addr_t cr_ind)
{
	return kvm_get_active_cr_mem_value(base, cr_ind, CR0_HI_I);
}
unsigned long
kvm_get_active_cr1_lo_value(e2k_addr_t base, e2k_addr_t cr_ind)
{
	return kvm_get_active_cr_mem_value(base, cr_ind, CR1_LO_I);
}
unsigned long
kvm_get_active_cr1_hi_value(e2k_addr_t base, e2k_addr_t cr_ind)
{
	return kvm_get_active_cr_mem_value(base, cr_ind, CR1_HI_I);
}
void kvm_put_active_cr0_lo_value(unsigned long cr_value,
					e2k_addr_t base, e2k_addr_t cr_ind)
{
	 kvm_put_active_cr_mem_value(cr_value, base, cr_ind, CR0_LO_I);
}
void kvm_put_active_cr0_hi_value(unsigned long cr_value,
					e2k_addr_t base, e2k_addr_t cr_ind)
{
	 kvm_put_active_cr_mem_value(cr_value, base, cr_ind, CR0_HI_I);
}
void kvm_put_active_cr1_lo_value(unsigned long cr_value,
					e2k_addr_t base, e2k_addr_t cr_ind)
{
	 kvm_put_active_cr_mem_value(cr_value, base, cr_ind, CR1_LO_I);
}
void kvm_put_active_cr1_hi_value(unsigned long cr_value,
					e2k_addr_t base, e2k_addr_t cr_ind)
{
	 kvm_put_active_cr_mem_value(cr_value, base, cr_ind, CR1_HI_I);
}

/*
 * The function defines sizes of all guest kernel hardware stacks(PS & PCS)
 * including host kernel part of the hardware stacks
 *
 * FIXME: host kernel stacks size additions should be determined
 * by host (hypercall or some shared common interface structure)
 */
void kvm_define_kernel_hw_stacks_sizes(hw_stack_t *hw_stacks)
{
	kvm_set_hw_ps_user_size(hw_stacks, KVM_GUEST_KERNEL_PS_SIZE);
	kvm_set_hw_pcs_user_size(hw_stacks, KVM_GUEST_KERNEL_PCS_SIZE);
}

int kvm_clean_pc_stack_zero_frame_kernel(void *addr)
{
	e2k_mem_crs_t *pcs;
	int ret;

	pcs = (e2k_mem_crs_t *)addr;

	ret = native_clean_pc_stack_zero_frame_kernel(pcs);
	if (ret)
		return ret;

	return 0;
}

int kvm_clean_pc_stack_zero_frame_user(void __user *addr)
{
	struct page *page;
	unsigned long u_addr, k_addr, offset;
	e2k_mem_crs_t *pcs;
	int ret;

	/*
	 * Guest user hardware stacks are mapped as privileged,
	 * but guest kernel is running as not privileged.
	 * Convert user address to virtual address of kernel page
	 */
	u_addr = (unsigned long)addr;
	page = get_user_addr_to_kernel_page(u_addr);
	if (unlikely(IS_ERR_OR_NULL(page))) {
		ret = (IS_ERR(page)) ? PTR_ERR(page) : -EINVAL;
		goto failed;
	}
	offset = u_addr & ~PAGE_MASK;
	k_addr = (unsigned long)page_address(page) + offset;
	pcs = (e2k_mem_crs_t *)k_addr;

	ret = native_clean_pc_stack_zero_frame_kernel(pcs);

	put_user_addr_to_kernel_page(page);

	return ret;

failed:
	if (ret == -ERESTARTSYS)
		/* there is/are pending fatal signal(s) */
		/* and task should be killed some later */
		return ret;

	pr_err("%s(): failed to get kernel page of user address %px, error %d\n",
		__func__, addr, ret);
	send_sig(SIGKILL, current, 0);
	return ret;
}

e2k_cute_t __user *kvm_get_cut_entry_pointer(int cui, struct page **page_p)
{
	struct page *page;
	unsigned long u_cute_p, k_cute_p, offset;
	int ret;

	u_cute_p = (unsigned long)native_get_cut_entry_pointer(cui);
	page = get_user_addr_to_kernel_page(u_cute_p);
	if (unlikely(IS_ERR_OR_NULL(page))) {
		ret = (IS_ERR(page)) ? PTR_ERR(page) : -EINVAL;
		goto failed;
	}
	offset = u_cute_p & ~PAGE_MASK;
	k_cute_p = (unsigned long)page_address(page) + offset;

	*page_p = page;
	return (e2k_cute_t *)k_cute_p;

failed:
	if (ret == -ERESTARTSYS) {
		/* there is/are pending fatal signal(s) */
		/* and task should be killed some later */
		;
	} else {
		pr_err("%s(): failed to get kernel page of user address %lx, "
			"error %d\n",
			__func__, u_cute_p, ret);
	}
	return NULL;
}

void kvm_put_cut_entry_pointer(struct page *page)
{
	put_user_addr_to_kernel_page(page);
}

int kvm_prepare_start_thread_frames(unsigned long entry, unsigned long sp)
{
	e2k_pcsp_lo_t	pcsp_lo;
	e2k_psp_lo_t	psp_lo;
	e2k_mem_crs_t	*pcs;
	e2k_mem_ps_t	*ps;
	e2k_mem_crs_t	pcs_frames[1];	/* 1 frames */
	kernel_mem_ps_t	ps_frames[2];	/* Assume a maximum of 4 */
					/* do_sys_execve()'s parameters */
	int pcs_frame_ind;
	int ps_frame_ind;
	int ps_frame_size;
	int ret;

	DebugKVMEX("entry 0x%lx sp 0x%lx\n", entry, sp);

	KVM_COPY_STACKS_TO_MEMORY();

	psp_lo = NATIVE_NV_READ_PSP_LO_REG();
	ps = (e2k_mem_ps_t *)psp_lo.PSP_lo_base;
	pcsp_lo = NATIVE_NV_READ_PCSP_LO_REG();
	pcs = (e2k_mem_crs_t *)pcsp_lo.PCSP_lo_base;
	DebugKVMEX("PS base %px ind 0x%x, PCS base %px ind 0x%x\n",
		ps, NATIVE_NV_READ_PSP_HI_REG().PSP_hi_ind,
		pcs, NATIVE_NV_READ_PCSP_HI_REG().PSP_hi_ind);

	/* PS & PCS stack frames should be updated, but guest cannot */
	/* preserves current updated frames from fill/spill and some */
	/* updates can be lost. So prepare frames in temporary storage */

	/* pcs[0] frame can be empty, because of it should not be returns */
	/* here and it is used only to fill into current CR registers */
	/* while run function on the next frame pcs[1] */
	DebugKVMEX("PCS[0]: IP %pF wbs 0x%x\n",
		(void *)(pcs[0].cr0_hi.CR0_hi_ip << 3),
		pcs[0].cr1_lo.CR1_lo_wbs * EXT_4_NR_SZ);

	/* Prepare pcs[1] frame, it is frame of do_sys_execve() */
	/* Update only IP (as start of function) */
	DebugKVMEX("PCS[1]: IP %pF wbs 0x%x\n",
		(void *)(pcs[1].cr0_hi.CR0_hi_ip << 3),
		pcs[1].cr1_lo.CR1_lo_wbs * EXT_4_NR_SZ);
	*pcs_frames = pcs[1];
	pcs_frame_ind = (1 * SZ_OF_CR);	/* 1-st frame index */

	// TODO execve now works the same way as other system calls, should
	// use generic handle_sys_call() to enter the new thread instead.
	//
	// pcs_frames[0].cr0_hi.CR0_hi_ip = (unsigned long) &do_sys_execve >> 3;
	BUG();

	DebugKVMEX("updated PCS[1]: IP %pF wbs 0x%x\n",
		(void *)(pcs_frames[0].cr0_hi.CR0_hi_ip << 3),
		pcs_frames[0].cr1_lo.CR1_lo_wbs * EXT_4_NR_SZ);

	/* prepare procedure stack frame ps[0] for pcs[1] should contain */
	/* do_sys_execve()'s function arguments */
	ps_frame_ind = 0;			/* update 0 frame from base */
	ps_frames[0].word_lo = entry;		/* %dr0	*/
	ps_frames[0].word_hi = sp;		/* %dr1	*/
	ps_frames[1].word_lo = true;		/* %dr2	*/
	ps_frame_size = (2 * EXT_4_NR_SZ);	/* 4 double-word registers */

retry:
	ret = HYPERVISOR_update_hw_stacks_frames(pcs_frames, pcs_frame_ind,
				ps_frames, ps_frame_ind, ps_frame_size);
	if (unlikely(ret == -EAGAIN)) {
		DebugKVMEX("could not update hardware stacks, error %d "
			"retry\n", ret);
		goto retry;
	} else if (unlikely(ret < 0)) {
		DebugKVMEX("could not update hardware stacks, error %d\n",
				ret);
	}

	return ret;
}

/**
 * prepare_kernel_frame - prepare for return to kernel function
 * @stacks - allocated stacks' parameters (will be corrected)
 * @crs - chain stack frame will be returned here
 * @fn - function to return to
 * @arg - function's argument
 *
 * Note that cr1_lo.psr value is taken from PSR register. This means
 * that interrupts and sge are expected to be enabled by caller.
 * It is paravirtualized KVM version of function.
 * In this case real switch is done by host (hypercall), so
 *    1) some more frames it need to prepare and
 *    2) chain frames should be into memory (new chain stack)
 */
static void kvm_prepare_kernel_frame(struct sw_regs *new_sw_regs,
		e2k_mem_crs_t *crs, unsigned long fn, unsigned long arg)
{
	e2k_cr0_lo_t cr0_lo;
	e2k_cr0_hi_t cr0_hi;
	e2k_cr1_lo_t cr1_lo;
	e2k_cr1_hi_t cr1_hi;
	e2k_psr_t psr;
	e2k_mem_crs_t *pcs;
	unsigned long *ps;
	int ps_size;
	int pcs_size;

	psr.PSR_reg = NATIVE_NV_READ_PSR_REG_VALUE();
	BUG_ON(!psr.PSR_sge && !IS_HV_GM());

	pcs = (e2k_mem_crs_t *)new_sw_regs->pcsp_lo.PCSP_lo_base;
	ps = (unsigned long *)new_sw_regs->psp_lo.PSP_lo_base;

	/* Prepare pcs[0] frame, it can be empty, because of should */
	/* not be returns here and it is used only to fill into current */
	/* CR registers while run function @fn on the next frame pcs[1] */
	pcs_size = SZ_OF_CR;

	/* procedure stack frame ps[-1] for pcs[0] not exists */
	ps_size = 0;


	/*
	 * Prepare crs[1] frame in chain stack. It should also be reserved
	 * because it is used by kvm_prepare_start_thread_frames for
	 * creation of new kernel thread via do_execve.
	 * kvm_prepare_start_thread_frames will rewrite this frame
	 * by do_sys_execve function.
	 */
	cr0_lo.CR0_lo_half = 0;
	cr0_lo.CR0_lo_pf = -1ULL;

	cr0_hi.CR0_hi_ip = 0; /* TODO: need handler of return here */

	cr1_lo.CR1_lo_half = 0;
	cr1_lo.CR1_lo_psr = psr.PSR_reg;
	cr1_lo.CR1_lo_cui = KERNEL_CODES_INDEX;
	if (machine.native_iset_ver < E2K_ISET_V6)
		AS(cr1_lo).ic = 0;
	cr1_lo.CR1_lo_wbs = 4;	/* 2 quad regs (4 doubles) */

	cr1_hi.CR1_hi_half = 0;
	cr1_hi.CR1_hi_ussz = new_sw_regs->usd_hi.USD_hi_size / 16;

	pcs[1].cr0_lo = cr0_lo;
	pcs[1].cr0_hi = cr0_hi;
	pcs[1].cr1_lo = cr1_lo;
	pcs[1].cr1_hi = cr1_hi;
	pcs_size += SZ_OF_CR;	/* 1 frame size */
	ps_size += (4 * EXT_4_NR_SZ);  /* 4 double args */


	/* Prepare crs[2] frame: @fn's frame in chain stack */
	/* The frame should be into memory and will fill after return to @fn */
	cr0_hi.CR0_hi_ip = fn >> 3;
	cr1_lo.CR1_lo_wbs = 1;	/* extended quad register (2 double) */

	pcs[2].cr0_lo = cr0_lo;
	pcs[2].cr0_hi = cr0_hi;
	pcs[2].cr1_lo = cr1_lo;
	pcs[2].cr1_hi = cr1_hi;
	pcs_size += SZ_OF_CR;	/* 1 frame size */

	/*
	 * Prepare procedure stack frame ps[EXT_4_NR_SZ] for pcs[2]
	 * should contain @fn's function argument @arg
	 */
	ps[4*EXT_4_NR_SZ/sizeof(unsigned long)] = arg;
	/* ps[2] not used, only reserved for aligement */
	/* @fn'S function procedure stack frame size is 1 quad register */
	/* (at memory it is 2 double + 2 double extentions */
	ps_size += (1 * EXT_4_NR_SZ);

	/* Prepare crs[3] frame: kvm_finish_switch_to_new_process()'s frame */
	/* The frame is used as return function from hypercall after real */
	/* switch of context to new process */
	/* The registers of the frame should be into sw_regs structure */
	/* and can be not at stack memory */
	cr0_hi.CR0_hi_IP = (u64)&kvm_finish_switch_to_new_process;
	/* other CRs can be same as at previous @fn's frame? including */
	/* wbs (1 quad register) and ussz (data stack frame not used) */

	crs->cr0_lo = cr0_lo;
	crs->cr0_hi = cr0_hi;
	crs->cr1_lo = cr1_lo;
	crs->cr1_hi = cr1_hi;

	/* prepare procedure stack frame ps[2] for pcs[3] */
	/* it will be filled from stack at memory, so should be reserved */
	/* kvm_finish_switch_to_new_process() set real frame sizes */
	/* Here reserved procedure stack frame for 1 quad register */
	/* (at memory it is 2 double + 2 double extentions */
	ps_size += (1 * EXT_4_NR_SZ);

	/* Update hardware stacks registers to point to prepared frames */
	new_sw_regs->pcsp_hi.PCSP_hi_ind = pcs_size;
	new_sw_regs->psp_hi.PSP_hi_ind = ps_size;
}

int kvm_copy_kernel_stacks(struct task_struct *new_task,
				unsigned long fn, unsigned long arg)
{
	thread_info_t	*new_ti = task_thread_info(new_task);
	struct sw_regs	*new_sw_regs = &new_task->thread.sw_regs;
	kvm_task_info_t	task_info;
	e2k_size_t	ps_size;
	e2k_size_t	pcs_size;
	int		ret;

	DebugKVMKS("started to create new kernel thread %s (%d)\n",
		new_task->comm, new_task->pid);

	/*
	 * Put function IP and argument to chain and procedure stacks.
	 */
	kvm_prepare_kernel_frame(new_sw_regs, &new_sw_regs->crs, fn, arg);
	DebugKVMKS("new kernel data stack: top 0x%lx, base 0x%llx, size 0x%x\n",
		new_sw_regs->top,
		new_ti->k_usd_lo.USD_lo_base,
		new_ti->k_usd_hi.USD_hi_size);
	DebugKVMKS("procedure stack: base 0x%llx size 0x%x index 0x%x\n",
		new_ti->k_psp_lo.PSP_lo_base,
		new_ti->k_psp_hi.PSP_hi_size,
		new_ti->k_psp_hi.PSP_hi_ind);
	DebugKVMKS("chain stack: base 0x%llx size 0x%x index 0x%x\n",
		new_ti->k_pcsp_lo.PCSP_lo_base,
		new_ti->k_pcsp_hi.PCSP_hi_size,
		new_ti->k_pcsp_hi.PCSP_hi_ind);

	task_info.sp_offset = new_sw_regs->usd_hi.USD_hi_size;
	task_info.us_base = (u64)new_task->stack + KERNEL_C_STACK_OFFSET;
	task_info.us_size = KERNEL_C_STACK_SIZE;
	task_info.flags = 0;
	DebugKVMKS("local data stack from 0x%lx size 0x%lx SP offset 0x%lx\n",
		task_info.us_base, task_info.us_size, task_info.sp_offset);

	BUG_ON(task_info.sp_offset > task_info.us_size);

	ps_size = new_sw_regs->psp_hi.PSP_hi_size;
	task_info.ps_base = new_sw_regs->psp_lo.PSP_lo_base;
	task_info.ps_ind = new_sw_regs->psp_hi.PSP_hi_ind;
	task_info.ps_size = ps_size;
	DebugKVMKS("procedure stack from 0x%lx size 0x%lx, index 0x%lx\n",
		task_info.ps_base, task_info.ps_size, task_info.ps_ind);

	pcs_size = new_sw_regs->pcsp_hi.PCSP_hi_size;
	task_info.pcs_base = new_sw_regs->pcsp_lo.PCSP_lo_base;
	task_info.pcs_ind = new_sw_regs->pcsp_hi.PCSP_hi_ind;
	task_info.pcs_size = pcs_size;
	task_info.flags |= (PS_HAS_NOT_GUARD_PAGE_TASK_FLAG |
				PCS_HAS_NOT_GUARD_PAGE_TASK_FLAG);
	DebugKVMKS("procedure chain stack from 0x%lx size 0x%lx, index 0x%lx\n",
		task_info.pcs_base, task_info.pcs_size, task_info.pcs_ind);

	task_info.cr0_lo = new_sw_regs->crs.cr0_lo.CR0_lo_half;
	task_info.cr0_hi = new_sw_regs->crs.cr0_hi.CR0_hi_half;
	task_info.cr1_wd = new_sw_regs->crs.cr1_lo.CR1_lo_half;
	task_info.cr1_ussz = new_sw_regs->crs.cr1_hi.CR1_hi_half;
	DebugKVMKS("chain registers: IP %pF, wbs 0x%lx, ussz 0x%lx\n",
		(void *)(task_info.cr0_hi), task_info.cr1_wd,
		task_info.cr1_ussz);

	ret = HYPERVISOR_copy_guest_kernel_stacks(&task_info);
	if (ret < 0) {
		pr_err("%s(): could not create new kernel thread, error %d\n",
			__func__, ret);
		goto out_k_stacks;
	}
	DebugKVMKS("created new kernel thread, GPID #%d\n", ret);
	new_ti->gpid_nr = ret;
	new_ti->gmmid_nr = current_thread_info()->gmmid_nr;

	new_sw_regs->crs.cr0_lo.CR0_lo_half = task_info.cr0_lo;
	new_sw_regs->crs.cr0_hi.CR0_hi_half = task_info.cr0_hi;
	new_sw_regs->crs.cr1_lo.CR1_lo_half = task_info.cr1_wd;
	new_sw_regs->crs.cr1_hi.CR1_hi_half = task_info.cr1_ussz;

	return 0;

out_k_stacks:
	return ret;
}

int kvm_do_parse_chain_stack(bool user, struct task_struct *p,
		parse_chain_fn_t func, void *arg, unsigned long delta_user,
		unsigned long top, unsigned long bottom)
{
	struct page *page;
	e2k_size_t offset, len, parsed = 0, to_parse;
	unsigned long k_top, k_bottom;
	int ret;

	if (top >= GUEST_PAGE_OFFSET) {
		/* it is parsing withing addresses of the guest kernel stack, */
		/* translation of guest user addresses in kernel do not need */
		BUG_ON(bottom < GUEST_PAGE_OFFSET);
		return ____parse_chain_stack(user, p, func, arg, delta_user, top, bottom);
	}

	/*
	 * Guest kernel cannot access to/from guest user hardware stacks
	 * because of these stacks are allocated at user space and
	 * are mapped as privileged.
	 * So it need translation user stack addresses to kernel pages
	 * at which the stack is loaded
	 */
	BUG_ON(bottom > top + SZ_OF_CR);
	if (bottom >= top) {
		return 0;
	}
	to_parse = top - bottom;
	do {
		offset = (unsigned long)top & ~PAGE_MASK;
		len = min(to_parse, (offset) ? offset : PAGE_SIZE);
		page = get_user_addr_to_kernel_page((offset) ? top : top - 1);
		if (unlikely(IS_ERR_OR_NULL(page))) {
			ret = (IS_ERR(page)) ? PTR_ERR(page) : -EINVAL;
			goto failed;
		}

		k_top = (unsigned long)page_address(page) + offset;
		if (offset == 0)
			k_top += PAGE_SIZE;
		k_bottom = k_top - len;
		delta_user = top - k_top;

		ret = ____parse_chain_stack(user, p, func, arg, delta_user, k_top, k_bottom);
		put_user_addr_to_kernel_page(page);
		if (ret != 0)
			break;
		top -= len;
		to_parse -= len;
		parsed += len;
	} while (top > bottom);

failed:
	return ret;

}

void __init kvm_bsp_switch_to_init_stack(void)
{
	kvm_task_info_t	task_info;
	e2k_addr_t stack_base = (unsigned long) &init_stack;
	e2k_addr_t us_base;
	e2k_addr_t ps_base;
	e2k_addr_t pcs_base;
	int ret;

	us_base = stack_base + KERNEL_C_STACK_OFFSET;
	ps_base = stack_base + KERNEL_P_STACK_OFFSET;
	pcs_base = stack_base + KERNEL_PC_STACK_OFFSET;

	task_info.sp_offset = KERNEL_C_STACK_SIZE;
	task_info.us_base = us_base;
	task_info.us_size = KERNEL_C_STACK_SIZE;
	task_info.flags = 0;
	DebugSWSTK("local data stack from 0x%lx size 0x%lx SP offset 0x%lx\n",
		task_info.us_base, task_info.us_size, task_info.sp_offset);

	BUG_ON(task_info.sp_offset > task_info.us_size);

	task_info.ps_base = ps_base;
	task_info.ps_ind = 0;
	task_info.ps_size = KERNEL_P_STACK_SIZE;
	DebugSWSTK("procedure stack from 0x%lx size 0x%lx, index 0x%lx\n",
		task_info.ps_base, task_info.ps_size, task_info.ps_ind);

	task_info.pcs_base = pcs_base;
	task_info.pcs_ind = 0;
	task_info.pcs_size = KERNEL_PC_STACK_SIZE;
	DebugSWSTK("procedure chain stack from 0x%lx size 0x%lx, index 0x%lx\n",
		task_info.pcs_base, task_info.pcs_size, task_info.pcs_ind);

	ret = HYPERVISOR_switch_guest_kernel_stacks(&task_info,
			(char *) &e2k_start_kernel_switched_stacks, NULL, 0);
	if (ret < 0) {
		panic("%s(): could not switch to init kernel stacks, "
			"error %d\n",
			__func__, ret);
	}
}

void kvm_setup_bsp_idle_task(int cpu)
{
	struct task_struct *idle = &init_task;
	struct thread_info *ti_idle;
	int ret;

	native_setup_bsp_idle_task(cpu);

	/* setup the idle task on host (get GPID_ID #) */
	ret = HYPERVISOR_setup_idle_task(cpu);
	if (ret < 0) {
		panic("%s(): could not setup CPU #%d idle task on host, "
			"error %d\n",
			__func__, cpu, ret);
	}
	ti_idle = task_thread_info(idle);
	BUG_ON(ti_idle != &init_task.thread_info);

	ti_idle->gpid_nr = ret;

	/* init mm should have GMMID == 0 */
	ti_idle->gmmid_nr = 0;
	init_mm.gmmid_nr = 0;
}

/*
 * The function defines sizes of all guest user hardware stacks(PS & PCS)
 * including host and guest kernel part of the hardware stacks
 *
 * FIXME: host kernel stacks size additions should be determined
 * by host (hypercall or some shared common interface structure)
 */
void kvm_define_user_hw_stacks_sizes(hw_stack_t *hw_stacks)
{
	kvm_set_hw_ps_user_size(hw_stacks, KVM_GUEST_USER_PS_INIT_SIZE);
	kvm_set_hw_pcs_user_size(hw_stacks, KVM_GUEST_USER_PCS_INIT_SIZE);
}

static long kvm_finish_switch_to_new_process(void)
{
	/* Restore interrupt mask and enable NMIs */
	RESTORE_IRQ_REG(AW(current->thread.sw_regs.psr),
			AW(current->thread.sw_regs.upsr));

	E2K_JUMP_WITH_ARGUMENTS(__ret_from_fork, 1,
			current->thread.sw_regs.prev_task);

	return (long)current->thread.sw_regs.prev_task;
}

int kvm_switch_to_new_user(e2k_stacks_t *stacks, hw_stack_t *hw_stacks,
			e2k_addr_t cut_base, e2k_size_t cut_size,
			e2k_addr_t entry_point, int cui,
			unsigned long flags, bool kernel)
{
	thread_info_t *thread_info = current_thread_info();
	kvm_task_info_t task_info;
	int ret;

	DebugKVMEX("started\n");
	task_info.flags = flags;
	task_info.u_us_base = stacks->usd_lo.USD_lo_base -
				stacks->usd_hi.USD_hi_size;
	task_info.u_us_size = stacks->top - task_info.u_us_base;
	task_info.u_sp_offset = stacks->usd_hi.USD_hi_size;
	DebugKVMEX("local data stack from 0x%lx size 0x%lx SP "
		"offset 0x%lx %s\n",
		task_info.u_us_base, task_info.u_us_size, task_info.u_sp_offset,
		(task_info.flags & PROTECTED_CODE_TASK_FLAG) ?
					"protected" : "not protected");
	BUG_ON(task_info.u_sp_offset > task_info.u_us_size);

	task_info.u_ps_base = stacks->psp_lo.PSP_lo_base;
	task_info.u_ps_size = stacks->psp_hi.PSP_hi_size;
	task_info.u_ps_ind = stacks->psp_hi.PSP_hi_ind;
	DebugKVMEX("procedure stack from 0x%lx size 0x%lx\n",
		task_info.u_ps_base, task_info.u_ps_size);
	task_info.u_pcs_base = stacks->pcsp_lo.PCSP_lo_base;
	task_info.u_pcs_size = stacks->pcsp_hi.PCSP_hi_size;
	task_info.u_pcs_ind = stacks->pcsp_hi.PCSP_hi_ind;
	DebugKVMEX("procedure chain stack from 0x%lx size 0x%lx\n",
		task_info.u_pcs_base, task_info.u_pcs_size);

	task_info.flags |= (PS_HAS_NOT_GUARD_PAGE_TASK_FLAG |
				PCS_HAS_NOT_GUARD_PAGE_TASK_FLAG);

	BUG_ON(thread_info->u_cutd.CUTD_base != cut_base);
	task_info.cut_base = cut_base;
	task_info.cut_size = cut_size;
	task_info.cui = cui;
	task_info.kernel = kernel;

	DebugKVMEX("compilation unit table CUT from 0x%lx size 0x%lx CUI %d\n",
		task_info.cut_base, task_info.cut_size, task_info.cui);
	task_info.entry_point = entry_point;
	DebugKVMEX("entry point to user 0x%lx\n", task_info.entry_point);

	thread_info->u_hw_stack = *hw_stacks;

	/*
	 * Set kernel local stack to empty state and forget old history
	 * of the process and start new life on new process
	 */
	thread_info->k_usd_lo.USD_lo_base =
		(u64)current->stack + KERNEL_C_STACK_SIZE;
	thread_info->k_usd_hi.USD_hi_size = KERNEL_C_STACK_SIZE;
	DebugKVMEX("set kernel local data stack to empty state: base 0x%llx "
		"size 0x%x\n",
		thread_info->k_usd_lo.USD_lo_base,
		thread_info->k_usd_hi.USD_hi_size);

	task_info.us_base = (u64)current->stack;
	task_info.us_size = KERNEL_C_STACK_SIZE;
	DebugKVMEX("kernel local data stack from 0x%lx size 0x%lx\n",
		task_info.us_base, task_info.us_size);

	task_info.ps_base = thread_info->k_psp_lo.PSP_lo_base;
	task_info.ps_size = thread_info->k_psp_hi.PSP_hi_size;
	DebugKVMEX("kernel procedure stack from 0x%lx size 0x%lx\n",
		task_info.ps_base, task_info.ps_size);

	task_info.pcs_base = thread_info->k_pcsp_lo.PCSP_lo_base;
	task_info.pcs_size = thread_info->k_pcsp_hi.PCSP_hi_size;
	DebugKVMEX("kernel procedure chain stack from 0x%lx size 0x%lx\n",
		task_info.pcs_base, task_info.pcs_size);

	/* Set flag to free the old hardware stacks after */
	/* real switch to the new ones and new user process */
	if (kernel) {
		DebugOLD("thread info %px old: ps %px pcs %px\n",
			thread_info,
			thread_info->old_ps_base, thread_info->old_pcs_base);
		BUG_ON(thread_info->old_ps_base != NULL ||
				thread_info->old_pcs_base != NULL);
	} else {
	}

	/* switch to IRQs control under PSR and init user UPSR */
	KVM_RETURN_TO_INIT_USER_UPSR();

retry:
	ret = HYPERVISOR_switch_to_guest_new_user(&task_info);
	if (unlikely(ret == -EAGAIN)) {
		DebugKVM("could not switch to new user process, error %d, "
			"retry\n", ret);
		goto retry;
	} else if (unlikely(ret < 0)) {
		DebugKVM("could not switch to new user process, error %d\n",
			ret);
		goto out;
	}

	/* successful switch to new user should not return here */
	panic("%s(): return from user execve()\n", __func__);
	ret = 1;	/* return from guest user process */

out:
	return ret;
}

int kvm_clone_prepare_spilled_user_stacks(e2k_stacks_t *child_stacks,
		const e2k_mem_crs_t *child_crs, const struct pt_regs *regs,
		struct sw_regs *new_sw_regs, struct thread_info *new_ti,
		unsigned long clone_flags)
{
	struct task_struct *new_task = thread_info_task(new_ti);
	kvm_task_info_t task_info;
	e2k_addr_t sbr;
	int ret, gpid_nr;

	if (DEBUG_KVM_CLONE_USER_MODE)
		debug_clone_guest = true;

	/* copy user's part of kernel hardware stacks */
	ret = native_clone_prepare_spilled_user_stacks(child_stacks, child_crs,
			regs, new_sw_regs, new_ti, clone_flags);
	if (ret != 0) {
		pr_err("%s(): native clone/prepare user stacks failed, "
			"error %d\n",
			__func__, ret);
		goto out_error;
	}

	/*
	 * Register new thread on host and complete new guest user thread
	 * creation
	 */
	/* guest kernel local data stack */
	task_info.sp_offset = new_sw_regs->usd_hi.USD_hi_size;
	task_info.us_base = new_sw_regs->usd_lo.USD_lo_base -
				new_sw_regs->usd_hi.USD_hi_size;
	task_info.us_size = new_sw_regs->top - task_info.us_base;
	/* guest user local data stack */
	sbr = round_up(child_stacks->top, E2K_ALIGN_STACK_BASE_REG);
	child_stacks->top = sbr;
	task_info.u_sp_offset = child_stacks->usd_hi.USD_hi_size;
	task_info.u_us_base = child_stacks->usd_lo.USD_lo_base -
				child_stacks->usd_hi.USD_hi_size;
	task_info.u_us_size = child_stacks->top - task_info.u_us_base;

	task_info.flags = 0;
	if (new_task->thread.flags & E2K_FLAG_PROTECTED_MODE)
		task_info.flags |= PROTECTED_CODE_TASK_FLAG;
	if (TASK_IS_BINCO(new_task))
		task_info.flags |= BIN_COMP_CODE_TASK_FLAG;
	DebugKVMCLN("kernel data stack from 0x%lx size 0x%lx SP offset 0x%lx\n",
		task_info.us_base, task_info.us_size, task_info.sp_offset);
	DebugKVMCLN("user data stack from 0x%lx size 0x%lx SP offset 0x%lx "
		"%s\n",
		task_info.u_us_base, task_info.u_us_size,
		task_info.u_sp_offset,
		(task_info.flags & PROTECTED_CODE_TASK_FLAG) ?
					"protected" : "not protected");
	BUG_ON(task_info.sp_offset > task_info.us_size);
	BUG_ON(task_info.u_sp_offset > task_info.u_us_size);

	/* guest kernel procedure stack */
	task_info.ps_base = new_sw_regs->psp_lo.PSP_lo_base;
	task_info.ps_size = new_sw_regs->psp_hi.PSP_hi_size;
	task_info.ps_ind = new_sw_regs->psp_hi.PSP_hi_ind;
	DebugKVMCLN("kernel procedure stack from 0x%lx size 0x%lx ind 0x%lx\n",
		task_info.ps_base, task_info.ps_size, task_info.ps_ind);
	/* guest user procedure stack */
	task_info.u_ps_base = child_stacks->psp_lo.PSP_lo_base;
	task_info.u_ps_size = child_stacks->psp_hi.PSP_hi_size;
	task_info.u_ps_ind = child_stacks->psp_hi.PSP_hi_ind;
	DebugKVMCLN("user procedure stack from 0x%lx size 0x%lx ind 0x%lx\n",
		task_info.u_ps_base, task_info.u_ps_size, task_info.u_ps_ind);

	/* guest kernel procedure chain stack */
	task_info.pcs_base = new_sw_regs->pcsp_lo.PCSP_lo_base;
	task_info.pcs_size = new_sw_regs->pcsp_hi.PCSP_hi_size;
	task_info.pcs_ind = new_sw_regs->pcsp_hi.PCSP_hi_ind;
	DebugKVMCLN("kernel procedure chain stack from 0x%lx size 0x%lx "
		"ind 0x%lx\n",
		task_info.pcs_base, task_info.pcs_size, task_info.pcs_ind);
	/* guest user procedure chain stack */
	task_info.u_pcs_base = child_stacks->pcsp_lo.PCSP_lo_base;
	task_info.u_pcs_size = child_stacks->pcsp_hi.PCSP_hi_size;
	task_info.u_pcs_ind = child_stacks->pcsp_hi.PCSP_hi_ind;
	DebugKVMCLN("user procedure chain stack from 0x%lx size 0x%lx "
		"ind 0x%lx\n",
		task_info.u_pcs_base, task_info.u_pcs_size,
		task_info.u_pcs_ind);

	task_info.flags |= (PS_HAS_NOT_GUARD_PAGE_TASK_FLAG |
				PCS_HAS_NOT_GUARD_PAGE_TASK_FLAG);

	task_info.cr0_lo = child_crs->cr0_lo.CR0_lo_half;
	task_info.cr0_hi = child_crs->cr0_hi.CR0_hi_half;
	task_info.cr1_wd = child_crs->cr1_lo.CR1_lo_half;
	task_info.cr1_ussz = child_crs->cr1_hi.CR1_hi_half;
	DebugKVMCLN("chain registers: IP %pF, wbs 0x%lx, ussz 0x%lx\n",
		(void *)(task_info.cr0_hi), task_info.cr1_wd,
		task_info.cr1_ussz);

	new_sw_regs->cutd = new_ti->u_cutd;
	task_info.cut_base = new_sw_regs->cutd.CUTD_base;

	if (clone_flags & CLONE_SETTLS) {
		task_info.flags |= CLONE_SETTLS_TASK_FLAG;
	}
	task_info.gregs = (e2k_addr_t)new_sw_regs->gregs.g;

	task_info.entry_point = (u64)&__ret_from_fork;
	DebugKVMCLN("handler of return from fork() is %pfx, gregs at 0x%lx\n",
		(void *)task_info.entry_point, task_info.gregs);

	/*
	 * Set pointers of kernel local & hardware stacks to empty state
	 */

	BUG_ON(task_info.us_base != new_ti->k_usd_lo.USD_lo_base -
					new_ti->k_usd_hi.USD_hi_size);
	BUG_ON(task_info.us_base != (u64)new_task->stack +
						KERNEL_C_STACK_OFFSET);

	BUG_ON(new_task->mm == NULL || new_task->mm->pgd == NULL);
	BUG_ON(new_task->mm != current->mm);

	ret = kvm_get_mm_notifier(new_task->mm);
	if (ret != 0)
		goto out_error;

retry:
	gpid_nr = HYPERVISOR_clone_guest_user_stacks(&task_info);
	if (unlikely(gpid_nr == -EAGAIN)) {
		pr_err("host could not clone stacks of new user thread, "
			"error %d, retry\n", gpid_nr);
		goto retry;
	} else if (unlikely(gpid_nr < 0)) {
		pr_err("host could not clone stacks of new user thread, "
			"error %d\n", gpid_nr);
		ret = gpid_nr;
		goto out_error;
	}
	new_ti->gpid_nr = gpid_nr;
	new_ti->gmmid_nr = current_thread_info()->gmmid_nr;

	/* FIXME: it need delete this field from arch-independent struct */
	new_task->mm->gmmid_nr = new_ti->gmmid_nr;

	DebugKVMCLN("new thread created on %s (%d) GPID %d GMMID %d\n",
		current->comm, current->pid, gpid_nr, new_ti->gmmid_nr);

	if (DEBUG_KVM_CLONE_USER_MODE)
		debug_clone_guest = false;

	return 0;

out_error:
	pr_warn("%s(): failed, error %d\n", __func__, ret);
	return ret;
}

int kvm_copy_spilled_user_stacks(e2k_stacks_t *child_stacks,
		e2k_mem_crs_t *child_crs, sw_regs_t *new_sw_regs,
		thread_info_t *new_ti)
{
	struct task_struct *new_task = thread_info_task(new_ti);
	kvm_task_info_t task_info;
	vcpu_gmmu_info_t gmmu_info;
	int ret, gpid_nr;

	/* copy user's part of kernel hardware stacks */
	native_copy_spilled_user_stacks(child_stacks, child_crs,
					new_sw_regs, new_ti);

	/*
	 * Register new thread on host and complete new guest user thread
	 * creation
	 */
	/* guest kernel local data stack */
	task_info.sp_offset = new_sw_regs->usd_hi.USD_hi_size;
	task_info.us_base = new_sw_regs->usd_lo.USD_lo_base -
				new_sw_regs->usd_hi.USD_hi_size;
	task_info.us_size = new_sw_regs->top - task_info.us_base;
	/* guest user local data stack */
	task_info.u_sp_offset = child_stacks->usd_hi.USD_hi_size;
	task_info.u_us_base = child_stacks->usd_lo.USD_lo_base -
				child_stacks->usd_hi.USD_hi_size;
	task_info.u_us_size = child_stacks->top - task_info.u_us_base;

	task_info.flags = 0;
	if (new_task->thread.flags & E2K_FLAG_PROTECTED_MODE)
		task_info.flags |= PROTECTED_CODE_TASK_FLAG;
	if (TASK_IS_BINCO(new_task))
		task_info.flags |= BIN_COMP_CODE_TASK_FLAG;
	DebugKVMCPY("kernel data stack from 0x%lx size 0x%lx SP offset 0x%lx\n",
		task_info.us_base, task_info.us_size, task_info.sp_offset);
	DebugKVMCPY("user data stack from 0x%lx size 0x%lx SP offset 0x%lx "
		"%s\n",
		task_info.u_us_base, task_info.u_us_size,
		task_info.u_sp_offset,
		(task_info.flags & PROTECTED_CODE_TASK_FLAG) ?
					"protected" : "not protected");
	BUG_ON(task_info.sp_offset > task_info.us_size);

	task_info.ps_base = new_sw_regs->psp_lo.PSP_lo_base;
	task_info.ps_size = new_sw_regs->psp_hi.PSP_hi_size;
	task_info.ps_ind = new_sw_regs->psp_hi.PSP_hi_ind;
	DebugKVMCPY("kernel procedure stack from 0x%lx size 0x%lx ind 0x%lx\n",
		task_info.ps_base, task_info.ps_size, task_info.ps_ind);
	task_info.pcs_base = new_sw_regs->pcsp_lo.PCSP_lo_base;
	task_info.pcs_size = new_sw_regs->pcsp_hi.PCSP_hi_size;
	task_info.pcs_ind = new_sw_regs->pcsp_hi.PCSP_hi_ind;
	DebugKVMCPY("kernel procedure chain stack from 0x%lx size 0x%lx "
		"ind 0x%lx\n",
		task_info.pcs_base, task_info.pcs_size, task_info.pcs_ind);

	task_info.flags |= (PS_HAS_NOT_GUARD_PAGE_TASK_FLAG |
				PCS_HAS_NOT_GUARD_PAGE_TASK_FLAG);

	task_info.cr0_lo = child_crs->cr0_lo.CR0_lo_half;
	task_info.cr0_hi = child_crs->cr0_hi.CR0_hi_half;
	task_info.cr1_wd = child_crs->cr1_lo.CR1_lo_half;
	task_info.cr1_ussz = child_crs->cr1_hi.CR1_hi_half;
	DebugKVMCPY("chain registers: IP %pF, wbs 0x%lx, ussz 0x%lx\n",
		(void *)(task_info.cr0_hi), task_info.cr1_wd,
		task_info.cr1_ussz);

	new_sw_regs->cutd = new_ti->u_cutd;
	task_info.cut_base = new_sw_regs->cutd.CUTD_base;

	task_info.gregs = (e2k_addr_t)new_sw_regs->gregs.g;

	task_info.entry_point = (u64)&__ret_from_fork;
	DebugKVMCLN("handler of return from fork() is %pfx, gregs at 0x%lx\n",
		(void *)task_info.entry_point, task_info.gregs);

	/*
	 * Set pointers of kernel local & hardware stacks to empty state
	 */

	BUG_ON(task_info.us_base != new_ti->k_usd_lo.USD_lo_base -
					new_ti->k_usd_hi.USD_hi_size);
	BUG_ON(task_info.us_base != (u64)new_task->stack +
						KERNEL_C_STACK_OFFSET);

	BUG_ON(new_task->mm == NULL || new_task->mm->pgd == NULL);

	ret = kvm_get_mm_notifier(new_task->mm);
	if (ret != 0)
		goto out_error;

	gmmu_info.opcode = CREATE_NEW_GMM_GMMU_OPC;
	gmmu_info.u_pptb = __pa(new_task->mm->pgd);

retry:
	gpid_nr = HYPERVISOR_copy_guest_user_stacks(&task_info, &gmmu_info);
	if (unlikely(gpid_nr == -EAGAIN)) {
		DebugKVM("could not copy stacks of new user thread, "
			"error %d, retry\n", gpid_nr);
		goto retry;
	} else if (unlikely(gpid_nr < 0)) {
		DebugKVM("could not copy stacks of new user thread, "
				"error %d\n", gpid_nr);
		ret = gpid_nr;
		goto out_error;
	}
	new_ti->gpid_nr = gpid_nr;
	new_ti->gmmid_nr = gmmu_info.gmmid_nr;

	/* FIXME: it need delete this field from arch-independent struct */
	new_task->mm->gmmid_nr = gmmu_info.gmmid_nr;

	DebugGMM("created on %s (%d) GPID %d GMMID %d\n",
		current->comm, current->pid, gpid_nr, new_ti->gmmid_nr);
	DebugKVMCPY("succeeded, new thread GPID #%d GMMID #%d\n",
		gpid_nr, new_ti->gmmid_nr);

	return 0;

out_error:
	pr_warn("%s(): failed, error %d\n", __func__, ret);
	return ret;
}

void kvm_save_kernel_glob_regs(kernel_gregs_t *k_gregs)
{
	panic("%s(): is not yetmplemented\n", __func__);
}
void kvm_save_glob_regs(e2k_global_regs_t *gregs)
{
	unsigned long **g_regs = (unsigned long **)&gregs->g[0].xreg;
	int ret;

retry:
	gregs->bgr = NATIVE_READ_BGR_REG();
	ret = HYPERVISOR_get_guest_glob_regs(g_regs, GUEST_GREGS_MASK,
				true,	/*dirty BGR */
				NULL);
	if (unlikely(ret == -EAGAIN)) {
		pr_err("%s(): could not get global registers state, "
			"error %d, retry\n", __func__, ret);
		goto retry;
	} else if (unlikely(ret < 0)) {
		pr_err("%s(): could not get global registers state, "
			"error %d\n", __func__, ret);
	}
}
void kvm_restore_glob_regs(const e2k_global_regs_t *gregs)
{
	unsigned long **g_regs = (unsigned long **)&gregs->g[0].xreg;
	int ret;

retry:
	ret = HYPERVISOR_set_guest_glob_regs(g_regs, GUEST_GREGS_MASK,
				true,	/*dirty BGR */
				NULL);
	if (unlikely(ret == -EAGAIN)) {
		pr_err("%s(): could not set global registers state, "
			"error %d, retry\n", __func__, ret);
		goto retry;
	} else if (unlikely(ret < 0)) {
		pr_err("%s(): could not set global registers state, "
			"error %d\n", __func__, ret);
	}
	NATIVE_WRITE_BGR_REG(gregs->bgr);
}
void kvm_save_glob_regs_dirty_bgr(e2k_global_regs_t *gregs)
{
	unsigned long **g_regs = (unsigned long **)&gregs->g[0].xreg;
	int ret;

retry:
	gregs->bgr = NATIVE_READ_BGR_REG();
	ret = HYPERVISOR_set_guest_glob_regs_dirty_bgr(g_regs,
				GUEST_GREGS_MASK);
	if (unlikely(ret == -EAGAIN)) {
		pr_err("%s(): could not get global registers state, "
			"error %d, retry\n", __func__, ret);
		goto retry;
	} else if (unlikely(ret < 0)) {
		pr_err("%s(): could not get global registers state, "
			"error %d\n", __func__, ret);
	}
}
void kvm_save_local_glob_regs(local_gregs_t *l_gregs, bool is_signal)
{
	unsigned long **gregs = (unsigned long **)&l_gregs->g[0].xreg;
	int ret;

retry:
	l_gregs->bgr = NATIVE_READ_BGR_REG();
	ret = HYPERVISOR_get_guest_local_glob_regs(gregs, is_signal);
	if (unlikely(ret == -EAGAIN)) {
		pr_err("%s(): could not get local global registers state, "
			"error %d, retry\n", __func__, ret);
		goto retry;
	} else if (unlikely(ret < 0)) {
		pr_err("%s(): could not get local global registers state, "
			"error %d\n", __func__, ret);
	}
}
void kvm_restore_local_glob_regs(const local_gregs_t *l_gregs, bool is_signal)
{
	unsigned long **gregs = (unsigned long **)&l_gregs->g[0].xreg;
	int ret;

retry:
	ret = HYPERVISOR_set_guest_local_glob_regs(gregs, is_signal);
	if (unlikely(ret == -EAGAIN)) {
		pr_err("%s(): could not get local global registers state, "
			"error %d, retry\n", __func__, ret);
		goto retry;
	} else if (unlikely(ret < 0)) {
		pr_err("%s(): could not get local global registers state, "
			"error %d\n", __func__, ret);
	}
	NATIVE_WRITE_BGR_REG(l_gregs->bgr);
}

void kvm_get_all_user_glob_regs(e2k_global_regs_t *gregs)
{
	unsigned long **g_regs = (unsigned long **)&gregs->g[0].xreg;
	int ret;

retry:
	ret = HYPERVISOR_get_all_guest_glob_regs(g_regs);
	if (unlikely(ret == -EAGAIN)) {
		pr_err("%s(): could not get all global registers state, "
			"error %d, retry\n", __func__, ret);
		goto retry;
	} else if (unlikely(ret < 0)) {
		pr_err("%s(): could not get all global registers state, "
			"error %d\n", __func__, ret);
	}
}

/*
 * We use this on KVM guest if we don't have any better idle routine.
 */
void kvm_default_idle(void)
{
	if (psr_and_upsr_irqs_disabled()) {
		local_irq_enable();
	}

	/* clear POLLING flag because of VCPU go to sleeping, */
	/* so cannot polling flag NEED_RESCHED and should be waked up */
	/* to reschedule if it need */
	clear_thread_flag(TIF_POLLING_NRFLAG);

	/*
	 * goto host to wait for some event will be injected into guest
	 * to wake up it
	 * Waiting is timed out and can be iterrupted on any event for
	 * this VCPU or guest kernel to exit from idle state
	 */
	HYPERVISOR_kvm_guest_vcpu_common_idle(GUEST_CPU_IDLE_TIMEOUT,
			true);	/* can interrupt waiting on any event */

	/* restore POLLING flag because of VCPU completed sleeping */
	/* and can polling flag NEED_RESCHED to reschedule if it need */
	set_thread_flag(TIF_POLLING_NRFLAG);
	if (kvm_get_vcpu_state()->do_dump_stack) {
		dump_stack();
		kvm_get_vcpu_state()->do_dump_stack = false;
	} else if (kvm_get_vcpu_state()->do_dump_state) {
		coredump_in_future();
		kvm_get_vcpu_state()->do_dump_state = false;
	}

	DebugKVMIDLE("current guest jiffies 0x%lx\n", jiffies);
}
EXPORT_SYMBOL(kvm_default_idle);

static inline void kvm_do_cpu_relax(void)
{
	cpumask_var_t cpus_allowed;
	int cpu = smp_processor_id();

	/* scheduler cannot be called into atomic */
	if (unlikely(in_atomic_preempt_off()))
		return;

	/* update allowed CPU mask to didsable migration */
	if (!alloc_cpumask_var(&cpus_allowed, GFP_KERNEL)) {
		pr_err("%s(): could not allocate CPUs mask structure "
			"to keep allowed mask\n",
			__func__);
		BUG_ON(true);
	}
	cpumask_copy(cpus_allowed, &current->cpus_mask);
	cpumask_copy(&current->cpus_mask, cpumask_of(cpu));

	if (likely(need_resched())) {
		/* probably some thread is ready to execute, so switch */
		/* to this thread before go to idle mode on host */
		schedule();
	}
	HYPERVISOR_kvm_guest_vcpu_common_idle(GUEST_CPU_WAKE_UP_TIMEOUT,
			true);	/* can interrupt waiting on any event */
				/* to enable rescheduling */
	if (likely(need_resched())) {
		/* timer interrupts should be handled */
		/* now timer handler is separate bottom half thread */
		schedule();
	}

	/* restore source mask of allowed CPUs */
	cpumask_copy(&current->cpus_mask, cpus_allowed);
	free_cpumask_var(cpus_allowed);
}

/*
 * We use this on KVM guest if we don't have any better idle routine.
 */
void kvm_cpu_relax(void)
{
	HYPERVISOR_kvm_guest_vcpu_common_idle(GUEST_CPU_WAKE_UP_TIMEOUT,
			true);	/* can interrupt waiting on any event */
				/* to enable rescheduling */
	if (kvm_get_vcpu_state()->do_dump_stack) {
		host_dump_stack_func();
	}
}
EXPORT_SYMBOL(kvm_cpu_relax);

/*
 * In some case it need CPU relaxation without rescheduling
 * for example CPU frequency measurement
 */
void kvm_cpu_relax_no_resched(void)
{
	HYPERVISOR_kvm_guest_vcpu_common_idle(GUEST_CPU_WAKE_UP_TIMEOUT,
			true);	/* can interrupt waiting on any event */
				/* to return to guest */
}

#ifdef	CONFIG_SMP
/*
 * Guest kernel cannot wait for some events in the loop on real CPU,
 * so make hypercall to free CPU and wait for the VCPU activation from
 * other VCPU or guest kernel
 * Waiting is not timed out and cannot be iterrupted on any event,
 * activation can be done only by different hypercall from other VCPU,
 */
void kvm_wait_for_cpu_booting(void)
{
	HYPERVISOR_kvm_guest_vcpu_common_idle(0,	/* without timeout */
			false);	/* cannot interrupt waiting on any event, */
				/* because of VCPU is not yet activated */
}
void kvm_wait_for_cpu_wake_up(void)
{
	kvm_do_cpu_relax();
}
/*
 * Activate the CPU, which is waiting on idle mode after hypercall above
 */
int kvm_activate_cpu(int cpu_id)
{
	int ret;

	ret = HYPERVISOR_kvm_activate_guest_vcpu(cpu_id);
	if (ret) {
		pr_err("%s(): failed to activate CPU #%d, error %d\n",
			__func__, cpu_id, ret);
	}
	return ret;
}
/*
 * Activate all CPUs, which are waiting on idle mode after hypercall above
 */
int kvm_activate_all_cpus(void)
{
	int ret;

	ret = HYPERVISOR_kvm_activate_guest_all_vcpus();
	if (ret) {
		pr_err("%s(): failed to activate all CPUs, error %d\n",
			__func__, ret);
	}
	return ret;
}
#endif	/* CONFIG_SMP */
