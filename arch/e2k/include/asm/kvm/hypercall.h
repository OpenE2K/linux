/******************************************************************************
 * hypercall.h
 *
 * KVM host <-> guest Linux-specific hypervisor handling.
 *
 * Copyright (c) 2011-2012, Salavat Gilyazov
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation; or, when distributed
 * separately from the Linux kernel or incorporated into other
 * software packages, subject to the following license:
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this source file (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#ifndef _ASM_E2K_HYPERCALL_H
#define _ASM_E2K_HYPERCALL_H

#include <linux/types.h>
#include <linux/kvm_types.h>

#include <asm/e2k_api.h>
#include <asm/cpu_regs_types.h>
#include <asm/machdep.h>
#include <asm/trap_def.h>
#include <asm/kvm/guest/cpu.h>

#ifdef	CONFIG_KVM_GUEST_HW_HCALL
extern unsigned long light_hw_hypercall(unsigned long nr,
				unsigned long arg1, unsigned long arg2,
				unsigned long arg3, unsigned long arg4,
				unsigned long arg5, unsigned long arg6);
extern unsigned long generic_hw_hypercall(unsigned long nr,
				unsigned long arg1, unsigned long arg2,
				unsigned long arg3, unsigned long arg4,
				unsigned long arg5, unsigned long arg6,
				unsigned long arg7);
#endif	/* CONFIG_KVM_GUEST_HW_HCALL */

static inline unsigned long light_hypercall(unsigned long nr,
				unsigned long arg1, unsigned long arg2,
				unsigned long arg3, unsigned long arg4,
				unsigned long arg5, unsigned long arg6)
{
	unsigned long ret;

#ifdef CONFIG_KVM_GUEST_HW_HCALL
# ifdef CONFIG_KVM_GUEST_KERNEL
	if (kvm_vcpu_host_support_hw_hc())
# endif /* CONFIG_KVM_GUEST_KERNEL */
		return light_hw_hypercall(nr, arg1, arg2, arg3,
					      arg4, arg5, arg6);
#endif	/* CONFIG_KVM_GUEST_HW_HCALL */

	ret = E2K_SYSCALL(LIGHT_HYPERCALL_TRAPNUM, nr, 6,
			arg1, arg2, arg3, arg4, arg5, arg6);

	return ret;
}
static inline unsigned long light_hypercall0(unsigned long nr)
{
	return light_hypercall(nr, 0, 0, 0, 0, 0, 0);
}

static inline unsigned long light_hypercall1(unsigned long nr,
				unsigned long arg1)
{
	return light_hypercall(nr, arg1, 0, 0, 0, 0, 0);
}

static inline unsigned long light_hypercall2(unsigned long nr,
				unsigned long arg1, unsigned long arg2)
{
	return light_hypercall(nr, arg1, arg2, 0, 0, 0, 0);
}

static inline unsigned long light_hypercall3(unsigned long nr,
				unsigned long arg1, unsigned long arg2,
				unsigned long arg3)
{
	return light_hypercall(nr, arg1, arg2, arg3, 0, 0, 0);
}

static inline unsigned long light_hypercall4(unsigned long nr,
				unsigned long arg1, unsigned long arg2,
				unsigned long arg3, unsigned long arg4)
{
	return light_hypercall(nr, arg1, arg2, arg3, arg4, 0, 0);
}

static inline unsigned long light_hypercall5(unsigned long nr,
				unsigned long arg1, unsigned long arg2,
				unsigned long arg3, unsigned long arg4,
				unsigned long arg5)
{
	return light_hypercall(nr, arg1, arg2, arg3, arg4, arg5, 0);
}

static inline unsigned long light_hypercall6(unsigned long nr,
				unsigned long arg1, unsigned long arg2,
				unsigned long arg3, unsigned long arg4,
				unsigned long arg5, unsigned long arg6)
{
	return light_hypercall(nr, arg1, arg2, arg3, arg4, arg5, arg6);
}

static inline unsigned long generic_hypercall(unsigned long nr,
	unsigned long arg1, unsigned long arg2, unsigned long arg3,
	unsigned long arg4, unsigned long arg5, unsigned long arg6,
	unsigned long arg7)
{
	unsigned long ret;

#ifdef CONFIG_KVM_GUEST_HW_HCALL
# ifdef CONFIG_KVM_GUEST_KERNEL
	if (kvm_vcpu_host_support_hw_hc())
# endif /* CONFIG_KVM_GUEST_KERNEL */
		return generic_hw_hypercall(nr,
				arg1, arg2, arg3, arg4, arg5, arg6, arg7);
#endif	/* CONFIG_KVM_GUEST_HW_HCALL */

	ret = E2K_SYSCALL(GENERIC_HYPERCALL_TRAPNUM, nr, 7,
			arg1, arg2, arg3, arg4, arg5, arg6, arg7);
	return ret;
}
static inline unsigned long generic_hypercall0(unsigned long nr)
{
	return generic_hypercall(nr, 0, 0, 0, 0, 0, 0, 0);
}

static inline unsigned long generic_hypercall1(unsigned long nr,
			unsigned long arg1)
{
	return generic_hypercall(nr, arg1, 0, 0, 0, 0, 0, 0);
}

static inline unsigned long generic_hypercall2(unsigned long nr,
			unsigned long arg1, unsigned long arg2)
{
	return generic_hypercall(nr, arg1, arg2, 0, 0, 0, 0, 0);
}

static inline unsigned long generic_hypercall3(unsigned long nr,
			unsigned long arg1, unsigned long arg2,
			unsigned long arg3)
{
	return generic_hypercall(nr, arg1, arg2, arg3, 0, 0, 0, 0);
}

static inline unsigned long generic_hypercall4(unsigned long nr,
			unsigned long arg1, unsigned long arg2,
			unsigned long arg3, unsigned long arg4)
{
	return generic_hypercall(nr, arg1, arg2, arg3, arg4, 0, 0, 0);
}

static inline unsigned long generic_hypercall5(unsigned long nr,
			unsigned long arg1, unsigned long arg2,
			unsigned long arg3, unsigned long arg4,
			unsigned long arg5)
{
	return generic_hypercall(nr, arg1, arg2, arg3, arg4, arg5, 0, 0);
}

static inline unsigned long generic_hypercall6(unsigned long nr,
			unsigned long arg1, unsigned long arg2,
			unsigned long arg3, unsigned long arg4,
			unsigned long arg5, unsigned long arg6)
{
	return generic_hypercall(nr, arg1, arg2, arg3, arg4, arg5, arg6, 0);
}

/*
 * KVM hypervisor (host) <-> guest lite hypercalls list
 */

#define	KVM_HCALL_COPY_STACKS_TO_MEMORY	 1	/* copy (flush) hardware */
						/* stacks to memory */
#define	KVM_HCALL_SWITCH_GUEST_THREAD_STACKS 2	/* switch guest kernel thread */
						/* stacks from current to new */
						/* specified by GPID number */
#define	KVM_HCALL_GET_ACTIVE_CR_MEM_ITEM 3	/* get current active */
						/* procedure chain stack item */
#define	KVM_HCALL_PUT_ACTIVE_CR_MEM_ITEM 4	/* put current active */
						/* procedure chain stack item */
#define	KVM_HCALL_GET_HOST_RUNSTATE_KTIME 5	/* get host kernel current */
						/* time at terms of runstate */
						/* time (cycles) */
#define	KVM_HCALL_GET_GUEST_RUNNING_TIME 6	/* get running time of guest */
						/* VCPU at cycles */
#define	KVM_HCALL_GET_VCPU_START_THREAD	8	/* register on host the guest */
						/* kernel VCPU booting thread */
#define	KVM_HCALL_UPDATE_PSP_HI		10	/* write updated value to */
						/* PSP_hi register */
#define	KVM_HCALL_UPDATE_PCSP_HI	11	/* write updated value to */
						/* PCSP_hi register */
#define	KVM_HCALL_SETUP_IDLE_TASK	12	/* setup current task of */
						/* guest as task */
#define	KVM_HCALL_MOVE_TAGGED_DATA	15	/* move quad value from to */
#define	KVM_HCALL_UNFREEZE_TRAPS	16	/* unfreeze TIRs & trap */
						/* cellar */
#define	KVM_HCALL_SWITCH_TO_INIT_MM	17	/* deactivate current guest */
						/* mm, switch to init mm */
#define	KVM_HCALL_EXTRACT_TAGS_32	19	/* extract tags from 32 bytes */
						/* of data */
#define	KVM_HCALL_INJECT_INTERRUPT	20	/* inject interrupt to handle */
						/* pending VIRQs by guest */
#define	KVM_HCALL_VIRQ_HANDLED		21	/* info host about all VIRQs */
						/* were handled by guest */
#define	KVM_HCALL_TEST_PENDING_VIRQ	22	/* test pending VIRQs on VCPU */
#define	KVM_HCALL_READ_DTLB_REG		23	/* read DTLB entry for */
						/* virtual address */
#define	KVM_HCALL_GET_DAM		24	/* get current DAM state */
#define	KVM_HCALL_FLUSH_DCACHE_LINE	25	/* flush DCACHE line */
#define	KVM_HCALL_CLEAR_DCACHE_L1_SET	26	/* clear DCACHE L1 set */
#define	KVM_HCALL_FLUSH_DCACHE_RANGE	27	/* flush DCACHE range of */
						/* virtual addresses */
#define	KVM_HCALL_CLEAR_DCACHE_L1_RANGE	28	/* flush DCACHE L1 range of */
						/* virtual addresses */
#define	KVM_HCALL_MMU_PROBE		29	/* probe MMU entry or */
						/* address */
#define	KVM_HCALL_FLUSH_ICACHE_RANGE	30	/* flush ICACHE range */
/* notify host kernel aboout switch to updated procedure stack on guest */
#define	KVM_HCALL_SWITCH_TO_EXPANDED_PROC_STACK	31
/* notify host kernel aboout switch to updated procedure chain stack on guest */
#define	KVM_HCALL_SWITCH_TO_EXPANDED_CHAIN_STACK 32

typedef struct kvm_hw_stacks_flush {
	unsigned long psp_lo;
	unsigned long psp_hi;
	unsigned long pcsp_lo;
	unsigned long pcsp_hi;
} kvm_hw_stacks_flush_t;

static inline unsigned long
HYPERVISOR_copy_stacks_to_memory(void)
{
	return light_hypercall1(KVM_HCALL_COPY_STACKS_TO_MEMORY,
				(unsigned long)NULL);
}

static inline unsigned long
HYPERVISOR_flush_hw_stacks_to_memory(kvm_hw_stacks_flush_t __user *hw_stacks)
{
	return light_hypercall1(KVM_HCALL_COPY_STACKS_TO_MEMORY,
				(unsigned long)hw_stacks);
}

static inline unsigned long
HYPERVISOR_switch_guest_thread_stacks(unsigned long gpid_nr,
				unsigned long gmmid_nr)
{
	return light_hypercall2(KVM_HCALL_SWITCH_GUEST_THREAD_STACKS,
					gpid_nr, gmmid_nr);
}

static inline unsigned long
HYPERVISOR_get_active_cr_mem_item(unsigned long __user *cr_value,
					e2k_addr_t base, e2k_addr_t cr_ind,
					e2k_addr_t cr_item)
{
	return light_hypercall4(KVM_HCALL_GET_ACTIVE_CR_MEM_ITEM,
					(unsigned long)cr_value,
					base, cr_ind, cr_item);
}
static inline unsigned long
HYPERVISOR_put_active_cr_mem_item(unsigned long cr_value,
					e2k_addr_t base, e2k_addr_t cr_ind,
					e2k_addr_t cr_item)
{
	return light_hypercall4(KVM_HCALL_PUT_ACTIVE_CR_MEM_ITEM,
					cr_value, base, cr_ind, cr_item);
}

static inline unsigned long
HYPERVISOR_get_host_runstate_ktime(void)
{
	return light_hypercall0(KVM_HCALL_GET_HOST_RUNSTATE_KTIME);
}
static inline unsigned long
HYPERVISOR_get_guest_running_time(void)
{
	return light_hypercall0(KVM_HCALL_GET_GUEST_RUNNING_TIME);
}

static inline unsigned long
HYPERVISOR_get_vcpu_start_thread(void)
{
	return light_hypercall0(KVM_HCALL_GET_VCPU_START_THREAD);
}

static inline unsigned long
HYPERVISOR_update_psp_hi(unsigned long psp_hi_value)
{
	return light_hypercall1(KVM_HCALL_UPDATE_PSP_HI, psp_hi_value);
}

static inline unsigned long
HYPERVISOR_update_pcsp_hi(unsigned long pcsp_hi_value)
{
	return light_hypercall1(KVM_HCALL_UPDATE_PCSP_HI, pcsp_hi_value);
}

static inline unsigned long
HYPERVISOR_setup_idle_task(int cpu)
{
	return light_hypercall1(KVM_HCALL_SETUP_IDLE_TASK, (unsigned long)cpu);
}

static inline unsigned long
HYPERVISOR_unfreeze_guest_traps(void)
{
	return light_hypercall0(KVM_HCALL_UNFREEZE_TRAPS);
}

static inline unsigned long
HYPERVISOR_switch_to_guest_init_mm(void)
{
	return light_hypercall0(KVM_HCALL_SWITCH_TO_INIT_MM);
}

union recovery_faulted_arg {
	struct {
		char vr;
		char chan;
		char qp;
		char atomic;
		u16 tag;
		u16 tag_ext;
	};
	u64 entire;
};
static inline unsigned long
HYPERVISOR_move_tagged_data(int word_size,
		e2k_addr_t addr_from, e2k_addr_t addr_to)
{
	return light_hypercall3(KVM_HCALL_MOVE_TAGGED_DATA,
				word_size, addr_from, addr_to);
}
static inline unsigned long
HYPERVISOR_extract_tags_32(u16 *dst, const void *src)
{
	return light_hypercall2(KVM_HCALL_EXTRACT_TAGS_32,
			(unsigned long)dst, (unsigned long)src);
}

static inline unsigned long
HYPERVISOR_inject_interrupt(void)
{
	return light_hypercall0(KVM_HCALL_INJECT_INTERRUPT);
}
static inline unsigned long
HYPERVISOR_virqs_handled(void)
{
	return light_hypercall0(KVM_HCALL_VIRQ_HANDLED);
}

static inline unsigned long
HYPERVISOR_test_pending_virqs(void)
{
	return light_hypercall0(KVM_HCALL_TEST_PENDING_VIRQ);
}
static inline unsigned long
HYPERVISOR_read_dtlb_reg(e2k_addr_t virt_addr)
{
	return light_hypercall1(KVM_HCALL_READ_DTLB_REG, virt_addr);
}
static inline unsigned long
HYPERVISOR_get_DAM(unsigned long long *dam, int dam_entries)
{
	return light_hypercall2(KVM_HCALL_GET_DAM, (unsigned long)dam,
				dam_entries);
}
static inline unsigned long
HYPERVISOR_flush_dcache_line(e2k_addr_t virt_addr)
{
	return light_hypercall1(KVM_HCALL_FLUSH_DCACHE_LINE, virt_addr);
}
static inline unsigned long
HYPERVISOR_clear_dcache_l1_set(e2k_addr_t virt_addr, unsigned long set)
{
	return light_hypercall2(KVM_HCALL_CLEAR_DCACHE_L1_SET, virt_addr, set);
}
static inline unsigned long
HYPERVISOR_flush_dcache_range(void *addr, size_t len)
{
	return light_hypercall2(KVM_HCALL_FLUSH_DCACHE_RANGE,
			(unsigned long)addr, len);
}
static inline unsigned long
HYPERVISOR_clear_dcache_l1_range(void *addr, size_t len)
{
	return light_hypercall2(KVM_HCALL_CLEAR_DCACHE_L1_RANGE,
			(unsigned long)addr, len);
}
static inline unsigned long
HYPERVISOR_flush_icache_range(e2k_addr_t start, e2k_addr_t end, u64 dummy)
{
	return light_hypercall3(KVM_HCALL_FLUSH_ICACHE_RANGE,
				start, end, dummy);
}

typedef enum kvm_mmu_probe {
	KVM_MMU_PROBE_ENTRY,
	KVM_MMU_PROBE_ADDRESS,
} kvm_mmu_probe_t;

static inline unsigned long
HYPERVISOR_mmu_probe(e2k_addr_t virt_address, kvm_mmu_probe_t what)
{
	return light_hypercall2(KVM_HCALL_MMU_PROBE, virt_address, what);
}

static inline long
HYPERVISOR_switch_to_expanded_guest_proc_stack(long delta_size,
				long delta_offset, bool decr_gk_ps)
{
	return light_hypercall3(KVM_HCALL_SWITCH_TO_EXPANDED_PROC_STACK,
			delta_size, delta_offset, (unsigned long)decr_gk_ps);
}
static inline long
HYPERVISOR_switch_to_expanded_guest_chain_stack(long delta_size,
				long delta_offset, bool decr_gk_pcs)
{
	return light_hypercall3(KVM_HCALL_SWITCH_TO_EXPANDED_CHAIN_STACK,
			delta_size, delta_offset, (unsigned long)decr_gk_pcs);
}

/*
 * KVM hypervisor (host) <-> guest generic hypercalls list
 */

#define KVM_HCALL_PV_WAIT 1			/* suspend current vcpu until */
						/* it will be woken up by */
						/* call KVM_HCALL_PV_KICK */
#define KVM_HCALL_PV_KICK 2			/* wake up vcpu suspended by */
						/* call KVM_HCALL_PV_WAIT */
#define	KVM_HCALL_RELEASE_TASK_STRUCT	8	/* release task struct on */
						/* host after task completion */
#define	KVM_HCALL_SET_CLOCKEVENT	10	/* set clock event */
#define	KVM_HCALL_COMPLETE_LONG_JUMP	12	/* long jump completion */
#define	KVM_HCALL_LAUNCH_SIG_HANDLER	14	/* launch guest user signal */
						/* handler */
#define	KVM_HCALL_SWITCH_TO_VIRT_MODE	16	/* switch from physical to */
						/* virtual addresses mode */
						/* (enable paging, TLB, TLU) */
#define	KVM_HCALL_APPLY_PSP_BOUNDS	17	/* update pending procedure */
						/* stack pointers after stack */
						/* bounds handling */
#define	KVM_HCALL_APPLY_PCSP_BOUNDS	18	/* update pending chain */
						/* stack pointers after stack */
						/* bounds handling */
#define	KVM_HCALL_CORRECT_TRAP_RETURN_IP 19	/* correct IP to return from */
						/* guest trap */
#define	KVM_HCALL_SWITCH_GUEST_KERNEL_STACKS 21	/* switch guest kernel thread */
						/* to new stacks */
#define	KVM_HCALL_COPY_GUEST_KERNEL_STACKS 22	/* copy guest kernel stacks */
						/* for kernel thread creation */
#define	KVM_HCALL_SWITCH_TO_GUEST_NEW_USER 28	/* end of execve() for guest */
						/* switch to new user stacks */
						/* start from user entry */
						/* point */
#define	KVM_HCALL_CLONE_GUEST_USER_STACKS 29	/* end of clone_user_stacks() */
						/* create new process thread */
						/* info agent on host and */
						/* register guest kernel */
						/* user local data stack */
#define	KVM_HCALL_COPY_GUEST_USER_STACKS 30	/* end of clone_user_stacks() */
						/* create new process thread */
						/* info agent on host and */
						/* register guest kernel */
						/* user local data stack */
#define	KVM_HCALL_UPDATE_HW_STACKS_FRAMES 36	/* update hardware stacks */
						/* frames */
#define	KVM_HCALL_PATCH_GUEST_DATA_AND_CHAIN_STACKS 38
						/* patch guest kernel data */
						/* chain stacks */
#define	KVM_HCALL_COPY_HW_STACKS_FRAMES	39	/* copy guest hardware stacks */
						/* (user<->kernel) on guest */
						/* addresses */
#define	KVM_HCALL_GET_GUEST_GLOB_REGS	40	/* get current state of */
						/* global registers, except */
						/* someones */
#define	KVM_HCALL_SET_GUEST_GLOB_REGS	41	/* set current state of */
						/* global registers, except */
						/* someones */
#define	KVM_HCALL_GET_GUEST_LOCAL_GLOB_REGS 42	/* get current state of */
						/* local global registers */
#define	KVM_HCALL_SET_GUEST_LOCAL_GLOB_REGS 43	/* set current state of */
						/* local global registers */
#define	KVM_HCALL_GET_ALL_GUEST_GLOB_REGS 44	/* get current state of all */
						/* guest user global regs */
#define	KVM_HCALL_BOOT_SPIN_LOCK_SLOW	47	/* slowpath of guest boot */
						/* time spinlock locking */
#define	KVM_HCALL_BOOT_SPIN_LOCKED_SLOW 48	/* slowpath of guest boot */
						/* time spinlock locking */
						/* is taken */
#define	KVM_HCALL_BOOT_SPIN_UNLOCK_SLOW 49	/* slowpath of guest boot */
						/* time spinlock unlocking */
#define	KVM_HCALL_GUEST_SPIN_LOCK_SLOW	50	/* slowpath of guest spinlock */
						/* locking */
#define	KVM_HCALL_GUEST_SPIN_LOCKED_SLOW 51	/* slowpath of guest spinlock */
						/* locking is taken */
#define	KVM_HCALL_GUEST_SPIN_UNLOCK_SLOW 52	/* slowpath of guest spinlock */
						/* unlocking */
#define	KVM_HCALL_GUEST_CSD_LOCK_CTL	53	/* serialize access to */
						/* per-cpu csd resources */
						/* wait and wake up on host */
#define	KVM_HCALL_GUEST_MM_DROP		63	/* drop host kernel agent */
						/* for the guest process mm */
#define	KVM_HCALL_ACTIVATE_GUEST_MM	64	/* activate host agent */
						/* for the new guest mm */
#define	KVM_HCALL_PT_ATOMIC_UPDATE	68	/* atomicaly update PT items */
#define	KVM_HCALL_SWITCH_GUEST_MM	78	/* switch host agent to */
						/* the next guest mm */
#define	KVM_HCALL_VCPU_MMU_STATE	79	/* common hcall to control */
						/* guest MMU state */
#define	KVM_HCALL_GUEST_IOPORT_REQ	80	/* guest kernel IO ports */
						/* in/out request */
#define	KVM_HCALL_GUEST_IOPORT_STRING_REQ 81	/* guest kernel IO ports */
						/* in/out string request */
#define	KVM_HCALL_GUEST_MMIO_REQ	82	/* guest kernel MMIO */
						/* read/write request */
#define	KVM_HCALL_CONSOLE_IO		83	/* raw write/read to/from */
						/* guest task console */
#define	KVM_HCALL_NOTIFY_IO		84	/* notify host on IO request */
						/* completion or starting */
#define	KVM_HCALL_GUEST_INTR_HANDLER	85	/* create guest interrupt */
						/* handler */
#define	KVM_HCALL_GUEST_INTR_THREAD	86	/* create guest interrupt */
						/* handler thread */
#define	KVM_HCALL_GUEST_FREE_INTR_HANDLER 87	/* stop guest interrupt */
						/* hansler thread */
#define	KVM_HCALL_WAIT_FOR_VIRQ		88	/* wait for the VIRQ */
#define	KVM_HCALL_GET_GUEST_DIRECT_VIRQ	90	/* register direct VIRQ */
#define	KVM_HCALL_FREE_GUEST_DIRECT_VIRQ 91	/* free direct VIRQ */
#define	KVM_HCALL_GUEST_VCPU_COMMON_IDLE 95	/* guest CPU on idle */
						/* wait for some events on */
						/* guest kernel */
#define	KVM_HCALL_GUEST_VCPU_RELAX	96	/* guest VCPU is waiting for */
						/* some event and relax real */
						/* CPU to schedule other */
						/* guest VCPU */
#define	KVM_HCALL_ACTIVATE_GUEST_VCPU	97	/* activate the VCPU, which */
						/* is waiting on idle mode */
#define	KVM_HCALL_ACTIVATE_GUEST_ALL_VCPUS 98	/* activate all VCPUs, which */
						/* is waiting on idle mode */
#define	KVM_HCALL_RECOVERY_FAULTED_TAGGED_GUEST_STORE 110
						/* recovery faulted store */
						/* tagged value operations */
#define	KVM_HCALL_RECOVERY_FAULTED_GUEST_LOAD 111
						/* recovery faulted load */
						/* value and tag */
#define	KVM_HCALL_RECOVERY_FAULTED_GUEST_MOVE 112
						/* recovery faulted move */
						/* value and tag to register */
						/* into procedure stack */
#define	KVM_HCALL_RECOVERY_FAULTED_LOAD_TO_GUEST_GREG 113
						/* recovery faulted load */
						/* value and tag to global */
						/* register */
#define	KVM_HCALL_MOVE_TAGGED_GUEST_DATA 114	/* move data value from to */
#define	KVM_HCALL_FAST_TAGGED_GUEST_MEMORY_COPY 115
						/* fast tagged memory copy */
#define	KVM_HCALL_FAST_TAGGED_GUEST_MEMORY_SET  116
						/* fast tagged memory set */
#define	KVM_HCALL_FAST_TAGGED_MEMORY_COPY 117	/* fast tagged memory copy */
#define	KVM_HCALL_FAST_TAGGED_MEMORY_SET  118	/* fast tagged memory set */
#define	KVM_HCALL_SHUTDOWN		120	/* shutdown of guest */
#define	KVM_HCALL_DUMP_GUEST_STACK	121	/* dump guest current stack */
#define	KVM_HCALL_FTRACE_STOP		122	/* stop host's ftrace */
#define	KVM_HCALL_FTRACE_DUMP		123	/* dump host's ftrace buffer */
#define	KVM_HCALL_DUMP_COMPLETION	125	/* show state or dump all */
						/* stacks is completed */

#define	KVM_HCALL_HOST_PRINTK		130	/* guest printk() on host */
#define	KVM_HCALL_PRINT_GUEST_KERNEL_PTES 131	/* dump guest kernel address */
						/* page table entries */
#define	KVM_HCALL_PRINT_GUEST_USER_ADDRESS_PTES 132	/* dump guest user */
						/* address ptes on host */
#ifdef CONFIG_KVM_ASYNC_PF
#define KVM_HCALL_PV_ENABLE_ASYNC_PF		133 /* enable async pf */
						    /* on current vcpu */
#endif /* CONFIG_KVM_ASYNC_PF */
#define KVM_HCALL_FLUSH_TLB_RANGE		134 /* flush given address */
						    /* range in tlb */
#define	KVM_HCALL_RECOVERY_FAULTED_TAGGED_STORE 141
						/* recovery faulted store */
						/* tagged value operations */
#define	KVM_HCALL_RECOVERY_FAULTED_LOAD 142	/* recovery faulted load */
						/* value and tag */
#define	KVM_HCALL_RECOVERY_FAULTED_MOVE 143
						/* recovery faulted move */
						/* value and tag to register */
						/* into procedure stack */
#define	KVM_HCALL_RECOVERY_FAULTED_LOAD_TO_GREG 144
						/* recovery faulted load */
						/* value and tag to global */
						/* register */


/*
 * KVM hypervisor (host) <-> guest hypercalls structures
 */

/* process and threads management */
typedef struct kvm_task_info {
	unsigned long	flags;		/* various task flags see header */
					/* asm/processor.h */
	unsigned long	us_base;	/* local data (user) stack base */
	unsigned long	us_size;	/* local data (user) stack size */
	unsigned long	sp_offset;	/* offset of local data stack pointer */
					/* SP from stack base */
	unsigned long	ps_base;	/* Procedure stack: base, */
	unsigned long	ps_size;	/* Procedure stack current: size, */
	unsigned long	ps_ind;		/* index */

/* should be unsed { */
	unsigned long	ps_offset;	/* current base offset, */
	unsigned long	ps_top;		/* current top, */
	unsigned long	us_ps_size;	/* user part of stack total size */
	unsigned long	init_ps_size;	/* and initial size. */
	unsigned long	g_ps_size;	/* guest kernel part of stack size, */
	unsigned long	ps_reserved;	/* current reserved size of guest */
					/* kernel */
/* } should be unsed */

	unsigned long	pcs_base;	/* Procedure chain stack: base, */
	unsigned long	pcs_size;	/* Chain stack current: size, */
	unsigned long	pcs_ind;	/* index */

/* should be unsed { */
	unsigned long	pcs_offset;	/* current base offset, */
	unsigned long	pcs_top;	/* current top, */
	unsigned long	us_pcs_size;	/* user part of stack total size */
	unsigned long	init_pcs_size;	/* and initial size. */
	unsigned long	g_pcs_size;	/* guest kernel part of stack size, */
	unsigned long	pcs_reserved;	/* current reserved size of guest */
					/* kernel part */
/* } should be unsed */

	/* new: guest user stacks */
	unsigned long	u_us_base;	/* local data (user) stack base */
	unsigned long	u_us_size;	/* local data (user) stack size */
	unsigned long	u_sp_offset;	/* offset of local data stack pointer */
					/* SP from stack base */
	unsigned long	u_ps_base;	/* Procedure stack: base, */
	unsigned long	u_ps_size;	/* Procedure stack current: size, */
	unsigned long	u_ps_ind;	/* index */
	unsigned long	u_pcs_base;	/* Procedure chain stack: base, */
	unsigned long	u_pcs_size;	/* Chain stack current: size, */
	unsigned long	u_pcs_ind;	/* index */

	unsigned long	cr0_lo;		/* Chain iregister #0 lo */
	unsigned long	cr0_hi;		/* Chain iregister #0 hi */
	unsigned long	cr1_wd;		/* Chain register which contains wbs */
	unsigned long	cr1_ussz;	/* Chain register which contains */
					/* user stack size */
	unsigned long	cud_base;	/* OSCUD: base */
	unsigned long	cud_size;	/* and size */
	unsigned long	gd_base;	/* OSGD: base */
	unsigned long	gd_size;	/* and size */
	unsigned long	cut_base;	/* CUTD: base */
	unsigned long	cut_size;	/* and size */
	unsigned int	cui;		/* compilation unit index of code */
	unsigned long	entry_point;	/* entry point (address) of task */
	unsigned long	tls;		/* TLS of new user thread */
} kvm_task_info_t;

/* hardware stack extention, update and change */
typedef struct kvm_hw_stack {
	unsigned long	flags;		/* various task flags see header */
					/* asm/processor.h */
	unsigned long	base;		/* Procedure stack: base, */
	unsigned long	offset;		/* current base offset, */
	unsigned long	top;		/* current top, */
	unsigned long	us_size;	/* user part of stack total size */
	unsigned long	size;		/* Procedure stack current: size, */
	unsigned long	delta_ind;	/* delta of index */
	unsigned long	reserved;	/* current reserved size of guest */
					/* kernel */
} kvm_hw_stack_t;

/* signal and signal handler management */
typedef struct kvm_sig_info {
	int		sig;		/* signal # */
	unsigned int	protected;	/* task is protected */
	void		*siginfo;	/* siginfo structure pointer */
	void		*ucontext;	/* ucontext structure pointer */
	int		si_size;	/* size of siginfo structure */
	int		uc_size;	/* size of ucontext structure */
	unsigned long	handler;	/* user handler function entry point */
	unsigned long	sbr;		/* user data stack */
	unsigned long	usd_lo;		/* to handle */
	unsigned long	usd_hi;		/* the signal */
} kvm_sig_info_t;

typedef	struct kvm_stacks_info {
	unsigned long	top;		/* top address (same as SBR pointer) */
	unsigned long	usd_lo;		/* curent state of stack pointer */
	unsigned long	usd_hi;		/* register: base & size */
	unsigned long	psp_lo;		/* Procedure stack pointer: */
	unsigned long	psp_hi;		/* base & index & size */
	unsigned long	pshtp;
	unsigned long	pcsp_lo;	/* Procedure chain stack */
	unsigned long	pcsp_hi;	/* pointer: base & index & size */
	unsigned	pcshtp;
	unsigned long	cr0_lo;
	unsigned long	cr0_hi;
	unsigned long	cr1_lo;
	unsigned long	cr1_hi;
} kvm_stacks_info_t;
typedef	kvm_stacks_info_t		kvm_long_jump_info_t;

/* guest kernel local data stack pointers update */
typedef struct kvm_data_stack_info {
	bool		protected;	/* protected stack flag */
	unsigned long	top;		/* top of the stack (register SBR) */
	unsigned long	usd_base;	/* USD pointer: base */
	unsigned long	usd_size;	/* size */
	unsigned long	usd_ind;	/* index (only for protected stack) */
} kvm_data_stack_info_t;

/* patch of fields od chain stack registers to update */
typedef struct kvm_pcs_patch_info {
	unsigned int	ind;		/* index of frame in bytes and */
					/* relative PCS base: */
					/* PCS_base + PCS_offset + PCSP.ind */
	unsigned int	update_flags;	/* flags of updated fields */
					/* see below */
	unsigned long	IP;		/* new IP [63:0] */
	unsigned int	usd_size;	/* data stack size in bytes */
					/* to calculate ussz fields */
	unsigned short	wbs;		/* quad registers number */
	unsigned short	wpsz;		/* quad registers number */
} kvm_pcs_patch_info_t;

/* chain stack registers updating flags (see structure above) */
#define	KVM_PCS_IP_UPDATE_FLAG		0x00000001
#define	KVM_PCS_USSZ_UPDATE_FLAG	0x00000100
#define	KVM_PCS_WBS_UPDATE_FLAG		0x00001000
#define	KVM_PCS_WPSZ_UPDATE_FLAG	0x00002000

#define	KVM_MAX_PCS_FRAME_NUM_TO_PATCH	4	/* max number of chain stack */
						/* frames to can update */
						/* at once */

/* hardware stacks updating interface */
#define	KVM_MAX_PS_FRAME_NUM_TO_UPDATE	2	/* max number of procedure */
						/* stack frame to can update */
						/* one frame is 2 double-word */
						/* registers with extentions */
#define	KVM_MAX_PS_FRAME_SIZE_TO_UPDATE	\
		(KVM_MAX_PS_FRAME_NUM_TO_UPDATE * EXT_4_NR_SZ)

/*
 * Common hypercal to get/set/control guest MMU state
 */

/* flags of operations on guest MMU */
#define	INIT_STATE_GMMU_OPC		0x00000001UL
#define	SET_OS_VAB_GMMU_OPC		0x00000010UL
#define	CREATE_NEW_GMM_GMMU_OPC		0x00000100UL

typedef struct vcpu_gmmu_info {
	unsigned long	opcode;		/* operations on guest MMU */
					/* (see above) */
	bool		sep_virt_space;	/* guest use separate PTs for */
					/* OS and user virtual spaces */
	bool		pt_v6;		/* guest PTs are of v6 format */
	unsigned long	mmu_cr;		/* MMU control register */
	unsigned long	pid;		/* MMU PID (context) register */
	unsigned long	trap_cellar;	/* MMU trap cellar base */
	unsigned long	u_pptb;		/* physical base of user (for */
					/* separate PT mode) or united PT */
	unsigned long	u_vptb;		/* virtual base of user (for */
					/* separate PT mode) or united PT */
	unsigned long	os_pptb;	/* physical base of kernel PT */
					/* (only for separate PT mode) */
	unsigned long	os_vptb;	/* virtual base of kernel PT */
					/* (only for separate PT mode) */
	unsigned long	os_vab;		/* offset of kernel virtual space */
					/* into common virtual addresses */
					/* range */
	unsigned long	gmmid_nr;	/* return to guest: ID (#) of host */
					/* gmm struct created for new guest */
					/* mm struct */
} vcpu_gmmu_info_t;

static inline void HYPERVISOR_pv_wait(void)
{
	generic_hypercall0(KVM_HCALL_PV_WAIT);
}

static inline void HYPERVISOR_pv_kick(int cpu)
{
	generic_hypercall1(KVM_HCALL_PV_KICK, cpu);
}

static inline unsigned long
HYPERVISOR_release_task_struct(int gpid_nr)
{
	return generic_hypercall1(KVM_HCALL_RELEASE_TASK_STRUCT, (long)gpid_nr);
}

static inline unsigned long
HYPERVISOR_set_clockevent(unsigned long delta)
{
	return generic_hypercall1(KVM_HCALL_SET_CLOCKEVENT, delta);
}

static inline unsigned long
HYPERVISOR_complete_long_jump(kvm_long_jump_info_t *regs_state)
{
	return generic_hypercall1(KVM_HCALL_COMPLETE_LONG_JUMP,
				  (unsigned long)regs_state);
}

static inline unsigned long
HYPERVISOR_launch_sig_handler(kvm_stacks_info_t *regs_state, long sys_rval)
{
	return generic_hypercall2(KVM_HCALL_LAUNCH_SIG_HANDLER,
				  (unsigned long)regs_state, sys_rval);
}

static inline unsigned long
HYPERVISOR_apply_psp_bounds(unsigned long base, unsigned long size,
		unsigned long start, unsigned long end, unsigned long delta)
{
	return generic_hypercall5(KVM_HCALL_APPLY_PSP_BOUNDS,
				base, size, start, end, delta);
}

static inline unsigned long
HYPERVISOR_apply_pcsp_bounds(unsigned long base, unsigned long size,
		unsigned long start, unsigned long end, unsigned long delta)
{
	return generic_hypercall5(KVM_HCALL_APPLY_PCSP_BOUNDS,
				base, size, start, end, delta);
}
static inline unsigned long
HYPERVISOR_correct_trap_return_ip(unsigned long return_ip)
{
	return generic_hypercall1(KVM_HCALL_CORRECT_TRAP_RETURN_IP, return_ip);
}

static inline unsigned long
HYPERVISOR_guest_intr_handler(int irq, int virq_id,
				int (*irq_handler)(int, void *), void *arg)
{
	return generic_hypercall4(KVM_HCALL_GUEST_INTR_HANDLER, irq, virq_id,
					(unsigned long)irq_handler,
					(unsigned long)arg);
}

static inline unsigned long
HYPERVISOR_guest_intr_thread(int vcpu_id, int irq, int virq_id, int gpid_nr,
				int (*irq_fn)(int, void *), void *arg)
{
	return generic_hypercall6(KVM_HCALL_GUEST_INTR_THREAD,
					vcpu_id, irq, virq_id,
					gpid_nr, (unsigned long)irq_fn,
					(unsigned long)arg);
}

static inline unsigned long
HYPERVISOR_guest_free_intr_handler(int irq, void *arg)
{
	return generic_hypercall2(KVM_HCALL_GUEST_FREE_INTR_HANDLER, irq,
					(unsigned long)arg);
}

static inline unsigned long
HYPERVISOR_get_guest_direct_virq(int irq, int virq_id)
{
	return generic_hypercall2(KVM_HCALL_GET_GUEST_DIRECT_VIRQ,
					irq, virq_id);
}

static inline unsigned long
HYPERVISOR_free_guest_direct_virq(int irq)
{
	return generic_hypercall1(KVM_HCALL_FREE_GUEST_DIRECT_VIRQ, irq);
}

static inline unsigned long
HYPERVISOR_switch_to_virt_mode(kvm_task_info_t *task_info,
		void (*func)(void *data, void *arg1, void *arg2),
		void *data, void *arg1, void *arg2)
{
	return generic_hypercall5(KVM_HCALL_SWITCH_TO_VIRT_MODE,
					(unsigned long)task_info,
					(unsigned long)func,
					(unsigned long)data,
					(unsigned long)arg1,
					(unsigned long)arg2);
}

static inline unsigned long
HYPERVISOR_switch_guest_kernel_stacks(kvm_task_info_t *task_info,
		char *entry_point, unsigned long *args, int args_num)
{
	return generic_hypercall4(KVM_HCALL_SWITCH_GUEST_KERNEL_STACKS,
			(unsigned long)task_info, (unsigned long)entry_point,
			(unsigned long)args, (unsigned long)args_num);
}

static inline unsigned long
HYPERVISOR_update_hw_stacks_frames(e2k_mem_crs_t *pcs_frame, int pcs_frame_ind,
		kernel_mem_ps_t *ps_frame, int ps_frame_ind, int ps_frame_size)
{
	return generic_hypercall5(KVM_HCALL_UPDATE_HW_STACKS_FRAMES,
					(unsigned long)pcs_frame,
					pcs_frame_ind,
					(unsigned long)ps_frame,
					ps_frame_ind, ps_frame_size);
}

static inline unsigned long
HYPERVISOR_copy_hw_stacks_frames(void __user *dst, void __user *src,
				 long size, bool is_chain)
{
	return generic_hypercall4(KVM_HCALL_COPY_HW_STACKS_FRAMES,
			(unsigned long)dst, (unsigned long)src, size, is_chain);
}
static inline unsigned long
HYPERVISOR_copy_guest_kernel_stacks(kvm_task_info_t *task_info)
{
	return generic_hypercall1(KVM_HCALL_COPY_GUEST_KERNEL_STACKS,
					(unsigned long)task_info);
}

static inline unsigned long
HYPERVISOR_switch_to_guest_new_user(kvm_task_info_t *task_info)
{
	return generic_hypercall1(KVM_HCALL_SWITCH_TO_GUEST_NEW_USER,
					(unsigned long)task_info);
}

static inline unsigned long
HYPERVISOR_clone_guest_user_stacks(kvm_task_info_t *task_info)
{
	return generic_hypercall1(KVM_HCALL_CLONE_GUEST_USER_STACKS,
					(unsigned long)task_info);
}

static inline unsigned long
HYPERVISOR_copy_guest_user_stacks(kvm_task_info_t *task_info,
				  vcpu_gmmu_info_t *gmmu_info)
{
	return generic_hypercall2(KVM_HCALL_COPY_GUEST_USER_STACKS,
			(unsigned long)task_info, (unsigned long)gmmu_info);
}

static inline unsigned long
HYPERVISOR_patch_guest_data_and_chain_stacks(kvm_data_stack_info_t *ds_patch,
		kvm_pcs_patch_info_t pcs_patch[], int pcs_frames)
{
	return generic_hypercall3(KVM_HCALL_PATCH_GUEST_DATA_AND_CHAIN_STACKS,
				(unsigned long)ds_patch,
				(unsigned long)pcs_patch, pcs_frames);
}

static inline unsigned long
HYPERVISOR_get_guest_glob_regs(unsigned long *gregs[2],
		unsigned long not_get_gregs_mask,
		bool dirty_bgr, unsigned int *bgr)
{
	return generic_hypercall4(KVM_HCALL_GET_GUEST_GLOB_REGS,
			(unsigned long)gregs, not_get_gregs_mask,
			(unsigned long)dirty_bgr, (unsigned long)bgr);
}
static inline unsigned long
HYPERVISOR_set_guest_glob_regs(unsigned long *gregs[2],
		unsigned long not_set_gregs_mask,
		bool dirty_bgr, unsigned int *bgr)
{
	return generic_hypercall4(KVM_HCALL_SET_GUEST_GLOB_REGS,
			(unsigned long)gregs, not_set_gregs_mask,
			(unsigned long)dirty_bgr, (unsigned long)bgr);
}
static inline unsigned long
HYPERVISOR_set_guest_glob_regs_dirty_bgr(unsigned long *gregs[2],
		unsigned long not_set_gregs_mask)
{
	return generic_hypercall4(KVM_HCALL_SET_GUEST_GLOB_REGS,
			(unsigned long)gregs, not_set_gregs_mask,
			(unsigned long)false, (unsigned long)NULL);
}
static inline unsigned long
HYPERVISOR_get_guest_local_glob_regs(unsigned long *l_gregs[2])
{
	return generic_hypercall1(KVM_HCALL_GET_GUEST_LOCAL_GLOB_REGS,
			(unsigned long)l_gregs);
}
static inline unsigned long
HYPERVISOR_set_guest_local_glob_regs(unsigned long *l_gregs[2])
{
	return generic_hypercall1(KVM_HCALL_SET_GUEST_LOCAL_GLOB_REGS,
			(unsigned long)l_gregs);
}

static inline unsigned long
HYPERVISOR_get_all_guest_glob_regs(unsigned long *gregs[2])
{
	return generic_hypercall1(KVM_HCALL_GET_ALL_GUEST_GLOB_REGS,
			(unsigned long)gregs);
}

static inline unsigned long
HYPERVISOR_recovery_faulted_tagged_guest_store(e2k_addr_t address, u64 wr_data,
		u32 data_tag, u64 st_rec_opc, u64 data_ext, u32 data_ext_tag,
		u64 opc_ext, int chan, int qp_store, int atomic_store)
{
	union recovery_faulted_arg arg = {
		.chan = chan,
		.qp = !!qp_store,
		.atomic = !!atomic_store,
		.tag = data_tag,
		.tag_ext = data_ext_tag
	};
	return generic_hypercall6(KVM_HCALL_RECOVERY_FAULTED_TAGGED_GUEST_STORE,
			address, wr_data, st_rec_opc, data_ext, opc_ext,
			arg.entire);
}
static inline unsigned long
HYPERVISOR_recovery_faulted_guest_load(e2k_addr_t address,
		u64 *ld_val, u8 *data_tag, u64 ld_rec_opc, int chan)
{
	return generic_hypercall5(KVM_HCALL_RECOVERY_FAULTED_GUEST_LOAD,
				address, (unsigned long)ld_val,
				(unsigned long)data_tag, ld_rec_opc, chan);
}
static inline unsigned long
HYPERVISOR_recovery_faulted_guest_move(e2k_addr_t addr_from, e2k_addr_t addr_to,
		e2k_addr_t addr_to_hi, int vr, u64 ld_rec_opc, int chan,
		int qp_load, int atomic_load)
{
	union recovery_faulted_arg arg = {
		.vr = vr,
		.chan = chan,
		.qp = !!qp_load,
		.atomic = !!atomic_load
	};
	return generic_hypercall5(KVM_HCALL_RECOVERY_FAULTED_GUEST_MOVE,
				addr_from, addr_to, addr_to_hi,
				ld_rec_opc, arg.entire);
}
static inline unsigned long
HYPERVISOR_recovery_faulted_load_to_guest_greg(e2k_addr_t address,
		u32 greg_num_d, int vr, u64 ld_rec_opc, int chan,
		int qp_load, int atomic_load,
		void *saved_greg_lo, void *saved_greg_hi)
{
	union recovery_faulted_arg arg = {
		.vr = vr,
		.chan = chan,
		.qp = !!qp_load,
		.atomic = !!atomic_load
	};
	return generic_hypercall6(KVM_HCALL_RECOVERY_FAULTED_LOAD_TO_GUEST_GREG,
			address, greg_num_d, ld_rec_opc, arg.entire,
			(unsigned long) saved_greg_lo,
			(unsigned long) saved_greg_hi);
}

static inline unsigned long
HYPERVISOR_recovery_faulted_tagged_store(e2k_addr_t address, u64 wr_data,
		u32 data_tag, u64 st_rec_opc, u64 data_ext, u32 data_ext_tag,
		u64 opc_ext, int chan, int qp_store, int atomic_store)
{
	union recovery_faulted_arg arg = {
		.chan = chan,
		.qp = !!qp_store,
		.atomic = !!atomic_store,
		.tag = data_tag,
		.tag_ext = data_ext_tag
	};
	return generic_hypercall6(KVM_HCALL_RECOVERY_FAULTED_TAGGED_STORE,
			address, wr_data, st_rec_opc, data_ext, opc_ext,
			arg.entire);
}
static inline unsigned long
HYPERVISOR_recovery_faulted_load(e2k_addr_t address, u64 *ld_val,
					u8 *data_tag, u64 ld_rec_opc, int chan)
{
	return generic_hypercall5(KVM_HCALL_RECOVERY_FAULTED_LOAD,
				address, (unsigned long)ld_val,
				(unsigned long)data_tag, ld_rec_opc, chan);
}
static inline unsigned long
HYPERVISOR_recovery_faulted_move(e2k_addr_t addr_from, e2k_addr_t addr_to,
		e2k_addr_t addr_to_hi, int vr, u64 ld_rec_opc, int chan,
		int qp_load, int atomic_load)
{
	union recovery_faulted_arg arg = {
		.vr = vr,
		.chan = chan,
		.qp = !!qp_load,
		.atomic = !!atomic_load
	};
	return generic_hypercall5(KVM_HCALL_RECOVERY_FAULTED_MOVE,
				addr_from, addr_to, addr_to_hi,
				ld_rec_opc, arg.entire);
}
static inline unsigned long
HYPERVISOR_recovery_faulted_load_to_greg(e2k_addr_t address, u32 greg_num_d,
		int vr, u64 ld_rec_opc, int chan, int qp_load,
		int atomic_load, void *saved_greg_lo, void *saved_greg_hi)
{
	union recovery_faulted_arg arg = {
		.vr = vr,
		.chan = chan,
		.qp = !!qp_load,
		.atomic = !!atomic_load
	};
	return generic_hypercall6(KVM_HCALL_RECOVERY_FAULTED_LOAD_TO_GREG,
				address, greg_num_d, ld_rec_opc, arg.entire,
				(unsigned long)saved_greg_lo,
				(unsigned long)saved_greg_hi);
}
static inline unsigned long
HYPERVISOR_move_tagged_guest_data(int word_size,
			e2k_addr_t addr_from, e2k_addr_t addr_to)
{
	return generic_hypercall3(KVM_HCALL_MOVE_TAGGED_GUEST_DATA,
				word_size, addr_from, addr_to);
}
static inline unsigned long
HYPERVISOR_fast_tagged_guest_memory_copy(void *dst, const void *src, size_t len,
		unsigned long strd_opcode, unsigned long ldrd_opcode,
		int prefetch)
{
	return generic_hypercall6(KVM_HCALL_FAST_TAGGED_GUEST_MEMORY_COPY,
			(unsigned long)dst, (unsigned long)src,
			len, strd_opcode, ldrd_opcode, prefetch);
}
static inline unsigned long
HYPERVISOR_fast_tagged_guest_memory_set(void *addr, u64 val, u64 tag,
		size_t len, u64 strd_opcode)
{
	return generic_hypercall5(KVM_HCALL_FAST_TAGGED_GUEST_MEMORY_SET,
			(unsigned long)addr, val, tag, len, strd_opcode);
}

static inline unsigned long
HYPERVISOR_boot_spin_lock_slow(void *lock, bool check_unlock)
{
	return generic_hypercall2(KVM_HCALL_BOOT_SPIN_LOCK_SLOW,
					(unsigned long)lock,
					(unsigned long)check_unlock);
}
static inline unsigned long
HYPERVISOR_boot_spin_locked_slow(void *lock)
{
	return generic_hypercall1(KVM_HCALL_BOOT_SPIN_LOCKED_SLOW,
					(unsigned long)lock);
}
static inline unsigned long
HYPERVISOR_boot_spin_unlock_slow(void *lock, bool add_to_unlock)
{
	return generic_hypercall2(KVM_HCALL_BOOT_SPIN_UNLOCK_SLOW,
					(unsigned long)lock,
					(unsigned long)add_to_unlock);
}

static inline unsigned long
HYPERVISOR_guest_spin_lock_slow(void *lock, bool check_unlock)
{
	return generic_hypercall2(KVM_HCALL_GUEST_SPIN_LOCK_SLOW,
					(unsigned long)lock,
					(unsigned long)check_unlock);
}
static inline unsigned long
HYPERVISOR_guest_spin_locked_slow(void *lock)
{
	return generic_hypercall1(KVM_HCALL_GUEST_SPIN_LOCKED_SLOW,
					(unsigned long)lock);
}
static inline unsigned long
HYPERVISOR_guest_spin_unlock_slow(void *lock, bool add_to_unlock)
{
	return generic_hypercall2(KVM_HCALL_GUEST_SPIN_UNLOCK_SLOW,
					(unsigned long)lock,
					(unsigned long)add_to_unlock);
}

typedef enum csd_ctl {
	CSD_LOCK_CTL = 1,	/* register csd lock wait */
	CSD_UNLOCK_CTL,		/* unlock csd lock wait and wake up */
				/* waiting guest VCPU */
	CSD_LOCK_WAIT_CTL,	/* wait for csd lock will be unlocked */
	CSD_LOCK_TRY_WAIT_CTL,	/* try wait for asynchronous csd lock */
} csd_ctl_t;

static inline unsigned long
HYPERVISOR_guest_csd_lock_ctl(csd_ctl_t csd_ctl, void *lock)
{
	return generic_hypercall2(KVM_HCALL_GUEST_CSD_LOCK_CTL,
					(unsigned long)csd_ctl,
					(unsigned long)lock);
}
static inline unsigned long
HYPERVISOR_guest_csd_lock(void *lock)
{
	return HYPERVISOR_guest_csd_lock_ctl(CSD_LOCK_CTL, lock);
}
static inline unsigned long
HYPERVISOR_guest_csd_unlock(void *lock)
{
	return HYPERVISOR_guest_csd_lock_ctl(CSD_UNLOCK_CTL, lock);
}
static inline unsigned long
HYPERVISOR_guest_csd_lock_wait(void *lock)
{
	return HYPERVISOR_guest_csd_lock_ctl(CSD_LOCK_WAIT_CTL, lock);
}
static inline unsigned long
HYPERVISOR_guest_csd_lock_try_wait(void *lock)
{
	return HYPERVISOR_guest_csd_lock_ctl(CSD_LOCK_TRY_WAIT_CTL, lock);
}

static inline unsigned long
HYPERVISOR_pt_atomic_update(unsigned long gpa, void __user *old_gpte,
		unsigned atomic_op, unsigned long prot_mask)
{
	return generic_hypercall4(KVM_HCALL_PT_ATOMIC_UPDATE,
			gpa, (unsigned long)old_gpte, atomic_op, prot_mask);
}

static inline unsigned long
HYPERVISOR_kvm_guest_mm_drop(unsigned long gmmid_nr)
{
	return generic_hypercall1(KVM_HCALL_GUEST_MM_DROP, gmmid_nr);
}

static inline unsigned long
HYPERVISOR_kvm_activate_guest_mm(unsigned long active_gmmid_nr,
			unsigned long gmmid_nr, e2k_addr_t u_phys_ptb)
{
	return generic_hypercall3(KVM_HCALL_ACTIVATE_GUEST_MM,
				active_gmmid_nr, gmmid_nr, u_phys_ptb);
}

static inline unsigned long
HYPERVISOR_kvm_switch_guest_mm(unsigned long gpid_nr, unsigned long gmmid_nr,
				e2k_addr_t u_phys_ptb)
{
	return generic_hypercall3(KVM_HCALL_SWITCH_GUEST_MM,
				gpid_nr, gmmid_nr, u_phys_ptb);
}

static inline unsigned long
HYPERVISOR_vcpu_guest_mmu_state(vcpu_gmmu_info_t *mmu_info)
{
	return generic_hypercall1(KVM_HCALL_VCPU_MMU_STATE,
					(unsigned long)mmu_info);
}

/* guest kernel memory attribytes to set/update */
typedef enum kvm_sma_mode {
	KVM_SMA_RO,
	KVM_SMA_RW,
	KVM_SMA_NX,
	KVM_SMA_X,
	KVM_SMA_P,
	KVM_SMA_NP,
} kvm_sma_mode_t;

/*
 * IO control hypercalls
 */

/*
 * Commands to HYPERVISOR_console_io().
 */
#define CONSOLEIO_write         0
#define CONSOLEIO_read          1

/*
 * Some hypercalls return value
 */
#define	RETURN_TO_HOST_APP_HCRET	\
		(((u64)'r' << 56) | ((u64)'e' << 48) | \
			((u64)'t' << 40) | ((u64)'2' << 32) | \
			((u64)'h' << 24) | ((u64)'o' << 16) | \
			((u64)'s' << 8)  | ((u64)'t' << 0))

static inline unsigned long
HYPERVISOR_guest_ioport_request(unsigned short port,
		unsigned int __user *data, unsigned char size,
		unsigned char is_out)
{
	return generic_hypercall4(KVM_HCALL_GUEST_IOPORT_REQ, port,
					(unsigned long)data,
					size, is_out);
}
static inline unsigned long
HYPERVISOR_guest_ioport_string_request(unsigned short port,
		const void __user *data, unsigned char size, unsigned int count,
		unsigned char is_out)
{
	return generic_hypercall5(KVM_HCALL_GUEST_IOPORT_STRING_REQ, port,
					(unsigned long)data,
					size, count, is_out);
}
static inline unsigned long
HYPERVISOR_guest_mmio_request(unsigned long mmio_addr,
		unsigned long __user *data, unsigned char size,
		unsigned char is_write)
{
	return generic_hypercall4(KVM_HCALL_GUEST_MMIO_REQ, mmio_addr,
					(unsigned long)data,
					size, is_write);
}
static inline unsigned long
HYPERVISOR_console_io(int io_cmd, int size, char __user *str)
{
	return generic_hypercall3(KVM_HCALL_CONSOLE_IO, io_cmd, size,
					(unsigned long)str);
}
static inline unsigned long
HYPERVISOR_notify_io(unsigned int notifier_io)
{
	return generic_hypercall1(KVM_HCALL_NOTIFY_IO, notifier_io);
}

/*
 * Kernel VM shut-down and panicking reason
 */
#define	KVM_SHUTDOWN_POWEROFF		0x01
#define	KVM_SHUTDOWN_RESTART		0x02
#define	KVM_SHUTDOWN_PANIC		0x03

extern void smp_send_refresh(void);
static inline unsigned long
HYPERVISOR_kvm_shutdown(void *msg, unsigned long reason)
{
	smp_send_refresh();
	return generic_hypercall2(KVM_HCALL_SHUTDOWN, (unsigned long)msg,
					reason);
}
static inline unsigned long
HYPERVISOR_kvm_guest_vcpu_common_idle(long timeout, bool interruptable)
{
	return generic_hypercall2(KVM_HCALL_GUEST_VCPU_COMMON_IDLE,
					timeout, interruptable);
}
static inline unsigned long
HYPERVISOR_kvm_guest_vcpu_relax(void)
{
	return generic_hypercall0(KVM_HCALL_GUEST_VCPU_RELAX);
}
#ifdef	CONFIG_SMP
static inline unsigned long
HYPERVISOR_kvm_activate_guest_vcpu(int vcpu_id)
{
	return generic_hypercall1(KVM_HCALL_ACTIVATE_GUEST_VCPU, vcpu_id);
}
static inline unsigned long
HYPERVISOR_kvm_activate_guest_all_vcpus(void)
{
	return generic_hypercall0(KVM_HCALL_ACTIVATE_GUEST_ALL_VCPUS);
}
#endif	/* CONFIG_SMP */
static inline unsigned long
HYPERVISOR_host_printk(char *msg, int size)
{
	return generic_hypercall2(KVM_HCALL_HOST_PRINTK, (unsigned long)msg,
					(unsigned long)size);
}
static inline unsigned long
HYPERVISOR_print_guest_kernel_ptes(e2k_addr_t address)
{
	return generic_hypercall1(KVM_HCALL_PRINT_GUEST_KERNEL_PTES, address);
}
static inline unsigned long
HYPERVISOR_print_guest_user_address_ptes(int gmmid_nr, e2k_addr_t address)
{
	return generic_hypercall2(KVM_HCALL_PRINT_GUEST_USER_ADDRESS_PTES,
			gmmid_nr, address);
}
static inline void
HYPERVISOR_dump_guest_stack(void)
{
	generic_hypercall0(KVM_HCALL_DUMP_GUEST_STACK);
}
static inline void
HYPERVISOR_ftrace_stop(void)
{
	generic_hypercall0(KVM_HCALL_FTRACE_STOP);
}
static inline void
HYPERVISOR_ftrace_dump(void)
{
	generic_hypercall0(KVM_HCALL_FTRACE_DUMP);
}
static inline void
HYPERVISOR_vcpu_show_state_completion(void)
{
	generic_hypercall0(KVM_HCALL_DUMP_COMPLETION);
}
static inline unsigned long
HYPERVISOR_fast_tagged_memory_copy(void *dst, const void *src, size_t len,
		unsigned long strd_opcode, unsigned long ldrd_opcode,
		int prefetch)
{
	return generic_hypercall6(KVM_HCALL_FAST_TAGGED_MEMORY_COPY,
			(unsigned long)dst, (unsigned long)src,
			len, strd_opcode, ldrd_opcode, prefetch);
}
static inline unsigned long
HYPERVISOR_fast_tagged_memory_set(void *addr, u64 val, u64 tag,
		size_t len, u64 strd_opcode)
{
	return generic_hypercall5(KVM_HCALL_FAST_TAGGED_MEMORY_SET,
			(unsigned long)addr, val, tag, len, strd_opcode);
}
#ifdef CONFIG_KVM_ASYNC_PF
static inline int HYPERVISOR_pv_enable_async_pf(u64 apf_reason_gpa,
		u64 apf_id_gpa, u32 apf_ready_vector, u32 irq_controller)
{
	return generic_hypercall4(KVM_HCALL_PV_ENABLE_ASYNC_PF,
					apf_reason_gpa, apf_id_gpa,
					apf_ready_vector, irq_controller);
}
#endif /* CONFIG_KVM_ASYNC_PF */
static inline unsigned long
HYPERVISOR_flush_tlb_range(e2k_addr_t start_gva, e2k_addr_t end_gva)
{
	return generic_hypercall2(KVM_HCALL_FLUSH_TLB_RANGE,
			start_gva, end_gva);
}

/*
 * arguments:
 * VIRQ number
 * flag: "is VIRQ handling in progress and need wake up main VCPU thread, which
 *	can be on idle"
 * results of waiting for VIRQ:
 * > 0 : number of VIRQs waiting for handling
 * = 0 : VIRQ handler should be stopped
 * < 0 : if error detected
 */
#define	KVM_VIRQ_RECEIVED(ret)	((ret) > 0)
#define	KVM_VIRQ_STOPPED(ret)	((ret) == 0)
#define	KVM_VIRQ_FAILED(ret)	((ret) < 0)

static inline unsigned long
HYPERVISOR_wait_for_virq(int virq, bool in_progress)
{
	return generic_hypercall2(KVM_HCALL_WAIT_FOR_VIRQ, virq, in_progress);
}

#endif /* _ASM_E2K_HYPERCALL_H */
