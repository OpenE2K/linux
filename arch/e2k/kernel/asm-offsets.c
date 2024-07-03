/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Generate definitions needed by assembly language modules.
 * This code generates raw asm output which is post-processed to extract
 * and format the required data.
 */

#define ASM_OFFSETS_C 1

#include <linux/types.h>
#include <linux/list.h>
#include <linux/kbuild.h>
#include <linux/numa.h>
#include <linux/ptrace.h>
#include <linux/uaccess.h>
#include <asm/p2v/boot_head.h>
#include <asm/machdep.h>
#include <asm/pv_info.h>
#ifdef	CONFIG_VIRTUALIZATION
#include <linux/kvm_host.h>
#endif	/* CONFIG_VIRTUALIZATION */

void common(void) {

OFFSET(TSK_TI_FLAGS, task_struct, thread_info.flags);
OFFSET(TSK_U_STACK_TOP, task_struct, thread_info.u_stack.top);
OFFSET(TSK_K_USD_LO, task_struct,  thread_info.k_usd_lo);
OFFSET(TSK_K_USD_HI, task_struct, thread_info.k_usd_hi);
OFFSET(TSK_IRQ_ENTER_CLK, task_struct, thread_info.irq_enter_clk);
OFFSET(TSK_UPSR, task_struct, thread_info.upsr);
#ifndef CONFIG_MMU_SEP_VIRT_SPACE_ONLY
OFFSET(TSK_K_ROOT_PTB, task_struct, thread.regs.k_root_ptb);
#endif

OFFSET(TI_FLAGS, thread_info, flags);
OFFSET(TI_STATUS, thread_info, status);
OFFSET(TI_K_USD_LO, thread_info, k_usd_lo);
OFFSET(TI_K_USD_HI, thread_info, k_usd_hi);
OFFSET(TSK_TI_K_PSP_LO, task_struct, thread_info.k_psp_lo);
OFFSET(TSK_TI_K_PSP_HI, task_struct, thread_info.k_psp_hi);
OFFSET(TSK_TI_K_PCSP_LO, task_struct, thread_info.k_pcsp_lo);
OFFSET(TSK_TI_K_PCSP_HI, task_struct, thread_info.k_pcsp_hi);

OFFSET(TSK_TI_TMP_U_PSP_LO, task_struct, thread_info.tmp_user_stacks.psp_lo);
OFFSET(TSK_TI_TMP_U_PSP_HI, task_struct, thread_info.tmp_user_stacks.psp_hi);
OFFSET(TSK_TI_TMP_U_PCSP_LO, task_struct, thread_info.tmp_user_stacks.pcsp_lo);
OFFSET(TSK_TI_TMP_U_PCSP_HI, task_struct, thread_info.tmp_user_stacks.pcsp_hi);
OFFSET(TSK_TI_TMP_U_PSHTP, task_struct, thread_info.tmp_user_stacks.pshtp);
OFFSET(TSK_TI_TMP_U_PCSHTP, task_struct, thread_info.tmp_user_stacks.pcshtp);

OFFSET(TSK_TI_G_VCPU_STATE, task_struct,
	thread_info.k_gregs.g[GUEST_VCPU_STATE_GREGS_PAIRS_INDEX].base);
OFFSET(TSK_TI_G_TASK, task_struct,
	thread_info.k_gregs.g[CURRENT_TASK_GREGS_PAIRS_INDEX].base);
OFFSET(TSK_TI_G_MY_CPU_OFFSET, task_struct,
	thread_info.k_gregs.g[MY_CPU_OFFSET_GREGS_PAIRS_INDEX].base);
OFFSET(TSK_TI_G_CPU_ID_PREEMPT, task_struct,
	thread_info.k_gregs.g[SMP_CPU_ID_GREGS_PAIRS_INDEX].base);
OFFSET(TSK_TI_G_VCPU_STATE_EXT, task_struct,
	thread_info.k_gregs.g[GUEST_VCPU_STATE_GREGS_PAIRS_INDEX].ext);
OFFSET(TSK_TI_G_TASK_EXT, task_struct,
	thread_info.k_gregs.g[CURRENT_TASK_GREGS_PAIRS_INDEX].ext);
OFFSET(TSK_TI_G_MY_CPU_OFFSET_EXT, task_struct,
	thread_info.k_gregs.g[MY_CPU_OFFSET_GREGS_PAIRS_INDEX].ext);
OFFSET(TSK_TI_G_CPU_ID_PREEMPT_EXT, task_struct,
	thread_info.k_gregs.g[SMP_CPU_ID_GREGS_PAIRS_INDEX].ext);

OFFSET(TSK_TI_TMP_G_VCPU_STATE, task_struct,
	thread_info.tmp_k_gregs.g[GUEST_VCPU_STATE_GREGS_PAIRS_INDEX].base);
OFFSET(TSK_TI_TMP_G_TASK, task_struct,
	thread_info.tmp_k_gregs.g[CURRENT_TASK_GREGS_PAIRS_INDEX].base);
OFFSET(TSK_TI_TMP_G_MY_CPU_OFFSET, task_struct,
	thread_info.tmp_k_gregs.g[MY_CPU_OFFSET_GREGS_PAIRS_INDEX].base);
OFFSET(TSK_TI_TMP_G_CPU_ID_PREEMPT, task_struct,
	thread_info.tmp_k_gregs.g[SMP_CPU_ID_GREGS_PAIRS_INDEX].base);
OFFSET(TSK_TI_TMP_G_VCPU_STATE_EXT, task_struct,
	thread_info.tmp_k_gregs.g[GUEST_VCPU_STATE_GREGS_PAIRS_INDEX].ext);
OFFSET(TSK_TI_TMP_G_TASK_EXT, task_struct,
	thread_info.tmp_k_gregs.g[CURRENT_TASK_GREGS_PAIRS_INDEX].ext);
OFFSET(TSK_TI_TMP_G_MY_CPU_OFFSET_EXT, task_struct,
	thread_info.tmp_k_gregs.g[MY_CPU_OFFSET_GREGS_PAIRS_INDEX].ext);
OFFSET(TSK_TI_TMP_G_CPU_ID_PREEMPT_EXT, task_struct,
	thread_info.tmp_k_gregs.g[SMP_CPU_ID_GREGS_PAIRS_INDEX].ext);
#ifdef	CONFIG_VIRTUALIZATION
OFFSET(TI_VCPU, thread_info, vcpu);
#endif	/* CONFIG_VIRTUALIZATION */
OFFSET(TI_KERNEL_GREGS, thread_info, k_gregs.g);
OFFSET(TI_G_VCPU_STATE, thread_info,
	k_gregs.g[GUEST_VCPU_STATE_GREGS_PAIRS_INDEX].base);
OFFSET(TI_G_TASK, thread_info, k_gregs.g[CURRENT_TASK_GREGS_PAIRS_INDEX].base);
OFFSET(TI_G_MY_CPU_OFFSET, thread_info,
		k_gregs.g[MY_CPU_OFFSET_GREGS_PAIRS_INDEX].base);
OFFSET(TI_G_CPU_ID_PREEMPT, thread_info, k_gregs.g[SMP_CPU_ID_GREGS_PAIRS_INDEX].base);
OFFSET(TI_G_VCPU_STATE_EXT, thread_info,
		k_gregs.g[GUEST_VCPU_STATE_GREGS_PAIRS_INDEX].ext);
OFFSET(TI_G_TASK_EXT, thread_info,
		k_gregs.g[CURRENT_TASK_GREGS_PAIRS_INDEX].ext);
OFFSET(TI_G_MY_CPU_OFFSET_EXT, thread_info,
		k_gregs.g[MY_CPU_OFFSET_GREGS_PAIRS_INDEX].ext);
OFFSET(TI_G_CPU_ID_PREEMPT_EXT, thread_info,
		k_gregs.g[SMP_CPU_ID_GREGS_PAIRS_INDEX].ext);

#ifdef CONFIG_FUNCTION_GRAPH_TRACER
OFFSET(TSK_CURR_RET_STACK, task_struct, curr_ret_stack);
#endif
OFFSET(TSK_PTRACE, task_struct, ptrace);
OFFSET(TSK_THREAD, task_struct, thread);
OFFSET(TSK_STACK, task_struct, stack);
OFFSET(TSK_FLAGS, task_struct, flags);
OFFSET(TSK_THREAD_FLAGS, task_struct, thread.flags);
OFFSET(TSK_DAM, task_struct, thread.dam);
OFFSET(TSK_TI, task_struct, thread_info);

OFFSET(TT_FLAGS, thread_struct, flags);

#ifdef	CONFIG_CLW_ENABLE
OFFSET(PT_US_CL_M0, pt_regs, us_cl_m[0]);
OFFSET(PT_US_CL_M1, pt_regs, us_cl_m[1]);
OFFSET(PT_US_CL_M2, pt_regs, us_cl_m[2]);
OFFSET(PT_US_CL_M3, pt_regs, us_cl_m[3]);
OFFSET(PT_US_CL_UP, pt_regs, us_cl_up);
OFFSET(PT_US_CL_B, pt_regs, us_cl_b);
#endif

#ifdef	CONFIG_VIRTUALIZATION
OFFSET(TI_KERNEL_IMAGE_PGD_P, thread_info, kernel_image_pgd_p);
OFFSET(TI_KERNEL_IMAGE_PGD, thread_info, kernel_image_pgd);
OFFSET(TI_SHADOW_IMAGE_PGD, thread_info, shadow_image_pgd);
OFFSET(TI_GTHREAD_INFO, thread_info, gthread_info);
OFFSET(TI_VCPU, thread_info, vcpu);

OFFSET(GLOB_REG_BASE, e2k_greg, base);
OFFSET(GLOB_REG_EXT, e2k_greg, ext);
DEFINE(GLOB_REG_SIZE, sizeof(struct e2k_greg));

OFFSET(VCPU_ARCH_VCPU_STATE, kvm_vcpu, arch.vcpu_state);
OFFSET(VCPU_STATE_CPU_REGS, kvm_vcpu_state, cpu.regs);
OFFSET(VCPU_ARCH_CTXT_SBR, kvm_vcpu, arch.sw_ctxt.sbr);
OFFSET(VCPU_ARCH_CTXT_USD_HI, kvm_vcpu, arch.sw_ctxt.usd_hi);
OFFSET(VCPU_ARCH_CTXT_USD_LO, kvm_vcpu, arch.sw_ctxt.usd_lo);
OFFSET(VCPU_ARCH_CTXT_SAVED_VALID, kvm_vcpu, arch.sw_ctxt.saved.valid);
OFFSET(VCPU_ARCH_CTXT_SAVED_SBR, kvm_vcpu, arch.sw_ctxt.saved.sbr);
OFFSET(VCPU_ARCH_CTXT_SAVED_USD_HI, kvm_vcpu, arch.sw_ctxt.saved.usd_hi);
OFFSET(VCPU_ARCH_CTXT_SAVED_USD_LO, kvm_vcpu, arch.sw_ctxt.saved.usd_lo);

#ifdef	CONFIG_CLW_ENABLE
OFFSET(VCPU_ARCH_CTXT_US_CL_D, kvm_vcpu, arch.sw_ctxt.us_cl_d);
OFFSET(VCPU_ARCH_CTXT_US_CL_B, kvm_vcpu, arch.sw_ctxt.us_cl_b);
OFFSET(VCPU_ARCH_CTXT_US_CL_UP, kvm_vcpu, arch.sw_ctxt.us_cl_up);
OFFSET(VCPU_ARCH_CTXT_US_CL_M0, kvm_vcpu, arch.sw_ctxt.us_cl_m0);
OFFSET(VCPU_ARCH_CTXT_US_CL_M1, kvm_vcpu, arch.sw_ctxt.us_cl_m1);
OFFSET(VCPU_ARCH_CTXT_US_CL_M2, kvm_vcpu, arch.sw_ctxt.us_cl_m2);
OFFSET(VCPU_ARCH_CTXT_US_CL_M3, kvm_vcpu, arch.sw_ctxt.us_cl_m3);
#endif
#endif	/* CONFIG_VIRTUALIZATION */

OFFSET(PT_TRAP, pt_regs, trap);
OFFSET(PT_U_ROOT_PTB, pt_regs, uaccess.u_root_ptb);
OFFSET(PT_CONT, pt_regs, uaccess.cont);
OFFSET(PT_CTRP1, pt_regs, ctpr1);
OFFSET(PT_CTRP2, pt_regs, ctpr2);
OFFSET(PT_CTRP3, pt_regs, ctpr3);
OFFSET(PT_CTPR1_HI, pt_regs, ctpr1_hi);
OFFSET(PT_CTPR2_HI, pt_regs, ctpr2_hi);
OFFSET(PT_CTPR3_HI, pt_regs, ctpr3_hi);
OFFSET(PT_LSR, pt_regs, lsr);
OFFSET(PT_ILCR, pt_regs, ilcr);
OFFSET(PT_LSR1, pt_regs, lsr1);
OFFSET(PT_ILCR1, pt_regs, ilcr1);
OFFSET(PT_STACK, pt_regs, stacks);
OFFSET(PT_SYS_NUM, pt_regs, sys_num);
OFFSET(PT_KERNEL_ENTRY, pt_regs, kernel_entry);
OFFSET(PT_ARG_5, pt_regs, args[5]);
OFFSET(PT_ARG_6, pt_regs, args[6]);
OFFSET(PT_ARG_7, pt_regs, args[7]);
OFFSET(PT_ARG_8, pt_regs, args[8]);
OFFSET(PT_ARG_9, pt_regs, args[9]);
OFFSET(PT_ARG_10, pt_regs, args[10]);
OFFSET(PT_ARG_11, pt_regs, args[11]);
OFFSET(PT_ARG_12, pt_regs, args[12]);

OFFSET(ST_USD_HI, e2k_stacks, usd_hi);
OFFSET(ST_USD_LO, e2k_stacks, usd_lo);
OFFSET(ST_TOP, e2k_stacks, top);
OFFSET(PT_NEXT, pt_regs, next);
BLANK();

#ifdef	CONFIG_VIRTUALIZATION
OFFSET(PT_G_STACK, pt_regs, g_stacks);
OFFSET(G_ST_TOP, e2k_stacks, top);
OFFSET(G_ST_SBR, e2k_stacks, top);
#endif	/* CONFIG_VIRTUALIZATION */

/*DEFINE(NATIVE_TASK_SIZE, NATIVE_TASK_SIZE);*/	/* defined at asm/pv_info.h */

#if !defined(CONFIG_VIRTUALIZATION)
/*DEFINE(TASK_SIZE, NATIVE_TASK_SIZE);*/
#else	/* CONFIG_VIRTUALIZATION */
/*DEFINE(HOST_TASK_SIZE, HOST_TASK_SIZE);*/	/* defined at asm/pv_info.h */
/*DEFINE(GUEST_TASK_SIZE, GUEST_TASK_SIZE);*/	/* defined at asm/pv_info.h */
 #ifndef	CONFIG_KVM_GUEST_KERNEL
 /*DEFINE(TASK_SIZE, NATIVE_TASK_SIZE);*/
 #else	/* only virtualized guest kernel */
 /*DEFINE(TASK_SIZE, GUEST_TASK_SIZE);*/
 #endif	/* !CONFIG_KVM_GUEST_KERNEL */
#endif	/* !CONFIG_VIRTUALIZATION */

DEFINE(PTRACE_SZOF, sizeof (struct pt_regs));
DEFINE(TRAP_PTREGS_SZOF, sizeof(struct trap_pt_regs));
DEFINE(PT_PTRACED, PT_PTRACED);
DEFINE(E2K_FLAG_32BIT, E2K_FLAG_32BIT);
DEFINE(MAX_NR_CPUS, NR_CPUS);
DEFINE(E2K_KERNEL_UPSR_LOC_IRQ_ENABLED, E2K_KERNEL_UPSR_LOC_IRQ_ENABLED.word);
DEFINE(E2K_KERNEL_UPSR_LOC_IRQ_DISABLED_ALL, E2K_KERNEL_UPSR_LOC_IRQ_DISABLED_ALL.word);
DEFINE(E2K_KERNEL_UPSR_GLOB_IRQ_ENABLED, E2K_KERNEL_UPSR_GLOB_IRQ_ENABLED.word);
DEFINE(E2K_KERNEL_UPSR_GLOB_IRQ_DISABLED_ALL, E2K_KERNEL_UPSR_GLOB_IRQ_DISABLED_ALL.word);
DEFINE(E2K_LSR_VLC, E2K_LSR_VLC);
DEFINE(KERNEL_C_STACK_OFFSET, KERNEL_C_STACK_OFFSET);
DEFINE(KERNEL_C_STACK_SIZE, KERNEL_C_STACK_SIZE);
DEFINE(KERNEL_P_STACK_SIZE, KERNEL_P_STACK_SIZE);
DEFINE(KERNEL_PC_STACK_SIZE, KERNEL_PC_STACK_SIZE);
DEFINE(KERNEL_STACKS_SIZE, KERNEL_STACKS_SIZE);
DEFINE(CPU_HWBUG_USD_ALIGNMENT, CPU_HWBUG_USD_ALIGNMENT);
DEFINE(CPU_HWBUG_INTC_CR_WRITE, CPU_HWBUG_INTC_CR_WRITE);
DEFINE(CPU_FEAT_TRAP_V5, CPU_FEAT_TRAP_V5);
DEFINE(CPU_FEAT_TRAP_V6, CPU_FEAT_TRAP_V6);
DEFINE(CPU_FEAT_QPREG, CPU_FEAT_QPREG);
DEFINE(CPU_FEAT_SEP_VIRT_SPACE, CPU_FEAT_SEP_VIRT_SPACE);
DEFINE(CPU_FEAT_ISET_V6, CPU_FEAT_ISET_V6);
DEFINE(CPU_FEAT_ISET_V7, CPU_FEAT_ISET_V7);
DEFINE(CPU_FEAT_GLOBAL_IRQ_MASK, CPU_FEAT_GLOBAL_IRQ_MASK);
DEFINE(USER_ADDR_MAX, USER_ADDR_MAX);
DEFINE(DAM_ENTRIES_NUM, DAM_ENTRIES_NUM);
DEFINE(OS_VAB_REG_ADDR, _MMU_REG_NO_TO_MMU_ADDR_VAL(_MMU_OS_VAB_NO));
DEFINE(ROOT_PTB_REG_ADDR, _MMU_REG_NO_TO_MMU_ADDR_VAL(_MMU_U_PPTB_NO));

DEFINE(KERNEL_CUT_BYTE_SIZE, sizeof (kernel_CUT));
DEFINE(TSK_TI_STACK_DELTA, offsetof(struct task_struct, stack) -
		offsetof(struct task_struct, thread_info));
#ifdef CONFIG_SMP
DEFINE(TSK_TI_CPU_DELTA, offsetof(struct task_struct, cpu) -
	offsetof(struct task_struct, thread_info));
#endif
#ifdef CONFIG_PREEMPT_LAZY
OFFSET(TASK_TI_flags, task_struct, thread_info.flags);
OFFSET(TASK_TI_preempt_lazy_count, task_struct, thread_info.preempt_lazy_count);
#endif

}
