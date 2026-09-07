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
#include <asm/hb_regs.h>
#include <asm/machdep.h>
#include <asm/pic.h>
#include <asm/pv_info.h>

#ifdef	CONFIG_VIRTUALIZATION
#include <linux/kvm_host.h>
#endif	/* CONFIG_VIRTUALIZATION */

#ifdef CONFIG_BPF_JIT
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/bpf.h>
#endif /* CONFIG_BPF_JIT */

void common(void) {

OFFSET(TSK_U_STACK_TOP, task_struct, thread_info.u_stack.top);
OFFSET(TSK_K_USD_LO, task_struct, thread_info.k_usd.lo);
OFFSET(TSK_K_USD_HI, task_struct, thread_info.k_usd.hi);
#ifdef SHOW_WOKEN_TIME
OFFSET(TSK_IRQ_ENTER_CLK, task_struct, thread_info.irq_enter_clk);
#endif
OFFSET(TSK_UPSR, task_struct, thread_info.upsr);
#ifndef CONFIG_MMU_SEP_VIRT_SPACE_ONLY
OFFSET(TSK_K_ROOT_PTB, task_struct, thread.regs.k_root_ptb);
#endif

OFFSET(TI_STATUS, thread_info, status);
OFFSET(TI_K_USD_LO, thread_info, k_usd.lo);
OFFSET(TI_K_USD_HI, thread_info, k_usd.hi);
OFFSET(TSK_TI_K_PSP_LO, task_struct, thread_info.k_psp.lo);
OFFSET(TSK_TI_K_PSP_HI, task_struct, thread_info.k_psp.hi);
OFFSET(TSK_TI_K_PCSP_LO, task_struct, thread_info.k_pcsp.lo);
OFFSET(TSK_TI_K_PCSP_HI, task_struct, thread_info.k_pcsp.hi);

OFFSET(TSK_TMP_U_PSP_LO, task_struct, thread.tmp_user_stacks.psp.lo);
OFFSET(TSK_TMP_U_PSP_HI, task_struct, thread.tmp_user_stacks.psp.hi);
OFFSET(TSK_TMP_U_PCSP_LO, task_struct, thread.tmp_user_stacks.pcsp.lo);
OFFSET(TSK_TMP_U_PCSP_HI, task_struct, thread.tmp_user_stacks.pcsp.hi);
OFFSET(TSK_TMP_U_PSHTP, task_struct, thread.tmp_user_stacks.pshtp);
OFFSET(TSK_TMP_U_PCSHTP, task_struct, thread.tmp_user_stacks.pcshtp);

OFFSET(TSK_G_TMP_TAG, task_struct, thread.g_tmp_tag);

OFFSET(TSK_U_BGR, task_struct, thread.u_gregs.bgr);
OFFSET(TSK_U_G16, task_struct, thread.u_gregs.g[0].base);
OFFSET(TSK_U_G17, task_struct, thread.u_gregs.g[1].base);
OFFSET(TSK_U_G18, task_struct, thread.u_gregs.g[2].base);
OFFSET(TSK_U_G19, task_struct, thread.u_gregs.g[3].base);
OFFSET(TSK_U_G20, task_struct, thread.u_gregs.g[4].base);
OFFSET(TSK_U_G21, task_struct, thread.u_gregs.g[5].base);
OFFSET(TSK_U_G22, task_struct, thread.u_gregs.g[6].base);
OFFSET(TSK_U_G23, task_struct, thread.u_gregs.g[7].base);
OFFSET(TSK_U_G24, task_struct, thread.u_gregs.g[8].base);
OFFSET(TSK_U_G25, task_struct, thread.u_gregs.g[9].base);
OFFSET(TSK_U_G26, task_struct, thread.u_gregs.g[10].base);
OFFSET(TSK_U_G27, task_struct, thread.u_gregs.g[11].base);
OFFSET(TSK_U_G28, task_struct, thread.u_gregs.g[12].base);
OFFSET(TSK_U_G29, task_struct, thread.u_gregs.g[13].base);
OFFSET(TSK_U_G30, task_struct, thread.u_gregs.g[14].base);
OFFSET(TSK_U_G31, task_struct, thread.u_gregs.g[15].base);
OFFSET(TSK_U_G16_EXT, task_struct, thread.u_gregs.g[0].v5_ext);
OFFSET(TSK_U_G17_EXT, task_struct, thread.u_gregs.g[1].v5_ext);
OFFSET(TSK_U_G18_EXT, task_struct, thread.u_gregs.g[2].v5_ext);
OFFSET(TSK_U_G19_EXT, task_struct, thread.u_gregs.g[3].v5_ext);
OFFSET(TSK_U_G20_EXT, task_struct, thread.u_gregs.g[4].v5_ext);
OFFSET(TSK_U_G21_EXT, task_struct, thread.u_gregs.g[5].v5_ext);
OFFSET(TSK_U_G22_EXT, task_struct, thread.u_gregs.g[6].v5_ext);
OFFSET(TSK_U_G23_EXT, task_struct, thread.u_gregs.g[7].v5_ext);
OFFSET(TSK_U_G24_EXT, task_struct, thread.u_gregs.g[8].v5_ext);
OFFSET(TSK_U_G25_EXT, task_struct, thread.u_gregs.g[9].v5_ext);
OFFSET(TSK_U_G26_EXT, task_struct, thread.u_gregs.g[10].v5_ext);
OFFSET(TSK_U_G27_EXT, task_struct, thread.u_gregs.g[11].v5_ext);
OFFSET(TSK_U_G28_EXT, task_struct, thread.u_gregs.g[12].v5_ext);
OFFSET(TSK_U_G29_EXT, task_struct, thread.u_gregs.g[13].v5_ext);
OFFSET(TSK_U_G30_EXT, task_struct, thread.u_gregs.g[14].v5_ext);
OFFSET(TSK_U_G31_EXT, task_struct, thread.u_gregs.g[15].v5_ext);

OFFSET(TSK_TMP_BGR, task_struct, thread.tmp_gregs.bgr);
OFFSET(TSK_TMP_G16, task_struct, thread.tmp_gregs.g[0].base);
OFFSET(TSK_TMP_G17, task_struct, thread.tmp_gregs.g[1].base);
OFFSET(TSK_TMP_G18, task_struct, thread.tmp_gregs.g[2].base);
OFFSET(TSK_TMP_G19, task_struct, thread.tmp_gregs.g[3].base);
OFFSET(TSK_TMP_G20, task_struct, thread.tmp_gregs.g[4].base);
OFFSET(TSK_TMP_G21, task_struct, thread.tmp_gregs.g[5].base);
OFFSET(TSK_TMP_G22, task_struct, thread.tmp_gregs.g[6].base);
OFFSET(TSK_TMP_G23, task_struct, thread.tmp_gregs.g[7].base);
OFFSET(TSK_TMP_G24, task_struct, thread.tmp_gregs.g[8].base);
OFFSET(TSK_TMP_G25, task_struct, thread.tmp_gregs.g[9].base);
OFFSET(TSK_TMP_G26, task_struct, thread.tmp_gregs.g[10].base);
OFFSET(TSK_TMP_G27, task_struct, thread.tmp_gregs.g[11].base);
OFFSET(TSK_TMP_G28, task_struct, thread.tmp_gregs.g[12].base);
OFFSET(TSK_TMP_G29, task_struct, thread.tmp_gregs.g[13].base);
OFFSET(TSK_TMP_G30, task_struct, thread.tmp_gregs.g[14].base);
OFFSET(TSK_TMP_G31, task_struct, thread.tmp_gregs.g[15].base);
OFFSET(TSK_TMP_G16_EXT, task_struct, thread.tmp_gregs.g[0].v5_ext);
OFFSET(TSK_TMP_G17_EXT, task_struct, thread.tmp_gregs.g[1].v5_ext);
OFFSET(TSK_TMP_G18_EXT, task_struct, thread.tmp_gregs.g[2].v5_ext);
OFFSET(TSK_TMP_G19_EXT, task_struct, thread.tmp_gregs.g[3].v5_ext);
OFFSET(TSK_TMP_G20_EXT, task_struct, thread.tmp_gregs.g[4].v5_ext);
OFFSET(TSK_TMP_G21_EXT, task_struct, thread.tmp_gregs.g[5].v5_ext);
OFFSET(TSK_TMP_G22_EXT, task_struct, thread.tmp_gregs.g[6].v5_ext);
OFFSET(TSK_TMP_G23_EXT, task_struct, thread.tmp_gregs.g[7].v5_ext);
OFFSET(TSK_TMP_G24_EXT, task_struct, thread.tmp_gregs.g[8].v5_ext);
OFFSET(TSK_TMP_G25_EXT, task_struct, thread.tmp_gregs.g[9].v5_ext);
OFFSET(TSK_TMP_G26_EXT, task_struct, thread.tmp_gregs.g[10].v5_ext);
OFFSET(TSK_TMP_G27_EXT, task_struct, thread.tmp_gregs.g[11].v5_ext);
OFFSET(TSK_TMP_G28_EXT, task_struct, thread.tmp_gregs.g[12].v5_ext);
OFFSET(TSK_TMP_G29_EXT, task_struct, thread.tmp_gregs.g[13].v5_ext);
OFFSET(TSK_TMP_G30_EXT, task_struct, thread.tmp_gregs.g[14].v5_ext);
OFFSET(TSK_TMP_G31_EXT, task_struct, thread.tmp_gregs.g[15].v5_ext);

#ifdef	CONFIG_VIRTUALIZATION
OFFSET(TI_VCPU, thread_info, vcpu);
#endif	/* CONFIG_VIRTUALIZATION */

#ifdef CONFIG_FUNCTION_GRAPH_TRACER
OFFSET(TSK_CURR_RET_STACK, task_struct, curr_ret_stack);
#endif
OFFSET(TSK_PTRACE, task_struct, ptrace);
OFFSET(TSK_STACK, task_struct, stack);
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
OFFSET(TI_VCPU, thread_info, vcpu);

OFFSET(GLOB_REG_BASE, e2k_greg, base);
OFFSET(GLOB_REG_EXT, e2k_greg, v5_ext);
DEFINE(GLOB_REG_SIZE, sizeof(struct e2k_greg));

OFFSET(VCPU_ARCH_CTXT_SBR, kvm_vcpu, arch.sw_ctxt.sbr);
OFFSET(VCPU_ARCH_CTXT_USD_HI, kvm_vcpu, arch.sw_ctxt.usd.hi);
OFFSET(VCPU_ARCH_CTXT_USD_LO, kvm_vcpu, arch.sw_ctxt.usd.lo);
#endif	/* CONFIG_VIRTUALIZATION */

OFFSET(PT_TRAP, pt_regs, trap);
OFFSET(PT_U_ROOT_PTB, pt_regs, uaccess.u_root_ptb);
OFFSET(PT_CONT, pt_regs, uaccess.cont);
OFFSET(PT_CTPR1, pt_regs, ctpr1.lo);
OFFSET(PT_CTPR2, pt_regs, ctpr2.lo);
OFFSET(PT_CTPR3, pt_regs, ctpr3.lo);
OFFSET(PT_CTPR1_HI, pt_regs, ctpr1.hi);
OFFSET(PT_CTPR2_HI, pt_regs, ctpr2.hi);
OFFSET(PT_CTPR3_HI, pt_regs, ctpr3.hi);
OFFSET(PT_LSR, pt_regs, lsr);
OFFSET(PT_ILCR, pt_regs, ilcr);
OFFSET(PT_LSR1, pt_regs, lsr1);
OFFSET(PT_ILCR1, pt_regs, ilcr1);
OFFSET(PT_RNDPR, pt_regs, rndpr);
OFFSET(PT_STACK, pt_regs, stacks);
OFFSET(PT_SYS_NUM, pt_regs, sys_num);
OFFSET(PT_KERNEL_ENTRY, pt_regs, kernel_entry);
OFFSET(PT_ARG_5, pt_regs, dargs[4]);
OFFSET(PT_ARG_6, pt_regs, dargs[5]);
OFFSET(PT_ARG_7, pt_regs, dargs[6]);
OFFSET(PT_ARG_8, pt_regs, dargs[7]);
OFFSET(PT_ARG_9, pt_regs, dargs[8]);
OFFSET(PT_ARG_10, pt_regs, dargs[9]);
OFFSET(PT_ARG_11, pt_regs, dargs[10]);
OFFSET(PT_ARG_12, pt_regs, dargs[11]);

OFFSET(ST_USD_HI, e2k_stacks, usd.hi);
OFFSET(ST_USD_LO, e2k_stacks, usd.lo);
OFFSET(ST_TOP, e2k_stacks, top);

#ifdef	CONFIG_VIRTUALIZATION
OFFSET(PT_G_STACK, pt_regs, g_stacks);
OFFSET(G_ST_SBR, e2k_stacks, top);
#endif	/* CONFIG_VIRTUALIZATION */

DEFINE(COLORED_MEM_STORE_REC_OPC_BYPASS_L1, AW(ldst_rec_color_store(CACHE_BYPASS_L1)));
DEFINE(COLORED_MEM_LOAD_REC_OPC_BYPASS_L1, AW(ldst_rec_color_load(CACHE_BYPASS_L1)));
DEFINE(TAGGED_MEM_STORE_REC_OPC, AW(ldst_rec_tagged_store()));
DEFINE(TAGGED_MEM_LOAD_REC_OPC, AW(ldst_rec_tagged_load()));
DEFINE(TAGGED_MEM_LOAD_REC_OPC_BYPASS_L1, AW(ldst_rec_tagged_load_bypass(CACHE_BYPASS_L1)));
DEFINE(PTRACE_SZOF, sizeof(struct pt_regs));
DEFINE(TRAP_PTREGS_SZOF, sizeof(struct trap_pt_regs));
DEFINE(E2K_FLAG_32BIT, E2K_FLAG_32BIT);
DEFINE(CR0_IP_MASK, E2K_VA_MASK & ~7);
DEFINE(E2K_ALIGN_GLOBALS_SZ, E2K_ALIGN_GLOBALS_SZ);
DEFINE(E2K_ALIGN_PSTACK_MASK, E2K_ALIGN_PSTACK_MASK);
DEFINE(E2K_ALIGN_PCSTACK_MASK, E2K_ALIGN_PCSTACK_MASK);
DEFINE(E2K_ALIGN_STACKS_BASE_MASK, E2K_ALIGN_STACKS_BASE_MASK);
DEFINE(E2K_ALIGN_USTACK_SIZE, E2K_ALIGN_USTACK_SIZE);
DEFINE(E2K_BOOT_KERNEL_US_SIZE, E2K_BOOT_KERNEL_US_SIZE);
DEFINE(E2K_BOOT_KERNEL_PS_SIZE, E2K_BOOT_KERNEL_PS_SIZE);
DEFINE(E2K_BOOT_KERNEL_PCS_SIZE, E2K_BOOT_KERNEL_PCS_SIZE);
DEFINE(E2K_KERNEL_CONTEXT, E2K_KERNEL_CONTEXT);
DEFINE(E2K_KERNEL_IMAGE_AREA_BASE, E2K_KERNEL_IMAGE_AREA_BASE);
DEFINE(E2K_KERNEL_UPSR_LOC_IRQ_ENABLED, E2K_KERNEL_UPSR_LOC_IRQ_ENABLED.word);
DEFINE(E2K_KERNEL_UPSR_LOC_IRQ_DISABLED_ALL, E2K_KERNEL_UPSR_LOC_IRQ_DISABLED_ALL.word);
DEFINE(E2K_KERNEL_UPSR_GLOB_IRQ_ENABLED, E2K_KERNEL_UPSR_GLOB_IRQ_ENABLED.word);
DEFINE(E2K_KERNEL_UPSR_GLOB_IRQ_DISABLED_ALL, E2K_KERNEL_UPSR_GLOB_IRQ_DISABLED_ALL.word);
DEFINE(E2K_SYSCALL_TRAP_ENTRY_SIZE, E2K_SYSCALL_TRAP_ENTRY_SIZE);
DEFINE(E2K_LSR_VLC, E2K_LSR_VLC);
DEFINE(KERNEL_C_STACK_OFFSET, KERNEL_C_STACK_OFFSET);
DEFINE(KERNEL_C_STACK_SIZE, KERNEL_C_STACK_SIZE);
DEFINE(KVM_PV_VCPU_TRAP_ENTRY_NUM, KVM_PV_VCPU_TRAP_ENTRY_NUM);
DEFINE(L2_CACHE_BYTES, L2_CACHE_BYTES);
DEFINE(INTERNODE_CACHE_BYTES, INTERNODE_CACHE_BYTES);
DEFINE(CPU_HWBUG_USD_ALIGNMENT, CPU_HWBUG_USD_ALIGNMENT);
DEFINE(CPU_HWBUG_CR_BEFORE_WRITES, CPU_HWBUG_CR_BEFORE_WRITES);
DEFINE(CPU_HWBUG_CR_EVERY_WRITE, CPU_HWBUG_CR_EVERY_WRITE);
DEFINE(CPU_HWBUG_CR_FIRST_WRITE, CPU_HWBUG_CR_FIRST_WRITE);
DEFINE(CPU_HWBUG_HCALL_EXC_ILL_INSTR_ADDR, CPU_HWBUG_HCALL_EXC_ILL_INSTR_ADDR);
DEFINE(CPU_FEAT_ATOMIC_LDRD, CPU_FEAT_ATOMIC_LDRD);
DEFINE(CPU_FEAT_TRAP_V5, CPU_FEAT_TRAP_V5);
DEFINE(CPU_FEAT_TRAP_V6, CPU_FEAT_TRAP_V6);
DEFINE(CPU_FEAT_QPREG, CPU_FEAT_QPREG);
DEFINE(CPU_FEAT_SEP_VIRT_SPACE, CPU_FEAT_SEP_VIRT_SPACE);
DEFINE(CPU_FEAT_SVSC, CPU_FEAT_SVSC);
DEFINE(CPU_FEAT_ISET_V6, CPU_FEAT_ISET_V6);
DEFINE(CPU_FEAT_ISET_V7, CPU_FEAT_ISET_V7);
DEFINE(CPU_FEAT_GLOBAL_IRQ_MASK, CPU_FEAT_GLOBAL_IRQ_MASK);
DEFINE(OS_VAB_REG_ADDR, _MMU_REG_NO_TO_MMU_ADDR_VAL(_MMU_OS_VAB_NO));
DEFINE(PAGE_MASK, PAGE_MASK);
DEFINE(PAGE_SIZE, PAGE_SIZE);
DEFINE(E2K_MAX_PAGE_SIZE, E2K_MAX_PAGE_SIZE);
DEFINE(TASK_SIZE, TASK_SIZE);
DEFINE(THREAD_SIZE, THREAD_SIZE);
DEFINE(MAS_DAM_REG, MAS_DAM_REG);
DEFINE(MAS_IO_OPERATION, MAS_IO_OPERATION);
DEFINE(MAS_SPECULATIVE_BYPASS_L1, MAS_SPECULATIVE(CACHE_BYPASS_L1));
DEFINE(MAS_BYPASS_L1_CACHE, MAS_BYPASS_L1_CACHE);
DEFINE(__NR_exit, __NR_exit);
DEFINE(__NR_sigreturn, __NR_sigreturn);
DEFINE(__NR_setcontext, __NR_setcontext);
DEFINE(NR_syscalls, NR_syscalls);
DEFINE(NR_fast_syscalls_mask, NR_fast_syscalls_mask);
DEFINE(ROOT_PTB_REG_ADDR, _MMU_REG_NO_TO_MMU_ADDR_VAL(_MMU_U_PPTB_NO));
DEFINE(LDST_REC_QP_Q, AW(ldst_rec_qword()));
DEFINE(LDST_REC_D, AW(ldst_rec_dword()));
DEFINE(LDST_REC_W, AW(ldst_rec_word()));
DEFINE(TSK_TI_STACK_DELTA, offsetof(struct task_struct, stack) -
		offsetof(struct task_struct, thread_info));
#ifdef CONFIG_SMP
DEFINE(TSK_TI_CPU_DELTA, offsetof(struct task_struct, thread_info.cpu) -
	offsetof(struct task_struct, thread_info));
#endif

DEFINE(HB_PCI_BUS_NUM, HB_PCI_BUS_NUM);
DEFINE(HB_PCI_SLOT, HB_PCI_SLOT);
DEFINE(HB_PCI_FUNC, HB_PCI_FUNC);
DEFINE(HB_PCI_TOM, HB_PCI_TOM);
DEFINE(E1CP_PCICFG_AREA_PHYS_BASE, E1CP_PCICFG_AREA_PHYS_BASE);

#ifdef CONFIG_BPF_JIT
/* constants for cBPF templates */
OFFSET(SKB_LEN, sk_buff, len);
OFFSET(SKB_MARK, sk_buff, mark);
OFFSET(SKB_HASH, sk_buff, hash);
OFFSET(SKB_VLAN_TCI, sk_buff, vlan_tci);
OFFSET(SKB_QUEUE_MAPPING, sk_buff, queue_mapping);
OFFSET(SKB_PROTOCOL, sk_buff, protocol);
OFFSET(SKB_VLAN_PROTO, sk_buff, vlan_proto);
OFFSET(SKB_DEV, sk_buff, dev);
OFFSET(NETDEV_IFINDEX, net_device, ifindex);
OFFSET(NETDEV_TYPE, net_device, type);
DEFINE(PKT_TYPE_OFFSET, PKT_TYPE_OFFSET);
DEFINE(PKT_TYPE_MAX, PKT_TYPE_MAX);
DEFINE(PKT_VLAN_PRESENT_OFFSET, PKT_VLAN_PRESENT_OFFSET);
DEFINE(PKT_VLAN_PRESENT_BIT, BIT(PKT_VLAN_PRESENT_BIT));
/* constants for eBPF templates */
OFFSET(BPF_ARRAY_MAP, bpf_array, map);
OFFSET(BPF_ARRAY_PTRS, bpf_array, ptrs);
OFFSET(BPF_MAP_MAX_ENTRIES, bpf_map, max_entries);
OFFSET(BPF_PROG_BPF_FUNC, bpf_prog, bpf_func);
DEFINE(MAX_TAIL_CALL_CNT, MAX_TAIL_CALL_CNT);
DEFINE(SIZEOF_BPF_ARRAY_PTRS, sizeof(((struct bpf_array *) NULL)->ptrs[0]));
#endif

}
