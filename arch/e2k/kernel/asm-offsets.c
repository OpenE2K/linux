/*
 * Generate definitions needed by assembly language modules.
 * This code generates raw asm output which is post-processed to extract
 * and format the required data.
 */

#define ASM_OFFSETS_C 1

#include <linux/types.h>
#include <linux/list.h>
#include <linux/ptrace.h>
#include <linux/kbuild.h>
#include <asm/boot_head.h>

OFFSET(TI_CPU, thread_info, cpu);
OFFSET(TI_FLAGS, thread_info, flags);
OFFSET(TI_K_STK_BASE, thread_info, k_stk_base);
OFFSET(TI_U_STK_BASE, thread_info, u_stk_base);
OFFSET(TI_U_STK_TOP, thread_info, u_stk_top);
OFFSET(TI_K_STK_SZ, thread_info, k_stk_sz);
OFFSET(TI_K_USD_LO, thread_info, k_usd_lo);
OFFSET(TI_K_USD_HI, thread_info, k_usd_hi);
OFFSET(TI_UPSR, thread_info, upsr);
OFFSET(TI_G16, thread_info, gbase[0]);
OFFSET(TI_G17, thread_info, gbase[1]);
OFFSET(TI_G18, thread_info, gbase[2]);
OFFSET(TI_G19, thread_info, gbase[3]);
OFFSET(TI_G16_EXT, thread_info, gext[0]);
OFFSET(TI_G17_EXT, thread_info, gext[1]);
OFFSET(TI_G18_EXT, thread_info, gext[2]);
OFFSET(TI_G19_EXT, thread_info, gext[3]);
OFFSET(TI_G16_TAG, thread_info, tag[0]);
OFFSET(TI_G17_TAG, thread_info, tag[1]);
OFFSET(TI_G18_TAG, thread_info, tag[2]);
OFFSET(TI_G19_TAG, thread_info, tag[3]);
OFFSET(TI_TASK, thread_info, task);
OFFSET(TI_U_USD_HI, thread_info, u_usd_hi);
OFFSET(TI_U_USD_LO, thread_info, u_usd_lo);
#ifdef CONFIG_MCST
OFFSET(TI_IRQ_ENTER_CLK, thread_info, irq_enter_clk);
#endif
#ifdef CONFIG_FUNCTION_GRAPH_TRACER
OFFSET(TSK_CURR_RET_STACK, task_struct, curr_ret_stack);
#endif
OFFSET(TSK_PTRACE, task_struct, ptrace);
OFFSET(TSK_THREAD, task_struct, thread);
OFFSET(TSK_THREAD_INFO, task_struct, stack);
OFFSET(TSK_FLAGS, task_struct, flags);
OFFSET(TSK_THREAD_FLAGS, task_struct, thread.flags);
OFFSET(TT_FLAGS, thread_struct, flags);
#ifdef	CONFIG_CLW_ENABLE
OFFSET(PT_US_CL_M0, pt_regs, us_cl_m[0]);
OFFSET(PT_US_CL_M1, pt_regs, us_cl_m[1]);
OFFSET(PT_US_CL_M2, pt_regs, us_cl_m[2]);
OFFSET(PT_US_CL_M3, pt_regs, us_cl_m[3]);
OFFSET(PT_US_CL_UP, pt_regs, us_cl_up);
OFFSET(PT_US_CL_B, pt_regs, us_cl_b);
#endif
OFFSET(TI_PT_REGS, thread_info, pt_regs);
OFFSET(PT_TRAP, pt_regs, trap);
OFFSET(PT_CTRP1, pt_regs, ctpr1);
OFFSET(PT_CTRP2, pt_regs, ctpr2);
OFFSET(PT_CTRP3, pt_regs, ctpr3);
OFFSET(PT_LSR, pt_regs, lsr);
OFFSET(PT_ILCR, pt_regs, ilcr);
OFFSET(PT_STACK, pt_regs, stacks);
OFFSET(PT_SYS_NUM, pt_regs, sys_num);
#ifdef CONFIG_E2S_CPU_RF_BUG
OFFSET(PT_G16, pt_regs, e2s_gbase[0]);
OFFSET(PT_G17, pt_regs, e2s_gbase[1]);
OFFSET(PT_G18, pt_regs, e2s_gbase[2]);
OFFSET(PT_G19, pt_regs, e2s_gbase[3]);
OFFSET(PT_G20, pt_regs, e2s_gbase[4]);
OFFSET(PT_G21, pt_regs, e2s_gbase[5]);
OFFSET(PT_G22, pt_regs, e2s_gbase[6]);
OFFSET(PT_G23, pt_regs, e2s_gbase[7]);
#endif

OFFSET(ST_USD_HI, e2k_stacks, usd_hi);
OFFSET(ST_USD_LO, e2k_stacks, usd_lo);
OFFSET(ST_SBR, e2k_stacks, sbr);
OFFSET(PT_NEXT, pt_regs, next);
BLANK();

DEFINE(TASK_SIZE, TASK_SIZE);
DEFINE(PTRACE_SZOF, sizeof (struct pt_regs));
DEFINE(TRAP_PTREGS_SZOF, sizeof(struct trap_pt_regs));
#ifdef CONFIG_USE_AAU
DEFINE(AAU_SZOF, sizeof(e2k_aau_t));
#endif
DEFINE(PT_PTRACED, PT_PTRACED);
DEFINE(E2K_FLAG_32BIT, E2K_FLAG_32BIT);
DEFINE(NR_CPUS, NR_CPUS);
DEFINE(E2K_KERNEL_UPSR_ENABLED, E2K_KERNEL_UPSR_ENABLED_ASM);
DEFINE(E2K_KERNEL_UPSR_DISABLED_ALL, E2K_KERNEL_UPSR_DISABLED_ALL_ASM);
DEFINE(E2K_KERNEL_PSR_ENABLED, E2K_KERNEL_PSR_ENABLED_ASM);
DEFINE(E2K_LSR_VLC, E2K_LSR_VLC);

#ifdef	CONFIG_KERNEL_CODE_CONTEXT
DEFINE(KERNEL_CUT_BYTE_SIZE, sizeof (kernel_CUT));
#endif	/* CONFIG_KERNEL_CODE_CONTEXT */

