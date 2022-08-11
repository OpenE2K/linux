/*  
 * arch/e2k/kernel/sec_space.c
 *
 * Secondary space support for E2K binary compiler
 *
 */
#include <linux/kernel.h>
#include <linux/signal.h>
#include <linux/irqflags.h>
#include <linux/sched/task.h>

#include <asm/types.h>
#include <asm/cpu_regs_access.h>
#include <asm/regs_state.h>
#include <asm/secondary_space.h>
#include <asm/mmu_regs_access.h>
#include <linux/uaccess.h>
#include <asm/cacheflush.h>

#undef	DEBUG_SS_MODE
#undef	DebugSS
#define	DEBUG_SS_MODE		0	/* Secondary Space Debug */
#define DebugSS(...)		DebugPrint(DEBUG_SS_MODE ,##__VA_ARGS__)

void set_upt_sec_ad_shift_dsbl(void *arg)
{
	unsigned long flags;
	e2k_cu_hw0_t cu_hw0;

	raw_all_irq_save(flags);
	cu_hw0 = READ_CU_HW0_REG();
	cu_hw0.upt_sec_ad_shift_dsbl = (arg) ? 1 : 0;
	WRITE_CU_HW0_REG(cu_hw0);
	raw_all_irq_restore(flags);
}

s64 sys_el_binary(s64 work, s64 arg2, s64 arg3, s64 arg4)
{
	s64		res = -EINVAL;
	thread_info_t   *ti = current_thread_info();

	if (!TASK_IS_BINCO(current)) {
		pr_info("Task %d is not binary compiler\n", current->pid);
		return res;
	}

	switch (work) {
	case GET_SECONDARY_SPACE_OFFSET:
		DebugSS("GET_SECONDARY_SPACE_OFFSET: 0x%lx\n", SS_ADDR_START);
		res = SS_ADDR_START;
		break;
	case SET_SECONDARY_REMAP_BOUND:
		DebugSS("SET_SECONDARY_REMAP_BOUND: bottom = 0x%llx\n", arg2);
		ti->ss_rmp_bottom = arg2 + SS_ADDR_START;
		res = 0;
		break;
	case SET_SECONDARY_DESCRIPTOR:
		/* arg2 - descriptor # ( 0-CS, 1-DS, 2-ES, 3-SS, 4-FS, 5-GS )
		 * arg3 - desc.lo
		 * arg4 - desc.hi
		 */
		DebugSS("SET_SECONDARY_DESCRIPTOR: desc #%lld, desc.lo = "
			"0x%llx, desc.hi = 0x%llx\n",
			arg2, arg3, arg4);
		res = 0;
		switch (arg2) {
		case CS_SELECTOR:
			WRITE_CS_LO_REG_VALUE(I32_ADDR_TO_E2K(arg3));
			WRITE_CS_HI_REG_VALUE(arg4);
			break;
		case DS_SELECTOR:
			WRITE_DS_LO_REG_VALUE(I32_ADDR_TO_E2K(arg3));
			WRITE_DS_HI_REG_VALUE(arg4);
			break;
		case ES_SELECTOR:
			WRITE_ES_LO_REG_VALUE(I32_ADDR_TO_E2K(arg3));
			WRITE_ES_HI_REG_VALUE(arg4);
			break;
		case SS_SELECTOR:
			WRITE_SS_LO_REG_VALUE(I32_ADDR_TO_E2K(arg3));
			WRITE_SS_HI_REG_VALUE(arg4);
			break;
		case FS_SELECTOR:
			WRITE_FS_LO_REG_VALUE(I32_ADDR_TO_E2K(arg3));
			WRITE_FS_HI_REG_VALUE(arg4);
			break;
		case GS_SELECTOR:
			WRITE_GS_LO_REG_VALUE(I32_ADDR_TO_E2K(arg3));
			WRITE_GS_HI_REG_VALUE(arg4);
			break;
		default:
			DebugSS("Invalid descriptor #%lld\n", arg2);
			res = -EINVAL;
		}
		break;
	case GET_SNXE_USAGE:
		DebugSS("GET_SNXE_USAGE\n");
		res = (machine.native_iset_ver >= E2K_ISET_V5) ? 1 : 0;
		break;
	case SIG_EXIT_GROUP:
		arg2 = arg2 & 0xff7f;
		DebugSS("SIG_EXIT_GROUP: code = 0x%llx\n", arg2);
		do_group_exit(arg2);
		BUG();
		break;
	case SET_RP_BOUNDS_AND_IP:
		DebugSS("SET_RP_BOUNDS_AND_IP: start=0x%llx, end=0x%llx, "
			"IP=0x%llx\n",
			arg2, arg3, arg4);
		ti->rp_start = arg2;
		ti->rp_end = arg3;
		ti->rp_ret_ip = arg4;
		res = 0;
		break;
	case SET_SECONDARY_64BIT_MODE:
		if (arg2 == 1) {
			current->thread.flags |= E2K_FLAG_64BIT_BINCO;
			res = 0;
		}
		break;
	case GET_PROTOCOL_VERSION:
		DebugSS("GET_PROTOCOL_VERSION: %d\n",
			BINCO_PROTOCOL_VERSION);
		res = BINCO_PROTOCOL_VERSION;
		break;
	case SET_IC_NEED_FLUSH_ON_SWITCH:
		DebugSS("SET_IC_NEED_FLUSH_ON_SWITCH: set = %lld\n", arg2);
		if (arg2)
			ti->last_ic_flush_cpu = smp_processor_id();
		else
			ti->last_ic_flush_cpu = -1;
		res = 0;
		break;
	case SET_UPT_SEC_AD_SHIFT_DSBL:
		DebugSS("SET_UPT_AEC_AD_SHIFT_DSBL: set = %lld\n", arg2);
		res = -EPERM;
		if (machine.native_iset_ver >= E2K_ISET_V6) {
			on_each_cpu(set_upt_sec_ad_shift_dsbl, (void *)arg2, 1);
			res = 0;
		}
		break;
	case GET_UPT_SEC_AD_SHIFT_DSBL:
		DebugSS("SET_UPT_AEC_AD_SHIFT_DSBL\n");
		res = -EPERM;
		if (machine.native_iset_ver >= E2K_ISET_V6) {
			e2k_cu_hw0_t cu_hw0 = READ_CU_HW0_REG();
			res = cu_hw0.upt_sec_ad_shift_dsbl;
		}
		break;
	default:
		DebugSS("Invalid work: #%lld\n", work);
		break;
	}

	return res;
}

static __init int check_ss_addr(void)
{
	WARN(SS_ADDR_END > USER_HW_STACKS_BASE,
	     "Secondary space crosses hardware stacks area!\n");

	return 0;
}
late_initcall(check_ss_addr);

