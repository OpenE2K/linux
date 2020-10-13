/*  
 * arch/e2k/kernel/sec_space.c
 *
 * Secondary space support for E2K binary compiler
 *
 */
#include <linux/kernel.h>
#include <linux/signal.h>
#include <linux/irqflags.h>

#include <asm/types.h>
#include <asm/cpu_regs_access.h>
#include <asm/regs_state.h>
#include <asm/secondary_space.h>
#include <asm/mmu_regs_access.h>
#include <asm/uaccess.h>

#undef	DEBUG_SS_MODE
#undef	DebugSS
#define	DEBUG_SS_MODE		0	/* Secondary Space Debug */
#define DebugSS(...)		DebugPrint(DEBUG_SS_MODE ,##__VA_ARGS__)

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
		DebugSS("GET_SECONDARY_SPACE_OFFSET: 0x%llx\n", SS_ADDR_START);
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
			E2K_SET_DSREG(cs.lo, I32_ADDR_TO_E2K(arg3));
			E2K_SET_DSREG(cs.hi, arg4);
			break;
		case DS_SELECTOR:
			E2K_SET_DSREG(ds.lo, I32_ADDR_TO_E2K(arg3));
			E2K_SET_DSREG(ds.hi, arg4);
			break;
		case ES_SELECTOR:
			E2K_SET_DSREG(es.lo, I32_ADDR_TO_E2K(arg3));
			E2K_SET_DSREG(es.hi, arg4);
			break;
		case SS_SELECTOR:
			E2K_SET_DSREG(ss.lo, I32_ADDR_TO_E2K(arg3));
			E2K_SET_DSREG(ss.hi, arg4);
			break;
		case FS_SELECTOR:
			E2K_SET_DSREG(fs.lo, I32_ADDR_TO_E2K(arg3));
			E2K_SET_DSREG(fs.hi, arg4);
			break;
		case GS_SELECTOR:
			E2K_SET_DSREG(gs.lo, I32_ADDR_TO_E2K(arg3));
			E2K_SET_DSREG(gs.hi, arg4);
			break;
		default:
			DebugSS("Invalid descriptor #%lld\n", arg2);
			res = -EINVAL;
		}
		break;
	case SET_SECONDARY_MTRR:
		/* arg2 - register # (0x10 - 0x30)
		 * arg3 - reg value
		 */
		DebugSS("SET_SECONDARY_MTRR: reg #%lld, rv = 0x%llx\n",
			arg2, arg3);
		set_MMU_MTRR_REG(arg2, arg3);
		res = 0;
		break;
	case GET_SECONDARY_MTRR:
		DebugSS("GET_SECONDARY_MTRR: reg #%lld\n", arg2);
		res = get_MMU_MTRR_REG(arg2);
		break;
	case TGKILL_INFO:
		DebugSS("TGKILL_INFO: pid = %ld, gid = %ld, info = 0x%lx\n",
			arg2, arg3, arg4);
		res = sys_tgkill_info(arg2, arg3,
				      (struct siginfo __user *) arg4);
		break;
	case SIG_EXIT_GROUP:
		arg2 = arg2 & 0xff7f;
		DebugSS("SIG_EXIT_GROUP: code = 0x%lx\n", arg2);
		do_group_exit(arg2);
		BUG();
		break;
	case SET_SYSCALL_RESTART_IGNORE:
		DebugSS("SET_SYSCALL_RESTART_IGNORE: 0x%lx\n", arg2);
		ti->sc_restart_ignore = arg2;
		res = 0;
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

