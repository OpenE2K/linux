#include <linux/uaccess.h>

#include <asm/proc_context_stacks.h>
#include <asm/mmu_types.h>
#include <asm/thread_info.h>
#include <asm/uaccess.h>
#include <asm/e2k_ptypes.h>
#include <asm/debug_print.h>
#include <asm/cpu_regs_types.h>
#include <asm/mmu_fault.h>
#include <asm/hw_stacks.h>

#define	DEBUG_CTX_STACK_MODE	0	/* hw stacks for contexts */
#if DEBUG_CTX_STACK_MODE
#define	DebugCTX_STACK(...)	DebugPrint(DEBUG_CTX_STACK_MODE, ##__VA_ARGS__)
#else
#define DebugCTX_STACK(...)
#endif


int native_mkctxt_prepare_hw_user_stacks(void (*user_func)(void),
					void *args, u64 args_size,
					size_t d_stack_sz, bool protected,
					void __user *ps_frames,
					e2k_mem_crs_t __user *cs_frames)
{
	e2k_mem_crs_t crs_trampoline, crs_user;
	unsigned long ts_flag;
	int ret, i;

	for (i = 0; i < args_size / 16; i++) {
		u64 val_lo, val_hi;
		u8 tag_lo, tag_hi, tag;

		if (IS_ALIGNED((unsigned long) args, 16)) {
			load_qvalue_and_tagq((unsigned long) (args + 16 * i),
					&val_lo, &val_hi, &tag_lo, &tag_hi);
		} else {
			/* Can happen in 32 and 64 bit modes */
			load_value_and_tagd(args + 16 * i, &val_lo, &tag_lo);
			load_value_and_tagd(args + 16 * i + 8, &val_hi, &tag_hi);
		}
		tag = (tag_hi << 4) | tag_lo;
		DebugCTX_STACK("register arguments: 0x%llx 0x%llx\n",
				val_lo, val_hi);

		if (protected) {
			/* We have to check for SAP */
			if (tag == ETAGAPQ && ((val_lo & AP_ITAG_MASK) >>
						AP_ITAG_SHIFT) == SAP_ITAG) {
				e2k_sap_lo_t sap;
				e2k_ap_lo_t ap;

				/* SAP was passed, convert to AP
				 * for the new context since it has
				 * separate data stack. */
				AW(sap) = val_lo;
				AW(ap) = 0;
				AS(ap).itag = AP_ITAG;
				AS(ap).rw = AS(sap).rw;
				AS(ap).base = AS(sap).base +
					((u64) current->stack & 0xFFFF00000000UL);
				val_lo = AW(ap);
				DebugCTX_STACK("\tfixed SAP: 0x%llx 0x%llx\n", val_lo, val_hi);
			}
		}

		ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
		ret = __put_user_tagged_16_offset(val_lo, val_hi, tag,
				ps_frames + EXT_4_NR_SZ * i, machine.qnr1_offset);
		clear_ts_flag(ts_flag);
		if (ret)
			return -EFAULT;
	}

	if (2 * i < args_size / 8) {
		u64 val;
		u8 tag;

		load_value_and_tagd(args + 16 * i, &val, &tag);

		ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
		ret = __put_user_tagged_8(val, tag,
				(u64 __user *) (ps_frames + EXT_4_NR_SZ * i));
		clear_ts_flag(ts_flag);
		if (ret)
			return -EFAULT;
		DebugCTX_STACK("register arguments: 0x%llx\n", val);
	}

	/*
	 * makecontext_trampoline()->do_longjmp() expects parameter area
	 * size (cr1_lo.wbs/cr1_lo.wpsz) according to the C ABI: 4 or 8.
	 */
	ret = chain_stack_frame_init(&crs_trampoline, protected ?
			makecontext_trampoline_protected :
				makecontext_trampoline,
			KERNEL_C_STACK_SIZE, E2K_KERNEL_PSR_DISABLED,
			C_ABI_PSIZE(protected), C_ABI_PSIZE(protected), false);
	ret = ret ?: chain_stack_frame_init(&crs_user, user_func,
			d_stack_sz, E2K_USER_INITIAL_PSR,
			C_ABI_PSIZE(protected), C_ABI_PSIZE(protected), true);
	if (ret)
		return ret;

	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
	ret = __clear_user(&cs_frames[1], SZ_OF_CR);
	ret = ret ?: __copy_to_user(&cs_frames[2], &crs_trampoline, SZ_OF_CR);
	ret = ret ?: __copy_to_user(&cs_frames[3], &crs_user, SZ_OF_CR);
	clear_ts_flag(ts_flag);
	if (ret)
		return -EFAULT;

	return 0;
}
