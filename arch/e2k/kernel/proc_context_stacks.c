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
					void *ps_frames,
					e2k_mem_crs_t *cs_frames)
{
	e2k_mem_crs_t crs_trampoline, crs_user;
	unsigned long ts_flag;
	int ret, i;

	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
	TRY_USR_PFAULT {
		for (i = 0; i < args_size / 16; i++) {
			u64 reg1_offset;
#if DEBUG_CTX_STACK_MODE
			u64 val_lo, val_hi;
			u8 tag_lo, tag_hi;

			load_qvalue_and_tagq((e2k_addr_t)(args + 16 * i),
					&val_lo, &val_hi, &tag_lo, &tag_hi);
			DebugCTX_STACK("register arguments: 0x%llx 0x%llx\n",
					val_lo, val_hi);
#endif

			reg1_offset = (machine.native_iset_ver < E2K_ISET_V5) ?
				8 : 16;

			if (protected) {
				/* We have to check for SAP */
				u64 val_lo, val_hi;
				u8 tag_lo, tag_hi;
				e2k_sap_lo_t sap;
				e2k_ap_lo_t ap;

				load_qvalue_and_tagq(
					(e2k_addr_t)(args + 16 * i),
					&val_lo, &val_hi, &tag_lo, &tag_hi);
				if (((tag_hi << 4) | tag_lo) == ETAGAPQ &&
						((val_lo & AP_ITAG_MASK) >>
						 AP_ITAG_SHIFT) == SAP_ITAG) {
					/*
					 * SAP was passed, convert to AP
					 * for the new context since it has
					 * separate data stack.
					 */
					AW(sap) = val_lo;
					AW(ap) = 0;
					AS(ap).itag = AP_ITAG;
					AS(ap).rw = AS(sap).rw;
					AS(ap).base = AS(sap).base +
						((u64)current->stack &
						 0xFFFF00000000UL);
					val_lo = AW(ap);
					DebugCTX_STACK("\tfixed SAP: 0x%llx "
						"0x%llx\n", val_lo, val_hi);
				}
				recovery_faulted_tagged_store((e2k_addr_t)
						(ps_frames + EXT_4_NR_SZ * i),
						val_lo, tag_lo,
						TAGGED_MEM_STORE_REC_OPC,
						val_hi, tag_hi,
						TAGGED_MEM_STORE_REC_OPC |
						reg1_offset,
						1, 0, 0);
			} else {
				recovery_faulted_move((e2k_addr_t)
						(args + 16 * i), (e2k_addr_t)
						(ps_frames + EXT_4_NR_SZ * i),
						0, 1, TAGGED_MEM_STORE_REC_OPC,
						2, 0, 0, 1,
						(tc_cond_t) {.word = 0});
				recovery_faulted_move((e2k_addr_t)
						(args + 16 * i + 8),
						(e2k_addr_t)
						(ps_frames + EXT_4_NR_SZ * i +
						 reg1_offset),
						0, 1, TAGGED_MEM_STORE_REC_OPC,
						2, 0, 0, 1,
						(tc_cond_t) {.word = 0});
			}
		}

		if (2 * i < args_size / 8) {
#if DEBUG_CTX_STACK_MODE
			u64 val;
			u8 tag;

			recovery_faulted_load((e2k_addr_t) (args + 16 * i),
					&val, &tag, TAGGED_MEM_LOAD_REC_OPC,
					0, (tc_cond_t){.word = 0});
			DebugCTX_STACK("register arguments: 0x%llx\n", val);
#endif
			recovery_faulted_move((e2k_addr_t)
					(args + 16 * i), (e2k_addr_t)
					(ps_frames + EXT_4_NR_SZ * i),
					0, 1, TAGGED_MEM_STORE_REC_OPC,
					2, 0, 0, 1,
					(tc_cond_t) {.word = 0});
		}

	} CATCH_USR_PFAULT {
		clear_ts_flag(ts_flag);
		return -EFAULT;
	} END_USR_PFAULT
	clear_ts_flag(ts_flag);

	/*
	 * makecontext_trampoline()->do_longjmp() expects parameter area
	 * size (cr1_lo.wbs/cr1_lo.wpsz) according to the C ABI: 4 or 8.
	 */
	ret = chain_stack_frame_init(&crs_trampoline, protected ?
			makecontext_trampoline_protected :
				makecontext_trampoline,
			KERNEL_C_STACK_SIZE, E2K_KERNEL_PSR_DISABLED,
			protected ? 8 : 4, protected ? 8 : 4, false);
	ret = ret ?: chain_stack_frame_init(&crs_user, user_func,
			d_stack_sz, E2K_USER_INITIAL_PSR,
			protected ? 8 : 4, protected ? 8 : 4, true);
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
