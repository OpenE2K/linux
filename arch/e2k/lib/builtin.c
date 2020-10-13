/*
 * $Id: builtin.c,v 1.9 2008/11/05 11:40:46 atic Exp $ Replacement of gcc __builtin_ ... macros
 */
#include <linux/sched.h>
#include <linux/thread_info.h>
#include <linux/types.h>
#include <linux/irqflags.h>
#include <asm/cpu_regs_access.h>
#include <asm/debug_print.h>
#include <asm/machdep.h>
#include <asm/system.h>
#include <asm/thread_info.h>


#define DEBUG_BLT	0
#define DebugBLT(...)		DebugPrint(DEBUG_BLT ,##__VA_ARGS__)

extern int printk(const char *fmt, ...);

/*
 * in Makefile -D__builtin_return_address=__e2k_kernel_return_address
 */
noinline notrace void * __e2k_read_kernel_return_address(int n)
{
	e2k_addr_t	ret = 0UL;
	e2k_cr0_hi_t	cr0_hi;
	e2k_pcsp_lo_t	pcsp_lo;
	e2k_pcsp_hi_t	pcsp_hi;
	u64		base;
	s64		cr_ind;
	u64		flags;

	raw_all_irq_save(flags);
	E2K_FLUSHC;

	AS_WORD(cr0_hi) = E2K_GET_DSREG_NV(cr0.hi);
	ret = AS_STRUCT(cr0_hi).ip << 3;

	pcsp_hi = READ_PCSP_HI_REG();
	pcsp_lo = READ_PCSP_LO_REG();

	cr_ind = AS_STRUCT(pcsp_hi).ind;
	base = AS_STRUCT(pcsp_lo).base;

	E2K_FLUSH_WAIT;

	DebugBLT("base 0x%lx\n", base);
	DebugBLT("ind 0x%lx\n", cr_ind);
	while (n >= 0) {
		e2k_mem_crs_t *frame;

		cr_ind -= SZ_OF_CR;

		if (cr_ind < 0) {
			ret = 0UL;
			break;
		}

		frame = (e2k_mem_crs_t *) (base + cr_ind);
		ret = AS_STRUCT(frame->cr0_hi).ip << 3;
		DebugBLT("ip 0x%lx\n", ret);

		--n;
	}

	raw_all_irq_restore(flags);

	return (void *) ret;
}
