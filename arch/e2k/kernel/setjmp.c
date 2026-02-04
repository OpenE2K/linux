/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2024 MCST
 */

#include <asm/cpu_regs.h>
#include <asm/process.h>
#include <asm/setjmp.h>

/* Use __interrupt to make sure that parent's values of USD are read */
__interrupt noinline __attribute__((returns_twice))
int e2k_setjmp(struct jump_buf_e2k *jb)
{
	unsigned long flags;
	e2k_pcsp_t pcsp;
	e2k_psp_t psp;
	e2k_usd_t usd;
	e2k_sbr_t sbr;
	e2k_cr0_t cr0;
	e2k_cr1_t cr1;
	e2k_pshtp_t pshtp;
	e2k_pcshtp_t pcshtp;

	raw_all_irq_save(flags);

	pcsp = read_PCSP_reg();
	psp = read_PSP_reg();
	usd = read_USD_reg();
	sbr = read_SBR_reg();
	cr0 = read_CR0_reg();
	cr1 = read_CR1_reg();
	pshtp = read_PSHTP_reg();
	pcshtp = read_PCSHTP_reg();

	psp = incr_psp_ind(psp, PSHTP_MEM_INDEX(pshtp));
	pcsp = incr_pcsp_ind(pcsp, pcshtp.ind);

	jb->pcsp = pcsp;
	jb->psp = psp;
	jb->usd = usd;
	jb->sbr = sbr;
	jb->crs.cr0 = cr0;
	jb->crs.cr1 = cr1;

	raw_all_irq_restore(flags);

	return 0;
}
EXPORT_SYMBOL(e2k_setjmp);

/* Use __interrupt to make sure that %usd is written correctly */
__interrupt noinline
void e2k_longjmp(const struct jump_buf_e2k *jb, int value)
{
	unsigned long flags;
	e2k_pcsp_t pcsp = jb->pcsp;
	e2k_psp_t psp = jb->psp;
	e2k_usd_t usd = jb->usd;
	e2k_sbr_t sbr = jb->sbr;
	e2k_cr0_t cr0 = jb->crs.cr0;
	e2k_cr1_t cr1 = jb->crs.cr1;

	raw_all_irq_save(flags);
	/* Sanity check that source and destination are from same stack */
	BUG_ON(PCSP_BASE(pcsp) != PCSP_BASE(read_PCSP_reg()));

	E2K_FLUSHCPU;
	native_write_stacks_cr(psp, pcsp, usd, sbr, cr0, cr1);
	raw_all_irq_restore(flags);

	/* Return passed value from e2k_setjmp() */
	asm volatile ("{return %%ctpr3\n"
		      " adds %[value], 0, %%r0}\n"
		      "{ct %%ctpr3\n}\n"
		      :: [value] "ir" (value)
		      : "ctpr3", "memory");
}
EXPORT_SYMBOL(e2k_longjmp);

static int check_setjmp(void)
{
	struct jump_buf_e2k jb;

	switch (e2k_setjmp(&jb)) {
	case 0:
		e2k_longjmp(&jb, 1);
		BUG();
	case 1:
		break;
	default:
		BUG();
	}

	return 0;
}
arch_initcall(check_setjmp);
