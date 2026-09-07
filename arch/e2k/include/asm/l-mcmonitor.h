/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef	_E2K_L_MCMONITOR_H_
#define	_E2K_L_MCMONITOR_H_

#include <asm/io.h>
#include <asm/sic_regs.h>
#include <asm/sic_regs_access.h>

typedef e2k_mc_ecc_t l_mc_ecc_t;

static inline u32 l_mc_get_error_cnt(l_mc_ecc_t *ecc, int node, int nr)
{
	*ecc = sic_get_mc_ecc(node, nr);
	return ecc->secnt;
}

static inline char *l_mc_get_error_str(l_mc_ecc_t *ecc, int nr,
				       char *error_msg, int error_msg_len)
{
	snprintf(error_msg, error_msg_len,
		 "MC%d_ECC=0x%x (ee=%d dmode=%d of=%d ue=%d secnt=%d)",
		 nr, AWP(ecc), ecc->ee, ecc->dmode, ecc->of,
		 ecc->ue, ecc->secnt);
	return error_msg;
}

static inline bool l_mcmonitor_eec_enabled(void)
{
	l_mc_ecc_t ecc = sic_get_mc_ecc(0, 0);
	return ecc.ee;
}

/* Now we have edac driver, so we don't need l_mcmonitor */
#if 0
#define l_mcmonitor_supported()	HAS_MACHINE_L_SIC
#else
#define l_mcmonitor_supported()	false
#endif

/* CC handles 32 bytes at a time */
#define L_MC_ECC_WORDS_NR	4
#define L_MCMONITOR_TEST_SIZE (256 * L_MC_ECC_WORDS_NR)

static inline void l_mcmonitor_fill_data(u64 *a, bool make_error)
{
	int i, mc = SIC_MC_COUNT;
	int sz = L_MCMONITOR_TEST_SIZE / L_MC_ECC_WORDS_NR / sizeof(*a);
	e2k_mc_ecc_t mc_ecc[SIC_MAX_MC_COUNT];
	void __iomem *aa = (void __iomem __force *)__pa(a);

	for (i = 0; i < mc; i++)
		mc_ecc[i] = sic_get_mc_ecc(0, i);

	for (i = 0; i < mc; i++) {
		l_mc_ecc_t e = mc_ecc[i];
		e.dmode = 1;
		sic_set_mc_ecc(0, i, e);
	}
	mb();

	for (i = 0; i < sz; i++, aa += L_MC_ECC_WORDS_NR) {
		int j;
		u64 d = 0;
		for (j = 0; j < L_MC_ECC_WORDS_NR; j++) {
			u64 v = d;
			if (j == 0 && make_error)
				v |= (1UL << (i % 64));
			boot_writeq(v, aa + j);
		}
		mb();
	}

	for (i = 0; i < mc; i++)
		sic_set_mc_ecc(0, i, mc_ecc[i]);
	mb();
}

static inline int l_mcmonitor_cmp(u64 *a)
{
	int i;
	for (i = 0; i < L_MCMONITOR_TEST_SIZE / sizeof(*a); i++) {
		if (a[i] != 0)
			return -EFAULT;
	}
	return 0;
}
#endif /* _E2K_L_MCMONITOR_H_ */
