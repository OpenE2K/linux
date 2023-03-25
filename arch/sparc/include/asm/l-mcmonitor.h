#ifndef	_SPARC_L_MCMONITOR_H_
#define	_SPARC_L_MCMONITOR_H_

#include <asm/io.h>

#define CC0_MC_ECC(node) (NODE_PFREG_AREA_BASE(node) | (1 << 25) | (0 << 8))
#define CC1_MC_ECC(node) (CC0_MC_ECC(node) | (1 << 26))

#define CC_MC_ERROR_COUNTER_SHIFT	32
#define CC_MC_ERROR_COUNTER_MASK	0xffffFFFF
#define CC_MC_ECC_SYN_SHIFT		12
#define CC_MC_ECC_SYN_MASK		0xff
#define CC_MC_ECC_CB_SHIFT		4
#define CC_MC_ECC_CB_MASK		0xff
#define CC_MC_EN_ECC_DMODE		(1 << 3)
#define CC_MC_EN_ECC_CINT		(1 << 2)
#define CC_MC_EN_ECC_CORR		(1 << 1)
#define CC_MC_EN_ECC_DET		(1 << 0)

typedef u64 l_mc_ecc_struct_t;

static inline u32 l_mc_get_error_cnt(l_mc_ecc_struct_t *ecc, int node,
				     int nr)
{
	u64 base = CC0_MC_ECC(node);
	if (nr)
		base = CC1_MC_ECC(node);
	*ecc = __raw_readq((void *)base);
	return *ecc >> CC_MC_ERROR_COUNTER_SHIFT;
}

static inline char *l_mc_get_error_str(l_mc_ecc_struct_t *ecc, int nr,
				       char *error_msg, int error_msg_len)
{
	snprintf(error_msg, error_msg_len,
		 "error counter: %u (CC_MC_ECC%d: %08llx)",
		(u32)(*ecc >> CC_MC_ERROR_COUNTER_SHIFT), nr, *ecc);
	return error_msg;
}

static inline bool l_mcmonitor_eec_enabled(void)
{
	u64 base = CC0_MC_ECC(0);
	u64 ecc = __raw_readq((void *)base);
	return (ecc & (CC_MC_EN_ECC_CORR | CC_MC_EN_ECC_CORR)) ==
			 (CC_MC_EN_ECC_CORR | CC_MC_EN_ECC_CORR);
}

#define l_mcmonitor_supported()	((e90s_get_cpu_type() == E90S_CPU_R2000) && \
			get_cpu_revision() > 0x11 /*Bug 107359*/)

#define SIC_MAX_MC_COUNT	2
#define SIC_MC_COUNT		SIC_MAX_MC_COUNT

/* CC handles 32 bytes at a time */
#define L_MC_ECC_WORDS_NR	4
#define L_MCMONITOR_TEST_SIZE (sizeof(l_good_data) * L_MC_ECC_WORDS_NR)
										
static const u64 l_good_data[] =
    { 0x51645e44ab98f0c9, 0x18ed950f0e82621f, 0x28a2a0a02fde054a,
0x8f597eec33ffb8ab, 0xeabad43b2da24553, 0x4d5bc4ff390179de, 0x7491662d7943d276,
0x1ae94cd46bf79bf3, 0xce17a4dcd95642db, 0xde21d28b154b9e48, 0x4bb2eac2723eda75,
0x04f25cde13c7964c, 0xeb63eb28a11747b4, 0x70a536ec16eca674, 0xbbb5e3dcab0054d9,
0xbfb86f11d2353c3b, 0x4c279041fc8ae329, 0x7bd9c3aa2cd41b5c, 0x4f09234d8a5290a2,
0x38f66a35fc4c7fdb, 0xd778dd1a0ff3e7e0, 0xf32d05401a82e1fa, 0x2817eb5785511580,
0xeb23563ddccf25df, 0xc127724c4a08eef5, 0x68d332bf14e49583, 0x046089a8b5e85fc9,
0x676433bdd0cc82d8, 0x4ea9d6422f75b83a, 0x9725c84b9b895d92, 0x7708451d0bb02872,
0xa08a665679547105, 0x31d5e812ce0fa38e, 0xa441944c6605dc6e, 0xe22fa272ae353c2b,
0x85e6833a211168ca, 0x00306aa862f1a9be, 0xf18743885c486792, 0xd7e2b28462e7886d,
0xfeb71e0bd9e6f2c1, 0x40dd36f387338753, 0x504526ac03f70700, 0x425191625d758895,
0x9f6f188abed4584f, 0x119440623aa8820b, 0xb0eb9f67d7dfdd33, 0x5d7dc9b790f8bcfb,
0xa623d31fad61ab4a, 0x0fdd5b441eac6264, 0xeac3ab5bdd599c59, 0xd57a3d69d16da623,
0x21333bad63220509, 0x43b415a94f05e5ad, 0x393c0ef347304b8e, 0x416ccb868b2ff6fc,
0xb0146df9b0e80803, 0x173e4ff32321237d, 0x95189d4247e070f2, 0xc466fc3aa5b651ff,
0x8716a93a5bb4b830, 0x68805a107190fda4, 0x7c3b6d80fef7a7cb, 0x25519a8c3836cdf9,
0x973828a29d19cd95, };

static u8 const l_good_ecc[] =
    { 0xe6, 0x91, 0xda, 0x20, 0x79, 0xa5, 0x65, 0xb2, 0xd4, 0x06, 0xec,
0xfd, 0x1a, 0xaf, 0xa5, 0x03, 0xff, 0x65, 0xba, 0x34, 0x3f, 0xfa, 0x4a, 0x76, 0x84,
0x57, 0xf0, 0x2c, 0x2c, 0xd6, 0x4d, 0xdc, 0xa2, 0x0d, 0x67, 0x88, 0xab, 0x0c, 0x18,
0x3a, 0x01, 0x21, 0x13, 0x37, 0xce, 0x86, 0x55, 0x10, 0x08, 0xb6, 0xc8, 0xbb, 0xab,
0x08, 0x2c, 0x2b, 0xd2, 0x99, 0xf8, 0xe4, 0x3b, 0x0f, 0x7a, 0xee, };

static inline void __l_mcmonitor_fill_data(u64 *a, const u64 *good,
				const u8 *ecc, int sz, bool make_error)
{
	void __iomem *mc_cfg = NULL + BASE_NODE0 + NBSR_MC_CONFIG;
	void __iomem *mc_ecc0 = (void *)CC0_MC_ECC(0);
	void __iomem *mc_ecc1 = (void *)CC1_MC_ECC(0);
	u64 v = __raw_readl(mc_cfg), ecc0, ecc1;
	bool interleaving = (v & (NBSR_MC_ENABLE_MC1 | NBSR_MC_ENABLE_MC0)) ==
			 (NBSR_MC_ENABLE_MC1 | NBSR_MC_ENABLE_MC0);
	u64 stride = (v >> NBSR_MC_INTERLEAVE_BIT_OFFSET) &
			 NBSR_MC_INTERLEAVE_BIT_MASK;
	int i, j;

	if (stride > NBSR_MC_INTERLEAVE_BIT_MAX)
		stride = NBSR_MC_INTERLEAVE_BIT_MAX;
	if (stride < NBSR_MC_INTERLEAVE_BIT_MIN)
		stride = NBSR_MC_INTERLEAVE_BIT_MIN;
	stride = 1 << stride;
	a = (void *)__pa(a);

	ecc0 = __raw_readq(mc_ecc0);
	ecc1 = __raw_readq(mc_ecc1);
	v = ecc0 & ~(CC_MC_EN_ECC_CORR | CC_MC_EN_ECC_DET);
	__raw_writeq(v, mc_ecc0);
	__raw_writeq(v, mc_ecc1);
	mb();
	for (i = 0; i < sz; i++, a += L_MC_ECC_WORDS_NR) {
		u8  e = ecc[i];
		u64 d = good[i];
		void __iomem *mc_ecc = interleaving && ((u64)a & stride) ?
				mc_ecc1 : mc_ecc0;
		__raw_writeq(v | (e << CC_MC_ECC_CB_SHIFT) |
			     CC_MC_EN_ECC_DMODE, mc_ecc);
		mb();
		if (make_error)
			d ^= (1UL << (i % 64));
		for (j = 0; j < L_MC_ECC_WORDS_NR; j++)
			__raw_writeq(d, a + j);
		mb();
	}
	__raw_writeq(ecc0, mc_ecc0);
	__raw_writeq(ecc1, mc_ecc1);
	mb();
}

static inline void l_mcmonitor_fill_data(u64 *a, bool make_error)
{
	__l_mcmonitor_fill_data(a, l_good_data, l_good_ecc,
			      ARRAY_SIZE(l_good_ecc), make_error);
}


static inline int __l_mcmonitor_cmp(u64 *a, const u64 *good, int sz)
{
	int i, j;
	for (i = 0; i < sz; i++, a += L_MC_ECC_WORDS_NR) {
		for (j = 0; j < L_MC_ECC_WORDS_NR; j++) {
			if (a[j] != good[i])
				return -EFAULT;
		}
	}
	return 0;
}

static inline int l_mcmonitor_cmp(u64 *a)
{
	return __l_mcmonitor_cmp(a, l_good_data, ARRAY_SIZE(l_good_data));
}
#endif				/* _SPARC_L_MCMONITOR_H_ */
