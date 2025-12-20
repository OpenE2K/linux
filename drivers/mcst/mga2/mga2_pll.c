/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include "mga2_drv.h"


#define DIV_ROUND_DOWN(n,d) ((n) / (d))

#define DIV_2(x)(					\
{	/* Round half to even */						\
	typeof(x) __x = x / 2;				\
	typeof(x) __d = x % 2;				\
	 __d ?	__x % 2 ? __x + 1 : __x			\
	 : __x;						\
}							\
)

static int
_mga2_calc_int_pll(struct mga2_clk *res, const unsigned long long fout,
		  unsigned long long *rfvco, unsigned long long *rerr)
{
	const unsigned long long vco_min = 6.8e+08;
	const unsigned long long vco_max = 3.4e+09;
	const unsigned long long ref_min = 415039;
	const unsigned long long ref_max = 3.4e+09;
	const int nr_min = 1;
	/* const int nr_max = 64; */
	const int nr_max = 5 /* e1c+ does not like more then that */;
	const int nf_min = 1;
	const int nf_max = 4096;
	const int no_min = 1;
	const int no_max = 16;
	const int no_even = 1;
	const int nb_min = 1;
	const int nb_max = 4096;
	const int max_vco = 1;
	const int ref_rng = 1;
	const unsigned long long fin = 100 * 1000 * 1000;
	int nr, nrx, nf, nfi, no, noe, not, nor, nore, nb, first, firstx,
	    found;
	long long nfx;
	unsigned long long fvco;
	long long val, nval, err, merr = 0, terr, x_err = 0;
	int x_nrx = 0, x_no = 0, x_nb = 0;
	long long x_nfx = 0;
	unsigned long long x_fvco = 0;

	terr = 0; /* minimize nr & err */
	terr = -2; /* minimize err */
	first = firstx = 1;
	val = fout / fin;
	found = 0;
	for (nfi = fout / fin; nfi < nf_max; ++nfi) {
		nr = DIV_ROUND_CLOSEST(nfi * fin, fout);
		if (nr == 0)
			continue;
		if ((ref_rng) && (nr < nr_min))
			continue;
		if (DIV_ROUND_UP(fin, nr) > ref_max)
			continue;
		nrx = nr;
		nf = nfx = nfi;
		nval = DIV_ROUND_CLOSEST(nfx * fin, nr);
		if (nf == 0)
			nf = 1;
		err = abs(fout - nval);

		if (first || err <= merr || err == 0) {
			not = DIV_ROUND_DOWN(vco_max, fout);
			for (no = (not > no_max) ? no_max : not;
			     no > no_min; --no) {
				if ((no_even) && (no & 1) && (no > 1)) {
					continue;
				}
				if ((ref_rng) && ((nr / no) < nr_min))
					continue;
				if ((nr % no) == 0)
					break;
			}
			if ((nr % no) != 0)
				continue;
			nor = ((not > no_max) ? no_max : not) / no;
			nore = nf_max / nf;
			if (nor > nore)
				nor = nore;
			if ((no_even) && (no & 1) && (no > 1) && (nor & 1)
			    && (nor > 1))
				--nor;
			noe = DIV_ROUND_UP(vco_min, fout);
			if (!max_vco) {
				nore = (noe - 1) / no + 1;
				if ((no_even) && (no & 1) && (no > 1)
				    && (nore & 1)
				    && (nor > nore))
					++nore;
				nor = nore;
				not = 0;	/* force next if to fail */
			}
			if ((((no * nor) < (not >> 1))
			     || ((no * nor) < noe))
			    && ((no * nor) < (nf_max / nf))) {
				no = nf_max / nf;
				if (no > no_max)
					no = no_max;
				if (no > not)
					no = not;
				if ((no_even) && (no & 1) && (no > 1))
					--no;
				nfx *= no;
				nf *= no;
				if ((no > 1) && (!firstx))
					continue;
				/* wait for larger nf in later iterations */
			} else {
				nrx /= no;
				nfx *= nor;
				nf *= nor;
				no *= nor;
				if (no > no_max)
					continue;
				if ((no_even) && (no & 1) && (no > 1))
					continue;
				if ((nor > 1) && (!firstx))
					continue;
				/* wait for larger nf in later iterations */
			}

			nb = DIV_2(nfx);
			if (nb < nb_min)
				nb = nb_min;
			if (nb > nb_max)
				continue;

			fvco = DIV_ROUND_CLOSEST(fin * nfx, nrx);
			if (fvco < vco_min)
				continue;
			if (fvco > vco_max)
				continue;
			if (nf < nf_min)
				continue;
			if (ref_rng && DIV_ROUND_DOWN(fin, nrx) < ref_min)
				continue;
			if ((ref_rng) && (nrx > nr_max))
				continue;
			if (!
			    (firstx || err < merr
			     || (max_vco && no > x_no)))
				continue;
			if ((!firstx) && (terr >= 0) && (nrx > x_nrx))
				continue;

			found = 1;
			x_no = no;
			x_nrx = nrx;
			x_nfx = nfx;
			x_nb = nb;
			x_fvco = fvco;
			x_err = err;
			first = firstx = 0;
			merr = err;
		}
	}

	res->nr = x_nrx;
	res->nf = x_nfx;
	res->od = x_no;
	res->nb = x_nb;

	nrx = x_nrx;
	nfx = x_nfx;
	no = x_no;
	nb = x_nb;
	fvco = x_fvco;
	err = x_err;

	*rfvco = fvco;
	*rerr = err;
	return !found;
}

int mga2_calc_int_pll(struct mga2_clk *res, const unsigned long long fout,
	unsigned long long *fvco, unsigned long long *err)
{
	const unsigned long long vco_min = 6.8e+08;
	const unsigned long long vco_max = 3.4e+09;
	const int no_min = 1;
	const int no_max = 16;
	if (fout * no_min > vco_max)
		return -EINVAL;

	if (fout * no_max < vco_min)
		return -EINVAL;

	return _mga2_calc_int_pll(res, fout, fvco, err);
}

static int
_mga25_calc_int_pll(struct mga2_clk *res, const unsigned long long fout,
		  unsigned long long *rfvco, unsigned long long *rerr)
{
	const unsigned long long vco_min = 1.5e+07;
	/*const unsigned long long vco_max = 3.25e+09; bug 130125:*/
	const unsigned long long vco_max = 3.0e+09; /*PLL losing lock*/
	const unsigned long long ref_min = 10000;
	const unsigned long long ref_max = 8.12e+08;
	const int nr_min = 1;
	/* const int nr_max = 4096; */
	const int nr_max = 5 /* e1c+ does not like more then that */;
	const int nf_min = 1;
	const int nf_max = 262144;
	/*const int nf_fbits = 33;*/
	const int no_min = 1;
	const int no_max = 2048;
	const int no_even = 0;
	const int max_vco = 1;
	const int ref_rng = 1;
	const unsigned long long fin = 100 * 1000 * 1000;
	int nr, nrx, nf, nfi, no, noe, not, nor, nore, first, firstx,
	    found;
	long long nfx;
	unsigned long long fvco;
	long long val, nval, err, merr = 0, terr, x_err = 0;
	int x_nrx = 0, x_no = 0;
	long long x_nfx = 0;
	unsigned long long x_fvco = 0;

	terr = 0; /* minimize nr & err */
	terr = -2; /* minimize err */
	first = firstx = 1;
	val = fout / fin;
	found = 0;
	for (nfi = fout / fin; nfi < nf_max; ++nfi) {
		nr = DIV_ROUND_CLOSEST(nfi * fin, fout);
		if (nr == 0)
			continue;
		if ((ref_rng) && (nr < nr_min))
			continue;
		if (DIV_ROUND_UP(fin, nr) > ref_max)
			continue;
		nrx = nr;
		nf = nfx = nfi;
		nval = DIV_ROUND_CLOSEST(nfx * fin, nr);
		if (nf == 0)
			nf = 1;
		err = abs(fout - nval);

		if (first || err <= merr || err == 0) {
			not = DIV_ROUND_DOWN(vco_max, fout);
			for (no = (not > no_max) ? no_max : not;
			     no > no_min; --no) {
				if ((no_even) && (no & 1) && (no > 1)) {
					continue;
				}
				if ((ref_rng) && ((nr / no) < nr_min))
					continue;
				if ((nr % no) == 0)
					break;
			}
			if ((nr % no) != 0)
				continue;
			nor = ((not > no_max) ? no_max : not) / no;
			nore = nf_max / nf;
			if (nor > nore)
				nor = nore;
			if ((no_even) && (no & 1) && (no > 1) && (nor & 1)
			    && (nor > 1))
				--nor;
			noe = DIV_ROUND_UP(vco_min, fout);
			if (!max_vco) {
				nore = (noe - 1) / no + 1;
				if ((no_even) && (no & 1) && (no > 1)
				    && (nore & 1)
				    && (nor > nore))
					++nore;
				nor = nore;
				not = 0;	/* force next if to fail */
			}
			if ((((no * nor) < (not >> 1))
			     || ((no * nor) < noe))
			    && ((no * nor) < (nf_max / nf))) {
				no = nf_max / nf;
				if (no > no_max)
					no = no_max;
				if (no > not)
					no = not;
				if ((no_even) && (no & 1) && (no > 1))
					--no;
				nfx *= no;
				nf *= no;
				if ((no > 1) && (!firstx))
					continue;
				/* wait for larger nf in later iterations */
			} else {
				nrx /= no;
				nfx *= nor;
				nf *= nor;
				no *= nor;
				if (no > no_max)
					continue;
				if ((no_even) && (no & 1) && (no > 1))
					continue;
				if ((nor > 1) && (!firstx))
					continue;
				/* wait for larger nf in later iterations */
			}

			fvco = DIV_ROUND_CLOSEST(fin * nfx, nrx);
			if (fvco < vco_min)
				continue;
			if (fvco > vco_max)
				continue;
			if (nf < nf_min)
				continue;
			if (ref_rng && DIV_ROUND_DOWN(fin, nrx) < ref_min)
				continue;
			if ((ref_rng) && (nrx > nr_max))
				continue;
			if (!
			    ((firstx && (terr < 0)) || err < merr
			     || (max_vco && no > x_no)))
				continue;
			if ((!firstx) && (terr >= 0) && (nrx > x_nrx))
				continue;

			found = 1;
			x_no = no;
			x_nrx = nrx;
			x_nfx = nfx;
			x_fvco = fvco;
			x_err = err;
			first = firstx = 0;
			merr = err;
		}
	}

	res->nr = x_nrx;
	res->nf_i = x_nfx;
	res->nf_f = 0;
	res->od = x_no;

	nrx = x_nrx;
	nfx = x_nfx;
	no = x_no;
	fvco = x_fvco;
	err = x_err;

	*rfvco = fvco;
	*rerr = err;
	return !found;
}

int mga25_calc_int_pll(struct mga2_clk *res, const unsigned long long fout,
	unsigned long long *fvco, unsigned long long *err)
{
	const unsigned long long vco_min = 1.5e+07;
	/*const unsigned long long vco_max = 3.25e+09;*/
	const unsigned long long vco_max = 3.0e+09; /*bug 130125*/
	const int no_min = 1;
	const int no_max = 2048;
	if (fout * no_min > vco_max)
		return -EINVAL;

	if (fout * no_max < vco_min)
		return -EINVAL;

	return _mga25_calc_int_pll(res, fout, fvco, err);
}

/*
 *******************************************************************************
 * RAMDAC
 *******************************************************************************
 */
#define I2C_RAMDAC_ADDR 0x69

#define FS_REF		0x0	/* Reference clock [000] */
#define FS_PLL1_0	0x2	/* PLL1 0* Phase   */
#define FS_PLL1_180	0x3	/* PLL1 180* Phase */
#define FS_PLL2_0	0x4	/* PLL2 0* Phase   */
#define FS_PLL2_180	0x5	/* PLL2 180* Phase */
#define FS_PLL3_0	0x6	/* PLL3 0* Phase   */
#define FS_PLL3_180	0x7	/* PLL3 180* Phase */

/* The reciprocal of the reference oscillator (14.3181 Mhz) in picoseconds */
#define PIXCLOCK_EXT 69841

/*******************************************************************************
 * TMDS
 *******************************************************************************
 */
#define I2C_TMDS_ADDR	0x38

#define TMDS_0x00_RVAL	0x01	/* VND_IDL */
#define TMDS_0x01_RVAL	0x00	/* VND_IDH */
#define TMDS_0x02_RVAL	0x06	/* DEV_IDL */
#define TMDS_0x03_RVAL	0x00	/* DEV_IDH */
#define TMDS_0x04_RVAL	0x00	/* DEV_REV */
#define TMDS_0x08_WVAL	\
	((1<<5/*VEN*/) |\
	 (1<<4/*HEN*/) |\
	 (0<<3/*DSEL*/)|\
	 (1<<2/*BSEL*/)|\
	 (1<<1/*EDGE*/)|\
	 (0<<0/*nPD*/))
#define TMDS_0x09_WVAL	((0x2<<4/*MSEL[2:0]*/)|(0<<3/*TSEL*/)|(0<<0/*MDI*/))
#define TMDS_0x0A_WVAL	0x90	/* Default */
#define TMDS_0x0C_WVAL	0x89	/* Default */

typedef struct {
	int div;		/* [6:0] Linear output divider */

	int q;			/* [7:0] PPL*_Q */
	int p;			/* [9:0] PPL*_P */
	int po;			/* [0:0] PPL_PO */

	int pixclock;
} clk_t;


#define ramdac_read(__i2c, __addr)	mga2_i2c_rd(__i2c, I2C_RAMDAC_ADDR, __addr)
#define ramdac_write(__i2c, __addr, __val)	mga2_i2c_wr(__i2c, I2C_RAMDAC_ADDR, __addr, __val)

static u8 mga2_i2c_rd(struct i2c_adapter *adapter, u8 slave_addr, u8 addr)
{
	u8 val = 0;
	u8 out_buf[2];
	u8 in_buf[2];
	struct i2c_msg msgs[] = {
		{
		 .addr = slave_addr,
		 .flags = 0,
		 .len = 1,
		 .buf = out_buf,
		 },
		{
		 .addr = slave_addr,
		 .flags = I2C_M_RD,
		 .len = 1,
		 .buf = in_buf,
		 }
	};

	out_buf[0] = addr;
	out_buf[1] = 0;

	if (i2c_transfer(adapter, msgs, 2) == 2) {
		val = in_buf[0];
		DRM_DEBUG("%s: rd: 0x%02x: 0x%02x\n",
			  adapter->name, addr, val);
	} else {
		DRM_DEBUG("i2c 0x%02x 0x%02x read failed\n", addr, val);
	}
	return val;
}

static void
mga2_i2c_wr(struct i2c_adapter *adapter, u8 slave_addr, u8 addr, u8 val)
{
	uint8_t out_buf[2];
	struct i2c_msg msg = {
		.addr = slave_addr,
		.flags = 0,
		.len = 2,
		.buf = out_buf,
	};

	out_buf[0] = addr;
	out_buf[1] = val;

	DRM_DEBUG("%s: wr: 0x%02x: 0x%02x\n", adapter->name, addr,
		  val);
	if (i2c_transfer(adapter, &msg, 1) != 1)
		DRM_DEBUG("i2c 0x%02x 0x%02x write failed\n", addr, val);
}

/*
 * Assumes:
 *    DivSel = 0
 */
static void __set_clk_fs(void __iomem * i2c, u8 a, u8 b, u8 c)
{
	u8 d = FS_REF;

	/* ClkA_FS[2:0] */
	ramdac_write(i2c, 0x08, (ramdac_read(i2c, 0x08) & 0x7F)
		     | ((a & 0x01) << 7));
	ramdac_write(i2c, 0x0E, (ramdac_read(i2c, 0x0E) & 0xFC)
		     | ((a & 0x06) >> 1));
	/* ClkB_FS[2:0] */
	ramdac_write(i2c, 0x0A, (ramdac_read(i2c, 0x0A) & 0x7F)
		     | ((b & 0x01) << 7));
	ramdac_write(i2c, 0x0E, (ramdac_read(i2c, 0x0E) & 0xF3)
		     | ((b & 0x06) << 1));
	/* ClkC_FS[2:0] */
	ramdac_write(i2c, 0x0C, (ramdac_read(i2c, 0x0C) & 0x7F)
		     | ((c & 0x01) << 7));
	ramdac_write(i2c, 0x0E, (ramdac_read(i2c, 0x0E) & 0xCF)
		     | ((c & 0x06) << 3));
	/* ClkD_FS[2:0] */
	ramdac_write(i2c, 0x0D, (ramdac_read(i2c, 0x0D) & 0x7F)
		     | ((d & 0x01) << 7));
	ramdac_write(i2c, 0x0E, (ramdac_read(i2c, 0x0E) & 0x3F)
		     | ((d & 0x06) << 5));
}

static inline unsigned pll_to_reg_offset(int pll)
{
	unsigned base;

	switch (pll) {
	case 1:
		base = 0x40;
		break;
	case 2:
		base = 0x11;
		break;
	case 3:
		base = 0x14;
		break;
	default:
		DRM_ERROR("Invalid PLL index %d\n", pll);
		return 0x11;
	}
	return base;
}

static void
__mga2_set_pll(struct i2c_adapter *i2c, int base, u8 Q, uint16_t P,
	       u8 PO)
{
	/* PLL*_Q[7:0] */
	ramdac_write(i2c, base + 0, Q);

	/* PLL*_P[7:0] */
	ramdac_write(i2c, base + 1, P & 0xFF);
	{
		u8 val;
		u8 LF = 0x0;

		int P_T = (2 * ((P & 0x3FF) + 3)) + (PO & 0x01);

		if (P_T <= 231)
			LF = 0x0;
		else if (P_T <= 626)
			LF = 0x1;
		else if (P_T <= 834)
			LF = 0x2;
		else if (P_T <= 1043)
			LF = 0x3;
		else if (P_T <= 1600)
			LF = 0x4;

		/* PLL*_En, PLL*_LF, PLL*_PO, PLL*_P[9:8] */
		val = (P & 0x300) >> 8;
		val |= (PO & 0x1) << 2;
		val |= LF << 3;
		/* val |= (enabled & 0x01) << 6; */

		ramdac_write(i2c, base + 2, val);
	}
}

static void
mga2_set_pll(struct i2c_adapter *i2c, int pll, u8 Q, uint16_t P, u8 PO)
{
	unsigned base = pll_to_reg_offset(pll);
	int i;
	int nr = (pll == 1) ? 8 : 1;
	for (i = 0; i < nr; i++, base += 3)
		__mga2_set_pll(i2c, base, Q, P, PO);

}

static void
__mga2_set_pll_enabled(struct i2c_adapter *i2c, u32 base, u8 enabled)
{
	u8 val;
	val = ramdac_read(i2c, base + 2);
	val = val & (~(0x01 << 6));
	val |= (enabled & 0x01) << 6;
	ramdac_write(i2c, base + 2, val);
}

static void
mga2_set_pll_enabled(struct i2c_adapter *i2c, int pll, u8 enabled)
{
	unsigned base = pll_to_reg_offset(pll);
	int i;
	int nr = (pll == 1) ? 8 : 1;
	for (i = 0; i < nr; i++, base += 3)
		__mga2_set_pll_enabled(i2c, base, enabled);

}

/*
 * Calculation of parameters PLL (here pixclock given in picoseconds,
 * so the argument 39,721 means the frequency of 10**12 / 39721 = 25175600 Hz
 */
static clk_t mga2_pll_calc(int pixclock, int use_div)
{
	clk_t res = { };
	clk_t cur;
	int delta = INT_MAX;
	int tmp_pixclock, tmp_delta;
	int mn_div = use_div ? 2 : 1;
	int mx_div = use_div ? 0x80 : 2;

#ifdef __e2k__
	/* If run under simulator skip long loops */
	if (NATIVE_IS_MACHINE_SIM) {
		goto out;
	}
#endif
	for (cur.p = 0; cur.p < 0x400; cur.p++) {
		for (cur.po = 0; cur.po < 0x2; cur.po++) {
			for (cur.div = mn_div; cur.div < mx_div;
			     cur.div += 2) {
				for (cur.q = 0; cur.q < 0x100; cur.q++) {

					tmp_pixclock =
					    (PIXCLOCK_EXT * cur.div *
					     (cur.q + 2)) / (2 * (cur.p +
								  3) +
							     cur.po);

					tmp_delta =
					    abs(pixclock - tmp_pixclock);
					if (tmp_delta < delta) {
						delta = tmp_delta;
						res = cur;
						res.pixclock =
						    tmp_pixclock;
					}
					if (tmp_delta == 0) {
						goto calculated;
					}
				}
			}
		}
	}
	DRM_ERROR
	    ("Can't calculate constants for pixclock=%d\n, use default\n",
	     pixclock);
	return res;

      calculated:
	DRM_DEBUG_KMS
	    ("Calculated: pixclock %d (%ld kHz) => %d (%ld kHz) PLL setup: "
	     "div=0x%02x q=0x%02x p=0x%02x po=0x%x\n", pixclock,
	     PICOS2KHZ(pixclock), res.pixclock, PICOS2KHZ(res.pixclock),
	     res.div, res.q, res.p, res.po);

#ifdef __e2k__
out:
#endif
	return res;
}

void mga2_pll_init_pixclock(struct i2c_adapter *i2c)
{
	int reg = 0;

	/* Init all i2c */
	for (reg = 0x08; reg <= 0x17; reg++)
		ramdac_write(i2c, reg, 0x0);

	for (reg = 0x40; reg <= 0x57; reg++)
		ramdac_write(i2c, reg, 0x0);

	ramdac_write(i2c, 0x17, 0x0);
//      ramdac_write(i2c, 0x0F, (0x01 << 6) | (0x01 << 4) | 0x01);
	ramdac_write(i2c, 0x0F,
		     (0x01 << 6) | (0x01 << 4) | (0x01 << 2) | 0x01);
	ramdac_write(i2c, 0x0D, 0x01);
	ramdac_write(i2c, 0x10, 0);
}

int
_mga2_ext_pll_set_pixclock(int pll, struct i2c_adapter *i2c,
			   unsigned long clock_khz)
{

	uint32_t pixclock = KHZ2PICOS(clock_khz);
	clk_t vidclk = mga2_pll_calc(pixclock, pll != 1);

	switch (pll) {
	case 2:
		ramdac_write(i2c, 0x08, 0x0);
		__set_clk_fs(i2c, FS_REF, FS_REF, FS_PLL3_0);
		{
			/* Reset vidclk enabled bit */
			mga2_set_pll_enabled(i2c, 2, 0);
			mga2_set_pll(i2c, 2, vidclk.q, vidclk.p,
				     vidclk.po);
		}
		__set_clk_fs(i2c, FS_PLL2_0, FS_REF, FS_PLL3_0);
		ramdac_write(i2c, 0x08, ((FS_PLL2_0 & 0x01) << 7)
			     | (vidclk.div & 0x7F));

		/* Set vidclk enabled bit */
		mga2_set_pll_enabled(i2c, 2, 1);
		break;

	case 3:
		ramdac_write(i2c, 0x0C, 0x0);
		__set_clk_fs(i2c, FS_PLL2_0, FS_REF, FS_REF);
		{
			/* Reset vidclk enabled bit */
			mga2_set_pll_enabled(i2c, 3, 0);
			mga2_set_pll(i2c, 3, vidclk.q, vidclk.p,
				     vidclk.po);
		}
		__set_clk_fs(i2c, FS_PLL2_0, FS_REF, FS_PLL3_0);
		ramdac_write(i2c, 0x0C, ((FS_PLL3_0 & 0x01) << 7)
			     | (vidclk.div & 0x7F));

		/* Set vidclk enabled bit */
		mga2_set_pll_enabled(i2c, 3, 1);
		break;
	case 1:
		ramdac_write(i2c, 0x0A, 0x0);
		__set_clk_fs(i2c, FS_REF, FS_PLL1_0, FS_REF);
		/* Reset vidclk enabled bit */
		mga2_set_pll_enabled(i2c, 1, 0);
		mga2_set_pll(i2c, 1, vidclk.q, vidclk.p, vidclk.po);

		__set_clk_fs(i2c, FS_PLL2_0, FS_PLL1_0, FS_PLL3_0);
		ramdac_write(i2c, 0x0A, ((FS_PLL1_0 & 0x01) << 7)
			     | (vidclk.div & 0x7F));

		/* Set vidclk enabled bit */
		mga2_set_pll_enabled(i2c, 1, 1);
		break;
	}

	return 0;
}
