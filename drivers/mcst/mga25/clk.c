/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifdef __KERNEL__
#include "drv.h"
#include <linux/gcd.h>
#endif /*__KERNEL__*/
/*
 * Copy-paste from amdgpu_pll.c
 */


/**
 * mga25_pll_reduce_ratio - fractional number reduction
 *
 * @nom: nominator
 * @den: denominator
 * @nom_min: minimum value for nominator
 * @den_min: minimum value for denominator
 *
 * Find the greatest common divisor and apply it on both nominator and
 * denominator, but make nominator and denominator are at least as large
 * as their minimum values.
 */
static void mga25_pll_reduce_ratio(unsigned *nom, unsigned *den,
				    unsigned nom_min, unsigned den_min)
{
	unsigned tmp;

	/* reduce the numbers to a simpler ratio */
	tmp = gcd(*nom, *den);
	*nom /= tmp;
	*den /= tmp;

	/* make sure nominator is large enough */
	if (*nom < nom_min) {
		tmp = DIV_ROUND_UP(nom_min, *nom);
		*nom *= tmp;
		*den *= tmp;
	}

	/* make sure the denominator is large enough */
	if (*den < den_min) {
		tmp = DIV_ROUND_UP(den_min, *den);
		*nom *= tmp;
		*den *= tmp;
	}
}

/**
 * mga25_pll_get_fb_ref_div - feedback and ref divider calculation
 *
 * @nom: nominator
 * @den: denominator
 * @post_div: post divider
 * @fb_div_max: feedback divider maximum
 * @ref_div_max: reference divider maximum
 * @fb_div: resulting feedback divider
 * @ref_div: resulting reference divider
 *
 * Calculate feedback and reference divider for a given post divider. Makes
 * sure we stay within the limits.
 */
static void mga25_pll_get_fb_ref_div(unsigned nom, unsigned den, unsigned post_div,
				      unsigned fb_div_max, unsigned ref_div_max,
				      unsigned *fb_div, unsigned *ref_div)
{
	/* limit reference * post divider to a maximum */
	ref_div_max = min(128 / post_div, ref_div_max);

	/* get matching reference and feedback divider */
	*ref_div = min(max(DIV_ROUND_CLOSEST(den, post_div), 1u), ref_div_max);
	*fb_div = DIV_ROUND_CLOSEST(nom * *ref_div * post_div, den);

	/* limit fb divider to its maximum */
	if (*fb_div > fb_div_max) {
		*ref_div = DIV_ROUND_CLOSEST(*ref_div * fb_div_max, *fb_div);
		*fb_div = fb_div_max;
	}
}

/**
 * mga25_pll_compute - compute PLL paramaters
 *
 * @pll: information about the PLL
 * @dot_clock_p: resulting pixel clock
 * fb_div_p: resulting feedback divider
 * frac_fb_div_p: fractional part of the feedback divider
 * ref_div_p: resulting reference divider
 * post_div_p: resulting reference divider
 *
 * Try to calculate the PLL parameters to generate the given frequency:
 * dot_clock = (ref_freq * feedback_div) / (ref_div * post_div)
 */
static void __mga25_pll_compute(const struct mga25_pll *pll,
			const u32 freq,
			u32 *dot_clock_p,
			u32 *fb_div_p,
			u32 *frac_fb_div_p,
			u32 *ref_div_p,
			u32 *post_div_p)
{
	unsigned target_clock = pll->flags & MGA2_PLL_USE_FRAC_FB_DIV ?
		freq  * 10 : freq;

	unsigned fb_div_min, fb_div_max, fb_div;
	unsigned post_div_min, post_div_max, post_div;
	unsigned ref_div_min, ref_div_max, ref_div;
	unsigned post_div_best, diff_best;
	unsigned nom, den;

	/* determine allowed feedback divider range */
	fb_div_min = pll->min_feedback_div;
	fb_div_max = pll->max_feedback_div;

	if (pll->flags & MGA2_PLL_USE_FRAC_FB_DIV) {
		fb_div_min *= 10;
		fb_div_max *= 10;
	}

	/* determine allowed ref divider range */
	if (pll->flags & MGA2_PLL_USE_REF_DIV)
		ref_div_min = pll->reference_div;
	else
		ref_div_min = pll->min_ref_div;

	if (pll->flags & MGA2_PLL_USE_FRAC_FB_DIV &&
	    pll->flags & MGA2_PLL_USE_REF_DIV)
		ref_div_max = pll->reference_div;
	else
		ref_div_max = pll->max_ref_div;

	/* determine allowed post divider range */
	if (pll->flags & MGA2_PLL_USE_POST_DIV) {
		post_div_min = pll->post_div;
		post_div_max = pll->post_div;
	} else {
		unsigned vco_min, vco_max;

		if (pll->flags & MGA2_PLL_IS_LCD) {
			vco_min = pll->lcd_pll_out_min;
			vco_max = pll->lcd_pll_out_max;
		} else {
			vco_min = pll->pll_out_min;
			vco_max = pll->pll_out_max;
		}

		if (pll->flags & MGA2_PLL_USE_FRAC_FB_DIV) {
			vco_min *= 10;
			vco_max *= 10;
		}

		post_div_min = vco_min / target_clock;
		if ((target_clock * post_div_min) < vco_min)
			++post_div_min;
		if (post_div_min < pll->min_post_div)
			post_div_min = pll->min_post_div;

		post_div_max = vco_max / target_clock;
		if ((target_clock * post_div_max) > vco_max)
			--post_div_max;
		if (post_div_max > pll->max_post_div)
			post_div_max = pll->max_post_div;
	}

	/* represent the searched ratio as fractional number */
	nom = target_clock;
	den = pll->reference_freq;

	/* reduce the numbers to a simpler ratio */
	mga25_pll_reduce_ratio(&nom, &den, fb_div_min, post_div_min);

	/* now search for a post divider */
	if (pll->flags & MGA2_PLL_PREFER_MINM_OVER_MAXP)
		post_div_best = post_div_min;
	else
		post_div_best = post_div_max;
	diff_best = ~0;

	for (post_div = post_div_min; post_div <= post_div_max; ++post_div) {
		unsigned diff;
		mga25_pll_get_fb_ref_div(nom, den, post_div, fb_div_max,
					  ref_div_max, &fb_div, &ref_div);
		diff = abs(target_clock - (pll->reference_freq * fb_div) /
			(ref_div * post_div));

		if (diff < diff_best || (diff == diff_best &&
		    !(pll->flags & MGA2_PLL_PREFER_MINM_OVER_MAXP))) {

			post_div_best = post_div;
			diff_best = diff;
		}
	}
	post_div = post_div_best;

	/* get the feedback and reference divider for the optimal value */
	mga25_pll_get_fb_ref_div(nom, den, post_div, fb_div_max, ref_div_max,
				  &fb_div, &ref_div);

	/* reduce the numbers to a simpler ratio once more */
	/* this also makes sure that the reference divider is large enough */
	mga25_pll_reduce_ratio(&fb_div, &ref_div, fb_div_min, ref_div_min);

	/* avoid high jitter with small fractional dividers */
	if (pll->flags & MGA2_PLL_USE_FRAC_FB_DIV && (fb_div % 10)) {
		fb_div_min = max(fb_div_min, (9 - (fb_div % 10)) * 20 + 60);
		if (fb_div < fb_div_min) {
			unsigned tmp = DIV_ROUND_UP(fb_div_min, fb_div);
			fb_div *= tmp;
			ref_div *= tmp;
		}
	}

	/* and finally save the result */
	if (pll->flags & MGA2_PLL_USE_FRAC_FB_DIV) {
		*fb_div_p = fb_div / 10;
		*frac_fb_div_p = fb_div % 10;
	} else {
		*fb_div_p = fb_div;
		*frac_fb_div_p = 0;
	}

	*dot_clock_p = ((pll->reference_freq * *fb_div_p * 10) +
			(pll->reference_freq * *frac_fb_div_p)) /
		       (ref_div * post_div * 10);
	*ref_div_p = ref_div;
	*post_div_p = post_div;
}

int mga25_pll_compute(const struct mga25_pll *pll,
			const u32 freq,
			u32 *dot_clock_p,
			u32 *fb_div_p,
			u32 *frac_fb_div_p,
			u32 *ref_div_p,
			u32 *post_div_p)
{
	if (!freq)
		return 0;


	if (freq < pll->pll_out_min ||
		freq > pll->pll_out_max
		)
			return -1;
	__mga25_pll_compute(pll, freq, dot_clock_p,
			fb_div_p, frac_fb_div_p,
			ref_div_p, post_div_p);

	if (*fb_div_p < pll->min_feedback_div ||
		*fb_div_p > pll->max_feedback_div ||
		*ref_div_p < pll->min_ref_div ||
		*ref_div_p > pll->max_ref_div ||
		*dot_clock_p < pll->pll_out_min ||
		*dot_clock_p > pll->pll_out_max ||
		*dot_clock_p < pll->pll_out_min ||
		*dot_clock_p > pll->pll_out_max ||
		((pll->flags & MGA2_PLL_USE_POST_DIV &&
		*post_div_p != pll->post_div) && (
		*post_div_p < pll->min_post_div ||
		*post_div_p > pll->max_post_div
		)))
			return -2;

	return 0;
}

