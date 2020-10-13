#include <asm/asm-offsets.h>
#include <asm/e2k_api.h>
#include <asm/sections.h>

/*
 * Functions to deal with signal handlers
 */

/* Hardware bug #25393
 * CUI must not be 0 when we return from user with non-zero CUI. */
__PROTECTED_TEXT

#ifdef	CONFIG_KERNEL_CODE_CONTEXT
/*
This function does the following:
notrace __interrupt __protect
void start_handler_sequel(int sig, siginfo_t *sip, struct ucontext *env,
		long fn, e2k_sbr_t sbr, e2k_usd_lo_t usd_lo,
		e2k_usd_hi_t usd_hi, e2k_cutd_t u_cutd)
{
	e2k_usd_lo_t k_usd_lo;
	AW(k_usd_lo) = E2K_GET_DSREG_NV(usd.lo);
	AS(k_usd_lo).p = 0;
	WRITE_USD_LO_REG(k_usd_lo);
	WRITE_CUTD_REG(u_cutd);
	as_sa_handler(sig, sip, env, fn, sbr, usd_lo, usd_hi);
}
*/
.global $start_handler_sequel
.type start_handler_sequel,@function
$start_handler_sequel:
	{
		setwd wsz = 0x9, nfx = 0x1
		setbn rsz = 0x3, rbs = 0x5, rcur = 0x0

		rrd %usd.lo, %dr8
	}
	{
		disp %ctpr1, $as_sa_handler
	}
	{
		andd,0 %dr8, _f64,_lts0 0xfbffffffffffffff, %dr8

		adds 0, %r0, %b[0]
		addd 0, %dr1, %db[1]
		addd 0, %dr2, %db[2]
		addd 0, %dr3, %db[3]
		addd 0, %dr4, %db[4]
	}
	{
		nop 5
		rwd,0 %dr8, %usd.lo
	}
	{
		nop 5

		/* No exceptions can happen here so there is
		 * no need for "wait all_e = 1". */
		rwd,0 %dr7, %cutd

		addd 0, %dr5, %db[5]
		addd 0, %dr6, %db[6]
	}
	{
		call %ctpr1, wbs = 0x5
	}
	{
		return %ctpr3
	}
	{
		ct %ctpr3
	}
.size $start_handler_sequel, . - $start_handler_sequel
#endif

.global $as_sa_handler_not_protect
.type as_sa_handler_not_protect,@function
$as_sa_handler_not_protect:
	{
		setwd wsz = 0x8, nfx = 0x1
		setbn rsz = 0x3, rbs = 0x4, rcur = 0x0
		setbp psz = 0x0
	}
	{
		disp %ctpr1, $go2user

		rwd %dr4, %sbr
	}
	{
		rwd %dr6, %usd.hi
	}
	{
		nop 5
		rwd %dr5, %usd.lo
	}
	{
		call %ctpr1, wbs = 0x4

		addd 0, %dr3, %db[0]
	}
	/* We should not get here */
	{
		return %ctpr3
	}
	{
		ct %ctpr3
	}
.size $as_sa_handler_not_protect, . - $as_sa_handler_not_protect

#ifdef CONFIG_PROTECTED_MODE
.global $prot_as_sa_handler
.type prot_as_sa_handler,@function
$prot_as_sa_handler:
	{
		setwd wsz = 0xa, nfx = 0x1
		setbn rsz = 0x3, rbs = 0x6, rcur = 0x0
		setbp psz = 0x0

		getsp 0, %dr8
	}
	{
		disp %ctpr1, $go2user

		ldd [ %dr8 + 0x40 ], %dr9
		ldd [ %dr8 + 0x50 ], %dr10
		ldd [ %dr8 + 0x48 ], %dr11
	}
	{
		rwd %dr9, %sbr

		puttagd %dr0, 15, %dr0
		puttagd %dr1, 12, %dr1
	}
	{
		rwd %dr10, %usd.hi

		puttagd %dr4, 15, %dr4
		puttagd %dr5, 12, %dr5
	}
	{
		nop 5

		rwd %dr11, %usd.lo

		puttagd %dr6, 15, %dr6
		puttagd %dr7, 12, %dr7
	}
	{
		call %ctpr1, wbs = 0x6

		addd 0, %dr3, %db[0]
	}
	/* We should not get here */
	{
		return %ctpr3
	}
	{
		ct %ctpr3
	}
.size $prot_as_sa_handler, . - $prot_as_sa_handler
#endif /* CONFIG_PROTECTED_MODE */





/*
 * Functions to deal with execve()
 */

.section ".text", "ax"
.global $switch_to_user_func
.type switch_to_user_func,@function
$switch_to_user_func:
	{
		setwd wsz = 0x8, nfx = 0x1
		setbn rsz = 0x3, rbs = 0x4, rcur = 0x0
		setbp psz = 0x0

		rrd %cr1.hi, %dr4
#ifdef CONFIG_E2S_CPU_RF_BUG
	}
	{
		rrd %osr0, %dg16
	}
	{
#endif
		ldd [ %dg16 + TI_K_USD_HI ], %dr5
	}
	{
		disp %ctpr1, $do_switch_to_user_func

		andd %dr4, 0xfffffffff, %dr4
		andd %dr5, 0xfffffff000000000, %dr5
	}
	{
		ord %dr4, %dr5, %dr4
	}
	{
		nop 4

		/* Correct value in %cr1.hi (currently it holds
		 * user data stack size while cr0.hi holds kernel IP) */
		rwd %dr4, %cr1.hi

		addd 0, 0, %dr0
		addd 0, %dr1, %db[0]
	}
	{
		call %ctpr1, wbs = 0x4
	}
.size $switch_to_user_func, . - $switch_to_user_func

#ifdef CONFIG_PROTECTED_MODE
.global $protected_switch_to_user_func
.type protected_switch_to_user_func,@function
$protected_switch_to_user_func:
	{
		setwd wsz = 0x8, nfx = 0x1
		setbn rsz = 0x3, rbs = 0x4, rcur = 0x0
		setbp psz = 0x0

		rrd %cr1.hi, %dr4
#ifdef CONFIG_E2S_CPU_RF_BUG
	}
	{
		rrd %osr0, %dg16
	}
	{
#endif
		ldd [ %dg16 + TI_K_USD_HI ], %dr5
	}
	{
		disp %ctpr1, $do_switch_to_user_func

		andd %dr4, 0xfffffffff, %dr4
		andd %dr5, 0xfffffff000000000, %dr5

		puttagd %dr0, 15, %dr0
		puttagd %dr1, 12, %dr1
	}
	{
		ord %dr4, %dr5, %dr4
	}
	{
		nop 4

		/* Correct value in %cr1.hi (currently it holds
		 * user data stack size while cr0.hi holds kernel IP) */
		rwd %dr4, %cr1.hi

		addd 0, %dr2, %db[0]
	}
	{
		call %ctpr1, wbs = 0x4
	}
.size $protected_switch_to_user_func, . - $protected_switch_to_user_func
#endif /* CONFIG_PROTECTED_MODE */





/*
 * Functions to deal with sys_{get/set}_backtrace()
 */

.section ".text", "ax"
.global $sys_backtrace_return
.type sys_backtrace_return,@function
$sys_backtrace_return:
	return %ctpr3
	ct %ctpr3
.size $sys_backtrace_return, . - $sys_backtrace_return
