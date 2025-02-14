#include <generated/asm-offsets.h>
#include <asm/pv_info.h>
#include <asm/e2k_api.h>
#include <asm/trap_table.h>
#include <asm/head.h>
#include <asm/sections.h>
#include <asm/alternative-asm.h>

/*
 * Functions to deal with execve()
 *
 * void switch_to_user_func(long dummy,
 *		start_fn start_func, e2k_size_t us_size, int cui);
 *
 */

.global $switch_to_user_func
.type switch_to_user_func,@function
$switch_to_user_func:
	{
		setwd wsz = 0x8, nfx = 0x1
		setbn rsz = 0x3, rbs = 0x4, rcur = 0x0
		setbp psz = 0x0

		rrd %cr1.hi, %dr6
		ldd [ GCURTASK + TSK_TI + TI_K_USD_HI ], %dr5
	}
	{
		rwd 0, %cr0.hi
		disp %ctpr1, $do_switch_to_user_func

		andd %dr6, 0xfffffffff, %dr6
		andd %dr5, 0xfffffff000000000, %dr5
	}
	{
		rwd 0, %cr1.lo
		ord %dr6, %dr5, %dr6
	}
ALTERNATIVE_1_ALTINSTR
/* CPU_HWBUG_INTC_CR_WRITE version */
	{
		nop 4

		/* Correct value in %cr1.hi (currently it holds
		 * user data stack size while cr0.hi holds kernel IP) */
		wait ma_c=1
		rwd %dr6, %cr1.hi

		addd 0, %dr1, %db[0]	/* start_func */
		addd 0, %dr2, %db[1]	/* us_size */
		addd 0, %dr3, %db[2]	/* cui */
	}
ALTERNATIVE_2_OLDINSTR
/* Default version */
	{
		nop 4

		/* Correct value in %cr1.hi (currently it holds
		 * user data stack size while cr0.hi holds kernel IP) */
		rwd %dr6, %cr1.hi

		addd 0, %dr1, %db[0]	/* start_func */
		addd 0, %dr2, %db[1]	/* us_size */
		addd 0, %dr3, %db[2]	/* cui */
	}
ALTERNATIVE_3_FEATURE(CPU_HWBUG_INTC_CR_WRITE)
	{
		/* Clear kernel information from user's registers */
		addd 0, 0, %db[3]
		addd 0, 0, %db[4]
		addd 0, 0, %db[5]
		addd 0, 0, %db[6]
		addd 0, 0, %db[7]
		call %ctpr1, wbs = 0x4
	}
.size $switch_to_user_func, . - $switch_to_user_func

#ifdef CONFIG_PROTECTED_MODE
/*
 * void protected_switch_to_user_func(long r0, long r1,
 *		start_fn start_func, e2k_size_t us_size, int cui);
 *
 */
.global $protected_switch_to_user_func
.type protected_switch_to_user_func,@function
$protected_switch_to_user_func:
	{
		setwd wsz = 0x9, nfx = 0x1
		setbn rsz = 0x3, rbs = 0x5, rcur = 0x0
		setbp psz = 0x0

		rrd %cr1.hi, %dr7
		ldd [ GCURTASK + TSK_TI + TI_K_USD_HI ], %dr6
	}
	{
		rwd 0, %cr0.hi
		disp %ctpr1, $do_switch_to_user_func

		andd,1 %dr7, 0xfffffffff, %dr7
		andd,3 %dr6, 0xfffffff000000000, %dr6

		puttagd %dr0, 15, %dr0
		puttagd %dr1, 12, %dr1
	}
	{
		ord %dr7, %dr6, %dr7
	}
ALTERNATIVE_1_ALTINSTR
/* CPU_HWBUG_INTC_CR_WRITE version */
	{
		nop	4

		/* Correct value in %cr1.hi (currently it holds
		 * user data stack size while cr0.hi holds kernel IP) */
		wait ma_c=1
		rwd %dr5, %cr1.hi

		addd 0,	%dr2, %db[0]	/* start_func */
		addd 0,	%dr3, %db[1]	/* us_size */
		addd 0,	%dr4, %db[2]	/* cui */
	}
ALTERNATIVE_2_OLDINSTR
/* Default version */
	{
		nop	4

		/* Correct value in %cr1.hi (currently it holds
		 * user data stack size while cr0.hi holds kernel IP) */
		rwd %dr7, %cr1.hi

		addd 0,	%dr2, %db[0]	/* start_func */
		addd 0,	%dr3, %db[1]	/* us_size */
		addd 0,	%dr4, %db[2]	/* cui */
	}
ALTERNATIVE_3_FEATURE(CPU_HWBUG_INTC_CR_WRITE)
	{
		/*
		* Set `rtld_fini' parameter to NULL so that the main executable's
		* `_start ()' can distinguish between the cases when it's invoked
		* directly by the kernel or ld.so.
		*/
		movtd	0x0, %dr2
		movtd	0x0, %dr3
	}
	{
		/* Clear kernel information from user's registers */
		addd 0, 0, %db[3]
		addd 0, 0, %db[4]
		addd 0, 0, %db[5]
		addd 0, 0, %db[6]
		addd 0, 0, %db[7]

		call	%ctpr1, wbs = 0x5
	}
.size $protected_switch_to_user_func, . - $protected_switch_to_user_func
#endif /* CONFIG_PROTECTED_MODE */

/*
 * Functions to deal with sys_{get/set}_backtrace()
 */

.text
.global $sys_backtrace_return
.type sys_backtrace_return,@function
$sys_backtrace_return:
	{
		nop 3
		return %ctpr3
	}
	ct %ctpr3
.size $sys_backtrace_return, . - $sys_backtrace_return
