/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _E2K_SYSWORK_H_
#define _E2K_SYSWORK_H_

#include <uapi/asm/e2k_syswork.h>


/* This macroses fill missing arguments with "(u64) (0)". */
#define EXPAND_ARGS_TO_8(...)	__EXPAND_ARGS_TO_8(__VA_ARGS__, 0, 0, 0, 0, 0, 0, 0)
#define __EXPAND_ARGS_TO_8(fmt, a1, a2, a3, a4, a5, a6, a7, ...) \
		fmt, (u64) (a1), (u64) (a2), (u64) (a3), \
		(u64) (a4), (u64) (a5), (u64) (a6), (u64) (a7)
#define EXPAND_ARGS_TO_7(...)	__EXPAND_ARGS_TO_7(__VA_ARGS__, 0, 0, 0, 0, 0, 0)
#define __EXPAND_ARGS_TO_7(fmt, a1, a2, a3, a4, a5, a6, ...) \
		fmt, (u64) (a1), (u64) (a2), (u64) (a3), (u64) (a4), (u64) (a5), (u64) (a6)

/* This macro is used to avoid printks with variable number of arguments
 * inside of functions with __check_stack attribute.
 *
 * If a call to printk has less than 8 parameters the macro sets any missing
 * arguments to (u64) (0).
 *
 * NOTE: maximum number of arguments that can be passed to a function
 * from within an __interrupt function is 8! */
#define _printk_fixed_args(...) \
		__printk_fixed_args(EXPAND_ARGS_TO_8(__VA_ARGS__))
#define trace_printk_fixed_args(fmt, args...) \
({ \
	static const char *trace_printk_fmt __used __section("__trace_printk_fmt") = fmt; \
	____trace_bprintk_fixed_args(_THIS_IP_, EXPAND_ARGS_TO_7(fmt, ##args)); \
})
#define panic_fixed_args(...) \
		__panic_fixed_args(EXPAND_ARGS_TO_8(__VA_ARGS__))

extern void __printk_fixed_args(char *fmt,
		u64 a1, u64 a2, u64 a3, u64 a4, u64 a5, u64 a6, u64 a7);
extern void __panic_fixed_args(char *fmt,
		u64 a1, u64 a2, u64 a3, u64 a4, u64 a5, u64 a6, u64 a7)
		__noreturn;
#ifdef CONFIG_TRACING
extern void ____trace_bprintk_fixed_args(unsigned long ip,
		char *fmt, u64 a1, u64 a2, u64 a3, u64 a4, u64 a5, u64 a6);
#endif

long do_longjmp(u64 retval, u64 jmp_sigmask, e2k_cr0_t jmp_cr0,
		e2k_cr1_t jmp_cr1, e2k_pcsp_t jmp_pcsp,
		u32 jmp_br, u32 jmp_psize);

long write_current_chain_stack(unsigned long dst, unsigned long buf,
		bool buf_is_user, unsigned long size);
long copy_current_proc_stack(unsigned long buf, bool buf_is_user, void __priv *p_stack,
			     unsigned long size, int write, unsigned long ps_used_top);

#endif /* _E2K_SYSWORK_H_ */
