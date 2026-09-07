/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _E2K_API_H_
#define _E2K_API_H_

#include <linux/stringify.h>
#include <linux/typecheck.h>

#include <asm/alternative.h>
#include <asm/cpu_regs_types_defs.h>
#include <asm/compiler.h>
#include <asm/cpu_feature_values.h>
#include <asm/instr_regs_types.h>	/* For instr_cs1_t */
#include <asm/mas.h>
#include <asm/tags.h>
#ifndef __ASSEMBLY__
#include <asm/mmu_types.h>
#include <asm/mmu_regs_types.h>
#include <asm/nbsr_v6_regs.h>
#include <asm/spmc_regs.h>
#endif
#include <uapi/asm/e2k_api.h>


#ifndef __ASSEMBLY__

/* CPU_HWBUG_JUMP: mark labels that are not targets of a call or jump */
#if __iset__ <= 6
# define NONTARGET_LABEL(num) ".non_target_label "num";"
#else
# define NONTARGET_LABEL(num) num":"
#endif

#endif /* !__ASSEMBLY__ */

/*
 * Used to separate one wide instruction from another
 */
#define	E2K_CMD_SEPARATOR		asm volatile ("{nop}" ::: "memory")

/* To avoid header dependencies use this define
 * instead of BUILD_BUG_ON() from <linux/kernel.h>. */
#define E2K_BUILD_BUG_ON(condition) ((void)sizeof(char[1 - 2*!!(condition)]))

/*
 * Normal simulator termination
 */
#define E2K_LMS_HALT_OK				\
({						\
	__no_asm_inline(1)		\
	asm volatile (".word \t0x00008001\n\t"	\
			".word \t0x60000000");	\
})

/*
 * Simulator termination on error
 */
#define E2K_LMS_HALT_ERROR(err_no)		\
({						\
	__no_asm_inline(1)		\
	asm volatile (".word \t0x00008001\n\t"	\
		".word \t0x60000000 | %0"	\
		:				\
		: "i" (err_no));		\
})

#define	ASM_GET_GREG_MNEMONIC(greg_no)	 __asm__("%g" #greg_no)
#define	ASM_GREG(greg_no) ASM_GET_GREG_MNEMONIC(greg_no)

#define ASM_GET_UNTEGGED_DGREG(reg_no) \
({ \
	register u64 res; \
	asm volatile ("addd,s \t0x0, %%dg" #reg_no ", %0\n"  \
		"puttagd,s \t%0, 0, %0"	\
		: "=r" (res)); \
	res; \
})
#define NATIVE_GET_UNTEGGED_DGREG(greg_no) \
		ASM_GET_UNTEGGED_DGREG(greg_no)

#define ASM_SET_DGREG(reg_no, val) \
({ \
	asm volatile ("addd \t0x0, %0, %%dg" #reg_no \
		: \
		: "ri" ((u64) (val))); \
})
#define	DO_ASM_SET_DGREG(greg_no, val) \
		ASM_SET_DGREG(greg_no, val)
#define E2K_SET_DGREG(greg_no, val)	\
		DO_ASM_SET_DGREG(greg_no, val)
#define NATIVE_SET_DGREG(greg_no, val) \
		DO_ASM_SET_DGREG(greg_no, val)

#define ASM_SET_DGREG_NV(greg_no, _val) \
({ \
	register u64 _greg asm("g" #greg_no); \
	asm ("addd 0, %[val], %[greg]" \
		  : [greg] "=r" (_greg) \
		  : [val] "ri" ((u64) (_val))); \
})
#define	DO_ASM_SET_DGREG_NV(greg_no, val) \
		ASM_SET_DGREG_NV(greg_no, val)
#define E2K_SET_DGREG_NV(greg_no, val)	\
		DO_ASM_SET_DGREG_NV(greg_no, val)
#define NATIVE_SET_DGREG_NV(greg_no, val) \
		DO_ASM_SET_DGREG_NV(greg_no, val)


#define __E2K_QPSWITCHD_SM_GREG(num)				\
do {								\
	asm ("qpswitchd,sm %%dg" #num ", %%dg" #num		\
			::: "%g" #num);				\
} while (0)

#define E2K_QPSWITCHD_SM_GREG(greg_num)					\
do {									\
	switch (greg_num) {						\
	case  0: __E2K_QPSWITCHD_SM_GREG(0); break;			\
	case  1: __E2K_QPSWITCHD_SM_GREG(1); break;			\
	case  2: __E2K_QPSWITCHD_SM_GREG(2); break;			\
	case  3: __E2K_QPSWITCHD_SM_GREG(3); break;			\
	case  4: __E2K_QPSWITCHD_SM_GREG(4); break;			\
	case  5: __E2K_QPSWITCHD_SM_GREG(5); break;			\
	case  6: __E2K_QPSWITCHD_SM_GREG(6); break;			\
	case  7: __E2K_QPSWITCHD_SM_GREG(7); break;			\
	case  8: __E2K_QPSWITCHD_SM_GREG(8); break;			\
	case  9: __E2K_QPSWITCHD_SM_GREG(9); break;			\
	case 10: __E2K_QPSWITCHD_SM_GREG(10); break;			\
	case 11: __E2K_QPSWITCHD_SM_GREG(11); break;			\
	case 12: __E2K_QPSWITCHD_SM_GREG(12); break;			\
	case 13: __E2K_QPSWITCHD_SM_GREG(13); break;			\
	case 14: __E2K_QPSWITCHD_SM_GREG(14); break;			\
	case 15: __E2K_QPSWITCHD_SM_GREG(15); break;			\
	case 16: __E2K_QPSWITCHD_SM_GREG(16); break;			\
	case 17: __E2K_QPSWITCHD_SM_GREG(17); break;			\
	case 18: __E2K_QPSWITCHD_SM_GREG(18); break;			\
	case 19: __E2K_QPSWITCHD_SM_GREG(19); break;			\
	case 20: __E2K_QPSWITCHD_SM_GREG(20); break;			\
	case 21: __E2K_QPSWITCHD_SM_GREG(21); break;			\
	case 22: __E2K_QPSWITCHD_SM_GREG(22); break;			\
	case 23: __E2K_QPSWITCHD_SM_GREG(23); break;			\
	case 24: __E2K_QPSWITCHD_SM_GREG(24); break;			\
	case 25: __E2K_QPSWITCHD_SM_GREG(25); break;			\
	case 26: __E2K_QPSWITCHD_SM_GREG(26); break;			\
	case 27: __E2K_QPSWITCHD_SM_GREG(27); break;			\
	case 28: __E2K_QPSWITCHD_SM_GREG(28); break;			\
	case 29: __E2K_QPSWITCHD_SM_GREG(29); break;			\
	case 30: __E2K_QPSWITCHD_SM_GREG(30); break;			\
	case 31: __E2K_QPSWITCHD_SM_GREG(31); break;			\
	default: panic("Invalid global register # %d\n", greg_num);	\
	}								\
} while (0)

#define _E2K_GET_DGREG_VAL_AND_TAG(greg_no, dst_reg, tag)	\
({								\
	u32 __dtag;						\
	__no_asm_inline(1)				\
	asm volatile ("{gettagd %%dg" #greg_no ", %0\n\t"	\
		      "puttagd %%dg" #greg_no ", 0, %1}"	\
		      : "=r" (__dtag), "=r" (dst_reg)		\
		      : );					\
	tag = __dtag;						\
})

#define E2K_GET_DGREG_VAL_AND_TAG(greg_num, dst_reg, tag)	     \
({								     \
	switch (greg_num) {					     \
	case  0: _E2K_GET_DGREG_VAL_AND_TAG(0, dst_reg, tag); break;  \
	case  1: _E2K_GET_DGREG_VAL_AND_TAG(1, dst_reg, tag); break;  \
	case  2: _E2K_GET_DGREG_VAL_AND_TAG(2, dst_reg, tag); break;  \
	case  3: _E2K_GET_DGREG_VAL_AND_TAG(3, dst_reg, tag); break;  \
	case  4: _E2K_GET_DGREG_VAL_AND_TAG(4, dst_reg, tag); break;  \
	case  5: _E2K_GET_DGREG_VAL_AND_TAG(5, dst_reg, tag); break;  \
	case  6: _E2K_GET_DGREG_VAL_AND_TAG(6, dst_reg, tag); break;  \
	case  7: _E2K_GET_DGREG_VAL_AND_TAG(7, dst_reg, tag); break;  \
	case  8: _E2K_GET_DGREG_VAL_AND_TAG(8, dst_reg, tag); break;  \
	case  9: _E2K_GET_DGREG_VAL_AND_TAG(9, dst_reg, tag); break;  \
	case 10: _E2K_GET_DGREG_VAL_AND_TAG(10, dst_reg, tag); break; \
	case 11: _E2K_GET_DGREG_VAL_AND_TAG(11, dst_reg, tag); break; \
	case 12: _E2K_GET_DGREG_VAL_AND_TAG(12, dst_reg, tag); break; \
	case 13: _E2K_GET_DGREG_VAL_AND_TAG(13, dst_reg, tag); break; \
	case 14: _E2K_GET_DGREG_VAL_AND_TAG(14, dst_reg, tag); break; \
	case 15: _E2K_GET_DGREG_VAL_AND_TAG(15, dst_reg, tag); break; \
	case 16: _E2K_GET_DGREG_VAL_AND_TAG(16, dst_reg, tag); break; \
	case 17: _E2K_GET_DGREG_VAL_AND_TAG(17, dst_reg, tag); break; \
	case 18: _E2K_GET_DGREG_VAL_AND_TAG(18, dst_reg, tag); break; \
	case 19: _E2K_GET_DGREG_VAL_AND_TAG(19, dst_reg, tag); break; \
	case 20: _E2K_GET_DGREG_VAL_AND_TAG(20, dst_reg, tag); break; \
	case 21: _E2K_GET_DGREG_VAL_AND_TAG(21, dst_reg, tag); break; \
	case 22: _E2K_GET_DGREG_VAL_AND_TAG(22, dst_reg, tag); break; \
	case 23: _E2K_GET_DGREG_VAL_AND_TAG(23, dst_reg, tag); break; \
	case 24: _E2K_GET_DGREG_VAL_AND_TAG(24, dst_reg, tag); break; \
	case 25: _E2K_GET_DGREG_VAL_AND_TAG(25, dst_reg, tag); break; \
	case 26: _E2K_GET_DGREG_VAL_AND_TAG(26, dst_reg, tag); break; \
	case 27: _E2K_GET_DGREG_VAL_AND_TAG(27, dst_reg, tag); break; \
	case 28: _E2K_GET_DGREG_VAL_AND_TAG(28, dst_reg, tag); break; \
	case 29: _E2K_GET_DGREG_VAL_AND_TAG(29, dst_reg, tag); break; \
	case 30: _E2K_GET_DGREG_VAL_AND_TAG(30, dst_reg, tag); break; \
	case 31: _E2K_GET_DGREG_VAL_AND_TAG(31, dst_reg, tag); break; \
	default: panic("Invalid global register # %d\n", greg_num);	     \
	}								     \
})

#define _E2K_SET_DGREG_VAL_AND_TAG(greg_no, val, tag)		\
do {								\
	asm volatile ("puttagd %0, %1, %%dg" #greg_no		\
		      :						\
		      : "r" (val), "r" (tag));			\
} while (0)

#define E2K_SET_DGREG_VAL_AND_TAG(greg_num, val, tag)	     	  \
do {								  \
	switch (greg_num) {					  \
	case  0: _E2K_SET_DGREG_VAL_AND_TAG(0, val, tag); break;  \
	case  1: _E2K_SET_DGREG_VAL_AND_TAG(1, val, tag); break;  \
	case  2: _E2K_SET_DGREG_VAL_AND_TAG(2, val, tag); break;  \
	case  3: _E2K_SET_DGREG_VAL_AND_TAG(3, val, tag); break;  \
	case  4: _E2K_SET_DGREG_VAL_AND_TAG(4, val, tag); break;  \
	case  5: _E2K_SET_DGREG_VAL_AND_TAG(5, val, tag); break;  \
	case  6: _E2K_SET_DGREG_VAL_AND_TAG(6, val, tag); break;  \
	case  7: _E2K_SET_DGREG_VAL_AND_TAG(7, val, tag); break;  \
	case  8: _E2K_SET_DGREG_VAL_AND_TAG(8, val, tag); break;  \
	case  9: _E2K_SET_DGREG_VAL_AND_TAG(9, val, tag); break;  \
	case 10: _E2K_SET_DGREG_VAL_AND_TAG(10, val, tag); break; \
	case 11: _E2K_SET_DGREG_VAL_AND_TAG(11, val, tag); break; \
	case 12: _E2K_SET_DGREG_VAL_AND_TAG(12, val, tag); break; \
	case 13: _E2K_SET_DGREG_VAL_AND_TAG(13, val, tag); break; \
	case 14: _E2K_SET_DGREG_VAL_AND_TAG(14, val, tag); break; \
	case 15: _E2K_SET_DGREG_VAL_AND_TAG(15, val, tag); break; \
	case 16: _E2K_SET_DGREG_VAL_AND_TAG(16, val, tag); break; \
	case 17: _E2K_SET_DGREG_VAL_AND_TAG(17, val, tag); break; \
	case 18: _E2K_SET_DGREG_VAL_AND_TAG(18, val, tag); break; \
	case 19: _E2K_SET_DGREG_VAL_AND_TAG(19, val, tag); break; \
	case 20: _E2K_SET_DGREG_VAL_AND_TAG(20, val, tag); break; \
	case 21: _E2K_SET_DGREG_VAL_AND_TAG(21, val, tag); break; \
	case 22: _E2K_SET_DGREG_VAL_AND_TAG(22, val, tag); break; \
	case 23: _E2K_SET_DGREG_VAL_AND_TAG(23, val, tag); break; \
	case 24: _E2K_SET_DGREG_VAL_AND_TAG(24, val, tag); break; \
	case 25: _E2K_SET_DGREG_VAL_AND_TAG(25, val, tag); break; \
	case 26: _E2K_SET_DGREG_VAL_AND_TAG(26, val, tag); break; \
	case 27: _E2K_SET_DGREG_VAL_AND_TAG(27, val, tag); break; \
	case 28: _E2K_SET_DGREG_VAL_AND_TAG(28, val, tag); break; \
	case 29: _E2K_SET_DGREG_VAL_AND_TAG(29, val, tag); break; \
	case 30: _E2K_SET_DGREG_VAL_AND_TAG(30, val, tag); break; \
	case 31: _E2K_SET_DGREG_VAL_AND_TAG(31, val, tag); break; \
	default: panic("Invalid global register # %d\n", greg_num);	     \
	}								     \
} while (0)

#define _E2K_GET_GREG_VAL_AND_TAG(greg_no, dst_reg, tag)	\
({								\
	u32 __tag;						\
	__no_asm_inline(1)				\
	asm volatile ("{gettags %%g" #greg_no ", %0\n\t"	\
		      " puttags %%g" #greg_no ", 0, %1}"	\
		      : "=r" (__tag), "=r" (dst_reg)		\
		      : );					\
	tag = __tag;						\
})

#define E2K_GET_GREG_VAL_AND_TAG(greg_num, dst_reg, tag)		\
({									\
	switch (greg_num) {						\
	case  0: _E2K_GET_GREG_VAL_AND_TAG(0, dst_reg, tag); break;	\
	case  1: _E2K_GET_GREG_VAL_AND_TAG(1, dst_reg, tag); break;	\
	case  2: _E2K_GET_GREG_VAL_AND_TAG(2, dst_reg, tag); break;	\
	case  3: _E2K_GET_GREG_VAL_AND_TAG(3, dst_reg, tag); break;	\
	case  4: _E2K_GET_GREG_VAL_AND_TAG(4, dst_reg, tag); break;	\
	case  5: _E2K_GET_GREG_VAL_AND_TAG(5, dst_reg, tag); break;	\
	case  6: _E2K_GET_GREG_VAL_AND_TAG(6, dst_reg, tag); break;	\
	case  7: _E2K_GET_GREG_VAL_AND_TAG(7, dst_reg, tag); break;	\
	case  8: _E2K_GET_GREG_VAL_AND_TAG(8, dst_reg, tag); break;	\
	case  9: _E2K_GET_GREG_VAL_AND_TAG(9, dst_reg, tag); break;	\
	case 10: _E2K_GET_GREG_VAL_AND_TAG(10, dst_reg, tag); break;	\
	case 11: _E2K_GET_GREG_VAL_AND_TAG(11, dst_reg, tag); break;	\
	case 12: _E2K_GET_GREG_VAL_AND_TAG(12, dst_reg, tag); break;	\
	case 13: _E2K_GET_GREG_VAL_AND_TAG(13, dst_reg, tag); break;	\
	case 14: _E2K_GET_GREG_VAL_AND_TAG(14, dst_reg, tag); break;	\
	case 15: _E2K_GET_GREG_VAL_AND_TAG(15, dst_reg, tag); break;	\
	case 16: _E2K_GET_GREG_VAL_AND_TAG(16, dst_reg, tag); break;	\
	case 17: _E2K_GET_GREG_VAL_AND_TAG(17, dst_reg, tag); break;	\
	case 18: _E2K_GET_GREG_VAL_AND_TAG(18, dst_reg, tag); break;	\
	case 19: _E2K_GET_GREG_VAL_AND_TAG(19, dst_reg, tag); break;	\
	case 20: _E2K_GET_GREG_VAL_AND_TAG(20, dst_reg, tag); break;	\
	case 21: _E2K_GET_GREG_VAL_AND_TAG(21, dst_reg, tag); break;	\
	case 22: _E2K_GET_GREG_VAL_AND_TAG(22, dst_reg, tag); break;	\
	case 23: _E2K_GET_GREG_VAL_AND_TAG(23, dst_reg, tag); break;	\
	case 24: _E2K_GET_GREG_VAL_AND_TAG(24, dst_reg, tag); break;	\
	case 25: _E2K_GET_GREG_VAL_AND_TAG(25, dst_reg, tag); break;	\
	case 26: _E2K_GET_GREG_VAL_AND_TAG(26, dst_reg, tag); break;	\
	case 27: _E2K_GET_GREG_VAL_AND_TAG(27, dst_reg, tag); break;	\
	case 28: _E2K_GET_GREG_VAL_AND_TAG(28, dst_reg, tag); break;	\
	case 29: _E2K_GET_GREG_VAL_AND_TAG(29, dst_reg, tag); break;	\
	case 30: _E2K_GET_GREG_VAL_AND_TAG(30, dst_reg, tag); break;	\
	case 31: _E2K_GET_GREG_VAL_AND_TAG(31, dst_reg, tag); break;	\
	default: panic("Invalid global register # %d\n", greg_num);	\
	}								\
})

#define ASM_SAVE_GREG_V3(__addr_lo, __addr_hi, numlo, numhi)	\
({									\
	u64 reg0, reg1;							\
	asm (	"strd,2 [ %[addr_lo] + %[opc_0] ], %%dg" #numlo "\n"	\
		"strd,5 [ %[addr_hi] + %[opc_0] ], %%dg" #numhi "\n"	\
		"movfi %%dg" #numlo ", %[reg0]\n"			\
		"movfi %%dg" #numhi ", %[reg1]\n"			\
		"sth [ %[addr_lo] + 8 ], %[reg0]\n"			\
		"sth [ %[addr_hi] + 8 ], %[reg1]\n"			\
		: [reg0] "=r" (reg0), [reg1] "=&r" (reg1),		\
		  [addr_lo] "=m" (*(__uint128_t *) (__addr_lo)), \
		  [addr_hi] "=m" (*(__uint128_t *) (__addr_hi)) \
		: [opc_0] "i" (TAGGED_MEM_STORE_REC_OPC)		\
		: "memory");						\
})

#define ASM_RESTORE_GREG_V3(__addr, __off_lo, __off_hi, numlo, numhi) \
do { \
	u64 reg0, reg1, reg2, reg3; \
	asm (	"ldrd,2 [ %[addr] + %[opc_lo] ], %%dg" #numlo "\n" \
		"ldrd,5 [ %[addr] + %[opc_hi] ], %%dg" #numhi "\n" \
		"ldh [ %[addr] + %[off_lo_8] ], %[reg0]\n" \
		"ldh [ %[addr] + %[off_hi_8] ], %[reg1]\n" \
		"gettagd %%dg" #numlo ", %[reg2]\n" \
		"gettagd %%dg" #numhi ", %[reg3]\n" \
		"cmpesb 0, %[reg2], %%pred2\n" \
		"cmpesb 0, %[reg3], %%pred3\n" \
		"movif %%dg" #numlo ", %[reg0], %%dg" #numlo " ? %%pred2\n" \
		"movif %%dg" #numhi ", %[reg1], %%dg" #numhi " ? %%pred3\n" \
		: [reg0] "=&r" (reg0),	[reg1] "=&r" (reg1), \
		  [reg2] "=&r" (reg2),	[reg3] "=&r" (reg3) \
		: [addr] "r" (__addr), \
		  [opc_lo] "i" (TAGGED_MEM_LOAD_REC_OPC | (__off_lo)), \
		  [opc_hi] "i" (TAGGED_MEM_LOAD_REC_OPC | (__off_hi)), \
		  [off_lo_8] "i" ((__off_lo) + 8), \
		  [off_hi_8] "i" ((__off_hi) + 8) \
		: "%g" #numlo, "%g" #numhi, "%pred2", "%pred3"); \
} while (0)

#if __iset__ >= 5
# define ASM_SAVE_GREG_V5(__addr_lo, __addr_hi, numlo, numhi) \
do { \
	register u64 __g_lo __asm__("%g" #numlo); \
	register u64 __g_hi __asm__("%g" #numhi); \
	/* CPU_HWBUG_TAGGED_STRQP: close this asm because \
	 * 'sm' for 'strqp' is not supported by lcc */ \
	__asm_length(1) \
	asm (	"{strqp,2,sm [ %[addr_lo] + %[opc] ], %[g_lo]\n" \
		" strqp,5,sm [ %[addr_hi] + %[opc] ], %[g_hi]}\n" \
		: [addr_lo] "=m" (*(__uint128_t *) (__addr_lo)), \
		  [addr_hi] "=m" (*(__uint128_t *) (__addr_hi)) \
		: [g_lo] "r" (__g_lo), [g_hi] "r" (__g_hi), \
		  [opc] "i" (TAGGED_MEM_STORE_REC_OPC)); \
} while (0)

# define ASM_RESTORE_GREG_V5(__addr, __off_lo, __off_hi, numlo, numhi) \
do { \
	register u64 __g_lo __asm__("%g" #numlo); \
	register u64 __g_hi __asm__("%g" #numhi); \
	asm (	"ldrqp [ %[addr] + %[opc_lo] ], %[g_lo]\n" \
		"ldrqp [ %[addr] + %[opc_hi] ], %[g_hi]\n" \
		: [g_lo] "=&r" (__g_lo), [g_hi] "=&r" (__g_hi) \
		: [addr] "r" (__addr), \
		  [opc_lo] "i" (TAGGED_MEM_LOAD_REC_OPC | (__off_lo)), \
		  [opc_hi] "i" (TAGGED_MEM_LOAD_REC_OPC | (__off_hi))); \
} while (0)
#else
# define ASM_SAVE_GREG_V5(__addr_lo, __addr_hi, numlo, numhi)	\
do { \
	__no_asm_inline(1) \
	asm (	".push_iset 5\n" \
		/* CPU_HWBUG_TAGGED_STRQP */ \
		"{strqp,2,sm [ %[addr_lo] + %[opc] ], %%dg" #numlo "\n" \
		" strqp,5,sm [ %[addr_hi] + %[opc] ], %%dg" #numhi "}\n" \
		".pop_iset\n" \
		: [addr_lo] "=m" (*(__uint128_t *) (__addr_lo)), \
		  [addr_hi] "=m" (*(__uint128_t *) (__addr_hi)) \
		: [opc] "i" (TAGGED_MEM_STORE_REC_OPC)); \
} while (0)

# define ASM_RESTORE_GREG_V5(__addr, __off_lo, __off_hi, numlo, numhi) \
do { \
	u64 reg0, reg1; \
	__no_asm_inline(1) \
	asm (	".push_iset 5\n" \
		"{ldrqp,2 [ %[addr] + %[opc_lo] ], %%dg" #numlo "\n" \
		" ldrqp,5 [ %[addr] + %[opc_hi] ], %%dg" #numhi "}\n" \
		".pop_iset\n" \
		: [reg0] "=&r" (reg0),	[reg1] "=&r" (reg1) \
		: [addr] "r" (__addr), \
		  [opc_lo] "i" (TAGGED_MEM_LOAD_REC_OPC | (__off_lo)), \
		  [opc_hi] "i" (TAGGED_MEM_LOAD_REC_OPC | (__off_hi)) \
		: "%g" #numlo, "%g" #numhi); \
} while (0)
#endif

#define ASM_SAVE_GREG(__addr_lo, __addr_hi, numlo, numhi, iset) \
do { \
	switch (iset) { \
	case E2K_ISET_V3: \
		ASM_SAVE_GREG_V3(__addr_lo, __addr_hi, numlo, numhi); \
		break; \
	case E2K_ISET_V5: \
		ASM_SAVE_GREG_V5(__addr_lo, __addr_hi, numlo, numhi); \
		break; \
	default: \
		BUILD_BUG_ON(1); \
	} \
} while (0)

#define ASM_RESTORE_GREG(__addr, __off_lo, __off_hi, numlo, numhi, iset) \
do { \
	switch (iset) { \
	case E2K_ISET_V3: \
		ASM_RESTORE_GREG_V3(__addr, __off_lo, __off_hi, numlo, numhi); \
		break; \
	case E2K_ISET_V5: \
		ASM_RESTORE_GREG_V5(__addr, __off_lo, __off_hi, numlo, numhi); \
		break; \
	default: \
		BUILD_BUG_ON(1); \
	} \
} while (0)

#define NATIVE_SAVE_GREG(__addr_lo, __addr_hi, numlo, numhi, iset) \
	ASM_SAVE_GREG(__addr_lo, __addr_hi, numlo, numhi, iset)
#define NATIVE_RESTORE_GREG(__addr, __off_lo, __off_hi, numlo, numhi, iset) \
	ASM_RESTORE_GREG(__addr, __off_lo, __off_hi, numlo, numhi, iset)

/* API to save/restore single gregs (words to qpwords). Used by soft_pm. */

#define ASM_SAVE_SINGLE_GREG_V3(__addr, num)                                \
	({                                                                  \
		u64 reg0;                                                   \
		asm("strd,2 [ %[addr] + %[opc_0] ], %%dg" #num "\n"         \
		    "movfi %%dg" #num ", %[reg0]\n"                         \
		    "sth [ %[addr] + 8 ], %[reg0]\n"                        \
		    : [reg0] "=&r"(reg0)                                    \
		    : [addr] "r"(__addr), [opc_0] "i"(                      \
						  TAGGED_MEM_STORE_REC_OPC) \
		    : "memory");                                            \
	})

#if __iset__ >= 5

#define ASM_SAVE_SINGLE_GREG_V5(__addr, num) \
do { \
	register u64 __g __asm__("%g" #num); \
	/* CPU_HWBUG_TAGGED_STRQP: close this asm because \
	 * 'sm' for 'strqp' is not supported by lcc */ \
	__asm_length(1) \
	asm(	"{strqp,2,sm [ %[addr] + %[opc] ], %[g]}" \
		: [addr] "=m" (*(__uint128_t *) (__addr)) \
		: [g] "r" (__g) \
		: [opc] "i"(TAGGED_MEM_STORE_REC_OPC)); \
} while (0)

#else

#define ASM_SAVE_SINGLE_GREG_V5(__addr, num)                                \
	do {                                                                \
		__no_asm_inline(1) asm(                                     \
			".push_iset 5\n" /* CPU_HWBUG_TAGGED_STRQP */       \
			"{strqp,2,sm [ %[addr] + %[opc] ], %%dg" #num "}\n" \
			".pop_iset\n"                                       \
			: [addr] "=m"(*(__uint128_t *)(__addr))             \
			: [opc] "i"(TAGGED_MEM_STORE_REC_OPC));             \
	} while (0)

#endif

#define ASM_RESTORE_SINGLE_GREG_V3(__addr, num)                               \
	do {                                                                  \
		u64 reg0, reg2;                                               \
		asm("ldrd,2 [ %[addr] + %[opc] ], %%dg" #num "\n"             \
		    "ldh [ %[addr] + %[off_8] ], %[reg0]\n"                   \
		    "gettagd %%dg" #num ", %[reg2]\n"                         \
		    "cmpesb 0, %[reg2], %%pred2\n"                            \
		    "movif %%dg" #num ", %[reg0], %%dg" #num " ? %%pred2\n"   \
		    : [reg0] "=&r"(reg0), [reg2] "=&r"(reg2)                  \
		    : [addr] "r"(__addr), [opc] "i"(TAGGED_MEM_LOAD_REC_OPC), \
		      [off_8] "i"(8)                                          \
		    : "%g" #num, "%pred2");                                   \
	} while (0)

#if __iset__ >= 5

#define ASM_RESTORE_SINGLE_GREG_V5(__addr, num)                              \
	do {                                                                 \
		asm("ldrqp,2 [ %[addr] + %[opc] ], %%dg" #num "\n"           \
		    :                                                        \
		    : [addr] "r"(__addr), [opc] "i"(TAGGED_MEM_LOAD_REC_OPC) \
		    : "%g" #num);                                            \
	} while (0)

#else

#define ASM_RESTORE_SINGLE_GREG_V5(__addr, num)                          \
	do {                                                             \
		__no_asm_inline(1) asm(                                  \
			".push_iset 5\n"                                 \
			"{ldrqp,2 [ %[addr] + %[opc] ], %%dg" #num "}\n" \
			".pop_iset\n"                                    \
			:                                                \
			: [addr] "r"(__addr),                            \
			  [opc] "i"(TAGGED_MEM_LOAD_REC_OPC)             \
			: "%g" #num);                                    \
	} while (0)

#endif

#define ASM_SAVE_SINGLE_GREG(__addr, num, iset)               \
	do {                                                  \
		switch (iset) {                               \
		case E2K_ISET_V3:                             \
		case E2K_ISET_V4:                             \
			ASM_SAVE_SINGLE_GREG_V3(__addr, num); \
			break;                                \
		case E2K_ISET_V5:                             \
		case E2K_ISET_V6:                             \
			ASM_SAVE_SINGLE_GREG_V5(__addr, num); \
			break;                                \
		default:                                      \
			BUG();                                \
		}                                             \
	} while (0)

#define NATIVE_SAVE_SINGLE_GREG(__addr, num, iset) \
	ASM_SAVE_SINGLE_GREG(__addr, num, iset)

#define ASM_RESTORE_SINGLE_GREG(__addr, num, iset)               \
	do {                                                     \
		switch (iset) {                                  \
		case E2K_ISET_V3:                                \
		case E2K_ISET_V4:                                \
			ASM_RESTORE_SINGLE_GREG_V3(__addr, num); \
			break;                                   \
		case E2K_ISET_V5:                                \
		case E2K_ISET_V6:                                \
			ASM_RESTORE_SINGLE_GREG_V5(__addr, num); \
			break;                                   \
		default:                                         \
			BUG();                                   \
		}                                                \
	} while (0)

#define NATIVE_RESTORE_SINGLE_GREG(__addr, num, iset) \
	ASM_RESTORE_SINGLE_GREG(__addr, num, iset)

#define ASM_SAVE_SINGLE_GREG_VAR(__addr, greg_num, iset)                   \
	({                                                                 \
		switch (greg_num) {                                        \
		case 0:                                                    \
			ASM_SAVE_SINGLE_GREG(__addr, 0, iset);             \
			break;                                             \
		case 1:                                                    \
			ASM_SAVE_SINGLE_GREG(__addr, 1, iset);             \
			break;                                             \
		case 2:                                                    \
			ASM_SAVE_SINGLE_GREG(__addr, 2, iset);             \
			break;                                             \
		case 3:                                                    \
			ASM_SAVE_SINGLE_GREG(__addr, 3, iset);             \
			break;                                             \
		case 4:                                                    \
			ASM_SAVE_SINGLE_GREG(__addr, 4, iset);             \
			break;                                             \
		case 5:                                                    \
			ASM_SAVE_SINGLE_GREG(__addr, 5, iset);             \
			break;                                             \
		case 6:                                                    \
			ASM_SAVE_SINGLE_GREG(__addr, 6, iset);             \
			break;                                             \
		case 7:                                                    \
			ASM_SAVE_SINGLE_GREG(__addr, 7, iset);             \
			break;                                             \
		case 8:                                                    \
			ASM_SAVE_SINGLE_GREG(__addr, 8, iset);             \
			break;                                             \
		case 9:                                                    \
			ASM_SAVE_SINGLE_GREG(__addr, 9, iset);             \
			break;                                             \
		case 10:                                                   \
			ASM_SAVE_SINGLE_GREG(__addr, 10, iset);            \
			break;                                             \
		case 11:                                                   \
			ASM_SAVE_SINGLE_GREG(__addr, 11, iset);            \
			break;                                             \
		case 12:                                                   \
			ASM_SAVE_SINGLE_GREG(__addr, 12, iset);            \
			break;                                             \
		case 13:                                                   \
			ASM_SAVE_SINGLE_GREG(__addr, 13, iset);            \
			break;                                             \
		case 14:                                                   \
			ASM_SAVE_SINGLE_GREG(__addr, 14, iset);            \
			break;                                             \
		case 15:                                                   \
			ASM_SAVE_SINGLE_GREG(__addr, 15, iset);            \
			break;                                             \
		case 16:                                                   \
			ASM_SAVE_SINGLE_GREG(__addr, 16, iset);            \
			break;                                             \
		case 17:                                                   \
			ASM_SAVE_SINGLE_GREG(__addr, 17, iset);            \
			break;                                             \
		case 18:                                                   \
			ASM_SAVE_SINGLE_GREG(__addr, 18, iset);            \
			break;                                             \
		case 19:                                                   \
			ASM_SAVE_SINGLE_GREG(__addr, 19, iset);            \
			break;                                             \
		case 20:                                                   \
			ASM_SAVE_SINGLE_GREG(__addr, 20, iset);            \
			break;                                             \
		case 21:                                                   \
			ASM_SAVE_SINGLE_GREG(__addr, 21, iset);            \
			break;                                             \
		case 22:                                                   \
			ASM_SAVE_SINGLE_GREG(__addr, 22, iset);            \
			break;                                             \
		case 23:                                                   \
			ASM_SAVE_SINGLE_GREG(__addr, 23, iset);            \
			break;                                             \
		case 24:                                                   \
			ASM_SAVE_SINGLE_GREG(__addr, 24, iset);            \
			break;                                             \
		case 25:                                                   \
			ASM_SAVE_SINGLE_GREG(__addr, 25, iset);            \
			break;                                             \
		case 26:                                                   \
			ASM_SAVE_SINGLE_GREG(__addr, 26, iset);            \
			break;                                             \
		case 27:                                                   \
			ASM_SAVE_SINGLE_GREG(__addr, 27, iset);            \
			break;                                             \
		case 28:                                                   \
			ASM_SAVE_SINGLE_GREG(__addr, 28, iset);            \
			break;                                             \
		case 29:                                                   \
			ASM_SAVE_SINGLE_GREG(__addr, 29, iset);            \
			break;                                             \
		case 30:                                                   \
			ASM_SAVE_SINGLE_GREG(__addr, 30, iset);            \
			break;                                             \
		case 31:                                                   \
			ASM_SAVE_SINGLE_GREG(__addr, 31, iset);            \
			break;                                             \
		default:                                                   \
			panic("Invalid global register # %d\n", greg_num); \
		}                                                          \
	})

#define ASM_RESTORE_SINGLE_GREG_VAR(__addr, greg_num, iset)                \
	({                                                                 \
		switch (greg_num) {                                        \
		case 0:                                                    \
			ASM_RESTORE_SINGLE_GREG(__addr, 0, iset);          \
			break;                                             \
		case 1:                                                    \
			ASM_RESTORE_SINGLE_GREG(__addr, 1, iset);          \
			break;                                             \
		case 2:                                                    \
			ASM_RESTORE_SINGLE_GREG(__addr, 2, iset);          \
			break;                                             \
		case 3:                                                    \
			ASM_RESTORE_SINGLE_GREG(__addr, 3, iset);          \
			break;                                             \
		case 4:                                                    \
			ASM_RESTORE_SINGLE_GREG(__addr, 4, iset);          \
			break;                                             \
		case 5:                                                    \
			ASM_RESTORE_SINGLE_GREG(__addr, 5, iset);          \
			break;                                             \
		case 6:                                                    \
			ASM_RESTORE_SINGLE_GREG(__addr, 6, iset);          \
			break;                                             \
		case 7:                                                    \
			ASM_RESTORE_SINGLE_GREG(__addr, 7, iset);          \
			break;                                             \
		case 8:                                                    \
			ASM_RESTORE_SINGLE_GREG(__addr, 8, iset);          \
			break;                                             \
		case 9:                                                    \
			ASM_RESTORE_SINGLE_GREG(__addr, 9, iset);          \
			break;                                             \
		case 10:                                                   \
			ASM_RESTORE_SINGLE_GREG(__addr, 10, iset);         \
			break;                                             \
		case 11:                                                   \
			ASM_RESTORE_SINGLE_GREG(__addr, 11, iset);         \
			break;                                             \
		case 12:                                                   \
			ASM_RESTORE_SINGLE_GREG(__addr, 12, iset);         \
			break;                                             \
		case 13:                                                   \
			ASM_RESTORE_SINGLE_GREG(__addr, 13, iset);         \
			break;                                             \
		case 14:                                                   \
			ASM_RESTORE_SINGLE_GREG(__addr, 14, iset);         \
			break;                                             \
		case 15:                                                   \
			ASM_RESTORE_SINGLE_GREG(__addr, 15, iset);         \
			break;                                             \
		case 16:                                                   \
			ASM_RESTORE_SINGLE_GREG(__addr, 16, iset);         \
			break;                                             \
		case 17:                                                   \
			ASM_RESTORE_SINGLE_GREG(__addr, 17, iset);         \
			break;                                             \
		case 18:                                                   \
			ASM_RESTORE_SINGLE_GREG(__addr, 18, iset);         \
			break;                                             \
		case 19:                                                   \
			ASM_RESTORE_SINGLE_GREG(__addr, 19, iset);         \
			break;                                             \
		case 20:                                                   \
			ASM_RESTORE_SINGLE_GREG(__addr, 20, iset);         \
			break;                                             \
		case 21:                                                   \
			ASM_RESTORE_SINGLE_GREG(__addr, 21, iset);         \
			break;                                             \
		case 22:                                                   \
			ASM_RESTORE_SINGLE_GREG(__addr, 22, iset);         \
			break;                                             \
		case 23:                                                   \
			ASM_RESTORE_SINGLE_GREG(__addr, 23, iset);         \
			break;                                             \
		case 24:                                                   \
			ASM_RESTORE_SINGLE_GREG(__addr, 24, iset);         \
			break;                                             \
		case 25:                                                   \
			ASM_RESTORE_SINGLE_GREG(__addr, 25, iset);         \
			break;                                             \
		case 26:                                                   \
			ASM_RESTORE_SINGLE_GREG(__addr, 26, iset);         \
			break;                                             \
		case 27:                                                   \
			ASM_RESTORE_SINGLE_GREG(__addr, 27, iset);         \
			break;                                             \
		case 28:                                                   \
			ASM_RESTORE_SINGLE_GREG(__addr, 28, iset);         \
			break;                                             \
		case 29:                                                   \
			ASM_RESTORE_SINGLE_GREG(__addr, 29, iset);         \
			break;                                             \
		case 30:                                                   \
			ASM_RESTORE_SINGLE_GREG(__addr, 30, iset);         \
			break;                                             \
		case 31:                                                   \
			ASM_RESTORE_SINGLE_GREG(__addr, 31, iset);         \
			break;                                             \
		default:                                                   \
			panic("Invalid global register # %d\n", greg_num); \
		}                                                          \
	})

#define NATIVE_SAVE_SINGLE_GREG_VAR(__addr, num, iset) \
	ASM_SAVE_SINGLE_GREG_VAR(__addr, num, iset)

#define NATIVE_RESTORE_SINGLE_GREG_VAR(__addr, num, iset) \
	ASM_RESTORE_SINGLE_GREG_VAR(__addr, num, iset)

/* end of API to save/restore single gregs */

#if __iset__ >= 5
# define CLEAR_GLOBAL_QP_GREGS() \
do { \
	u64 __cl_qp_value; \
	asm (	"qppackdl 0, 0, %[value]\n" \
		"puttagqp %[value], %[tag], %%dg0\n" \
		"puttagqp %[value], %[tag], %%dg1\n" \
		"puttagqp %[value], %[tag], %%dg2\n" \
		"puttagqp %[value], %[tag], %%dg3\n" \
		"puttagqp %[value], %[tag], %%dg4\n" \
		"puttagqp %[value], %[tag], %%dg5\n" \
		"puttagqp %[value], %[tag], %%dg6\n" \
		"puttagqp %[value], %[tag], %%dg7\n" \
		"puttagqp %[value], %[tag], %%dg8\n" \
		"puttagqp %[value], %[tag], %%dg9\n" \
		"puttagqp %[value], %[tag], %%dg10\n" \
		"puttagqp %[value], %[tag], %%dg11\n" \
		"puttagqp %[value], %[tag], %%dg12\n" \
		"puttagqp %[value], %[tag], %%dg13\n" \
		"puttagqp %[value], %[tag], %%dg14\n" \
		"puttagqp %[value], %[tag], %%dg15\n" \
		: [value] "=&r" (__cl_qp_value) \
		: [tag] "ri" ((u32) ETAGEWQP) \
		: "%g0", "%g1", "%g2", "%g3", "%g4", "%g5", "%g6", "%g7", \
		  "%g8", "%g9", "%g10", "%g11", "%g12", "%g13", "%g14", "%g15"); \
} while (0)

# define CLEAR_LOCAL_QP_GREGS() \
do { \
	u64 __cl_qp_value; \
	asm (	"qppackdl 0, 0, %[value]\n" \
		"puttagqp %[value], %[tag], %%qpg16\n" \
		"puttagqp %[value], %[tag], %%qpg17\n" \
		"puttagqp %[value], %[tag], %%qpg18\n" \
		"puttagqp %[value], %[tag], %%qpg19\n" \
		"puttagqp %[value], %[tag], %%qpg20\n" \
		"puttagqp %[value], %[tag], %%qpg21\n" \
		"puttagqp %[value], %[tag], %%qpg22\n" \
		"puttagqp %[value], %[tag], %%qpg23\n" \
		"puttagqp %[value], %[tag], %%qpg24\n" \
		"puttagqp %[value], %[tag], %%qpg25\n" \
		"puttagqp %[value], %[tag], %%qpg26\n" \
		"puttagqp %[value], %[tag], %%qpg27\n" \
		"puttagqp %[value], %[tag], %%qpg28\n" \
		"puttagqp %[value], %[tag], %%qpg29\n" \
		"puttagqp %[value], %[tag], %%qpg30\n" \
		"puttagqp %[value], %[tag], %%qpg31\n" \
		: [value] "=&r" (__cl_qp_value) \
		: [tag] "ri" ((u32) ETAGEWQP) \
		: "%g16", "%g17", "%g18", "%g19", "%g20", "%g21", "%g22", "%g23", \
		  "%g24", "%g25", "%g26", "%g27", "%g28", "%g29", "%g30", "%g31"); \
} while (0)
#else
# define CLEAR_GLOBAL_QP_GREGS() \
do { \
	u64 __cl_qp_value; \
	__no_asm_inline(8) \
	asm (	".push_iset 5\n" \
		"{nop 3\n" \
		" qppackdl,sm 0, 0, %[value]}\n" \
		"{puttagqp %[value], %[tag], %%dg0\n" \
		" puttagqp %[value], %[tag], %%dg1\n" \
		" puttagqp %[value], %[tag], %%dg2\n" \
		" puttagqp %[value], %[tag], %%dg3}\n" \
		"{puttagqp %[value], %[tag], %%dg4\n" \
		" puttagqp %[value], %[tag], %%dg5\n" \
		" puttagqp %[value], %[tag], %%dg6\n" \
		" puttagqp %[value], %[tag], %%dg7}\n" \
		"{puttagqp %[value], %[tag], %%dg8\n" \
		" puttagqp %[value], %[tag], %%dg9\n" \
		" puttagqp %[value], %[tag], %%dg10\n" \
		" puttagqp %[value], %[tag], %%dg11}\n" \
		"{puttagqp %[value], %[tag], %%dg12\n" \
		" puttagqp %[value], %[tag], %%dg13\n" \
		" puttagqp %[value], %[tag], %%dg14\n" \
		" puttagqp %[value], %[tag], %%dg15}\n" \
		".pop_iset\n" \
		: [value] "=&r" (__cl_qp_value) \
		: [tag] "ri" ((u32) ETAGEWQP) \
		: "%g0", "%g1", "%g2", "%g3", "%g4", "%g5", "%g6", "%g7", \
		  "%g8", "%g9", "%g10", "%g11", "%g12", "%g13", "%g14", "%g15"); \
} while (0)

# define CLEAR_LOCAL_QP_GREGS() \
do { \
	u64 __cl_qp_value; \
	__no_asm_inline(8) \
	asm (	".push_iset 5\n" \
		"{nop 3\n" \
		" qppackdl,sm 0, 0, %[value]}\n" \
		"{puttagqp %[value], %[tag], %%dg16\n" \
		" puttagqp %[value], %[tag], %%dg17\n" \
		" puttagqp %[value], %[tag], %%dg18\n" \
		" puttagqp %[value], %[tag], %%dg19}\n" \
		"{puttagqp %[value], %[tag], %%dg20\n" \
		" puttagqp %[value], %[tag], %%dg21\n " \
		" puttagqp %[value], %[tag], %%dg22\n" \
		" puttagqp %[value], %[tag], %%dg23}\n" \
		"{puttagqp %[value], %[tag], %%dg24\n" \
		" puttagqp %[value], %[tag], %%dg25\n" \
		" puttagqp %[value], %[tag], %%dg26\n" \
		" puttagqp %[value], %[tag], %%dg27}\n" \
		"{puttagqp %[value], %[tag], %%dg28\n" \
		" puttagqp %[value], %[tag], %%dg29\n" \
		" puttagqp %[value], %[tag], %%dg30\n" \
		" puttagqp %[value], %[tag], %%dg31}\n" \
		".pop_iset\n" \
		: [value] "=&r" (__cl_qp_value) \
		: [tag] "ri" ((u32) ETAGEWQP) \
		: "%g16", "%g17", "%g18", "%g19", "%g20", "%g21", "%g22", "%g23", \
		  "%g24", "%g25", "%g26", "%g27", "%g28", "%g29", "%g30", "%g31"); \
} while (0)
#endif

#define CLEAR_GLOBAL_Q_GREGS() \
do { \
	u64 __cl_q_unused; \
	asm (	"puttagd 0, %[tag], %%dg0\n" \
		"puttagd 0, %[tag], %%dg1\n" \
		"puttagd 0, %[tag], %%dg2\n" \
		"puttagd 0, %[tag], %%dg3\n" \
		"puttagd 0, %[tag], %%dg4\n" \
		"puttagd 0, %[tag], %%dg5\n" \
		"puttagd 0, %[tag], %%dg6\n" \
		"puttagd 0, %[tag], %%dg7\n" \
		"puttagd 0, %[tag], %%dg8\n" \
		"puttagd 0, %[tag], %%dg9\n" \
		"puttagd 0, %[tag], %%dg10\n" \
		"puttagd 0, %[tag], %%dg11\n" \
		"puttagd 0, %[tag], %%dg12\n" \
		"puttagd 0, %[tag], %%dg13\n" \
		"puttagd 0, %[tag], %%dg14\n" \
		"puttagd 0, %[tag], %%dg15\n" \
		: "=r" (__cl_q_unused) \
		: [tag] "ri" ((u32) ETAGEWD) \
		: "%g0", "%g1", "%g2", "%g3", "%g4", "%g5", "%g6", "%g7", \
		  "%g8", "%g9", "%g10", "%g11", "%g12", "%g13", "%g14", "%g15"); \
} while (0)

#define CLEAR_LOCAL_Q_GREGS() \
do { \
	u64 __cl_q_unused; \
	asm (	"puttagd 0, %[tag], %%dg16\n" \
		"puttagd 0, %[tag], %%dg17\n" \
		"puttagd 0, %[tag], %%dg18\n" \
		"puttagd 0, %[tag], %%dg19\n" \
		"puttagd 0, %[tag], %%dg20\n" \
		"puttagd 0, %[tag], %%dg21\n" \
		"puttagd 0, %[tag], %%dg22\n" \
		"puttagd 0, %[tag], %%dg23\n" \
		"puttagd 0, %[tag], %%dg24\n" \
		"puttagd 0, %[tag], %%dg25\n" \
		"puttagd 0, %[tag], %%dg26\n" \
		"puttagd 0, %[tag], %%dg27\n" \
		"puttagd 0, %[tag], %%dg28\n" \
		"puttagd 0, %[tag], %%dg29\n" \
		"puttagd 0, %[tag], %%dg30\n" \
		"puttagd 0, %[tag], %%dg31\n" \
		: "=r" (__cl_q_unused) \
		: [tag] "ri" ((u32) ETAGEWD) \
		: "%g16", "%g17", "%g18", "%g19", "%g20", "%g21", "%g22", "%g23", \
		  "%g24", "%g25", "%g26", "%g27", "%g28", "%g29", "%g30", "%g31"); \
} while (0)

#define NATIVE_SET_GREGS_EMPTY(global, local) \
do { \
	if (cpu_has(CPU_FEAT_QPREG)) { \
		if (global) \
			CLEAR_GLOBAL_QP_GREGS(); \
		if (local) \
			CLEAR_LOCAL_QP_GREGS(); \
	} else { \
		if (global) \
			CLEAR_GLOBAL_Q_GREGS(); \
		if (local) \
			CLEAR_LOCAL_Q_GREGS(); \
	} \
} while (0)

/*
 * We copy the value,tag and extension for all global regs
 * (we must copy all componets of register with bad tags too)
 */
#define	E2K_GET_GREGS_FROM_THREAD(_g_u, _gt_u, _base)			\
({									\
	u64 reg0, reg1, reg2, reg3, reg6, reg7, reg8;			\
									\
	asm (								\
		"addd %[base], 0x0, %[r6]\n"				\
		"addd 0, 0x0, %[r7]\n"					\
		"addd 0, 0x0, %[r8]\n"					\
									\
		"1:\n"							\
		"ldrd,2 [%[r6] + %[opc_0]], %[val_lo]\n"		\
		"ldrd,5 [%[r6] + %[opc_16]], %[val_hi]\n"		\
		"addd %[r6], 32, %[r6]\n"				\
									\
		"gettagd,2 %[val_lo], %[tag_lo]\n"			\
		"gettagd,5 %[val_hi], %[tag_hi]\n"			\
		"shls %[tag_hi], 8, %[tag_hi]\n"			\
		"ors %[tag_lo], %[tag_hi], %[tag_lo]\n"			\
		"sth [%[gt_u], %[r8]], %[tag_lo]\n"			\
		"addd %[r8], 2, %[r8]\n"				\
									\
		"puttagd,2 %[val_lo], 0, %[val_lo]\n"			\
		"std [%[g_u], %[r7]], %[val_lo]\n"			\
		"addd %[r7], 8, %[r7]\n"				\
									\
		"puttagd,5 %[val_hi], 0, %[val_hi]\n"			\
		"std [%[g_u], %[r7]], %[val_hi]\n"			\
		"addd %[r7], 8, %[r7]\n"				\
									\
		"disp %%ctpr3, 1b\n"					\
		"cmpedb %[r8], 32, %%pred2\n"				\
		"ct %%ctpr3 ? ~ %%pred2\n"				\
									\
		: [val_lo] "=&r"(reg0), [val_hi] "=&r"(reg1),		\
		  [tag_lo] "=&r"(reg2), [tag_hi] "=&r"(reg3),		\
		  [r6] "=&r"(reg6), [r7] "=&r"(reg7), [r8] "=&r"(reg8)	\
		: [g_u] "r"(_g_u), [gt_u] "r"(_gt_u), [base] "r"(_base),\
		  [opc_0] "i" (TAGGED_MEM_LOAD_REC_OPC),		\
		  [opc_16] "i" (TAGGED_MEM_LOAD_REC_OPC | 16UL)		\
		: "%ctpr3", "%pred1", "%pred2", "memory");		\
})

#define	E2K_SET_GREGS_TO_THREAD(_base, _g_u, _gt_u)			\
({									\
	u64 reg0, reg1, reg2, reg3, reg6, reg7, reg8;			\
									\
	asm (								\
		"addd 0, 0x0, %[r6]\n"					\
		"addd 0, 0x0, %[r7]\n"					\
		"addd %[base], 0x0, %[r8]\n"				\
									\
		"2:\n"							\
		"ldd [%[g_u], %[r6]], %[val_lo]\n"			\
		"addd %[r6], 8, %[r6]\n"				\
		"ldd [%[g_u], %[r6]], %[val_hi]\n"			\
		"addd %[r6], 8, %[r6]\n"				\
									\
		"ldb [%[gt_u], %[r7]], %[tag_lo]\n"			\
		"addd %[r7], 1, %[r7]\n"				\
		"ldb [%[gt_u], %[r7]], %[tag_hi]\n"			\
		"addd %[r7], 1, %[r7]\n"				\
									\
		"puttagd,2 %[val_lo], %[tag_lo], %[val_lo]\n"		\
		"puttagd,5 %[val_hi], %[tag_hi], %[val_hi]\n"		\
									\
		"strd,2 [%[r8] + %[opc_0]], %[val_lo]\n"		\
		"strd,5 [%[r8] + %[opc_16]], %[val_hi]\n"		\
		"addd %[r8], 32, %[r8]\n"				\
									\
		"disp %%ctpr3, 2b\n"					\
									\
		"cmpedb %[r7], 32, %%pred2\n"				\
		"ct %%ctpr3 ? ~ %%pred2\n"				\
									\
		: [val_lo] "=&r"(reg0), [val_hi] "=&r"(reg1),		\
		  [tag_lo] "=&r"(reg2), [tag_hi] "=&r"(reg3),		\
		  [r6] "=&r"(reg6), [r7] "=&r"(reg7), [r8] "=&r"(reg8)	\
		: [base] "r"(_base), [g_u] "r"(_g_u), [gt_u] "r"(_gt_u),\
		  [opc_0] "i" (TAGGED_MEM_STORE_REC_OPC),		\
		  [opc_16] "i" (TAGGED_MEM_STORE_REC_OPC | 16UL)	\
		: "%ctpr3", "%pred2", "memory");			\
})

#define	E2K_GET_GREG_FROM_THREAD(_g_u, _gt_u, _base) \
do { \
	u64 reg0, reg1, reg2, reg3; \
 \
	asm ( \
		"ldrd,2 [%[base] + %[opc_0]], %[val_lo]\n" \
		"ldrd,5 [%[base] + %[opc_16]], %[val_hi]\n" \
 \
		"gettagd,2 %[val_lo], %[tag_lo]\n" \
		"gettagd,5 %[val_hi], %[tag_hi]\n" \
		"shls %[tag_hi], 8, %[tag_hi]\n" \
		"ors %[tag_lo], %[tag_hi], %[tag_lo]\n" \
		"sth [%[gt_u], 0], %[tag_lo]\n" \
 \
		"puttagd,2 %[val_lo], 0, %[val_lo]\n" \
		"puttagd,5 %[val_hi], 0, %[val_hi]\n" \
 \
		"std [%[g_u], 0], %[val_lo]\n" \
		"std [%[g_u], 8], %[val_hi]\n" \
		: [val_lo] "=&r"(reg0), [val_hi] "=&r"(reg1), \
		  [tag_lo] "=&r"(reg2), [tag_hi] "=&r"(reg3) \
		: [g_u] "r"(_g_u), [gt_u] "r"(_gt_u), [base] "r"(_base), \
		  [opc_0] "i" (TAGGED_MEM_LOAD_REC_OPC), \
		  [opc_16] "i" (TAGGED_MEM_LOAD_REC_OPC | 16UL) \
		: "%ctpr3", "memory"); \
} while (0)

#define	E2K_SET_GREGS_TO_THREAD(_base, _g_u, _gt_u)			\
({									\
	u64 reg0, reg1, reg2, reg3, reg6, reg7, reg8;			\
									\
	asm (								\
		"addd 0, 0x0, %[r6]\n"					\
		"addd 0, 0x0, %[r7]\n"					\
		"addd %[base], 0x0, %[r8]\n"				\
									\
		"2:\n"							\
		"ldd [%[g_u], %[r6]], %[val_lo]\n"			\
		"addd %[r6], 8, %[r6]\n"				\
		"ldd [%[g_u], %[r6]], %[val_hi]\n"			\
		"addd %[r6], 8, %[r6]\n"				\
									\
		"ldb [%[gt_u], %[r7]], %[tag_lo]\n"			\
		"addd %[r7], 1, %[r7]\n"				\
		"ldb [%[gt_u], %[r7]], %[tag_hi]\n"			\
		"addd %[r7], 1, %[r7]\n"				\
									\
		"puttagd,2 %[val_lo], %[tag_lo], %[val_lo]\n"		\
		"puttagd,5 %[val_hi], %[tag_hi], %[val_hi]\n"		\
									\
		"strd,2 [%[r8] + %[opc_0]], %[val_lo]\n"		\
		"strd,5 [%[r8] + %[opc_16]], %[val_hi]\n"		\
		"addd %[r8], 32, %[r8]\n"				\
									\
		"disp %%ctpr3, 2b\n"					\
									\
		"cmpedb %[r7], 32, %%pred2\n"				\
		"ct %%ctpr3 ? ~ %%pred2\n"				\
									\
		: [val_lo] "=&r"(reg0), [val_hi] "=&r"(reg1),		\
		  [tag_lo] "=&r"(reg2), [tag_hi] "=&r"(reg3),		\
		  [r6] "=&r"(reg6), [r7] "=&r"(reg7), [r8] "=&r"(reg8)	\
		: [base] "r"(_base), [g_u] "r"(_g_u), [gt_u] "r"(_gt_u),\
		  [opc_0] "i" (TAGGED_MEM_STORE_REC_OPC),		\
		  [opc_16] "i" (TAGGED_MEM_STORE_REC_OPC | 16UL)	\
		: "%ctpr3", "%pred2", "memory");			\
})

#define	E2K_MOVE_DGREG_TO_DREG(greg_no, local_reg)			\
do {									\
	__no_asm_inline(1) \
	asm volatile ("movtd \t%%dg" #greg_no ", %0"			\
			: "=&r" (local_reg));				\
} while (0)

#define	E2K_MOVE_DREG_TO_DGREG(greg_no, local_reg)			\
do {									\
	__no_asm_inline(1) \
	asm volatile ("movtd \t%0, %%dg" #greg_no			\
			:						\
			: "r" ((u64) (local_reg)));		\
} while (0)

/*
 * We have following macros for registers reading/writing:
 *
 * NATIVE_GET_[DS]REG_OPEN() - read register supported by compiler
 * NATIVE_GET_[DS]REG_CLOSED() - read register
 *
 * NATIVE_SET_[DS]REG_NOEXC() - write register when it is
 *	_not_ listed in exceptions list in 1.1.1 1) of "Scheduling"
 * NATIVE_SET_[DS]REG_EXC() - write register when it _is_
 *	listed in exceptions list in 1.1.1 1) of "Scheduling"
 */

#define NATIVE_GET_REG_OPEN(reg, type, size_letter) \
({ \
	type _res; \
	asm ("rr" #size_letter " %%" #reg ", %0" : "=r" (_res)); \
	_res; \
})
/* Read register supported by compiler (see -masm-inline) */
#define NATIVE_GET_SREG_OPEN(reg) NATIVE_GET_REG_OPEN(reg, u32, s)
/* Read register supported by compiler (see -masm-inline) */
#define NATIVE_GET_DREG_OPEN(reg) NATIVE_GET_REG_OPEN(reg, u64, d)


/*
 * Keep "volatile" since some of those registers can have side effects
 * (for example, see %dibsr reading in arch/e2k/kernel/perf_event.c -
 * it must be done before reading %dimar; or look at %clkr).
 */
#define NATIVE_GET_REG_CLOSED(iset, reg, type, size_letter, clobbers...) \
({ \
	register type _res; \
	__no_asm_inline(1) \
	asm volatile ( \
		".push_iset " #iset "\n" \
		"rr" #size_letter " %%" #reg ", %[res]\n" \
		".pop_iset\n" \
		: [res] "=r" (_res) \
		: \
		: clobbers); \
	_res; \
})
#define NATIVE_GET_SREG_CLOSED_ISET(iset, reg, clobbers...) \
	NATIVE_GET_REG_CLOSED(iset, reg, u32, s ,##clobbers)
#define NATIVE_GET_DREG_CLOSED_ISET(iset, reg, clobbers...) \
	NATIVE_GET_REG_CLOSED(iset, reg, u64, d ,##clobbers)
#define NATIVE_GET_SREG_CLOSED(reg, clobbers...) \
	NATIVE_GET_SREG_CLOSED_ISET(3, reg ,##clobbers)
#define NATIVE_GET_DREG_CLOSED(reg, clobbers...) \
	NATIVE_GET_DREG_CLOSED_ISET(3, reg ,##clobbers)


/*
 * According to "Scheduling 1.1.1", the next 3 long instructions
 * after the write must not generate delayed exceptions, and the next
 * 4 long instruction must not generate exact exceptions. So add nops
 * after the write.
 *
 * This is slow but this version is used only for rarely written registers.
 * %usd/%psp/etc registers are supported by lcc and are written with an
 * open GNU asm.
 */

#define NATIVE_SET_REG_NOEXC(iset, reg, _val, type, size_letter, clobbers...) \
do { \
	__no_asm_inline(5) \
	asm volatile (".push_iset " #iset "\n" \
		      "{rw" #size_letter " %[val], %%" #reg "}\n" \
		      ".pop_iset\n" \
		      "{nop} {nop} {nop}" \
		      "{wait all_e=1}" \
		      : \
		      : [val] "ri" ((type) (_val)) \
		      : clobbers); \
} while (0)
/* Write register under "Scheduling 1.1.1.1" rules */
#define NATIVE_SET_SREG_NOEXC(iset, reg, val, clobbers...) \
	NATIVE_SET_REG_NOEXC(iset, reg, (val), u32, s ,##clobbers)
/* Write register under "Scheduling 1.1.1.1" rules */
#define NATIVE_SET_DREG_NOEXC(iset, reg, val, clobbers...) \
	NATIVE_SET_REG_NOEXC(iset, reg, (val), u64, d ,##clobbers)

#define NATIVE_SET_VIRT_CTRL_CU(_val) \
do { \
	__no_asm_inline(5) \
	asm volatile (".push_iset 6\n" \
		      ALTERNATIVE( \
		      /* Default version */ \
			"{rwd %[val], %%virt_ctrl_cu}\n", \
		      /* CPU_HWBUG_RW_VIRT_CTRL_CU version */ \
			"{nop 1;" \
			" rwd %[val], %%virt_ctrl_cu}\n", \
		      %[cpu_hwbug_rw_virt_ctrl_cu]) \
		      ".pop_iset\n" \
		      "{nop} {nop} {nop}" \
		      "{wait all_e=1}" \
		      : \
		      : [val] "ri" ((u64) (_val)), \
			[cpu_hwbug_rw_virt_ctrl_cu] "i" (CPU_HWBUG_RW_VIRT_CTRL_CU)); \
} while (0)

#define NATIVE_SET_REGS_NOEXC(iset, reg1, reg2, _val1, _val2, type, size_letter) \
do { \
	__asm_length(6) \
	asm volatile (".push_iset " #iset "\n" \
		      "{rw" #size_letter " %[val1], %%" #reg1 "}\n"\
		      "{rw" #size_letter " %[val2], %%" #reg2 "}\n"\
		      ".pop_iset \n" \
		      "{nop} {nop} {nop}" \
		      "{wait all_e=1}\n" \
		      : \
		      : [val1] "ri" ((type) (_val1)), \
			[val2] "ri" ((type) (_val2))); \
} while (0)

/* Write registers under "Scheduling 1.1.1.1" rules */
#define NATIVE_SET_SREGS_NOEXC(iset, reg1, reg2, val1, val2) \
	NATIVE_SET_REGS_NOEXC(iset, reg1, reg2, (val1), (val2), u32, s)

/* Write registers under "Scheduling 1.1.1.1" rules */
#define NATIVE_SET_DREGS_NOEXC(iset, reg1, reg2, val1, val2) \
	NATIVE_SET_REGS_NOEXC(iset, reg1, reg2, (val1), (val2), u64, d)


#define NATIVE_SET_REG_EXC(iset, reg, val, type, size_letter, clobbers...) \
do { \
	__asm_length(2) \
	asm volatile (".push_iset " #iset "\n" \
		      "{rw" #size_letter " %0, %%" #reg "}\n" \
		      ".pop_iset \n"  \
		      "{wait all_e=1}" \
		      : \
		      : "ri" ((type) (val)) \
		      : clobbers); \
} while (0)
/* Write register without "Scheduling 1.1.1.1" rules */
#define NATIVE_SET_SREG_EXC(iset, reg, val, clobbers...) \
	NATIVE_SET_REG_EXC(iset, reg, (val), u32, s ,##clobbers)
/* Write register without "Scheduling 1.1.1.1" rules */
#define NATIVE_SET_DREG_EXC(iset, reg, val, clobbers...) \
	NATIVE_SET_REG_EXC(iset, reg, (val), u64, d ,##clobbers)

#define NATIVE_SET_REGS_EXC(iset, reg1, reg2, _val1, _val2, type, size_letter, clobbers...) \
do { \
	__asm_length(3) \
	asm volatile (".push_iset " #iset "\n" \
		      "{rw" #size_letter " %[val1], %%" #reg1 "}\n"\
		      "{rw" #size_letter " %[val2], %%" #reg2 "}\n"\
		      ".pop_iset \n" \
		      "{wait all_e=1}\n" \
		      : \
		      : [val1] "ri" ((type) (_val1)), \
			[val2] "ri" ((type) (_val2)) \
		      : clobbers); \
} while (0)
/* Write registers without "Scheduling 1.1.1.1" rules */
#define NATIVE_SET_SREGS_EXC(iset, reg1, reg2, val1, val2, clobbers...) \
	NATIVE_SET_REGS_EXC(iset, reg1, reg2, (val1), (val2), u32, s ,##clobbers)
/* Write registers without "Scheduling 1.1.1.1" rules */
#define NATIVE_SET_DREGS_EXC(iset, reg1, reg2, val1, val2, clobbers...) \
	NATIVE_SET_REGS_EXC(iset, reg1, reg2, (val1), (val2), u64, d ,##clobbers)

#define NATIVE_SET_3_REGS_EXC(iset, reg1, reg2, reg3, _val1, _val2, _val3, \
			      type, size_letter, clobbers...) \
do { \
	__asm_length(4) \
	asm volatile (".push_iset " #iset "\n" \
		      "{rw" #size_letter " %[val1], %%" #reg1 "}\n"\
		      "{rw" #size_letter " %[val2], %%" #reg2 "}\n"\
		      "{rw" #size_letter " %[val3], %%" #reg3 "}\n"\
		      ".pop_iset \n"	\
		      "{wait all_e=1}\n" \
		      : \
		      : [val1] "ri" ((type) (_val1)), \
			[val2] "ri" ((type) (_val2)), \
			[val3] "ri" ((type) (_val3)) \
		      : clobbers); \
} while (0)
/* Write registers without "Scheduling 1.1.1.1" rules */
#define NATIVE_SET_3_SREGS_EXC(iset, reg1, reg2, reg3, val1, val2, val3, clobbers...) \
	NATIVE_SET_3_REGS_EXC(iset, reg1, reg2, reg3, (val1), (val2), (val3), u32, s ,##clobbers)
/* Write registers without "Scheduling 1.1.1.1" rules */
#define NATIVE_SET_3_DREGS_EXC(iset, reg1, reg2, reg3, val1, val2, val3, clobbers...) \
	NATIVE_SET_3_REGS_EXC(iset, reg1, reg2, reg3, (val1), (val2), (val3), u64, d ,##clobbers)


/* Here to avoid include hell */
#define NATIVE_NV_READ_UPSR_REG_VALUE() NATIVE_GET_DREG_OPEN(upsr)


/*
 * Chain stack registers (%cr) require special handling
 */

#define NATIVE_SET_CR_CLOSED_NOEXC(reg, val) \
do { \
	/* Add ctpr3 clobber to avoid writing \
	 * CRs between `return` and `ct` */ \
	__no_asm_inline(6) \
	asm volatile (	ALTERNATIVE( \
			/* Default version */ \
				"", \
			/* CPU_HWBUG_CR_BEFORE_WRITES version */ \
				"{wait ma_c=1}", \
			%[cpu_hwbug_cr_before_writes]) \
			ALTERNATIVE_2( \
			/* Default version */ \
				"{rwd %[value], %%" #reg "}", \
			/* CPU_HWBUG_CR_EVERY_WRITE version */ \
				"{wait ma_c=1;" \
				" rwd %[value], %%" #reg "}", \
			%[cpu_hwbug_cr_every_write], \
			/* CPU_HWBUG_CR_FIRST_WRITE version */ \
				"{wait ma_c=1;" \
				" rwd %[value], %%" #reg "}", \
			%[cpu_hwbug_cr_first_write]) \
			"{nop} {nop} {nop}" \
			"{wait all_e=1}" \
			: \
			: [value] "ri" ((u64) (val)), \
			  [cpu_hwbug_cr_before_writes] "i" (CPU_HWBUG_CR_BEFORE_WRITES), \
			  [cpu_hwbug_cr_every_write] "i" (CPU_HWBUG_CR_EVERY_WRITE), \
			  [cpu_hwbug_cr_first_write] "i" (CPU_HWBUG_CR_FIRST_WRITE) \
			: "ctpr3"); \
} while (0)

#define NATIVE_SET_Q_CR_CLOSED_NOEXC(reg_lo, reg_hi, val_lo, val_hi) \
do { \
	/* Add ctpr3 clobber to avoid writing \
	 * CRs between `return` and `ct` */ \
	__no_asm_inline(7) \
	asm volatile (	ALTERNATIVE( \
			/* Default version */ \
				"", \
			/* CPU_HWBUG_CR_BEFORE_WRITES version */ \
				"{wait ma_c=1}", \
			%[cpu_hwbug_cr_before_writes]) \
			ALTERNATIVE_2( \
			/* Default version */ \
				"{rwd %[value_lo], %%" #reg_lo "}" \
				"{rwd %[value_hi], %%" #reg_hi "}", \
			/* CPU_HWBUG_CR_EVERY_WRITE version */ \
				"{wait ma_c=1;" \
				" rwd %[value_lo], %%" #reg_lo "}" \
				"{wait ma_c=1;" \
				" rwd %[value_hi], %%" #reg_hi "}", \
			%[cpu_hwbug_cr_every_write], \
			/* CPU_HWBUG_CR_FIRST_WRITE version */ \
				"{wait ma_c=1;" \
				" rwd %[value_lo], %%" #reg_lo "}" \
				"{rwd %[value_hi], %%" #reg_hi "}", \
			%[cpu_hwbug_cr_first_write]) \
			"{nop} {nop} {nop}" \
			"{wait all_e=1}" \
			: \
			: [value_lo] "ri" ((u64) (val_lo)), \
			  [value_hi] "ri" ((u64) (val_hi)), \
			  [cpu_hwbug_cr_before_writes] "i" (CPU_HWBUG_CR_BEFORE_WRITES), \
			  [cpu_hwbug_cr_every_write] "i" (CPU_HWBUG_CR_EVERY_WRITE), \
			  [cpu_hwbug_cr_first_write] "i" (CPU_HWBUG_CR_FIRST_WRITE) \
			: "ctpr3"); \
} while (0)


/*
 * RRSH/RWSH macros are for hypervisor saving and restoring of
 * guest's registers that do have shadow
 */

#define RRSH_DREG(reg) \
({ \
	unsigned long __rd_flags; \
	u64 __rd_res; \
	u32 __rd_core_mode, __rd_tmp32; \
	bool cpu_hwbug_rrsh_descr_v7 = cpu_has(CPU_HWBUG_RRSH_DESCR_V7); \
 \
	if (cpu_hwbug_rrsh_descr_v7) { \
		/* Interrupt might access stack registers which \
		 * won't work with temporary %core_mode value */ \
		raw_all_irq_save(__rd_flags); \
	} \
 \
	__no_asm_inline(1) \
	asm volatile ( \
		ALTERNATIVE( \
		/* Default version */ \
			"", \
		/* CPU_HWBUG_RRSH_DESCR_V7 version */ \
			".push_iset 7\n" \
			"rrs %%sh_core_mode, %[tmp32]\n" \
			".pop_iset\n" \
			"rrs %%core_mode, %[core_mode]\n" \
			/* Get %sh_core_mode.descr_v7 */ \
			"getfs %[tmp32], 0x47, %[tmp32]\n" \
			"insfs %[core_mode], 0x47, %[tmp32], %[tmp32]\n" \
			"scls %[tmp32], 0x7, %[tmp32]\n" \
			"rws %[tmp32], %%core_mode\n" \
			"wait all_e=1\n", \
		%[cpu_hwbug_rrsh_descr_v7]) \
		ALTERNATIVE( \
		/* Default version */ \
			".push_iset 6\n" \
			"rrd %%" #reg ", %[res]\n" \
			".pop_iset\n", \
		/* CPU_FEAT_V7_CPU_REGS version */ \
			".push_iset 7\n" \
			"rrshd %%" #reg ", %[res]\n" \
			".pop_iset\n", \
		%[cpu_feat_v7_cpu_regs]) \
		ALTERNATIVE( \
		/* Default version */ \
			"", \
		/* CPU_HWBUG_RRSH_DESCR_V7 version */ \
			"rws %[core_mode], %%core_mode\n" \
			"wait all_e=1\n", \
		%[cpu_hwbug_rrsh_descr_v7]) \
		: [res] "=&r" (__rd_res), [tmp32] "=&r" (__rd_tmp32), \
		  [core_mode] "=&r" (__rd_core_mode) \
		: [cpu_hwbug_rrsh_descr_v7] "i" (CPU_HWBUG_RRSH_DESCR_V7), \
		  [cpu_feat_v7_cpu_regs] "i" (CPU_FEAT_V7_CPU_REGS)); \
 \
	if (cpu_hwbug_rrsh_descr_v7) { \
		 raw_all_irq_restore(__rd_flags); \
	} \
 \
	__rd_res; \
})

#define RWSH_DREG(reg, _val) \
do { \
	__no_asm_inline(2) \
	asm volatile ( \
		ALTERNATIVE( \
		/* Default version */ \
			".push_iset 6\n" \
			"rwd %[val], %%" #reg "\n" \
			".pop_iset\n", \
		/* CPU_FEAT_V7_CPU_REGS version */ \
			".push_iset 7\n" \
			"rwshd %[val], %%" #reg "\n" \
			".pop_iset\n", \
		%[cpu_feat_v7_cpu_regs]) \
		"wait all_e=1\n" \
		: \
		: [val] "ir" ((u64) (_val)), \
		  [cpu_feat_v7_cpu_regs] "i" (CPU_FEAT_V7_CPU_REGS)); \
} while (0)

#define RWSH_DREGS(reg1, reg2, _val1, _val2) \
do { \
	__no_asm_inline(3) \
	asm volatile ( \
		ALTERNATIVE( \
		/* Default version */ \
			".push_iset 6\n" \
			"rwd %[val1], %%" #reg1 "\n" \
			"rwd %[val2], %%" #reg2 "\n" \
			".pop_iset\n", \
		/* CPU_FEAT_V7_CPU_REGS version */ \
			".push_iset 7\n" \
			"rwshd %[val1], %%" #reg1 "\n" \
			"rwshd %[val2], %%" #reg2 "\n" \
			".pop_iset\n", \
		%[cpu_feat_v7_cpu_regs]) \
		"wait all_e=1\n" \
		: \
		: [val1] "ir" ((u64) (_val1)), [val2] "ir" ((u64) (_val2)), \
		  [cpu_feat_v7_cpu_regs] "i" (CPU_FEAT_V7_CPU_REGS)); \
} while (0)

#define RWSH_CTPR_NOIRQ(reg, ctpr) \
do { \
	u32 __rc_core_mode; \
	u64 __rc_tmp1, __rc_tmp2; \
	e2k_ctpr_t __rc_val = (ctpr); \
 \
	__no_asm_inline(3) \
	asm volatile ( \
		ALTERNATIVE( \
		/* Default version */ \
			"", \
		/* CPU_HWBUG_RRSH_RWSH_CTPR version */ \
			".push_iset 7\n" \
			"rrs %%sh_core_mode, %[tmp1]\n" \
			".pop_iset\n" \
			"rrs %%core_mode, %[core_mode]\n" \
			/* Get %sh_core_mode.descr_v7 */ \
			"{ands %[core_mode], ~0x80, %[tmp2]\n" \
			" getfzs %[tmp1], 0xe200, %[tmp1]}\n" \
			"ors %[tmp1], %[tmp2], %[tmp1]\n" \
			"rws %[tmp1], %%core_mode\n" \
			"wait all_e=1\n", \
		%[cpu_hwbug_rrsh_rwsh_ctpr]) \
		ALTERNATIVE( \
		/* Default version */ \
			"rwd %[val_lo], %%" #reg "\n" \
			"rwd %[val_hi], %%" #reg ".hi\n", \
		/* CPU_FEAT_V7_CPU_REGS version */ \
			".push_iset 7\n" \
			"rwshd %[val_lo], %%" #reg "\n" \
			"rwshd %[val_hi], %%" #reg ".hi\n" \
			".pop_iset\n", \
		%[cpu_feat_v7_cpu_regs]) \
		"wait all_e=1\n" \
		ALTERNATIVE( \
		/* Default version */ \
			"", \
		/* CPU_HWBUG_RRSH_RWSH_CTPR version */ \
			"rws %[core_mode], %%core_mode\n" \
			"wait all_e=1\n", \
		%[cpu_hwbug_rrsh_rwsh_ctpr]) \
		"wait all_e=1\n" \
		: [tmp1] "=&r" (__rc_tmp1), [tmp2] "=&r" (__rc_tmp2), \
		  [core_mode] "=&r" (__rc_core_mode) \
		: [val_lo] "ir" (__rc_val.lo), [val_hi] "ir" (__rc_val.hi), \
		  [cpu_feat_v7_cpu_regs] "i" (CPU_FEAT_V7_CPU_REGS), \
		  [cpu_hwbug_rrsh_rwsh_ctpr] "i" (CPU_HWBUG_RRSH_RWSH_CTPR) \
		: #reg); \
} while (0)


#define NATIVE_GET_USFS() \
({ \
	u64 __ngu_val; \
	__no_asm_inline(2) \
	asm (".push_iset 7\n" \
	     "{ nop }\n" \
	     "{ rrd %%usfs, %0 }\n" \
	     ".pop_iset\n" \
	     : "=r" (__ngu_val) :);  \
	__ngu_val; \
})

/* Write updated registers. */
#define NATIVE_EXIT_HANDLE_SYSCALL(_sbr, _usd, _upsr, _psize, _cr0, _cr1) \
do { \
	e2k_usd_t __ehs_usd = (_usd); \
	e2k_cr0_t __ehs_cr0 = (_cr0); \
	e2k_cr1_t __ehs_cr1 = (_cr1); \
	u64 __ehs_wd; \
	__asm_length(11) \
	asm volatile ("{rwd %[sbr], %%sbr}" \
		      /* Must read %wd in asm (i.e. after `setwd`). \
		       * Also serves as workaround for CPU_HWBUG_USD_ALIGNMENT */ \
		      "{rrd %%wd, %[wd]}" \
		      "{rwd %[usd_lo], %%usd.lo}" \
		      ALTERNATIVE( \
		      /* Default version */ \
			"{rwd %[usd_hi], %%usd.hi;" \
			" insfd %[wd], %[insf_params], %[psize], %[wd]}", \
		      /* CPU_HWBUG_CR_BEFORE_WRITES version */ \
			"{wait ma_c=1;" \
			" rwd %[usd_hi], %%usd.hi;" \
			" insfd %[wd], %[insf_params], %[psize], %[wd]}", \
		      %[cpu_hwbug_cr_before_writes]) \
		      ALTERNATIVE_2( \
		      /* Default version */ \
			"{rwd %[cr0_lo], %%cr0.lo}" \
			"{rwd %[cr0_hi], %%cr0.hi}" \
			"{rwd %[cr1_lo], %%cr1.lo}" \
			"{rwd %[cr1_hi], %%cr1.hi}", \
		      /* CPU_HWBUG_CR_EVERY_WRITE version */ \
			"{wait ma_c=1;" \
			" rwd %[cr0_lo], %%cr0.lo}" \
			"{wait ma_c=1;" \
			" rwd %[cr0_hi], %%cr0.hi}" \
			"{wait ma_c=1;" \
			" rwd %[cr1_lo], %%cr1.lo}" \
			"{wait ma_c=1;" \
			" rwd %[cr1_hi], %%cr1.hi}", \
		      %[cpu_hwbug_cr_every_write], \
		      /* CPU_HWBUG_CR_FIRST_WRITE version */ \
			"{wait ma_c=1;" \
			" rwd %[cr0_lo], %%cr0.lo}" \
			"{rwd %[cr0_hi], %%cr0.hi}" \
			"{rwd %[cr1_lo], %%cr1.lo}" \
			"{rwd %[cr1_hi], %%cr1.hi}", \
		      %[cpu_hwbug_cr_first_write]) \
		      "{rws %[upsr], %%upsr;" \
		      " scld %[wd], 32, %[wd]}" \
		      /* %wd write must be last since RF is not \
		       * available while %wd is being modified */ \
		      "{rwd %[wd], %%wd}\n" \
		      "{wait all_e=1}" \
		      : [wd] "=&r" (__ehs_wd) \
		      : [sbr] "ri" ((u64) ((_sbr).word)), \
			[usd_hi] "ri" ((u64) (__ehs_usd.hi)), \
			[usd_lo] "ri" ((u64) (__ehs_usd.lo)), \
			[cr0_lo] "ri" ((u64) (__ehs_cr0.lo)), \
			[cr0_hi] "ri" ((u64) (__ehs_cr0.hi)), \
			[cr1_lo] "ri" ((u64) (__ehs_cr1.lo)), \
			[cr1_hi] "ri" ((u64) (__ehs_cr1.hi)), \
			[upsr] "ri" ((u32) ((_upsr).word)), \
			[psize] "ri" ((u64) (_psize)), \
			[insf_params] "i" (32 /*shift*/ | (11 /*size*/ << 6) | \
					   (1 /*me3hi*/ << 15)), \
			[cpu_hwbug_cr_before_writes] "i" (CPU_HWBUG_CR_BEFORE_WRITES), \
			[cpu_hwbug_cr_every_write] "i" (CPU_HWBUG_CR_EVERY_WRITE), \
			[cpu_hwbug_cr_first_write] "i" (CPU_HWBUG_CR_FIRST_WRITE)); \
} while (0)

#ifndef __ASSEMBLY__
static __always_inline void native_set_binco_regs(e2k_qreg_t cs, e2k_qreg_t ds,
		e2k_qreg_t es, e2k_qreg_t fs, e2k_qreg_t gs, e2k_qreg_t ss,
		e2k_rpr_t rpr, u64 tcd)
{
	__asm_length(16)
	asm volatile ("{flushts;"
		      " rwd %[cs_lo], %%cs.lo}"
		      "{rwd %[cs_hi], %%cs.hi}"
		      "{rwd %[ds_lo], %%ds.lo}"
		      "{rwd %[ds_hi], %%ds.hi}"
		      "{rwd %[es_lo], %%es.lo}"
		      "{rwd %[es_hi], %%es.hi}"
		      "{rwd %[fs_lo], %%fs.lo}"
		      "{rwd %[fs_hi], %%fs.hi}"
		      "{rwd %[gs_lo], %%gs.lo}"
		      "{rwd %[gs_hi], %%gs.hi}"
		      "{rwd %[ss_lo], %%ss.lo}"
		      "{rwd %[ss_hi], %%ss.hi}"
		      "{rwd %[rpr_lo], %%rpr.lo}"
		      "{rwd %[rpr_hi], %%rpr.hi}"
		      "{puttc %[tcd], 0, %%tcd}"
		      "{wait all_e=1}"
		      :
		      : [cs_lo] "ri" (cs.lo), [cs_hi] "ri" (cs.hi),
			[ds_lo] "ri" (ds.lo), [ds_hi] "ri" (ds.hi),
			[es_lo] "ri" (es.lo), [es_hi] "ri" (es.hi),
			[fs_lo] "ri" (fs.lo), [fs_hi] "ri" (fs.hi),
			[gs_lo] "ri" (gs.lo), [gs_hi] "ri" (gs.hi),
			[ss_lo] "ri" (ss.lo), [ss_hi] "ri" (ss.hi),
			[rpr_lo] "ri" (rpr.lo), [rpr_hi] "ri" (rpr.hi),
			[tcd] "ri" (tcd));
}
#endif /* !__ASSEMBLY__ */

#define NATIVE_SET_DATA_STACK_HOST_REGS(_usd, _sbr) \
do { \
	e2k_usd_t __sr_usd = (_usd); \
	__asm_length(5) \
	asm volatile ("{rwd %[sbr], %%sbr}" \
		      /* Workaround for CPU_HWBUG_USD_ALIGNMENT */ \
		      "{nop}" \
		      "{rwd %[usd_lo], %%usd.lo}" \
		      "{rwd %[usd_hi], %%usd.hi};" \
		      "{wait all_e=1}" \
		      : \
		      : [usd_lo] "ri" ((u64) (__sr_usd.lo)), \
			[usd_hi] "ri" ((u64) (__sr_usd.hi)), \
			[sbr] "ri" ((u64) ((_sbr).word))); \
} while (0)

#define NATIVE_SET_DATA_STACK_GUEST_REGS(_usd, _sbr) \
do { \
	e2k_usd_t __sr_usd = (_usd); \
	_Pragma("asm_length(5)") \
	asm volatile ("{rwd %[sbr], %%sbr}" \
		      /* Workaround for CPU_HWBUG_USD_ALIGNMENT */ \
		      "{nop}" \
		      ALTERNATIVE( \
		      /* Default version */ \
			"{rwd %[usd_lo], %%usd.lo}" \
			"{rwd %[usd_hi], %%usd.hi}", \
		      /* CPU_FEAT_V7_CPU_REGS version */ \
			".push_iset 7\n" \
			"{rwshd %[usd_lo], %%usd.lo}" \
			"{rwshd %[usd_hi], %%usd.hi}" \
			".pop_iset\n", \
		      %[cpu_feat_v7_cpu_regs]) \
		      "{wait all_e=1}" \
		      : \
		      : [usd_lo] "ri" ((u64) (__sr_usd.lo)), \
			[usd_hi] "ri" ((u64) (__sr_usd.hi)), \
			[sbr] "ri" ((u64) ((_sbr).word)), \
			[cpu_feat_v7_cpu_regs] "i" (CPU_FEAT_V7_CPU_REGS)); \
} while (0)

#define NATIVE_SET_STACK_REGS(_psp, _pcsp, _usd, _sbr) \
do { \
	e2k_psp_t __sr_psp = (_psp); \
	e2k_pcsp_t __sr_pcsp = (_pcsp); \
	e2k_usd_t __sr_usd = (_usd); \
	__asm_length(8) \
	asm volatile ("{rwd %[psp_lo], %%psp.lo}" \
		      "{rwd %[psp_hi], %%psp.hi}" \
		      "{rwd %[pcsp_lo], %%pcsp.lo}" \
		      "{rwd %[sbr], %%sbr}" \
		      /* This also serves as workaround for CPU_HWBUG_USD_ALIGNMENT */ \
		      "{rwd %[pcsp_hi], %%pcsp.hi}" \
		      "{rwd %[usd_lo], %%usd.lo}" \
		      "{rwd %[usd_hi], %%usd.hi};" \
		      "{wait all_e=1}" \
		      : \
		      : [psp_lo] "ri" ((u64) (__sr_psp.lo)), \
			[psp_hi] "ri" ((u64) (__sr_psp.hi)), \
			[pcsp_lo] "ri" ((u64) (__sr_pcsp.lo)), \
			[pcsp_hi] "ri" ((u64) (__sr_pcsp.hi)), \
			[usd_lo] "ri" ((u64) (__sr_usd.lo)), \
			[usd_hi] "ri" ((u64) (__sr_usd.hi)), \
			[sbr] "ri" ((u64) ((_sbr).word))); \
} while (0)

#define NATIVE_SET_STACK_CR_REGS(_psp, _pcsp, _usd, _sbr, _cr0, _cr1) \
do { \
	e2k_psp_t __sr_psp = (_psp); \
	e2k_pcsp_t __sr_pcsp = (_pcsp); \
	e2k_usd_t __sr_usd = (_usd); \
	e2k_cr0_t __sr_cr0 = (_cr0); \
	e2k_cr1_t __sr_cr1 = (_cr1); \
 \
	/* Add ctpr3 clobber to avoid writing CRs between `return` and `ct` */ \
	__asm_length(12) \
	asm volatile ("{rwd %[psp_lo], %%psp.lo}" \
		      "{rwd %[psp_hi], %%psp.hi}" \
		      "{rwd %[pcsp_lo], %%pcsp.lo}" \
		      "{rwd %[sbr], %%sbr}" \
		      /* This also serves as workaround for CPU_HWBUG_USD_ALIGNMENT */ \
		      "{rwd %[pcsp_hi], %%pcsp.hi}" \
		      "{rwd %[usd_lo], %%usd.lo}" \
		      ALTERNATIVE( \
		      /* Default version */ \
			"{rwd %[usd_hi], %%usd.hi}", \
		      /* CPU_HWBUG_CR_BEFORE_WRITES version */ \
			"{wait ma_c=1;" \
			" rwd %[usd_hi], %%usd.hi}", \
		      %[cpu_hwbug_cr_before_writes]) \
		      ALTERNATIVE_2( \
		      /* Default version */ \
			"{rwd %[cr0_lo], %%cr0.lo}" \
			"{rwd %[cr0_hi], %%cr0.hi}" \
			"{rwd %[cr1_lo], %%cr1.lo}" \
			"{rwd %[cr1_hi], %%cr1.hi}", \
		      /* CPU_HWBUG_CR_EVERY_WRITE version */ \
			"{wait ma_c=1;" \
			" rwd %[cr0_lo], %%cr0.lo}" \
			"{wait ma_c=1;" \
			" rwd %[cr0_hi], %%cr0.hi}" \
			"{wait ma_c=1;" \
			" rwd %[cr1_lo], %%cr1.lo}" \
			"{wait ma_c=1;" \
			" rwd %[cr1_hi], %%cr1.hi}", \
		      %[cpu_hwbug_cr_every_write], \
		      /* CPU_HWBUG_CR_FIRST_WRITE version */ \
			"{wait ma_c=1;" \
			" rwd %[cr0_lo], %%cr0.lo}" \
			"{rwd %[cr0_hi], %%cr0.hi}" \
			"{rwd %[cr1_lo], %%cr1.lo}" \
			"{rwd %[cr1_hi], %%cr1.hi}", \
		      %[cpu_hwbug_cr_first_write]) \
		      "{wait all_e=1}" \
		      : \
		      : [cr0_lo] "ri" ((u64) (__sr_cr0.lo)), \
			[cr0_hi] "ri" ((u64) (__sr_cr0.hi)), \
			[cr1_lo] "ri" ((u64) (__sr_cr1.lo)), \
			[cr1_hi] "ri" ((u64) (__sr_cr1.hi)), \
			[psp_lo] "ri" ((u64) (__sr_psp.lo)), \
			[psp_hi] "ri" ((u64) (__sr_psp.hi)), \
			[pcsp_lo] "ri" ((u64) (__sr_pcsp.lo)), \
			[pcsp_hi] "ri" ((u64) (__sr_pcsp.hi)), \
			[usd_lo] "ri" ((u64) (__sr_usd.lo)), \
			[usd_hi] "ri" ((u64) (__sr_usd.hi)), \
			[sbr] "ri" ((u64) ((_sbr).word)), \
			[cpu_hwbug_cr_before_writes] "i" (CPU_HWBUG_CR_BEFORE_WRITES), \
			[cpu_hwbug_cr_every_write] "i" (CPU_HWBUG_CR_EVERY_WRITE), \
			[cpu_hwbug_cr_first_write] "i" (CPU_HWBUG_CR_FIRST_WRITE) \
		      : "ctpr3"); \
} while (0)

#define NATIVE_SET_HW_STACK_REGS(_psp, _pcsp) \
do { \
	e2k_psp_t __sr_psp = (_psp); \
	e2k_pcsp_t __sr_pcsp = (_pcsp); \
	__asm_length(5) \
	asm volatile ("{rwd %[psp_lo], %%psp.lo}" \
		      "{rwd %[psp_hi], %%psp.hi}" \
		      "{rwd %[pcsp_lo], %%pcsp.lo}" \
		      "{rwd %[pcsp_hi], %%pcsp.hi}" \
		      "{wait all_e=1}" \
		      : \
		      : [psp_lo] "ri" ((u64) (__sr_psp.lo)), \
			[psp_hi] "ri" ((u64) (__sr_psp.hi)), \
			[pcsp_lo] "ri" ((u64) (__sr_pcsp.lo)), \
			[pcsp_hi] "ri" ((u64) (__sr_pcsp.hi))); \
} while (0)

#define NATIVE_SET_HW_STACK_CR_REGS(_psp, _pcsp, _cr0, _cr1) \
do { \
	e2k_psp_t __sr_psp = (_psp); \
	e2k_pcsp_t __sr_pcsp = (_pcsp); \
	e2k_cr0_t __sr_cr0 = (_cr0); \
	e2k_cr1_t __sr_cr1 = (_cr1); \
 \
	/* Add ctpr3 clobber to avoid writing CRs between `return` and `ct` */ \
	__asm_length(9) \
	asm volatile ("{rwd %[psp_lo], %%psp.lo}" \
		      "{rwd %[psp_hi], %%psp.hi}" \
		      "{rwd %[pcsp_lo], %%pcsp.lo}" \
		      ALTERNATIVE( \
		      /* Default version */ \
			"{rwd %[pcsp_hi], %%pcsp.hi}", \
		      /* CPU_HWBUG_CR_BEFORE_WRITES version */ \
			"{wait ma_c=1;" \
			" rwd %[pcsp_hi], %%pcsp.hi}", \
		      %[cpu_hwbug_cr_before_writes]) \
		      ALTERNATIVE_2( \
		      /* Default version */ \
			"{rwd %[cr0_lo], %%cr0.lo}" \
			"{rwd %[cr0_hi], %%cr0.hi}" \
			"{rwd %[cr1_lo], %%cr1.lo}" \
			"{rwd %[cr1_hi], %%cr1.hi}", \
		      /* CPU_HWBUG_CR_EVERY_WRITE version */ \
			"{wait ma_c=1;" \
			" rwd %[cr0_lo], %%cr0.lo}" \
			"{wait ma_c=1;" \
			" rwd %[cr0_hi], %%cr0.hi}" \
			"{wait ma_c=1;" \
			" rwd %[cr1_lo], %%cr1.lo}" \
			"{wait ma_c=1;" \
			" rwd %[cr1_hi], %%cr1.hi}", \
		      %[cpu_hwbug_cr_every_write], \
		      /* CPU_HWBUG_CR_FIRST_WRITE version */ \
			"{wait ma_c=1;" \
			" rwd %[cr0_lo], %%cr0.lo}" \
			"{rwd %[cr0_hi], %%cr0.hi}" \
			"{rwd %[cr1_lo], %%cr1.lo}" \
			"{rwd %[cr1_hi], %%cr1.hi}", \
		      %[cpu_hwbug_cr_first_write]) \
		      "{wait all_e=1}" \
		      : \
		      : [cr0_lo] "ri" ((u64) (__sr_cr0.lo)), \
			[cr0_hi] "ri" ((u64) (__sr_cr0.hi)), \
			[cr1_lo] "ri" ((u64) (__sr_cr1.lo)), \
			[cr1_hi] "ri" ((u64) (__sr_cr1.hi)), \
			[psp_lo] "ri" ((u64) (__sr_psp.lo)), \
			[psp_hi] "ri" ((u64) (__sr_psp.hi)), \
			[pcsp_lo] "ri" ((u64) (__sr_pcsp.lo)), \
			[pcsp_hi] "ri" ((u64) (__sr_pcsp.hi)), \
			[cpu_hwbug_cr_before_writes] "i" (CPU_HWBUG_CR_BEFORE_WRITES), \
			[cpu_hwbug_cr_every_write] "i" (CPU_HWBUG_CR_EVERY_WRITE), \
			[cpu_hwbug_cr_first_write] "i" (CPU_HWBUG_CR_FIRST_WRITE) \
		      : "ctpr3"); \
} while (0)

/* Useful for skipping CPU_HWBUG_CR_FIRST_WRITE/... workaround if it can be done later */
#define NATIVE_SET_HW_STACK_CR_REGS__NO_WAIT(_psp, _pcsp, _cr0, _cr1) \
do { \
	e2k_psp_t __sr_psp = (_psp); \
	e2k_pcsp_t __sr_pcsp = (_pcsp); \
	e2k_cr0_t __sr_cr0 = (_cr0); \
	e2k_cr1_t __sr_cr1 = (_cr1); \
 \
	/* Add ctpr3 clobber to avoid writing CRs between `return` and `ct` */ \
	__no_asm_inline(9) \
	asm volatile ("{rwd %[psp_lo], %%psp.lo}" \
		      "{rwd %[psp_hi], %%psp.hi}" \
		      "{rwd %[pcsp_lo], %%pcsp.lo}" \
		      "{rwd %[pcsp_hi], %%pcsp.hi}" \
		      "{rwd %[cr0_lo], %%cr0.lo}" \
		      "{rwd %[cr0_hi], %%cr0.hi}" \
		      "{rwd %[cr1_lo], %%cr1.lo}" \
		      "{rwd %[cr1_hi], %%cr1.hi}" \
		      "{wait all_e=1}" \
		      : \
		      : [cr0_lo] "ri" ((u64) (__sr_cr0.lo)), \
			[cr0_hi] "ri" ((u64) (__sr_cr0.hi)), \
			[cr1_lo] "ri" ((u64) (__sr_cr1.lo)), \
			[cr1_hi] "ri" ((u64) (__sr_cr1.hi)), \
			[psp_lo] "ri" ((u64) (__sr_psp.lo)), \
			[psp_hi] "ri" ((u64) (__sr_psp.hi)), \
			[pcsp_lo] "ri" ((u64) (__sr_pcsp.lo)), \
			[pcsp_hi] "ri" ((u64) (__sr_pcsp.hi)) \
		      : "ctpr3"); \
} while (0)

#define NATIVE_SET_CR_REGS(_cr0, _cr1) \
do { \
	e2k_cr0_t __sr_cr0 = (_cr0); \
	e2k_cr1_t __sr_cr1 = (_cr1); \
 \
	/* Add ctpr3 clobber to avoid writing CRs between `return` and `ct` */ \
	__asm_length(5) \
	asm volatile (ALTERNATIVE( \
		      /* Default version */ \
			"", \
		      /* CPU_HWBUG_CR_BEFORE_WRITES version */ \
			"{wait ma_c=1}", \
		      %[cpu_hwbug_cr_before_writes]) \
		      ALTERNATIVE_2( \
		      /* Default version */ \
			"{rwd %[cr0_lo], %%cr0.lo}" \
			"{rwd %[cr0_hi], %%cr0.hi}" \
			"{rwd %[cr1_lo], %%cr1.lo}" \
			"{rwd %[cr1_hi], %%cr1.hi}", \
		      /* CPU_HWBUG_CR_EVERY_WRITE version */ \
			"{wait ma_c=1;" \
			" rwd %[cr0_lo], %%cr0.lo}" \
			"{wait ma_c=1;" \
			" rwd %[cr0_hi], %%cr0.hi}" \
			"{wait ma_c=1;" \
			" rwd %[cr1_lo], %%cr1.lo}" \
			"{wait ma_c=1;" \
			" rwd %[cr1_hi], %%cr1.hi}", \
		      %[cpu_hwbug_cr_every_write], \
		      /* CPU_HWBUG_CR_FIRST_WRITE version */ \
			"{wait ma_c=1;" \
			" rwd %[cr0_lo], %%cr0.lo}" \
			"{rwd %[cr0_hi], %%cr0.hi}" \
			"{rwd %[cr1_lo], %%cr1.lo}" \
			"{rwd %[cr1_hi], %%cr1.hi}", \
		      %[cpu_hwbug_cr_first_write]) \
		      "{wait all_e=1}" \
		      : \
		      : [cr0_lo] "ri" ((u64) (__sr_cr0.lo)), \
			[cr0_hi] "ri" ((u64) (__sr_cr0.hi)), \
			[cr1_lo] "ri" ((u64) (__sr_cr1.lo)), \
			[cr1_hi] "ri" ((u64) (__sr_cr1.hi)), \
			[cpu_hwbug_cr_before_writes] "i" (CPU_HWBUG_CR_BEFORE_WRITES), \
			[cpu_hwbug_cr_every_write] "i" (CPU_HWBUG_CR_EVERY_WRITE), \
			[cpu_hwbug_cr_first_write] "i" (CPU_HWBUG_CR_FIRST_WRITE) \
		      : "ctpr3"); \
} while (0)

/* Useful for skipping CPU_HWBUG_CR_FIRST_WRITE/... workaround if it can be done later */
#define NATIVE_SET_CR_REGS__NO_WAIT(_cr0, _cr1) \
do { \
	e2k_cr0_t __sr_cr0 = (_cr0); \
	e2k_cr1_t __sr_cr1 = (_cr1); \
 \
	/* Add ctpr3 clobber to avoid writing CRs between `return` and `ct` */ \
	__no_asm_inline(5) \
	asm volatile ("{rwd %[cr0_lo], %%cr0.lo}" \
		      "{rwd %[cr0_hi], %%cr0.hi}" \
		      "{rwd %[cr1_lo], %%cr1.lo}" \
		      "{rwd %[cr1_hi], %%cr1.hi}" \
		      "{wait all_e=1}" \
		      : \
		      : [cr0_lo] "ri" ((u64) (__sr_cr0.lo)), \
			[cr0_hi] "ri" ((u64) (__sr_cr0.hi)), \
			[cr1_lo] "ri" ((u64) (__sr_cr1.lo)), \
			[cr1_hi] "ri" ((u64) (__sr_cr1.hi)) \
		      : "ctpr3"); \
} while (0)

/*
 * A workaround to restore inner clw register us_cl_low on v6 and e48c.rev0,
 * as it isn't directly available for read-write there.
 * 1) fictive set us_cl_b = us_cl_up;
 * 2) restore usd.lo by actual value;
 * 3) 1 and 2 must be inseparable sequence, so wait for operands and align code to ib line start.
 */
#define RESTORE_US_CL_LOW(_us_cl_up, _usd_lo) \
do { \
	if (cpu_has(CPU_FEAT_ISET_V7)) { \
		__asm_length(4) \
		asm volatile ( \
			"{wait all_c=1\n" \
			" ibranch 1f}\n" \
			".align 0x100\n" \
			"1:\n" \
			"{rwd,0 %[usd_lo], %%usd.lo}" \
			"{nop}" \
			".push_iset 6\n" \
			"{mmurw,2 %[us_cl_up], %%us_cl_b}" \
			".pop_iset\n" \
			: \
			: [us_cl_up] "r" ((u64) (_us_cl_up)), \
			  [usd_lo] "r" ((u64) (_usd_lo))); \
	} else { \
		__asm_length(3) \
		asm volatile ( \
			"{wait all_c=1\n" \
			" ibranch 1f}\n" \
			".align 0x100\n" \
			"1:\n" \
			".push_iset 6\n" \
			"{ mmurw,2 %[us_cl_up], %%us_cl_b }" \
			".pop_iset\n" \
			"{ rwd,0 %[usd_lo], %%usd.lo }" \
			: \
			: [us_cl_up] "r" ((u64) (_us_cl_up)), \
			  [usd_lo] "r" ((u64) (_usd_lo))); \
	} \
} while (0)


#define NATIVE_SET_PSR_IRQ_BARRIER(val) \
({ \
	/* Use closed GNU asm to make sure compiler sees custom clobbers */ \
	__no_asm_inline(2) \
	asm volatile ("{rws %0, %%psr}" \
		      "{wait all_e=1}" \
		      : \
		      : "ri" ((u32) (val)) \
		      : "memory", PREEMPTION_CLOBBERS); \
})
#define NATIVE_SET_UPSR_IRQ_BARRIER(val) \
({ \
	/* Use closed GNU asm to make sure compiler sees custom clobbers */ \
	__no_asm_inline(2) \
	asm volatile ("{rws %0, %%upsr}" \
		      "{wait all_e=1}" \
		      : \
		      : "ri" ((u32) (val)) \
		      : "memory", PREEMPTION_CLOBBERS); \
})

#define NATIVE_GET_MMUREG(reg) \
({ \
	u64 res; \
	asm volatile ("mmurr %%" #reg ", %0" \
		: "=r" (res)); \
	res; \
})

#if defined CONFIG_E2K_MACHINE && CONFIG_CPU_ISET_MIN < 7
# define MMURW_NOPS 2
#else
# define MMURW_NOPS 3
#endif

#define NATIVE_GET_MMUREG_ISET(iset, reg) \
({ \
	u64 res; \
	__no_asm_inline(1) \
	asm volatile ( \
		".push_iset " #iset "\n" \
		"mmurr %%" #reg ", %0\n" \
		".pop_iset\n"	\
		: "=r" (res) \
		: \
		: "memory"); \
	res; \
})

#define NATIVE_SET_MMUREG(reg, val) \
({ \
	__asm_length(3) \
	asm volatile ( \
		ALTERNATIVE( \
		/* Default version */ \
			"{mmurw %0, %%" #reg "}\n" \
			"{wait all_c=1\n" \
			" nop 3}\n", \
		/* CPU_FEAT_ISET_NOT_V6 version */ \
			"{nop 2\n" \
			" mmurw %0, %%" #reg "}\n", \
		%[cpu_feat_iset_not_v6]) \
		: \
		: "r" ((u64) (val)), \
		  [cpu_feat_iset_not_v6] "i" (CPU_FEAT_ISET_NOT_V6) \
		: "memory"); \
})

#define NATIVE_SET_MMUREG_ISET(iset, reg, val) \
({ \
	__asm_length(3) \
	asm volatile ( \
		ALTERNATIVE( \
		/* Default version */ \
			".push_iset " #iset "\n" \
			"{mmurw %0, %%" #reg "}\n" \
			"{wait all_c=1\n" \
			" nop 3}\n" \
			".pop_iset\n", \
		/* CPU_FEAT_ISET_NOT_V6 version */ \
			".push_iset " #iset "\n" \
			"{nop 2\n" \
			" mmurw %0, %%" #reg "}\n" \
			".pop_iset\n", \
			%[cpu_feat_iset_not_v6]) \
		: \
		: "r" ((u64) (val)), \
		  [cpu_feat_iset_not_v6] "i" (CPU_FEAT_ISET_NOT_V6) \
		: "memory"); \
})

#ifndef __ASSEMBLY__
__attribute__((__always_inline__))
static inline void native_get_clw(u64 *us_cl_b, u64 *us_cl_up, u64 *us_cl_m0,
				  u64 *us_cl_m1, u64 *us_cl_m2, u64 *us_cl_m3)
{
	_Pragma("asm_length(3)")
	asm volatile (
		"{mmurr %%us_cl_b, %[us_cl_b]}\n"
		"{mmurr %%us_cl_up, %[us_cl_up]}\n"
		"{mmurr %%us_cl_m0, %[us_cl_m0]}\n"
		"{mmurr %%us_cl_m1, %[us_cl_m1]}\n"
		"{mmurr %%us_cl_m2, %[us_cl_m2]}\n"
		"{mmurr %%us_cl_m3, %[us_cl_m3]}\n"
		: [us_cl_b] "=r" (*us_cl_b), [us_cl_up] "=r" (*us_cl_up),
		  [us_cl_m0] "=r" (*us_cl_m0), [us_cl_m1] "=r" (*us_cl_m1),
		  [us_cl_m2] "=r" (*us_cl_m2), [us_cl_m3] "=r" (*us_cl_m3)
		:
		: "memory");
}

__attribute__((__always_inline__))
static inline void native_set_clw_v6(u64 us_cl_b, u64 us_cl_up, u64 us_cl_m0,
				     u64 us_cl_m1, u64 us_cl_m2, u64 us_cl_m3)
{
	_Pragma("asm_length(3)")
	asm volatile (
		".push_iset 6\n"
		"{mmurw %[us_cl_b], %%us_cl_b}\n"
		"{mmurw %[us_cl_up], %%us_cl_up}\n"
		"{mmurw %[us_cl_m0], %%us_cl_m0}\n"
		"{mmurw %[us_cl_m1], %%us_cl_m1}\n"
		"{mmurw %[us_cl_m2], %%us_cl_m2}\n"
		"{mmurw %[us_cl_m3], %%us_cl_m3}\n"
		".pop_iset\n"
		"{wait all_c=1\n"
		" nop 3}\n"
		:
		: [us_cl_b] "r" (us_cl_b), [us_cl_up] "r" (us_cl_up),
		  [us_cl_m0] "r" (us_cl_m0), [us_cl_m1] "r" (us_cl_m1),
		  [us_cl_m2] "r" (us_cl_m2), [us_cl_m3] "r" (us_cl_m3)
		: "memory");
}
#endif /* !__ASSEMBLY__ */

/*
 * Write user's context (%cont) and page table root (%root_ptb which was
 * renamed to %u_pptb in iset v6).
 *
 * Note that context version is not masked before writing.  This works OK
 * because %cont has only one field, and even if that field is expanded
 * in the future it'll still be a backwards compatible change (kernel
 * will flush TLB more often than expected by hardware but that does not
 * break correctness).
 */
#define WRITE_UACCESS_REGS(_cont, _root_ptb) \
do { \
	u64 unused; \
	__asm_length(4) \
	asm NOT_VOLATILE ( \
		"{mmurw %[root_ptb], %%root_ptb}\n" \
		ALTERNATIVE( \
		/* Default version */ \
			"{mmurw %[cont], %%cont}\n" \
			"{wait all_c=1\n" \
			" nop 3}\n", \
		/* CPU_FEAT_ISET_NOT_V6 version */ \
			"{nop 2\n" \
			" mmurw %[cont], %%cont}\n", \
		%[cpu_feat_iset_not_v6]) \
		: "=r" (unused) \
		: [root_ptb] "r" ((u64) (_root_ptb)), \
		  [cont] "r" ((u64) (_cont)), \
		  [cpu_feat_iset_not_v6] "i" (CPU_FEAT_ISET_NOT_V6) \
		: "memory"); \
} while (0)

/*
 * This version of `WRITE_UACCESS_REGS()` can be called under open
 * interrupts when writing user's values but there are some rules
 * to follow.
 *
 * Each value must be loaded and written into register atomically,
 * otherwise an interrupt in the middle might update context after
 * we have loaded it.  Atomic operation is possible here because
 * values are cached in %g registers which can be directly accessed
 * by `mmurw` instruction.
 *
 * This also means that to write arbitrary values you still have to
 * use `WRITE_UACCESS_REGS()` and possibly close interrupts depending
 * on values written.
 */
#define WRITE_UACCESS_REGS_CACHED() \
do { \
	u64 unused; \
	__asm_length(4) \
	asm NOT_VOLATILE ( \
		"{mmurw %%g" __stringify(U_ROOT_PTB_GREG) ", %%root_ptb}\n" \
		ALTERNATIVE( \
		/* Default version */ \
			"{mmurw %%g" __stringify(CURRENT_MMU_CONTEXT_GREG) ", %%cont}\n" \
			"{wait all_c=1\n" \
			" nop 3}\n", \
		/* CPU_FEAT_ISET_NOT_V6 version */ \
			"{nop 2\n" \
			" mmurw %%g" __stringify(CURRENT_MMU_CONTEXT_GREG) ", %%cont}\n", \
		%[cpu_feat_iset_not_v6]) \
		: "=r" (unused) \
		: [cpu_feat_iset_not_v6] "i" (CPU_FEAT_ISET_NOT_V6) \
		: "memory", "g" __stringify(U_ROOT_PTB_GREG), \
		  "g" __stringify(CURRENT_MMU_CONTEXT_GREG)); \
} while (0)

#define NATIVE_SET_MMUREG_ISET_V5_V6(iset, reg, val, nop_before_v6, nop_since_v6) \
({ \
	__no_asm_inline(1) \
	asm volatile ( \
		ALTERNATIVE( \
		/* Default version */ \
			".push_iset " #iset "\n" \
			"{mmurw %0, %%" #reg "}\n" \
			"{wait all_c=1\n" \
			" nop " __stringify(nop_since_v6) "}\n" \
			".pop_iset\n", \
		/* CPU_FEAT_ISET_NOT_V6 version */ \
			".push_iset " #iset "\n" \
			"{nop " __stringify(nop_before_v6) "\n" \
			" mmurw %0, %%" #reg "}\n" \
			".pop_iset\n", \
		%[cpu_feat_iset_not_v6]) \
		: \
		: "r" ((u64) (val)), \
		  [cpu_feat_iset_not_v6] "i" (CPU_FEAT_ISET_NOT_V6) \
		: "memory"); \
})

#define NATIVE_TAGGED_LOAD_TO_MMUREG(reg, _addr) \
do { \
	unsigned long long _tmp; \
	__no_asm_inline(6) \
	asm volatile ("{ldrd [ %[addr] + %[opc] ], %[tmp]\n" \
		      " nop 3}\n" \
		      "{wait all_e=1}\n" \
		      "{mmurw,s %[tmp], %%" #reg "}\n" \
		      : [tmp] "=r" (_tmp) \
		      : [addr] "m" (*((unsigned long long *) (_addr))),	\
			[opc] "i" (TAGGED_MEM_LOAD_REC_OPC)); \
} while (0)

#define NATIVE_STORE_TAGGED_MMUREG(_addr, reg) \
do { \
	unsigned long long _tmp; \
	__no_asm_inline(2) \
	asm volatile ("mmurr %%" #reg ", %[tmp]\n" \
		      "strd [ %[addr] + %[opc] ], %[tmp]\n" \
		      : [tmp] "=r" (_tmp) \
		      : [addr] "m" (*((unsigned long long *) (_addr))), \
			[opc] "i" (TAGGED_MEM_STORE_REC_OPC)); \
} while (0)

#define NATIVE_GET_MMU_DEBUG_REG(reg_no) \
({ \
	register u64 res; \
	asm volatile ("ldd,5 \t[%1 + 0] %2, %0" \
		: "=r" (res) \
		: "ri" ((u64) _DEBUG_REG_NO_TO_MMU_ADDR(reg_no)), \
		  "i" MAS_MMU_DEBUG_REG); \
	res; \
})
#define NATIVE_SET_MMU_DEBUG_REG(reg_no, val) \
({ \
	asm volatile ("std,2 \t[%0 + 0] %1, %2" \
		: \
		: "ri" ((u64) _DEBUG_REG_NO_TO_MMU_ADDR(reg_no)), \
		  "i" MAS_MMU_DEBUG_REG, \
		  "ri" ((u64) (val))); \
})

#define NATIVE_GET_AAUREG(reg, chan_letter) \
({ \
	u32 res; \
	asm ("aaurr," #chan_letter " \t%%" #reg ", %0" \
		: "=r" (res)); \
	res; \
})

/* This macro is used to pack two 'aaurr' into one long instruction */
#define NATIVE_GET_AAUREGS(l_reg, r_reg, lval, rval) \
({ \
    asm ("aaurr,2 \t%%" #l_reg ", %0\n" \
	 "aaurr,5 \t%%" #r_reg ", %1" \
	 : "=r" (lval), "=r" (rval)); \
})

#define NATIVE_SET_AAUREG(reg, val, chan_letter) \
({ \
	int unused; \
	asm ("aaurw," #chan_letter " %1, %%" #reg \
	     : "=r" (unused) \
	     : "r" ((u32) (val))); \
})

/* This macro is used to pack two 'aaurr' into one long instruction */
#define NATIVE_SET_AAUREGS(l_reg, r_reg, lval, rval) \
do { \
	int unused; \
	asm ("aaurw,2 %1, %%" #l_reg "\n" \
	     "aaurw,5 %2, %%" #r_reg \
	     : "=r" (unused) \
	     : "r" ((u32) (lval)), "r" ((u32) (rval))); \
} while (0)

#define NATIVE_GET_AAUDREG(reg, chan_letter) \
({ \
	u64 res; \
	asm ("aaurrd," #chan_letter " %%" #reg ", %0" \
		: "=r" (res)); \
	res; \
})

#define NATIVE_GET_AAUDREGS(l_reg, r_reg, lval, rval) \
({ \
    asm ("aaurrd,2 %%" #l_reg ", %0\n" \
	 "aaurrd,5 %%" #r_reg ", %1" \
	 : "=r" (lval), "=r" (rval)); \
})


#define NATIVE_SET_AAUDREG(reg, val, chan_letter) \
do { \
	int unused; \
	asm ("aaurwd," #chan_letter " %1, %%" #reg \
	     : "=r" (unused) \
	     : "r" (val)); \
} while (0)

#define NATIVE_SET_AAUDREGS(l_reg, r_reg, lval, rval) \
do { \
	int unused; \
	asm ("aaurwd,2 %1, %%" #l_reg "\n" \
	     "aaurwd,5 %2, %%" #r_reg \
	     : "=r" (unused) \
	     : "r" (lval), "r" (rval)); \
} while (0)


#define NATIVE_GET_AAUQREGS(mem_p, reg1, reg2, reg3, reg4) \
do { \
	__asm_length(6) \
	asm volatile ("aaurrq \t%%" #reg1 ", %%qb[0]\n" \
		      "aaurrq \t%%" #reg2 ", %%qb[2]\n" \
		      "aaurrq \t%%" #reg3 ", %%qb[4]\n" \
		      "aaurrq \t%%" #reg4 ", %%qb[6]\n" \
		      "{addd %%db[0], 0, %0\n" \
		      " addd %%db[1], 0, %1\n" \
		      " addd %%db[2], 0, %2\n" \
		      " addd %%db[3], 0, %3}\n" \
		      "{addd %%db[4], 0, %4\n" \
		      " addd %%db[5], 0, %5\n" \
		      " addd %%db[6], 0, %6\n" \
		      " addd %%db[7], 0, %7}\n" \
		      : "=r" ((mem_p)->lo), "=r" ((mem_p)->hi), \
			"=r" ((mem_p + 1)->lo), "=r" ((mem_p + 1)->hi), \
			"=r" ((mem_p + 2)->lo), "=r" ((mem_p + 2)->hi), \
			"=r" ((mem_p + 3)->lo), "=r" ((mem_p + 3)->hi) \
		      : \
		      : "%b[0]", "%b[1]", "%b[2]", "%b[3]", \
			"%b[4]", "%b[5]", "%b[6]", "%b[7]"); \
} while (0)

#define NATIVE_SET_AAUQREGS(mem_p, reg1, reg2, reg3, reg4) \
do { \
	__asm_length(7) \
	asm volatile ("{ldd,0 [ %0 + 0x0 ], %%db[0]\n" \
		      " ldd,2 [ %0 + 0x8 ], %%db[1]\n" \
		      " ldd,3 [ %0 + 0x10 ], %%db[2]\n" \
		      " ldd,5 [ %0 + 0x18 ], %%db[3]}\n" \
		      ALTERNATIVE_1_ALTINSTR \
		      /* CPU_FEAT_ISET_V6 version */ \
			      "{nop 3\n" \
			      " ldd,0 [ %0 + 0x20 ], %%db[4]\n" \
			      " ldd,2 [ %0 + 0x28 ], %%db[5]\n" \
			      " ldd,3 [ %0 + 0x30 ], %%db[6]\n" \
			      " ldd,5 [ %0 + 0x38 ], %%db[7]}\n" \
		      ALTERNATIVE_2_OLDINSTR \
		      /* Default version */ \
			      "{nop 1\n" \
			      " ldd,0 [ %0 + 0x20 ], %%db[4]\n" \
			      " ldd,2 [ %0 + 0x28 ], %%db[5]\n" \
			      " ldd,3 [ %0 + 0x30 ], %%db[6]\n" \
			      " ldd,5 [ %0 + 0x38 ], %%db[7]}\n" \
		      ALTERNATIVE_3_FEATURE(%[facility]) \
		      "aaurwq,2 %%qb[0], %%" #reg1 "\n" \
		      "aaurwq,2 %%qb[2], %%" #reg2 "\n" \
		      "aaurwq,2 %%qb[4], %%" #reg3 "\n" \
		      "aaurwq,2 %%qb[6], %%" #reg4 "\n" \
		      : \
		      : "r" (mem_p), [facility] "i" (CPU_FEAT_ISET_V6) \
		      : "%b[0]", "%b[1]", "%b[2]", "%b[3]", \
			"%b[4]", "%b[5]", "%b[6]", "%b[7]"); \
} while (0)

#define NATIVE_CLEAR_AAU_AADS() \
do { \
	__uint128_t empty_aad; \
	asm ("addd 0x0, 0x0, %L[empty_aad]\n" \
	     "addd 0x0, 0x0, %H[empty_aad]\n" \
	     "aaurwq %[empty_aad], %%aad0\n" \
	     "aaurwq %[empty_aad], %%aad1\n" \
	     "aaurwq %[empty_aad], %%aad2\n" \
	     "aaurwq %[empty_aad], %%aad3\n" \
	     "aaurwq %[empty_aad], %%aad4\n" \
	     "aaurwq %[empty_aad], %%aad5\n" \
	     "aaurwq %[empty_aad], %%aad6\n" \
	     "aaurwq %[empty_aad], %%aad7\n" \
	     "aaurwq %[empty_aad], %%aad8\n" \
	     "aaurwq %[empty_aad], %%aad9\n" \
	     "aaurwq %[empty_aad], %%aad10\n" \
	     "aaurwq %[empty_aad], %%aad11\n" \
	     "aaurwq %[empty_aad], %%aad12\n" \
	     "aaurwq %[empty_aad], %%aad13\n" \
	     "aaurwq %[empty_aad], %%aad14\n" \
	     "aaurwq %[empty_aad], %%aad15\n" \
	     "aaurwq %[empty_aad], %%aad16\n" \
	     "aaurwq %[empty_aad], %%aad17\n" \
	     "aaurwq %[empty_aad], %%aad18\n" \
	     "aaurwq %[empty_aad], %%aad19\n" \
	     "aaurwq %[empty_aad], %%aad20\n" \
	     "aaurwq %[empty_aad], %%aad21\n" \
	     "aaurwq %[empty_aad], %%aad22\n" \
	     "aaurwq %[empty_aad], %%aad23\n" \
	     "aaurwq %[empty_aad], %%aad24\n" \
	     "aaurwq %[empty_aad], %%aad25\n" \
	     "aaurwq %[empty_aad], %%aad26\n" \
	     "aaurwq %[empty_aad], %%aad27\n" \
	     "aaurwq %[empty_aad], %%aad28\n" \
	     "aaurwq %[empty_aad], %%aad29\n" \
	     "aaurwq %[empty_aad], %%aad30\n" \
	     "aaurwq %[empty_aad], %%aad31\n" \
	     : [empty_aad] "=r" (empty_aad) \
	     : ); \
} while (0)

/* Clear AAU to prepare it for restoring */
#define NATIVE_CLEAR_APB() \
do { \
	__asm_length(1) \
	asm volatile ("1:\n" \
		      "{ipd 0; disp %%ctpr2, 1b}" \
		      : \
		      : \
		      : "ctpr2"); \
} while (0)

/* Do "disp" for all %ctpr's */
#define E2K_DISP_CTPRS() \
do { \
	__asm_length(3) \
	asm volatile ("1:\n" \
		      "{ipd 0; disp %%ctpr1, 1b}" \
		      "{ipd 0; disp %%ctpr2, 1b}" \
		      "{ipd 0; disp %%ctpr3, 1b}" \
		      : \
		      : \
		      : "ctpr1", "ctpr2", "ctpr3"); \
} while (0)

#define LOAD_NV_MAS(_addr, _val, _mas, size_letter, clobber) \
do { \
	__no_asm_inline(1) \
	asm NOT_VOLATILE ("ld" #size_letter" %[addr], %[val], mas=%[mas]" \
		: [val] "=r" (_val) \
		: [addr] "m" (*(_addr)), \
		  [mas] "i" (_mas) \
		: clobber); \
} while (0)

#define STORE_NV_MAS(_addr, _val, _mas, size_letter, clobber) \
do { \
	if ((_mas) == MAS_STORE_RELEASE_V6(MAS_MT_0) || \
	    (_mas) == MAS_STORE_RELEASE_V6(MAS_MT_1)) { \
		__no_asm_inline(1) \
		asm NOT_VOLATILE ( \
			ALTERNATIVE( \
			/* Default version */ \
				"{wait st_c=1, ld_c=1\n" \
				" st" #size_letter" %[addr], %[val]}", \
			/* CPU_NO_HWBUG_STORE_RELEASE version */ \
				"{st" #size_letter" %[addr], %[val], mas=%[mas]}", \
			%[cpu_no_hwbug_store_release]) \
			: [addr] "=m" (*(_addr)) \
			: [val] "r" (_val), \
			  [mas] "i" (_mas), \
			  [cpu_no_hwbug_store_release] "i" (CPU_NO_HWBUG_STORE_RELEASE) \
			: clobber); \
	} else { \
		__no_asm_inline(1) \
		asm NOT_VOLATILE ("st" #size_letter" %[addr], %[val], mas=%[mas]" \
			: [addr] "=m" (*(_addr)) \
			: [val] "r" (_val), \
			  [mas] "i" (_mas) \
			: clobber); \
	} \
} while (0)

/**
 * IO read/write
 *
 * (Bug 79732) All UC accesses from the same long
 * instruction must land in the same virtual page,
 * and that instruction must have only UC memory
 * accesses, only then hardware ensures access order.
 */
#define IO_LOAD_NV_MAS(_addr, _val, _mas, size_letter, clobber) \
do { \
	__no_asm_inline(1) \
	asm NOT_VOLATILE ("{ld" #size_letter" %[addr], %[val], mas=%[mas]}" \
		: [val] "=r" (_val) \
		: [addr] "m" (*(_addr)), \
		  [mas] "i" (_mas) \
		: clobber); \
} while (0)

#define IO_STORE_NV_MAS(_addr, _val, _mas, size_letter, clobber) \
do { \
	if ((_mas) == MAS_STORE_RELEASE_V6(MAS_MT_0) || \
	    (_mas) == MAS_STORE_RELEASE_V6(MAS_MT_1)) { \
		__no_asm_inline(1) \
		asm NOT_VOLATILE ( \
			ALTERNATIVE( \
			/* Default version */ \
				"{wait st_c=1, ld_c=1\n" \
				" st" #size_letter" %[addr], %[val]}", \
			/* CPU_NO_HWBUG_STORE_RELEASE version */ \
				"{st" #size_letter" %[addr], %[val], mas=%[mas]}", \
			%[cpu_no_hwbug_store_release]) \
			: [addr] "=m" (*(_addr)) \
			: [val] "r" (_val), \
			  [mas] "i" (_mas), \
			  [cpu_no_hwbug_store_release] "i" (CPU_NO_HWBUG_STORE_RELEASE) \
			: clobber); \
	} else { \
		__no_asm_inline(1) \
		asm NOT_VOLATILE ("{st" #size_letter" %[addr], %[val], mas=%[mas]}" \
			: [addr] "=m" (*(_addr)) \
			: [val] "r" (_val), \
			  [mas] "i" (_mas) \
			: clobber); \
	} \
} while (0)

/*
 * Do load with specified MAS
 */

/*
 * After iset v6 these loads are not ordered with regards to RAM accesses.
 * so add barriers manually. Driver writers who want control over barriers
 * should use readX_relaxed()/writeX_relaxed() anyway.
 */
#if CONFIG_CPU_ISET_MIN >= 6

# define READ_MAS_BARRIER_AFTER(mas) \
do { \
	if ((mas) == MAS_IOADDR) \
		__E2K_WAIT(_ld_c | _lal | _sal); \
} while (0)
# define WRITE_MAS_BARRIER_BEFORE(mas) \
do { \
	if ((mas) == MAS_IOADDR) \
		__E2K_WAIT(_st_c | _sas | _ld_c | _sal); \
} while (0)
/*
 * Not required by documentation, but this is how
 * x86 works and how most of the drivers are tested.
 */
# define WRITE_MAS_BARRIER_AFTER(mas) \
do { \
	if ((mas) == MAS_IOADDR) \
		__E2K_WAIT(_st_c | _sas); \
} while (0)

#elif !defined CONFIG_E2K_MACHINE

# define READ_MAS_BARRIER_AFTER(mas) \
do { \
	if ((mas) == MAS_IOADDR) \
		__E2K_WAIT(_ld_c); \
} while (0)
# define WRITE_MAS_BARRIER_BEFORE(mas) \
do { \
	if ((mas) == MAS_IOADDR) \
		__E2K_WAIT(_st_c | _sas | _ld_c | _sal); \
} while (0)
/*
 * Not required by documentation, but this is how
 * x86 works and how most of the drivers are tested.
 */
# define WRITE_MAS_BARRIER_AFTER(mas) \
do { \
	if ((mas) == MAS_IOADDR) \
		__E2K_WAIT(_st_c | _sas); \
} while (0)

#else

# define READ_MAS_BARRIER_AFTER(mas)
# define WRITE_MAS_BARRIER_BEFORE(mas)
# define WRITE_MAS_BARRIER_AFTER(mas)
#endif

#define NATIVE_DO_READ_MAS(addr, mas, type, size_letter, chan_letter) \
({ \
	register type res; \
	int __mas = (mas); \
	asm volatile ("ld" #size_letter "," #chan_letter " \t0x0, [%1] %2, %0" \
		: "=r" (res) \
		: "r" ((u64) (addr)), \
		  "i" (__mas)); \
	READ_MAS_BARRIER_AFTER(__mas); \
	res; \
})

#define NATIVE_DO_WRITE_MAS(addr, val, mas, type, size_letter, chan_letter) \
({ \
	int __mas = (mas); \
	WRITE_MAS_BARRIER_BEFORE(__mas); \
	asm volatile ("st" #size_letter "," #chan_letter " \t0x0, [%0] %2, %1" \
		: \
		: "r" ((u64) (addr)), \
		  "r" ((type) (val)), \
		  "i" (__mas) \
		: "memory"); \
	WRITE_MAS_BARRIER_AFTER(__mas); \
})

#define NATIVE_DO_WRITE_TAGGED(addr, val, type, size_letter, chan_letter) \
({ \
	asm volatile ("st" #size_letter ",sm," #chan_letter " \t0x0, [%0], %1" \
		: \
		: "r" ((u64) (addr)), \
		  "r" ((type) (val))); \
})

#define NATIVE_READ_MAS_B_CH(addr, mas, chan_letter) \
		NATIVE_DO_READ_MAS((addr), (mas), u8, b, chan_letter)
#define NATIVE_READ_MAS_H_CH(addr, mas, chan_letter) \
		NATIVE_DO_READ_MAS((addr), (mas), u16, h, chan_letter)
#define NATIVE_READ_MAS_W_CH(addr, mas, chan_letter) \
		NATIVE_DO_READ_MAS((addr), (mas), u32, w, chan_letter)
#define NATIVE_READ_MAS_D_CH(addr, mas, chan_letter) \
		NATIVE_DO_READ_MAS((addr), (mas), u64, d, chan_letter)

/* Stops CPU until required flags are set in 64-bit value */
#define E2K_WATCH_FOR_MODIFICATION_64(_addr, _flags) \
({ \
	u64 _res; \
	__asm_length(10) \
	asm volatile (\
		"{nop 4\n" \
		" disp %%ctpr1, 1f\n" \
		" ldd,0 [ %[addr] + 0x0 ], %[res], mas=%[mas]}\n" \
		"{nop 2\n" \
		" cmpandedb %[res], %[flags], %%pred20}\n" \
		/* 153764: do not use %cmp here */ \
		"ct %%ctpr1 ? ~ %%pred20\n" \
		"wait mem_mod=1, int=1\n" \
		"1:\n" \
		: [res] "=r" (_res) \
		: [addr] "m" (*(u64 *) (_addr)), \
		  [flags] "ir" (_flags), \
		  [mas] "i" (MAS_WATCH_FOR_MODIFICATION_V6) \
		: "pred20"); \
	_res; \
})
/* Stops CPU until required mask are set or reset in 64-bit value */
#define E2K_WATCH_FOR_MASK_SET_RESET_64(_addr, _mask, _set) \
({ \
	u64 _res; \
	u8 _cond; \
	__asm_length(10) \
	asm volatile (\
		"{\n" \
		" nop 4\n" \
		" disp %%ctpr1, 1f\n" \
		" ldd,0 [ %[addr] + 0x0 ], %[res], mas=%[mas]\n" \
		"}\n" \
		"{\n" \
		" nop 2\n" \
		" cmpandesb %[set], 0xff, %%pred20\n" \
		" cmpandedb %[res], %[mask], %%pred21\n" \
		"}\n" \
		"{\n" \
		" merges 0x0, 0x1, %[cond], %%pred21 ? %%pred20\n" \
		" merges 0x0, 0x1, %[cond], ~ %%pred21 ? ~ %%pred20\n" \
		"}\n" \
		"{\n" \
		" nop 2\n" \
		" cmpesb %[cond], 0x0, %%pred20\n" \
		"}\n" \
		/* 153764: do not use %cmp here */ \
		"ct %%ctpr1 ? ~ %%pred20\n" \
		"wait mem_mod=1, int=1\n" \
		"1:\n" \
		: [res] "=r" (_res), \
		  [cond] "=r" (_cond) \
		: [addr] "m" (*(u64 *) (_addr)), \
		  [mask] "ir" (_mask), \
		  [set] "ir" (_set), \
		  [mas] "i" (MAS_WATCH_FOR_MODIFICATION_V6) \
		: "pred20", "pred21"); \
	_res; \
})
#define E2K_WATCH_FOR_MASK_SET_64(_addr, _mask) \
		E2K_WATCH_FOR_MASK_SET_RESET_64(_addr, _mask, true)
#define E2K_WATCH_FOR_MASK_RESET_64(_addr, _mask) \
		E2K_WATCH_FOR_MASK_SET_RESET_64(_addr, _mask, false)

#define NATIVE_READ_MAS_B(addr, mas)  NATIVE_READ_MAS_B_CH((addr), (mas), 2)
#define NATIVE_READ_MAS_H(addr, mas)  NATIVE_READ_MAS_H_CH((addr), (mas), 2)
#define NATIVE_READ_MAS_W(addr, mas)  NATIVE_READ_MAS_W_CH((addr), (mas), 2)
#define NATIVE_READ_MAS_D(addr, mas)  NATIVE_READ_MAS_D_CH((addr), (mas), 2)

#define NATIVE_READ_MAS_B_5(addr, mas)  NATIVE_READ_MAS_B_CH((addr), (mas), 5)
#define NATIVE_READ_MAS_H_5(addr, mas)  NATIVE_READ_MAS_H_CH((addr), (mas), 5)
#define NATIVE_READ_MAS_W_5(addr, mas)  NATIVE_READ_MAS_W_CH((addr), (mas), 5)
#define NATIVE_READ_MAS_D_5(addr, mas)  NATIVE_READ_MAS_D_CH((addr), (mas), 5)

#define NATIVE_WRITE_MAS_B_CH(addr, val, mas, chan_letter) \
		NATIVE_DO_WRITE_MAS((addr), (val), (mas), u8, b, \
					chan_letter)
#define NATIVE_WRITE_MAS_H_CH(addr, val, mas, chan_letter) \
		NATIVE_DO_WRITE_MAS((addr), (val), (mas), u16, h, \
					chan_letter)
#define NATIVE_WRITE_MAS_W_CH(addr, val, mas, chan_letter) \
		NATIVE_DO_WRITE_MAS((addr), (val), (mas), u32, w, \
					chan_letter)
#define NATIVE_WRITE_MAS_D_CH(addr, val, mas, chan_letter) \
		NATIVE_DO_WRITE_MAS((addr), (val), (mas), u64, d, \
					chan_letter)
#define	NATIVE_WRITE_TAGGED_D_CH(addr, val, chan_letter) \
		NATIVE_DO_WRITE_TAGGED((addr), (val), u64, d, \
					chan_letter)
#define NATIVE_WRITE_MAS_B(addr, val, mas)				\
		NATIVE_DO_WRITE_MAS(addr, val, mas, u8, b, 2)
#define NATIVE_WRITE_MAS_H(addr, val, mas)				\
		NATIVE_DO_WRITE_MAS(addr, val, mas, u16, h, 2)
#define NATIVE_WRITE_MAS_W(addr, val, mas)				\
		NATIVE_DO_WRITE_MAS(addr, val, mas, u32, w, 2)
#define NATIVE_WRITE_MAS_D(addr, val, mas)				\
		NATIVE_DO_WRITE_MAS(addr, val, mas, u64, d, 2)

/*
 * Read from and write to system configuration registers SIC
 * Now SIC is the same as NBSRs registers
 */
#define native_set_sicreg(reg_off, val, cln, pln) \
({ \
	register u64 addr; \
	register u64 node_id = (cln) << 2; \
	node_id = node_id + ((pln)&0x3); \
	addr = (u64) THE_NODE_NBSR_PHYS_BASE(node_id); \
	addr = addr + reg_off; \
	NATIVE_WRITE_MAS_W(addr, val, MAS_IOADDR); \
})
#define native_get_sicreg(reg_off, cln, pln) \
({ \
	register u32 res; \
	register u64 addr; \
	register u64 node_id = (cln) << 2; \
	node_id = node_id + ((pln)&0x3); \
	addr = (u64) THE_NODE_NBSR_PHYS_BASE(node_id); \
	addr = addr + reg_off; \
	res = NATIVE_READ_MAS_W(addr, MAS_IOADDR); \
	res; \
})

#define NATIVE_SET_SICREG(reg, val, cln, pln) \
		native_set_sicreg(SIC_##reg, val, cln, pln)
#define NATIVE_GET_SICREG(reg, cln, pln) \
		native_get_sicreg(SIC_##reg, cln, pln)


#if !defined(CONFIG_BOOT_E2K) && !defined(E2K_P2V)

# define MIGHT_HAVE_CPU_HWBUG_PREFETCH_EMPTY() \
		(IS_ENABLED(CONFIG_CPU_E16C) || IS_ENABLED(CONFIG_CPU_E2C3))
/* Use semi-spec. prefetches on kernels with enabled support
 * and fallback to fully speculative prefetches otherwise.
 *
 * CPU_HWBUG_PREFETCH_EMPTY - to avoid expensive dynamic checks,
 * just check the model without checking revision */
# if defined(__LCC__)
#  define __MAS_LOAD_SEMI_SPEC() \
		((IS_ENABLED(CONFIG_SEMI_SPECULATIVE_KERNEL) ? 0 : MAS_LOAD_SPEC) | \
		 (MIGHT_HAVE_CPU_HWBUG_PREFETCH_EMPTY() ? MAS_BYPASS_L1_CACHE : 0))
# else
#  define __MAS_LOAD_SEMI_SPEC() (MAS_LOAD_SPEC | \
		 (MIGHT_HAVE_CPU_HWBUG_PREFETCH_EMPTY() ? MAS_BYPASS_L1_CACHE : 0))
# endif

# define E2K_PREFETCH_L2_SPEC(addr) \
do { \
	int unused; \
	asm ("ldb,sm %1, 0, %%empty, mas=%2\n" \
		: "=r" (unused) \
		: "r" (addr), \
		  "i" (__MAS_LOAD_SEMI_SPEC() | MAS_BYPASS_L1_CACHE)); \
} while (0)

# define E2K_PREFETCH_L2_NOSPEC_OFFSET(addr, offset) \
do { \
	int unused; \
	asm ("ldb %1, %2, %%empty, mas=%3\n" \
		: "=r" (unused) \
		: "r" (addr), \
		  "i" (offset), \
		  "i" (MAS_BYPASS_L1_CACHE)); \
} while (0)

# define E2K_PREFETCH_256_LOOP(_addr, _lcnt, _mas) \
do { \
	e2k_lsr_t lsr = { 0 }; \
	unsigned long __pref_addr = (unsigned long) (_addr); \
	unsigned long __pref_addr1 = __pref_addr, \
		      __pref_addr2 = __pref_addr + 2 * PREFETCH_STRIDE; \
	lsr.vlc = 1; \
	lsr.lcnt = _lcnt; \
	__asm_length(5) \
	asm (	"{rwd %[lsr], %%lsr\n" \
		" disp %%ctpr1, 0f}\n" \
		"{nop} {nop} {nop} {nop}" /* lsr->ct delay; also CPU_HWBUG_RWD_LSR */ \
		"0:\n" \
		"{loop_mode\n" \
		" ct %%ctpr1 ? %%NOT_LOOP_END\n" \
		" alc alcf = 1, alct = 1\n" \
		" addd,1 %[addr1], %[iteration_stride], %[addr1]\n" \
		" addd,4 %[addr2], %[iteration_stride], %[addr2]\n" \
		" ldb,0,sm %[addr1], 0, %%empty, mas=%[mas]\n" \
		" ldb,2,sm %[addr1], %[prefetch_stride], %%empty, mas=%[mas]\n" \
		" ldb,3,sm %[addr2], 0, %%empty, mas=%[mas]\n" \
		" ldb,5,sm %[addr2], %[prefetch_stride], %%empty, mas=%[mas]}\n" \
		: [addr1] "+r" (__pref_addr1), [addr2] "+r" (__pref_addr2) \
		: [lsr] "ir" (AW(lsr)), \
		  [mas] "i" (MIGHT_HAVE_CPU_HWBUG_PREFETCH_EMPTY() ? \
					MAS_BYPASS_L1_CACHE : (_mas)), \
		  [prefetch_stride] "i" (PREFETCH_STRIDE), \
		  [iteration_stride] "i" (4 * PREFETCH_STRIDE) \
		: /* "lsr" cannot be specified so clobber all ctpr instead */ \
		  "ctpr1", "ctpr2", "ctpr3"); \
} while (0)

# define E2K_PREFETCH_L1_SPEC(addr) \
do { \
	int unused; \
	asm ("ldb,sm %1, 0, %%empty, mas=%2\n" \
		: "=r" (unused) \
		: "r" (addr), \
		  "i" (__MAS_LOAD_SEMI_SPEC())); \
} while (0)

# define E2K_PREFETCH_L1_NOSPEC(addr) \
do { \
	int unused; \
	asm ("ldb %1, 0, %%empty, mas=%2" \
		: "=r" (unused) \
		: "r" (addr), \
		  "i" (MIGHT_HAVE_CPU_HWBUG_PREFETCH_EMPTY() ? \
				MAS_BYPASS_L1_CACHE : 0)); \
} while (0)

# define E2K_PREFETCH_L1_SPEC_OFFSET(addr, offset) \
do { \
	int unused; \
	asm ("ldb,sm %1, %2, %%empty, mas=%3\n" \
		: "=r" (unused) \
		: "r" (addr), \
		  "i" (offset), \
		  "i" (__MAS_LOAD_SEMI_SPEC())); \
} while (0)
#else
# define E2K_PREFETCH_L2_SPEC(addr)		do { (void) (addr); } while (0)
# define E2K_PREFETCH_L2_NOSPEC_OFFSET(addr, offset) \
				do { (void) (addr); (void) (offset); } while (0)
# define E2K_PREFETCH_256_LOOP(addr, lcnt, mas) \
	do { (void) (addr); (void) (lcnt); (void) (mas); } while (0)
# define E2K_PREFETCH_L1_SPEC(addr)		do { (void) (addr); } while (0)
# define E2K_PREFETCH_L1_NOSPEC(addr)		do { (void) (addr); } while (0)
# define E2K_PREFETCH_L1_SPEC_OFFSET(addr, offset) \
				do { (void) (addr); (void) (offset); } while (0)
#endif

/*
 * Recovery operations
 * chan: 0, 1, 2 or 3
 */
#define NATIVE_RECOVERY_TAGGED_LOAD_TO(_addr, _opc, _val, _tag, _chan) \
do { \
	__no_asm_inline(8) \
	asm (	"{nop 1\n" \
		" cmpesb,0 %[chan], 0, %%pred20\n" \
		" cmpesb,1 %[chan], 1, %%pred21\n" \
		" cmpesb,3 %[chan], 2, %%pred22\n" \
		" cmpesb,4 %[chan], 3, %%pred23}\n" \
		"{nop 4\n" \
		" ldrd,0 [ %[addr] + %[opc] ], %[val] ? %%pred20\n" \
		" ldrd,2 [ %[addr] + %[opc] ], %[val] ? %%pred21\n" \
		" ldrd,3 [ %[addr] + %[opc] ], %[val] ? %%pred22\n" \
		" ldrd,5 [ %[addr] + %[opc] ], %[val] ? %%pred23}\n" \
		"{gettagd,2 %[val], %[tag]\n" \
		" puttagd,5 %[val], 0, %[val]}\n" \
		: [val] "=r"(_val), [tag] "=r"(_tag) \
		: [addr] "r" (_addr), [opc] "r" (_opc), \
		  [chan] "r" ((u32) (_chan)) \
		: "memory", "pred20", "pred21", "pred22", "pred23"); \
} while (0)

/*
 * The same as asm-macros above, but additionally sets return value at '_ret'.
 * If recovery operations complete successfully, then '_ret' sets to 0.
 * If execution is interrupted by page fault, then '_ret' value does not change.
 */
#define TRY_RECOVERY_TAGGED_LOAD_TO(_addr, _opc, _val, _tag, _chan, _ret) \
do { \
	__no_asm_inline(8) \
	asm (	"{nop 1\n" \
		" cmpesb,0 %[chan], 0, %%pred20\n" \
		" cmpesb,1 %[chan], 1, %%pred21\n" \
		" cmpesb,3 %[chan], 2, %%pred22\n" \
		" cmpesb,4 %[chan], 3, %%pred23}\n" \
		"{nop 4\n" \
		" ldrd,0 [ %[addr] + %[opc] ], %[val] ? %%pred20\n" \
		" ldrd,2 [ %[addr] + %[opc] ], %[val] ? %%pred21\n" \
		" ldrd,3 [ %[addr] + %[opc] ], %[val] ? %%pred22\n" \
		" ldrd,5 [ %[addr] + %[opc] ], %[val] ? %%pred23}\n" \
		"{addd,0 0, 0, %[ret]\n" \
		" gettagd,2 %[val], %[tag]\n" \
		" puttagd,5 %[val], 0, %[val]}\n" \
		: [val] "=r"(_val), [tag] "=r"(_tag), \
		  [ret] "=r" (_ret) \
		: [addr] "r" (_addr), [opc] "r" (_opc), \
		  [chan] "r" ((u32) (_chan)) \
		: "memory", "pred20", "pred21", "pred22", "pred23"); \
} while (0)

#define NATIVE_RECOVERY_LOAD_TO(addr, opc, val, chan_letter) \
({ \
	asm volatile ("ldrd," #chan_letter "\t[%1 + %2], %0" \
			: "=r"(val) \
			: "r" ((u64) (addr)), \
			  "r" ((u64) (opc))); \
})

#define NATIVE_LOAD_TAGGED_DGREGS(addr, numlo, numhi)	\
do {							\
	asm ("ldrd,2 [%0 + %1], %%dg" #numlo "\n"	\
	     "ldrd,5 [%0 + %2], %%dg" #numhi "\n"	\
	     :						\
	     : "r" (addr),				\
	       "i" (TAGGED_MEM_LOAD_REC_OPC),		\
	       "i" (TAGGED_MEM_LOAD_REC_OPC | 8UL)	\
	     : "%g" #numlo, "%g" #numhi);		\
} while (0)

#define NATIVE_STORE_TAGGED_DGREG(addr, greg_no) \
do { \
	asm ("strd [%0 + %1], %%dg" #greg_no \
	     : \
	     : "r" (addr), "i" (TAGGED_MEM_STORE_REC_OPC)); \
} while (0)

/*
 * chan: 0, 1, 2 or 3
 * vr: set to 0 if we want to preserve the lower 4-byte word
 *     (same as vr in cellar)
 */
#define NATIVE_RECOVERY_LOAD_TO_THE_GREG_CH_VR(_addr, _opc_lo, _opc_hi, \
		greg_no, _chan, _vr, _quadro) \
do { \
	u64 val_lo, val_hi; \
	u32 __chan = (u32) (_chan); \
	u32 __quadro = (u32) (_quadro); \
	u32 __chan_q = (__quadro) ? __chan : 4; /* Not existent channel - skip */ \
	__no_asm_inline(10) \
	asm volatile ( \
		"{disp %%ctpr1, qpswitchd_sm\n" \
		" cmpesb,0 %[chan], 0, %%pred20\n" \
		" cmpesb,1 %[chan], 1, %%pred21\n" \
		" cmpesb,3 %[chan], 2, %%pred22\n" \
		" cmpesb,4 %[chan], 3, %%pred23}\n" \
		"{cmpesb,0 %[chan_q], 0, %%pred24\n" \
		" cmpesb,1 %[chan_q], 1, %%pred25\n" \
		" cmpesb,3 %[chan_q], 2, %%pred26\n" \
		" cmpesb,4 %[chan_q], 3, %%pred27}\n" \
		"{ldrd,0 [ %[addr] + %[opc_lo] ], %[val_lo] ? %%pred20\n" \
		" ldrd,2 [ %[addr] + %[opc_lo] ], %[val_lo] ? %%pred21\n" \
		" ldrd,3 [ %[addr] + %[opc_lo] ], %[val_lo] ? %%pred22\n" \
		" ldrd,5 [ %[addr] + %[opc_lo] ], %[val_lo] ? %%pred23\n" \
		" cmpesb,1 %[quadro], 0, %%pred18\n" \
		" cmpesb,4 %[vr], 0, %%pred19}\n" \
		"{nop 3\n" \
		" ldrd,0 [ %[addr] + %[opc_hi] ], %[val_hi] ? %%pred24\n" \
		" ldrd,2 [ %[addr] + %[opc_hi] ], %[val_hi] ? %%pred25\n" \
		" ldrd,3 [ %[addr] + %[opc_hi] ], %[val_hi] ? %%pred26\n" \
		" ldrd,5 [ %[addr] + %[opc_hi] ], %[val_hi] ? %%pred27}\n" \
		"{movts %%g" #greg_no ", %[val_lo] ? %%pred19}\n" \
		"{movtd %[val_hi], %%dg" #greg_no " ? ~ %%pred18\n" \
		" addd %[greg], 0, %%db[0] ? ~ %%pred18\n" \
		" call %%ctpr1, wbs=%# ? ~ %%pred18}\n" \
		"{movtd %[val_lo], %%dg" #greg_no "}\n" \
		: [val_lo] "=&r" (val_lo), [val_hi] "=&r" (val_hi) \
		: [addr] "r" (_addr), [vr] "ir" ((u32) (_vr)), \
		  [chan] "ir" (__chan), [chan_q] "ir" (__chan_q), \
		  [opc_lo] "r" ((u64) (_opc_lo)), [opc_hi] "r" ((u64) (_opc_hi)), \
		  [quadro] "r" (__quadro), [greg] "i" ((u64) (greg_no)) \
		: "call", "memory", "pred18", "pred19", "pred20", "pred21", \
		  "pred22", "pred23", "pred24", "pred25", "pred26", "pred27", \
		  "g" #greg_no); \
} while (0)

/*
 * The same as asm-macros above, but additionally sets return value at '_ret'.
 * If recovery operations complete successfully, then '_ret' sets to 0.
 * If execution is interrupted by page fault, then '_ret' value does not change.
 */
#define TRY_RECOVERY_LOAD_TO_THE_GREG_CH_VR(_addr, _opc_lo, _opc_hi, \
		greg_no, _chan, _vr, _quadro, _ret) \
do { \
	u64 val_lo, val_hi; \
	u32 __chan = (u32) (_chan); \
	u32 __quadro = (u32) (_quadro); \
	u32 __chan_q = (__quadro) ? __chan : 4; /* Not existent channel - skip */ \
	__no_asm_inline(10) \
	asm volatile ( \
		"{disp %%ctpr1, qpswitchd_sm\n" \
		" cmpesb,0 %[chan], 0, %%pred20\n" \
		" cmpesb,1 %[chan], 1, %%pred21\n" \
		" cmpesb,3 %[chan], 2, %%pred22\n" \
		" cmpesb,4 %[chan], 3, %%pred23}\n" \
		"{cmpesb,0 %[chan_q], 0, %%pred24\n" \
		" cmpesb,1 %[chan_q], 1, %%pred25\n" \
		" cmpesb,3 %[chan_q], 2, %%pred26\n" \
		" cmpesb,4 %[chan_q], 3, %%pred27}\n" \
		"{ldrd,0 [ %[addr] + %[opc_lo] ], %[val_lo] ? %%pred20\n" \
		" ldrd,2 [ %[addr] + %[opc_lo] ], %[val_lo] ? %%pred21\n" \
		" ldrd,3 [ %[addr] + %[opc_lo] ], %[val_lo] ? %%pred22\n" \
		" ldrd,5 [ %[addr] + %[opc_lo] ], %[val_lo] ? %%pred23\n" \
		" cmpesb,1 %[quadro], 0, %%pred18\n" \
		" cmpesb,4 %[vr], 0, %%pred19}\n" \
		"{nop 3\n" \
		" ldrd,0 [ %[addr] + %[opc_hi] ], %[val_hi] ? %%pred24\n" \
		" ldrd,2 [ %[addr] + %[opc_hi] ], %[val_hi] ? %%pred25\n" \
		" ldrd,3 [ %[addr] + %[opc_hi] ], %[val_hi] ? %%pred26\n" \
		" ldrd,5 [ %[addr] + %[opc_hi] ], %[val_hi] ? %%pred27}\n" \
		"{movts %%g" #greg_no ", %[val_lo] ? %%pred19}\n" \
		"{movtd %[val_hi], %%dg" #greg_no " ? ~ %%pred18\n" \
		" addd %[greg], 0, %%db[0] ? ~ %%pred18\n" \
		" call %%ctpr1, wbs=%# ? ~ %%pred18}\n" \
		"{addd 0, 0, %[ret]\n" \
		" movtd %[val_lo], %%dg" #greg_no "}\n" \
		: [val_lo] "=&r" (val_lo), [val_hi] "=&r" (val_hi), \
		  [ret] "=r" (_ret) \
		: [addr] "r" (_addr), [vr] "ir" ((u32) (_vr)), \
		  [chan] "ir" (__chan), [chan_q] "ir" (__chan_q), \
		  [opc_lo] "r" ((u64) (_opc_lo)), [opc_hi] "r" ((u64) (_opc_hi)), \
		  [quadro] "r" (__quadro), [greg] "i" ((u64) (greg_no)) \
		: "call", "memory", "pred18", "pred19", "pred20", "pred21", \
		  "pred22", "pred23", "pred24", "pred25", "pred26", "pred27", \
		  "g" #greg_no); \
} while (0)

#define RECOVERY_LOAD_TO_THE_GREG_CH_VR(_addr, _opc_lo, _opc_hi, greg_no, \
		_chan, _vr, _quadro, _try, _ret) \
({ \
	if (_try) { \
		TRY_RECOVERY_LOAD_TO_THE_GREG_CH_VR(_addr, _opc_lo, _opc_hi, \
				greg_no, _chan, _vr, _quadro, _ret); \
	} else { \
		NATIVE_RECOVERY_LOAD_TO_THE_GREG_CH_VR(_addr, _opc_lo, _opc_hi, \
				greg_no, _chan, _vr, _quadro); \
	} \
})

/*
 * As NATIVE_RECOVERY_LOAD_TO_THE_GREG_CH_VR but repeats from cellar
 * an aligned atomic 16-bytes load.
 */
#define NATIVE_RECOVERY_LOAD_TO_THE_GREG_VR_ATOMIC_QP(_addr, _opc_lo, _opc_hi, greg_no, _vr) \
do { \
	u64 tmp; \
	/* #133760 Use a real quadro register when repeating atomic load */ \
	__no_asm_inline(9) \
	asm (	"{disp %%ctpr1, qpswitchd_sm\n" \
		" nop 4\n" \
		" ldrd,0 [ %[addr] + %[opc_lo] ], %%db[0]\n" \
		" ldrd,2 [ %[addr] + %[opc_hi] ], %%db[1]\n" \
		" cmpesb,1 %[vr], 0, %%pred19}\n" \
		"{movts,0 %%g" #greg_no ", %%b[0] ? %%pred19\n" \
		" movtd,1 %%db[1], %%dg" #greg_no "}\n" \
		"{movtd,0 %%db[0], %[tmp]\n" \
		" addd,2 %[greg], 0, %%db[0]\n" \
		" call %%ctpr1, wbs=%#}\n" \
		"{movtd,0 %[tmp], %%dg" #greg_no "}\n" \
		: [tmp] "=&r" (tmp) \
		: [opc_lo] "r" ((u64) (_opc_lo)), [opc_hi] "r" ((u64) (_opc_hi)), \
		  [addr] "r" (_addr), [vr] "ir" ((u32) (_vr)), \
		  [greg] "i" ((u64) (greg_no)) \
		: "call", "memory", "pred19", "g" #greg_no); \
} while (false)

/*
 * The same as asm-macros above, but additionally sets return value at '_ret'.
 * If recovery operations complete successfully, then '_ret' sets to 0.
 * If execution is interrupted by page fault, then '_ret' value does not change.
 */
#define TRY_RECOVERY_LOAD_TO_THE_GREG_VR_ATOMIC_QP(_addr, _opc_lo, _opc_hi, \
		greg_no, _vr, _ret) \
do { \
	u64 tmp; \
	/* #133760 Use a real quadro register when repeating atomic load */ \
	__no_asm_inline(9) \
	asm (	"{disp %%ctpr1, qpswitchd_sm\n" \
		" nop 4\n" \
		" ldrd,0 [ %[addr] + %[opc_lo] ], %%db[0]\n" \
		" ldrd,2 [ %[addr] + %[opc_hi] ], %%db[1]\n" \
		" cmpesb,1 %[vr], 0, %%pred19}\n" \
		"{movts,0 %%g" #greg_no ", %%b[0] ? %%pred19\n" \
		" movtd,1 %%db[1], %%dg" #greg_no "}\n" \
		"{movtd,0 %%db[0], %[tmp]\n" \
		" addd,2 %[greg], 0, %%db[0]\n" \
		" call %%ctpr1, wbs=%#}\n" \
		"{addd 0, 0, %[ret]\n" \
		" movtd,0 %[tmp], %%dg" #greg_no "}\n" \
		: [tmp] "=&r" (tmp), \
		  [ret] "=r" (_ret) \
		: [opc_lo] "r" ((u64) (_opc_lo)), [opc_hi] "r" ((u64) (_opc_hi)), \
		  [addr] "r" (_addr), [vr] "ir" ((u32) (_vr)), \
		  [greg] "i" ((u64) (greg_no)) \
		: "call", "memory", "pred19", "g" #greg_no); \
} while (false)

#define RECOVERY_LOAD_TO_THE_GREG_VR_ATOMIC_QP(_addr, _opc_lo, _opc_hi, \
		greg_no, _vr, _try, _ret) \
({ \
	if (_try) { \
		TRY_RECOVERY_LOAD_TO_THE_GREG_VR_ATOMIC_QP(_addr, \
				_opc_lo, _opc_hi, greg_no, _vr, _ret); \
	} else { \
		NATIVE_RECOVERY_LOAD_TO_THE_GREG_VR_ATOMIC_QP(_addr, \
				_opc_lo, _opc_hi, greg_no, _vr); \
	} \
})

#define NATIVE_RECOVERY_LOAD_TO_THE_GREG_VR_ATOMIC_QP_OR_Q(_addr, _opc_lo, _opc_hi, \
		greg_no_lo, greg_no_hi, _vr, _qp_load) \
do { \
	u64 tmp; \
	/* #133760 Use a real quadro register when repeating atomic load */ \
	if (_qp_load) { \
		__no_asm_inline(9) \
		asm (	"{disp %%ctpr1, qpswitchd_sm\n" \
			" nop 4\n" \
			" ldrd,0 [ %[addr] + %[opc_lo] ], %%db[0]\n" \
			" ldrd,2 [ %[addr] + %[opc_hi] ], %%db[1]\n" \
			" cmpesb,1 %[vr], 0, %%pred19}\n" \
			"{movts,0 %%g" #greg_no_lo ", %%b[0] ? %%pred19\n" \
			" movtd,1 %%db[1], %%dg" #greg_no_lo "}\n" \
			"{movtd,0 %%db[0], %[tmp]\n" \
			" addd,2 %[greg], 0, %%db[0]\n" \
			" call %%ctpr1, wbs=%#}\n" \
			"{movtd %[tmp], %%dg" #greg_no_lo "}\n" \
			: [tmp] "=&r" (tmp) \
			: [addr] "r" (_addr), [vr] "ir" ((u32) (_vr)), \
			  [opc_lo] "r" ((u64) (_opc_lo)), [opc_hi] "r" ((u64) (_opc_hi)), \
			  [greg] "i" ((u64) (greg_no_lo)) \
			: "call", "memory", "pred19", "g" #greg_no_lo); \
	} else { \
		__no_asm_inline(6) \
		asm (	"{nop 4\n" \
			" ldrd,0 [ %[addr] + %[opc_lo] ], %%g" #greg_no_lo "\n" \
			" ldrd,2 [ %[addr] + %[opc_hi] ], %%g" #greg_no_hi "\n" \
			" movts,1 %%g" #greg_no_lo ", %[tmp]\n" \
			" cmpesb,4 %[vr], 0, %%pred19}\n" \
			"{movts,0 %[tmp], %%g" #greg_no_lo " ? %%pred19}\n" \
			: [tmp] "=&r" (tmp) \
			: [addr] "r" (_addr), [vr] "ir" ((u32) (_vr)), \
			  [opc_lo] "r" ((u64) (_opc_lo)), [opc_hi] "r" ((u64) (_opc_hi)), \
			  [greg] "i" ((u64) (greg_no_lo)) \
			: "memory", "pred19", "g" #greg_no_lo, "g" #greg_no_hi); \
	} \
} while (false)

/*
 * The same as asm-macros above, but additionally sets return value at '_ret'.
 * If recovery operations complete successfully, then '_ret' sets to 0.
 * If execution is interrupted by page fault, then '_ret' value does not change.
 */
#define TRY_RECOVERY_LOAD_TO_THE_GREG_VR_ATOMIC_QP_OR_Q(_addr, _opc_lo, _opc_hi, \
		greg_no_lo, greg_no_hi, _vr, _qp_load, _ret) \
do { \
	u64 tmp; \
	/* #133760 Use a real quadro register when repeating atomic load */ \
	if (_qp_load) { \
		__no_asm_inline(9) \
		asm (	"{disp %%ctpr1, qpswitchd_sm\n" \
			" nop 4\n" \
			" ldrd,0 [ %[addr] + %[opc_lo] ], %%db[0]\n" \
			" ldrd,2 [ %[addr] + %[opc_hi] ], %%db[1]\n" \
			" cmpesb,1 %[vr], 0, %%pred19}\n" \
			"{movts,0 %%g" #greg_no_lo ", %%b[0] ? %%pred19\n" \
			" movtd,1 %%db[1], %%dg" #greg_no_lo "}\n" \
			"{movtd,0 %%db[0], %[tmp]\n" \
			" addd,2 %[greg], 0, %%db[0]\n" \
			" call %%ctpr1, wbs=%#}\n" \
			"{addd 0, 0, %[ret]\n" \
			" movtd %[tmp], %%dg" #greg_no_lo "}\n" \
			: [tmp] "=&r" (tmp), \
			  [ret] "=r" (_ret) \
			: [addr] "r" (_addr), [vr] "ir" ((u32) (_vr)), \
			  [opc_lo] "r" ((u64) (_opc_lo)), [opc_hi] "r" ((u64) (_opc_hi)), \
			  [greg] "i" ((u64) (greg_no_lo)) \
			: "call", "memory", "pred19", "g" #greg_no_lo); \
	} else { \
		__no_asm_inline(6) \
		asm (	"{nop 4\n" \
			" ldrd,0 [ %[addr] + %[opc_lo] ], %%g" #greg_no_lo "\n" \
			" ldrd,2 [ %[addr] + %[opc_hi] ], %%g" #greg_no_hi "\n" \
			" movts,1 %%g" #greg_no_lo ", %[tmp]\n" \
			" cmpesb,4 %[vr], 0, %%pred19}\n" \
			"{addd 0, 0, %[ret]\n" \
			" movts,0 %[tmp], %%g" #greg_no_lo " ? %%pred19}\n" \
			: [tmp] "=&r" (tmp), \
			  [ret] "=r" (_ret) \
			: [addr] "r" (_addr), [vr] "ir" ((u32) (_vr)), \
			  [opc_lo] "r" ((u64) (_opc_lo)), [opc_hi] "r" ((u64) (_opc_hi)), \
			  [greg] "i" ((u64) (greg_no_lo)) \
			: "memory", "pred19", "g" #greg_no_lo, "g" #greg_no_hi); \
	} \
} while (false)

#define RECOVERY_LOAD_TO_THE_GREG_VR_ATOMIC_QP_OR_Q(_addr, _opc_lo, _opc_hi, \
		greg_no_lo, greg_no_hi, _vr, _qp_load, _try, _ret) \
({ \
	if (_try) { \
		TRY_RECOVERY_LOAD_TO_THE_GREG_VR_ATOMIC_QP_OR_Q(_addr, _opc_lo, _opc_hi, \
				greg_no_lo, greg_no_hi, _vr, _qp_load, _ret); \
	} else { \
		NATIVE_RECOVERY_LOAD_TO_THE_GREG_VR_ATOMIC_QP_OR_Q(_addr, _opc_lo, _opc_hi, \
				greg_no_lo, greg_no_hi, _vr, _qp_load); \
	} \
})

#define RECOVERY_LOAD_TO_A_GREG_CH_VR(addr, _opc_lo, _opc_hi, greg_num, \
		chan_opc, vr, quadro, _try, _ret) \
do { \
	switch (greg_num) { \
	case  0: \
		RECOVERY_LOAD_TO_THE_GREG_CH_VR(addr, _opc_lo, _opc_hi, 0, \
					chan_opc, vr, quadro, _try, _ret); \
		break; \
	case  1: \
		RECOVERY_LOAD_TO_THE_GREG_CH_VR(addr, _opc_lo, _opc_hi, 1, \
					chan_opc, vr, quadro, _try, _ret); \
		break; \
	case  2: \
		RECOVERY_LOAD_TO_THE_GREG_CH_VR(addr, _opc_lo, _opc_hi, 2, \
					chan_opc, vr, quadro, _try, _ret); \
		break; \
	case  3: \
		RECOVERY_LOAD_TO_THE_GREG_CH_VR(addr, _opc_lo, _opc_hi, 3, \
					chan_opc, vr, quadro, _try, _ret); \
		break; \
	case  4: \
		RECOVERY_LOAD_TO_THE_GREG_CH_VR(addr, _opc_lo, _opc_hi, 4, \
					chan_opc, vr, quadro, _try, _ret); \
		break; \
	case  5: \
		RECOVERY_LOAD_TO_THE_GREG_CH_VR(addr, _opc_lo, _opc_hi, 5, \
					chan_opc, vr, quadro, _try, _ret); \
		break; \
	case  6: \
		RECOVERY_LOAD_TO_THE_GREG_CH_VR(addr, _opc_lo, _opc_hi, 6, \
					chan_opc, vr, quadro, _try, _ret); \
		break; \
	case  7: \
		RECOVERY_LOAD_TO_THE_GREG_CH_VR(addr, _opc_lo, _opc_hi, 7, \
					chan_opc, vr, quadro, _try, _ret); \
		break; \
	case  8: \
		RECOVERY_LOAD_TO_THE_GREG_CH_VR(addr, _opc_lo, _opc_hi, 8, \
					chan_opc, vr, quadro, _try, _ret); \
		break; \
	case  9: \
		RECOVERY_LOAD_TO_THE_GREG_CH_VR(addr, _opc_lo, _opc_hi, 9, \
					chan_opc, vr, quadro, _try, _ret); \
		break; \
	case 10: \
		RECOVERY_LOAD_TO_THE_GREG_CH_VR(addr, _opc_lo, _opc_hi, 10, \
					chan_opc, vr, quadro, _try, _ret); \
		break; \
	case 11: \
		RECOVERY_LOAD_TO_THE_GREG_CH_VR(addr, _opc_lo, _opc_hi, 11, \
					chan_opc, vr, quadro, _try, _ret); \
		break; \
	case 12: \
		RECOVERY_LOAD_TO_THE_GREG_CH_VR(addr, _opc_lo, _opc_hi, 12, \
					chan_opc, vr, quadro, _try, _ret); \
		break; \
	case 13: \
		RECOVERY_LOAD_TO_THE_GREG_CH_VR(addr, _opc_lo, _opc_hi, 13, \
					chan_opc, vr, quadro, _try, _ret); \
		break; \
	case 14: \
		RECOVERY_LOAD_TO_THE_GREG_CH_VR(addr, _opc_lo, _opc_hi, 14, \
					chan_opc, vr, quadro, _try, _ret); \
		break; \
	case 15: \
		RECOVERY_LOAD_TO_THE_GREG_CH_VR(addr, _opc_lo, _opc_hi, 15, \
					chan_opc, vr, quadro, _try, _ret); \
		break; \
	/* Do not load to g16-g31 directly as they are used by kernel */ \
	case 16 ... 31: \
	default: \
		BUG(); \
	} \
} while (0)

#define NATIVE_RECOVERY_LOAD_TO_A_GREG_CH_VR(addr, _opc_lo, _opc_hi, greg_num, \
		chan_opc, vr, quadro) \
({ \
	long unused; \
	RECOVERY_LOAD_TO_A_GREG_CH_VR(addr, _opc_lo, _opc_hi, greg_num, \
			chan_opc, vr, quadro, 0, unused); \
})

/*
 * The same as asm-macros above, but additionally sets return value at '_ret'.
 * If recovery operations complete successfully, then '_ret' sets to 0.
 * If execution is interrupted by page fault, then '_ret' value does not change.
 */
#define TRY_RECOVERY_LOAD_TO_A_GREG_CH_VR(addr, _opc_lo, _opc_hi, greg_num, \
		chan_opc, vr, quadro, _ret) \
		RECOVERY_LOAD_TO_A_GREG_CH_VR(addr, _opc_lo, _opc_hi, greg_num, \
			chan_opc, vr, quadro, 1, _ret)

#define RECOVERY_LOAD_TO_A_GREG_VR_ATOMIC(addr, opc_lo, opc_hi, greg_num, \
		vr, qp_load, _try, _ret) \
do { \
	switch (greg_num) { \
	case  0: \
		RECOVERY_LOAD_TO_THE_GREG_VR_ATOMIC_QP_OR_Q(addr, opc_lo, opc_hi, \
				0, 1, vr, qp_load, _try, _ret); \
		break; \
	case  1: \
		RECOVERY_LOAD_TO_THE_GREG_VR_ATOMIC_QP(addr, opc_lo, opc_hi, 1, \
				vr, _try, _ret); \
		break; \
	case  2: \
		RECOVERY_LOAD_TO_THE_GREG_VR_ATOMIC_QP_OR_Q(addr, opc_lo, opc_hi, \
				2, 3, vr, qp_load, _try, _ret); \
		break; \
	case  3: \
		RECOVERY_LOAD_TO_THE_GREG_VR_ATOMIC_QP(addr, opc_lo, opc_hi, 3, \
				vr, _try, _ret); \
		break; \
	case  4: \
		RECOVERY_LOAD_TO_THE_GREG_VR_ATOMIC_QP_OR_Q(addr, opc_lo, opc_hi, \
				4, 5, vr, qp_load, _try, _ret); \
		break; \
	case  5: \
		RECOVERY_LOAD_TO_THE_GREG_VR_ATOMIC_QP(addr, opc_lo, opc_hi, 5, \
				vr, _try, _ret); \
		break; \
	case  6: \
		RECOVERY_LOAD_TO_THE_GREG_VR_ATOMIC_QP_OR_Q(addr, opc_lo, opc_hi, \
				6, 7, vr, qp_load, _try, _ret); \
		break; \
	case  7: \
		RECOVERY_LOAD_TO_THE_GREG_VR_ATOMIC_QP(addr, opc_lo, opc_hi, 7, \
				vr, _try, _ret); \
		break; \
	case  8: \
		RECOVERY_LOAD_TO_THE_GREG_VR_ATOMIC_QP_OR_Q(addr, opc_lo, opc_hi, \
				8, 9, vr, qp_load, _try, _ret); \
		break; \
	case  9: \
		RECOVERY_LOAD_TO_THE_GREG_VR_ATOMIC_QP(addr, opc_lo, opc_hi, 9, \
				vr, _try, _ret); \
		break; \
	case 10: \
		RECOVERY_LOAD_TO_THE_GREG_VR_ATOMIC_QP_OR_Q(addr, opc_lo, opc_hi, \
				10, 11, vr, qp_load, _try, _ret); \
		break; \
	case 11: \
		RECOVERY_LOAD_TO_THE_GREG_VR_ATOMIC_QP(addr, opc_lo, opc_hi, 11, \
				vr, _try, _ret); \
		break; \
	case 12: \
		RECOVERY_LOAD_TO_THE_GREG_VR_ATOMIC_QP_OR_Q(addr, opc_lo, opc_hi, \
				12, 13, vr, qp_load, _try, _ret); \
		break; \
	case 13: \
		RECOVERY_LOAD_TO_THE_GREG_VR_ATOMIC_QP(addr, opc_lo, opc_hi, 13, \
				vr, _try, _ret); \
		break; \
	case 14: \
		RECOVERY_LOAD_TO_THE_GREG_VR_ATOMIC_QP_OR_Q(addr, opc_lo, opc_hi, \
				14, 15, vr, qp_load, _try, _ret); \
		break; \
	case 15: \
		RECOVERY_LOAD_TO_THE_GREG_VR_ATOMIC_QP(addr, opc_lo, opc_hi, 15, \
				vr, _try, _ret); \
		break; \
	/* Do not load g16-g31 as they are used by kernel */ \
	case 16 ... 31: \
	default: \
		BUG(); \
	} \
} while (0)

#define NATIVE_RECOVERY_LOAD_TO_A_GREG_VR_ATOMIC(addr, opc_lo, opc_hi, greg_num, vr, qp_load) \
({ \
	long unused; \
	RECOVERY_LOAD_TO_A_GREG_VR_ATOMIC(addr, opc_lo, opc_hi, greg_num, vr, qp_load, 0, unused); \
})

/*
 * The same as asm-macros above, but additionally sets return value at '_ret'.
 * If recovery operations complete successfully, then '_ret' sets to 0.
 * If execution is interrupted by page fault, then '_ret' value does not change.
 */
#define TRY_RECOVERY_LOAD_TO_A_GREG_VR_ATOMIC(addr, opc_lo, opc_hi, greg_num, vr, qp_load, _ret) \
	RECOVERY_LOAD_TO_A_GREG_VR_ATOMIC(addr, opc_lo, opc_hi, greg_num, vr, qp_load, 1, _ret)

#define NATIVE_RECOVERY_STORE(_addr, _val, _opc, _chan) \
do { \
	asm volatile ("strd," #_chan " [ %[addr] + %[opc] ], %[val]" \
		      : \
		      : [addr] "r" ((u64) (_addr)), \
			[opc] "ir" ((u64) (_opc)), \
			[val] "r" ((u64) (_val)) \
		      : "memory"); \
} while (0)

#define NATIVE_RECOVERY_TAGGED_STORE_ATOMIC(_addr, _val, _tag, _opc, \
		_val_ext, _tag_ext, _opc_ext) \
({ \
	u64 tmp, tmp_ext; \
	__no_asm_inline(2) \
	asm (	"{puttagd,2 %[val], %[tag], %[tmp]\n" \
		" puttagd,5 %[val_ext], %[tag_ext], %[tmp_ext]}\n" \
		"{strd,2 [ %[addr] + %[opc] ], %[tmp]\n" \
		" strd,5 [ %[addr] + %[opc_ext] ], %[tmp_ext]}\n" \
		ALTERNATIVE( \
			"", \
			"{nop}\n" \
			"{nop}\n" \
			"{nop}\n" \
			"{nop}\n", \
		%[cpu_hwbug_store_mas]) \
		: [tmp] "=&r" (tmp), [tmp_ext] "=&r" (tmp_ext) \
		: [addr] "r" (_addr), \
		  [val] "r" ((u64) (_val)), [val_ext] "r" ((u64) (_val_ext)), \
		  [tag] "r" ((u32) (_tag)), [tag_ext] "r" ((u32) (_tag_ext)), \
		  [opc] "ir" (_opc), [opc_ext] "ir" (_opc_ext), \
		  [cpu_hwbug_store_mas] "i" (CPU_HWBUG_STORE_MAS) \
		: "memory"); \
})

#define NATIVE_RECOVERY_TAGGED_STORE(_addr, _val, _tag, _opc, \
		_val_ext, _tag_ext, _opc_ext, _chan, _quadro) \
({ \
	u64 tmp, tmp_ext; \
	u32 __chan = (u32) (_chan); \
	u32 __chan_q = (_quadro) ? __chan : 4; /* Not existent channel - skip */ \
	__no_asm_inline(4) \
	asm (	"{nop 1\n" \
		" puttagd,2 %[val], %[tag], %[tmp]\n" \
		" puttagd,5,sm %[val_ext], %[tag_ext], %[tmp_ext]\n" \
		" cmpesb,0 %[chan], 1, %%pred20\n" \
		" cmpesb,3 %[chan], 3, %%pred21\n" \
		" cmpesb,1 %[chan_q], 1, %%pred22\n" \
		" cmpesb,4 %[chan_q], 3, %%pred23}\n" \
		"{strd,2 [ %[addr] + %[opc] ], %[tmp] ? %%pred20\n" \
		" strd,5 [ %[addr] + %[opc] ], %[tmp] ? %%pred21}\n" \
		"{strd,2 [ %[addr] + %[opc_ext] ], %[tmp_ext] ? %%pred22\n" \
		" strd,5 [ %[addr] + %[opc_ext] ], %[tmp_ext] ? %%pred23}\n" \
		ALTERNATIVE( \
			"", \
			"{nop}\n" \
			"{nop}\n" \
			"{nop}\n" \
			"{nop}\n", \
		%[cpu_hwbug_store_mas]) \
		: [tmp] "=&r" (tmp), [tmp_ext] "=&r" (tmp_ext) \
		: [addr] "r" (_addr), \
		  [val] "r" ((u64) (_val)), [val_ext] "r" ((u64) (_val_ext)), \
		  [tag] "r" ((u32) (_tag)), [tag_ext] "r" ((u32) (_tag_ext)), \
		  [opc] "ir" (_opc), [opc_ext] "ir" (_opc_ext), \
		  [chan] "ir" ((u32) (__chan)), [chan_q] "ir" ((u32) (__chan_q)), \
		  [cpu_hwbug_store_mas] "i" (CPU_HWBUG_STORE_MAS) \
		: "memory", "pred20", "pred21", "pred22", "pred23"); \
})

/*
 * The same as asm-macros above, but additionally sets return value at '_ret'.
 * If recovery operations complete successfully, then '_ret' sets to 0.
 * If execution is interrupted by page fault, then '_ret' value does not change.
 */
#define TRY_RECOVERY_TAGGED_STORE_ATOMIC(_addr, _val, _tag, _opc, \
		_val_ext, _tag_ext, _opc_ext, _ret) \
({ \
	u64 tmp, tmp_ext; \
	__no_asm_inline(3) \
	asm (	"{puttagd,2 %[val], %[tag], %[tmp]\n" \
		" puttagd,5 %[val_ext], %[tag_ext], %[tmp_ext]}\n" \
		"{strd,2 [ %[addr] + %[opc] ], %[tmp]\n" \
		" strd,5 [ %[addr] + %[opc_ext] ], %[tmp_ext]}\n" \
		ALTERNATIVE( \
			"", \
			"{nop}\n" \
			"{nop}\n" \
			"{nop}\n", \
		%[cpu_hwbug_store_mas]) \
		"{addd,0 0, 0, %[ret]}\n" \
		: [tmp] "=&r" (tmp), [tmp_ext] "=&r" (tmp_ext), \
		  [ret] "=r" (_ret) \
		: [addr] "r" (_addr), \
		  [val] "r" ((u64) (_val)), [val_ext] "r" ((u64) (_val_ext)), \
		  [tag] "r" ((u32) (_tag)), [tag_ext] "r" ((u32) (_tag_ext)), \
		  [opc] "ir" (_opc), [opc_ext] "ir" (_opc_ext), \
		  [cpu_hwbug_store_mas] "i" (CPU_HWBUG_STORE_MAS) \
		: "memory"); \
})

/*
 * The same as asm-macros above, but additionally sets return value at '_ret'.
 * If recovery operations complete successfully, then '_ret' sets to 0.
 * If execution is interrupted by page fault, then '_ret' value does not change.
 */
#define TRY_RECOVERY_TAGGED_STORE(_addr, _val, _tag, _opc, \
		_val_ext, _tag_ext, _opc_ext, _chan, _quadro, _ret) \
({ \
	u64 tmp, tmp_ext; \
	u32 __chan = (u32) (_chan); \
	u32 __chan_q = (_quadro) ? __chan : 4; /* Not existent channel - skip */ \
	__no_asm_inline(5) \
	asm (	"{nop 1\n" \
		" puttagd,2 %[val], %[tag], %[tmp]\n" \
		" puttagd,5,sm %[val_ext], %[tag_ext], %[tmp_ext]\n" \
		" cmpesb,0 %[chan], 1, %%pred20\n" \
		" cmpesb,3 %[chan], 3, %%pred21\n" \
		" cmpesb,1 %[chan_q], 1, %%pred22\n" \
		" cmpesb,4 %[chan_q], 3, %%pred23}\n" \
		"{strd,2 [ %[addr] + %[opc] ], %[tmp] ? %%pred20\n" \
		" strd,5 [ %[addr] + %[opc] ], %[tmp] ? %%pred21}\n" \
		"{strd,2 [ %[addr] + %[opc_ext] ], %[tmp_ext] ? %%pred22\n" \
		" strd,5 [ %[addr] + %[opc_ext] ], %[tmp_ext] ? %%pred23}\n" \
		ALTERNATIVE( \
			"", \
			"{nop}\n" \
			"{nop}\n" \
			"{nop}\n", \
		%[cpu_hwbug_store_mas]) \
		"{addd,0 0, 0, %[ret]}\n" \
		: [tmp] "=&r" (tmp), [tmp_ext] "=&r" (tmp_ext), \
		  [ret] "=r" (_ret) \
		: [addr] "r" (_addr), \
		  [val] "r" ((u64) (_val)), [val_ext] "r" ((u64) (_val_ext)), \
		  [tag] "r" ((u32) (_tag)), [tag_ext] "r" ((u32) (_tag_ext)), \
		  [opc] "ir" (_opc), [opc_ext] "ir" (_opc_ext), \
		  [chan] "ir" ((u32) (__chan)), [chan_q] "ir" ((u32) (__chan_q)), \
		  [cpu_hwbug_store_mas] "i" (CPU_HWBUG_STORE_MAS) \
		: "memory", "pred20", "pred21", "pred22", "pred23"); \
})

/*
 * #58441  - work with taged value (compiler problem)
 * store tag and store taged word must be in common asm code
 *  (cloused asm code)
 */
#define	NATIVE_STORE_VALUE_WITH_TAG(addr, val, tag) \
		NATIVE_STORE_TAGGED_WORD(addr, val, tag, \
						TAGGED_MEM_STORE_REC_OPC, 2)

#define	NATIVE_STORE_TAGGED_WORD(addr, val, tag, opc, chan_letter) \
do { \
	u64 __tmp_reg = val; \
	E2K_BUILD_BUG_ON(sizeof(val) != 8); \
	__no_asm_inline(2) \
	asm volatile ("{puttagd %0, %2, %0\n}" \
		      "{strd," #chan_letter " [%1 + %3], %0}\n" \
		      : "+r" (__tmp_reg) \
		      : "r" ((u64) (addr)), \
			"ri" ((u32) (tag)), \
			"ri" ((opc)) \
		      : "memory"); \
} while (0)

#define	NATIVE_STORE_TAGGED_WORD_CH(addr, val, tag, opc, trap_cellar_chan) \
do { \
	switch (trap_cellar_chan) { \
	case 1: \
		NATIVE_STORE_TAGGED_WORD(addr, val, tag, opc, 2); \
		break; \
	case 3: \
		NATIVE_STORE_TAGGED_WORD(addr, val, tag, opc, 5); \
		break; \
	} \
} while (0)


#define	NATIVE_STORE_TAGGED_QWORD(_addr, _val_lo, _val_hi, _tag_lo, _tag_hi, _offset) \
do { \
	u64 __reg1_stq, __reg2_stq; \
	E2K_BUILD_BUG_ON(sizeof(_val_hi) != 8); \
	E2K_BUILD_BUG_ON(sizeof(_val_lo) != 8); \
	__no_asm_inline(2) \
	asm volatile (	"{puttagd,2 %[val_lo], %[tag_lo], %[reg1]\n" \
			" puttagd,5 %[val_hi], %[tag_hi], %[reg2]}\n" \
			"{strd,2 [ %[addr] + %[opc_lo] ], %[reg1]\n" \
			" strd,5 [ %[addr] + %[opc_hi] ], %[reg2]}\n" \
			: [reg1] "=&r" (__reg1_stq), \
			  [reg2] "=&r" (__reg2_stq) \
			: [addr] "r" ((u64) (unsigned long) (_addr)), \
			  [val_lo] "r" ((u64) (_val_lo)), \
			  [val_hi] "r" ((u64) (_val_hi)), \
			  [tag_lo] "ri" ((u32) (_tag_lo)), \
			  [tag_hi] "ri" ((u32) (_tag_hi)), \
			  [opc_lo] "i" (TAGGED_MEM_STORE_REC_OPC), \
			  [opc_hi] "ri" (TAGGED_MEM_STORE_REC_OPC | (_offset)) \
			: "memory"); \
} while (0)

#define NATIVE_MOVE_TAGGED_QWORD(_from_lo, _from_hi, _to_lo, _to_hi)	\
({									\
	u64 __val_lo, __val_hi;						\
	__no_asm_inline(6)					\
	asm ("{nop 4\n"							\
	     " ldrd,2 [ %[from_lo] + %[opc_ld] ], %[val_lo]\n"		\
	     " ldrd,5 [ %[from_hi] + %[opc_ld] ], %[val_hi]}\n"		\
	     "{strd,2 [ %[to_lo] + %[opc_st] ], %[val_lo]\n"		\
	     " strd,5 [ %[to_hi] + %[opc_st] ], %[val_hi]}\n"		\
	     : [val_lo] "=&r" (__val_lo), [val_hi] "=&r" (__val_hi)	\
	     : [from_lo] "r" (_from_lo), [from_hi] "r" (_from_hi),	\
	       [to_lo] "r" (_to_lo), [to_hi] "r" (_to_hi),		\
	       [opc_ld] "i" (TAGGED_MEM_LOAD_REC_OPC),			\
	       [opc_st] "i" (TAGGED_MEM_STORE_REC_OPC)			\
	     : "memory");						\
})

#define NATIVE_MOVE_TAGGED_DWORD(_from, _to) \
do { \
	long _tmp; \
	asm (	"ldrd [ %[from] + %[opc] ], %[tmp]\n" \
		"strd [ %[to] + %[opc_st] ], %[tmp]\n" \
		: [tmp] "=&r" (_tmp) \
		: [from] "r" (_from), [to] "r" (_to), \
		  [opc] "i" (TAGGED_MEM_LOAD_REC_OPC), \
		  [opc_st] "i" (TAGGED_MEM_STORE_REC_OPC) \
		: "memory"); \
} while (false)

#define NATIVE_MOVE_TAGGED_WORD(_from, _to) \
do { \
	long _tmp; \
	asm (	"ldrd [ %[from] + %[opc] ], %[tmp]\n" \
		"strd [ %[to] + %[opc_st] ], %[tmp]\n" \
		: [tmp] "=&r" (_tmp) \
		: [from] "r" (_from), [to] "r" (_to), \
		  [opc] "i" (TAGGED_MEM_LOAD_REC_OPC_W), \
		  [opc_st] "i" (TAGGED_MEM_STORE_REC_OPC_W) \
		: "memory"); \
} while (false)

/*
 * Repeat memory load from cellar.
 * chan: 0, 1, 2 or 3 - channel for operation
 * quadro: set if this is a non-atomic quadro operation to move 16 bytes
 * vr: set to 0 if we want to preserve the lower 4-byte word
 *     (same as vr in cellar)
 * not_single_byte: set to "false" if we want to write only 1 byte at target
 *                  address (i.e. do not clear the whole register we are
 *                  writing into).  This makes sense when we manually split
 *                  the faulting load into a series of 1-byte loads - only
 *                  the first one should clear the register then.
 */
#define NATIVE_MOVE_TAGGED_DWORD_WITH_OPC_CH_VR(_from, _to, _to_hi, _vr, \
		_opc_lo, _opc_hi, _chan, _quadro, _not_single_byte) \
do { \
	u64 prev, val_lo, val_hi; \
	u32 __chan = (u32) (_chan); \
	u32 __quadro = (u32) (_quadro); \
	u32 __chan_q = (__quadro) ? __chan : 4; /* Not existent channel - skip */ \
	__no_asm_inline(11) \
	asm (	"{cmpesb %[quadro], 0, %%pred18\n" \
		" cmpesb %[vr], 0, %%pred19\n" \
		" cmpesb %[not_single_byte], 0, %%pred28}\n" \
		"{cmpesb,0 %[chan], 0, %%pred20\n" \
		" cmpesb,1 %[chan], 1, %%pred21\n" \
		" cmpesb,3 %[chan], 2, %%pred22\n" \
		" cmpesb,4 %[chan], 3, %%pred23}\n" \
		"{cmpesb,0 %[chan_q], 0, %%pred24\n" \
		" cmpesb,1 %[chan_q], 1, %%pred25\n" \
		" cmpesb,3 %[chan_q], 2, %%pred26\n" \
		" cmpesb,4 %[chan_q], 3, %%pred27\n" \
		" ldrd [ %[to] + %[opc_ld] ], %[prev] ? %%pred19}\n" \
		"{ldrd,0 [ %[from] + %[opc_lo] ], %[val_lo] ? %%pred20\n" \
		" ldrd,2 [ %[from] + %[opc_lo] ], %[val_lo] ? %%pred21\n" \
		" ldrd,3 [ %[from] + %[opc_lo] ], %[val_lo] ? %%pred22\n" \
		" ldrd,5 [ %[from] + %[opc_lo] ], %[val_lo] ? %%pred23}\n" \
		"{nop 3\n" \
		" ldrd,0 [ %[from] + %[opc_hi] ], %[val_hi] ? %%pred24\n" \
		" ldrd,2 [ %[from] + %[opc_hi] ], %[val_hi] ? %%pred25\n" \
		" ldrd,3 [ %[from] + %[opc_hi] ], %[val_hi] ? %%pred26\n" \
		" ldrd,5 [ %[from] + %[opc_hi] ], %[val_hi] ? %%pred27}\n" \
		"{movts,1 %[prev], %[val_lo] ? %%pred19}\n" \
		"{strd,2 [ %[to] + %[opc_st_byte] ], %[val_lo] ? %%pred28}\n" \
		"{strd,2 [ %[to] + %[opc_st] ], %[val_lo] ? ~%%pred28\n" \
		" strd,5 [ %[to_hi] + %[opc_st] ], %[val_hi] ? ~ %%pred18}\n" \
		ALTERNATIVE( \
			"", \
			"{nop}\n" \
			"{nop}\n" \
			"{nop}\n" \
			"{nop}\n", \
		%[cpu_hwbug_store_mas]) \
		: [prev] "=&r" (prev), \
		  [val_lo] "=&r" (val_lo), [val_hi] "=&r" (val_hi) \
		: [from] "r" (_from), [to] "r" (_to), [to_hi] "r" (_to_hi), \
		  [vr] "ir" ((u32) (_vr)), [quadro] "r" (__quadro), \
		  [chan] "ir" (__chan), [chan_q] "ir" (__chan_q), \
		  [opc_lo] "r" ((u64) (_opc_lo)), [opc_hi] "r" ((u64) (_opc_hi)),  \
		  [not_single_byte] "ir" (_not_single_byte), \
		  [opc_ld] "i" (TAGGED_MEM_LOAD_REC_OPC), \
		  [opc_st_byte] "i" (MEM_STORE_REC_OPC_B), \
		  [opc_st] "i" (TAGGED_MEM_STORE_REC_OPC), \
		  [cpu_hwbug_store_mas] "i" (CPU_HWBUG_STORE_MAS) \
		: "memory", "pred18", "pred19", "pred20", "pred21", \
		  "pred22", "pred23", "pred24", "pred25", "pred26", \
		  "pred27", "pred28"); \
} while (false)

/*
 * The same as asm-macros above, but additionally sets return value at '_ret'.
 * If recovery operations complete successfully, then '_ret' sets to 0.
 * If execution is interrupted by page fault, then '_ret' value does not change.
 */
#define TRY_MOVE_TAGGED_DWORD_WITH_OPC_CH_VR(_from, _to, _to_hi, _vr, _opc, \
		_chan, _quadro, _not_single_byte, _ret) \
do { \
	u64 prev, val, val_8; \
	u32 __chan = (u32) (_chan); \
	u32 __quadro = (u32) (_quadro); \
	u32 __chan_q = (__quadro) ? __chan : 4; /* Not existent channel - skip */ \
	u64 __opc = (_opc); \
	__no_asm_inline(12) \
	asm (	"{cmpesb %[quadro], 0, %%pred18\n" \
		" cmpesb %[vr], 0, %%pred19\n" \
		" cmpesb %[not_single_byte], 0, %%pred28}\n" \
		"{cmpesb,0 %[chan], 0, %%pred20\n" \
		" cmpesb,1 %[chan], 1, %%pred21\n" \
		" cmpesb,3 %[chan], 2, %%pred22\n" \
		" cmpesb,4 %[chan], 3, %%pred23}\n" \
		"{cmpesb,0 %[chan_q], 0, %%pred24\n" \
		" cmpesb,1 %[chan_q], 1, %%pred25\n" \
		" cmpesb,3 %[chan_q], 2, %%pred26\n" \
		" cmpesb,4 %[chan_q], 3, %%pred27\n" \
		" ldrd [ %[to] + %[opc_ld] ], %[prev] ? %%pred19}\n" \
		"{ldrd,0 [ %[from] + %[opc] ], %[val] ? %%pred20\n" \
		" ldrd,2 [ %[from] + %[opc] ], %[val] ? %%pred21\n" \
		" ldrd,3 [ %[from] + %[opc] ], %[val] ? %%pred22\n" \
		" ldrd,5 [ %[from] + %[opc] ], %[val] ? %%pred23}\n" \
		"{nop 3\n" \
		" ldrd,0 [ %[from] + %[opc_8] ], %[val_8] ? %%pred24\n" \
		" ldrd,2 [ %[from] + %[opc_8] ], %[val_8] ? %%pred25\n" \
		" ldrd,3 [ %[from] + %[opc_8] ], %[val_8] ? %%pred26\n" \
		" ldrd,5 [ %[from] + %[opc_8] ], %[val_8] ? %%pred27}\n" \
		"{movts,1 %[prev], %[val] ? %%pred19}\n" \
		"{strd,2 [ %[to] + %[opc_st_byte] ], %[val] ? %%pred28}\n" \
		"{strd,2 [ %[to] + %[opc_st] ], %[val] ? ~%%pred28\n" \
		" strd,5 [ %[to_hi] + %[opc_st] ], %[val_8] ? ~ %%pred18}\n" \
		ALTERNATIVE( \
			"", \
			"{nop}\n" \
			"{nop}\n" \
			"{nop}\n", \
		%[cpu_hwbug_store_mas]) \
		"{addd,0 0, 0, %[ret]}\n" \
		: [prev] "=&r" (prev), [val] "=&r" (val), \
		  [val_8] "=&r" (val_8), \
		  [ret] "=r" (_ret) \
		: [from] "r" (_from), [to] "r" (_to), [to_hi] "r" (_to_hi), \
		  [vr] "ir" ((u32) (_vr)), [quadro] "r" (__quadro), \
		  [chan] "ir" (__chan), [chan_q] "ir" (__chan_q), \
		  [opc] "r" (__opc), [opc_8] "r" (__opc | 8ull),  \
		  [not_single_byte] "ir" (_not_single_byte), \
		  [opc_ld] "i" (TAGGED_MEM_LOAD_REC_OPC), \
		  [opc_st_byte] "i" (MEM_STORE_REC_OPC_B), \
		  [opc_st] "i" (TAGGED_MEM_STORE_REC_OPC), \
		  [cpu_hwbug_store_mas] "i" (CPU_HWBUG_STORE_MAS) \
		: "memory", "pred18", "pred19", "pred20", "pred21", \
		  "pred22", "pred23", "pred24", "pred25", "pred26", \
		  "pred27", "pred28"); \
} while (false)

/*
 * As NATIVE_MOVE_TAGGED_DWORD_WITH_OPC_CH_VR but repeats from cellar
 * an aligned atomic 16-bytes load.
 */
#define NATIVE_MOVE_TAGGED_DWORD_WITH_OPC_VR_ATOMIC(_from, _to, _to_hi, _vr, _opc_lo, _opc_hi) \
do { \
	u64 prev; \
	/* #133760 Use a real quadro register when repeating atomic load */ \
	e2k_qreg_t __qvalue; \
	__no_asm_inline(9) \
	asm (	"{cmpesb %[vr], 0, %%pred19}\n" \
		"{ldrd,0 [ %[from] + %[opc_lo] ], %L[qvalue]\n" \
		" ldrd,2 [ %[from] + %[opc_hi] ], %H[qvalue]}\n" \
		"{nop 4\n" \
		" ldrd [ %[to] + %[opc_ld] ], %[prev] ? %%pred19}\n" \
		"{movts,1 %[prev], %L[qvalue] ? %%pred19}\n" \
		"{strd,2 [ %[to] + %[opc_st] ], %L[qvalue]\n" \
		" strd,5 [ %[to_hi] + %[opc_st] ], %H[qvalue]}\n" \
		ALTERNATIVE( \
			"", \
			"{nop}\n" \
			"{nop}\n" \
			"{nop}\n" \
			"{nop}\n", \
		%[cpu_hwbug_store_mas]) \
		: [prev] "=&r" (prev), [qvalue] "=&r" (__qvalue) \
		: [from] "r" (_from), [to] "r" (_to), [to_hi] "r" (_to_hi), \
		  [vr] "ir" ((u32) (_vr)), \
		  [opc_lo] "r" ((u64) (_opc_lo)), [opc_hi] "r" ((u64) (_opc_hi)), \
		  [opc_ld] "i" (TAGGED_MEM_LOAD_REC_OPC), \
		  [opc_st] "i" (TAGGED_MEM_STORE_REC_OPC), \
		  [cpu_hwbug_store_mas] "i" (CPU_HWBUG_STORE_MAS) \
		: "memory", "pred19"); \
} while (false)

/*
 * The same as asm-macros above, but additionally sets return value at '_ret'.
 * If recovery operations complete successfully, then '_ret' sets to 0.
 * If execution is interrupted by page fault, then '_ret' value does not change.
 */
#define TRY_MOVE_TAGGED_DWORD_WITH_OPC_VR_ATOMIC(_from, _to, _to_hi, \
		_vr, _opc, _ret) \
do { \
	u64 prev; \
	/* #133760 Use a real quadro register when repeating atomic load */ \
	e2k_qreg_t __qvalue; \
	u64 __opc = (_opc); \
	__no_asm_inline(10) \
	asm (	"{cmpesb %[vr], 0, %%pred19}\n" \
		"{ldrd,0 [ %[from] + %[opc] ], %L[qvalue]\n" \
		" ldrd,2 [ %[from] + %[opc_8] ], %H[qvalue]}\n" \
		"{nop 4\n" \
		" ldrd [ %[to] + %[opc_ld] ], %[prev] ? %%pred19}\n" \
		"{movts,1 %[prev], %L[qvalue] ? %%pred19}\n" \
		"{strd,2 [ %[to] + %[opc_st] ], %L[qvalue]\n" \
		" strd,5 [ %[to_hi] + %[opc_st] ], %H[qvalue]}\n" \
		ALTERNATIVE( \
			"", \
			"{nop}\n" \
			"{nop}\n" \
			"{nop}\n", \
		%[cpu_hwbug_store_mas]) \
		"{addd,0 0, 0, %[ret]}\n" \
		: [prev] "=&r" (prev), [qvalue] "=&r" (__qvalue), \
		  [ret] "=r" (_ret) \
		: [from] "r" (_from), [to] "r" (_to), [to_hi] "r" (_to_hi), \
		  [vr] "ir" ((u32) (_vr)), \
		  [opc] "r" (__opc), [opc_8] "r" (__opc | 8ull), \
		  [opc_ld] "i" (TAGGED_MEM_LOAD_REC_OPC), \
		  [opc_st] "i" (TAGGED_MEM_STORE_REC_OPC), \
		  [cpu_hwbug_store_mas] "i" (CPU_HWBUG_STORE_MAS) \
		: "memory", "pred19"); \
} while (false)

#define E2K_TAGGED_MEMMOVE_8(___dst, ___src)				\
({									\
	volatile void * __dst = (___dst);				\
	const volatile void * __src = (___src);				\
	u64 __tmp1;							\
	__no_asm_inline(6)					\
	asm (								\
		"{\n"							\
		"nop 4\n"						\
		"ldrd,2 [ %[src] + %[ld_opc_0] ], %[tmp1]\n"		\
		"}\n"							\
		"{\n"							\
		"strd,2 [ %[dst] + %[st_opc_0] ], %[tmp1]\n"		\
		"}\n"							\
		: [tmp1] "=&r" (__tmp1)					\
		: [src] "r" (__src), [dst] "r" (__dst),			\
		  [ld_opc_0] "i" (TAGGED_MEM_LOAD_REC_OPC),		\
		  [st_opc_0] "i" (TAGGED_MEM_STORE_REC_OPC)		\
		: "memory");						\
})

#define E2K_TAGGED_MEMMOVE_16(___dst, ___src)				\
({									\
	volatile void * __dst = (___dst);				\
	const volatile void * __src = (___src);				\
	u64 __tmp1, __tmp2;						\
	__no_asm_inline(6)					\
	asm (								\
		"{\n"							\
		"nop 4\n"						\
		"ldrd,2 [ %[src] + %[ld_opc_0] ], %[tmp1]\n"		\
		"ldrd,5 [ %[src] + %[ld_opc_8] ], %[tmp2]\n"		\
		"}\n"							\
		"{\n"							\
		"strd,2 [ %[dst] + %[st_opc_0] ], %[tmp1]\n"		\
		"strd,5 [ %[dst] + %[st_opc_8] ], %[tmp2]\n"		\
		"}\n"							\
		: [tmp1] "=&r" (__tmp1), [tmp2] "=&r" (__tmp2)		\
		: [src] "r" (__src), [dst] "r" (__dst),			\
		  [ld_opc_0] "i" (TAGGED_MEM_LOAD_REC_OPC),		\
		  [ld_opc_8] "i" (TAGGED_MEM_LOAD_REC_OPC | 8),		\
		  [st_opc_0] "i" (TAGGED_MEM_STORE_REC_OPC),		\
		  [st_opc_8] "i" (TAGGED_MEM_STORE_REC_OPC | 8)		\
		: "memory");						\
})

#define E2K_TAGGED_MEMMOVE_24(___dst, ___src)				\
({									\
	volatile void * __dst = (___dst);				\
	const volatile void * __src = (___src);				\
	u64 __tmp1, __tmp2, __tmp3;					\
	__no_asm_inline(7)					\
	asm (								\
		"{\n"							\
		"ldrd,2 [ %[src] + %[ld_opc_0] ], %[tmp1]\n"		\
		"ldrd,5 [ %[src] + %[ld_opc_8] ], %[tmp2]\n"		\
		"}\n"							\
		"{\n"							\
		"nop 3\n"						\
		"ldrd,2 [ %[src] + %[ld_opc_16] ], %[tmp3]\n"		\
		"}\n"							\
		"{\n"							\
		"strd,2 [ %[dst] + %[st_opc_0] ], %[tmp1]\n"		\
		"strd,5 [ %[dst] + %[st_opc_8] ], %[tmp2]\n"		\
		"}\n"							\
		"{\n"							\
		"strd,2 [ %[dst] + %[st_opc_16] ], %[tmp3]\n"		\
		"}\n"							\
		: [tmp1] "=&r" (__tmp1), [tmp2] "=&r" (__tmp2),		\
		  [tmp3] "=&r" (__tmp3)					\
		: [src] "r" (__src), [dst] "r" (__dst),			\
		  [ld_opc_0] "i" (TAGGED_MEM_LOAD_REC_OPC),		\
		  [ld_opc_8] "i" (TAGGED_MEM_LOAD_REC_OPC | 8),		\
		  [ld_opc_16] "i" (TAGGED_MEM_LOAD_REC_OPC | 16),	\
		  [st_opc_0] "i" (TAGGED_MEM_STORE_REC_OPC),		\
		  [st_opc_8] "i" (TAGGED_MEM_STORE_REC_OPC | 8),	\
		  [st_opc_16] "i" (TAGGED_MEM_STORE_REC_OPC | 16)	\
		: "memory");						\
})

#define E2K_TAGGED_MEMMOVE_32(___dst, ___src)				\
({									\
	volatile void * __dst = (___dst);				\
	const volatile void * __src = (___src);				\
	u64 __tmp1, __tmp2, __tmp3, __tmp4;				\
	__no_asm_inline(7)					\
	asm (								\
		"{\n"							\
		"ldrd,2 [ %[src] + %[ld_opc_0] ], %[tmp1]\n"		\
		"ldrd,5 [ %[src] + %[ld_opc_8] ], %[tmp2]\n"		\
		"}\n"							\
		"{\n"							\
		"nop 3\n"						\
		"ldrd,2 [ %[src] + %[ld_opc_16] ], %[tmp3]\n"		\
		"ldrd,5 [ %[src] + %[ld_opc_24] ], %[tmp4]\n"		\
		"}\n"							\
		"{\n"							\
		"strd,2 [ %[dst] + %[st_opc_0] ], %[tmp1]\n"		\
		"strd,5 [ %[dst] + %[st_opc_8] ], %[tmp2]\n"		\
		"}\n"							\
		"{\n"							\
		"strd,2 [ %[dst] + %[st_opc_16] ], %[tmp3]\n"		\
		"strd,5 [ %[dst] + %[st_opc_24] ], %[tmp4]\n"		\
		"}\n"							\
		: [tmp1] "=&r" (__tmp1), [tmp2] "=&r" (__tmp2),		\
		  [tmp3] "=&r" (__tmp3), [tmp4] "=&r" (__tmp4)		\
		: [src] "r" (__src), [dst] "r" (__dst),			\
		  [ld_opc_0] "i" (TAGGED_MEM_LOAD_REC_OPC),		\
		  [ld_opc_8] "i" (TAGGED_MEM_LOAD_REC_OPC | 8),		\
		  [ld_opc_16] "i" (TAGGED_MEM_LOAD_REC_OPC | 16),	\
		  [ld_opc_24] "i" (TAGGED_MEM_LOAD_REC_OPC | 24),	\
		  [st_opc_0] "i" (TAGGED_MEM_STORE_REC_OPC),		\
		  [st_opc_8] "i" (TAGGED_MEM_STORE_REC_OPC | 8),	\
		  [st_opc_16] "i" (TAGGED_MEM_STORE_REC_OPC | 16),	\
		  [st_opc_24] "i" (TAGGED_MEM_STORE_REC_OPC | 24)	\
		: "memory");						\
})

#define E2K_TAGGED_MEMMOVE_40(___dst, ___src)				\
({									\
	volatile void * __dst = (___dst);				\
	const volatile void * __src = (___src);				\
	u64 __tmp1, __tmp2, __tmp3, __tmp4, __tmp5;			\
	__no_asm_inline(8)					\
	asm (								\
		"{\n"							\
		"ldrd,2 [ %[src] + %[ld_opc_0] ], %[tmp1]\n"		\
		"ldrd,5 [ %[src] + %[ld_opc_8] ], %[tmp2]\n"		\
		"}\n"							\
		"{\n"							\
		"ldrd,2 [ %[src] + %[ld_opc_16] ], %[tmp3]\n"		\
		"ldrd,5 [ %[src] + %[ld_opc_24] ], %[tmp4]\n"		\
		"}\n"							\
		"{\n"							\
		"nop 2\n"						\
		"ldrd,2 [ %[src] + %[ld_opc_32] ], %[tmp5]\n"		\
		"}\n"							\
		"{\n"							\
		"strd,2 [ %[dst] + %[st_opc_0] ], %[tmp1]\n"		\
		"strd,5 [ %[dst] + %[st_opc_8] ], %[tmp2]\n"		\
		"}\n"							\
		"{\n"							\
		"strd,2 [ %[dst] + %[st_opc_16] ], %[tmp3]\n"		\
		"strd,5 [ %[dst] + %[st_opc_24] ], %[tmp4]\n"		\
		"}\n"							\
		"{\n"							\
		"strd,2 [ %[dst] + %[st_opc_32] ], %[tmp5]\n"		\
		"}\n"							\
		: [tmp1] "=&r" (__tmp1), [tmp2] "=&r" (__tmp2),		\
		  [tmp3] "=&r" (__tmp3), [tmp4] "=&r" (__tmp4),		\
		  [tmp5] "=&r" (__tmp5)					\
		: [src] "r" (__src), [dst] "r" (__dst),			\
		  [ld_opc_0] "i" (TAGGED_MEM_LOAD_REC_OPC),		\
		  [ld_opc_8] "i" (TAGGED_MEM_LOAD_REC_OPC | 8),		\
		  [ld_opc_16] "i" (TAGGED_MEM_LOAD_REC_OPC | 16),	\
		  [ld_opc_24] "i" (TAGGED_MEM_LOAD_REC_OPC | 24),	\
		  [ld_opc_32] "i" (TAGGED_MEM_LOAD_REC_OPC | 32),	\
		  [st_opc_0] "i" (TAGGED_MEM_STORE_REC_OPC),		\
		  [st_opc_8] "i" (TAGGED_MEM_STORE_REC_OPC | 8),	\
		  [st_opc_16] "i" (TAGGED_MEM_STORE_REC_OPC | 16),	\
		  [st_opc_24] "i" (TAGGED_MEM_STORE_REC_OPC | 24),	\
		  [st_opc_32] "i" (TAGGED_MEM_STORE_REC_OPC | 32)	\
		: "memory");						\
})

#define E2K_TAGGED_MEMMOVE_48(___dst, ___src)				\
({									\
	volatile void * __dst = (___dst);				\
	const volatile void * __src = (___src);				\
	u64 __tmp1, __tmp2, __tmp3, __tmp4, __tmp5, __tmp6;		\
	__no_asm_inline(8)					\
	asm (								\
		"{\n"							\
		"ldrd,2 [ %[src] + %[ld_opc_0] ], %[tmp1]\n"		\
		"ldrd,5 [ %[src] + %[ld_opc_8] ], %[tmp2]\n"		\
		"}\n"							\
		"{\n"							\
		"ldrd,2 [ %[src] + %[ld_opc_16] ], %[tmp3]\n"		\
		"ldrd,5 [ %[src] + %[ld_opc_24] ], %[tmp4]\n"		\
		"}\n"							\
		"{\n"							\
		"nop 2\n"						\
		"ldrd,2 [ %[src] + %[ld_opc_32] ], %[tmp5]\n"		\
		"ldrd,5 [ %[src] + %[ld_opc_40] ], %[tmp6]\n"		\
		"}\n"							\
		"{\n"							\
		"strd,2 [ %[dst] + %[st_opc_0] ], %[tmp1]\n"		\
		"strd,5 [ %[dst] + %[st_opc_8] ], %[tmp2]\n"		\
		"}\n"							\
		"{\n"							\
		"strd,2 [ %[dst] + %[st_opc_16] ], %[tmp3]\n"		\
		"strd,5 [ %[dst] + %[st_opc_24] ], %[tmp4]\n"		\
		"}\n"							\
		"{\n"							\
		"strd,2 [ %[dst] + %[st_opc_32] ], %[tmp5]\n"		\
		"strd,5 [ %[dst] + %[st_opc_40] ], %[tmp6]\n"		\
		"}\n"							\
		: [tmp1] "=&r" (__tmp1), [tmp2] "=&r" (__tmp2),		\
		  [tmp3] "=&r" (__tmp3), [tmp4] "=&r" (__tmp4),		\
		  [tmp5] "=&r" (__tmp5), [tmp6] "=&r" (__tmp6)		\
		: [src] "r" (__src), [dst] "r" (__dst),			\
		  [ld_opc_0] "i" (TAGGED_MEM_LOAD_REC_OPC),		\
		  [ld_opc_8] "i" (TAGGED_MEM_LOAD_REC_OPC | 8),		\
		  [ld_opc_16] "i" (TAGGED_MEM_LOAD_REC_OPC | 16),	\
		  [ld_opc_24] "i" (TAGGED_MEM_LOAD_REC_OPC | 24),	\
		  [ld_opc_32] "i" (TAGGED_MEM_LOAD_REC_OPC | 32),	\
		  [ld_opc_40] "i" (TAGGED_MEM_LOAD_REC_OPC | 40),	\
		  [st_opc_0] "i" (TAGGED_MEM_STORE_REC_OPC),		\
		  [st_opc_8] "i" (TAGGED_MEM_STORE_REC_OPC | 8),	\
		  [st_opc_16] "i" (TAGGED_MEM_STORE_REC_OPC | 16),	\
		  [st_opc_24] "i" (TAGGED_MEM_STORE_REC_OPC | 24),	\
		  [st_opc_32] "i" (TAGGED_MEM_STORE_REC_OPC | 32),	\
		  [st_opc_40] "i" (TAGGED_MEM_STORE_REC_OPC | 40)	\
		: "memory");						\
})

#define E2K_TAGGED_MEMMOVE_56(___dst, ___src)				\
({									\
	volatile void * __dst = (___dst);				\
	const volatile void * __src = (___src);				\
	u64 __tmp1, __tmp2, __tmp3, __tmp4, __tmp5, __tmp6, __tmp7;	\
	__no_asm_inline(9)					\
	asm (								\
		"{\n"							\
		"ldrd,2 [ %[src] + %[ld_opc_0] ], %[tmp1]\n"		\
		"ldrd,5 [ %[src] + %[ld_opc_8] ], %[tmp2]\n"		\
		"}\n"							\
		"{\n"							\
		"ldrd,2 [ %[src] + %[ld_opc_16] ], %[tmp3]\n"		\
		"ldrd,5 [ %[src] + %[ld_opc_24] ], %[tmp4]\n"		\
		"}\n"							\
		"{\n"							\
		"ldrd,2 [ %[src] + %[ld_opc_32] ], %[tmp5]\n"		\
		"ldrd,5 [ %[src] + %[ld_opc_40] ], %[tmp6]\n"		\
		"}\n"							\
		"{\n"							\
		"nop 1\n"						\
		"ldrd,2 [ %[src] + %[ld_opc_48] ], %[tmp7]\n"		\
		"}\n"							\
		"{\n"							\
		"strd,2 [ %[dst] + %[st_opc_0] ], %[tmp1]\n"		\
		"strd,5 [ %[dst] + %[st_opc_8] ], %[tmp2]\n"		\
		"}\n"							\
		"{\n"							\
		"strd,2 [ %[dst] + %[st_opc_16] ], %[tmp3]\n"		\
		"strd,5 [ %[dst] + %[st_opc_24] ], %[tmp4]\n"		\
		"}\n"							\
		"{\n"							\
		"strd,2 [ %[dst] + %[st_opc_32] ], %[tmp5]\n"		\
		"strd,5 [ %[dst] + %[st_opc_40] ], %[tmp6]\n"		\
		"}\n"							\
		"{\n"							\
		"strd,2 [ %[dst] + %[st_opc_48] ], %[tmp7]\n"		\
		"}\n"							\
		: [tmp1] "=&r" (__tmp1), [tmp2] "=&r" (__tmp2),		\
		  [tmp3] "=&r" (__tmp3), [tmp4] "=&r" (__tmp4),		\
		  [tmp5] "=&r" (__tmp5), [tmp6] "=&r" (__tmp6),		\
		  [tmp7] "=&r" (__tmp7)					\
		: [src] "r" (__src), [dst] "r" (__dst),			\
		  [ld_opc_0] "i" (TAGGED_MEM_LOAD_REC_OPC),		\
		  [ld_opc_8] "i" (TAGGED_MEM_LOAD_REC_OPC | 8),		\
		  [ld_opc_16] "i" (TAGGED_MEM_LOAD_REC_OPC | 16),	\
		  [ld_opc_24] "i" (TAGGED_MEM_LOAD_REC_OPC | 24),	\
		  [ld_opc_32] "i" (TAGGED_MEM_LOAD_REC_OPC | 32),	\
		  [ld_opc_40] "i" (TAGGED_MEM_LOAD_REC_OPC | 40),	\
		  [ld_opc_48] "i" (TAGGED_MEM_LOAD_REC_OPC | 48),	\
		  [st_opc_0] "i" (TAGGED_MEM_STORE_REC_OPC),		\
		  [st_opc_8] "i" (TAGGED_MEM_STORE_REC_OPC | 8),	\
		  [st_opc_16] "i" (TAGGED_MEM_STORE_REC_OPC | 16),	\
		  [st_opc_24] "i" (TAGGED_MEM_STORE_REC_OPC | 24),	\
		  [st_opc_32] "i" (TAGGED_MEM_STORE_REC_OPC | 32),	\
		  [st_opc_40] "i" (TAGGED_MEM_STORE_REC_OPC | 40),	\
		  [st_opc_48] "i" (TAGGED_MEM_STORE_REC_OPC | 48)	\
		: "memory");						\
})

#define E2K_TAGGED_MEMMOVE_64(___dst, ___src)				\
({									\
	volatile void * __dst = (___dst);				\
	const volatile void * __src = (___src);				\
	u64 __tmp1, __tmp2, __tmp3, __tmp4, __tmp5, __tmp6, __tmp7, __tmp8; \
	__no_asm_inline(9)					\
	asm (								\
		"{\n"							\
		"ldrd,2 [ %[src] + %[ld_opc_0] ], %[tmp1]\n"		\
		"ldrd,5 [ %[src] + %[ld_opc_8] ], %[tmp2]\n"		\
		"}\n"							\
		"{\n"							\
		"ldrd,2 [ %[src] + %[ld_opc_16] ], %[tmp3]\n"		\
		"ldrd,5 [ %[src] + %[ld_opc_24] ], %[tmp4]\n"		\
		"}\n"							\
		"{\n"							\
		"ldrd,2 [ %[src] + %[ld_opc_32] ], %[tmp5]\n"		\
		"ldrd,5 [ %[src] + %[ld_opc_40] ], %[tmp6]\n"		\
		"}\n"							\
		"{\n"							\
		"nop 1\n"						\
		"ldrd,2 [ %[src] + %[ld_opc_48] ], %[tmp7]\n"		\
		"ldrd,5 [ %[src] + %[ld_opc_56] ], %[tmp8]\n"		\
		"}\n"							\
		"{\n"							\
		"strd,2 [ %[dst] + %[st_opc_0] ], %[tmp1]\n"		\
		"strd,5 [ %[dst] + %[st_opc_8] ], %[tmp2]\n"		\
		"}\n"							\
		"{\n"							\
		"strd,2 [ %[dst] + %[st_opc_16] ], %[tmp3]\n"		\
		"strd,5 [ %[dst] + %[st_opc_24] ], %[tmp4]\n"		\
		"}\n"							\
		"{\n"							\
		"strd,2 [ %[dst] + %[st_opc_32] ], %[tmp5]\n"		\
		"strd,5 [ %[dst] + %[st_opc_40] ], %[tmp6]\n"		\
		"}\n"							\
		"{\n"							\
		"strd,2 [ %[dst] + %[st_opc_48] ], %[tmp7]\n"		\
		"strd,5 [ %[dst] + %[st_opc_56] ], %[tmp8]\n"		\
		"}\n"							\
		: [tmp1] "=&r" (__tmp1), [tmp2] "=&r" (__tmp2),		\
		  [tmp3] "=&r" (__tmp3), [tmp4] "=&r" (__tmp4),		\
		  [tmp5] "=&r" (__tmp5), [tmp6] "=&r" (__tmp6),		\
		  [tmp7] "=&r" (__tmp7), [tmp8] "=&r" (__tmp8)		\
		: [src] "r" (__src), [dst] "r" (__dst),			\
		  [ld_opc_0] "i" (TAGGED_MEM_LOAD_REC_OPC),		\
		  [ld_opc_8] "i" (TAGGED_MEM_LOAD_REC_OPC | 8),		\
		  [ld_opc_16] "i" (TAGGED_MEM_LOAD_REC_OPC | 16),	\
		  [ld_opc_24] "i" (TAGGED_MEM_LOAD_REC_OPC | 24),	\
		  [ld_opc_32] "i" (TAGGED_MEM_LOAD_REC_OPC | 32),	\
		  [ld_opc_40] "i" (TAGGED_MEM_LOAD_REC_OPC | 40),	\
		  [ld_opc_48] "i" (TAGGED_MEM_LOAD_REC_OPC | 48),	\
		  [ld_opc_56] "i" (TAGGED_MEM_LOAD_REC_OPC | 56),	\
		  [st_opc_0] "i" (TAGGED_MEM_STORE_REC_OPC),		\
		  [st_opc_8] "i" (TAGGED_MEM_STORE_REC_OPC | 8),	\
		  [st_opc_16] "i" (TAGGED_MEM_STORE_REC_OPC | 16),	\
		  [st_opc_24] "i" (TAGGED_MEM_STORE_REC_OPC | 24),	\
		  [st_opc_32] "i" (TAGGED_MEM_STORE_REC_OPC | 32),	\
		  [st_opc_40] "i" (TAGGED_MEM_STORE_REC_OPC | 40),	\
		  [st_opc_48] "i" (TAGGED_MEM_STORE_REC_OPC | 48),	\
		  [st_opc_56] "i" (TAGGED_MEM_STORE_REC_OPC | 56)	\
		: "memory");						\
})

/*
 * Read tags at @src and pack them at @dst.
 */
#define NATIVE_EXTRACT_TAGS_32(dst, src) \
do { \
	register u64 __opc0 = TAGGED_MEM_LOAD_REC_OPC; \
	register u64 __opc8 = TAGGED_MEM_LOAD_REC_OPC | 8; \
	register u64 __opc16 = TAGGED_MEM_LOAD_REC_OPC | 16; \
	register u64 __opc24 = TAGGED_MEM_LOAD_REC_OPC | 24; \
	register u64 __tmp0, __tmp8, __tmp16, __tmp24; \
 \
	__no_asm_inline(9) \
	asm volatile (	"{\n" \
			"nop 4\n" \
			"ldrd,0 [%5 + %6], %0\n" \
			"ldrd,2 [%5 + %7], %1\n" \
			"ldrd,3 [%5 + %8], %2\n" \
			"ldrd,5 [%5 + %9], %3\n" \
			"}\n" \
			"{\n" \
			"gettagd,2 %1, %1\n" \
			"gettagd,5 %3, %3\n" \
			"}\n" \
			"{\n" \
			"gettagd,2 %0, %0\n" \
			"gettagd,5 %2, %2\n" \
			"shls,0 %1, 4, %1\n" \
			"shls,3 %3, 4, %3\n" \
			"}\n" \
			"{\n" \
			"ors,0 %0, %1, %0\n" \
			"ors,3 %2, %3, %2\n" \
			"}\n" \
			"{\n" \
			"stb,2 [ %4 + 0 ], %0\n" \
			"stb,5 [ %4 + 1 ], %2\n" \
			"}\n" \
			: "=&r" (__tmp0), "=&r" (__tmp8), \
			  "=&r" (__tmp16), "=&r" (__tmp24) \
			: "r" (dst), "r" (src), \
			  "r" (__opc0), "r" (__opc8), \
			  "r" (__opc16), "r" (__opc24)); \
} while (0)

#define NATIVE_LOAD_TAGD(_addr) \
({ \
	u32 __dtag; \
	ASM_LENGTH_V5_V6(4, 6) \
	asm (ALTERNATIVE( \
	     /* Default version */ \
		"{ldrd [ %[addr] + %[opc] ], %[dtag]\n" \
		" nop 2}\n", \
	     /* CPU_FEAT_ISET_V6 version */ \
		"{ldrd [ %[addr] + %[opc] ], %[dtag]\n" \
		" nop 4}\n", \
	     %[cpu_feat_iset_v6]) \
	     "gettagd %[dtag], %[dtag]\n" \
	     : [dtag] "=r" (__dtag) \
	     : [addr] "m" (*(const u64 *) (_addr)), \
	       [opc] "i" (TAGGED_MEM_LOAD_REC_OPC), \
	       [cpu_feat_iset_v6] "i" (CPU_FEAT_ISET_V6)); \
	__dtag; \
})

#define NATIVE_LOAD_VAL_AND_TAGD(_addr, _val, _tag) \
do { \
	BUILD_BUG_ON(sizeof(_tag) > 4); \
	ASM_LENGTH_V5_V6(5, 6) \
	asm (ALTERNATIVE( \
	     /* Default version */ \
		"{ldrd [ %[addr] + %[opc] ], %[val]\n" \
		" nop 2}\n" \
		"{gettagd %[val], %[tag]}\n" \
		"{puttagd %[val], 0, %[val]}\n", \
	     /* CPU_FEAT_ISET_V6 version */ \
		"{ldrd [ %[addr] + %[opc] ], %[val]\n" \
		" nop 4}\n" \
		"{gettagd %[val], %[tag]\n" \
		" puttagd %[val], 0, %[val]}\n", \
	     %[cpu_feat_iset_v6]) \
	     : [tag] "=r" (_tag), \
	       [val] "=r" (_val) \
	     : [addr] "m" (*((const u64 *) (_addr))), \
	       [opc] "i" (TAGGED_MEM_LOAD_REC_OPC), \
	       [cpu_feat_iset_v6] "i" (CPU_FEAT_ISET_V6)); \
} while (0)

#define NATIVE_LOAD_VAL_AND_TAGW(_addr, _val, _tag) \
do { \
	BUILD_BUG_ON(sizeof(_tag) > 4); \
	ASM_LENGTH_V5_V6(5, 6) \
	asm (ALTERNATIVE( \
	     /* Default version */ \
		"{ldrd [ %[addr] + %[opc] ], %[val]\n" \
		" nop 2}\n" \
		"{gettags %[val], %[tag]}\n" \
		"{puttags %[val], 0, %[val]}\n", \
	     /* CPU_FEAT_ISET_V6 version */ \
		"{ldrd [ %[addr] + %[opc] ], %[val]\n" \
		" nop 4}\n" \
		"{gettags %[val], %[tag]\n" \
		" puttags %[val], 0, %[val]}\n", \
	     %[cpu_feat_iset_v6]) \
	     : [tag] "=r" (_tag), \
	       [val] "=r" (_val) \
	     : [addr] "m" (*((const u32 *) (_addr))), \
	       [opc] "i" (TAGGED_MEM_LOAD_REC_OPC_W), \
	       [cpu_feat_iset_v6] "i" (CPU_FEAT_ISET_V6)); \
} while (0)

#define	NATIVE_LOAD_VAL_AND_TAGQ(_addr, _lo, _hi, _tag, _offset) \
do { \
	u32 __tag_lo_lvt, __tag_hi_lvt; \
	ASM_LENGTH_V5_V6(5, 7) \
	asm (ALTERNATIVE( \
	     /* Default version */ \
		"{ldrd,2 [ %[addr] + %[opc_lo] ], %[lo]\n" \
		" ldrd,5 [ %[addr] + %[opc_hi] ], %[hi]\n" \
		" nop 2}\n", \
	     /* CPU_FEAT_ISET_V6 version */ \
		"{ldrd,2 [ %[addr] + %[opc_lo] ], %[lo]\n" \
		" ldrd,5 [ %[addr] + %[opc_hi] ], %[hi]\n" \
		" nop 4}\n", \
	     %[cpu_feat_iset_v6]) \
	     "{gettagd,2 %[lo], %[tag_lo]\n" \
	     " gettagd,5 %[hi], %[tag_hi]}\n" \
	     "{puttagd,2 %[lo], 0, %[lo]\n" \
	     " puttagd,5 %[hi], 0, %[hi]}\n" \
	     : [tag_lo] "=r" (__tag_lo_lvt), [tag_hi] "=r" (__tag_hi_lvt), \
	       [lo] "=r" (_lo), [hi] "=r" (_hi) \
	     : [addr] "m" (*((const u64 *) (_addr))), \
	       [opc_lo] "i" (TAGGED_MEM_LOAD_REC_OPC), \
	       [opc_hi] "ir" (TAGGED_MEM_LOAD_REC_OPC | (u64) (u32) (_offset)), \
	       [cpu_feat_iset_v6] "i" (CPU_FEAT_ISET_V6) \
	     : "memory"); \
	(_tag) = (__tag_hi_lvt << 4) | __tag_lo_lvt; \
} while (0)

/**
 * Load/stote based data operations
 */
#define E2K_LD_GREG_BASED_B(greg_no, offset, chan_letter) \
({ \
	register unsigned long res; \
	asm volatile ("ldb," #chan_letter "\t%%dg" #greg_no ", [%1], %0" \
			: "=r"(res) \
			: "ri" ((u64) (offset))); \
	res; \
})
#define E2K_LD_GREG_BASED_H(greg_no, offset, chan_letter) \
({ \
	register unsigned long res; \
	asm volatile ("ldh," #chan_letter "\t%%dg" #greg_no ", [%1], %0" \
			: "=r"(res) \
			: "ri" ((u64) (offset))); \
	res; \
})
#define E2K_LD_GREG_BASED_W(greg_no, offset, chan_letter) \
({ \
	register unsigned long res; \
	asm volatile ("ldw," #chan_letter "\t%%dg" #greg_no ", [%1], %0" \
			: "=r"(res) \
			: "ri" ((u64) (offset))); \
	res; \
})
#define E2K_LD_GREG_BASED_D(greg_no, offset, chan_letter) \
({ \
	register unsigned long long res; \
	asm volatile ("ldd," #chan_letter "\t%%dg" #greg_no ", [%1], %0" \
			: "=r"(res) \
			: "ri" ((u64) (offset))); \
	res; \
})
#define E2K_ST_GREG_BASED_B(greg_no, offset, value, chan_letter) \
({ \
	asm volatile ("stb," #chan_letter "\t%%dg" #greg_no ", [%0], %1" \
			: \
			: "ri" ((u64) (offset)), \
			  "r" ((u8) (value))); \
})
#define E2K_ST_GREG_BASED_H(greg_no, offset, value, chan_letter) \
({ \
	asm volatile ("sth," #chan_letter "\t%%dg" #greg_no ", [%0], %1" \
			: \
			: "ri" ((u64) (offset)), \
			  "r" ((u16) (value))); \
})
#define E2K_ST_GREG_BASED_W(greg_no, offset, value, chan_letter) \
({ \
	asm volatile ("stw," #chan_letter "\t%%dg" #greg_no ", [%0], %1" \
			: \
			: "ri" ((u64) (offset)), \
			  "r" ((u32) (value))); \
})
#define E2K_ST_GREG_BASED_D(greg_no, offset, value, chan_letter) \
({ \
	asm volatile ("std," #chan_letter "\t%%dg" #greg_no ", [%0], %1" \
			: \
			: "ri" ((u64) (offset)), \
			  "r" ((u64) (value))); \
})

#define E2K_LOAD_GREG_BASED_B(greg_no, offset)				\
			E2K_LD_GREG_BASED_B(greg_no, offset, 0)
#define E2K_LOAD_GREG_BASED_H(greg_no, offset)				\
			E2K_LD_GREG_BASED_H(greg_no, offset, 0)
#define E2K_LOAD_GREG_BASED_W(greg_no, offset)				\
			E2K_LD_GREG_BASED_W(greg_no, offset, 0)
#define E2K_LOAD_GREG_BASED_D(greg_no, offset)				\
			E2K_LD_GREG_BASED_D(greg_no, offset, 0)

#define E2K_STORE_GREG_BASED_B(greg_no, offset, value)			\
			E2K_ST_GREG_BASED_B(greg_no, offset, value, 2)
#define E2K_STORE_GREG_BASED_H(greg_no, offset, value)			\
			E2K_ST_GREG_BASED_H(greg_no, offset, value, 2)
#define E2K_STORE_GREG_BASED_W(greg_no, offset, value)			\
			E2K_ST_GREG_BASED_W(greg_no, offset, value, 2)
#define E2K_STORE_GREG_BASED_D(greg_no, offset, value)			\
			E2K_ST_GREG_BASED_D(greg_no, offset, value, 2)


/*
 * Atomic read hardware stacks (procedure and chain) registers
 * in coordinated state.
 * Any interrupt inside registers reading sequence can update
 * some fields of registers and them can be at miscoordinated state
 * So use "wait lock" and "wait unlock" load/store to avoid interrupts
 * Argument 'lock_addr' is used only to provide lock/unlock, so it can be
 * any unused local variable of caller
 */
#define ATOMIC_READ_P_STACK_REGS(psp, pshtp)				\
({									\
	unsigned long lock_addr;					\
	asm volatile (							\
		"\n"							\
		"1:\n"							\
		"\t ldd,0  \t 0, [%3] 7, %0\n"				\
									\
		"\t rrd    \t %%psp.lo,  %0\n"				\
		"\t rrd    \t %%psp.hi,  %1\n"				\
		"\t rrd    \t %%pshtp,   %2\n"				\
									\
		"{\n"							\
			"\t std,2   \t 0, [%3] 2, %0\n"			\
			"\t ibranch \t 1b ? %%MLOCK\n"			\
		"}\n"							\
		: "=&r" (psp.lo),					\
		  "=&r" (psp.hi),					\
		  "=&r" (pshtp)						\
		: "r" ((u64) (&lock_addr))			\
		: "memory");						\
})
#define ATOMIC_READ_PC_STACK_REGS(pcsp, pcshtp)				\
({									\
	unsigned long lock_addr;					\
	asm volatile (							\
		"\n"							\
		"1:\n"							\
		"\t ldd,0  \t 0, [%3] 7, %0\n"				\
									\
		"\t rrd    \t %%pcsp.lo,  %0\n"				\
		"\t rrd    \t %%pcsp.hi,  %1\n"				\
		"\t rrd    \t %%pcshtp,   %2\n"				\
									\
		"{\n"							\
			"\t std,2   \t 0, [%3] 2, %0\n"			\
			"\t ibranch \t 1b ? %%MLOCK\n"			\
		"}\n"							\
		: "=&r" (pcsp.lo),					\
		  "=&r" (pcsp.hi),					\
		  "=&r" (pcshtp)					\
		: "r" ((u64) (&lock_addr))			\
		: "memory");						\
})
#define ATOMIC_READ_HW_PS_SIZES(psp_hi, pshtp)				\
({									\
	unsigned long lock_addr;					\
	__asm_length(4)					\
	asm volatile (							\
		"\n"							\
		"1:\n"							\
		"\t ldd,0  \t 0, [%2] 7, %0\n"				\
									\
		"\t rrd    \t %%psp.hi,  %0\n"				\
		"\t rrd    \t %%pshtp,   %1\n"				\
									\
		"{\n"							\
			"\t std,2   \t 0, [%2] 2, %0\n"			\
			"\t ibranch \t 1b ? %%MLOCK\n"			\
		"}\n"							\
		: "=&r" (psp_hi),					\
		  "=&r" (pshtp)						\
		: "r" ((u64) (&lock_addr))			\
		: "memory");						\
})
#define ATOMIC_READ_HW_PCS_SIZES(pcsp_hi, pcshtp)			\
({									\
	unsigned long lock_addr;					\
	__asm_length(4)					\
	asm volatile (							\
		"\n"							\
		"1:\n"							\
		"\t ldd,0  \t 0, [%2] 7, %0\n"				\
									\
		"\t rrd    \t %%pcsp.hi, %0\n"				\
		"\t rrs    \t %%pcshtp,  %1\n"				\
									\
		"{\n"							\
			"\t std,2   \t 0, [%2] 2, %0\n"			\
			"\t ibranch \t 1b ? %%MLOCK\n"			\
		"}\n"							\
		: "=&r" (pcsp_hi),					\
		  "=&r" (pcshtp)					\
		: "r" ((u64) (&lock_addr))			\
		: "memory");						\
})
#define ATOMIC_READ_HW_STACKS_SIZES(psp_hi, pshtp, pcsp_hi, pcshtp)	\
({									\
	unsigned long lock_addr;					\
	__asm_length(6)					\
	asm volatile (							\
		"\n"							\
		"1:\n"							\
		"\t ldd,0  \t 0, [%4] 7, %0\n"				\
									\
		"\t rrd    \t %%psp.hi,  %0\n"				\
		"\t rrd    \t %%pshtp,   %1\n"				\
		"\t rrd    \t %%pcsp.hi, %2\n"				\
		"\t rrs    \t %%pcshtp,  %3\n"				\
									\
		"{\n"							\
			"\t std,2   \t 0, [%4] 2, %0\n"			\
			"\t ibranch \t 1b ? %%MLOCK\n"			\
		"}\n"							\
		: "=&r" (psp_hi),					\
		  "=&r" (pshtp),					\
		  "=&r" (pcsp_hi),					\
		  "=&r" (pcshtp)					\
		: "r" ((u64) (&lock_addr))			\
		: "memory");						\
})
#define ATOMIC_READ_HW_STACKS_REGS(psp, pshtp, pcsp, pcshtp)		\
({									\
	unsigned long lock_addr;					\
	asm volatile (							\
		"\n"							\
		"1:\n"							\
		"\t ldd,0  \t 0, [%6] 7, %0\n"				\
									\
		"\t rrd    \t %%psp.lo,  %0\n"				\
		"\t rrd    \t %%psp.hi,  %1\n"				\
		"\t rrd    \t %%pshtp,   %2\n"				\
		"\t rrd    \t %%pcsp.lo, %3\n"				\
		"\t rrd    \t %%pcsp.hi, %4\n"				\
		"\t rrs    \t %%pcshtp,  %5\n"				\
									\
		"{\n"							\
			"\t std,2   \t 0, [%6] 2, %0\n"			\
			"\t ibranch \t 1b ? %%MLOCK\n"			\
		"}\n"							\
		: "=&r" (psp.lo),					\
		  "=&r" (psp.hi),					\
		  "=&r" (pshtp.word),					\
		  "=&r" (pcsp.lo),					\
		  "=&r" (pcsp.hi),					\
		  "=&r" (pcshtp.word)					\
		: "r" ((u64) (&lock_addr))			\
		: "memory");						\
})
/*
 * Atomic read all stacks hardware (procedure and chain) and data stack
 * registers in coordinated state.
 */
#define ATOMIC_READ_ALL_STACKS_REGS(psp, pshtp, pcsp, pcshtp, usd, cr1)	\
({									\
	unsigned long lock_addr;					\
	asm volatile (							\
		"\n"							\
		"1:\n"							\
		"\t ldd,0  \t 0, [%9] 7, %0\n"				\
									\
		"\t rrd    \t %%psp.lo,  %0\n"				\
		"\t rrd    \t %%psp.hi,  %1\n"				\
		"\t rrd    \t %%pshtp,   %2\n"				\
		"\t rrd    \t %%pcsp.lo, %3\n"				\
		"\t rrd    \t %%pcsp.hi, %4\n"				\
		"\t rrs    \t %%pcshtp,  %5\n"				\
		"\t rrd    \t %%usd.lo,  %6\n"				\
		"\t rrd    \t %%usd.hi,  %7\n"				\
		"\t rrd    \t %%cr1.lo,  %8\n"				\
		"\t rrd    \t %%cr1.hi,  %9\n"				\
									\
		"{\n"							\
			"\t std,2   \t 0, [%9] 2, %0\n"			\
			"\t ibranch \t 1b ? %%MLOCK\n"			\
		"}\n"							\
		: "=&r" (psp.lo),					\
		  "=&r" (psp.hi),					\
		  "=&r" (pshtp.word),					\
		  "=&r" (pcsp.lo),					\
		  "=&r" (pcsp.hi),					\
		  "=&r" (pcshtp.word),					\
		  "=&r" (usd.lo),					\
		  "=&r" (usd.hi),					\
		  "=&r" (cr1.lo),					\
		  "=&r" (cr1.hi)					\
		: "r" ((u64) (&lock_addr))			\
		: "memory");						\
})

#define NATIVE_CLEAN_LD_ACQ_ADDRESS(_reg1, _reg2, _hwbug_address) \
({ \
	__asm_length(4) \
	asm volatile ( \
		"{\n" \
		"ldb,0,sm %[addr], 0 * 4096 + 0 * 64, %[reg1], mas=%[mas]\n" \
		"ldb,3,sm %[addr], 0 * 4096 + 4 * 64, %[reg2], mas=%[mas]\n" \
		"}\n" \
		"{\n" \
		"ldb,0,sm %[addr], 8 * 4096 + 1 * 64, %[reg1], mas=%[mas]\n" \
		"ldb,3,sm %[addr], 8 * 4096 + 5 * 64, %[reg2], mas=%[mas]\n" \
		"}\n" \
		"{\n" \
		"ldb,0,sm %[addr], 16 * 4096 + 2 * 64, %[reg1], mas=%[mas]\n" \
		"ldb,3,sm %[addr], 16 * 4096 + 6 * 64, %[reg2], mas=%[mas]\n" \
		"}\n" \
		"{\n" \
		"ldb,0,sm %[addr], 24 * 4096 + 3 * 64, %[reg1], mas=%[mas]\n" \
		"ldb,3,sm %[addr], 24 * 4096 + 7 * 64, %[reg2], mas=%[mas]\n" \
		"}\n" \
		: [reg1] "=&r" (_reg1), [reg2] "=&r" (_reg2) \
		: [addr] "r" (__hwbug_address), \
		  [mas] "i" (MAS_BYPASS_ALL_CACHES | \
			     MAS_MODE_LOAD_OP_LOCK_CHECK)); \
})

/*
 * #89527: on E4C with multiple nodes atomic operations have fully relaxed
 * memory ordering because of a hardware bug, must add "wait ma_c".
 */
#if defined CONFIG_CPU_E2S && defined CONFIG_NUMA
# define MB_BEFORE_ATOMIC	"{wait st_c=1, ma_c=1}\n"
# define MB_AFTER_ATOMIC	"{wait st_c=1, ma_c=1}\n"
# define MB_AFTER_ATOMIC_LOCK_MB
#else
# define MB_BEFORE_ATOMIC
# define MB_AFTER_ATOMIC
# define MB_AFTER_ATOMIC_LOCK_MB
#endif

#define MB_BEFORE_ATOMIC_LOCK_MB

#define MB_BEFORE_ATOMIC_STRONG_MB	MB_BEFORE_ATOMIC
#define MB_AFTER_ATOMIC_STRONG_MB	MB_AFTER_ATOMIC

#define MB_BEFORE_ATOMIC_RELEASE_MB	MB_BEFORE_ATOMIC
#define MB_AFTER_ATOMIC_RELEASE_MB

#define MB_BEFORE_ATOMIC_ACQUIRE_MB
#define MB_AFTER_ATOMIC_ACQUIRE_MB	MB_AFTER_ATOMIC

#define MB_BEFORE_ATOMIC_RELAXED_MB
#define MB_AFTER_ATOMIC_RELAXED_MB

#if defined CONFIG_CPU_E16C || defined CONFIG_CPU_E2C3 || defined CONFIG_CPU_E12C
#define BEFORE_ATOMIC(label, mem_model, no_atomic_spurious_fault) \
		MB_BEFORE_ATOMIC_##mem_model \
		label "\n" \
		ALTERNATIVE( \
		/* Default version */ \
			"{nop 1}", \
		/* CPU_NO_HWBUG_ATOMIC_SPURIOUS_FAULT version */ \
			"", \
		%[no_atomic_spurious_fault])
#else
#define BEFORE_ATOMIC(label, mem_model, no_atomic_spurious_fault) \
		MB_BEFORE_ATOMIC_##mem_model \
		label "\n"
#endif /* CONFIG_CPU_E16C || CONFIG_CPU_E2C3 || CONFIG_CPU_E12C */


#if CONFIG_CPU_ISET_MIN >= 5
# define ACQUIRE_MB_ATOMIC_CHANNEL	"5"
# define RELAXED_MB_ATOMIC_CHANNEL	"5"
#else
# define ACQUIRE_MB_ATOMIC_CHANNEL	"2"
# define RELAXED_MB_ATOMIC_CHANNEL	"2"
#endif
#define RELEASE_MB_ATOMIC_CHANNEL	"2"
#define STRONG_MB_ATOMIC_CHANNEL	"2"
#define LOCK_MB_ATOMIC_CHANNEL		ACQUIRE_MB_ATOMIC_CHANNEL

#define LOCK_MB_ATOMIC_MAS_VALUE	0x2
#define ACQUIRE_MB_ATOMIC_MAS_VALUE	0x2
#define RELAXED_MB_ATOMIC_MAS_VALUE	0x2
#if CONFIG_CPU_ISET_MIN >= 6
# define RELEASE_MB_ATOMIC_MAS_VALUE	0x73
/* We use "release" operation since in practive it has strong semantics too
 * but (unlike normal one) also allows specifying "mt=1" parameter */
# define STRONG_MB_ATOMIC_MAS_VALUE	0x73
#else
# define RELEASE_MB_ATOMIC_MAS_VALUE	0x2
# define STRONG_MB_ATOMIC_MAS_VALUE	0x2
#endif
#define LOCK_MB_ATOMIC_MAS		__stringify(LOCK_MB_ATOMIC_MAS_VALUE)
#define ACQUIRE_MB_ATOMIC_MAS		__stringify(ACQUIRE_MB_ATOMIC_MAS_VALUE)
#define RELAXED_MB_ATOMIC_MAS		__stringify(RELAXED_MB_ATOMIC_MAS_VALUE)
#define RELEASE_MB_ATOMIC_MAS		__stringify(RELEASE_MB_ATOMIC_MAS_VALUE)
#define STRONG_MB_ATOMIC_MAS		__stringify(STRONG_MB_ATOMIC_MAS_VALUE)

#define CLOBBERS_LOCK_MB	: "memory"
#define CLOBBERS_ACQUIRE_MB	: "memory"
#define CLOBBERS_RELEASE_MB	: "memory"
#define CLOBBERS_STRONG_MB	: "memory"
#define CLOBBERS_RELAXED_MB

/*
 * mem_model - one of the following:
 * LOCK_MB
 * ACQUIRE_MB
 * RELEASE_MB
 * STRONG_MB
 * RELAXED_MB
 */
#define NATIVE_ATOMIC_OP(__val, __addr, __rval, \
			size_letter, op, mem_model) \
do { \
	ASM_LENGTH_V5_V6(11, 12) \
	asm NOT_VOLATILE ( \
		BEFORE_ATOMIC("1:", mem_model, no_atomic_spurious_fault) \
		ALTERNATIVE( \
		/* Default version - 10 cycles ld->st delay */ \
			"{nop 6\n" \
			" ld" #size_letter ",0 %[addr], %[rval], mas=0x7}\n", \
		/* CPU_FEAT_ISET_V6 - 11 cycles ld->st delay */ \
			"{nop 7\n" \
			" ld" #size_letter ",0 %[addr], %[rval], mas=0x7}\n", \
		%[iset_v6]) \
		"{nop 2\n" \
		  op " %[rval], %[val], %[rval]}\n" \
		"{st" #size_letter "," mem_model##_ATOMIC_CHANNEL \
			" %[addr], %[rval], mas=" mem_model##_ATOMIC_MAS "\n" \
		" ibranch 1b ? %%MLOCK}\n" \
		MB_AFTER_ATOMIC_##mem_model \
		: [rval] "=&r" (__rval), [addr] "+m" (*(__addr)) \
		: [val] "ir" (__val), \
		  [iset_v6] "i" (CPU_FEAT_ISET_V6), \
		  [no_atomic_spurious_fault] "i" (CPU_NO_HWBUG_ATOMIC_SPURIOUS_FAULT) \
		CLOBBERS_##mem_model); \
} while (0)

#define NATIVE_ATOMIC_FETCH_OP(__val, __addr, __rval, __tmp, \
			size_letter, op, mem_model) \
do { \
	ASM_LENGTH_V5_V6(11, 12) \
	asm NOT_VOLATILE ( \
		BEFORE_ATOMIC("1:", mem_model, no_atomic_spurious_fault) \
		ALTERNATIVE( \
		/* Default version - 10 cycles ld->st delay */ \
			"{nop 6\n" \
			" ld" #size_letter ",0 %[addr], %[rval], mas=0x7}\n", \
		/* CPU_FEAT_ISET_V6 - 11 cycles ld->st delay */ \
			"{nop 7\n" \
			" ld" #size_letter ",0 %[addr], %[rval], mas=0x7}\n", \
		%[iset_v6]) \
		"{nop 2\n" \
		  op " %[rval], %[val], %[tmp]}\n" \
		"{st" #size_letter "," mem_model##_ATOMIC_CHANNEL \
			" %[addr], %[tmp], mas=" mem_model##_ATOMIC_MAS "\n" \
		" ibranch 1b ? %%MLOCK}\n" \
		MB_AFTER_ATOMIC_##mem_model \
		: [tmp] "=&r" (__tmp), [addr] "+m" (*(__addr)), \
		  [rval] "=&r" (__rval) \
		: [val] "ir" (__val), \
		  [iset_v6] "i" (CPU_FEAT_ISET_V6), \
		  [no_atomic_spurious_fault] "i" (CPU_NO_HWBUG_ATOMIC_SPURIOUS_FAULT) \
		CLOBBERS_##mem_model); \
} while (0)

/* Atomically add to 16 low bits and return the new 32 bits value */
#define NATIVE_ATOMIC16_ADD_RETURN32_LOCK(val, addr, rval, tmp) \
({ \
	__asm_length(11) \
	asm NOT_VOLATILE ( \
		BEFORE_ATOMIC("1:", LOCK_MB, no_atomic_spurious_fault) \
		"\n{"\
		"\nnop 4"\
		"\nldw,0\t0x0, [%3] 0x7, %0" \
		"\n}" \
		"\n{"\
		"\nadds %0, %2, %1" \
		"\nands %0, 0xffff0000, %0" \
		"\n}" \
		"\nands %1, 0x0000ffff, %1" \
		"\n{"\
		"\nnop 2"\
		"\nadds %0, %1, %0" \
		"\n}" \
		"\n{"\
		"\nstw," LOCK_MB_ATOMIC_CHANNEL " 0x0, [%3] 0x2, %0" \
		"\nibranch 1b ? %%MLOCK" \
		"\n}" \
		MB_AFTER_ATOMIC_LOCK_MB \
		: "=&r" (rval), "=&r" (tmp) \
		: "i" (val), "r" ((u64) (addr)), \
		  [no_atomic_spurious_fault] "i" (CPU_NO_HWBUG_ATOMIC_SPURIOUS_FAULT) \
		: "memory");	\
})

/*
 * C equivalent:
 *
 *	boot_spinlock_t oldval, newval;
 *	oldval.lock = ACCESS_ONCE(lock->lock);
 *	if (oldval.head == oldval.tail) {
 *		newval.lock = oldval.lock + (1 << BOOT_SPINLOCK_TAIL_SHIFT);
 *		if (cmpxchg(&lock->lock, oldval.lock, newval.lock) ==
 *				oldval.lock)
 *			return 1;
 *	}
 *	return 0;
 */
#define NATIVE_ATOMIC_TICKET_TRYLOCK(spinlock, tail_shift, \
				__val, __head, __tail, __rval) \
do { \
	ASM_LENGTH_V5_V6(11, 12) \
	asm NOT_VOLATILE ( \
		BEFORE_ATOMIC("1:", LOCK_MB, no_atomic_spurious_fault) \
		ALTERNATIVE( \
		/* Default version - 10 cycles ld->st delay */ \
			"{nop 5\n"\
			" ldw,0 %[addr], %[val], mas=0x7}\n", \
		/* CPU_FEAT_ISET_V6 - 11 cycles ld->st delay */ \
			"{nop 6\n"\
			" ldw,0 %[addr], %[val], mas=0x7}\n", \
		%[iset_v6]) \
		"{shrs,0 %[val], 0x10, %[tail]\n" \
		" getfs,1 %[val], 0x400, %[head]}\n" \
		"{nop 1\n" \
		" cmpesb,0 %[tail], %[head], %%pred2}\n" \
		"{merges,0 0, 1, %[rval], %%pred2\n" \
		" adds,2 %[val], %[incr], %[val] ? %%pred2}\n" \
		"{stw," LOCK_MB_ATOMIC_CHANNEL " %[addr], %[val], mas=" LOCK_MB_ATOMIC_MAS "\n" \
		" ibranch 1b ? %%MLOCK}\n" \
		MB_AFTER_ATOMIC_LOCK_MB \
		: [rval] "=&r" (__rval), [val] "=&r" (__val), \
		  [head] "=&r" (__head), [tail] "=&r" (__tail), \
		  [addr] "+m" (*(spinlock)) \
		: [incr] "i" (1 << tail_shift), \
		  [iset_v6] "i" (CPU_FEAT_ISET_V6), \
		  [no_atomic_spurious_fault] "i" (CPU_NO_HWBUG_ATOMIC_SPURIOUS_FAULT) \
		: "memory", "pred2"); \
} while (0)


/*
 * Atomic operations with return value and acquire/release semantics
 */

#define NATIVE_ATOMIC_FETCH_OP_UNLESS(__val, __addr, __unless, __tmp, __rval, \
		size_letter, op, op_pred, add_op, add_op_pred, cmp_op, mem_model) \
do { \
	ASM_LENGTH_V5_V6(11, 12) \
	asm NOT_VOLATILE ( \
		BEFORE_ATOMIC("1:", mem_model, no_atomic_spurious_fault) \
		ALTERNATIVE( \
		/* Default version - 10 cycles ld->st delay */ \
			"{nop 6\n" \
			" ld"#size_letter ",0 %[addr], %[rval], mas=0x7}\n", \
		/* CPU_FEAT_ISET_V6 - 11 cycles ld->st delay */ \
			"{nop 7\n" \
			" ld"#size_letter ",0 %[addr], %[rval], mas=0x7}\n", \
		%[iset_v6]) \
		"{nop 1\n" \
		  cmp_op " %[rval], %[unless], %%pred2}\n" \
		"{\n" \
		  op " %[rval], %[val], %[tmp] ? " op_pred "%%pred2\n" \
		  add_op " %[rval], 0, %[tmp] ? " add_op_pred "%%pred2}\n" \
		"{st"#size_letter "," mem_model##_ATOMIC_CHANNEL \
		      " %[addr], %[tmp], mas=" mem_model##_ATOMIC_MAS "\n" \
		" ibranch 1b ? %%MLOCK}\n" \
		MB_AFTER_ATOMIC_##mem_model \
		: [rval] "=&r" (__rval), [tmp] "=&r" (__tmp), \
		  [addr] "+m" (*(__addr)) \
		: [val] "ir" (__val), [unless] "ir" (__unless), \
		  [iset_v6] "i" (CPU_FEAT_ISET_V6), \
		  [no_atomic_spurious_fault] "i" (CPU_NO_HWBUG_ATOMIC_SPURIOUS_FAULT) \
		CLOBBERS_PRED2_##mem_model); \
} while (0)

#define NATIVE_ATOMIC_FETCH_XCHG_UNLESS_INC(__val, __addr, __tmp, __rval, \
		mem_size_letter, alu_size_letter, merge_op, cmp_op, mem_model) \
do { \
	ASM_LENGTH_V5_V6(11, 12) \
	asm NOT_VOLATILE ( \
		BEFORE_ATOMIC("1:", mem_model, no_atomic_spurious_fault) \
		ALTERNATIVE( \
		/* Default version - 10 cycles ld->st delay */ \
			"{nop 5\n"\
			" ld"#mem_size_letter ",0 %[addr], %[rval], mas=0x7}\n", \
		/* CPU_FEAT_ISET_V6 - 11 cycles ld->st delay */ \
			"{nop 6\n"\
			" ld"#mem_size_letter ",0 %[addr], %[rval], mas=0x7}\n", \
		%[iset_v6]) \
		"{nop 1\n" \
		  cmp_op " %[rval], %[val], %%pred2\n" \
		" add"#alu_size_letter " 0x1, %[rval], %[rval]}\n" \
		"{" merge_op " %[rval], %[val], %[tmp], %%pred2}\n" \
		"{st"#mem_size_letter "," mem_model##_ATOMIC_CHANNEL \
			"%[addr], %[tmp], mas=" mem_model##_ATOMIC_MAS "\n" \
		" ibranch 1b ? %%MLOCK}\n" \
		MB_AFTER_ATOMIC_##mem_model \
		: [rval] "=&r" (__rval), [tmp] "=&r" (__tmp), \
		  [addr] "+m" (*(__addr)) \
		: [val] "ir" (__val), \
		  [iset_v6] "i" (CPU_FEAT_ISET_V6), \
		  [no_atomic_spurious_fault] "i" (CPU_NO_HWBUG_ATOMIC_SPURIOUS_FAULT) \
		CLOBBERS_PRED2_##mem_model); \
} while (0)

#define NATIVE_ATOMIC_XCHG_RETURN(__val, __addr, __rval, \
				  size_letter, mem_model) \
do { \
	ASM_LENGTH_V6_V7(6, 5) \
	asm NOT_VOLATILE ( \
		BEFORE_ATOMIC("1:", mem_model, no_atomic_spurious_fault) \
		ALTERNATIVE_2( \
		/* Default version - 6 cycles ld->st delay */ \
			"{nop 5\n" \
			" ld"#size_letter ",0 %[addr], %[rval], mas=0x7}\n", \
		/* CPU_FEAT_ISET_V6 - 7 cycles ld->st delay */ \
			"{nop 6\n" \
			" ld"#size_letter ",0 %[addr], %[rval], mas=0x7}\n", \
			%[iset_v6], \
		/* CPU_FEAT_ISET_V7 - 5 cycles ld->st delay */ \
			"{nop 4\n" \
			" ld"#size_letter ",0 %[addr], %[rval], mas=0x7}\n", \
			%[iset_v7] \
		) \
		"{st"#size_letter "," mem_model##_ATOMIC_CHANNEL \
			" %[addr], %[val], mas=" mem_model##_ATOMIC_MAS "\n" \
		" ibranch 1b ? %%MLOCK}\n" \
		MB_AFTER_ATOMIC_##mem_model \
		: [rval] "=&r" (__rval), [addr] "+m" (*(__addr)) \
		: [val] "r" (__val), \
		  [iset_v6] "i" (CPU_FEAT_ISET_V6), \
		  [iset_v7] "i" (CPU_FEAT_ISET_V7), \
		  [no_atomic_spurious_fault] "i" (CPU_NO_HWBUG_ATOMIC_SPURIOUS_FAULT) \
		CLOBBERS_##mem_model); \
} while (0)

#define CLOBBERS_PRED2_LOCK_MB		: "memory", "pred2"
#define CLOBBERS_PRED2_ACQUIRE_MB	: "memory", "pred2"
#define CLOBBERS_PRED2_RELEASE_MB	: "memory", "pred2"
#define CLOBBERS_PRED2_STRONG_MB	: "memory", "pred2"
#define CLOBBERS_PRED2_RELAXED_MB	: "pred2"


#define CLOBBERS_PRED2_3_LOCK_MB	: "memory", "pred2", "pred3"
#define CLOBBERS_PRED2_3_ACQUIRE_MB	: "memory", "pred2", "pred3"
#define CLOBBERS_PRED2_3_RELEASE_MB	: "memory", "pred2", "pred3"
#define CLOBBERS_PRED2_3_STRONG_MB	: "memory", "pred2", "pred3"
#define CLOBBERS_PRED2_3_RELAXED_MB	: "pred2", "pred3"


#define NATIVE_ATOMIC_CMPXCHG_RETURN(__old, __new, __addr, __stored_val, \
			__rval, size_letter, sxt_size, mem_model) \
do { \
	ASM_LENGTH_V5_V6(11, 12) \
	asm NOT_VOLATILE ( \
		BEFORE_ATOMIC("3:", mem_model, no_atomic_spurious_fault) \
		ALTERNATIVE( \
		/* Default version - 10 cycles ld->st delay */ \
			"{nop 5\n"\
			" ld"#size_letter ",0 %[addr], %[rval], mas=0x7}\n", \
		/* CPU_FEAT_ISET_V6 - 11 cycles ld->st delay */ \
			"{nop 6\n"\
			" ld"#size_letter ",0 %[addr], %[rval], mas=0x7}\n", \
		%[iset_v6]) \
		"{sxt "#sxt_size", %[rval], %[rval]}\n" \
		"{nop 1\n" \
		" cmpedb %[rval], %[old], %%pred2}\n" \
		"{merged %[rval], %[new], %[stored_val], %%pred2}\n" \
		"{st"#size_letter "," mem_model##_ATOMIC_CHANNEL \
			" %[addr], %[stored_val], mas=" mem_model##_ATOMIC_MAS "\n" \
		" ibranch 3b ? %%MLOCK}\n" \
		MB_AFTER_ATOMIC_##mem_model \
		: [rval] "=&r" (__rval), [stored_val] "=&r" (__stored_val), \
		  [addr] "+m" (*(__addr)) \
		: [new] "ir" ((u64) (__new)), [old] "ir" ((u64) (__old)), \
		  [iset_v6] "i" (CPU_FEAT_ISET_V6), \
		  [no_atomic_spurious_fault] "i" (CPU_NO_HWBUG_ATOMIC_SPURIOUS_FAULT) \
		CLOBBERS_PRED2_##mem_model); \
} while (0)

#define NATIVE_ATOMIC_CMPXCHG_WORD_RETURN(__old, __new, __addr, \
					  __stored_val, __rval, mem_model) \
do { \
	ASM_LENGTH_V5_V6(11, 12) \
	asm NOT_VOLATILE ( \
		BEFORE_ATOMIC("3:", mem_model, no_atomic_spurious_fault) \
		ALTERNATIVE( \
		/* Default version - 10 cycles ld->st delay */ \
			"{nop 6\n"\
			" ldw,0 %[addr], %[rval], mas=0x7}\n", \
		/* CPU_FEAT_ISET_V6 - 11 cycles ld->st delay */ \
			"{nop 7\n"\
			" ldw,0 %[addr], %[rval], mas=0x7}\n", \
		%[iset_v6]) \
		"{nop 1\n" \
		" cmpesb %[rval], %[old], %%pred2}\n" \
		"{merges %[rval], %[new], %[stored_val], %%pred2}\n" \
		"{stw," mem_model##_ATOMIC_CHANNEL \
			" %[addr], %[stored_val], mas=" mem_model##_ATOMIC_MAS "\n" \
		" ibranch 3b ? %%MLOCK}\n" \
		MB_AFTER_ATOMIC_##mem_model \
		: [stored_val] "=&r" (__stored_val), \
		  [rval] "=&r" (__rval), [addr] "+m" (*(__addr)) \
		: [new] "ir" (__new), [old] "ir" (__old), \
		  [iset_v6] "i" (CPU_FEAT_ISET_V6), \
		  [no_atomic_spurious_fault] "i" (CPU_NO_HWBUG_ATOMIC_SPURIOUS_FAULT) \
		CLOBBERS_PRED2_##mem_model); \
} while (0)

#define NATIVE_ATOMIC_CMPXCHG_DWORD_RETURN(__old, __new, __addr, \
					   __stored_val, __rval, mem_model) \
do { \
	ASM_LENGTH_V5_V6(11, 12) \
	asm NOT_VOLATILE ( \
		BEFORE_ATOMIC("3:", mem_model, no_atomic_spurious_fault) \
		ALTERNATIVE( \
		/* Default version - 10 cycles ld->st delay */ \
			"{nop 6\n" \
			" ldd,0 %[addr], %[rval], mas=0x7}", \
		/* CPU_FEAT_ISET_V6 - 11 cycles ld->st delay */ \
			"{nop 7\n" \
			" ldd,0 %[addr], %[rval], mas=0x7}", \
		%[iset_v6]) \
		"{nop 1\n" \
		" cmpedb %[rval], %[old], %%pred2}\n" \
		"{merged %[rval], %[new], %[stored_val], %%pred2}\n" \
		"{std," mem_model##_ATOMIC_CHANNEL \
			" %[addr], %[stored_val], mas=" mem_model##_ATOMIC_MAS "\n" \
		" ibranch 3b ? %%MLOCK}\n" \
		MB_AFTER_ATOMIC_##mem_model \
		: [stored_val] "=&r" (__stored_val), \
		  [rval] "=&r" (__rval), [addr] "+m" (*(__addr)) \
		: [new] "ir" (__new), [old] "ir" (__old), \
		  [iset_v6] "i" (CPU_FEAT_ISET_V6), \
		  [no_atomic_spurious_fault] "i" (CPU_NO_HWBUG_ATOMIC_SPURIOUS_FAULT) \
		CLOBBERS_PRED2_##mem_model); \
} while (0)

#ifdef CONFIG_HAVE_CMPXCHG_DOUBLE
/*
 * C equivalent:
		if (page->freelist == freelist_old &&
					page->counters == counters_old) {
			page->freelist = freelist_new;
			page->counters = counters_new;
 */
#define NATIVE_ATOMIC_CMPXCHG_DWORD_PAIRS(__addr, __old1, __old2, \
	  __new1, __new2, __rval, mem_model) \
do { \
	__uint128_t __qvalue; \
	ASM_LENGTH_V5_V6(11, 12) \
	asm NOT_VOLATILE ( \
		BEFORE_ATOMIC("3:", mem_model, no_atomic_spurious_fault) \
		ALTERNATIVE( \
		/* Default version - 10 cycles ld->st delay */ \
			"{nop 5\n" \
			" ldq,0 %[addr], %[qvalue], mas=0x5}\n", \
		/* CPU_FEAT_ISET_V6 - 11 cycles ld->st delay */ \
			"{nop 6\n" \
			" ldq,0 %[addr], %[qvalue], mas=0x5}\n", \
		%[iset_v6]) \
		"{cmpedb %[old1], %L[qvalue], %%pred2\n" \
		" cmpedb %[old2], %H[qvalue], %%pred3}\n" \
		"{nop 1\n" \
		" pass	%%pred2, @p0\n" \
		" pass	%%pred3, @p1\n" \
		" landp	@p0, @p1, @p4\n" \
		" pass	@p4, %%pred2}\n" \
		"{addd 0, %[new1], %L[qvalue] ? %%pred2\n" \
		" addd 0, %[new2], %H[qvalue] ? %%pred2\n" \
		" merged 0, 1, %[rval], %%pred2}\n" \
		"{stq," mem_model##_ATOMIC_CHANNEL \
			" %[addr], %[qvalue], mas=" mem_model##_ATOMIC_MAS "\n" \
		" ibranch 3b ? %%MLOCK}\n" \
		MB_AFTER_ATOMIC_##mem_model \
		: [rval] "=&r" (__rval), [addr] "+m" (*(__addr)), \
		  [qvalue] "=&r" (__qvalue) \
		: [new1] "ir" (__new1), [old1] "ir" (__old1),	 \
		  [new2] "ir" (__new2), [old2] "ir" (__old2), \
		  [iset_v6] "i" (CPU_FEAT_ISET_V6), \
		  [no_atomic_spurious_fault] "i" (CPU_NO_HWBUG_ATOMIC_SPURIOUS_FAULT) \
		CLOBBERS_PRED2_3_##mem_model); \
} while (0)
#endif /* CONFIG_HAVE_CMPXCHG_DOUBLE */

#define _fl_c_mode	0x8000	/* do not flush CPU pipeline */
#define _macp		0x4000	/* wait for color protection exceptions */
#define _mem_mod	0x2000	/* watch for modification */
#define _int		0x1000	/* stop the CPU pipeline until interrupt */
#define _mt		0x800
#define _lal		0x400	/* load-after-load modifier for _ld_c */
#define _las		0x200	/* load-after-store modifier for _st_c */
#define _sal		0x100	/* store-after-load modifier for _ld_c */
#define _sas		0x80	/* store-after-store modifier for _st_c */
/* "trap=1" requires special handling, see C1_wait_trap() so don't
 * define it here, as using it in E2K_WAIT() makes no sense. */
#define _ma_c		0x20	/* stop until all memory operations complete */
#define _fl_c		0x10	/* stop until TLB/cache flush operations complete */
#define _ld_c		0x8	/* stop until all load operations complete */
#define _st_c		0x4	/* stop until all store operations complete */
#define _all_e		0x2	/* stop until prev. operations issue all exceptions */
#define _all_c		0x1	/* stop until prev. operations complete */

#if defined CONFIG_CPU_E2S && defined CONFIG_NUMA
# define WORKAROUND_WAIT_HWBUG(num) (((num) & (_st_c | _all_c | _sas)) ? \
						((num) | _ma_c) : (num))
#else
# define WORKAROUND_WAIT_HWBUG(num)	num
#endif

#ifndef __ASSEMBLY__
/* We use a static inline function instead of a macro
 * because otherwise the preprocessed files size will
 * increase tenfold making compile times much worse. */
__attribute__((__always_inline__))
static inline void __E2K_WAIT(int _num)
{
	int unused, num = WORKAROUND_WAIT_HWBUG(_num);

	/* Use "asm volatile" around tricky barriers such as _ma_c, _fl_c, etc */
	if (_num & ~(_st_c | _ld_c | _sas | _sal | _las | _lal | _mt)) {
		__asm_length(0)
		asm volatile ("" ::: "memory");
	}

	/* Header dependency hell, cannot use here:
	 *   cpu_has(CPU_HWBUG_SOFT_WAIT_E8C2)
	 * so just check straight for E8C2 */
	if (IS_ENABLED(CONFIG_CPU_E8C2) && (num & (_sas | _sal))) {
		__asm_length(1)
		asm ("{nop}" ::: "memory");
	}

	/* CPU_NO_HWBUG_SOFT_WAIT: use faster workaround for "lal" barriers */
	if (_num == (_ld_c | _lal) || _num == (_ld_c | _lal | _mt)) {
		instr_cs1_t cs1 = {
			.opc = CS1_OPC_WAIT,
			.param = num
		};
__no_asm_inline(1)
		asm NOT_VOLATILE (ALTERNATIVE(
			/* Default version - add "nop 5" after and a separate
			 * wide instruction before the barrier. */
				"{nop}\n"
				".word 0x00008281\n"
				".word %[cs1]\n",
			/* CPU_NO_HWBUG_SOFT_WAIT version */
				".word 0x00008011\n"
				".word %[cs1]\n"
				".word 0x0\n"
				".word 0x0\n",
			%[facility])
			: "=r" (unused)
			: [cs1] "i" (cs1.word),
			  [facility] "i" (CPU_NO_HWBUG_SOFT_WAIT)
			: "memory");
	} else {
		instr_cs1_t cs1 = {
			.opc = CS1_OPC_WAIT,
			.param = num
		};
		instr_cs1_t cs1_no_soft_barriers = {
			.opc = CS1_OPC_WAIT,
			.param = num & ~(_lal | _las | _sal | _sas)
		};
		/* #79245 - use .word to encode relaxed barriers */
__no_asm_inline(1)
		asm NOT_VOLATILE (ALTERNATIVE(
			/* Default version */
				".word 0x00008001\n"
				".word %[cs1_no_soft_barriers]\n",
			/* CPU_NO_HWBUG_SOFT_WAIT version - use soft barriers */
				".word 0x00008001\n"
				".word %[cs1]\n",
			%[facility])
			: "=r" (unused)
			: [cs1] "i" (cs1.word),
			  [cs1_no_soft_barriers] "i" (cs1_no_soft_barriers.word),
			  [facility] "i" (CPU_NO_HWBUG_SOFT_WAIT)
			: "memory");
	}

	/* Use "asm volatile" around tricky barriers such as _ma_c, _fl_c, etc */
	if (_num & ~(_st_c | _ld_c | _sas | _sal | _las | _lal | _mt)) {
		__asm_length(0)
		asm volatile ("" ::: "memory");
	}
}
#endif

#define E2K_WAIT(num) \
do { \
	__E2K_WAIT(num); \
	if ((num) & (_st_c | _ld_c | _all_c | _ma_c)) \
		NATIVE_HWBUG_AFTER_LD_ACQ(); \
} while (0)

/*
 * IMPORTANT NOTE!!!
 * Do not add 'sas' and 'sal' here, as they are modifiers
 * for st_c/ld_c which make them _less_ restrictive.
 */
#define	E2K_WAIT_OP_ALL_MASK	(_ma_c | _fl_c | _ld_c | _st_c | _all_c | _all_e)

#define	E2K_WAIT_MA		E2K_WAIT(_ma_c)
#define	E2K_WAIT_FLUSH		E2K_WAIT(_fl_c)
#define	E2K_WAIT_LD		E2K_WAIT(_ld_c)
#define	E2K_WAIT_ST		E2K_WAIT(_st_c)
#define	E2K_WAIT_ALL_OP		E2K_WAIT(_all_c)
#define	E2K_WAIT_ALL_EX		E2K_WAIT(_all_e)
#define	E2K_WAIT_ALL		E2K_WAIT(E2K_WAIT_OP_ALL_MASK)
#define	__E2K_WAIT_ALL		__E2K_WAIT(E2K_WAIT_OP_ALL_MASK)

/* Wait for the load to finish before issuing
 * next memory loads/stores. */
#define E2K_RF_WAIT_LOAD(reg) \
do { \
	int unused; \
	__asm_length(1) \
	asm NOT_VOLATILE ("{adds %1, 0, %%empty}" \
			  : "=r" (unused) \
			  : "r" (reg) \
			  : "memory"); \
	NATIVE_HWBUG_AFTER_LD_ACQ(); \
} while (0)

/*
 * Hardware stacks flush rules for e2k:
 *
 * 1) PSP/PCSP/PSHTP/PCSHTP reads wait for the corresponding SPILL/FILL
 * to finish (whatever the reason for SPILL/FILL is - "flushc", "flushr",
 * register file overflow, etc). "rr" must not be in the same wide
 * instruction as "flushc"/"flushr".
 *
 * 2) CWD reads wait for the chain stack SPILL/FILL to finish.
 *
 * 3) On e3m SPILL/FILL were asynchronous and "wait all_e=1" should had
 * been used between SPILL/FILL operations and memory accesses. This is
 * not needed anymore.
 *
 * 4) PSP/PCSP writes wait _only_ for SPILL. So if we do not know whether
 * there can be a FILL going right now then some form of wait must be
 * inserted before the write. Also writing PSHTP/PCSHTP has undefined
 * behavior in instruction set, so using it is not recommended because
 * of compatibility with future processors.
 *
 * 5) "wait ma_c=1" waits for all memory accesses including those issued
 * by SPILL/FILL opertions. It does _not_ wait for SPILL/FILL itself.
 *
 * 6) Because of hardware bug #102582 "flushr" shouldn't be in the first
 * command after "call".
 */

#define NATIVE_FLUSHR \
do { \
	__asm_length(2) \
	asm volatile ("{nop} {flushr}" ::: "memory"); \
} while (0)

#define	NATIVE_FLUSHC \
do { \
	__asm_length(7) \
	asm volatile ("{nop 2} {flushc; nop 3}" ::: "memory"); \
} while (0)
#define native_FLUSHC NATIVE_FLUSHC

#define NATIVE_FLUSHCPU \
do { \
	__asm_length(8) \
	asm volatile ("{nop 2} {flushc; nop 3} {flushr}" ::: "memory"); \
} while (0)

#define NATIVE_FLUSH_ALL_TC() \
do { \
	/* Instruction set recommends using %empty for invtc */ \
	__asm_length(4) \
	asm volatile ("{nop 3; invtc 0x0, %%empty}" ::: "memory"); \
} while (0)

#define	DO_ATOMIC_WRITE_PSR_REG_VALUE(greg_no, psr_off, psr_value, \
					under_upsr_off, under_upsr_bool) \
({ \
	__asm_length(1) \
	asm volatile ( \
		"{\n\t" \
		"  stw %%dg" #greg_no ", [%0], %2\n\t" \
		"  stb %%dg" #greg_no ", [%1], %3\n\t" \
		"}" \
		: \
		: "ri" ((u64)(psr_off)), \
		  "ri" ((u64)(under_upsr_off)), \
		  "r"  ((u32)(psr_value)), \
		  "r"  ((u8)(under_upsr_bool))); \
})
#define	KVM_DO_ATOMIC_WRITE_PSR_REG_VALUE(greg_no, psr_off, psr_value, \
					under_upsr_off, under_upsr_bool) \
		DO_ATOMIC_WRITE_PSR_REG_VALUE(greg_no, psr_off, psr_value, \
					under_upsr_off, under_upsr_bool) \

#define	DO_ATOMIC_WRITE_UPSR_REG_VALUE(greg_no, upsr_off, upsr_value) \
do { \
	__no_asm_inline(5) \
	asm volatile ( \
		ALTERNATIVE_1_ALTINSTR \
		/* CPU_FEAT_ISET_NOT_V7 version */ \
		"{\n\t" \
		"  nop 4\n" \
		"  rws %1, %%upsr\n\t" \
		"  stw %%dg" #greg_no ", [%0], %1\n\t" \
		"}" \
		ALTERNATIVE_2_OLDINSTR \
		/* Default version */ \
		"{\n\t" \
		"  nop 6\n" \
		"  rws %1, %%upsr\n\t" \
		"  stw %%dg" #greg_no ", [%0], %1\n\t" \
		"}" \
		ALTERNATIVE_3_FEATURE(%[cpu_feat_iset_not_v7]) \
		: \
		: "ri" ((u64)(upsr_off)), \
		  "r"  ((u32)(upsr_value)), \
		  [cpu_feat_iset_not_v7] "i" (CPU_FEAT_ISET_NOT_V7)); \
} while (0)
#define	KVM_DO_ATOMIC_WRITE_UPSR_REG_VALUE(greg_no, upsr_off, upsr_value) \
		DO_ATOMIC_WRITE_UPSR_REG_VALUE(greg_no, upsr_off, upsr_value)

#define NATIVE_GET_TCD() \
({ \
	u64 res; \
	__asm_length(7) \
	asm volatile ("{gettc 0x1, %%ctpr1\n" \
		      " nop 5}\n" \
		      "{rrd %%ctpr1, %0}\n" \
		      : "=r" (res) :: "ctpr1" ); \
	res; \
})

/* Add ctpr3 to clobbers to explain to lcc that this
 * GNU asm does a return. */
#define E2K_DONE() \
do { \
	/* #80747: must repeat interrupted barriers */ \
	asm volatile ("{wait st_c=1}\n" \
		      "{nop 2\n" \
		      " mmurw %[zero], %%dam_inv}\n" \
		      "{done}" \
		      : \
		      : [zero] "r" (0ull) \
		      : "ctpr3"); \
	unreachable(); \
} while (0)

/* Add ctpr3 to clobbers to explain to lcc that this
 * GNU asm does a return. */
#define E2K_DONE_RNDPR(_rndpr) \
do { \
	typecheck(e2k_rndpr_t, _rndpr); \
	/* #80747: must repeat interrupted barriers */ \
	asm volatile ("{wait st_c=1\n" \
		      " rwd %[rndpr], %%rndpr}\n" \
		      "{mmurw %[zero], %%dam_inv}\n" \
		      ALTERNATIVE("nop 2", "nop 4", %[iset_v7]) \
		      "{done}" \
		      : \
		      : [zero] "r" (0ull), \
			[rndpr] "ir" ((u64) (AW(_rndpr))), \
			[iset_v7] "i" (CPU_FEAT_ISET_V7) \
		      : "ctpr3"); \
} while (0)

#define NATIVE_RETURN() \
do { \
	asm volatile(	ALTERNATIVE( \
			/* Default version */ \
				"{return %%ctpr3} {ct %%ctpr3}", \
			/* CPU_FEAT_ISET_V7 version */ \
				".push_iset 7\n" \
				"{iret}\n" \
				".pop_iset\n", \
			%[iset_v7]) \
			: \
			: [iset_v7] "i" (CPU_FEAT_ISET_V7) \
			: "ctpr3"); \
	unreachable(); \
} while (0)

#define NATIVE_RETURN_RNDPR(_rndpr) \
do { \
	typecheck(e2k_rndpr_t, _rndpr); \
	asm volatile(	"{return %%ctpr3\n" \
			" rwd %[rndpr], %%rndpr}\n" \
			ALTERNATIVE("nop 4", "nop 5", %[iset_v7]) \
			"{ct %%ctpr3}\n" \
			: \
			: [rndpr] "ir" ((u64) (AW(_rndpr))), \
			  [iset_v7] "i" (CPU_FEAT_ISET_V7) \
			: "ctpr3"); \
	unreachable(); \
} while (0)

#define NATIVE_RETURN_VALUE(rval) \
do { \
	asm volatile(   "{\n" \
			"return %%ctpr3\n" \
			"addd %[r0], 0, %%dr0\n" \
			"addd 0, 0, %%dr1\n" \
			"addd 0, 0, %%dr2\n" \
			"addd 0, 0, %%dr3\n" \
			"addd 0, 0, %%dr4\n" \
			"addd 0, 0, %%dr5\n" \
			"}\n" \
			"{\n" \
			"addd 0, 0, %%dr6\n" \
			"addd 0, 0, %%dr7\n" \
			"ct %%ctpr3\n" \
			"}\n" \
			: \
			: [r0] "ir" (rval) \
			: "ctpr3"); \
	unreachable(); \
} while (0)

#define E2K_SYSCALL_RETURN(rval, _rndpr) \
do { \
	typecheck(e2k_rndpr_t, _rndpr); \
	asm volatile(   "{return %%ctpr3\n" \
			" rwd %[rndpr], %%rndpr\n" \
			" addd %[r0], 0, %%dr0\n" \
			" addd 0, 0, %%dr1\n" \
			" addd 0, 0, %%dr2\n" \
			" addd 0, 0, %%dr3\n" \
			" addd 0, 0, %%dr4\n}\n" \
			"{mmurw %[zero], %%dam_inv}\n" \
			ALTERNATIVE("nop 3", "nop 4", %[iset_v7]) \
			"{addd 0, 0, %%dr5\n" \
			" addd 0, 0, %%dr6\n" \
			" addd 0, 0, %%dr7\n" \
			" ct %%ctpr3}\n" \
			: \
			: [r0] "ir" (rval), [zero] "r" (0ull), \
			  [rndpr] "ir" ((u64) (AW(_rndpr))), \
			  [iset_v7] "i" (CPU_FEAT_ISET_V7) \
			: "ctpr3"); \
	unreachable(); \
} while (0)

#define E2K_EMPTY_CMD(input...) \
do { \
	asm volatile ("{nop}" :: input); \
} while (0)

#define E2K_DUMMY_CLEARWINDOW(input...) \
do { \
	/* This is used as substitute for macros in ttable_asm.h \
	 * in two-stage compilation of arch/e2k/kernel/ttable.c \
	 * This means that `pragma asm(length)` must not be set \
	 * (because arch/e2k/kernel/mkclearwindow does not set it).  */ \
	asm volatile ("{nop}" :: input); \
	unreachable(); \
} while (0)

#define E2K_PSYSCALL_RETURN(r0, r1, r2, r3, tag2, tag3, _rndpr) \
do { \
	typecheck(e2k_rndpr_t, _rndpr); \
	asm volatile (	"{return %%ctpr3\n" \
			" rwd %[rndpr], %%rndpr\n" \
			" puttagd %[_r2], %[_tag2], %%dr2\n" \
			" puttagd %[_r3], %[_tag3], %%dr3\n" \
			" addd %[_r0], 0, %%dr0\n" \
			" addd %[_r1], 0, %%dr1\n" \
			" addd 0, 0, %%dr4}\n" \
			"{mmurw %[zero], %%dam_inv\n" \
			" addd 0, 0, %%dr5\n" \
			" addd 0, 0, %%dr6\n" \
			" addd 0, 0, %%dr7\n" \
			" addd 0, 0, %%dr8\n" \
			" addd 0, 0, %%dr9}\n" \
			ALTERNATIVE("nop 3", "nop 4", %[iset_v7]) \
			"{addd 0, 0, %%dr10\n" \
			" addd 0, 0, %%dr11\n" \
			" addd 0, 0, %%dr12\n" \
			" addd 0, 0, %%dr13\n" \
			" addd 0, 0, %%dr14\n" \
			" addd 0, 0, %%dr15\n" \
			" ct %%ctpr3}\n" \
			:: [_r0] "ir" (r0), [_r1] "ir" (r1), \
			   [_r2] "ir" (r2), [_r3] "ir" (r3), \
			   [_tag2] "ir" (tag2), [_tag3] "ir" (tag3), \
			   [zero] "r" (0ull), \
			   [rndpr] "ir" ((u64) (AW(_rndpr))), \
			   [iset_v7] "i" (CPU_FEAT_ISET_V7) \
			: "ctpr3"); \
	unreachable(); \
} while (0)

#ifndef __ASSEMBLY__

# ifdef __SANITIZE_ADDRESS__
#  define ASM_NO_SANITIZE_OR_NO_INLINE _Pragma("no_asm_inline")
# else
#  define ASM_NO_SANITIZE_OR_NO_INLINE
# endif

static __always_inline u8 __user_ldrd_b(const u8 __user *addr)
{
	ldst_rec_op_t opc = { .prot = 1, .fmt = LDST_BYTE_FMT };
	u8 ret;

	ASM_NO_SANITIZE_OR_NO_INLINE
	asm ("ldrd [ %[addr] + %[opc] ], %[ret]"
		: [ret] "=r" (ret)
		: [addr] "m" (*(addr)),
		  [opc] "ir" (opc.word));

	return ret;
}

static __always_inline u16 __user_ldrd_h(const u16 __user *addr)
{
	ldst_rec_op_t opc = { .prot = 1, .fmt = LDST_HALF_FMT };
	u16 ret;

	ASM_NO_SANITIZE_OR_NO_INLINE
	asm ("ldrd [ %[addr] + %[opc] ], %[ret]"
		: [ret] "=r" (ret)
		: [addr] "m" (*(addr)),
		  [opc] "ir" (opc.word));

	return ret;
}

static __always_inline u32 __user_ldrd_w(const u32 __user *addr)
{
	ldst_rec_op_t opc = { .prot = 1, .fmt = LDST_WORD_FMT };
	u32 ret;

	ASM_NO_SANITIZE_OR_NO_INLINE
	asm ("ldrd [ %[addr] + %[opc] ], %[ret]"
		: [ret] "=r" (ret)
		: [addr] "m" (*(addr)),
		  [opc] "ir" (opc.word));

	return ret;
}

static __always_inline u64 __user_ldrd_d(const u64 __user *addr)
{
	ldst_rec_op_t opc = { .prot = 1, .fmt = LDST_DWORD_FMT };
	u64 ret;

	ASM_NO_SANITIZE_OR_NO_INLINE
	asm ("ldrd [ %[addr] + %[opc] ], %[ret]"
		: [ret] "=r" (ret)
		: [addr] "m" (*(addr)),
		  [opc] "ir" (opc.word));

	return ret;
}

static __always_inline u64 __user_ldrd_d_opc(const u64 __user *addr,
		ldst_rec_op_t opc)
{
	u64 ret;

	ASM_NO_SANITIZE_OR_NO_INLINE
	asm ("ldrd [ %[addr] + %[opc] ], %[ret]"
		: [ret] "=r" (ret)
		: [addr] "m" (*(addr)),
		  [opc] "ir" (opc.word));

	return ret;
}

static __always_inline void __user_strd_b(u8 value, u8 __user *addr)
{
	ldst_rec_op_t opc = { .prot = 1, .fmt = LDST_BYTE_FMT };

	ASM_NO_SANITIZE_OR_NO_INLINE
	asm ("strd [ %[addr] + %[opc] ], %[value]"
		: [addr] "=m" (*(addr))
		: [value] "r" (value),
		  [opc] "ir" (opc.word));
}

static __always_inline void __user_strd_h(u16 value, u16 __user *addr)
{
	ldst_rec_op_t opc = { .prot = 1, .fmt = LDST_HALF_FMT };

	ASM_NO_SANITIZE_OR_NO_INLINE
	asm ("strd [ %[addr] + %[opc] ], %[value]"
		: [addr] "=m" (*(addr))
		: [value] "r" (value),
		  [opc] "ir" (opc.word));
}

static __always_inline void __user_strd_w(u32 value, u32 __user *addr)
{
	ldst_rec_op_t opc = { .prot = 1, .fmt = LDST_WORD_FMT };

	ASM_NO_SANITIZE_OR_NO_INLINE
	asm ("strd [ %[addr] + %[opc] ], %[value]"
		: [addr] "=m" (*(addr))
		: [value] "r" (value),
		  [opc] "ir" (opc.word));
}

static __always_inline void __user_strd_d(u64 value, u64 __user *addr)
{
	ldst_rec_op_t opc = { .prot = 1, .fmt = LDST_DWORD_FMT };

	ASM_NO_SANITIZE_OR_NO_INLINE
	asm ("strd [ %[addr] + %[opc] ], %[value]"
		: [addr] "=m" (*(addr))
		: [value] "r" (value),
		  [opc] "ir" (opc.word));
}

static __always_inline void __user_strd_d_opc(u64 value, u64 __user *addr,
		ldst_rec_op_t opc)
{
	ASM_NO_SANITIZE_OR_NO_INLINE
	asm ("strd [ %[addr] + %[opc] ], %[value]"
		: [addr] "=m" (*(addr))
		: [value] "r" (value),
		  [opc] "ir" (opc.word));
}

extern void __user_ldst_bad(void) __attribute__((noreturn));
#endif

/*
 * Protected mode has PTE.int_pr feature: any non-protected access
 * into a page that has 'int_pr' bit set in page tables will cause
 * an exception.  To work with user space of such applications we
 * mark kernel accesses to user as "protected" by using ldrd/strd.
 *
 * For CONFIG_KVM_GUEST_KERNEL case we don't enable this protection
 * since fully paravirtualized guest would get a prohibitive
 * performance hit from it.
 */
#ifdef CONFIG_KVM_GUEST_KERNEL
# define USER_LD(x, ptr) do { (x) = *(ptr); } while (0)
# define USER_ST(x, ptr) do { *(ptr) = (x); } while (0)
# define GET_USER_ASM_LD(addr, opc, x, fmt) __stringify(ld##fmt[addr + 0], x)
# define PUT_USER_ASM_ST(addr, opc, x, fmt) __stringify(st##fmt[addr + 0], x)
#else
# define GET_USER_ASM_LD(addr, opc, x, fmt) __stringify(ldrd,0 [addr + opc], x)
# define PUT_USER_ASM_ST(addr, opc, x, fmt) __stringify(strd [addr + opc], x)

# define USER_LD(x, ptr) \
do { \
	const __typeof__(*(ptr)) __user *__u_ld_addr = (ptr); \
	__chk_user_ptr(ptr); \
	switch (sizeof(*__u_ld_addr)) { \
	case 1: \
		(x) = __user_ldrd_b((const u8 __user *) (__u_ld_addr)); \
		break; \
	case 2: \
		(x) = __user_ldrd_h((const u16 __user *) (__u_ld_addr)); \
		break; \
	case 4: \
		(x) = __user_ldrd_w((const u32 __user *) (__u_ld_addr)); \
		break; \
	case 8: \
		(x) = __user_ldrd_d((const u64 __user *) (__u_ld_addr)); \
		break; \
	default: \
		__user_ldst_bad(); \
		break; \
	} \
} while (0)

/* See USER_LD() */
# define USER_ST(x, ptr) \
do { \
	__typeof__(*(ptr)) __user *__u_st_addr = (ptr); \
	__chk_user_ptr(ptr); \
	switch (sizeof(*__u_st_addr)) { \
	case 1: \
		__user_strd_b((x),  (u8 __user *) (__u_st_addr)); \
		break; \
	case 2: \
		__user_strd_h((x),  (u16 __user *) (__u_st_addr)); \
		break; \
	case 4: \
		__user_strd_w((x),  (u32 __user *) (__u_st_addr)); \
		break; \
	case 8: \
		__user_strd_d((x),  (u64 __user *) (__u_st_addr)); \
		break; \
	default: \
		__user_ldst_bad(); \
		break; \
	} \
} while (0)
#endif

/* See also: USER_LD() */
#define GET_USER_ASM(_x, _addr, _opc, __ret_gu, _fmt) \
do { \
	e2k_madmr_t madmr = cpu_has(CPU_FEAT_MADM) ? read_MADMR_reg() : \
						     (e2k_madmr_t) { .word = 0 }; \
	ASM_LENGTH_V5_V6(3, 5) \
	asm (ALTERNATIVE_1_ALTINSTR \
	     /* CPU_FEAT_ISET_V6 version */ \
		     "{" GET_USER_ASM_LD(%[addr], %[opc], %[x], _fmt) "\n" \
		     " cmpandesb,1 %[madmr], 0x3, %%pred0\n" \
		     " adds,2 0, 0, %[ret]\n" \
		     " nop 3}\n" \
		     "{adds,sm 0, %[x], %%empty ? ~ %%pred0}\n" \
	     ALTERNATIVE_2_OLDINSTR \
	     /* Default version */ \
		     "{" GET_USER_ASM_LD(%[addr], %[opc], %[x], _fmt) "\n" \
		     " cmpandesb,1 %[madmr], 0x3, %%pred0\n" \
		     " adds,2 0, 0, %[ret]\n" \
		     " nop 1}\n" \
		     /* Careful, both alternatives must have the same offset */ \
		     NONTARGET_LABEL("1") "\n" \
		     /* Keep this instruction inside alternatives to make sure \
		      * there are no NOPs between it and the load above */ \
		     "{adds,sm 0, %[x], %%empty ? ~ %%pred0}\n" \
	     ALTERNATIVE_3_FEATURE(%[facility]) \
	     "2:\n" \
	     ".section .fixup,\"ax\"\n" \
	     "3:{adds 0, %[efault], %[ret]\n" \
	     "   addd 0, 0, %[x]\n" \
	     "   ibranch 2b}\n" \
	     ".previous\n" \
	     ".section __ex_table,\"a\"\n" \
	     ".dword 1b, 3b\n" \
	     ".previous\n" \
	     : [ret] "=r" (__ret_gu), [x] "=r" (_x) \
	     : [addr] "m" (*(_addr)), [efault] "i" (-EFAULT), \
	       [opc] "ir" (_opc), [madmr] "ir" (AW(madmr)), \
	       [facility] "i" (CPU_FEAT_ISET_V6) \
	     : "pred0"); \
} while (0)

#define ASM_USER_STRD_16(_addr, _val, _tag, _opc) \
({ \
	int _ret = 0; \
	asm (	"puttagd %[val], %[tag], %[val]\n" \
		"{strd [ %[addr] + %[opc_lo] ], %[val]\n" \
		"strd [ %[addr] + %[opc_hi] ], %[val]\n}" \
		NONTARGET_LABEL("1") "\n" \
		"2:\n" \
		".section .fixup,\"ax\"\n" \
		"3:{adds 0, %[efault], %[ret]\n" \
		"   ibranch 2b}\n" \
		".previous\n" \
		".section __ex_table,\"a\"\n" \
		".dword 1b, 3b\n" \
		".previous\n" \
		: [addr] "=m" (*(u64 __user *) (_addr)), \
		  [ret] "+r" (_ret) \
		: [val] "r" (_val), \
		  [tag] "ir" (_tag), \
		  [opc_lo] "i" (_opc), \
		  [opc_hi] "i" (_opc | 8), \
		  [efault] "i" (-EFAULT)); \
	_ret; \
})

/* See also: USER_LD() */
#define PUT_USER_ASM(_x, ptr, _opc, _retval, _fmt) \
do { \
	__no_asm_inline(1) \
	asm ("{" PUT_USER_ASM_ST(%[addr], %[opc], %[x], _fmt) "\n" \
	     "   adds 0, 0, %[ret]}\n" \
	     NONTARGET_LABEL("1") "\n" \
	     "2:\n" \
	     ".section .fixup,\"ax\"\n" \
	     "3:{adds 0, %[efault], %[ret]\n" \
	     "   ibranch 2b}\n" \
	     ".previous\n" \
	     ".section __ex_table,\"a\"\n" \
	     ".dword 1b, 3b\n" \
	     ".previous\n" \
	     : [ret] "=r" (_retval), [addr] "=m" (*ptr) \
	     : [x] "r" (_x), [efault] "i" (-EFAULT), \
	       [opc] "ir" (_opc)); \
} while (0)

#define NATIVE_GET_USER_VAL_AND_TAGW(_val, _tag, _addr, __ret_gu) \
do { \
	ldst_rec_op_t __u_ld_opc = { \
		.fmt = LDST_WORD_FMT, \
		.mas = MAS_FILL_OPERATION, \
		.prot = 1 \
	}; \
	BUILD_BUG_ON(sizeof(_tag) > 4); \
	ASM_LENGTH_V5_V6(5, 6) \
	asm ( \
	     ALTERNATIVE("" /* Default version */, \
			 "{nop 3}\n" /* CPU_HWBUG_TAGGED_LDW version */, \
			 %[hwbug_tagged_ldw]) \
	     ALTERNATIVE( \
	     /* Default version */ \
		     "{ldrd [ %[addr] + %[opc] ], %[val]\n" \
		     " adds 0, 0, %[ret]\n" \
		     " nop 2}\n" \
		     /* Careful, both alternatives must have the same offset */ \
		     NONTARGET_LABEL("1") "\n" \
		     "{gettagd %[val], %[tag]}\n" \
		     "{puttagd %[val], 0, %[val]}\n", \
	     /* CPU_FEAT_ISET_V6 version */ \
		     "{ldrd [ %[addr] + %[opc] ], %[val]\n" \
		     " adds 0, 0, %[ret]\n" \
		     " nop 4}\n" \
		     "{gettagd %[val], %[tag]\n" \
		     " puttagd %[val], 0, %[val]}\n", \
	     %[iset_v6]) \
	     "2:\n" \
	     ".section .fixup,\"ax\"\n" \
	     "3:{adds 0, %[efault], %[ret]\n" \
	     "   addd 0, 0, %[val]\n" \
	     "   adds 0, 0, %[tag]\n" \
	     "   ibranch 2b}\n" \
	     ".previous\n" \
	     ".section __ex_table,\"a\"\n" \
	     ".dword 1b, 3b\n" \
	     ".previous\n" \
	     : [ret] "=&r" (__ret_gu), [val] "=&r" (_val), [tag] "=&r" (_tag) \
	     : [addr] "m" (*((u64 __user *) (_addr))), \
	       [efault] "i" (-EFAULT), \
	       [iset_v6] "i" (CPU_FEAT_ISET_V6), \
	       [hwbug_tagged_ldw] "i" (CPU_HWBUG_TAGGED_LDW), \
	       [opc] "i" (AW(__u_ld_opc))); \
} while (0)

#define NATIVE_GET_USER_VAL_AND_TAGD(_val, _tag, _addr, __ret_gu) \
do { \
	ldst_rec_op_t __u_ld_opc = { \
		.fmt = LDST_DWORD_FMT, \
		.mas = MAS_FILL_OPERATION, \
		.prot = 1 \
	}; \
	BUILD_BUG_ON(sizeof(_tag) > 4); \
	ASM_LENGTH_V5_V6(5, 6) \
	asm ( \
	     ALTERNATIVE( \
	     /* Default version */ \
		     "{ldrd [ %[addr] + %[opc] ], %[val]\n" \
		     " adds 0, 0, %[ret]\n" \
		     " nop 2}\n" \
		     /* Careful, both alternatives must have the same offset */ \
		     NONTARGET_LABEL("1") "\n" \
		     "{gettagd %[val], %[tag]}\n" \
		     "{puttagd %[val], 0, %[val]}\n", \
	     /* CPU_FEAT_ISET_V6 version */ \
		     "{ldrd [ %[addr] + %[opc] ], %[val]\n" \
		     " adds 0, 0, %[ret]\n" \
		     " nop 4}\n" \
		     "{gettagd %[val], %[tag]\n" \
		     " puttagd %[val], 0, %[val]}\n", \
	     %[facility]) \
	     "2:\n" \
	     ".section .fixup,\"ax\"\n" \
	     "3:{adds 0, %[efault], %[ret]\n" \
	     "   addd 0, 0, %[val]\n" \
	     "   adds 0, 0, %[tag]\n" \
	     "   ibranch 2b}\n" \
	     ".previous\n" \
	     ".section __ex_table,\"a\"\n" \
	     ".dword 1b, 3b\n" \
	     ".previous\n" \
	     : [ret] "=&r" (__ret_gu), [val] "=&r" (_val), [tag] "=&r" (_tag) \
	     : [addr] "m" (*((const u64 __user *) (_addr))), [efault] "i" (-EFAULT), \
	       [facility] "i" (CPU_FEAT_ISET_V6), \
	       [opc] "i" (AW(__u_ld_opc))); \
} while (0)

#define NATIVE_GET_USER_VAL_AND_TAGQ(_val_lo, _val_hi, _tag, _addr, __ret_gu, _offset) \
do { \
	const u64 __user *__guvt_addr = (const u64 __user *) (_addr); \
	ldst_rec_op_t __u_ld_opc = { \
		.fmt = LDST_QWORD_FMT, \
		.mas = MAS_FILL_OPERATION, \
		.prot = 1 \
	}; \
	if (!WARN_ON_ONCE(!IS_ALIGNED((unsigned long) __guvt_addr, 16))) { \
		u32 __tmp_tag_lo, __tmp_tag_hi; \
		e2k_qreg_t __qvalue; \
\
		ASM_LENGTH_V5_V6(5, 7) \
		asm (ALTERNATIVE( \
		     /* Default version */ \
			"{ldrd,0 [ %[addr] + %[opc_lo] ], %L[qvalue]\n" \
			" ldrd,3 [ %[addr] + %[opc_hi] ], %H[qvalue]\n" \
			" adds,1 0, 0, %[ret]\n" \
			" nop 2}\n" \
			/* Careful, both alternatives must have the same offset */ \
			NONTARGET_LABEL("1") "\n", \
		     /* CPU_FEAT_ISET_V6 version */ \
			"{ldrd,0 [ %[addr] + %[opc_lo] ], %L[qvalue]\n" \
			" ldrd,3 [ %[addr] + %[opc_hi] ], %H[qvalue]\n" \
			" adds,1 0, 0, %[ret]\n" \
			" nop 4}\n", \
		     %[facility]) \
		     "{gettagd,2 %L[qvalue], %[tag_lo]\n" \
		     " gettagd,5 %H[qvalue], %[tag_hi]}\n" \
		     "{puttagd,2 %L[qvalue], 0, %L[qvalue]\n" \
		     " puttagd,5 %H[qvalue], 0, %H[qvalue]}\n" \
		     "2:\n" \
		     ".section .fixup,\"ax\"\n" \
		     "3:{adds 0, %[efault], %[ret]\n" \
		     "   adds 0, 0, %[tag_lo]\n" \
		     "   adds 0, 0, %[tag_hi]\n" \
		     "   addd 0, 0, %L[qvalue]\n" \
		     "   addd 0, 0, %H[qvalue]\n" \
		     "   ibranch 2b}\n" \
		     ".previous\n" \
		     ".section __ex_table,\"a\"\n" \
		     ".dword 1b, 3b\n" \
		     ".previous\n" \
		     : [ret] "=&r" (__ret_gu), \
		       [qvalue] "=&r" (__qvalue), \
		       [tag_lo] "=&r" (__tmp_tag_lo), [tag_hi] "=&r" (__tmp_tag_hi) \
		     : [addr] "m" (*(const u64 __user *) __guvt_addr), \
		       [addr_hi] "m" (*(const u64 __user *) \
				((const void __user *) __guvt_addr + (_offset))), \
		       [efault] "i" (-EFAULT), [facility] "i" (CPU_FEAT_ISET_V6), \
		       [opc_lo] "i" (AW(__u_ld_opc)), \
		       [opc_hi] "ir" (AW(__u_ld_opc) | (_offset))); \
 \
		(_tag) = __tmp_tag_lo | (__tmp_tag_hi << 4); \
		(_val_lo) = __qvalue.lo; \
		(_val_hi) = __qvalue.hi; \
	}  else { \
		(_tag) = (typeof(_tag)) 0; \
		(_val_lo) = (typeof(_val_lo)) 0; \
		(_val_hi) = (typeof(_val_hi)) 0; \
		(__ret_gu) = -EFAULT; \
	} \
} while (0)

#define NATIVE_PUT_USER_VAL_AND_TAGD(_val, _tag, _addr, _ret) \
do { \
	ldst_rec_op_t __u_st_opc = { .fmt = LDST_DWORD_FMT, .prot = 1 }; \
	u64 __npu_tmp; \
	__no_asm_inline(2) \
	asm ("{puttagd %[val], %[tag], %[tmp]\n" \
	     " adds 0, 0, %[ret]}\n" \
	     "{strd [ %[addr] + %[opc] ], %[tmp]}\n" \
	     NONTARGET_LABEL("1") "\n" \
	     "2:\n" \
	     ".section .fixup,\"ax\"\n" \
	     "3:{adds 0, %[efault], %[ret]\n" \
	     "   ibranch 2b}\n" \
	     ".previous\n" \
	     ".section __ex_table,\"a\"\n" \
	     ".dword 1b, 3b\n" \
	     ".previous\n" \
	     : [ret] "=&r" (_ret), [addr] "=m" (*(u64 __user *) (_addr)), \
	       [tmp] "=&r" (__npu_tmp) \
	     : [val] "ir" (_val), [tag] "ir" (_tag), \
	       [efault] "i" (-EFAULT), \
	       [opc] "i" (AW(__u_st_opc))); \
} while (0)

#define NATIVE_PUT_USER_VAL_AND_TAGQ(_val_lo, _val_hi, _tag, _addr, _ret, _offset) \
do { \
	u64 __user *__puvt_addr = (u64 __user *) (_addr); \
	ldst_rec_op_t __u_st_opc = { .fmt = LDST_QWORD_FMT, .prot = 1 }; \
	u32 __npu_tmp_tag = (_tag); \
	if (!WARN_ON_ONCE(!IS_ALIGNED((unsigned long) __puvt_addr, 16))) { \
		e2k_qreg_t __qvalue; \
		__no_asm_inline(2) \
		asm ("{puttagd,2 %[val_lo], %[tag_lo], %L[qvalue]\n" \
		     " puttagd,5 %[val_hi], %[tag_hi], %H[qvalue]\n" \
		     " adds,1 0, 0, %[ret]}\n" \
		     "{strd,2 [ %[addr] + %[opc_lo] ], %L[qvalue]\n" \
		     " strd,5 [ %[addr] + %[opc_hi] ], %H[qvalue]}\n" \
		     NONTARGET_LABEL("1") "\n" \
		     "2:\n" \
		     ".section .fixup,\"ax\"\n" \
		     "3:{adds 0, %[efault], %[ret]\n" \
		     "   ibranch 2b}\n" \
		     ".previous\n" \
		     ".section __ex_table,\"a\"\n" \
		     ".dword 1b, 3b\n" \
		     ".previous\n" \
		     : [ret] "=&r" (_ret), [addr] "=m" (*(u64 __user *) __puvt_addr), \
		       [addr_hi] "=m" (*(u64 __user *) ((void __user *) __puvt_addr + (_offset))), \
		       [qvalue] "=&r" (__qvalue) \
		     : [val_lo] "ir" (_val_lo), [val_hi] "ir" (_val_hi), \
		       [tag_lo] "ir" (__npu_tmp_tag), [tag_hi] "ir" (__npu_tmp_tag >> 4), \
		       [efault] "i" (-EFAULT), \
		       [opc_lo] "i" (AW(__u_st_opc)), \
		       [opc_hi] "ir" (AW(__u_st_opc) | (_offset))); \
	} else { \
		(_ret) = -EFAULT; \
	} \
} while (0)

#define USER_ATOMIC_FETCH_OP(__val, __addr, __rval, __tmp, __size, size_letter, __fmt, \
		op, use_descriptor, mem_model, _ret) \
do { \
	if (cpu_has(CPU_FEAT_ATOMIC_LDRD)) { \
		int uaf_fmt = (__fmt); \
		ldst_rec_op_t uaf_opc_ld = (ldst_rec_op_t) { \
			.fmt = uaf_fmt, \
			.mas = _MAS_MODE_LOAD_OP_WAIT, \
			.prot = 1, \
		}; \
		ldst_rec_op_t uaf_opc_st = (ldst_rec_op_t) { \
			.fmt = uaf_fmt, \
			.mas = mem_model##_ATOMIC_MAS_VALUE, \
			.prot = 1, \
		}; \
		__asm_length(12) \
		asm NOT_VOLATILE ( \
			BEFORE_ATOMIC("1:", mem_model, no_atomic_spurious_fault) \
			/* iset>=v6: 11 cycles ld->st delay */ \
			"{nop 7\n" \
			" adds,1 0, 0, %[ret]\n" \
			" ldrd,0 [ %[addr] + %[opc_ld] ], %[rval]}\n" \
			NONTARGET_LABEL("2") "\n" \
			"{nop 2\n" \
			op " %[rval], %[val], %[tmp]}\n" \
			"{strd," mem_model##_ATOMIC_CHANNEL " [ %[addr] + %[opc_st] ], %[tmp]\n" \
			" ibranch 1b ? %%MLOCK}\n" \
			"3:\n" \
			".section .fixup,\"ax\"\n" \
			"4:{adds 0, %[efault], %[ret]\n" \
			"   addd 0, 0, %[rval]\n" \
			"   ibranch 3b}\n" \
			".previous\n" \
			".section __ex_table,\"a\"\n" \
			".dword 1b, 4b\n" \
			".dword 2b, 4b\n" \
			".previous\n" \
			MB_AFTER_ATOMIC_##mem_model \
			: [ret] "=&r" (_ret), [tmp] "=&r" (__tmp), \
			  [addr] "+m" (*(__addr)), [rval] "=&r" (__rval) \
			: [val] "ir" (__val), [efault] "i" (-EFAULT), \
			  [opc_ld] "ir" (uaf_opc_ld.word), \
			  [opc_st] "ir" (uaf_opc_st.word), \
			  [no_atomic_spurious_fault] "i" (CPU_NO_HWBUG_ATOMIC_SPURIOUS_FAULT) \
			CLOBBERS_##mem_model); \
	} else if (!(use_descriptor)) { \
		__asm_length(11) \
		asm NOT_VOLATILE ( \
			BEFORE_ATOMIC("1:", mem_model, no_atomic_spurious_fault) \
			/* iset<v6: 10 cycles ld->st delay */ \
			"{nop 6\n" \
			" adds,1 0, 0, %[ret]\n" \
			" ld" #size_letter ",0 %[addr], %[rval], mas=0x7}\n" \
			NONTARGET_LABEL("2") "\n" \
			"{nop 2\n" \
			op " %[rval], %[val], %[tmp]}\n" \
			"{st" #size_letter "," mem_model##_ATOMIC_CHANNEL \
				"%[addr], %[tmp], mas=" mem_model##_ATOMIC_MAS "\n" \
			" ibranch 1b ? %%MLOCK}\n" \
			"3:\n" \
			".section .fixup,\"ax\"\n" \
			"4:{adds 0, %[efault], %[ret]\n" \
			"   addd 0, 0, %[rval]\n" \
			"   ibranch 3b}\n" \
			".previous\n" \
			".section __ex_table,\"a\"\n" \
			".dword 1b, 4b\n" \
			".dword 2b, 4b\n" \
			".previous\n" \
			MB_AFTER_ATOMIC_##mem_model \
			: [ret] "=&r" (_ret), [tmp] "=&r" (__tmp), \
			  [addr] "+m" (*(__addr)), [rval] "=&r" (__rval) \
			: [val] "ir" (__val), [efault] "i" (-EFAULT), \
			  [no_atomic_spurious_fault] "i" (CPU_NO_HWBUG_ATOMIC_SPURIOUS_FAULT) \
			CLOBBERS_##mem_model); \
	} else { \
		e2k_ap_t uaf_descriptor = MAKE_AP((__addr), (__size)); \
		__asm_length(12) \
		asm NOT_VOLATILE ( \
			"{puttagd,2 %L[descriptor], %[ap_lo_etag], %L[descriptor]\n" \
			" puttagd,5 %H[descriptor], %[ap_hi_etag], %H[descriptor]}\n" \
			BEFORE_ATOMIC("1:", mem_model, no_atomic_spurious_fault) \
			/* iset<v6: 10 cycles ld->st delay */ \
			"{nop 6\n" \
			" adds,1 0, 0, %[ret]\n" \
			" ldap" #size_letter ",0 %[descriptor], %[rval], mas=0x7}\n" \
			NONTARGET_LABEL("2") "\n" \
			"{nop 2\n" \
			op " %[rval], %[val], %[tmp]}\n" \
			"{stap" #size_letter "," mem_model##_ATOMIC_CHANNEL \
				"%[descriptor], %[tmp], mas=" mem_model##_ATOMIC_MAS "\n" \
			" ibranch 1b ? %%MLOCK}\n" \
			"3:\n" \
			".section .fixup,\"ax\"\n" \
			"4:{adds 0, %[efault], %[ret]\n" \
			"   addd 0, 0, %[rval]\n" \
			"   ibranch 3b}\n" \
			".previous\n" \
			".section __ex_table,\"a\"\n" \
			".dword 1b, 4b\n" \
			".dword 2b, 4b\n" \
			".previous\n" \
			MB_AFTER_ATOMIC_##mem_model \
			: [ret] "=&r" (_ret), [tmp] "=&r" (__tmp), \
			  [addr] "+m" (*(__addr)), [rval] "=&r" (__rval), \
			  [descriptor] "+r" (uaf_descriptor) \
			: [val] "ir" (__val), [efault] "i" (-EFAULT), \
			  [ap_lo_etag] "ir" (E2K_AP_LO_ETAG), [ap_hi_etag] "ir" (E2K_AP_HI_ETAG), \
			  [no_atomic_spurious_fault] "i" (CPU_NO_HWBUG_ATOMIC_SPURIOUS_FAULT) \
			CLOBBERS_##mem_model); \
	} \
} while (0)

#define USER_ATOMIC_CMPXCHG_WORD_RETURN(__old, __new, __addr, __tmp, \
		__oldval, use_descriptor, mem_model, __ret) \
do { \
	if (cpu_has(CPU_FEAT_ATOMIC_LDRD)) { \
		ldst_rec_op_t uac_opc_ld = (ldst_rec_op_t) { \
			.fmt = LDST_WORD_FMT, \
			.mas = _MAS_MODE_LOAD_OP_WAIT, \
			.prot = 1, \
		}; \
		ldst_rec_op_t uac_opc_st = (ldst_rec_op_t) { \
			.fmt = LDST_WORD_FMT, \
			.mas = mem_model##_ATOMIC_MAS_VALUE, \
			.prot = 1, \
		}; \
		__asm_length(12) \
		asm NOT_VOLATILE ( \
			BEFORE_ATOMIC("1:", mem_model, no_atomic_spurious_fault) \
			/* iset>=v6: 11 cycles ld->st delay */ \
			"{nop 7\n" \
			" adds,1 0, 0, %[ret]\n" \
			" ldrd,0 [ %[addr] + %[opc_ld] ], %[oldval]}\n" \
			NONTARGET_LABEL("2") "\n" \
			"{nop 1\n" \
			" cmpesb %[oldval], %[old], %%pred2}\n" \
			"{merges %[oldval], %[new], %[tmp], %%pred2}\n" \
			"{strd," mem_model##_ATOMIC_CHANNEL " [ %[addr] + %[opc_st] ], %[tmp]\n" \
			" ibranch 1b ? %%MLOCK}\n" \
			"3:\n" \
			".section .fixup,\"ax\"\n" \
			"4:{adds 0, %[efault], %[ret]\n" \
			"   addd 0, 0, %[oldval]\n" \
			"   ibranch 3b}\n" \
			".previous\n" \
			".section __ex_table,\"a\"\n" \
			".dword 1b, 4b\n" \
			".dword 2b, 4b\n" \
			".previous\n" \
			MB_AFTER_ATOMIC_##mem_model \
			: [ret] "=&r" (__ret), [tmp] "=&r" (__tmp), \
			  [oldval] "=&r" (__oldval), [addr] "+m" (*(__addr)) \
			: [new] "ir" (__new), [old] "ir" (__old), [efault] "i" (-EFAULT), \
			  [opc_ld] "ir" (uac_opc_ld.word), \
			  [opc_st] "ir" (uac_opc_st.word), \
			  [no_atomic_spurious_fault] "i" (CPU_NO_HWBUG_ATOMIC_SPURIOUS_FAULT) \
			CLOBBERS_PRED2_##mem_model); \
	} else if (!(use_descriptor)) { \
		__asm_length(11) \
		asm NOT_VOLATILE ( \
			BEFORE_ATOMIC("1:", mem_model, no_atomic_spurious_fault) \
			/* iset<v6: 10 cycles ld->st delay */ \
			"{nop 6\n" \
			" adds,1 0, 0, %[ret]\n" \
			" ldw,0 %[addr], %[oldval], mas=0x7}\n" \
			NONTARGET_LABEL("2") "\n" \
			"{nop 1\n" \
			" cmpesb %[oldval], %[old], %%pred2}\n" \
			"{merges %[oldval], %[new], %[tmp], %%pred2}\n" \
			"{stw," mem_model##_ATOMIC_CHANNEL \
				" %[addr], %[tmp], mas=" mem_model##_ATOMIC_MAS "\n" \
			" ibranch 1b ? %%MLOCK}\n" \
			"3:\n" \
			".section .fixup,\"ax\"\n" \
			"4:{adds 0, %[efault], %[ret]\n" \
			"   addd 0, 0, %[oldval]\n" \
			"   ibranch 3b}\n" \
			".previous\n" \
			".section __ex_table,\"a\"\n" \
			".dword 1b, 4b\n" \
			".dword 2b, 4b\n" \
			".previous\n" \
			MB_AFTER_ATOMIC_##mem_model \
			: [ret] "=&r" (__ret), [tmp] "=&r" (__tmp), \
			  [oldval] "=&r" (__oldval), [addr] "+m" (*(__addr)) \
			: [new] "ir" (__new), [old] "ir" (__old), [efault] "i" (-EFAULT), \
			  [no_atomic_spurious_fault] "i" (CPU_NO_HWBUG_ATOMIC_SPURIOUS_FAULT) \
			CLOBBERS_PRED2_##mem_model); \
	} else { \
		e2k_ap_t uac_descriptor = MAKE_AP((__addr), 4); \
		__asm_length(12) \
		asm NOT_VOLATILE ( \
			"{puttagd,2 %L[descriptor], %[ap_lo_etag], %L[descriptor]\n" \
			" puttagd,5 %H[descriptor], %[ap_hi_etag], %H[descriptor]}\n" \
			BEFORE_ATOMIC("1:", mem_model, no_atomic_spurious_fault) \
			/* iset<v6: 10 cycles ld->st delay */ \
			"{nop 6\n" \
			" adds,1 0, 0, %[ret]\n" \
			" ldapw,0 %[descriptor], %[oldval], mas=0x7}\n" \
			NONTARGET_LABEL("2") "\n" \
			"{nop 1\n" \
			" cmpesb %[oldval], %[old], %%pred2}\n" \
			"{merges %[oldval], %[new], %[tmp], %%pred2}\n" \
			"{stapw," mem_model##_ATOMIC_CHANNEL \
				" %[descriptor], %[tmp], mas=" mem_model##_ATOMIC_MAS "\n" \
			" ibranch 1b ? %%MLOCK}\n" \
			"3:\n" \
			".section .fixup,\"ax\"\n" \
			"4:{adds 0, %[efault], %[ret]\n" \
			"   addd 0, 0, %[oldval]\n" \
			"   ibranch 3b}\n" \
			".previous\n" \
			".section __ex_table,\"a\"\n" \
			".dword 1b, 4b\n" \
			".dword 2b, 4b\n" \
			".previous\n" \
			MB_AFTER_ATOMIC_##mem_model \
			: [ret] "=&r" (__ret), [tmp] "=&r" (__tmp), \
			  [oldval] "=&r" (__oldval), [addr] "+m" (*(__addr)), \
			  [descriptor] "+r" (uac_descriptor) \
			: [new] "ir" (__new), [old] "ir" (__old), [efault] "i" (-EFAULT), \
			  [ap_lo_etag] "ir" (E2K_AP_LO_ETAG), [ap_hi_etag] "ir" (E2K_AP_HI_ETAG), \
			  [no_atomic_spurious_fault] "i" (CPU_NO_HWBUG_ATOMIC_SPURIOUS_FAULT) \
			CLOBBERS_PRED2_##mem_model); \
	} \
} while (0)

#define USER_ATOMIC_XCHG_RETURN(__val, __addr, __oldval, __size, size_letter, __fmt, \
		use_descriptor, mem_model, __ret) \
do { \
	if (cpu_has(CPU_FEAT_ATOMIC_LDRD)) { \
		int uax_fmt = (__fmt); \
		ldst_rec_op_t uax_opc_ld = (ldst_rec_op_t) { \
			.fmt = uax_fmt, \
			.mas = _MAS_MODE_LOAD_OP_WAIT, \
			.prot = 1, \
		}; \
		ldst_rec_op_t uax_opc_st = (ldst_rec_op_t) { \
			.fmt = uax_fmt, \
			.mas = mem_model##_ATOMIC_MAS_VALUE, \
			.prot = 1, \
		}; \
		ASM_LENGTH_V6_V7(8, 6) \
		asm NOT_VOLATILE ( \
			BEFORE_ATOMIC("1:", mem_model, no_atomic_spurious_fault) \
			ALTERNATIVE( \
			/* Default version - 7 cycles ld->st delay */ \
				"{nop 6\n" \
				" adds,1 0, 0, %[ret]\n" \
				" ldrd,0 [ %[addr] + %[opc_ld] ], %[oldval]}\n", \
			/* CPU_FEAT_ISET_V7 - 5 cycles ld->st delay */ \
				"{nop 4\n" \
				" adds,1 0, 0, %[ret]\n" \
				" ldrd,0 [ %[addr] + %[opc_ld] ], %[oldval]}\n", \
			%[iset_v7]) \
			NONTARGET_LABEL("2") "\n" \
			"{strd," mem_model##_ATOMIC_CHANNEL " [ %[addr] + %[opc_st] ], %[val]\n" \
			" ibranch 1b ? %%MLOCK}\n" \
			"3:\n" \
			".section .fixup,\"ax\"\n" \
			"4:{adds 0, %[efault], %[ret]\n" \
			"   addd 0, 0, %[oldval]\n" \
			"   ibranch 3b}\n" \
			".previous\n" \
			".section __ex_table,\"a\"\n" \
			".dword 1b, 4b\n" \
			".dword 2b, 4b\n" \
			".previous\n" \
			MB_AFTER_ATOMIC_##mem_model \
			: [ret] "=&r" (__ret), [oldval] "=&r" (__oldval), \
			  [addr] "+m" (*(__addr)) \
			: [val] "r" (__val), [efault] "i" (-EFAULT), \
			  [opc_ld] "ir" (uax_opc_ld.word), \
			  [opc_st] "ir" (uax_opc_st.word), \
			  [iset_v7] "i" (CPU_FEAT_ISET_V7), \
			  [no_atomic_spurious_fault] "i" (CPU_NO_HWBUG_ATOMIC_SPURIOUS_FAULT) \
			CLOBBERS_##mem_model); \
	} else if (!(use_descriptor)) { \
		__asm_length(7) \
		asm NOT_VOLATILE ( \
			BEFORE_ATOMIC("1:", mem_model, no_atomic_spurious_fault) \
			/* iset<v6: 6 cycles ld->st delay */ \
			"{nop 5\n" \
			" adds,1 0, 0, %[ret]\n" \
			" ld"#size_letter ",0 %[addr], %[oldval], mas=0x7}\n" \
			NONTARGET_LABEL("2") "\n" \
			"{st"#size_letter "," mem_model##_ATOMIC_CHANNEL \
				" %[addr], %[val], mas=" mem_model##_ATOMIC_MAS "\n" \
			" ibranch 1b ? %%MLOCK}\n" \
			"3:\n" \
			".section .fixup,\"ax\"\n" \
			"4:{adds 0, %[efault], %[ret]\n" \
			"   addd 0, 0, %[oldval]\n" \
			"   ibranch 3b}\n" \
			".previous\n" \
			".section __ex_table,\"a\"\n" \
			".dword 1b, 4b\n" \
			".dword 2b, 4b\n" \
			".previous\n" \
			MB_AFTER_ATOMIC_##mem_model \
			: [ret] "=&r" (__ret), [oldval] "=&r" (__oldval), \
			  [addr] "+m" (*(__addr)) \
			: [val] "r" (__val), [efault] "i" (-EFAULT), \
			  [no_atomic_spurious_fault] "i" (CPU_NO_HWBUG_ATOMIC_SPURIOUS_FAULT) \
			CLOBBERS_##mem_model); \
	} else { \
		e2k_ap_t uax_descriptor = MAKE_AP((__addr), (__size)); \
		__asm_length(8) \
		asm NOT_VOLATILE ( \
			"{puttagd,2 %L[descriptor], %[ap_lo_etag], %L[descriptor]\n" \
			" puttagd,5 %H[descriptor], %[ap_hi_etag], %H[descriptor]}\n" \
			BEFORE_ATOMIC("1:", mem_model, no_atomic_spurious_fault) \
			/* iset<v6: 6 cycles ld->st delay */ \
			"{nop 5\n" \
			" adds,1 0, 0, %[ret]\n" \
			" ldap"#size_letter ",0 %[descriptor], %[oldval], mas=0x7}\n" \
			NONTARGET_LABEL("2") "\n" \
			"{stap"#size_letter "," mem_model##_ATOMIC_CHANNEL \
				" %[descriptor], %[val], mas=" mem_model##_ATOMIC_MAS "\n" \
			" ibranch 1b ? %%MLOCK}\n" \
			"3:\n" \
			".section .fixup,\"ax\"\n" \
			"4:{adds 0, %[efault], %[ret]\n" \
			"   addd 0, 0, %[oldval]\n" \
			"   ibranch 3b}\n" \
			".previous\n" \
			".section __ex_table,\"a\"\n" \
			".dword 1b, 4b\n" \
			".dword 2b, 4b\n" \
			".previous\n" \
			MB_AFTER_ATOMIC_##mem_model \
			: [ret] "=&r" (__ret), [oldval] "=&r" (__oldval), \
			  [addr] "+m" (*(__addr)), [descriptor] "+r" (uax_descriptor) \
			: [val] "r" (__val), [efault] "i" (-EFAULT), \
			  [ap_lo_etag] "ir" (E2K_AP_LO_ETAG), [ap_hi_etag] "ir" (E2K_AP_HI_ETAG), \
			  [no_atomic_spurious_fault] "i" (CPU_NO_HWBUG_ATOMIC_SPURIOUS_FAULT) \
			CLOBBERS_##mem_model); \
	} \
} while (0)

#define LOAD_UNALIGNED_ZEROPAD(_addr) \
({ \
	u64 *__addr = (u64 *) (_addr); \
	u64 _ret, _aligned_addr, _offset; \
	__no_asm_inline(1) \
	asm (	" ldd [ %[addr] + 0 ], %[ret]\n" \
		NONTARGET_LABEL("1") "\n" \
		"2:\n" \
		".section .fixup,\"ax\"\n" \
		"3:\n" \
		"{\n" \
		" andnd %[addr_val], 7, %[aligned_addr]\n" \
		" andd %[addr_val], 7, %[offset]\n" \
		"}\n" \
		"{\n" \
		" nop 4\n" \
		" ldd [ %[aligned_addr] + 0 ], %[ret]\n" \
		" shld %[offset], 3, %[offset]\n" \
		"}\n" \
		"{\n" \
		" shrd %[ret], %[offset], %[ret]\n" \
		" ibranch 2b\n" \
		"}\n" \
		".previous\n" \
		".section __ex_table,\"a\"\n" \
		".dword 1b, 3b\n" \
		".previous\n" \
		: [ret] "=&r" (_ret), [offset] "=&r" (_offset), \
		  [aligned_addr] "=&r" (_aligned_addr) \
		: [addr] "m" (*__addr), \
		  [addr_val] "r" (__addr)); \
	_ret; \
})

#ifdef CONFIG_DEBUG_BUGVERBOSE

# define __EMIT_BUG(_flags) \
do { \
	__no_asm_inline(1) \
	asm (NONTARGET_LABEL("1") "\n" \
	     "{setsft}\n" \
	     ".section .rodata.str,\"aMS\",@progbits,1\n" \
	     "2: .asciz  \""__FILE__"\"\n" \
	     ".previous\n" \
	     ".section __bug_table,\"aw\"\n" \
	     "3:\n" \
	     ".word 1b - 3b\n"    /* bug_entry:bug_addr_disp */ \
	     ".word 2b - 3b\n"    /* bug_entry:file_disp */ \
	     ".short %[line]\n"   /* bug_entry:line */ \
	     ".short %[flags]\n"  /* bug_entry:flags */ \
	     ".org 3b + %[entry_size]\n" \
	     ".previous\n" \
	     :: [line] "i" (__LINE__), [flags] "i" (_flags), \
		[entry_size] "i" (sizeof(struct bug_entry))); \
} while (0)

#else

# define __EMIT_BUG(_flags) \
do { \
	__no_asm_inline(1) \
	asm (NONTARGET_LABEL("1") "\n" \
	     "{setsft}\n" \
	     ".section __bug_table,\"aw\"\n" \
	     "3:\n" \
	     ".word 1b - 3b\n"    /* bug_entry:bug_addr_disp */ \
	     ".short %[flags]\n"  /* bug_entry:flags */ \
	     ".org 3b + %[entry_size]\n" \
	     ".previous\n" \
	     :: [flags] "i" (_flags), \
		[entry_size] "i" (sizeof(struct bug_entry))); \
} while (0)

#endif

#ifndef	__ASSEMBLY__
/* new version */
/*
 * this code used before call printk in special procedures
 *  sp register is used to pass parameters for printk
 */
static __always_inline void E2K_SET_USER_STACK(int x)
{
	if (__builtin_constant_p(x)) {
		if (x) {
			__builtin_alloca(1024);
		}
	} else {
		/* special for compiler error */
		/* fix  gcc problem -  warning */
#ifdef __LCC__
	asm ("" : : "i"(x)); /* hook!!  parameter must be const */
#endif /*  __LCC__ */
	}
}
#endif /* __ASSEMBLY__ */

#define E2K_NOP(nr) \
do { \
	CONCATENATE(ASM_LENGTH_, ADD_1_##nr) \
	__asm__ __volatile__("{nop " #nr "}" ::: "memory"); \
} while (0)

#ifdef CONFIG_SMP
# define SMP_ONLY(...) __VA_ARGS__
# define NOT_SMP_ONLY(...)
#else
# define SMP_ONLY(...)
# define NOT_SMP_ONLY(...) __VA_ARGS__
#endif

#define NATIVE_FILL_HARDWARE_STACKS__HW() \
do { \
	/* "{fillc; fillr}" */ \
	__no_asm_inline(1) \
	asm volatile (".word 0x00008001; .word 0x7000000c" ::: "memory"); \
} while (0)
#define NATIVE_FILL_HARDWARE_STACKS__SW(_sw_fill_sequel) \
do { \
	__no_asm_inline(7) \
	asm volatile ( \
		"{\n" \
		"nop 4\n" \
		"return %%ctpr3\n" \
		"movtd %[sw_fill_sequel], %%dg" __stringify(GUEST_VCPU_STATE_GREG) "\n" \
		"}\n" \
		"{\n" \
		"ct %%ctpr3\n" \
		"}\n" \
		: \
		: [sw_fill_sequel] "ir" (_sw_fill_sequel) \
		: "ctpr1", "ctpr2", "ctpr3", "memory"); \
} while (0)
#define NATIVE_FILL_CHAIN_STACK__HW() \
do { \
	/* "{fillc}" */ \
	__no_asm_inline(1) \
	asm volatile (".word 0x00008001; .word 0x70000008" ::: "memory"); \
} while (0)

#ifndef	__ASSEMBLY__

#define	DO_FUNC_TO_NAME(func)	#func
#define	FUNC_TO_NAME(func)	DO_FUNC_TO_NAME(func)

#define GET_LBL_ADDR(name, where) \
do { \
	__no_asm_inline(1) \
	asm ("movtd [" name "], %0" : "=r" (where)); \
} while (0)

#define E2K_JUMP(func)	E2K_JUMP_WITH_ARGUMENTS(func, 0)

#define	E2K_JUMP_WITH_ARG(func, arg)	E2K_JUMP_WITH_ARGUMENTS(func, 1, arg)

#define E2K_JUMP_WITH_ARGUMENTS(func, num_args, ...) \
	__E2K_JUMP_WITH_ARGUMENTS_##num_args(func, ##__VA_ARGS__)

#define __E2K_JUMP_WITH_ARGUMENTS_0(func) \
do { \
	asm volatile ("{\n" \
		      "disp %%ctpr1, %0\n" \
		      "}\n" \
		      "ct %%ctpr1\n" \
		      :: "i" (&(func)) : "ctpr1"); \
	unreachable(); \
} while (0)

#define __E2K_JUMP_WITH_ARGUMENTS_1(func, arg1) \
do { \
	asm volatile ("{\n" \
		      "disp %%ctpr1, %1\n" \
		      "addd  %0, 0, %%dr0\n" \
		      "}\n" \
		      "ct %%ctpr1\n" \
		      : \
		      : "ri" ((u64) (arg1)), "i" (&(func)) \
		      : "ctpr1", "r0"); \
	unreachable(); \
} while (0)

#define __E2K_JUMP_WITH_ARGUMENTS_2(func, arg1, arg2) \
do { \
	asm volatile ("{\n" \
		      "disp %%ctpr1, %2\n" \
		      "addd  %0, 0, %%dr0\n" \
		      "addd  %1, 0, %%dr1\n" \
		      "}\n" \
		      "ct %%ctpr1\n" \
		      : \
		      : "ri" ((u64) (arg1)), "ri" ((u64) (arg2)), "i" (&(func)) \
		      : "ctpr1", "r0", "r1"); \
	unreachable(); \
} while (0)

#define __E2K_JUMP_WITH_ARGUMENTS_3(func, arg1, arg2, arg3) \
do { \
	asm volatile ("{\n" \
		      "disp %%ctpr1, %3\n" \
		      "addd  %0, 0, %%dr0\n" \
		      "addd  %1, 0, %%dr1\n" \
		      "addd  %2, 0, %%dr2\n" \
		      "}\n" \
		      "ct %%ctpr1\n" \
		      : \
		      : "ri" ((u64) (arg1)), "ri" ((u64) (arg2)), \
			"ri" ((u64) (arg3)), "i" (&(func)) \
		      : "ctpr1", "r0", "r1", "r2"); \
	unreachable(); \
} while (0)

#define __E2K_JUMP_WITH_ARGUMENTS_4(func, arg1, arg2, arg3, arg4) \
do { \
	asm volatile ("{\n" \
		      "disp %%ctpr1, %4\n" \
		      "addd  %0, 0, %%dr0\n" \
		      "addd  %1, 0, %%dr1\n" \
		      "addd  %2, 0, %%dr2\n" \
		      "addd  %3, 0, %%dr3\n" \
		      "}\n" \
		      "ct %%ctpr1\n" \
		      : \
		      : "ri" ((u64) (arg1)), "ri" ((u64) (arg2)), \
			"ri" ((u64) (arg3)), "ri" ((u64) (arg4)), "i" (&(func)) \
		      : "ctpr1", "r0", "r1", "r2", "r3"); \
	unreachable(); \
} while (0)

#define __E2K_JUMP_WITH_ARGUMENTS_5(func, arg1, arg2, arg3, arg4, arg5) \
do { \
	asm volatile ("{\n" \
		      "disp %%ctpr1, %5\n" \
		      "addd  %0, 0, %%dr0\n" \
		      "addd  %1, 0, %%dr1\n" \
		      "addd  %2, 0, %%dr2\n" \
		      "addd  %3, 0, %%dr3\n" \
		      "addd  %4, 0, %%dr4\n" \
		      "}\n" \
		      "ct %%ctpr1\n" \
		      : \
		      : "ri" ((u64) (arg1)), "ri" ((u64) (arg2)), \
			"ri" ((u64) (arg3)), "ri" ((u64) (arg4)), \
			"ri" ((u64) (arg5)), "i" (&(func)) \
		      : "ctpr1", "r0", "r1", "r2", "r3", "r4"); \
	unreachable(); \
} while (0)

#define __E2K_JUMP_WITH_ARGUMENTS_6(func, \
			arg1, arg2, arg3, arg4, arg5, arg6) \
do { \
	asm volatile ("{\n" \
		      "disp %%ctpr1, %6\n" \
		      "addd  %0, 0, %%dr0\n" \
		      "addd  %1, 0, %%dr1\n" \
		      "addd  %2, 0, %%dr2\n" \
		      "addd  %3, 0, %%dr3\n" \
		      "addd  %4, 0, %%dr4\n" \
		      "addd  %5, 0, %%dr5\n" \
		      "}\n" \
		      "ct %%ctpr1\n" \
		      : \
		      : "ri" ((u64) (arg1)), "ri" ((u64) (arg2)), \
			"ri" ((u64) (arg3)), "ri" ((u64) (arg4)), \
			"ri" ((u64) (arg5)), "ri" ((u64) (arg6)), "i" (&(func)) \
		      : "ctpr1", "r0", "r1", "r2", "r3", "r4", "r5"); \
	unreachable(); \
} while (0)

#define __E2K_JUMP_FUNC_WITH_ARGUMENTS_7(func, \
			arg1, arg2, arg3, arg4, arg5, arg6, arg7) \
do { \
	asm volatile ("{\n" \
		      "disp %%ctpr1, %7\n" \
		      "addd  %0, 0, %%dr0\n" \
		      "addd  %1, 0, %%dr1\n" \
		      "addd  %2, 0, %%dr2\n" \
		      "addd  %3, 0, %%dr3\n" \
		      "addd  %4, 0, %%dr4\n" \
		      "addd  %5, 0, %%dr5\n" \
		      "}\n" \
		      "{\n" \
		      "addd  %6, 0, %%dr6\n" \
		      "ct %%ctpr1\n" \
		      "}\n" \
		      : \
		      : "ri" ((u64) (arg1)), "ri" ((u64) (arg2)), \
			"ri" ((u64) (arg3)), "ri" ((u64) (arg4)), \
			"ri" ((u64) (arg5)), "ri" ((u64) (arg6)), \
			"ri" ((u64) (arg7)), "i" (&(func)) \
		      : "ctpr1", "r0", "r1", "r2", "r3", "r4", "r5", "r6"); \
	unreachable(); \
} while (0)

#define __E2K_JUMP_FUNC_ADDR_WITH_ARGUMENTS_7(_func_addr, \
			arg1, arg2, arg3, arg4, arg5, arg6, arg7) \
do { \
	asm volatile ("{\n" \
		      "movtd,0,sm %[func_addr], %%ctpr1\n" \
		      "addd  %0, 0, %%dr0\n" \
		      "addd  %1, 0, %%dr1\n" \
		      "addd  %2, 0, %%dr2\n" \
		      "addd  %3, 0, %%dr3\n" \
		      "addd  %4, 0, %%dr4\n" \
		      "}\n" \
		      "{\n" \
		      "addd  %5, 0, %%dr5\n" \
		      "addd  %6, 0, %%dr6\n" \
		      "ct %%ctpr1\n" \
		      "}\n" \
		      : \
		      : [func_addr] "r" (_func_addr), \
			"ri" ((u64) (arg1)), "ri" ((u64) (arg2)), \
			"ri" ((u64) (arg3)), "ri" ((u64) (arg4)), \
			"ri" ((u64) (arg5)), "ri" ((u64) (arg6)), \
			"ri" ((u64) (arg7)) \
		      : "ctpr1", "r0", "r1", "r2", "r3", "r4", "r5", "r6"); \
	unreachable(); \
} while (false)
#define __E2K_JUMP_WITH_ARGUMENTS_7(func, \
			arg1, arg2, arg3, arg4, arg5, arg6, arg7) \
do { \
	__E2K_JUMP_FUNC_WITH_ARGUMENTS_7(func, \
			arg1, arg2, arg3, arg4, arg5, arg6, arg7); \
} while (false)

#define __E2K_JUMP_FUNC_WITH_ARGUMENTS_8(func_name, \
			arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8) \
do { \
	asm volatile ("{\n" \
		      "disp %%ctpr1, " func_name "\n" \
		      "addd  %0, 0, %%dr0\n" \
		      "addd  %1, 0, %%dr1\n" \
		      "addd  %2, 0, %%dr2\n" \
		      "addd  %3, 0, %%dr3\n" \
		      "addd  %4, 0, %%dr4\n" \
		      "addd  %5, 0, %%dr5\n" \
		      "}\n" \
		      "{\n" \
		      "addd  %6, 0, %%dr6\n" \
		      "addd  %7, 0, %%dr7\n" \
		      "ct %%ctpr1\n" \
		      "}\n" \
		      : \
		      : "ri" ((u64) (arg1)), "ri" ((u64) (arg2)), \
			"ri" ((u64) (arg3)), "ri" ((u64) (arg4)), \
			"ri" ((u64) (arg5)), "ri" ((u64) (arg6)), \
			"ri" ((u64) (arg7)), "ri" ((u64) (arg8)) \
		      : "ctpr1", "r0", "r1", "r2", "r3", "r4", "r5", "r6", \
			"r7"); \
	unreachable(); \
} while (0)
#define __E2K_JUMP_WITH_ARGUMENTS_8(func, \
			arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8) \
		__E2K_JUMP_FUNC_WITH_ARGUMENTS_8(FUNC_TO_NAME(func), \
				arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)

#define __E2K_JUMP_FUNC_RNDPR_7(func, arg1, arg2, arg3, arg4, arg5, arg6, arg7, _rndpr) \
do { \
	typecheck(e2k_rndpr_t, _rndpr); \
	asm volatile (	"{disp %%ctpr1, %7\n" \
			" rwd %[rndpr], %%rndpr\n" \
			" addd  %0, 0, %%dr0\n" \
			" addd  %1, 0, %%dr1\n" \
			" addd  %2, 0, %%dr2\n" \
			" addd  %3, 0, %%dr3\n" \
			" addd  %4, 0, %%dr4}\n" \
			ALTERNATIVE("nop 3", "nop 5", %[iset_v7]) \
			"{addd  %5, 0, %%dr5\n" \
			" addd  %6, 0, %%dr6\n" \
			" ct %%ctpr1}\n" \
			: \
			: "ri" ((u64) (arg1)), "ri" ((u64) (arg2)), \
			  "ri" ((u64) (arg3)), "ri" ((u64) (arg4)), \
			  "ri" ((u64) (arg5)), "ri" ((u64) (arg6)), \
			  "ri" ((u64) (arg7)), "i" (&(func)), \
			  [rndpr] "ir" ((u64) (AW(_rndpr))), \
			  [iset_v7] "i" (CPU_FEAT_ISET_V7) \
			: "ctpr1", "r0", "r1", "r2", "r3", "r4", "r5", "r6"); \
	unreachable(); \
} while (0)

#define __E2K_JUMP_FUNC_ADDR_RNDPR_7(_func_addr, \
			arg1, arg2, arg3, arg4, arg5, arg6, arg7, _rndpr) \
do { \
	typecheck(e2k_rndpr_t, _rndpr); \
	asm volatile (	"{rwd %[rndpr], %%rndpr\n" \
			" movtd,sm %[func_addr], %%ctpr1\n" \
			" addd  %0, 0, %%dr0\n" \
			" addd  %1, 0, %%dr1\n" \
			" addd  %2, 0, %%dr2\n" \
			" addd  %3, 0, %%dr3}\n" \
			ALTERNATIVE("nop 3", "nop 5", %[iset_v7]) \
			"{addd  %4, 0, %%dr4\n" \
			" addd  %5, 0, %%dr5\n" \
			" addd  %6, 0, %%dr6\n" \
			" ct %%ctpr1}\n" \
			: \
			: [func_addr] "r" (_func_addr), \
			  "ri" ((u64) (arg1)), "ri" ((u64) (arg2)), \
			  "ri" ((u64) (arg3)), "ri" ((u64) (arg4)), \
			  "ri" ((u64) (arg5)), "ri" ((u64) (arg6)), \
			  "ri" ((u64) (arg7)), \
			  [rndpr] "ir" ((u64) (AW(_rndpr))), \
			  [iset_v7] "i" (CPU_FEAT_ISET_V7) \
			: "ctpr1", "r0", "r1", "r2", "r3", "r4", "r5", "r6"); \
	unreachable(); \
} while (false)

#define __E2K_JUMP_RNDPR_7(func, \
			arg1, arg2, arg3, arg4, arg5, arg6, arg7, is_name, _rndpr) \
do { \
	if (is_name) { \
		__E2K_JUMP_FUNC_RNDPR_7(func, \
			arg1, arg2, arg3, arg4, arg5, arg6, arg7, _rndpr); \
	} else { \
		__E2K_JUMP_FUNC_ADDR_RNDPR_7(func, \
			arg1, arg2, arg3, arg4, arg5, arg6, arg7, _rndpr); \
	} \
} while (false)

#ifdef CONFIG_CPU_HWBUG_IBRANCH
# define WORKAROUND_IBRANCH_HWBUG "{nop} {nop}\n"
#else
# define WORKAROUND_IBRANCH_HWBUG
#endif

#define E2K_GOTO_ARG0(func) \
do { \
	__no_asm_inline(1) \
	asm volatile ("{ibranch " #func "}\n" \
		      WORKAROUND_IBRANCH_HWBUG \
		      :: ); \
	unreachable(); \
} while (0)

#define E2K_GOTO_ARG1(label, arg1)					\
do {									\
	__no_asm_inline(1)					\
	asm volatile (							\
		"{\n"							\
		"addd \t 0, %0, %%dr0\n"				\
		"ibranch \t" #label "\n"				\
		"}\n"							\
		WORKAROUND_IBRANCH_HWBUG				\
		:							\
		: "ri" ((u64) (arg1))				\
	);								\
	unreachable();							\
} while (false)

#define E2K_GOTO_ARG2(label, arg1, arg2)				\
do {									\
	__no_asm_inline(1)					\
	asm volatile ("\n"						\
		"{\n"							\
		"addd \t 0, %0, %%dr0\n"				\
		"addd \t 0, %1, %%dr1\n"				\
		"ibranch \t" #label "\n"				\
		"}\n"							\
		WORKAROUND_IBRANCH_HWBUG				\
		:							\
		: "ri" ((u64) (arg1)),				\
		  "ri" ((u64) (arg2))				\
	);								\
	unreachable();							\
} while (false)

#define E2K_GOTO_ARG3(label, arg1, arg2, arg3)				\
do {									\
	__no_asm_inline(1)					\
	asm volatile ("\n"						\
		"{\n"							\
		"addd \t 0, %0, %%dr0\n"				\
		"addd \t 0, %1, %%dr1\n"				\
		"addd \t 0, %2, %%dr2\n"				\
		"ibranch \t" #label "\n"				\
		"}\n"							\
		WORKAROUND_IBRANCH_HWBUG				\
		:							\
		: "ri" ((u64) (arg1)),				\
		  "ri" ((u64) (arg2)),				\
		  "ri" ((u64) (arg3))				\
	);								\
	unreachable();							\
} while (false)

#define E2K_GOTO_ARG4(label, arg1, arg2, arg3, arg4)			\
do {									\
	__no_asm_inline(1)					\
	asm volatile ("\n"						\
		"{\n"							\
		"addd \t 0, %0, %%dr0\n"				\
		"addd \t 0, %1, %%dr1\n"				\
		"addd \t 0, %2, %%dr2\n"				\
		"addd \t 0, %3, %%dr3\n"				\
		"ibranch \t" #label "\n"				\
		"}\n"							\
		WORKAROUND_IBRANCH_HWBUG				\
		:							\
		: "ri" ((u64) (arg1)),				\
		  "ri" ((u64) (arg2)),				\
		  "ri" ((u64) (arg3)),				\
		  "ri" ((u64) (arg4))				\
	);								\
	unreachable();							\
} while (false)

#define E2K_GOTO_ARG7(label, arg1, arg2, arg3, arg4, arg5, arg6, arg7)	\
do {									\
	__no_asm_inline(2)					\
	asm volatile ("\n"						\
		"{\n"							\
		"addd \t 0, %1, %%dr1\n"				\
		"addd \t 0, %2, %%dr2\n"				\
		"addd \t 0, %3, %%dr3\n"				\
		"addd \t 0, %4, %%dr4\n"				\
		"addd \t 0, %5, %%dr5\n"				\
		"addd \t 0, %6, %%dr6\n"				\
		"}\n"							\
		"{\n"							\
		"addd \t 0, %0, %%dr0\n"				\
		"ibranch \t" #label "\n"				\
		"}\n"							\
		WORKAROUND_IBRANCH_HWBUG				\
		:							\
		: "i" ((u64) (arg1)),				\
		  "ri" ((u64) (arg2)),				\
		  "ri" ((u64) (arg3)),				\
		  "ri" ((u64) (arg4)),				\
		  "ri" ((u64) (arg5)),				\
		  "ri" ((u64) (arg6)),				\
		  "ri" ((u64) (arg7))				\
	);								\
	unreachable();							\
} while (false)

#define __FASTSYS_PROTECTED_FALLBACK(sys_num, tags, usd_lo, arg2, arg3, arg4, arg5, arg6, arg7) \
({ \
	long __ret; \
	u64 prev_usd; \
	u32 tag2 = ARG_TAG(2), tag3 = ARG_TAG(3), tag4 = ARG_TAG(4), \
	    tag5 = ARG_TAG(5), tag6 = ARG_TAG(6), tag7 = ARG_TAG(7); \
	__no_asm_inline(14) \
	asm volatile ("{rrd %%usd.lo, %[_prev_usd]\n}" \
		      "{nop 7\n" \
		      " rwd %[_usd_lo], %%usd.lo\n" \
		      " disp %%ctpr1, %[_func]\n" \
		      " adds %[_sys_num], 0, %%b[0]\n" \
		      " puttagd %[_arg2], %[_tag2], %%db[2]\n" \
		      " puttagd %[_arg3], %[_tag3], %%db[3]\n}" \
		      "{puttagd %[_arg4], %[_tag4], %%db[4]\n" \
		      " puttagd %[_arg5], %[_tag5], %%db[5]}" \
		      "{puttagd %[_arg6], %[_tag6], %%db[6]\n" \
		      " puttagd %[_arg7], %[_tag7], %%db[7]\n" \
		      " call %%ctpr1, wbs=%#\n}" \
		      "{nop 7\n" \
		      " rwd %[_prev_usd], %%usd.lo\n" \
		      " addd %%db[0], 0, %[_ret]}" \
		      : [_ret] "=r" (__ret), [_prev_usd] "=&r" (prev_usd) \
		      : [_func] "i" (&ttable_entry8), [_sys_num] "r" (sys_num), \
			[_usd_lo] "r" (usd_lo), \
			[_arg2] "r" (arg2), [_arg3] "r" (arg3), \
			[_arg4] "r" (arg4), [_arg5] "r" (arg5), \
			[_arg6] "r" (arg6), [_arg7] "r" (arg7), \
			[_tag2] "r" (tag2), [_tag3] "r" (tag3), \
			[_tag4] "r" (tag4), [_tag5] "r" (tag5), \
			[_tag6] "r" (tag6), [_tag7] "r" (tag7) \
		      : E2K_SYSCALL_CLOBBERS); \
	__ret; \
})

#define E2K_SCALL_ARG7(trap_num, sys_num, arg1, arg2, arg3, arg4, arg5, arg6) \
({									\
	unsigned long esa_ret__;					\
	__no_asm_inline(5) \
	asm volatile (							\
		"{\n"							\
		"addd \t 0, %[_sys_num], %%db[0]\n"			\
		"addd \t 0, %[_arg1], %%db[1]\n"			\
		"addd \t 0, %[_arg2], %%db[2]\n"			\
		"addd \t 0, %[_arg3], %%db[3]\n"			\
		"addd \t 0, %[_arg4], %%db[4]\n"			\
		"addd \t 0, %[_arg5], %%db[5]\n"			\
		"}\n"							\
		"{\n"							\
		"addd \t 0, %[_arg6], %%db[6]\n"			\
		"sdisp \t %%ctpr1, 0x"#trap_num"\n"			\
		"}\n"							\
		"{\n"							\
		"call %%ctpr1, wbs = %#\n"				\
		"}\n"							\
		"{\n"							\
		"addd,0,sm 0x0, %%db[0], %[_ret]\n"			\
		"}\n"							\
		: [_ret] "=r" (esa_ret__)				\
		: [_sys_num] "ri" ((u64) (sys_num)),		\
		  [_arg1] "ri" ((u64) (arg1)),			\
		  [_arg2] "ri" ((u64) (arg2)),			\
		  [_arg3] "ri" ((u64) (arg3)),			\
		  [_arg4] "ri" ((u64) (arg4)),			\
		  [_arg5] "ri" ((u64) (arg5)),			\
		  [_arg6] "ri" ((u64) (arg6))			\
		: "b[0]", "b[1]", "b[2]", "b[3]", "b[4]", "b[5]",	\
		  "b[6]", "ctpr1"					\
	);								\
	esa_ret__;							\
})
#define E2K_COND_GOTO(label, cond, pred_no)				\
do {									\
	__no_asm_inline(2) \
	asm volatile (							\
		"\ncmpesb \t0, %0, %%pred" #pred_no			\
		"\n{"							\
		"\nibranch \t" #label " ? ~%%pred" #pred_no		\
		"\n}"							\
		WORKAROUND_IBRANCH_HWBUG				\
		:							\
		: "ri" ((u32) (cond))				\
		: "pred" #pred_no					\
	);								\
} while (false)
#define E2K_COND_GOTO_ARG1(label, cond, pred_no, arg1)			\
do {									\
	__no_asm_inline(2) \
	asm volatile (							\
		"\ncmpesb \t0, %0, %%pred" #pred_no			\
		"\n{"							\
		"\naddd \t 0, %1, %%dr0 ? ~%%pred" #pred_no		\
		"\nibranch \t" #label " ? ~%%pred" #pred_no		\
		"\n}"							\
		WORKAROUND_IBRANCH_HWBUG				\
		:							\
		: "ri" ((u32) (cond)),				\
		  "ri" ((u64) (arg1))				\
		: "pred" #pred_no					\
	);								\
} while (false)
#define	DEF_COND_GOTO(label, cond)					\
		E2K_COND_GOTO(label, cond, 0)
#define	DEF_COND_GOTO_ARG1(label, cond, arg1)				\
		E2K_COND_GOTO_ARG1(label, cond, 0, arg1)

#define E2K_JUMP_ABSOLUTE_WITH_ARGUMENTS_1(func, arg1) \
do { \
	asm volatile ("{\n" \
		      "movtd %[_func], %%ctpr1\n" \
		      "addd  %[_arg1], 0, %%dr0\n" \
		      "}\n" \
		      "ct %%ctpr1\n" \
		      : \
		      : [_func] "ir" (func), \
			[_arg1] "ri" (arg1) \
		      : "ctpr1", "r0"); \
	unreachable(); \
} while (0)

#define E2K_JUMP_ABSOLUTE_WITH_ARGUMENTS_2(func, arg1, arg2) \
do { \
	asm volatile ("{\n" \
		      "movtd %[_func], %%ctpr1\n" \
		      "addd  %[_arg1], 0, %%dr0\n" \
		      "addd  %[_arg2], 0, %%dr1\n" \
		      "}\n" \
		      "ct %%ctpr1\n" \
		      : \
		      : [_func] "ir" (func), \
			[_arg1] "ri" (arg1), [_arg2] "ri" (arg2) \
		      : "ctpr1", "r0", "r1"); \
	unreachable(); \
} while (0)

#define __E2K_RESTART_TTABLE_ENTRY10_C(func, arg0, arg1, arg2, arg3, arg4, \
					arg5, arg6, arg7, tags, _rndpr) \
do { \
	typecheck(e2k_rndpr_t, _rndpr); \
	asm volatile ("{\n" \
		      "disp %%ctpr1, " #func "\n" \
		      "rwd %[rndpr], %%rndpr\n" \
		      "addd  %0, 0, %%dr0\n" \
		      "addd  %1, 0, %%dr1\n" \
		      "addd  %2, 0, %%dr2\n" \
		      "addd  %3, 0, %%dr3\n" \
		      "addd  %4, 0, %%dr4\n" \
		      "}\n" \
		      "{\n" \
		      "addd  %5, 0, %%dr5\n" \
		      "addd  %6, 0, %%dr6\n" \
		      "addd  %7, 0, %%dr7\n" \
		      "addd  %8, 0, %%dr8\n" \
		      "}\n" \
		      "{\n" \
		      "puttagd %%dr0, %%dr8, %%dr0\n" \
		      "shrs %%dr8, 4, %%dr8\n" \
		      "}\n" \
		      "{\n" \
		      "puttagd %%dr1, %%dr8, %%dr1\n" \
		      "shrs %%dr8, 4, %%dr8\n" \
		      "}\n" \
		      "{\n" \
		      "puttagd %%dr2, %%dr8, %%dr2\n" \
		      "shrs %%dr8, 4, %%dr8\n" \
		      "}\n" \
		      "{\n" \
		      "puttagd %%dr3, %%dr8, %%dr3\n" \
		      "shrs %%dr8, 4, %%dr8\n" \
		      "}\n" \
		      "{\n" \
		      "puttagd %%dr4, %%dr8, %%dr4\n" \
		      "shrs %%dr8, 4, %%dr8\n" \
		      "}\n" \
		      "{\n" \
		      "puttagd %%dr5, %%dr8, %%dr5\n" \
		      "shrs %%dr8, 4, %%dr8\n" \
		      "}\n" \
		      "{\n" \
		      "puttagd %%dr6, %%dr8, %%dr6\n" \
		      "shrs %%dr8, 4, %%dr8\n" \
		      "}\n" \
		      "{\n" \
		      "puttagd %%dr7, %%dr8, %%dr7\n" \
		      "ct %%ctpr1\n" \
		      "}\n" \
		      : \
		      : "ri" (arg0), "ri" (arg1), "ri" (arg2), "ri" (arg3), \
			"ri" (arg4), "ri" (arg5), "ri" (arg6), "ri" (arg7), \
			"ri" (tags), [rndpr] "ir" ((u64) (AW(_rndpr))) \
		      : "ctpr1", "r0", "r1", "r2", "r3", "r4", "r5", "r6", \
			"r7", "r8"); \
	unreachable(); \
} while (0)

#define __E2K_RESTART_TTABLE_ENTRY8_C(func, _sys_num, arg1, arg2, arg3, arg4, \
		arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12, _tags, _rndpr) \
do { \
	u64 tag_lo, tag_hi; \
	typecheck(e2k_rndpr_t, _rndpr); \
	asm volatile ( \
		"{\n" \
		"rwd %[rndpr], %%rndpr\n" \
		"disp %%ctpr1, " #func "\n" \
		"shrd,1 %[tags], 8, %[tag_lo]\n" \
		"shrd,4 %[tags], 12, %[tag_hi]\n" \
		"}\n" \
		"{\n" \
		"puttagd,2 %[a1], %[tag_lo], %%dr2\n" \
		"puttagd,5 %[a2], %[tag_hi], %%dr3\n" \
		"shrd,1  %[tags], 16, %[tag_lo]\n" \
		"shrd,4  %[tags], 20, %[tag_hi]\n" \
		"}\n" \
		"{\n" \
		"puttagd,2 %[a3], %[tag_lo], %%dr4\n" \
		"puttagd,5 %[a4], %[tag_hi], %%dr5\n" \
		"shrd,1  %[tags], 24, %[tag_lo]\n" \
		"shrd,4  %[tags], 28, %[tag_hi]\n" \
		"}\n" \
		"{\n" \
		"puttagd,2 %[a5], %[tag_lo], %%dr6\n" \
		"puttagd,5 %[a6], %[tag_hi], %%dr7\n" \
		"shrd,1  %[tags], 32, %[tag_lo]\n" \
		"shrd,4  %[tags], 36, %[tag_hi]\n" \
		"}\n" \
		"{\n" \
		"puttagd,2 %[a7], %[tag_lo], %%dr8\n" \
		"puttagd,5 %[a8], %[tag_hi], %%dr9\n" \
		"shrd,1  %[tags], 40, %[tag_lo]\n" \
		"shrd,4  %[tags], 44, %[tag_hi]\n" \
		"}\n" \
		"{\n" \
		"puttagd,2 %[a9], %[tag_lo], %%dr10\n" \
		"puttagd,5 %[a10], %[tag_hi], %%dr11\n" \
		"shrd,1  %[tags], 48, %[tag_lo]\n" \
		"shrd,4  %[tags], 52, %[tag_hi]\n" \
		"}\n" \
		"{\n" \
		"puttagd,2 %[a11], %[tag_lo], %%dr12\n" \
		"puttagd,5 %[a12], %[tag_hi], %%dr13\n" \
		"adds 0, %[sys_num], %%r0\n" \
		"ct %%ctpr1\n" \
		"}\n" \
		: [tag_lo] "=&r" (tag_lo), [tag_hi] "=&r" (tag_hi) \
		: [sys_num] "ri" (_sys_num), [a1] "ri" (arg1), \
		  [a2] "ri" (arg2), [a3] "ri" (arg3), [a4] "ri" (arg4), \
		  [a5] "ri" (arg5), [a6] "ri" (arg6), [a7] "ri" (arg7), \
		  [a8] "ri" (arg8), [a9] "ri" (arg9), [a10] "ri" (arg10), \
		  [a11] "ri" (arg11), [a12] "ri" (arg12), [tags] "ri" (_tags), \
		  [rndpr] "ir" ((u64) (AW(_rndpr))) \
		: "ctpr1", "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", \
		  "r8", "r9", "r10", "r11", "r12", "r13"); \
	unreachable(); \
} while (0)

#define E2K_GETCONTEXT(_fpcr, _fpsr, _pfpfr, _pcsp, _psp, _sbr, _cr1_lo) \
do { \
	e2k_pcshtp_t __pcshtp; \
	e2k_pshtp_t __pshtp; \
	e2k_pcsp_t __pcsp; \
	e2k_psp_t __psp; \
	__asm_length(13) \
	asm volatile ("{rrs %%fpcr, %[fpcr]}" \
		      "{rrs %%fpsr, %[fpsr]}" \
		      "{rrs %%pfpfr, %[pfpfr]}" \
		      "{rrd %%cr1.lo, %[cr1_lo]}" \
		      "{rrd %%pcshtp, %[pcshtp]}" \
		      "{rrd %%pcsp.lo, %[pcsp_lo]}" \
		      "{rrd %%pcsp.hi, %[pcsp_hi]}" \
		      "{rrd %%pshtp, %[pshtp]}" \
		      "{rrd %%psp.lo, %[psp_lo]}" \
		      "{rrd %%psp.hi, %[psp_hi]}" \
		      "{rrd %%sbr, %[sbr];" \
		      /* Delay after FPU reading is 11 cycles */ \
		      " nop 2}" \
		      : [fpcr] "=r" (_fpcr), [fpsr] "=r" (_fpsr), [pfpfr] "=r" (_pfpfr), \
			[pcsp_lo] "=r" (__pcsp.lo), [pcsp_hi] "=r" (__pcsp.hi), \
			[psp_lo] "=r" (__psp.lo), [psp_hi] "=r" (__psp.hi), \
			[pcshtp] "=r" (AW(__pcshtp)), [pshtp] "=r" (AW(__pshtp)), \
			[sbr] "=r" (_sbr), [cr1_lo] "=r" (_cr1_lo) \
		      : ); \
	(_pcsp) = incr_pcsp_ind(__pcsp, __pcshtp.ind); \
	(_psp) = incr_psp_ind(__psp, PSHTP_MEM_INDEX(__pshtp)); \
} while (0)

#define E2K_CLEAR_RF_108() \
do { \
	__asm_length(14) \
	asm volatile ( \
		"{\n" \
		"nop 3\n" \
		"disp %%ctpr1, 1f\n" \
		"setwd wsz=108\n" \
		"setbn rbs=0, rsz=62, rcur=0\n" \
		"rwd 21UL | (1UL << 37), %%lsr\n" \
		"}\n" \
		"{\n" \
		"disp %%ctpr2, 2f\n" \
		"}\n" \
		"1:" \
		"{\n" \
		"loop_mode\n" \
		"addd 0, 0, %%db[0]\n" \
		"addd 0, 0, %%db[1]\n" \
		"addd 0, 0, %%db[42]\n" \
		"addd 0, 0, %%db[43]\n" \
		"addd 0, 0, %%db[84]\n" \
		"addd 0, 0, %%db[85]\n" \
		"alc alcf = 1, alct = 1\n" \
		"abn abnf = 1, abnt = 1\n" \
		"ct %%ctpr1 ? %%NOT_LOOP_END\n" \
		"}\n" \
		"{\n" \
		"nop 4\n" \
		"setbn rbs=63, rsz=44, rcur=0\n" \
		"rwd 15UL | (1UL << 37), %%lsr\n" \
		"}\n" \
		"2:" \
		"{\n" \
		"loop_mode\n" \
		"addd 0, 0, %%db[0]\n" \
		"addd 0, 0, %%db[1]\n" \
		"addd 0, 0, %%db[32]\n" \
		"addd 0, 0, %%db[33]\n" \
		"addd 0, 0, %%db[64]\n" \
		"addd 0, 0, %%db[65]\n" \
		"alc alcf = 1, alct = 1\n" \
		"abn abnf = 1, abnt = 1\n" \
		"ct %%ctpr2 ? %%NOT_LOOP_END\n" \
		"}\n" \
		::: "ctpr1", "ctpr2"); \
} while (0)

#define E2K_CLEAR_RF_112() \
do { \
	__asm_length(14) \
	asm volatile ( \
		"{\n" \
		"nop 3\n" \
		"disp %%ctpr1, 1f\n" \
		"setwd wsz=112\n" \
		"setbn rbs=0, rsz=62, rcur=0\n" \
		"rwd 21UL | (1UL << 37), %%lsr\n" \
		"}\n" \
		"{\n" \
		"disp %%ctpr2, 2f\n" \
		"}\n" \
		"1:" \
		"{\n" \
		"loop_mode\n" \
		"addd 0, 0, %%db[0]\n" \
		"addd 0, 0, %%db[1]\n" \
		"addd 0, 0, %%db[42]\n" \
		"addd 0, 0, %%db[43]\n" \
		"addd 0, 0, %%db[84]\n" \
		"addd 0, 0, %%db[85]\n" \
		"alc alcf = 1, alct = 1\n" \
		"abn abnf = 1, abnt = 1\n" \
		"ct %%ctpr1 ? %%NOT_LOOP_END\n" \
		"}\n" \
		"{\n" \
		"nop 4\n" \
		"setbn rbs=63, rsz=48, rcur=0\n" \
		"rwd 16UL | (1UL << 37), %%lsr\n" \
		"}\n" \
		"2:" \
		"{\n" \
		"loop_mode\n" \
		"addd 0, 0, %%db[0]\n" \
		"addd 0, 0, %%db[1]\n" \
		"addd 0, 0, %%db[32]\n" \
		"addd 0, 0, %%db[33]\n" \
		"addd 0, 0, %%db[64]\n" \
		"addd 0, 0, %%db[65]\n" \
		"alc alcf = 1, alct = 1\n" \
		"abn abnf = 1, abnt = 1\n" \
		"ct %%ctpr2 ? %%NOT_LOOP_END\n" \
		"}\n" \
		"{\n" \
		"addd 0, 0, %%db[64]\n" \
		"addd 0, 0, %%db[65]\n" \
		"}\n" \
		::: "ctpr1", "ctpr2"); \
} while (0)

#define	E2K_CLEAR_CTPRS()			\
do {						\
	u64	reg;			\
	__asm_length(4) \
	asm volatile (				\
		"{puttagd,2 0, 5, %0}\n"	\
		"{movtd,s %0, %%ctpr1}\n"	\
		"{movtd,s %0, %%ctpr2}\n"	\
		"{movtd,s %0, %%ctpr3}\n"	\
		: "=r" (reg)			\
		:				\
		: "ctpr1", "ctpr2", "ctpr3");	\
} while (0)

#define NATIVE_RESTORE_COMMON_REGS_VALUES(_ctpr1, _ctpr2, _ctpr3, _ctpr1_hi, \
		_ctpr2_hi, _ctpr3_hi, _lsr, _lsr1, _ilcr, _ilcr1) \
do { \
	__no_asm_inline(5) \
	asm volatile ( \
		      "{rwd %[ctpr2], %%ctpr2}\n" \
 \
		      ALTERNATIVE_1_ALTINSTR \
		      /* CPU_FEAT_TRAP_V5 version */ \
			      ".push_iset 5\n" \
			      "{rwd %[ctpr3], %%ctpr3}\n" \
			      "{rwd %[ctpr1], %%ctpr1}\n" \
			      "{rwd %[lsr], %%lsr}\n" \
			      "{rwd %[lsr1], %%lsr1}\n" \
			      "{rwd %[ilcr], %%ilcr}\n" \
			      "{rwd %[ilcr1], %%ilcr1}\n" \
			      ".pop_iset\n" \
		      ALTERNATIVE_2_ALTINSTR2 \
		      /* CPU_FEAT_TRAP_V6 version */ \
			      ".push_iset 6\n" \
			      "{rwd %[ctpr3], %%ctpr3}\n" \
			      "{rwd %[ctpr1], %%ctpr1}\n" \
			      "{rwd %[ctpr1_hi], %%ctpr1.hi}\n" \
			      "{rwd %[ctpr2_hi], %%ctpr2.hi}\n" \
			      "{rwd %[ctpr3_hi], %%ctpr3.hi}\n" \
			      "{rwd %[lsr], %%lsr}\n" \
			      "{rwd %[lsr1], %%lsr1}\n" \
			      "{rwd %[ilcr], %%ilcr}\n" \
			      "{rwd %[ilcr1], %%ilcr1}\n" \
			      ".pop_iset\n" \
		      ALTERNATIVE_3_OLDINSTR2 \
			      "{rwd %[ctpr3], %%ctpr3}\n" \
			      "{rwd %[ctpr1], %%ctpr1}\n" \
			      "{rwd %[lsr], %%lsr}\n" \
			      "{rwd %[ilcr], %%ilcr}\n" \
		      ALTERNATIVE_4_FEATURE2(%[facility1], %[facility2]) \
 \
		      ALTERNATIVE("", "{nop} {nop}", %[cpu_hwbug_rwd_lsr]) \
		      "{wait all_e=1}\n" \
		      :: [ctpr1] "r" (_ctpr1), [ctpr2] "r" (_ctpr2), \
			 [ctpr3] "r" (_ctpr3), [ctpr1_hi] "r" (_ctpr1_hi), \
			 [ctpr2_hi] "r" (_ctpr2_hi), [ctpr3_hi] "r" (_ctpr3_hi), \
			 [lsr] "r" (_lsr), [lsr1] "r" (_lsr1), \
			 [ilcr] "r" (_ilcr), [ilcr1] "r" (_ilcr1), \
			 [facility1] "i" (CPU_FEAT_TRAP_V5), \
			 [facility2] "i" (CPU_FEAT_TRAP_V6), \
			 [cpu_hwbug_rwd_lsr] "i" (CPU_HWBUG_RWD_LSR) \
		      : "memory"); \
} while (0)

#define NATIVE_RESTORE_KERNEL_GREGS(_k_gregs) \
do { \
	u64 f16, f17, f18, f19, tmp1, tmp2; \
	__no_asm_inline_nolength ASM_LENGTH_V4_V5(8, 3) \
	asm volatile ( \
		ALTERNATIVE_1_ALTINSTR \
		/* iset v5 version - restore qp registers extended part */ \
 \
			"{\n" \
			"addd,2 %[k_gregs], %%db[0]\n" \
			"addd,5 %[k_gregs], %%db[1]\n" \
			"}\n" \
			/* "{ldrqp,2 [ %%db[0] + 0x50400000000 ], %%g16\n" \
			   " ldrqp,5 [ %%db[1] + 0x50400000010 ], %%g17}\n" */ \
			".word 0x92400033\n" \
			".word 0x6b00dcf0\n" \
			".word 0x6b01def1\n" \
			".word 0x02c002c0\n" \
			".word 0x00000504\n" \
			".word 0x00000010\n" \
			".word 0x00000504\n" \
			".word 0x00000000\n" \
			/* "{ldrqp,2 [ %%db[0] + 0x50400000020 ], %%g18\n" \
			   " ldrqp,5 [ %%db[1] + 0x50400000030 ], %%g19}\n" */ \
			".word 0x92400033\n" \
			".word 0x6b00dcf2\n" \
			".word 0x6b01def3\n" \
			".word 0x02c002c0\n" \
			".word 0x00000504\n" \
			".word 0x00000030\n" \
			".word 0x00000504\n" \
			".word 0x00000020\n" \
 \
		ALTERNATIVE_2_OLDINSTR \
		/* Original instruction - restore only 16 bits */ \
 \
			"{\n" \
			"ldrd,2 [ %[k_gregs] + 0x50400000000 ], %%g16\n" \
			"ldrd,5 [ %[k_gregs] + 0x50400000010 ], %%g17\n" \
			"}\n" \
			"{\n" \
			"ldrd,2 [ %[k_gregs] + 0x50400000020 ], %%g18\n" \
			"ldrd,5 [ %[k_gregs] + 0x50400000030 ], %%g19\n" \
			"}\n" \
			"{\n" \
			"ldh,0 [ %[k_gregs] + 0x8 ], %[f16]\n" \
			"ldh,3 [ %[k_gregs] + 0x18 ], %[f17]\n" \
			"ldh,2 [ %[k_gregs] + 0x28 ], %[f18]\n" \
			"ldh,5 [ %[k_gregs] + 0x38 ], %[f19]\n" \
			"}\n" \
			"{\n" \
			"gettagd,2 %%g16, %[tmp1]\n" \
			"gettagd,5 %%g17, %[tmp2]\n" \
			"}\n" \
			"{\n" \
			"cmpesb,0 0x0, %[tmp1], %%pred16\n" \
			"cmpesb,3 0x0, %[tmp2], %%pred17\n" \
			"gettagd,2 %%g18, %[tmp1]\n" \
			"gettagd,5 %%g19, %[tmp2]\n" \
			"}\n" \
			"{\n" \
			"cmpesb,0 0x0, %[tmp1], %%pred18\n" \
			"cmpesb,3 0x0, %[tmp2], %%pred19\n" \
			"}\n" \
			"{\n" \
			"movif,0 %%g16, %[f16], %%g16 ? %%pred16\n" \
			"movif,3 %%g17, %[f17], %%g17 ? %%pred17\n" \
			"}\n" \
			"{\n" \
			"movif,0 %%g18, %[f18], %%g18 ? %%pred18\n" \
			"movif,3 %%g19, %[f19], %%g19 ? %%pred19\n" \
			"}\n" \
 \
		ALTERNATIVE_3_FEATURE(%[facility]) \
		: [f16] "=&r" (f16), [f17] "=&r" (f17), [f18] "=&r" (f18), \
		  [f19] "=&r" (f19), [tmp1] "=&r" (tmp1), [tmp2] "=&r" (tmp2) \
		: [k_gregs] "m" (*(_k_gregs)), [facility] "i" (CPU_FEAT_QPREG) \
		: "g16", "g17", "g18", "g19", \
		  "pred16", "pred17", "pred18", "pred19"); \
} while (0)

#define NATIVE_RESTORE_HOST_GREGS(_h_gregs) \
do { \
	u64 f20, f21, tmp1, tmp2; \
	__no_asm_inline_nolength ASM_LENGTH_V4_V5(7, 2) \
	asm volatile ( \
		ALTERNATIVE_1_ALTINSTR \
		/* iset v5 version - restore qp registers extended part */ \
 \
			"{\n" \
			"addd,2 %[h_gregs], %%db[0]\n" \
			"addd,5 %[h_gregs], %%db[1]\n" \
			"}\n" \
			/* "{ldrqp,2 [ %%db[0] + 0x50400000000 ], %%g20\n" \
			    "ldrqp,5 [ %%db[1] + 0x50400000010 ], %%g21}\n" */ \
			".word 0x92400033\n" \
			".word 0x6b00dcf4\n" \
			".word 0x6b01def5\n" \
			".word 0x02c002c0\n" \
			".word 0x00000504\n" \
			".word 0x00000010\n" \
			".word 0x00000504\n" \
			".word 0x00000000\n" \
 \
		ALTERNATIVE_2_OLDINSTR \
		/* Original instruction - restore only 16 bits */ \
 \
			"{\n" \
			"ldrd,2 [ %[h_gregs] + 0x50400000000 ], %%g20\n" \
			"ldrd,5 [ %[h_gregs] + 0x50400000010 ], %%g21\n" \
			"}\n" \
			"{\n" \
			"nop 1\n" \
			"ldh,0 [ %[h_gregs] + 0x8 ], %[f20]\n" \
			"ldh,3 [ %[h_gregs] + 0x18 ], %[f21]\n" \
			"}\n" \
			"{\n" \
			"gettagd,2 %%g20, %[tmp1]\n" \
			"gettagd,5 %%g21, %[tmp2]\n" \
			"}\n" \
			"{\n" \
			"nop 1\n" \
			"cmpesb,0 0x0, %[tmp1], %%pred20\n" \
			"cmpesb,3 0x0, %[tmp2], %%pred21\n" \
			"}\n" \
			"{\n" \
			"movif,0 %%g20, %[f20], %%g20 ? %%pred20\n" \
			"movif,3 %%g21, %[f21], %%g21 ? %%pred21\n" \
			"}\n" \
 \
		ALTERNATIVE_3_FEATURE(%[facility]) \
		: [f20] "=&r" (f20), [f21] "=&r" (f21), \
		  [tmp1] "=&r" (tmp1), [tmp2] "=&r" (tmp2) \
		: [h_gregs] "m" (*(_h_gregs)), [facility] "i" (CPU_FEAT_QPREG) \
		: "g20", "g21", "pred20", "pred21"); \
} while (0)


#define LDRD(addr)						\
({								\
	register long __dres;					\
	__asm_length(1) \
	asm volatile ("{ldrd [%1], %0\n}"			\
		      : "=r"(__dres)				\
		      : "m" (*((unsigned long long *)(addr))));	\
	__dres;							\
})

#define SIMPLE_RECOVERY_STORE(_addr, _data, _opc) \
do { \
	u32 _fmt = ((ldst_rec_op_t *) &_opc)->fmt; \
	u64 _ind = ((ldst_rec_op_t *) &_opc)->index; \
	__no_asm_inline(4) \
	asm ( \
		"{nop 1\n" \
		" cmpesb,0 %[fmt], 1, %%pred20\n" \
		" cmpesb,1 %[fmt], 2, %%pred21\n" \
		" cmpesb,3 %[fmt], 3, %%pred22\n" \
		" cmpesb,4 %[fmt], 4, %%pred23}\n" \
		"{stb,2 %[addr], %[ind], %[data] ? %%pred20\n" \
		" sth,5 %[addr], %[ind], %[data] ? %%pred21}\n" \
		"{stw,2 %[addr], %[ind], %[data] ? %%pred22\n" \
		" std,5 %[addr], %[ind], %[data] ? %%pred23}\n" \
		: \
		: [addr] "r" (_addr), [data] "r" (_data), \
		  [fmt] "r" (_fmt), [ind] "r" (_ind) \
		: "memory", "pred20", "pred21", "pred22", "pred23" \
	); \
} while (0)

#define SIMPLE_RECOVERY_LOAD_TO_GREG_NO(_addr, _opc, _greg_no, _sm, _mas) \
do { \
	u32 _fmt = ((ldst_rec_op_t *) &_opc)->fmt; \
	u64 _ind = ((ldst_rec_op_t *) &_opc)->index; \
	__no_asm_inline(7) \
	asm ( \
		"{nop 1\n" \
		" cmpesb,0 %[fmt], 1, %%pred20\n" \
		" cmpesb,1 %[fmt], 2, %%pred21\n" \
		" cmpesb,3 %[fmt], 3, %%pred22\n" \
		" cmpesb,4 %[fmt], 4, %%pred23}\n" \
		"{nop 4\n" \
		" ldb" _sm ",0 %[addr], %[ind], %%dg" #_greg_no ", " \
			"mas=%[mas] ? %%pred20\n" \
		" ldh" _sm ",2 %[addr], %[ind], %%dg" #_greg_no ", " \
			"mas=%[mas] ? %%pred21\n" \
		" ldw" _sm ",3 %[addr], %[ind], %%dg" #_greg_no ", " \
			"mas=%[mas] ? %%pred22\n" \
		" ldd" _sm ",5 %[addr], %[ind], %%dg" #_greg_no ", " \
			"mas=%[mas] ? %%pred23}\n" \
		: \
		: [addr] "r" (_addr), [fmt] "r" (_fmt), \
		  [ind] "r" (_ind), [mas] "i" (_mas) \
		: "memory", "pred20", "pred21", "pred22", "pred23", \
		  "g" #_greg_no \
	); \
} while (0)

#define SIMPLE_RECOVERY_LOAD_TO_GREG(_addr, _opc, _greg_num, _sm, _mas) \
do { \
	switch (_greg_num) { \
	case  0: \
		SIMPLE_RECOVERY_LOAD_TO_GREG_NO(_addr, _opc, 0, _sm, _mas); \
		break; \
	case  1: \
		SIMPLE_RECOVERY_LOAD_TO_GREG_NO(_addr, _opc, 1, _sm, _mas); \
		break; \
	case  2: \
		SIMPLE_RECOVERY_LOAD_TO_GREG_NO(_addr, _opc, 2, _sm, _mas); \
		break; \
	case  3: \
		SIMPLE_RECOVERY_LOAD_TO_GREG_NO(_addr, _opc, 3, _sm, _mas); \
		break; \
	case  4: \
		SIMPLE_RECOVERY_LOAD_TO_GREG_NO(_addr, _opc, 4, _sm, _mas); \
		break; \
	case  5: \
		SIMPLE_RECOVERY_LOAD_TO_GREG_NO(_addr, _opc, 5, _sm, _mas); \
		break; \
	case  6: \
		SIMPLE_RECOVERY_LOAD_TO_GREG_NO(_addr, _opc, 6, _sm, _mas); \
		break; \
	case  7: \
		SIMPLE_RECOVERY_LOAD_TO_GREG_NO(_addr, _opc, 7, _sm, _mas); \
		break; \
	case  8: \
		SIMPLE_RECOVERY_LOAD_TO_GREG_NO(_addr, _opc, 8, _sm, _mas); \
		break; \
	case  9: \
		SIMPLE_RECOVERY_LOAD_TO_GREG_NO(_addr, _opc, 9, _sm, _mas); \
		break; \
	case 10: \
		SIMPLE_RECOVERY_LOAD_TO_GREG_NO(_addr, _opc, 10, _sm, _mas); \
		break; \
	case 11: \
		SIMPLE_RECOVERY_LOAD_TO_GREG_NO(_addr, _opc, 11, _sm, _mas); \
		break; \
	case 12: \
		SIMPLE_RECOVERY_LOAD_TO_GREG_NO(_addr, _opc, 12, _sm, _mas); \
		break; \
	case 13: \
		SIMPLE_RECOVERY_LOAD_TO_GREG_NO(_addr, _opc, 13, _sm, _mas); \
		break; \
	case 14: \
		SIMPLE_RECOVERY_LOAD_TO_GREG_NO(_addr, _opc, 14, _sm, _mas); \
		break; \
	case 15: \
		SIMPLE_RECOVERY_LOAD_TO_GREG_NO(_addr, _opc, 15, _sm, _mas); \
		break; \
	/* Do not load g16-g19 as they are used by kernel */ \
	case 16: \
	case 17: \
	case 18: \
	case 19: \
		break; \
	case 20: \
		SIMPLE_RECOVERY_LOAD_TO_GREG_NO(_addr, _opc, 20, _sm, _mas); \
		break; \
	case 21: \
		SIMPLE_RECOVERY_LOAD_TO_GREG_NO(_addr, _opc, 21, _sm, _mas); \
		break; \
	case 22: \
		SIMPLE_RECOVERY_LOAD_TO_GREG_NO(_addr, _opc, 22, _sm, _mas); \
		break; \
	case 23: \
		SIMPLE_RECOVERY_LOAD_TO_GREG_NO(_addr, _opc, 23, _sm, _mas); \
		break; \
	case 24: \
		SIMPLE_RECOVERY_LOAD_TO_GREG_NO(_addr, _opc, 24, _sm, _mas); \
		break; \
	case 25: \
		SIMPLE_RECOVERY_LOAD_TO_GREG_NO(_addr, _opc, 25, _sm, _mas); \
		break; \
	case 26: \
		SIMPLE_RECOVERY_LOAD_TO_GREG_NO(_addr, _opc, 26, _sm, _mas); \
		break; \
	case 27: \
		SIMPLE_RECOVERY_LOAD_TO_GREG_NO(_addr, _opc, 27, _sm, _mas); \
		break; \
	case 28: \
		SIMPLE_RECOVERY_LOAD_TO_GREG_NO(_addr, _opc, 28, _sm, _mas); \
		break; \
	case 29: \
		SIMPLE_RECOVERY_LOAD_TO_GREG_NO(_addr, _opc, 29, _sm, _mas); \
		break; \
	case 30: \
		SIMPLE_RECOVERY_LOAD_TO_GREG_NO(_addr, _opc, 30, _sm, _mas); \
		break; \
	case 31: \
		SIMPLE_RECOVERY_LOAD_TO_GREG_NO(_addr, _opc, 31, _sm, _mas); \
		break; \
	default: \
		panic("Invalid global register # %d\n", _greg_num); \
	} \
} while (0)

#define SIMPLE_RECOVERY_MOVE(_from, _to, _opc, _first_time, _sm, _mas) \
do { \
	u64 _data; \
	u32 _fmt = ((ldst_rec_op_t *) &_opc)->fmt; \
	u64 _ind = ((ldst_rec_op_t *) &_opc)->index; \
	__no_asm_inline(12) \
	asm ( \
		"{nop 1\n" \
		" cmpesb,0 %[fmt], 1, %%pred20\n" \
		" cmpesb,1 %[fmt], 2, %%pred21\n" \
		" cmpesb,3 %[fmt], 3, %%pred22\n" \
		" cmpesb,4 %[fmt], 4, %%pred23}\n" \
		"{nop 4\n" \
		" ldb" _sm ",0 %[from], %[ind], %[data], " \
			"mas=%[mas] ? %%pred20\n" \
		" ldh" _sm ",2 %[from], %[ind], %[data], " \
			"mas=%[mas] ? %%pred21\n" \
		" ldw" _sm ",3 %[from], %[ind], %[data], " \
			"mas=%[mas] ? %%pred22\n" \
		" ldd" _sm ",5 %[from], %[ind], %[data], " \
			"mas=%[mas] ? %%pred23}\n" \
		"{cmpesb,0 %[first_time], 0, %%pred19}\n" \
		"{pass %%pred19, @p0\n" \
		" pass %%pred20, @p1\n" \
		" pass %%pred21, @p2\n" \
		" pass %%pred22, @p3\n" \
		" landp @p0, @p1, @p4\n" \
		" pass @p4, %%pred20\n" \
		" landp @p0, @p2, @p5\n" \
		" pass @p5, %%pred21\n" \
		" landp @p0, @p3, @p6\n" \
		" pass @p6, %%pred22}\n" \
		"{pass %%pred19, @p0\n" \
		" pass %%pred23, @p1\n" \
		" landp @p0, ~@p1, @p4\n" \
		" pass @p4, %%pred23}\n" \
		"{stb,sm,2 %[to], 0, %[data] ? %%pred20\n" \
		" sth,sm,5 %[to], 0, %[data] ? %%pred21}\n" \
		"{stw,sm,2 %[to], 0, %[data] ? %%pred22\n" \
		" std,sm,5 %[to], 0, %[data] ? ~%%pred23}\n" \
		: [data] "=&r" (_data) \
		: [from] "r" (_from), [to] "r" (_to), \
		  [fmt] "r" (_fmt), [ind] "r" (_ind), \
		  [first_time] "r" (_first_time), [mas] "i" (_mas) \
		: "memory", "pred19", "pred20", "pred21", "pred22", "pred23" \
	); \
} while (0)

/* Since v6 this got replaced with "wait int=1,mem_mod=1" */
#define C1_WAIT_TRAP_V3() \
do { \
	__no_asm_inline(1) \
	asm volatile ("wait trap=1" ::: "memory"); \
} while (0)

#define C3_WAIT_TRAP_V3(__val, __phys_base, __st_core) \
do { \
	u64 _reg; \
	__no_asm_inline(14) \
	asm volatile ( \
		/* 1) Disable instruction prefetch */ \
		"mmurr %%mmu_cr, %[reg]\n" \
		"andnd %[reg], 0x800, %[reg]\n" /* clear mmu_cr.ipd */ \
		"{nop 3\n" \
		" mmurw %[reg], %%mmu_cr}\n" \
		"disp %%ctpr1, 1f\n" \
		"{wait all_c=1\n" \
		" ct %%ctpr1}\n" /* force Instruction Buffer to use new ipd */ \
		"1:\n" \
		/* 2) Disable %ctpr's */ \
		"rwd 0, %%ctpr1\n" \
		"rwd 0, %%ctpr2\n" \
		"rwd 0, %%ctpr3\n" \
		"wait all_c=1\n" \
		/* 3) Flush TLB and instruction cache (wait only for L1I \
		 * flush so that it does not flush stw + wait from under us) */ \
		"wait ma_c=1\n" \
		"std,2 0x0, %[addr_flush_icache], %[val_icache], mas=%[mas_icache]\n" \
		"std,2 0x0, %[addr_flush_tlb], %[val_tlb], mas=%[mas_tlb]\n" \
		"{wait fl_c=1\n" \
		/* 4) Make sure the actual disabling code lies in the same cache line */ \
		" ibranch 2f}\n" \
		".align 256\n" \
		"2:\n" \
		/* 5) Flush data cache (except L3 which is shared) */ \
		"std,2 0x0, %[addr_flush_cache], %[val_cache], mas=%[mas_cache]\n"  \
		"wait fl_c=1, ma_c=1\n" \
		/* 6) Disable the clock. We access SIC register by physical address \
		 * because we've just flushed TLB, and accessing by virtual address \
		 * would stall until all 4 page table levels are read into TLB. */ \
		ALTERNATIVE_1_ALTINSTR \
		/* CPU_HWBUG_C3_WAIT_MA_C version */ \
			"nop 7\n" \
			"nop 7\n" \
			"nop 7\n" \
			"nop 7\n" \
			"nop 7\n" \
			"nop 7\n" \
			"nop 7\n" \
			"nop 7\n" \
			"nop 1\n" \
			"wait ma_c=1\n" \
		ALTERNATIVE_2_OLDINSTR \
		/* Default version */ \
		ALTERNATIVE_3_FEATURE(%[cpu_hwbug_c3_wait_ma_c]) \
		ALTERNATIVE_1_ALTINSTR \
		/* CPU_HWBUG_C3_CREDITS_L3 version */ \
			"{stw %[phys_base], 0x120, %[val], mas=%[mas_ioaddr]\n" \
			" stw %[phys_base], 0x160, %[val], mas=%[mas_ioaddr]}\n" \
			"{stw %[phys_base], 0x1a0, %[val], mas=%[mas_ioaddr]\n" \
			" stw %[phys_base], 0x1e0, %[val], mas=%[mas_ioaddr]}\n" \
			"{stw %[phys_base], 0x220, %[val], mas=%[mas_ioaddr]\n" \
			" stw %[phys_base], 0x260, %[val], mas=%[mas_ioaddr]}\n" \
			"{stw %[phys_base], 0x2a0, %[val], mas=%[mas_ioaddr]\n" \
			" stw %[phys_base], 0x2e0, %[val], mas=%[mas_ioaddr]}\n" \
			"stw %[phys_base], %[st_core], %[val], mas=%[mas_ioaddr]\n" \
			"wait trap=1\n" \
		ALTERNATIVE_2_OLDINSTR \
		/* Default version */ \
			"stw %[phys_base], %[st_core], %[val], mas=%[mas_ioaddr]\n" \
			"wait trap=1\n" \
		ALTERNATIVE_3_FEATURE(%[cpu_hwbug_c3_credits_l3]) \
		/* Will never get here */ \
		: [reg] "=&r" (_reg) \
		: [val] "r" ((u32) (__val)), \
		  [phys_base] "r" ((u64) (__phys_base)), \
		  [st_core] "ir" ((u64) (__st_core)), \
		  [addr_flush_cache] "r" ((u64) (_FLUSH_WRITE_BACK_CACHE_L12_OP)), \
		  [val_cache] "r" (0ULL), \
		  [mas_cache] "i" (MAS_CACHE_FLUSH), \
		  [addr_flush_icache] "r" ((u64) (_FLUSH_ICACHE_ALL_OP)), \
		  [val_icache] "r" (0ULL), \
		  [mas_icache] "i" (MAS_ICACHE_FLUSH), \
		  [addr_flush_tlb] "r" ((u64) (_FLUSH_TLB_ALL_OP)), \
		  [val_tlb] "r" (0ULL), \
		  [mas_tlb] "i" (MAS_TLB_FLUSH), \
		  [mas_ioaddr] "i" (MAS_IOADDR), \
		  [cpu_hwbug_c3_wait_ma_c] "i" (CPU_HWBUG_C3_WAIT_MA_C), \
		  [cpu_hwbug_c3_credits_l3] "i" (CPU_HWBUG_C3_CREDITS_L3) \
		: "memory", "ctpr1", "ctpr2", "ctpr3"); \
} while (0)

/* Preparing to turn the synchoniztion clock off
 * by writing the value __val to register PMC pointed by __phys_addr */
#define C3_WAIT_INT_V6(__val, __phys_addr) \
do { \
	u64 _reg; \
	__no_asm_inline(14) \
	asm volatile ( \
		/* 1) Disable instruction prefetch */ \
		"mmurr %%mmu_cr, %[reg]\n" \
		"andnd %[reg], 0x800, %[reg]\n" /* clear mmu_cr.ipd */ \
		"mmurw %[reg], %%mmu_cr\n" \
		"{wait all_c=1\n" \
		" nop 3}\n" \
		"disp %%ctpr1, 1f\n" \
		"{wait all_c=1\n" \
		" ct %%ctpr1}\n" /* force Instruction Buffer to use new ipd */ \
		"1:\n" \
		/* 2) Disable %ctpr's */ \
		"rwd 0, %%ctpr1\n" \
		"rwd 0, %%ctpr2\n" \
		"rwd 0, %%ctpr3\n" \
		"wait all_c=1\n" \
		/* 3) Flush TLB and instruction cache */ \
		"wait ma_c=1\n" \
		"std,2 0x0, %[addr_flush_icache], %[val_icache], mas=%[mas_icache]\n" \
		"std,2 0x0, %[addr_flush_tlb], %[val_tlb], mas=%[mas_tlb]\n" \
		"{wait fl_c=1, ma_c=1\n" \
		/* 4) Make sure the actual disabling code lies in the same cache line */ \
		" ibranch 2f}\n" \
		".align 256\n" \
		"2:\n" \
		/* 5) Flush data cache (except L3 which is shared) */ \
		"std,2 0x0, %[addr_flush_cache], %[val_cache], mas=%[mas_cache]\n"  \
		"wait fl_c=1, ma_c=1\n" \
		/* 6) Disable the clock. We access SIC register by physical address \
		 * because we've just flushed TLB, and accessing by virtual address \
		 * would stall until all 4 page table levels are read into TLB. */ \
		"stw %[phys_addr], 0, %[val], mas=%[mas_ioaddr]\n" \
		"wait st_c=1, int=1\n" \
		/* 7) We are woken, reenable instruction prefetch */ \
		"mmurr %%mmu_cr, %[reg]\n" \
		"ord %[reg], 0x800, %[reg]\n" /* clear mmu_cr.ipd */ \
		"mmurw %[reg], %%mmu_cr\n" \
		"{wait all_c=1\n" \
		" nop 3}\n" \
		"disp %%ctpr1, 3f\n" \
		"{wait all_c=1\n" \
		" ct %%ctpr1}\n" /* force Instruction Buffer to use new ipd */ \
		"3:\n" \
		: [reg] "=&r" (_reg) \
		: [val] "r" ((u32) (__val)), \
		  [phys_addr] "r" ((u64) (__phys_addr)), \
		  [addr_flush_cache] "r" ((u64) (_FLUSH_WRITE_BACK_CACHE_L12_OP)), \
		  [val_cache] "r" (0ULL), \
		  [mas_cache] "i" (MAS_CACHE_FLUSH), \
		  [addr_flush_icache] "r" ((u64) (_FLUSH_ICACHE_ALL_OP)), \
		  [val_icache] "r" (0ULL), \
		  [mas_icache] "i" (MAS_ICACHE_FLUSH), \
		  [addr_flush_tlb] "r" ((u64) (_FLUSH_TLB_ALL_OP)), \
		  [val_tlb] "r" (0ULL), \
		  [mas_tlb] "i" (MAS_TLB_FLUSH), \
		  [mas_ioaddr] "i" (MAS_IOADDR) \
		  : "memory", "ctpr1", "ctpr2", "ctpr3"); \
} while (0)

#ifndef __ASSEMBLY__
/* Second part of entering S3 state; cannot be written in C because
 * all of the following MC registers writes must be done without any
 * accesses to RAM. */
static inline void s3_entry_complete_e2c3(int node, phys_addr_t node_nbsr,
		u64 cycles_10us, u64 cycles_100ns, e2k_mc_pwr_t mc_pwr,
		e2k_mc_ctl_t mc_ctl, e2k_mc_ch_t mc_ch_write,
		phys_addr_t addr_spmc_pm1_cnt, spmc_pm1_cnt_t pm1_cnt, u32 mcen)
{
	e2k_mc_ch_t mc_ch_read, mc_ch_read0 = (e2k_mc_ch_t) { .n = 0 };
	u64 reg, tmp;
	e2k_mc_ctl_t mc_ctl_2a, mc_ctl_2b, mc_ctl_2c, mc_ctl_2e;

	mc_ctl_2a = mc_ctl;
	mc_ctl_2a.phyinitreq = 0;

	mc_ctl_2b = mc_ctl_2a;
	mc_ctl_2b.dfi_freq = 0x1f;

	mc_ctl_2c = mc_ctl_2b;
	mc_ctl_2c.phyinitreq = 1;

	mc_ctl_2e = mc_ctl_2c;
	mc_ctl_2e.phyinitreq = 0;

	asm volatile (
		/* 1) Disable instruction prefetch and data caches
		 * (but instruction buffer will still work) */
		"mmurr %%mmu_cr, %[reg]\n"
		"andnd %[reg], 0x800, %[reg]\n" /* clear mmu_cr.ipd */
		"mmurw %[reg], %%mmu_cr\n"
		"{wait all_c=1\n"
		" nop 3}\n"
		"disp %%ctpr1, 1f\n"
		"{wait all_c=1\n"
		" ct %%ctpr1}\n" /* force Instruction Buffer to use new ipd */
		"1:\n"
		/* 2) Disable %ctpr's */
		"rwd 0, %%ctpr1\n"
		"rwd 0, %%ctpr2\n"
		"rwd 0, %%ctpr3\n"
		"wait all_c=1\n"
		/* 3) Flush TLB and instruction cache */
		"wait ma_c=1\n"
		"std,2 0x0, %[addr_flush_icache], %[val_icache], mas=%[mas_icache]\n"
		"std,2 0x0, %[addr_flush_tlb], %[val_tlb], mas=%[mas_tlb]\n"
		"{wait fl_c=1, ma_c=1\n"
		/* 4) Make sure the actual disabling code lies in the same cache line */
		" cmpedb 0, 0, %%pred1\n"
		" ibranch 2f}\n"
		/* CPU_HWBUG_CODE_PLACEMENT: make sure the critical code
		 * is not moved around, so use 4096 instead of 256 */
		".align 4096\n"
		"2:\n"
		/* Make sure second instruction cache line is also prefetched */
		"{wait ma_c=1\n"
		" ibranch 5f ? %%pred1}\n"
		/* 5) Enter the S3.  After wake up CPU will enter boot again. */
		/* SPMC 5.8 1c) Set MC_PWR and delay for 10 us.
		 * Memory accesses are prohibited from this point. */
		"{rrd %%clkr, %[tmp]\n"
		" stw 0, %[addr_mc_pwr], %[mc_pwr], mas=%[mas_ioaddr]}\n"
		"addd %[tmp], %[cycles_10us], %[tmp]\n"
		"3:\n"
		"rrd %%clkr, %[reg]\n"
		"cmpbdb %[reg], %[tmp], %%pred0\n"
		"ibranch 3b ? %%pred0\n"
		/* SPMC 5.8 2a) Clear MC_CTL.phyinitreq and delay for 100ns */
		"{rrd %%clkr, %[tmp]\n"
		" stw 0, %[addr_mc_ctl], %[mc_ctl_2a], mas=%[mas_ioaddr]}\n"
		"addd %[tmp], %[cycles_100ns], %[tmp]\n"
		"4:\n"
		"rrd %%clkr, %[reg]\n"
		"cmpbdb %[reg], %[tmp], %%pred0\n"
		"ibranch 4b ? %%pred0\n"
		/* SPMC 5.8 2b) Set MC_CTL.dfi_freq */
		"stw 0, %[addr_mc_ctl], %[mc_ctl_2b], mas=%[mas_ioaddr]\n"
		/* SPMC 5.8 2c) Set MC_CTL.phyinitreq */
		"stw 0, %[addr_mc_ctl], %[mc_ctl_2c], mas=%[mas_ioaddr]\n"
		/* The second instruction cache line must be prefetched already */
		"ibranch 5f\n"
		".align 256\n"
		"5:\n"
		"ibranch 10f ? %%pred1\n"
		/* SPMC 5.8 2d) Wait until MC_STATUS_E2K.phyinitdone=0 */
		"{addd %[mc_ch_read0], 0, %[mc_ch_read]\n"
		" adds %[mcen], 0, %[tmp]}\n"
		"6:\n"
		"{cmpesb %[tmp], 0, %%pred2\n"
		" cmpandesb %[tmp], 1, %%pred3}\n"
		"ibranch 9f ? %%pred2\n"
		"{ibranch 8f ? %%pred3\n"
		" stw 0, %[addr_mc_ch], %[mc_ch_read], mas=%[mas_ioaddr] ? ~ %%pred3}\n"
		"7:\n"
		"ldw,2 %[addr_mc_status], 0, %[reg], mas=%[mas_ioaddr]\n"
		"cmpandesb %[reg], 0x40, %%pred0\n"
		"ibranch 7b ? ~ %%pred0\n"
		"8:\n"
		"{shrs %[tmp], 1, %[tmp]\n"
		" adds %[mc_ch_read], 1, %[mc_ch_read]\n"
		" ibranch 6b}\n"
		"9:\n"
		/* SPMC 5.8 2e) Clear MC_CTL.phyinitreq */
		"stw 0, %[addr_mc_ch], %[mc_ch_write], mas=%[mas_ioaddr]\n"
		"stw 0, %[addr_mc_ctl], %[mc_ctl_2e], mas=%[mas_ioaddr]\n"
		/* Make sure third instruction cache line is also prefetched */
		"ibranch 10f\n"
		".align 256\n"
		"10:\n"
		"{cmpedb 0, 1, %%pred1 ? %%pred1\n"
		" ibranch 2b ? %%pred1}\n"
		/* SPMC 5.8 2f) Wait until MC_STATUS_E2K.phyinitdone=1 */
		"{addd %[mc_ch_read0], 0, %[mc_ch_read]\n"
		" adds %[mcen], 0, %[tmp]}\n"
		"11:\n"
		"{cmpesb %[tmp], 0, %%pred2\n"
		" cmpandesb %[tmp], 1, %%pred3}\n"
		"ibranch 14f ? %%pred2\n"
		"{ibranch 13f ? %%pred3\n"
		" stw 0, %[addr_mc_ch], %[mc_ch_read], mas=%[mas_ioaddr] ? ~ %%pred3}\n"
		"12:\n"
		"ldw,2 %[addr_mc_status], 0, %[reg], mas=%[mas_ioaddr]\n"
		"cmpandesb %[reg], 0x40, %%pred0\n"
		"ibranch 12b ? %%pred0\n"
		"13:\n"
		"{shrs %[tmp], 1, %[tmp]\n"
		" adds %[mc_ch_read], 1, %[mc_ch_read]\n"
		" ibranch 11b}\n"
		"14:\n"
		/* Sleep at last */
		"stw 0, %[addr_spmc_pm1_cnt], %[pm1_cnt], mas=%[mas_ioaddr]\n"
		: [reg] "=&r" (reg), [tmp] "=&r" (tmp),
		  [mc_ch_read] "=&r" (AW(mc_ch_read))
		: [addr_flush_cache] "r" ((u64) (_FLUSH_WRITE_BACK_CACHE_L12_OP)),
		  [val_cache] "r" (0ULL),
		  [mas_cache] "i" (MAS_CACHE_FLUSH),
		  [addr_flush_icache] "r" ((u64) (_FLUSH_ICACHE_ALL_OP)),
		  [val_icache] "r" (0ULL),
		  [mas_icache] "i" (MAS_ICACHE_FLUSH),
		  [addr_flush_tlb] "r" ((u64) (_FLUSH_TLB_ALL_OP)),
		  [val_tlb] "r" (0ULL),
		  [mas_tlb] "i" (MAS_TLB_FLUSH),
		  [mas_ioaddr] "i" (MAS_IOADDR),
		  [addr_mc_ch] "r" (node_nbsr + MC_CH),
		  [mc_ch_read0] "r" (AW(mc_ch_read0)),
		  [mc_ch_write] "r" (AW(mc_ch_write)),
		  [addr_mc_pwr] "r" (node_nbsr + MC_PWR),
		  [mc_pwr] "r" (AW(mc_pwr)),
		  [addr_mc_ctl] "r" (node_nbsr + MC_CTL),
		  [mc_ctl_2a] "r" (AW(mc_ctl_2a)),
		  [mc_ctl_2b] "r" (AW(mc_ctl_2b)),
		  [mc_ctl_2c] "r" (AW(mc_ctl_2c)),
		  [mc_ctl_2e] "r" (AW(mc_ctl_2e)),
		  [addr_mc_status] "r" (node_nbsr + MC_STATUS_E2K),
		  [addr_spmc_pm1_cnt] "r" (addr_spmc_pm1_cnt),
		  [pm1_cnt] "r" (pm1_cnt.reg),
		  [mcen] "r" ((u32) mcen),
		  [cycles_10us] "r" (cycles_10us),
		  [cycles_100ns] "r" (cycles_100ns)
		: "memory", "ctpr1", "ctpr2", "ctpr3",
		  "pred0", "pred1", "pred2", "pred3");
}
#endif

/* Hardware virtualized extensions support */
#define E2K_GLAUNCH(_ctpr1, _ctpr1_hi, _ctpr2, _ctpr2_hi, _ctpr3, _ctpr3_hi, \
		    _lsr, _lsr1, _ilcr, _ilcr1) \
do { \
	u32 __gl_core_mode; \
	u64 __gl_tmp1, __gl_tmp2; \
	__no_asm_inline(14) \
	asm volatile (ALTERNATIVE( \
		      /* Default version */ \
			"", \
		      /* CPU_HWBUG_RRSH_RWSH_CTPR version */ \
			".push_iset 7\n" \
			"rrs %%sh_core_mode, %[tmp1]\n" \
			".pop_iset\n" \
			"rrs %%core_mode, %[core_mode]\n" \
			/* Get %sh_core_mode.descr_v7 */ \
			"{ands %[core_mode], ~0x80, %[tmp2]\n" \
			" getfzs %[tmp1], 0xe200, %[tmp1]}\n" \
			"ors %[tmp1], %[tmp2], %[tmp1]\n" \
			"rws %[tmp1], %%core_mode\n" \
			"wait all_e=1\n", \
		      %[cpu_hwbug_rrsh_rwsh_ctpr]) \
		      ALTERNATIVE( \
		      /* Default version */ \
			"{rwd %[ctpr1], %%ctpr1}\n" \
			"{rwd %[ctpr1_hi], %%ctpr1.hi}\n" \
			"{rwd %[ctpr3], %%ctpr3}\n" \
			"{rwd %[ctpr3_hi], %%ctpr3.hi}\n", \
		      /* CPU_FEAT_V7_CPU_REGS version */ \
			".push_iset 7\n" \
			"{rwshd %[ctpr1], %%ctpr1}\n" \
			"{rwshd %[ctpr1_hi], %%ctpr1.hi}\n" \
			"{rwshd %[ctpr3], %%ctpr3}\n" \
			"{rwshd %[ctpr3_hi], %%ctpr3.hi}\n" \
			".pop_iset\n", \
		      %[cpu_feat_v7_cpu_regs]) \
		      ALTERNATIVE( \
		      /* Default version */ \
			"", \
		      /* CPU_HWBUG_RRSH_RWSH_CTPR version */ \
			"wait all_e=1\n" \
			"rws %[core_mode], %%core_mode\n" \
			"wait all_e=1\n", \
		      %[cpu_hwbug_rrsh_rwsh_ctpr]) \
		      "{rwd %[lsr], %%lsr}\n" \
		      "{rwd %[lsr1], %%lsr1}\n" \
		      "{rwd %[ilcr], %%ilcr}\n" \
		      "{rwd %[ilcr1], %%ilcr1}\n" \
		      /* #80747: must repeat interrupted barriers */ \
		      "{wait st_c=1,all_e=1}\n" \
		      "{glaunch}\n" \
		      "{wait fl_c=1\n" \
		      " rrd %%lsr, %[lsr]}\n" \
		      "{rrd %%ilcr, %[ilcr]}\n" \
		      "{rrd %%lsr1, %[lsr1]}\n" \
		      "{rrd %%ilcr1, %[ilcr1]}\n" \
		      ALTERNATIVE( \
		      /* Default version */ \
			"", \
		      /* CPU_HWBUG_RRSH_RWSH_CTPR version */ \
			".push_iset 7\n" \
			"rrs %%sh_core_mode, %[tmp1]\n" \
			".pop_iset\n" \
			"rrs %%core_mode, %[core_mode]\n" \
			/* Get %sh_core_mode.descr_v7 */ \
			"{ands %[core_mode], ~0x80, %[tmp2]\n" \
			" getfzs %[tmp1], 0xe200, %[tmp1]}\n" \
			"ors %[tmp1], %[tmp2], %[tmp1]\n" \
			"rws %[tmp1], %%core_mode\n" \
			"wait all_e=1\n", \
		      %[cpu_hwbug_rrsh_rwsh_ctpr]) \
		      ALTERNATIVE( \
		      /* Default version */ \
			"{rrd %%ctpr1, %[ctpr1]}\n" \
			"{rrd %%ctpr1.hi, %[ctpr1_hi]}\n" \
			"{rrd %%ctpr2, %[ctpr2]}\n" \
			"{rrd %%ctpr2.hi, %[ctpr2_hi]}\n" \
			"{rrd %%ctpr3, %[ctpr3]}\n" \
			"{rrd %%ctpr3.hi, %[ctpr3_hi]}\n", \
		      /* CPU_FEAT_V7_CPU_REGS version */ \
			".push_iset 7\n" \
			"{rrshd %%ctpr1, %[ctpr1]}\n" \
			"{rrshd %%ctpr1.hi, %[ctpr1_hi]}\n" \
			"{rrshd %%ctpr2, %[ctpr2]}\n" \
			"{rrshd %%ctpr2.hi, %[ctpr2_hi]}\n" \
			"{rrshd %%ctpr3, %[ctpr3]}\n" \
			"{rrshd %%ctpr3.hi, %[ctpr3_hi]}\n" \
			".pop_iset\n", \
		      %[cpu_feat_v7_cpu_regs]) \
		      ALTERNATIVE( \
		      /* Default version */ \
			"", \
		      /* CPU_HWBUG_RRSH_RWSH_CTPR version */ \
			"wait all_e=1\n" \
			"rws %[core_mode], %%core_mode\n" \
			"wait all_e=1\n", \
		      %[cpu_hwbug_rrsh_rwsh_ctpr]) \
		      /* CPU_HWBUG_BRANCH_ACTIVATES_CTPR: avoid rbranch, ibranch \
		       * and ibranchd instructions until all %ctpr[.hi] registers \
		       * have been read */ \
		      ALTERNATIVE_1_ALTINSTR \
		      /* CPU_HWBUG_L1I_STOPS_WORKING version */ \
			      NONTARGET_LABEL("1") "\n" \
			      "{ipd 0; disp %%ctpr1, 1b}" \
			      /* ctpr2 will be cleared after saving AAU */ \
			      "{ipd 0; disp %%ctpr3, 1b}" \
		      ALTERNATIVE_2_OLDINSTR \
		      /* Default version */ \
			      "{nop}" \
		      ALTERNATIVE_3_FEATURE(%[cpu_hwbug_l1i_stops_working]) \
		      : [lsr] "+r" (_lsr), [lsr1] "+r" (_lsr1), \
			[ilcr] "+r" (_ilcr), [ilcr1] "+r" (_ilcr1), \
			[ctpr1] "+r" (_ctpr1), [ctpr1_hi] "+r" (_ctpr1_hi), \
			[ctpr2] "+r" (_ctpr2), [ctpr2_hi] "+r" (_ctpr2_hi), \
			[ctpr3] "+r" (_ctpr3), [ctpr3_hi] "+r" (_ctpr3_hi), \
			[core_mode] "=&r" (__gl_core_mode), \
			[tmp1] "=&r" (__gl_tmp1), [tmp2] "=&r" (__gl_tmp2) \
		      : [cpu_hwbug_l1i_stops_working] "i" (CPU_HWBUG_L1I_STOPS_WORKING), \
			[cpu_feat_v7_cpu_regs] "i" (CPU_FEAT_V7_CPU_REGS), \
			[cpu_hwbug_rrsh_rwsh_ctpr] "i" (CPU_HWBUG_RRSH_RWSH_CTPR) \
		      : "memory", "b[1]", "b[3]", "ctpr1", "ctpr2", "ctpr3"); \
} while (0)


#define __E2K_CALL_PTR_0(_fn) \
({ \
	register u64 __res; \
	__asm_length(3) \
	asm volatile ( \
		"movtd %[fn], %%ctpr1\n" \
		"call %%ctpr1, wbs = %#\n" \
		"addd 0x0, %%b[0], %[res]\n" \
		: [res] "=r" (__res) \
		: [fn] "ir" (_fn) \
		: "call"); \
	__res; \
})

#define __E2K_CALL_PTR_1(_fn, _arg0) \
({ \
	register u64 __res; \
	__asm_length(3) \
	asm volatile ( \
		"{addd 0x0, %[arg0], %%b[0]\n" \
		" movtd %[fn], %%ctpr1}\n" \
		"call %%ctpr1, wbs = %#\n\t" \
		"addd 0x0, %%b[0], %[res]" \
		: [res] "=r" (__res) \
		: [arg0] "ri" ((u64) (_arg0)), [fn] "ir" (_fn) \
		: "call"); \
	__res; \
})

#define __E2K_CALL_PTR_2(_fn, _arg0, _arg1) \
({ \
	register u64 __res; \
	__asm_length(3) \
	asm volatile ( \
		"{addd 0x0, %[arg0], %%b[0]\n\t" \
		" addd 0x0, %[arg1], %%b[1]\n\t" \
		" movtd %[fn], %%ctpr1}\n" \
		"call %%ctpr1, wbs = %#\n\t" \
		"addd 0x0, %%b[0], %[res]" \
		: [res] "=r" (__res) \
		: [arg0] "ri" ((u64) (_arg0)), [arg1] "ri" ((u64) (_arg1)), \
		  [fn] "ir" (_fn) \
		: "call"); \
	__res; \
})

#define __E2K_CALL_PTR_3(_fn, _arg0, _arg1, _arg2) \
({ \
	register u64 __res; \
	__asm_length(3) \
	asm volatile ( \
		"{addd 0x0, %[arg0], %%b[0]\n" \
		" addd 0x0, %[arg1], %%b[1]\n" \
		" addd 0x0, %[arg2], %%b[2]\n" \
		" movtd %[fn], %%ctpr1}\n" \
		"call %%ctpr1, wbs = %#\n" \
		"addd 0x0, %%b[0], %[res]" \
		: [res] "=r" (__res) \
		: [arg0] "ri" ((u64) (_arg0)), [arg1] "ri" ((u64) (_arg1)), \
		  [arg2] "ri" ((u64) (_arg2)), [fn] "ir" (_fn) \
		: "call"); \
	__res; \
})

#define __E2K_CALL_PTR_4(_fn, _arg0, _arg1, _arg2, _arg3) \
({ \
	register u64 __res; \
	__asm_length(3) \
	asm volatile ( \
		"{addd 0x0, %[arg0], %%b[0]\n\t" \
		" addd 0x0, %[arg1], %%b[1]\n\t" \
		" addd 0x0, %[arg2], %%b[2]\n\t" \
		" addd 0x0, %[arg3], %%b[3]\n\t" \
		" movtd %[fn], %%ctpr1}\n" \
		"call %%ctpr1, wbs = %#\n" \
		"addd 0x0, %%b[0], %[res]" \
		: [res] "=r" (__res) \
		: [arg0] "ri" ((u64) (_arg0)), [arg1] "ri" ((u64) (_arg1)), \
		  [arg2] "ri" ((u64) (_arg2)), [arg3] "ri" ((u64) (_arg3)), \
		  [fn] "ir" (_fn) \
		: "call"); \
	__res; \
})

#define __E2K_CALL_PTR_5(_fn, _arg0, _arg1, _arg2, _arg3, _arg4) \
({ \
	register u64 __res; \
	__asm_length(3) \
	asm volatile ( \
		"{addd 0x0, %[arg0], %%b[0]\n" \
		" addd 0x0, %[arg1], %%b[1]\n" \
		" addd 0x0, %[arg2], %%b[2]\n" \
		" addd 0x0, %[arg3], %%b[3]\n" \
		" addd 0x0, %[arg4], %%b[4]\n" \
		" movtd %[fn], %%ctpr1}\n" \
		"call %%ctpr1, wbs = %#\n" \
		"addd 0x0, %%b[0], %[res]" \
		: [res] "=r" (__res) \
		: [arg0] "ri" ((u64) (_arg0)), [arg1] "ri" ((u64) (_arg1)), \
		  [arg2] "ri" ((u64) (_arg2)), [arg3] "ri" ((u64) (_arg3)), \
		  [arg4] "ri" ((u64) (_arg4)), [fn] "ir" (_fn) \
		: "call"); \
	__res; \
})

#define __E2K_CALL_PTR_6(_fn, _arg0, _arg1, _arg2, _arg3, _arg4, _arg5) \
({ \
	register u64 __res; \
	__asm_length(3) \
	asm volatile ( \
		"{addd 0x0, %[arg0], %%b[0]\n" \
		" addd 0x0, %[arg1], %%b[1]\n" \
		" addd 0x0, %[arg2], %%b[2]\n" \
		" addd 0x0, %[arg3], %%b[3]\n" \
		" addd 0x0, %[arg4], %%b[4]\n" \
		" addd 0x0, %[arg5], %%b[5]\n" \
		" movtd %[fn], %%ctpr1}\n" \
		"call %%ctpr1, wbs = %#\n" \
		"addd 0x0, %%b[0], %[res]" \
		: [res] "=r" (__res) \
		: [arg0] "ri" ((u64) (_arg0)), [arg1] "ri" ((u64) (_arg1)), \
		  [arg2] "ri" ((u64) (_arg2)), [arg3] "ri" ((u64) (_arg3)), \
		  [arg4] "ri" ((u64) (_arg4)), [arg5] "ri" ((u64) (_arg5)), \
		  [fn] "ir" (_fn) \
		: "call"); \
	__res; \
})

#define __E2K_CALL_PTR_7(_fn, _arg0, _arg1, _arg2, _arg3, _arg4, _arg5, _arg6) \
({ \
	register u64 __res; \
	__asm_length(3) \
	asm volatile ( \
		"{addd 0x0, %[arg0], %%b[0]\n" \
		" addd 0x0, %[arg1], %%b[1]\n" \
		" addd 0x0, %[arg2], %%b[2]\n" \
		" addd 0x0, %[arg3], %%b[3]\n" \
		" addd 0x0, %[arg4], %%b[4]\n" \
		" addd 0x0, %[arg5], %%b[5]\n" \
		" movtd %[fn], %%ctpr1}\n" \
		"{addd 0x0, %[arg6], %%b[6]\n" \
		" call %%ctpr1, wbs = %#}\n" \
		"addd 0x0, %%b[0], %[res]" \
		: [res] "=r" (__res) \
		: [arg0] "ri" ((u64) (_arg0)), [arg1] "ri" ((u64) (_arg1)), \
		  [arg2] "ri" ((u64) (_arg2)), [arg3] "ri" ((u64) (_arg3)), \
		  [arg4] "ri" ((u64) (_arg4)), [arg5] "ri" ((u64) (_arg5)) \
		  [arg6] "ri" ((u64) (_arg6)), [fn] "ir" (_fn) \
		: "call"); \
	__res; \
})

#define E2K_CALL_PTR(fn, num_args, args...) \
	__E2K_CALL_PTR_##num_args(fn, args)


/* Clobbers "ctpr" are here to tell lcc that there is a call inside */
#define E2K_HCALL_CLOBBERS \
		"ctpr1", "ctpr2", "ctpr3", \
		"b[0]", "b[1]", "b[2]", "b[3]", \
		"b[4]", "b[5]", "b[6]", "b[7]"

#define __E2K_HCALL_0(_trap, _sys_num, _arg1) \
({ \
	register u64 __res; \
	__asm_length(3) \
	asm volatile ( \
		"addd 0x0, %[sys_num], %%b[0]\n\t" \
		"{\n" \
		"hcall %[trap], wbs = %#\n\t" \
		"}\n" \
		"addd 0x0, %%b[0], %[res]" \
		: [res]     "=r" (__res) \
		: [trap]    "i"  ((int) (_trap)), \
		  [sys_num] "ri" ((u64) (_sys_num)) \
		: E2K_HCALL_CLOBBERS); \
	__res; \
})

#define __E2K_HCALL_1(_trap, _sys_num, _arg1) \
({ \
	register u64 __res; \
	__asm_length(3) \
	asm volatile ("{\n" \
		"addd 0x0, %[sys_num], %%b[0]\n\t" \
		"addd 0x0, %[arg1], %%b[1]\n\t" \
		"}\n" \
		"{\n" \
		"hcall %[trap], wbs = %#\n\t" \
		"}\n" \
		"addd 0x0, %%b[0], %[res]" \
		: [res]     "=r" (__res) \
		: [trap]    "i"  ((int) (_trap)), \
		  [sys_num] "ri" ((u64) (_sys_num)), \
		  [arg1]    "ri" ((u64) (_arg1)) \
		: E2K_HCALL_CLOBBERS); \
	__res; \
})

#define __E2K_HCALL_2(_trap, _sys_num, _arg1, _arg2) \
({ \
	register u64 __res; \
	__asm_length(3) \
	asm volatile ("{\n" \
		"addd 0x0, %[sys_num], %%b[0]\n\t" \
		"addd 0x0, %[arg1], %%b[1]\n\t" \
		"addd 0x0, %[arg2], %%b[2]\n\t" \
		"}\n" \
		"{\n" \
		"hcall %[trap], wbs = %#\n\t" \
		"}\n" \
		"addd 0x0, %%b[0], %[res]" \
		: [res]     "=r" (__res) \
		: [trap]    "i"  ((int) (_trap)), \
		  [sys_num] "ri" ((u64) (_sys_num)), \
		  [arg1]    "ri" ((u64) (_arg1)), \
		  [arg2]    "ri" ((u64) (_arg2)) \
		: E2K_HCALL_CLOBBERS); \
	__res; \
})

#define __E2K_HCALL_3(_trap, _sys_num, _arg1, _arg2, _arg3) \
({ \
	register u64 __res; \
	__asm_length(3) \
	asm volatile ("{\n" \
		"addd 0x0, %[sys_num], %%b[0]\n\t" \
		"addd 0x0, %[arg1], %%b[1]\n\t" \
		"addd 0x0, %[arg2], %%b[2]\n\t" \
		"addd 0x0, %[arg3], %%b[3]\n\t" \
		"}\n" \
		"{\n" \
		"hcall %[trap], wbs = %#\n\t" \
		"}\n" \
		"addd 0x0, %%b[0], %[res]" \
		: [res]     "=r" (__res) \
		: [trap]    "i"  ((int) (_trap)), \
		  [sys_num] "ri" ((u64) (_sys_num)), \
		  [arg1]    "ri" ((u64) (_arg1)), \
		  [arg2]    "ri" ((u64) (_arg2)), \
		  [arg3]    "ri" ((u64) (_arg3)) \
		: E2K_HCALL_CLOBBERS); \
	__res; \
})

#define __E2K_HCALL_4(_trap, _sys_num, _arg1, _arg2, _arg3, _arg4) \
({ \
	register u64 __res; \
	__asm_length(3) \
	asm volatile ("{\n" \
		"addd 0x0, %[sys_num], %%b[0]\n\t" \
		"addd 0x0, %[arg1], %%b[1]\n\t" \
		"addd 0x0, %[arg2], %%b[2]\n\t" \
		"addd 0x0, %[arg3], %%b[3]\n\t" \
		"addd 0x0, %[arg4], %%b[4]\n\t" \
		"}\n" \
		"{\n" \
		"hcall %[trap], wbs = %#\n\t" \
		"}\n" \
		"addd 0x0, %%b[0], %[res]" \
		: [res]     "=r" (__res) \
		: [trap]    "i"  ((int) (_trap)), \
		 [sys_num] "ri" ((u64) (_sys_num)), \
		 [arg1]    "ri" ((u64) (_arg1)), \
		 [arg2]    "ri" ((u64) (_arg2)), \
		 [arg3]    "ri" ((u64) (_arg3)), \
		 [arg4]    "ri" ((u64) (_arg4)) \
		: E2K_HCALL_CLOBBERS); \
	__res; \
})

#define __E2K_HCALL_5(_trap, _sys_num, _arg1, _arg2, _arg3, _arg4, _arg5) \
({ \
	register u64 __res; \
	__asm_length(3) \
	asm volatile ("{\n" \
		"addd 0x0, %[sys_num], %%b[0]\n\t" \
		"addd 0x0, %[arg1], %%b[1]\n\t" \
		"addd 0x0, %[arg2], %%b[2]\n\t" \
		"addd 0x0, %[arg3], %%b[3]\n\t" \
		"addd 0x0, %[arg4], %%b[4]\n\t" \
		"addd 0x0, %[arg5], %%b[5]\n\t" \
		"}\n" \
		"{\n" \
		"hcall %[trap], wbs = %#\n\t" \
		"}\n" \
		"addd 0x0, %%b[0], %[res]" \
		: [res]     "=r" (__res) \
		: [trap]    "i"  ((int) (_trap)), \
		  [sys_num] "ri" ((u64) (_sys_num)), \
		  [arg1]    "ri" ((u64) (_arg1)), \
		  [arg2]    "ri" ((u64) (_arg2)), \
		  [arg3]    "ri" ((u64) (_arg3)), \
		  [arg4]    "ri" ((u64) (_arg4)), \
		  [arg5]    "ri" ((u64) (_arg5)) \
		: E2K_HCALL_CLOBBERS); \
	__res; \
})

#define __E2K_HCALL_6(_trap, _sys_num, _arg1, \
			_arg2, _arg3, _arg4, _arg5, _arg6) \
({ \
	register u64 __res; \
	__asm_length(4) \
	asm volatile ( \
		"addd 0x0, %[sys_num], %%b[0]\n\t" \
		"{\n" \
		"addd 0x0, %[arg1], %%b[1]\n\t" \
		"addd 0x0, %[arg2], %%b[2]\n\t" \
		"addd 0x0, %[arg3], %%b[3]\n\t" \
		"addd 0x0, %[arg4], %%b[4]\n\t" \
		"addd 0x0, %[arg5], %%b[5]\n\t" \
		"addd 0x0, %[arg6], %%b[6]\n\t" \
		"}\n" \
		"{\n" \
		"hcall %[trap], wbs = %#\n\t" \
		"}\n" \
		"addd 0x0, %%b[0], %[res]" \
		: [res]     "=r" (__res) \
		: [trap]    "i"  ((int) (_trap)), \
		  [sys_num] "ri" ((u64) (_sys_num)), \
		  [arg1]    "ri" ((u64) (_arg1)), \
		  [arg2]    "ri" ((u64) (_arg2)), \
		  [arg3]    "ri" ((u64) (_arg3)), \
		  [arg4]    "ri" ((u64) (_arg4)), \
		  [arg5]    "ri" ((u64) (_arg5)), \
		  [arg6]    "ri" ((u64) (_arg6)) \
		: E2K_HCALL_CLOBBERS); \
	__res; \
})

#define __E2K_HCALL_7(_trap, _sys_num, _arg1, \
			_arg2, _arg3, _arg4, _arg5, _arg6, _arg7) \
({ \
	register u64 __res; \
	__asm_length(4) \
	asm volatile ("{\n" \
		"addd 0x0, %[sys_num], %%b[0]\n\t" \
		"addd 0x0, %[arg1], %%b[1]\n\t" \
		"addd 0x0, %[arg2], %%b[2]\n\t" \
		"addd 0x0, %[arg3], %%b[3]\n\t" \
		"addd 0x0, %[arg4], %%b[4]\n\t" \
		"addd 0x0, %[arg5], %%b[5]\n\t" \
		"}\n" \
		"{\n" \
		"addd 0x0, %[arg6], %%b[6]\n\t" \
		"addd 0x0, %[arg7], %%b[7]\n\t" \
		"}\n" \
		"{\n" \
		"hcall %[trap], wbs = %#\n\t" \
		"}\n" \
		"addd 0x0, %%b[0], %[res]" \
		: [res]     "=r" (__res) \
		: [trap]    "i"  ((int) (_trap)), \
		  [sys_num] "ri" ((u64) (_sys_num)), \
		  [arg1]    "ri" ((u64) (_arg1)), \
		  [arg2]    "ri" ((u64) (_arg2)), \
		  [arg3]    "ri" ((u64) (_arg3)), \
		  [arg4]    "ri" ((u64) (_arg4)), \
		  [arg5]    "ri" ((u64) (_arg5)), \
		  [arg6]    "ri" ((u64) (_arg6)), \
		  [arg7]    "ri" ((u64) (_arg7)) \
		: E2K_HCALL_CLOBBERS); \
	__res; \
})

#define E2K_HCALL(trap, sys_num, num_args, args...) \
	__E2K_HCALL_##num_args(trap, sys_num, args)


/* Clobbers "ctpr" are here to tell lcc that there is a return inside */
#define E2K_HRET_CLOBBERS  "ctpr1", "ctpr2", "ctpr3"

#define E2K_HRET_READ_INTC_PTR_CU \
	".word 0x04100011\n" /* rrd,0 %intc_ptr_cu, %dr0 */ \
	".word 0x3f65c080\n" \
	".word 0x01c00000\n" \
	".word 0x00000000\n"

#define E2K_HRET_CLEAR_INTC_INFO_CU \
	".word 0x04100291\n" /* nop 5 */ \
	".word 0x3dc0c064\n" /* rwd,0 0x0, %intc_info_cu */ \
	".word 0x01c00000\n" \
	".word 0x00000000\n"

#define E2K_HRET(_ret) \
do { \
	__asm_length(2) \
	asm volatile ( \
		ALTERNATIVE_1_ALTINSTR \
		/* CPU_HWBUG_HRET_INTC_CU version */ \
			E2K_HRET_READ_INTC_PTR_CU \
			E2K_HRET_CLEAR_INTC_INFO_CU \
			E2K_HRET_CLEAR_INTC_INFO_CU \
			E2K_HRET_READ_INTC_PTR_CU \
		ALTERNATIVE_2_OLDINSTR \
		/* Default version */ \
		ALTERNATIVE_3_FEATURE(%[cpu_hwbug_hret_intc_cu]) \
		"addd 0x0, %[ret], %%r0\n" \
		"{.word 0x00005012\n" /* HRET */ \
		" .word 0xc0000020\n" \
		" .word 0x30000003\n" \
		" .word 0x00000000}\n" \
		: \
		: [cpu_hwbug_hret_intc_cu] "i" (CPU_HWBUG_HRET_INTC_CU), \
		  [ret] "ir" (_ret) \
		: E2K_HRET_CLOBBERS); \
	unreachable(); \
} while (0)

#define __arch_this_cpu_read(_var, size) \
({ \
	typeof(_var) __ret; \
	__no_asm_inline(1) \
	asm ("ld" size " %%dg" __stringify(MY_CPU_OFFSET_GREG) ", %[var], %[ret]" \
				: [ret] "=r" (__ret) \
				: [var] "r" (&(_var)) \
				: "memory"); \
	__ret; \
})

#define __arch_this_cpu_write(_var, _val, size) \
do { \
	int unused; \
	__no_asm_inline(1) \
	asm ("st" size " %%dg" __stringify(MY_CPU_OFFSET_GREG) ", %[var], %[val]" \
				: "=r" (unused) /* Prevent automatic volatile */ \
				: [var] "r" (&(_var)), [val] "r" (_val) \
				: "memory"); \
} while (0)

/* Use relaxed atomics for percpu if they are available */
#if CONFIG_CPU_ISET_MIN >= 5

# define __arch_pcpu_atomic_xchg(_val, _var, size) \
({ \
	typeof(_var) __ret; \
	ASM_LENGTH_V6_V7(6, 5) \
	asm NOT_VOLATILE ( \
		BEFORE_ATOMIC("1:", RELAXED_MB, no_atomic_spurious_fault) \
		ALTERNATIVE_2( \
		/* Default version - 6 cycles ld->st delay */ \
			"{nop 5\n" \
			" ld" size ",0 %%dg" __stringify(MY_CPU_OFFSET_GREG) \
				", %[var], %[ret], mas=0x7}\n", \
		/* CPU_FEAT_ISET_V6 - 7 cycles ld->st delay */ \
			"{nop 6\n" \
			" ld" size ",0 %%dg" __stringify(MY_CPU_OFFSET_GREG) \
				", %[var], %[ret], mas=0x7}\n", \
			%[iset_v6], \
		/* CPU_FEAT_ISET_V7 - 5 cycles ld->st delay */ \
			"{nop 4\n" \
			" ld" size ",0 %%dg" __stringify(MY_CPU_OFFSET_GREG) \
				", %[var], %[ret], mas=0x7}\n", \
			%[iset_v7] \
		) \
		"{st" size "," RELAXED_MB_ATOMIC_CHANNEL "%%dg" __stringify(MY_CPU_OFFSET_GREG) \
			", %[var], %[val], mas=" RELAXED_MB_ATOMIC_MAS "\n" \
		" ibranch 1b ? %%MLOCK}\n" \
		MB_AFTER_ATOMIC_RELAXED_MB \
		: [ret] "=&r" (__ret) \
		: [var] "r" (&(_var)), [val] "r" ((u64) (_val)), \
		  [iset_v6] "i" (CPU_FEAT_ISET_V6), \
		  [iset_v7] "i" (CPU_FEAT_ISET_V7), \
		  [no_atomic_spurious_fault] "i" (CPU_NO_HWBUG_ATOMIC_SPURIOUS_FAULT) \
		: "memory"); \
	__ret; \
})

# define __arch_pcpu_atomic_cmpxchg(_old, _new, _var, size, sxt_size) \
({ \
	typeof(_var) __ret, __stored_val; \
	ASM_LENGTH_V5_V6(11, 12) \
	asm NOT_VOLATILE ( \
		BEFORE_ATOMIC("3:", RELAXED_MB, no_atomic_spurious_fault) \
		ALTERNATIVE( \
		/* Default version - 10 cycles ld->st delay */ \
			"{nop 5\n" \
			" ld" size ",0 %%dg" __stringify(MY_CPU_OFFSET_GREG) \
				", %[var], %[ret], mas=0x7}\n", \
		/* CPU_FEAT_ISET_V6 - 11 cycles ld->st delay */ \
			"{nop 6\n" \
			" ld" size ",0 %%dg" __stringify(MY_CPU_OFFSET_GREG) \
				", %[var], %[ret], mas=0x7}\n", \
		%[iset_v6]) \
		"{sxt "#sxt_size", %[ret], %[ret]}\n" \
		"{nop 1\n" \
		" cmpedb %[ret], %[old], %%pred2}\n" \
		"{merged %[ret], %[new], %[stored_val], %%pred2}\n" \
		"{st" size "," RELAXED_MB_ATOMIC_CHANNEL "%%dg" __stringify(MY_CPU_OFFSET_GREG) \
			", %[var], %[stored_val], mas=" RELAXED_MB_ATOMIC_MAS "\n" \
		" ibranch 3b ? %%MLOCK}\n" \
		MB_AFTER_ATOMIC_RELAXED_MB \
		: [ret] "=&r" (__ret), [stored_val] "=&r" (__stored_val) \
		: [var] "r" (&(_var)), [new] "ir" (_new), [old] "ir" (_old), \
		  [iset_v6] "i" (CPU_FEAT_ISET_V6), \
		  [no_atomic_spurious_fault] "i" (CPU_NO_HWBUG_ATOMIC_SPURIOUS_FAULT) \
		: "memory", "pred2"); \
	__ret; \
})

# define __arch_pcpu_atomic_cmpxchg_word(_old, _new, _var) \
({ \
	typeof(_var) __ret, __stored_val; \
	ASM_LENGTH_V5_V6(11, 12) \
	asm NOT_VOLATILE ( \
		BEFORE_ATOMIC("3:", RELAXED_MB, no_atomic_spurious_fault) \
		ALTERNATIVE( \
		/* Default version - 10 cycles ld->st delay */ \
			"{nop 6\n"\
			" ldw,0 %%dg" __stringify(MY_CPU_OFFSET_GREG) \
				", %[var], %[ret], mas=0x7}\n" \
		/* CPU_FEAT_ISET_V6 - 11 cycles ld->st delay */ \
			"{nop 7\n"\
			" ldw,0 %%dg" __stringify(MY_CPU_OFFSET_GREG) \
				", %[var], %[ret], mas=0x7}\n" \
		%[iset_v6]) \
		"{nop 1\n"\
		" cmpesb %[ret], %[old], %%pred2}\n" \
		"{merges %[ret], %[new], %[stored_val], %%pred2}\n" \
		"{stw," RELAXED_MB_ATOMIC_CHANNEL "%%dg" __stringify(MY_CPU_OFFSET_GREG) \
			", %[var], %[stored_val], mas=" RELAXED_MB_ATOMIC_MAS "\n" \
		" ibranch 3b ? %%MLOCK}\n" \
		MB_AFTER_ATOMIC_RELAXED_MB \
		: [ret] "=&r" (__ret), [stored_val] "=&r" (__stored_val) \
		: [var] "r" (&(_var)), [new] "ir" (_new), [old] "ir" (_old), \
		  [iset_v6] "i" (CPU_FEAT_ISET_V6), \
		  [no_atomic_spurious_fault] "i" (CPU_NO_HWBUG_ATOMIC_SPURIOUS_FAULT) \
		: "memory", "pred2"); \
	__ret; \
})

# define __arch_pcpu_atomic_cmpxchg_dword(_old, _new, _var) \
({ \
	typeof(_var) __ret, __stored_val; \
	ASM_LENGTH_V5_V6(11, 12) \
	asm NOT_VOLATILE ( \
		BEFORE_ATOMIC("3:", RELAXED_MB, no_atomic_spurious_fault) \
		ALTERNATIVE( \
		/* Default version - 10 cycles ld->st delay */ \
			"{nop 6\n"\
			" ldd,0 %%dg" __stringify(MY_CPU_OFFSET_GREG) \
				", %[var], %[ret], mas=0x7}\n", \
		/* CPU_FEAT_ISET_V6 - 11 cycles ld->st delay */ \
			"{nop 7\n"\
			" ldd,0 %%dg" __stringify(MY_CPU_OFFSET_GREG) \
				", %[var], %[ret], mas=0x7}\n", \
		%[iset_v6]) \
		"{nop 1\n"\
		" cmpedb %[ret], %[old], %%pred2}\n" \
		"{merged %[ret], %[new], %[stored_val], %%pred2}\n" \
		"{std," RELAXED_MB_ATOMIC_CHANNEL "%%dg" __stringify(MY_CPU_OFFSET_GREG) \
			", %[var], %[stored_val], mas=" RELAXED_MB_ATOMIC_MAS "\n" \
		" ibranch 3b ? %%MLOCK}\n" \
		MB_AFTER_ATOMIC_RELAXED_MB \
		: [ret] "=&r" (__ret), [stored_val] "=&r" (__stored_val) \
		: [var] "r" (&(_var)), [new] "ir" ((u64) (_new)), [old] "ir" ((u64) (_old)), \
		  [iset_v6] "i" (CPU_FEAT_ISET_V6), \
		  [no_atomic_spurious_fault] "i" (CPU_NO_HWBUG_ATOMIC_SPURIOUS_FAULT) \
		: "memory", "pred2"); \
	__ret; \
})

# define __arch_pcpu_atomic_op(_val, _var, size, op) \
({ \
	typeof(_var) __ret; \
	ASM_LENGTH_V5_V6(11, 12) \
	asm NOT_VOLATILE ( \
		BEFORE_ATOMIC("1:", RELAXED_MB, no_atomic_spurious_fault) \
		ALTERNATIVE( \
		/* Default version - 10 cycles ld->st delay */ \
			"{nop 6\n"\
			" ld" size ",0 %%dg" __stringify(MY_CPU_OFFSET_GREG) \
				", %[var], %[ret], mas=0x7}\n", \
		/* CPU_FEAT_ISET_V6 - 11 cycles ld->st delay */ \
			"{nop 7\n"\
			" ld" size ",0 %%dg" __stringify(MY_CPU_OFFSET_GREG) \
				", %[var], %[ret], mas=0x7}\n", \
		%[iset_v6]) \
		"{nop 2\n" \
		  op " %[ret], %[val], %[ret]}\n" \
		"{st" size "," RELAXED_MB_ATOMIC_CHANNEL "%%dg" __stringify(MY_CPU_OFFSET_GREG) \
			", %[var], %[ret], mas=" RELAXED_MB_ATOMIC_MAS "\n" \
		" ibranch 1b ? %%MLOCK}\n" \
		MB_AFTER_ATOMIC_RELAXED_MB \
		: [ret] "=&r" (__ret) \
		: [var] "r" (&(_var)), [val] "ir" ((u64) (_val)), \
		  [iset_v6] "i" (CPU_FEAT_ISET_V6), \
		  [no_atomic_spurious_fault] "i" (CPU_NO_HWBUG_ATOMIC_SPURIOUS_FAULT) \
		: "memory"); \
	__ret; \
})

#endif

/* Disable %aalda writes on iset v6 (iset correction v6.107).
 * Use alternatives since we cannot do jumps at this point
 * (%ctpr's have been restored already). */
#define NATIVE_SET_ALL_AALDAS(aaldas_p) \
do { \
	u32 *aaldas = (u32 *)(aaldas_p); \
	ASM_LENGTH_V5_V6(8, 1) \
	asm ( \
		ALTERNATIVE_1_ALTINSTR \
		/* CPU_FEAT_ISET_V6 version */ \
			"{nop}" \
		ALTERNATIVE_2_OLDINSTR \
		/* Default version */ \
			"{aaurws,2 %[aalda0], %%aalda0\n" \
			" aaurws,5 %[aalda32], %%aalda0}\n" \
			"{aaurws,2 %[aalda4], %%aalda4\n" \
			" aaurws,5 %[aalda36], %%aalda4}\n" \
			"{aaurws,2 %[aalda8], %%aalda8\n" \
			" aaurws,5 %[aalda40], %%aalda8}\n" \
			"{aaurws,2 %[aalda12], %%aalda12\n" \
			" aaurws,5 %[aalda44], %%aalda12}\n" \
			"{aaurws,2 %[aalda16], %%aalda16\n" \
			" aaurws,5 %[aalda48], %%aalda16}\n" \
			"{aaurws,2 %[aalda20], %%aalda20\n" \
			" aaurws,5 %[aalda52], %%aalda20}\n" \
			"{aaurws,2 %[aalda24], %%aalda24\n" \
			" aaurws,5 %[aalda56], %%aalda24}\n" \
			"{aaurws,2 %[aalda28], %%aalda28\n" \
			" aaurws,5 %[aalda60], %%aalda28}\n" \
		ALTERNATIVE_3_FEATURE(%[facility]) \
		:: [aalda0] "r" (aaldas[0]), [aalda32] "r" (aaldas[8]), \
		   [aalda4] "r" (aaldas[1]), [aalda36] "r" (aaldas[9]), \
		   [aalda8] "r" (aaldas[2]), [aalda40] "r" (aaldas[10]), \
		   [aalda12] "r" (aaldas[3]), [aalda44] "r" (aaldas[11]), \
		   [aalda16] "r" (aaldas[4]), [aalda48] "r" (aaldas[12]), \
		   [aalda20] "r" (aaldas[5]), [aalda52] "r" (aaldas[13]), \
		   [aalda24] "r" (aaldas[6]), [aalda56] "r" (aaldas[14]), \
		   [aalda28] "r" (aaldas[7]), [aalda60] "r" (aaldas[15]), \
		   [facility] "i" (CPU_FEAT_ISET_V6)); \
} while (0)

#define NATIVE_CLEAR_ALL_AALDAS() \
do { \
	if (!cpu_has(CPU_FEAT_ISET_V6)) { \
		u32 __tmp = 0; \
		asm ("aaurws,2 %[tmp], %%aalda0\n" \
		     "aaurws,5 %[tmp], %%aalda0\n" \
		     "aaurws,2 %[tmp], %%aalda4\n" \
		     "aaurws,5 %[tmp], %%aalda4\n" \
		     "aaurws,2 %[tmp], %%aalda8\n" \
		     "aaurws,5 %[tmp], %%aalda8\n" \
		     "aaurws,2 %[tmp], %%aalda12\n" \
		     "aaurws,5 %[tmp], %%aalda12\n" \
		     "aaurws,2 %[tmp], %%aalda16\n" \
		     "aaurws,5 %[tmp], %%aalda16\n" \
		     "aaurws,2 %[tmp], %%aalda20\n" \
		     "aaurws,5 %[tmp], %%aalda20\n" \
		     "aaurws,2 %[tmp], %%aalda24\n" \
		     "aaurws,5 %[tmp], %%aalda24\n" \
		     "aaurws,2 %[tmp], %%aalda28\n" \
		     "aaurws,5 %[tmp], %%aalda28\n" \
		     : [tmp] "=r" (__tmp)); \
	} \
} while (0)

/* Force load OSGD->GD */
#define E2K_LOAD_OSGD_TO_GD() \
do { \
	__asm_length(3) \
	asm volatile ("{nop; sdisp %%ctpr2, 11}\n" \
		      "{call %%ctpr2, wbs=%#}\n" \
		      ::: "call"); \
} while (0)

/*
 * Arithmetic operations that are atomic with regard to interrupts.
 * I.e. an interrupt can arrive only before or after the operation.
 */
#define E2K_INSFD_ATOMIC(src1, src2, src3_dst) \
do { \
	__no_asm_inline(1) \
	asm ("insfd %[new_value], %[insf_params], %[reg], %[reg]" \
	     : [reg] "+r" (src3_dst) \
	     : [insf_params] "i" (src2), \
	       [new_value] "ir" (src1)); \
} while (0)

#define E2K_ADDD_ATOMIC(src1_dst, src2) \
do { \
	__no_asm_inline(1) \
	asm ("addd %[reg], %[val], %[reg]" \
	     : [reg] "+r" (src1_dst) \
	     : [val] "ir" (src2)); \
} while (0)

#define E2K_SUBD_ATOMIC(src1_dst, src2) \
do { \
	__no_asm_inline(1) \
	asm ("subd %[reg], %[val], %[reg]" \
	     : [reg] "+r" (src1_dst) \
	     : [val] "ir" (src2)); \
} while (0)

#define E2K_SUBD_ATOMIC__SHRD32(src1_dst, src2, _old) \
do { \
	__asm_length(1) \
	asm ("{subd %[reg], %[val], %[reg]\n" \
	     " shrd %[reg], 32, %[old]}" \
	     : [reg] "+r" (src1_dst), \
	       [old] "=r" (_old) \
	     : [val] "i" (src2)); \
} while (0)

#endif /* __ASSEMBLY__ */

#define E2K_SEMI_SPEC_LOAD(address) \
do { \
	__asm_length(1) \
	asm volatile ("{ldd,sm %[addr], 0, %%empty, mas=%[mas]}" \
		:: [addr] "r" (address), \
		   [mas] "i" (MIGHT_HAVE_CPU_HWBUG_PREFETCH_EMPTY() ? \
				MAS_BYPASS_L1_CACHE : 0)); \
} while (0)

#if __iset__ >= 7
# define GET_V7_CPU_REG_BASE(_reg) \
({ \
	u64 __crb_btm_offset, __crb_ptr; \
	asm ("{getind %[reg], %[offset]\n" \
	     " getptr %[reg], %[ptr]}\n" \
	     : [offset] "=r" (__crb_btm_offset), [ptr] "=r" (__crb_ptr) \
	     : [reg] "r" (((__uint128_t) (_reg).hi << 64) | (_reg).lo)); \
	__crb_ptr - __crb_btm_offset; \
})

# define GET_V7_CPU_REG_SIZE(_reg) \
({ \
	u64 __crs_max_ind, lo = (_reg).lo, hi = (_reg).hi; \
	asm ("getmi %[reg], %[max_ind]\n" \
	     : [max_ind] "=r" (__crs_max_ind) \
	     : [reg] "r" (((__uint128_t) hi << 64) | lo)); \
	(hi & E2K_V7_AP_RW_MASK) ? (__crs_max_ind + 1) : 0; \
})

# define GET_V7_CPU_REG_IND(_reg) \
({ \
	u64 __cri_btm_offset = 0, lo = (_reg).lo, hi = (_reg).hi; \
	if (hi & E2K_V7_AP_RW_MASK) { \
		asm ("getind %[reg], %[offset]\n" \
		     : [offset] "=r" (__cri_btm_offset) \
		     : [reg] "r" (((__uint128_t) hi << 64) | lo)); \
	} \
	__cri_btm_offset; \
})

# define GET_V7_CPU_REG_PTR(_reg) \
({ \
	u64 __crp_ptr; \
	asm ("getptr %[reg], %[ptr]\n" \
	     : [ptr] "=r" (__crp_ptr) \
	     : [reg] "r" (((__uint128_t) (_reg).hi << 64) | (_reg).lo)); \
	__crp_ptr; \
})

/* Note: 0x388c00001f7ffffd0000000000000000 is AP to all possible memory */
# define NEW_V7_CPU_REG(_base, _ind, _size) \
({ \
	__uint128_t __crn_reg = (__uint128_t) 0x388c00001f7ffffdull << 64; \
	asm ("{apincr %[reg], %[base], %[reg]}\n" \
	     "{nop 1\n" \
	     " subarr %[reg], %[size], %[reg]}\n" \
	     "{apincr %[reg], %[ind], %[reg]}\n" \
	     : [reg] "+r" (__crn_reg) \
	     : [base] "r" ((u64) (_base)), \
	       [ind] "r" ((u64) (_ind)), \
	       [size] "r" ((u64) ((_size) - 1))); \
	(e2k_qreg_t) { .lo = __crn_reg, .hi = __crn_reg >> 64}; \
})
#else
# define GET_V7_CPU_REG_BASE(_reg) \
({ \
	u64 __crb_btm_offset, __crb_ptr; \
	__no_asm_inline(1) \
	asm (".push_iset 7\n" \
	     "{getind %[reg], %[offset]\n" \
	     " getptr %[reg], %[ptr]}\n" \
	     ".pop_iset\n" \
	     : [offset] "=r" (__crb_btm_offset), [ptr] "=r" (__crb_ptr) \
	     : [reg] "r" (((__uint128_t) (_reg).hi << 64) | (_reg).lo)); \
	__crb_ptr - __crb_btm_offset; \
})

# define GET_V7_CPU_REG_SIZE(_reg) \
({ \
	u64 __crs_max_ind, lo = (_reg).lo, hi = (_reg).hi; \
	__no_asm_inline(1) \
	asm (".push_iset 7\n" \
	     "getmi %[reg], %[max_ind]\n" \
	     ".pop_iset\n" \
	     : [max_ind] "=r" (__crs_max_ind) \
	     : [reg] "r" (((__uint128_t) hi << 64) | lo)); \
	(hi & E2K_V7_AP_RW_MASK) ? (__crs_max_ind + 1) : 0; \
})

# define GET_V7_CPU_REG_IND(_reg) \
({ \
	u64 __cri_btm_offset = 0, lo = (_reg).lo, hi = (_reg).hi; \
	if (hi & E2K_V7_AP_RW_MASK) { \
		__no_asm_inline(1) \
		asm (".push_iset 7\n" \
		     "getind %[reg], %[offset]\n" \
		     ".pop_iset\n" \
		     : [offset] "=r" (__cri_btm_offset) \
		     : [reg] "r" (((__uint128_t) hi << 64) | lo)); \
	} \
	__cri_btm_offset; \
})

# define GET_V7_CPU_REG_PTR(_reg) \
({ \
	u64 __crp_ptr; \
	__no_asm_inline(1) \
	asm (".push_iset 7\n" \
	     "getptr %[reg], %[ptr]\n" \
	     ".pop_iset\n" \
	     : [ptr] "=r" (__crp_ptr) \
	     : [reg] "r" (((__uint128_t) (_reg).hi << 64) | (_reg).lo)); \
	__crp_ptr; \
})

/* Note: 0x388c00001f7ffffd0000000000000000 is AP to all possible memory */
# define NEW_V7_CPU_REG(_base, _ind, _size) \
({ \
	__uint128_t __crn_reg = (__uint128_t) 0x388c00001f7ffffdull << 64; \
	__no_asm_inline(4) \
	asm (".push_iset 7\n" \
	     "{apincr %[reg], %[base], %[reg]}\n" \
	     "{nop 1\n" \
	     " subarr %[reg], %[size], %[reg]}\n" \
	     "{apincr %[reg], %[ind], %[reg]}\n" \
	     ".pop_iset\n" \
	     : [reg] "+r" (__crn_reg) \
	     : [base] "r" ((u64) (_base)), \
	       [ind] "r" ((u64) (_ind)), \
	       [size] "r" ((u64) ((_size) - 1))); \
	(e2k_qreg_t) { .lo = __crn_reg, .hi = __crn_reg >> 64}; \
})
#endif

/* Get PTR + color */
#define GET_V7_CPU_REG_PTRC(_reg) \
({ \
	u64 __crp_ptr; \
	__no_asm_inline(1) \
	asm (".push_iset 7\n" \
	     "getptrc %[reg], %[ptr]\n" \
	     ".pop_iset\n" \
	     : [ptr] "=r" (__crp_ptr) \
	     : [reg] "r" (((__uint128_t) (_reg).hi << 64) | (_reg).lo)); \
	__crp_ptr; \
})

#endif /* _E2K_API_H_ */
