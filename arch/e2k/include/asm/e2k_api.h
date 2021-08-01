#ifndef _E2K_API_H_
#define _E2K_API_H_

#include <linux/stringify.h>
#include <asm/mas.h>


#ifndef __ASSEMBLY__
typedef unsigned char __e2k_u8_t;
typedef unsigned short int __e2k_u16_t;
typedef unsigned int __e2k_u32_t;
typedef unsigned long long __e2k_u64_t;
typedef void *__e2k_ptr_t;
#endif


/*
 * FIXME: the following header include is commented
#include <asm/mmu_types.h>
 * because of this header 'asm/e2k_api.h' is included in arch-independent
 * header 'linux/compiler-gcc.h' (see header to know why).
 * So header 'asm/mmu_types.h' cannot contain any types from 'linux/types.h'
 * and it need include the header directly before 'asm/e2k_api.h' into follow
 * files:
 *	kernel/trap_table.S
 *	kernel/page_tables.S
 */

/*
 * Used to separate one wide instruction from another
 */ 
#define	E2K_CMD_SEPARATOR		asm volatile ("{nop}" ::: "memory")

/* To avoid header dependencies use this define
 * instead of BUILD_BUG_ON() from <linux/kernel.h>. */
#define E2K_BUILD_BUG_ON(condition) ((void)sizeof(char[1 - 2*!!(condition)]))

#ifndef E2K_BIN_VER
#define E2K_BIN_VER	8
#endif

#define	EI_SEMANTIC	7

#define	ELF_CODE_UNKNOWN                0
#define	ELF_CODE_32_UNPROTECTED         1
#define	ELF_CODE_64_UNPROTECTED         2
#define	ELF_CODE_NEW_PROTECTED          5
#define ELF_CODE_NEW_PROTECTED_CXX      6

#define ELF_BIN_COMP		0x4
/* 
 * If  x->e_flags && ELF_E2K_INCOMPAT == 1 
 * the code can executed only (mtype==0) -     any
 *                                  ==2        es2
 *                                  ==3        e2s
 *                                  ==4        e8c
 */                             
#define ELF_E2K_INCOMPAT        0x10 

#define IS_INCOMPAT(x)		((x)->e_machine == ELF_ARCH && \
				((x)->e_flags & ELF_E2K_INCOMPAT))

/* protected mode flag */
#define ELF_E2K_PM	        0x20
/* ELF segments are to be mapped in packed way. */
#define ELF_E2K_PACK_SEGMENTS	0x40

#define EM_E2KL 	(33 + (E2K_BIN_VER << 1))     /* Little endian */
#define EM_E2KB 	(34 + (E2K_BIN_VER << 1))     /* Big endian */
#define EM_E2K_FAKE	EM_E2KL
#define EM_E2K		175
/* Compilation unit number for all memory allocations in 32-bit comp. mode */
#define	E2K_ELF32_COMP_UNIT	1

/*
 * Machine type checker. Is to be used for 64-bit, 32-bit elf
 * and protected mode. Result depends on machine type and binary type.  
 */

#define elf_check_e2k_mtype(x)						\
({									\
	unsigned long mt;						\
	int _res  = 0;							\
	int _iset = machine.native_iset_ver;				\
									\
	if ((x)->e_machine == ELF_ARCH) {				\
		mt = (unsigned long)((x)->e_flags >> 24);		\
	} else {							\
		mt = (unsigned long)((x)->e_flags >> 28) & 0x7;		\
	}								\
									\
	switch (mt) {							\
	case 0:								\
		if (!IS_INCOMPAT(x) || _iset == ELBRUS_S_ISET)		\
			_res = 1;					\
		break;							\
	case 2:								\
		if (!IS_INCOMPAT(x) && _iset > ELBRUS_S_ISET		\
				|| _iset == ELBRUS_S_ISET)		\
			_res = 1;					\
		break;							\
	case 3:								\
		if (!IS_INCOMPAT(x) && _iset > ELBRUS_2S_ISET		\
				|| _iset == ELBRUS_2S_ISET)		\
			_res = 1;					\
		break;							\
	case 4:								\
		if (!IS_INCOMPAT(x) && _iset > ELBRUS_8C_ISET		\
				|| _iset == ELBRUS_8C_ISET)		\
			_res = 1;					\
		break;							\
	case 5:								\
		if (!IS_INCOMPAT(x) && _iset > ELBRUS_8C2_ISET		\
				|| _iset == ELBRUS_8C2_ISET)		\
			_res = 1;					\
		break;							\
	case 6:								\
		if (_iset == E2K_ISET_V6)				\
			_res = 1;					\
		break;							\
	case 19:							\
		if (IS_MACHINE_E8C)					\
			_res = 1;					\
		break;							\
	case 20:							\
		if (IS_MACHINE_E1CP)					\
			_res = 1;					\
		break;							\
	case 21:							\
		if (IS_MACHINE_E12C)					\
			_res = 1;					\
		break;							\
	case 22:							\
		if (IS_MACHINE_E16C)					\
			_res = 1;					\
		break;							\
	case 23:							\
		if (IS_MACHINE_E2C3)					\
			_res = 1;					\
		break;							\
	default:							\
		break;							\
	}								\
									\
	_res;								\
})

/*
 * Normal simulator termination
 */
#define E2K_LMS_HALT_OK				\
({						\
	_Pragma("no_asm_inline")		\
	asm volatile (".word \t0x00008001\n\t"	\
			".word \t0x60000000");	\
})

/*
 * Simulator termination on error
 */
#define E2K_LMS_HALT_ERROR(err_no)		\
({						\
	_Pragma("no_asm_inline")		\
	asm volatile (".word \t0x00008001\n\t"	\
		".word \t0x60000000 | %0"	\
		:				\
		: "i" (err_no));		\
})

/*
 * Kprobes breakpoint instruction
 */
#define E2K_KPROBES_BREAKPOINT		\
({					\
	_Pragma("no_asm_inline")		\
	asm volatile (".word \t0x04000001\n\t"	\
			".word \t0x0dc0c040");	\
})

#define	ASM_GET_GREG_MEMONIC(greg_no)	 __asm__("%g" #greg_no)
#define	DO_ASM_GET_GREG_MEMONIC(greg_no) ASM_GET_GREG_MEMONIC(greg_no)

#define E2K_GET_REG(reg_no) \
({ \
    register __e2k_u32_t res; \
    asm volatile ("adds \t0x0, %%r" #reg_no ", %0"  \
                  : "=r" (res)); \
    res; \
})

#define E2K_GET_DREG(reg_no) \
({ \
    register __e2k_u64_t res; \
    asm volatile ("addd \t0x0, %%dr" #reg_no ", %0"  \
                  : "=r" (res)); \
    res; \
})

#define ASM_GET_DGREG(reg_no) \
({ \
    register __e2k_u64_t res; \
    asm volatile ("addd \t0x0, %%dg" #reg_no ", %0"  \
                  : "=r" (res)); \
    res; \
})
#define	DO_ASM_GET_DGREG(greg_no) \
		ASM_GET_DGREG(greg_no)
#define E2K_GET_DGREG(greg_no)	\
		DO_ASM_GET_DGREG(greg_no)
#define NATIVE_GET_DGREG(greg_no) \
		DO_ASM_GET_DGREG(greg_no)


#define ASM_GET_UNTEGGED_DGREG(reg_no) \
({ \
	register __e2k_u64_t res; \
	asm volatile ("addd,s \t0x0, %%dg" #reg_no ", %0\n"  \
		"puttagd,s \t%0, 0, %0"	\
		: "=r" (res)); \
	res; \
})
#define	DO_ASM_GET_UNTEGGED_DGREG(greg_no) \
		ASM_GET_UNTEGGED_DGREG(greg_no)
#define E2K_GET_UNTEGGED_DGREG(greg_no)	\
		DO_ASM_GET_UNTEGGED_DGREG(greg_no)
#define NATIVE_GET_UNTEGGED_DGREG(greg_no) \
		DO_ASM_GET_UNTEGGED_DGREG(greg_no)

#define ASM_SET_DGREG(reg_no, val) \
({ \
	asm volatile ("addd \t0x0, %0, %%dg" #reg_no \
		: \
		: "ri" ((__e2k_u64_t) (val))); \
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
                  : [val] "ri" ((__e2k_u64_t) (_val))); \
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

/*
 * Copy single register tagged value to single register
 * src_reg - local value of type single register to copy from
 * dst_reg - local value of type single register to copy to
 */
#define E2K_MOVE_TAGGED_REG(src_reg, dst_reg) \
({ \
	asm volatile ("movts \t%1, %0"  \
			: "=r" (dst_reg) \
			: "r" ((__e2k_u32_t) (src_reg))); \
})

#define _E2K_GET_DGREG_VAL_AND_TAG(greg_no, dst_reg, tag)	\
({								\
	u32 __dtag;						\
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
	asm volatile ("{gettags %%g" #greg_no ", %0\n\t"	\
		      "puttags %%g" #greg_no ", 0, %1}"		\
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

#define ASM_SAVE_GREG_V2(__addr_lo, __addr_hi, numlo, numhi, iset)	\
({									\
	u64 reg0, reg1;							\
	BUILD_BUG_ON(iset != E2K_ISET_V2);				\
									\
	asm (								\
		"strd,2 [ %[addr_lo] + %[opc_0] ], %%dg" #numlo "\n"	\
		"strd,5 [ %[addr_hi] + %[opc_0] ], %%dg" #numhi "\n"	\
		"movfi %%dg" #numlo ", %[reg0]\n"			\
		"movfi %%dg" #numhi ", %[reg1]\n"			\
		"sth [ %[addr_lo] + 8 ], %[reg0]\n"			\
		"sth [ %[addr_hi] + 8 ], %[reg1]\n"			\
		: [reg0] "=&r" (reg0), [reg1] "=&r" (reg1)		\
		: [addr_lo] "r" (__addr_lo), [addr_hi] "r" (__addr_hi),	\
		  [opc_0] "i" (TAGGED_MEM_STORE_REC_OPC)		\
		: "memory");						\
})

#define ASM_RESTORE_GREG_V2(__addr_lo, __addr_hi, numlo, numhi, iset)	\
({									\
	u64 reg0, reg1, reg2, reg3;					\
	BUILD_BUG_ON(iset != E2K_ISET_V2);				\
									\
	asm (								\
		"ldrd,2 [ %[addr_lo] + %[opc_0] ], %%dg" #numlo "\n"	\
		"ldrd,5 [ %[addr_hi] + %[opc_0] ], %%dg" #numhi "\n"	\
		"ldh [ %[addr_lo] + 8 ], %[reg0]\n"			\
		"ldh [ %[addr_hi] + 8 ], %[reg1]\n"			\
		"gettagd %%dg" #numlo ", %[reg2]\n"			\
		"gettagd %%dg" #numhi ", %[reg3]\n"			\
		"cmpesb 0, %[reg2], %%pred2\n"				\
		"cmpesb 0, %[reg3], %%pred3\n"				\
		"movif %%dg" #numlo ", %[reg0], %%dg" #numlo " ? %%pred2\n" \
		"movif %%dg" #numhi ", %[reg1], %%dg" #numhi " ? %%pred3\n" \
		: [reg0] "=&r" (reg0),	[reg1] "=&r" (reg1),		\
		  [reg2] "=&r" (reg2),	[reg3] "=&r" (reg3)		\
		: [addr_lo] "r" (__addr_lo), [addr_hi] "r" (__addr_hi),	\
		  [opc_0] "i" (TAGGED_MEM_LOAD_REC_OPC)			\
		:"%g" #numlo, "%g" #numhi, "%pred2", "%pred3");		\
})

#define ASM_SAVE_GREG_V5(__addr_lo, __addr_hi, numlo, numhi, iset)	\
({									\
	u64 unused;							\
	BUILD_BUG_ON(iset != E2K_ISET_V5);				\
									\
	asm (								\
		/* Bug 116851 - all strqp must be speculative		\
		 * if dealing with tags */				\
		"{\n" /* Close this asm because 'sm' for 'strqp'	\
			 is not supported by lcc */			\
		"strqp,2,sm [ %[addr_lo] + %[opc_0] ], %%dg" #numlo "\n" \
		"strqp,5,sm [ %[addr_hi] + %[opc_0] ], %%dg" #numhi "\n" \
		"}\n"							\
		: [unused] "=r" (unused)				\
		: [addr_lo] "r" (__addr_lo), [addr_hi] "r" (__addr_hi),	\
		  [opc_0] "i" (TAGGED_MEM_STORE_REC_OPC)		\
		: "memory");						\
})

#define ASM_RESTORE_GREG_V5(__addr_lo, __addr_hi, numlo, numhi, iset)	\
({									\
	u64 reg0, reg1;							\
	BUILD_BUG_ON(iset != E2K_ISET_V5);				\
									\
	asm (								\
		"ldrqp,2 [ %[addr_lo] + %[opc_0] ], %%dg" #numlo "\n"	\
		"ldrqp,5 [ %[addr_hi] + %[opc_0] ], %%dg" #numhi "\n"	\
		: [reg0] "=&r" (reg0),	[reg1] "=&r" (reg1)		\
		: [addr_lo] "r" (__addr_lo), [addr_hi] "r" (__addr_hi),	\
		  [opc_0] "i" (TAGGED_MEM_LOAD_REC_OPC)			\
		: "%g" #numlo, "%g" #numhi);				\
})

#if __iset__ == 2

#define ASM_SAVE_GREG(__addr_lo, __addr_hi, numlo, numhi, iset)		\
		ASM_SAVE_GREG_V2(__addr_lo, __addr_hi, numlo, numhi, iset)

#define ASM_RESTORE_GREG(__addr_lo, __addr_hi, numlo, numhi, iset)	\
		ASM_RESTORE_GREG_V2(__addr_lo, __addr_hi, numlo, numhi, iset)

#elif __iset__ == 5

#define ASM_SAVE_GREG(__addr_lo, __addr_hi, numlo, numhi, iset)		\
		ASM_SAVE_GREG_V5(__addr_lo, __addr_hi, numlo, numhi, iset)

#define ASM_RESTORE_GREG(__addr_lo, __addr_hi, numlo, numhi, iset)	\
		ASM_RESTORE_GREG_V5(__addr_lo, __addr_hi, numlo, numhi, iset)

#else
/* IMPORTANT: Do NOT use these macros directly, use
 * machine.save_gregs()/machine.restore_gregs() instead */
#endif

#define NATIVE_SAVE_GREG(__addr_lo, __addr_hi, numlo, numhi, iset)	\
	ASM_SAVE_GREG(__addr_lo, __addr_hi, numlo, numhi, iset)
#define NATIVE_SAVE_GREG_V2(__addr_lo, __addr_hi, numlo, numhi)		\
	ASM_SAVE_GREG_V2(__addr_lo, __addr_hi, numlo, numhi, E2K_ISET_V2)
#define NATIVE_SAVE_GREG_V5(__addr_lo, __addr_hi, numlo, numhi)		\
	ASM_SAVE_GREG_V5(__addr_lo, __addr_hi, numlo, numhi, E2K_ISET_V5)
#define NATIVE_RESTORE_GREG(__addr_lo, __addr_hi, numlo, numhi, iset) \
	ASM_RESTORE_GREG(__addr_lo, __addr_hi, numlo, numhi, iset)
#define NATIVE_RESTORE_GREG_V2(__addr_lo, __addr_hi, numlo, numhi)	\
	ASM_RESTORE_GREG_V2(__addr_lo, __addr_hi, numlo, numhi, E2K_ISET_V2)
#define NATIVE_RESTORE_GREG_V5(__addr_lo, __addr_hi, numlo, numhi)	\
	ASM_RESTORE_GREG_V5(__addr_lo, __addr_hi, numlo, numhi, E2K_ISET_V5)

#define ASM_SAVE_THE_KERNEL_GREG(greg_no, _base, ind)			\
({									\
	u64 reg0, reg1;							\
	BUILD_BUG_ON(iset != E2K_ISET_V2);				\
									\
	asm (								\
		"strd [ %[base] + %[opc] ], %%dg" #greg_no "\n"		\
		:							\
		: [base] "r" (_base),					\
		  [opc] "i" (TAGGED_MEM_STORE_REC_OPC | ind * 16UL)	\
		: "%g" #greg_no, "memory");				\
})
#define NATIVE_SAVE_THE_KERNEL_GREG(greg_no, _base, ind)		\
		ASM_SAVE_THE_KERNEL_GREG(greg_no, _base, ind)

#define ASM_RESTORE_THE_KERNEL_GREG(greg_no, _base, ind)		\
do {									\
	asm (								\
		"ldrd [ %[base] + %[opc] ], %%dg" #greg_no "\n"		\
		:							\
		: [base] "r" (_base),					\
		  [opc] "i" (TAGGED_MEM_LOAD_REC_OPC | ind * 16UL)	\
		: "%g" #greg_no, "memory");				\
} while (false)
#define NATIVE_RESTORE_THE_KERNEL_GREG(greg_no, _base, ind)		\
		ASM_RESTORE_THE_KERNEL_GREG(greg_no, _base, ind)

#define ASM_RESTORE_KERNEL_GREG(__base,					\
				indlo1, indhi1, indlo2, indhi2,		\
				numlo1, numhi1, numlo2, numhi2)		\
do {									\
	u64 _base = (u64) (__base);					\
	register u64 g##numlo1 asm("g" #numlo1);			\
	register u64 g##numhi1 asm("g" #numhi1);			\
	register u64 g##numlo2 asm("g" #numlo2);			\
	register u64 g##numhi2 asm("g" #numhi2);			\
	asm (	"ldrd [ %[base] + %[opc_lo1] ], %[g_lo1]\n"		\
		"ldrd [ %[base] + %[opc_hi1] ], %[g_hi1]\n"		\
		"ldrd [ %[base] + %[opc_lo2] ], %[g_lo2]\n"		\
		"ldrd [ %[base] + %[opc_hi2] ], %[g_hi2]\n"		\
		: [g_lo1] "=r" (g##numlo1), [g_hi1] "=r" (g##numhi1),	\
		  [g_lo2] "=r" (g##numlo2), [g_hi2] "=r" (g##numhi2)	\
		: [base] "r" (_base),					\
		  [opc_lo1] "i" (TAGGED_MEM_LOAD_REC_OPC | indlo1 * 16UL), \
		  [opc_hi1] "i" (TAGGED_MEM_LOAD_REC_OPC | indhi1 * 16UL), \
		  [opc_lo2] "i" (TAGGED_MEM_LOAD_REC_OPC | indlo2 * 16UL), \
		  [opc_hi2] "i" (TAGGED_MEM_LOAD_REC_OPC | indhi2 * 16UL)); \
} while (false)
#define NATIVE_RESTORE_KERNEL_GREG(base,				\
			indlo1, indhi1, indlo2, indhi2,			\
			numlo1, numhi1, numlo2, numhi2)			\
		ASM_RESTORE_KERNEL_GREG(base,				\
				indlo1, indhi1, indlo2, indhi2,		\
				numlo1, numhi1, numlo2, numhi2)

#define E2K_ALL_GREGS_SET_EMPTY()				\
({								\
	register char tag;					\
	tag = ETAGEWD;						\
	asm ("puttagd 0, %0, %%dg0\n"				\
	     "puttagd 0, %0, %%dg1\n"				\
	     "puttagd 0, %0, %%dg2\n"				\
	     "puttagd 0, %0, %%dg3\n"				\
	     "puttagd 0, %0, %%dg4\n"				\
	     "puttagd 0, %0, %%dg5\n"				\
	     "puttagd 0, %0, %%dg6\n"				\
	     "puttagd 0, %0, %%dg7\n"				\
	     "puttagd 0, %0, %%dg8\n"				\
	     "puttagd 0, %0, %%dg9\n"				\
	     "puttagd 0, %0, %%dg10\n"				\
	     "puttagd 0, %0, %%dg11\n"				\
	     "puttagd 0, %0, %%dg12\n"				\
	     "puttagd 0, %0, %%dg13\n"				\
	     "puttagd 0, %0, %%dg14\n"				\
	     "puttagd 0, %0, %%dg15\n"				\
	     "puttagd 0, %0, %%dg16\n"				\
	     "puttagd 0, %0, %%dg17\n"				\
	     "puttagd 0, %0, %%dg18\n"				\
	     "puttagd 0, %0, %%dg19\n"				\
	     "puttagd 0, %0, %%dg20\n"				\
	     "puttagd 0, %0, %%dg21\n"				\
	     "puttagd 0, %0, %%dg22\n"				\
	     "puttagd 0, %0, %%dg23\n"				\
	     "puttagd 0, %0, %%dg24\n"				\
	     "puttagd 0, %0, %%dg25\n"				\
	     "puttagd 0, %0, %%dg26\n"				\
	     "puttagd 0, %0, %%dg27\n"				\
	     "puttagd 0, %0, %%dg28\n"				\
	     "puttagd 0, %0, %%dg29\n"				\
	     "puttagd 0, %0, %%dg30\n"				\
	     "puttagd 0, %0, %%dg31\n"				\
	     :							\
	     : "ri" ((char) (tag))				\
	     : "%g0", "%g1", "%g2", "%g3", "%g4", "%g5",	\
	       "%g6", "%g7", "%g8", "%g9", "%g10", "%g11",	\
	       "%g12", "%g13", "%g14", "%g15", "%g16",		\
	       "%g17", "%g18", "%g19", "%g20", "%g21",		\
	       "%g22", "%g23", "%g24", "%g25", "%g26",		\
	       "%g27", "%g28", "%g29", "%g30", "%g31");		\
})

#define	NATIVE_GREGS_SET_EMPTY()				\
({								\
	register char tag;					\
	tag = ETAGEWD;						\
	asm ("puttagd 0, %0, %%dg0\n"				\
	     "puttagd 0, %0, %%dg1\n"				\
	     "puttagd 0, %0, %%dg2\n"				\
	     "puttagd 0, %0, %%dg3\n"				\
	     "puttagd 0, %0, %%dg4\n"				\
	     "puttagd 0, %0, %%dg5\n"				\
	     "puttagd 0, %0, %%dg6\n"				\
	     "puttagd 0, %0, %%dg7\n"				\
	     "puttagd 0, %0, %%dg8\n"				\
	     "puttagd 0, %0, %%dg9\n"				\
	     "puttagd 0, %0, %%dg10\n"				\
	     "puttagd 0, %0, %%dg11\n"				\
	     "puttagd 0, %0, %%dg12\n"				\
	     "puttagd 0, %0, %%dg13\n"				\
	     "puttagd 0, %0, %%dg14\n"				\
	     "puttagd 0, %0, %%dg15\n"				\
	     /* g16-g19 are used by kernel */			\
	     /*"puttagd 0, %0, %%dg16\n"*/			\
	     /*"puttagd 0, %0, %%dg17\n"*/			\
	     /*"puttagd 0, %0, %%dg18\n"*/			\
	     /*"puttagd 0, %0, %%dg19\n"*/			\
	     "puttagd 0, %0, %%dg20\n"				\
	     "puttagd 0, %0, %%dg21\n"				\
	     "puttagd 0, %0, %%dg22\n"				\
	     "puttagd 0, %0, %%dg23\n"				\
	     "puttagd 0, %0, %%dg24\n"				\
	     "puttagd 0, %0, %%dg25\n"				\
	     "puttagd 0, %0, %%dg26\n"				\
	     "puttagd 0, %0, %%dg27\n"				\
	     "puttagd 0, %0, %%dg28\n"				\
	     "puttagd 0, %0, %%dg29\n"				\
	     "puttagd 0, %0, %%dg30\n"				\
	     "puttagd 0, %0, %%dg31\n"				\
	     :							\
	     : "ri" ((char) (tag))				\
	     : "%g0", "%g1", "%g2", "%g3", "%g4", "%g5",	\
	       "%g6", "%g7", "%g8", "%g9", "%g10", "%g11",	\
	       "%g12", "%g13", "%g14", "%g15", /*"%g16",*/	\
	       /*"%g17", "%g18", "%g19",*/ "%g20", "%g21",	\
	       "%g22", "%g23", "%g24", "%g25", "%g26",		\
	       "%g27", "%g28", "%g29", "%g30", "%g31");		\
})

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

#define	E2K_MOVE_GREG_TO_REG(greg_no, local_reg)			\
({									\
_Pragma("no_asm_inline")						\
	asm volatile ("\nmovts \t%%g" #greg_no ", %0"			\
			: "=&r" (local_reg));				\
})
#define	E2K_MOVE_DGREG_TO_DREG(greg_no, local_reg)			\
({									\
_Pragma("no_asm_inline")						\
	asm volatile ("\nmovtd \t%%dg" #greg_no ", %0"			\
			: "=&r" (local_reg));				\
})

#define	E2K_MOVE_REG_TO_GREG(greg_no, local_reg)			\
({									\
_Pragma("no_asm_inline")						\
	asm volatile ("\nmovts \t%0, %%g" #greg_no			\
			:						\
			: "&r" ((__e2k_u32_t) (local_reg)));		\
})
#define	E2K_MOVE_DREG_TO_DGREG(greg_no, local_reg)			\
({									\
_Pragma("no_asm_inline")						\
	asm volatile ("\nmovtd \t%0, %%dg" #greg_no			\
			:						\
			: "r" ((__e2k_u64_t) (local_reg)));		\
})
#define	E2K_ADD_DREGS_TO_DGREG(greg_no, local_reg1, local_reg2)		\
({									\
_Pragma("no_asm_inline")						\
	asm volatile ("\naddd \t%0, %1, %%dg" #greg_no			\
			:						\
			: "ri" ((__e2k_u64_t) (local_reg1)),		\
			  "r" ((__e2k_u64_t) (local_reg2)));		\
})

/*
 * bug #97048
 *
 * We have following macros for registers reading/writing
 * depending on whether lcc supports the register in question:
 *
 * NATIVE_GET_[D]SREG_OPEN() - read supported register
 * NATIVE_GET_[D]SREG_CLOSED() - read unsupported register
 *
 * NATIVE_SET_[D]SREG_OPEN() - write supported register
 * NATIVE_SET_[D]SREG_OPEN_NOIRQ() - write supported register when
 *     it must be done under closed interrupts (for psp.hi/pcsp.hi/cr/cutd)
 * NATIVE_SET_[D]SREG_CLOSED_NOEXC() - write unsupported register when
 *     it is _not_ listed in exceptions list in 1.1.1 1) of "Scheduling"
 * NATIVE_SET_[D]SREG_CLOSED_EXC() - write unsupported register when
 *     it _is_ listed in exceptions list in 1.1.1 1) of "Scheduling"
 */

/*
 * bug #60599, #97048
 * Allow for lcc optimizations of registers reads and writes
 * (when lcc supports the registers in question)
 */
#if defined CONFIG_OPTIMIZE_REGISTERS_ACCESS
# define NATIVE_GET_SREG_OPEN(reg_mnemonic) \
({ \
	register __e2k_u32_t res; \
	asm ("rrs %%" #reg_mnemonic ", %0" \
		: "=r" (res)); \
	res; \
})

# define NATIVE_GET_DSREG_OPEN(reg_mnemonic) \
({ \
	register __e2k_u64_t res; \
	asm ("rrd %%" #reg_mnemonic ", %0" \
		: "=r" (res)); \
	res; \
})

# define NATIVE_SET_SREG_OPEN(reg_mnemonic, val) \
({ \
	/* Fake return value is needed for lcc to optimize inline asm... */ \
	register __e2k_u32_t res; \
	asm ("rws %1, %%" #reg_mnemonic \
		: "=r" (res) \
		: "ri" ((__e2k_u32_t) (val))); \
})

# define NATIVE_SET_DSREG_OPEN(reg_mnemonic, val) \
({ \
	/* Fake return value is needed for lcc to optimize inline asm... */ \
	register __e2k_u64_t res; \
	asm ("rwd %1, %%" #reg_mnemonic \
		: "=r" (res) \
		: "ri" ((__e2k_u64_t) (val))); \
})

/*
 * *_NOIRQ version is for psp.hi/pcsp.hi/cr/cutd
 *
 * Rules for writing:
 * 1) There must be NO exceptions and interrupts
 * 2) As a consequence of 1), instructions that are placed _later_
 * than "rw" should not generate exceptions too because compiler
 * can reorder them before the "rw" instruction.
 *
 * IOW in the whole area covered by all_irq_save()/all_irq_restore()
 * there must not be any exception-generating instructions.
 */

# define NATIVE_SET_DSREG_OPEN_NOIRQ(reg_mnemonic, val) \
({ \
	register __e2k_u64_t res; \
	asm ("rwd %1, %%" #reg_mnemonic \
		: "=r" (res) \
		: "ri" ((__e2k_u64_t) (val))); \
})

#else
# define NATIVE_GET_SREG_OPEN		NATIVE_GET_SREG_CLOSED
# define NATIVE_GET_DSREG_OPEN		NATIVE_GET_DSREG_CLOSED
# define NATIVE_SET_SREG_OPEN(reg, val) \
		NATIVE_SET_SREG_CLOSED_NOEXC(reg, (val), 7)
# define NATIVE_SET_DSREG_OPEN(reg, val) \
		NATIVE_SET_DSREG_CLOSED_NOEXC(reg, (val), 7)
# define NATIVE_SET_DSREG_OPEN_NOIRQ(reg, val) \
		NATIVE_SET_DSREG_CLOSED_NOEXC(reg, (val), 7)
#endif


/*
 * bug #97048
 * Closed GNU asm is used for rarely read registers.
 * Keep "volatile" since some of those registers can have side effects
 * (for example, see %dibsr reading in arch/e2k/kernel/perf_event.c -
 * it must be done before reading %dimar; or look at %clkr).
 */
#define NATIVE_GET_SREG_CLOSED(reg_mnemonic) \
({ \
	register __e2k_u32_t res; \
	_Pragma("no_asm_inline") \
	asm volatile ("rrs %%" #reg_mnemonic ", %0" \
	     : "=r" (res)); \
	res; \
})

#define NATIVE_GET_DSREG_CLOSED(reg_mnemonic) \
({ \
	register __e2k_u64_t res; \
	_Pragma("no_asm_inline") \
	asm volatile ("rrd %%" #reg_mnemonic ", %0" \
	     : "=r" (res)); \
	res; \
})

#define NATIVE_GET_DSREG_CLOSED_CLOBBERS(reg_mnemonic, clobbers) \
({ \
	register __e2k_u64_t res; \
	_Pragma("no_asm_inline") \
	asm volatile ("rrd %%" #reg_mnemonic ", %0" \
	     : "=r" (res) :: clobbers); \
	res; \
})

/*
 * These macros will insert real wide instructions
 * instead of doing all nops with "nop x" field in HS.
 * This is needed, for example, when writing %wd.
 */
#define NOP_0_MINUS_4 0
#define NOP_1_MINUS_4 0
#define NOP_2_MINUS_4 0
#define NOP_3_MINUS_4 0
#define NOP_4_MINUS_4 0
#define NOP_5_MINUS_4 1
#define NOP_6_MINUS_4 2
#define NOP_7_MINUS_4 3

/*
 * bug #97048
 *
 * For closed writes we have to manually check how many NOPs are needed
 * for this register. If we try to use _Pragma("no_asm_inline"), then
 * lcc will use its default value of 5 nops which is not always enough.
 *
 * Also, according to "Scheduling 1.1.1", the next 3 long instructions
 * after the write must not generate delayed exceptions, and the next
 * 4 long instruction must not generate exact exceptions. So add 4 nops
 * after the write.
 *
 * This is slow but this version is used only for rarely written registers.
 * %usd/%psp/etc registers are supported by lcc and are written with an
 * open GNU asm.
 */
#define NATIVE_SET_SREG_CLOSED_NOEXC(reg_mnemonic, val, nop) \
({ \
	asm volatile ("{nop " __stringify(NOP_##nop##_MINUS_4) "\n" \
		      " rws %0, %%" #reg_mnemonic "}\n" \
		      "{nop} {nop} {nop} {nop}" \
		      : \
		      : "ri" ((__e2k_u32_t) (val))); \
})

#define NATIVE_SET_DSREG_CLOSED_NOEXC(reg_mnemonic, val, nop) \
({ \
	asm volatile ("{nop " __stringify(NOP_##nop##_MINUS_4) "\n" \
		      " rwd %0, %%" #reg_mnemonic "}" \
		      "{nop} {nop} {nop} {nop}" \
		      : \
		      : "ri" ((__e2k_u64_t) (val))); \
})

/*
 * For some registers (see "Scheduling 1.1.1") there is no requirement
 * of avoiding deferred and exact exception after the long instruction.
 * But some registers (e.g. %wd, %bgr) still require at least 1 real
 * instruction after the write.
 */
#define NATIVE_SET_SREG_CLOSED_EXC(reg_mnemonic, val, nop) \
({ \
	asm volatile ("{nop " __stringify(nop) "\n" \
		      " rws %0, %%" #reg_mnemonic "}\n" \
		      : \
		      : "ri" ((__e2k_u32_t) (val))); \
})

#define NATIVE_SET_DSREG_CLOSED_EXC(reg_mnemonic, val, nop) \
({ \
	asm volatile ("{nop " __stringify(nop) "\n" \
		      " rwd %0, %%" #reg_mnemonic "}" \
		      : \
		      : "ri" ((__e2k_u64_t) (val))); \
})

#define NATIVE_SET_DSREG_CLOSED_EXC_CLOBBERS(reg_mnemonic, val, nop, clobbers) \
({ \
	asm volatile ("{nop " __stringify(nop) "\n" \
		      " rwd %0, %%" #reg_mnemonic "}" \
		      : \
		      : "ri" ((__e2k_u64_t) (val)) \
		      : clobbers); \
})


#define NATIVE_EXIT_HANDLE_SYSCALL(sbr, usd_hi, usd_lo, upsr) \
({ \
	asm volatile ("{rwd %0, %%sbr}" \
		      "{rwd %1, %%usd.hi}" \
		      "{rwd %2, %%usd.lo}" \
		      "{rws %3, %%upsr;" \
		      " nop 4}\n" \
		      : \
		      : "ri" ((__e2k_u64_t) (sbr)), \
			"ri" ((__e2k_u64_t) (usd_hi)), \
			"ri" ((__e2k_u64_t) (usd_lo)), \
			"ri" ((__e2k_u32_t) (upsr))); \
})


/* lcc ignores manually specified clobbers for opened GNU asm,
 * so use closed version (bug #69565, bug #60599) */
#define NATIVE_SET_PSR_IRQ_BARRIER(val) \
({ \
	asm volatile ("{\n" \
		      "nop 5\n" \
		      "rwd %0, %%psr" \
		      "}" \
		      : \
		      : "ri" ((__e2k_u64_t) (val)) \
		      : "memory", PREEMPTION_CLOBBERS); \
})
#define NATIVE_SET_UPSR_IRQ_BARRIER(val) \
({ \
	asm volatile ("{\n" \
		      "nop 4\n" \
		      "rwd %0, %%upsr" \
		      "}" \
		      : \
		      : "ri" ((__e2k_u64_t) (val)) \
		      : "memory", PREEMPTION_CLOBBERS); \
})


#define NATIVE_GET_MMUREG(reg_mnemonic) \
({ \
	register __e2k_u64_t res; \
	asm volatile ("mmurr \t%%" #reg_mnemonic ", %0" \
		: "=r" (res)); \
	res; \
})

#define NATIVE_SET_MMUREG(reg_mnemonic, val) \
({ \
	asm volatile ("mmurw \t%0, %%" #reg_mnemonic \
		: \
		: "r" ((__e2k_u64_t) (val))); \
})

#define NATIVE_TAGGED_LOAD_TO_MMUREG(reg_mnemonic, _addr) \
do { \
	unsigned long long _tmp; \
	asm volatile ("ldrd [ %[addr] + %[opc] ], %[tmp]\n" \
		      "mmurw,s %[tmp], %%" #reg_mnemonic "\n" \
		      : [tmp] "=r" (_tmp) \
		      : [addr] "m" (*((unsigned long long *) (_addr))),	\
			[opc] "i" (TAGGED_MEM_LOAD_REC_OPC)); \
} while (0)

#define NATIVE_STORE_TAGGED_MMUREG(_addr, reg_mnemonic) \
do { \
	unsigned long long _tmp; \
	asm volatile ("mmurr %%" #reg_mnemonic ", %[tmp]\n" \
		      "strd [ %[addr] + %[opc] ], %[tmp]\n" \
		      : [tmp] "=r" (_tmp) \
		      : [addr] "m" (*((unsigned long long *) (_addr))), \
			[opc] "i" (TAGGED_MEM_STORE_REC_OPC)); \
} while (0)

#define NATIVE_GET_MMU_DEBUG_REG(reg_no) \
({ \
	register __e2k_u64_t res; \
	asm volatile ("ldd,5 \t[%1 + 0] %2, %0" \
		: "=r" (res) \
		: "ri" ((__e2k_ptr_t) _DEBUG_REG_NO_TO_MMU_ADDR(reg_no)), \
		  "i" MAS_MMU_DEBUG_REG); \
	res; \
})
#define NATIVE_SET_MMU_DEBUG_REG(reg_no, val) \
({ \
	asm volatile ("std,2 \t[%0 + 0] %1, %2" \
		: \
		: "ri" ((__e2k_ptr_t) _DEBUG_REG_NO_TO_MMU_ADDR(reg_no)), \
		  "i" MAS_MMU_DEBUG_REG, \
		  "ri" ((__e2k_u64_t) (val))); \
})

#define NATIVE_GET_AAUREG(reg_mnemonic, chan_letter) \
({ \
    register __e2k_u32_t res; \
    asm ("aaurr," #chan_letter " \t%%" #reg_mnemonic ", %0" \
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

#define NATIVE_SET_AAUREG(reg_mnemonic, val, chan_letter) \
({ \
	int unused; \
	asm ("aaurw," #chan_letter " %1, %%" #reg_mnemonic \
	     : "=r" (unused) \
	     : "r" ((__e2k_u32_t) (val))); \
})

/* This macro is used to pack two 'aaurr' into one long instruction */
#define NATIVE_SET_AAUREGS(l_reg, r_reg, lval, rval) \
do { \
	int unused; \
	asm ("aaurw,2 %1, %%" #l_reg "\n" \
	     "aaurw,5 %2, %%" #r_reg \
	     : "=r" (unused) \
	     : "r" ((__e2k_u32_t) (lval)), "r" ((__e2k_u32_t) (rval))); \
} while (0)

#define NATIVE_GET_AAUDREG(reg_mnemonic, chan_letter) \
({ \
    register __e2k_u64_t res; \
    asm ("aaurrd," #chan_letter " %%" #reg_mnemonic ", %0" \
                  : "=r" (res)); \
    res; \
})

#define NATIVE_GET_AAUDREGS(l_reg, r_reg, lval, rval) \
({ \
    asm ("aaurrd,2 %%" #l_reg ", %0\n" \
         "aaurrd,5 %%" #r_reg ", %1" \
         : "=r" (lval), "=r" (rval)); \
})


#define NATIVE_SET_AAUDREG(reg_mnemonic, val, chan_letter) \
do { \
	int unused; \
	asm ("aaurwd," #chan_letter " %1, %%" #reg_mnemonic \
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


#define NATIVE_GET_AAUQREG(mem_p, reg_mnemonic) \
({ \
    register __e2k_u64_t lo asm ("%b[0]"); \
    register __e2k_u64_t hi asm ("%b[1]"); \
    asm volatile ("aaurrq \t%%" #reg_mnemonic ", %%qb[0]" \
                  : \
                  : \
                  : "%b[0]", "%b[1]"); \
    (mem_p)->lo = lo; \
    (mem_p)->hi = hi; \
})

#define NATIVE_GET_AAUQREGS(mem_p, reg1, reg2, reg3, reg4) \
({ \
    register __e2k_u64_t lo1 asm ("%b[0]"); \
    register __e2k_u64_t hi1 asm ("%b[1]"); \
    register __e2k_u64_t lo2 asm ("%b[2]"); \
    register __e2k_u64_t hi2 asm ("%b[3]"); \
    register __e2k_u64_t lo3 asm ("%b[4]"); \
    register __e2k_u64_t hi3 asm ("%b[5]"); \
    register __e2k_u64_t lo4 asm ("%b[6]"); \
    register __e2k_u64_t hi4 asm ("%b[7]"); \
    asm volatile ("aaurrq \t%%" #reg1 ", %%qb[0]\n" \
                  "aaurrq \t%%" #reg2 ", %%qb[2]\n" \
                 "aaurrq \t%%" #reg3 ", %%qb[4]\n" \
                 "aaurrq \t%%" #reg4 ", %%qb[6]\n" \
                  : \
                  : \
                  : "%b[0]", "%b[1]", "%b[2]", "%b[3]", \
                   "%b[4]", "%b[5]", "%b[6]", "%b[7]"); \
    (mem_p)->lo = lo1; \
    (mem_p)->hi = hi1; \
    (mem_p + 1)->lo = lo2; \
    (mem_p + 1)->hi = hi2; \
    (mem_p + 2)->lo = lo3; \
    (mem_p + 2)->hi = hi3; \
    (mem_p + 3)->lo = lo4; \
    (mem_p + 3)->hi = hi4; \
})

#define NATIVE_SET_AAUQREG(reg_mnemonic, mem_p) \
do { \
	register u64 lo asm ("%b[0]"); \
	register u64 hi asm ("%b[1]"); \
	int unused; \
	lo = (mem_p)->lo; \
	hi = (mem_p)->hi; \
	asm ("aaurwq %%r0, %%" #reg_mnemonic \
	     : "=r" (unused) \
	     : "r" (lo), "r" (hi)); \
} while (0)

#define NATIVE_SET_AAUQREGS(mem_p, reg1, reg2, reg3, reg4) \
do { \
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

/* Clear AAU to prepare it for restoring */
#define NATIVE_CLEAR_APB() \
do { \
	asm volatile ("1:\n" \
		      "{ipd 0; disp %%ctpr2, 1b}" \
		      : \
		      : \
		      : "ctpr2"); \
} while (0)

/* Do "disp" for all %ctpr's */
#define E2K_DISP_CTPRS() \
	asm volatile ("1:\n" \
		      "{ipd 0; disp %%ctpr1, 1b}" \
		      "{ipd 0; disp %%ctpr2, 1b}" \
		      "{ipd 0; disp %%ctpr3, 1b}" \
		      : \
		      : \
		      : "ctpr1", "ctpr2", "ctpr3")

#define LOAD_NV_MAS(_addr, _val, _mas, size_letter, clobber) \
do { \
	_Pragma("no_asm_inline") \
	asm NOT_VOLATILE ("ld" #size_letter" %[addr], %[val], mas=%[mas]" \
		: [val] "=r" (_val) \
		: [addr] "m" (*(_addr)), \
		  [mas] "i" (_mas) \
		: clobber); \
} while (0)

#define STORE_NV_MAS(_addr, _val, _mas, size_letter, clobber) \
do { \
	_Pragma("no_asm_inline") \
	asm NOT_VOLATILE ("st" #size_letter" %[addr], %[val], mas=%[mas]" \
		: [addr] "=m" (*(_addr)) \
		: [val] "r" (_val), \
		  [mas] "i" (_mas) \
		: clobber); \
} while (0)

/*
 * Do load with specified MAS
 */

/*
 * After iset v6 these loads are not ordered with regards to RAM accesses.
 * so add barriers manually. Driver writers who want control over barriers
 * should use readX_relaxed()/writeX_relaxed() anyway.
 */
#if CONFIG_CPU_ISET >= 6

# define READ_MAS_BARRIER_AFTER(mas) \
do { \
	if ((mas) == MAS_IOADDR) \
		E2K_WAIT_LD_C_LAL_SAL(); \
} while (0)
# define WRITE_MAS_BARRIER_BEFORE(mas) \
do { \
	if ((mas) == MAS_IOADDR) \
		E2K_WAIT_ST_C_SAS_LD_C_SAL(); \
} while (0)
/*
 * Not required by documentation, but this is how
 * x86 works and how most of the drivers are tested.
 */
# define WRITE_MAS_BARRIER_AFTER(mas) \
do { \
	if ((mas) == MAS_IOADDR) \
		E2K_WAIT_ST_C_SAS(); \
} while (0)

#elif CONFIG_CPU_ISET == 0

# define READ_MAS_BARRIER_AFTER(mas) \
do { \
	if ((mas) == MAS_IOADDR) \
		__E2K_WAIT(_ld_c); \
} while (0)
# define WRITE_MAS_BARRIER_BEFORE(mas) \
do { \
	if ((mas) == MAS_IOADDR) \
		__E2K_WAIT(_st_c | _ld_c); \
} while (0)
/*
 * Not required by documentation, but this is how
 * x86 works and how most of the drivers are tested.
 */
# define WRITE_MAS_BARRIER_AFTER(mas) \
do { \
	if ((mas) == MAS_IOADDR) \
		__E2K_WAIT(_st_c); \
} while (0)

#else

# define READ_MAS_BARRIER_AFTER(mas)
# define WRITE_MAS_BARRIER_BEFORE(mas)
# define WRITE_MAS_BARRIER_AFTER(mas)
#endif

#define NATIVE_DO_READ_MAS_TO(addr, val, mas, size_letter, chan_letter) \
({ \
	int __mas = (mas); \
	asm volatile ("ld" #size_letter "," #chan_letter " \t0x0, [%1] %2, %0" \
		: "=r" (val) \
		: "r" ((__e2k_ptr_t) (addr)), \
		"i" (__mas)); \
	READ_MAS_BARRIER_AFTER(__mas); \
})

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
		: "r" ((__e2k_ptr_t) (addr)), \
		  "r" ((type) (val)), \
		  "i" (__mas)); \
	WRITE_MAS_BARRIER_AFTER(__mas); \
})

#define NATIVE_DO_WRITE_TAGGED(addr, val, type, size_letter, chan_letter) \
({ \
	asm volatile ("st" #size_letter ",sm," #chan_letter " \t0x0, [%0], %1" \
		: \
		: "r" ((__e2k_ptr_t) (addr)), \
		  "r" ((type) (val))); \
})

#define NATIVE_READ_MAS_B_CH_TO(addr, val, mas, chan_letter) \
		NATIVE_DO_READ_MAS_TO((addr), (val), (mas), b, chan_letter)
#define NATIVE_READ_MAS_H_CH_TO(addr, val, mas, chan_letter) \
		NATIVE_DO_READ_MAS_TO((addr), (val), (mas), h, chan_letter)
#define NATIVE_READ_MAS_W_CH_TO(addr, val, mas, chan_letter) \
		NATIVE_DO_READ_MAS_TO((addr), (val), (mas), w, chan_letter)
#define NATIVE_READ_MAS_D_CH_TO(addr, val, mas, chan_letter) \
		NATIVE_DO_READ_MAS_TO((addr), (val), (mas), d, chan_letter)

#define NATIVE_READ_MAS_B_CH(addr, mas, chan_letter) \
		NATIVE_DO_READ_MAS((addr), (mas), __e2k_u8_t, b, chan_letter)
#define NATIVE_READ_MAS_H_CH(addr, mas, chan_letter) \
		NATIVE_DO_READ_MAS((addr), (mas), __e2k_u16_t, h, chan_letter)
#define NATIVE_READ_MAS_W_CH(addr, mas, chan_letter) \
		NATIVE_DO_READ_MAS((addr), (mas), __e2k_u32_t, w, chan_letter)
#define NATIVE_READ_MAS_D_CH(addr, mas, chan_letter) \
		NATIVE_DO_READ_MAS((addr), (mas), __e2k_u64_t, d, chan_letter)

#define NATIVE_READ_MAS_B(addr, mas)  NATIVE_READ_MAS_B_CH((addr), (mas), 2)
#define NATIVE_READ_MAS_H(addr, mas)  NATIVE_READ_MAS_H_CH((addr), (mas), 2)
#define NATIVE_READ_MAS_W(addr, mas)  NATIVE_READ_MAS_W_CH((addr), (mas), 2)
#define NATIVE_READ_MAS_D(addr, mas)  NATIVE_READ_MAS_D_CH((addr), (mas), 2)

#define NATIVE_READ_MAS_B_5(addr, mas)  NATIVE_READ_MAS_B_CH((addr), (mas), 5)
#define NATIVE_READ_MAS_H_5(addr, mas)  NATIVE_READ_MAS_H_CH((addr), (mas), 5)
#define NATIVE_READ_MAS_W_5(addr, mas)  NATIVE_READ_MAS_W_CH((addr), (mas), 5)
#define NATIVE_READ_MAS_D_5(addr, mas)  NATIVE_READ_MAS_D_CH((addr), (mas), 5)

#define NATIVE_WRITE_MAS_B_CH(addr, val, mas, chan_letter) \
		NATIVE_DO_WRITE_MAS((addr), (val), (mas), __e2k_u8_t, b, \
					chan_letter)
#define NATIVE_WRITE_MAS_H_CH(addr, val, mas, chan_letter) \
		NATIVE_DO_WRITE_MAS((addr), (val), (mas), __e2k_u16_t, h, \
					chan_letter)
#define NATIVE_WRITE_MAS_W_CH(addr, val, mas, chan_letter) \
		NATIVE_DO_WRITE_MAS((addr), (val), (mas), __e2k_u32_t, w, \
					chan_letter)
#define NATIVE_WRITE_MAS_D_CH(addr, val, mas, chan_letter) \
		NATIVE_DO_WRITE_MAS((addr), (val), (mas), __e2k_u64_t, d, \
					chan_letter)
#define	NATIVE_WRITE_TAGGED_D_CH(addr, val, chan_letter) \
		NATIVE_DO_WRITE_TAGGED((addr), (val), __e2k_u64_t, d, \
					chan_letter)
#define NATIVE_WRITE_MAS_B(addr, val, mas)				\
		NATIVE_DO_WRITE_MAS(addr, val, mas, __e2k_u8_t, b, 2)
#define NATIVE_WRITE_MAS_H(addr, val, mas)				\
		NATIVE_DO_WRITE_MAS(addr, val, mas, __e2k_u16_t, h, 2)
#define NATIVE_WRITE_MAS_W(addr, val, mas)				\
		NATIVE_DO_WRITE_MAS(addr, val, mas, __e2k_u32_t, w, 2)
#define NATIVE_WRITE_MAS_D(addr, val, mas)				\
		NATIVE_DO_WRITE_MAS(addr, val, mas, __e2k_u64_t, d, 2)

/*
 * Read from and write to system configuration registers SIC
 * Now SIC is the same as NBSRs registers
 */

#define NATIVE_SET_SICREG(reg_mnemonic, val, cln, pln) \
({ \
	register __e2k_u64_t addr; \
	register __e2k_u64_t node_id = (cln) << 2; \
	node_id = node_id + ((pln)&0x3); \
	addr = (__e2k_u64_t) THE_NODE_NBSR_PHYS_BASE(node_id); \
	addr = addr + SIC_##reg_mnemonic; \
	NATIVE_WRITE_MAS_W(addr, val, MAS_IOADDR); \
})
#define NATIVE_GET_SICREG(reg_mnemonic, cln, pln) \
({ \
	register __e2k_u32_t res; \
	register __e2k_u64_t addr; \
	register __e2k_u64_t node_id = (cln) << 2; \
	node_id = node_id + ((pln)&0x3); \
	addr = (__e2k_u64_t) THE_NODE_NBSR_PHYS_BASE(node_id); \
	addr = addr + SIC_##reg_mnemonic; \
	res = NATIVE_READ_MAS_W(addr, MAS_IOADDR); \
	res; \
})


/*
 * Prefetching with fully speculative load is
 * needed when the passed address can be invalid.
 */
#if !defined(CONFIG_BOOT_E2K) && !defined(E2K_P2V)
# define E2K_PREFETCH_L2_SPEC(addr) \
do { \
	int unused; \
	asm ("ldb,sm %1, 0, %%empty, mas=%2\n" \
		: "=r" (unused) \
		: "r" (addr), \
		  "i" (MAS_LOAD_SPEC | MAS_BYPASS_L1_CACHE)); \
} while (0)

# define E2K_PREFETCH_L2_SPEC_OFFSET(addr, offset) \
do { \
	int unused; \
	asm ("ldb,sm %1, %2, %%empty, mas=%3\n" \
		: "=r" (unused) \
		: "r" (addr), \
		  "i" (offset), \
		  "i" (MAS_LOAD_SPEC | MAS_BYPASS_L1_CACHE)); \
} while (0)

# define E2K_PREFETCH_L2_OFFSET(addr, offset) \
do { \
	int unused; \
	asm ("ldb,sm %1, %2, %%empty, mas=%3\n" \
		: "=r" (unused) \
		: "r" (addr), \
		  "i" (offset), \
		  "i" (MAS_BYPASS_L1_CACHE)); \
} while (0)

# define E2K_PREFETCH_L2_256(addr) \
do { \
	int unused; \
	asm (	"ldb,0,sm %1, 0, %%empty, mas=%2\n" \
		"ldb,2,sm %1, 64, %%empty, mas=%2\n" \
		"ldb,3,sm %1, 128, %%empty, mas=%2\n" \
		"ldb,5,sm %1, 192, %%empty, mas=%2" \
		: "=r" (unused) \
		: "r" (addr), \
		  "i" (MAS_BYPASS_L1_CACHE)); \
} while (0)

# define E2K_PREFETCH_L2(addr) \
do { \
	int unused; \
	asm ("ldb,sm %1, 0, %%empty, mas=%2" \
		: "=r" (unused) \
		: "r" (addr), \
		  "i" (MAS_BYPASS_L1_CACHE)); \
} while (0)

# define E2K_PREFETCH_L1_SPEC(addr) \
do { \
	int unused; \
	asm ("ldb,sm %1, 0, %%empty, mas=%2\n" \
		: "=r" (unused) \
		: "r" (addr), \
		  "i" (MAS_LOAD_SPEC)); \
} while (0)

# define E2K_PREFETCH_L1_SPEC_OFFSET(addr, offset) \
do { \
	int unused; \
	asm ("ldb,sm %1, %2, %%empty, mas=%3\n" \
		: "=r" (unused) \
		: "r" (addr), \
		  "i" (offset), \
		  "i" (MAS_LOAD_SPEC)); \
} while (0)

# define E2K_PREFETCH_L1_OFFSET(addr, offset) \
do { \
	int unused; \
	asm ("ldb,sm %1, %2, %%empty\n" \
		: "=r" (unused) \
		: "r" (addr), \
		  "i" (offset)); \
} while (0)

# define E2K_PREFETCH_L1_256(addr) \
do { \
	int unused; \
	asm (	"ldb,0,sm %1, 0, %%empty\n" \
		"ldb,2,sm %1, 64, %%empty\n" \
		"ldb,3,sm %1, 128, %%empty\n" \
		"ldb,5,sm %1, 192, %%empty" \
		: "=r" (unused) \
		: "r" (addr)); \
} while (0)

# define E2K_PREFETCH_L1(addr) \
do { \
	int unused; \
	asm ("ldb,3 %1, 0, %%empty" \
		: "=r" (unused) \
		: "r" (addr)); \
} while (0)
#else
# define E2K_PREFETCH_L2_SPEC_OFFSET(addr, offset) \
				do { (void) (addr); (void) (offset); } while (0)
# define E2K_PREFETCH_L2_OFFSET(addr, offset) \
				do { (void) (addr); (void) (offset); } while (0)
# define E2K_PREFETCH_L1_SPEC_OFFSET(addr, offset) \
				do { (void) (addr); (void) (offset); } while (0)
# define E2K_PREFETCH_L1_OFFSET(addr, offset) \
				do { (void) (addr); (void) (offset); } while (0)
# define E2K_PREFETCH_L2_SPEC(addr)		do { (void) (addr); } while (0)
# define E2K_PREFETCH_L2_256(addr)		do { (void) (addr); } while (0)
# define E2K_PREFETCH_L2(addr)			do { (void) (addr); } while (0)
# define E2K_PREFETCH_L1_SPEC(addr)		do { (void) (addr); } while (0)
# define E2K_PREFETCH_L1_256(addr)		do { (void) (addr); } while (0)
# define E2K_PREFETCH_L1(addr)			do { (void) (addr); } while (0)
#endif

/*
 * Recovery operations
 * chan: 0, 1, 2 or 3
 */
#define NATIVE_RECOVERY_TAGGED_LOAD_TO(_addr, _opc, _val, _tag, _chan) \
do { \
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

#define NATIVE_RECOVERY_LOAD_TO(addr, opc, val, chan_letter) \
({ \
 	asm volatile ("ldrd," #chan_letter "\t[%1 + %2], %0" \
 			: "=r"(val) \
 			: "r" ((__e2k_ptr_t) (addr)), \
 			  "r" ((__e2k_u64_t) (opc))); \
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
#define NATIVE_RECOVERY_LOAD_TO_THE_GREG_CH_VR(_addr, _opc, greg_no, \
		_chan, _vr, _quadro) \
do { \
	u64 val, val_8; \
	u32 __chan = (u32) (_chan); \
	u32 __quadro = (u32) (_quadro); \
	u32 __chan_q = (__quadro) ? __chan : 4; /* Not existent channel - skip */ \
	u64 __opc = (_opc); \
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
		"{ldrd,0 [ %[addr] + %[opc] ], %[val] ? %%pred20\n" \
		" ldrd,2 [ %[addr] + %[opc] ], %[val] ? %%pred21\n" \
		" ldrd,3 [ %[addr] + %[opc] ], %[val] ? %%pred22\n" \
		" ldrd,5 [ %[addr] + %[opc] ], %[val] ? %%pred23\n" \
		" cmpesb,1 %[quadro], 0, %%pred18\n" \
		" cmpesb,4 %[vr], 0, %%pred19}\n" \
		"{nop 3\n" \
		" ldrd,0 [ %[addr] + %[opc_8] ], %[val_8] ? %%pred24\n" \
		" ldrd,2 [ %[addr] + %[opc_8] ], %[val_8] ? %%pred25\n" \
		" ldrd,3 [ %[addr] + %[opc_8] ], %[val_8] ? %%pred26\n" \
		" ldrd,5 [ %[addr] + %[opc_8] ], %[val_8] ? %%pred27}\n" \
		"{movts %%g" #greg_no ", %[val] ? %%pred19}\n" \
		"{movtd %[val_8], %%dg" #greg_no " ? ~ %%pred18\n" \
		" addd %[greg], 0, %%db[0] ? ~ %%pred18\n" \
		" call %%ctpr1, wbs=%# ? ~ %%pred18}\n" \
		"{movtd %[val], %%dg" #greg_no "}\n" \
		: [val] "=&r" (val), [val_8] "=&r" (val_8) \
		: [addr] "r" (_addr), [vr] "ir" ((u32) (_vr)), \
		  [chan] "ir" (__chan), [chan_q] "ir" (__chan_q), \
		  [opc] "r" (__opc), [opc_8] "r" (__opc | 8ull),	\
		  [quadro] "r" (__quadro), [greg] "i" ((u64) (greg_no)) \
		: "call", "memory", "pred18", "pred19", "pred20", "pred21", \
		  "pred22", "pred23", "pred24", "pred25", "pred26", "pred27", \
		  "g" #greg_no); \
} while (0)

/*
 * As NATIVE_RECOVERY_LOAD_TO_THE_GREG_CH_VR but repeats from cellar
 * an aligned atomic 16-bytes load.
 */
#define NATIVE_RECOVERY_LOAD_TO_THE_GREG_VR_ATOMIC_QP(_addr, _opc, \
		greg_no, _vr) \
do { \
	u64 val; \
	u64 __opc = (_opc); \
	asm (	"{disp %%ctpr1, qpswitchd_sm\n" \
		" nop 4\n" \
		" ldrd,0 [ %[addr] + %[opc] ], %[val]\n" \
		" ldrd,2 [ %[addr] + %[opc_8] ], %%g" #greg_no "\n" \
		" cmpesb,1 %[vr], 0, %%pred19}\n" \
		"{movts,0 %%g" #greg_no ", %[val] ? %%pred19\n" \
		" addd,2 %[greg], 0, %%db[0]\n" \
		" call %%ctpr1, wbs=%#}\n" \
		"{movtd %[val], %%dg" #greg_no "}\n" \
		: [val] "=&r" (val) \
		: [addr] "r" (_addr), [vr] "ir" ((u32) (_vr)), \
		  [opc] "r" (__opc), [opc_8] "r" (__opc | 8ull), \
		  [greg] "i" ((u64) (greg_no)) \
		: "call", "memory", "pred19", "g" #greg_no); \
} while (false)

#define NATIVE_RECOVERY_LOAD_TO_THE_GREG_VR_ATOMIC_QP_OR_Q(_addr, _opc, \
		greg_no_lo, greg_no_hi, _vr, _qp_load) \
do { \
	u64 val; \
	u64 __opc = (_opc); \
	if (_qp_load) { \
		asm (	"{disp %%ctpr1, qpswitchd_sm\n" \
			" nop 4\n" \
			" ldrd,0 [ %[addr] + %[opc] ], %[val]\n" \
			" ldrd,2 [ %[addr] + %[opc_8] ], %%g" #greg_no_lo "\n" \
			" cmpesb,1 %[vr], 0, %%pred19}\n" \
			"{movts,0 %%g" #greg_no_lo ", %[val] ? %%pred19\n" \
			" addd,2 %[greg], 0, %%db[0]\n" \
			" call %%ctpr1, wbs=%#}\n" \
			"{movtd %[val], %%dg" #greg_no_lo "}\n" \
			: [val] "=&r" (val) \
			: [addr] "r" (_addr), [vr] "ir" ((u32) (_vr)), \
			  [opc] "r" (__opc), [opc_8] "r" (__opc | 8ull), \
			  [greg] "i" ((u64) (greg_no_lo)) \
			: "call", "memory", "pred19", "g" #greg_no_lo); \
	} else { \
		asm (	"{nop 4\n" \
			" ldrd,0 [ %[addr] + %[opc] ], %[val]\n" \
			" ldrd,2 [ %[addr] + %[opc_8] ], %%g" #greg_no_hi "\n" \
			" cmpesb,1 %[vr], 0, %%pred19}\n" \
			"{nop 1\n" \
			" movts,0 %%g" #greg_no_lo ", %[val] ? %%pred19}\n" \
			"{movtd,0 %[val], %%dg" #greg_no_lo "}\n" \
			: [val] "=&r" (val) \
			: [addr] "r" (_addr), [vr] "ir" ((u32) (_vr)), \
			  [opc] "r" (__opc), [opc_8] "r" (__opc | 8ull), \
			  [greg] "i" ((u64) (greg_no_lo)) \
			: "call", "memory", "pred19", "g" #greg_no_lo); \
	} \
} while (false)

#define NATIVE_RECOVERY_LOAD_TO_A_GREG_CH_VR(addr, opc, greg_num, \
		chan_opc, vr, quadro) \
do { \
	switch (greg_num) { \
	case  0: \
		NATIVE_RECOVERY_LOAD_TO_THE_GREG_CH_VR(addr, opc, 0, \
							chan_opc, vr, quadro); \
		break; \
	case  1: \
		NATIVE_RECOVERY_LOAD_TO_THE_GREG_CH_VR(addr, opc, 1, \
							chan_opc, vr, quadro); \
		break; \
	case  2: \
		NATIVE_RECOVERY_LOAD_TO_THE_GREG_CH_VR(addr, opc, 2, \
							chan_opc, vr, quadro); \
		break; \
	case  3: \
		NATIVE_RECOVERY_LOAD_TO_THE_GREG_CH_VR(addr, opc, 3, \
							chan_opc, vr, quadro); \
		break; \
	case  4: \
		NATIVE_RECOVERY_LOAD_TO_THE_GREG_CH_VR(addr, opc, 4, \
							chan_opc, vr, quadro); \
		break; \
	case  5: \
		NATIVE_RECOVERY_LOAD_TO_THE_GREG_CH_VR(addr, opc, 5, \
							chan_opc, vr, quadro); \
		break; \
	case  6: \
		NATIVE_RECOVERY_LOAD_TO_THE_GREG_CH_VR(addr, opc, 6, \
							chan_opc, vr, quadro); \
		break; \
	case  7: \
		NATIVE_RECOVERY_LOAD_TO_THE_GREG_CH_VR(addr, opc, 7, \
							chan_opc, vr, quadro); \
		break; \
	case  8: \
		NATIVE_RECOVERY_LOAD_TO_THE_GREG_CH_VR(addr, opc, 8, \
							chan_opc, vr, quadro); \
		break; \
	case  9: \
		NATIVE_RECOVERY_LOAD_TO_THE_GREG_CH_VR(addr, opc, 9, \
							chan_opc, vr, quadro); \
		break; \
	case 10: \
		NATIVE_RECOVERY_LOAD_TO_THE_GREG_CH_VR(addr, opc, 10, \
							chan_opc, vr, quadro); \
		break; \
	case 11: \
		NATIVE_RECOVERY_LOAD_TO_THE_GREG_CH_VR(addr, opc, 11, \
							chan_opc, vr, quadro); \
		break; \
	case 12: \
		NATIVE_RECOVERY_LOAD_TO_THE_GREG_CH_VR(addr, opc, 12, \
							chan_opc, vr, quadro); \
		break; \
	case 13: \
		NATIVE_RECOVERY_LOAD_TO_THE_GREG_CH_VR(addr, opc, 13, \
							chan_opc, vr, quadro); \
		break; \
	case 14: \
		NATIVE_RECOVERY_LOAD_TO_THE_GREG_CH_VR(addr, opc, 14, \
							chan_opc, vr, quadro); \
		break; \
	case 15: \
		NATIVE_RECOVERY_LOAD_TO_THE_GREG_CH_VR(addr, opc, 15, \
							chan_opc, vr, quadro); \
		break; \
	/* Do not load g16-g19 as they are used by kernel */ \
	case 16: \
	case 17: \
	case 18: \
	case 19: \
		break; \
	case 20: \
		NATIVE_RECOVERY_LOAD_TO_THE_GREG_CH_VR(addr, opc, 20, \
							chan_opc, vr, quadro); \
		break; \
	case 21: \
		NATIVE_RECOVERY_LOAD_TO_THE_GREG_CH_VR(addr, opc, 21, \
							chan_opc, vr, quadro); \
		break; \
	case 22: \
		NATIVE_RECOVERY_LOAD_TO_THE_GREG_CH_VR(addr, opc, 22, \
							chan_opc, vr, quadro); \
		break; \
	case 23: \
		NATIVE_RECOVERY_LOAD_TO_THE_GREG_CH_VR(addr, opc, 23, \
							chan_opc, vr, quadro); \
		break; \
	case 24: \
		NATIVE_RECOVERY_LOAD_TO_THE_GREG_CH_VR(addr, opc, 24, \
							chan_opc, vr, quadro); \
		break; \
	case 25: \
		NATIVE_RECOVERY_LOAD_TO_THE_GREG_CH_VR(addr, opc, 25, \
							chan_opc, vr, quadro); \
		break; \
	case 26: \
		NATIVE_RECOVERY_LOAD_TO_THE_GREG_CH_VR(addr, opc, 26, \
							chan_opc, vr, quadro); \
		break; \
	case 27: \
		NATIVE_RECOVERY_LOAD_TO_THE_GREG_CH_VR(addr, opc, 27, \
							chan_opc, vr, quadro); \
		break; \
	case 28: \
		NATIVE_RECOVERY_LOAD_TO_THE_GREG_CH_VR(addr, opc, 28, \
							chan_opc, vr, quadro); \
		break; \
	case 29: \
		NATIVE_RECOVERY_LOAD_TO_THE_GREG_CH_VR(addr, opc, 29, \
							chan_opc, vr, quadro); \
		break; \
	case 30: \
		NATIVE_RECOVERY_LOAD_TO_THE_GREG_CH_VR(addr, opc, 30, \
							chan_opc, vr, quadro); \
		break; \
	case 31: \
		NATIVE_RECOVERY_LOAD_TO_THE_GREG_CH_VR(addr, opc, 31, \
							chan_opc, vr, quadro); \
		break; \
	default: \
		panic("Invalid global register # %d\n", greg_num); \
	} \
} while (0)

#define NATIVE_RECOVERY_LOAD_TO_A_GREG_VR_ATOMIC(addr, opc, greg_num, \
		vr, qp_load) \
do { \
	switch (greg_num) { \
	case  0: \
		NATIVE_RECOVERY_LOAD_TO_THE_GREG_VR_ATOMIC_QP_OR_Q(addr, opc, \
				0, 1, vr, qp_load); \
		break; \
	case  1: \
		NATIVE_RECOVERY_LOAD_TO_THE_GREG_VR_ATOMIC_QP(addr, opc, 1, \
				vr); \
		break; \
	case  2: \
		NATIVE_RECOVERY_LOAD_TO_THE_GREG_VR_ATOMIC_QP_OR_Q(addr, opc, \
				2, 3, vr, qp_load); \
		break; \
	case  3: \
		NATIVE_RECOVERY_LOAD_TO_THE_GREG_VR_ATOMIC_QP(addr, opc, 3, \
				vr); \
		break; \
	case  4: \
		NATIVE_RECOVERY_LOAD_TO_THE_GREG_VR_ATOMIC_QP_OR_Q(addr, opc, \
				4, 5, vr, qp_load); \
		break; \
	case  5: \
		NATIVE_RECOVERY_LOAD_TO_THE_GREG_VR_ATOMIC_QP(addr, opc, 5, \
				vr); \
		break; \
	case  6: \
		NATIVE_RECOVERY_LOAD_TO_THE_GREG_VR_ATOMIC_QP_OR_Q(addr, opc, \
				6, 7, vr, qp_load); \
		break; \
	case  7: \
		NATIVE_RECOVERY_LOAD_TO_THE_GREG_VR_ATOMIC_QP(addr, opc, 7, \
				vr); \
		break; \
	case  8: \
		NATIVE_RECOVERY_LOAD_TO_THE_GREG_VR_ATOMIC_QP_OR_Q(addr, opc, \
				8, 9, vr, qp_load); \
		break; \
	case  9: \
		NATIVE_RECOVERY_LOAD_TO_THE_GREG_VR_ATOMIC_QP(addr, opc, 9, \
				vr); \
		break; \
	case 10: \
		NATIVE_RECOVERY_LOAD_TO_THE_GREG_VR_ATOMIC_QP_OR_Q(addr, opc, \
				10, 11, vr, qp_load); \
		break; \
	case 11: \
		NATIVE_RECOVERY_LOAD_TO_THE_GREG_VR_ATOMIC_QP(addr, opc, 11, \
				vr); \
		break; \
	case 12: \
		NATIVE_RECOVERY_LOAD_TO_THE_GREG_VR_ATOMIC_QP_OR_Q(addr, opc, \
				12, 13, vr, qp_load); \
		break; \
	case 13: \
		NATIVE_RECOVERY_LOAD_TO_THE_GREG_VR_ATOMIC_QP(addr, opc, 13, \
				vr); \
		break; \
	case 14: \
		NATIVE_RECOVERY_LOAD_TO_THE_GREG_VR_ATOMIC_QP_OR_Q(addr, opc, \
				14, 15, vr, qp_load); \
		break; \
	case 15: \
		NATIVE_RECOVERY_LOAD_TO_THE_GREG_VR_ATOMIC_QP(addr, opc, 15, \
				vr); \
		break; \
	/* Do not load g16-g19 as they are used by kernel */ \
	case 16: \
	case 17: \
	case 18: \
	case 19: \
		break; \
	case 20: \
		NATIVE_RECOVERY_LOAD_TO_THE_GREG_VR_ATOMIC_QP_OR_Q(addr, opc, \
				20, 21, vr, qp_load); \
		break; \
	case 21: \
		NATIVE_RECOVERY_LOAD_TO_THE_GREG_VR_ATOMIC_QP(addr, opc, 21, \
				vr); \
		break; \
	case 22: \
		NATIVE_RECOVERY_LOAD_TO_THE_GREG_VR_ATOMIC_QP_OR_Q(addr, opc, \
				22, 23, vr, qp_load); \
		break; \
	case 23: \
		NATIVE_RECOVERY_LOAD_TO_THE_GREG_VR_ATOMIC_QP(addr, opc, 23, \
				vr); \
		break; \
	case 24: \
		NATIVE_RECOVERY_LOAD_TO_THE_GREG_VR_ATOMIC_QP_OR_Q(addr, opc, \
				24, 25, vr, qp_load); \
		break; \
	case 25: \
		NATIVE_RECOVERY_LOAD_TO_THE_GREG_VR_ATOMIC_QP(addr, opc, 25, \
				vr); \
		break; \
	case 26: \
		NATIVE_RECOVERY_LOAD_TO_THE_GREG_VR_ATOMIC_QP_OR_Q(addr, opc, \
				26, 27, vr, qp_load); \
		break; \
	case 27: \
		NATIVE_RECOVERY_LOAD_TO_THE_GREG_VR_ATOMIC_QP(addr, opc, 27, \
				vr); \
		break; \
	case 28: \
		NATIVE_RECOVERY_LOAD_TO_THE_GREG_VR_ATOMIC_QP_OR_Q(addr, opc, \
				28, 29, vr, qp_load); \
		break; \
	case 29: \
		NATIVE_RECOVERY_LOAD_TO_THE_GREG_VR_ATOMIC_QP(addr, opc, 29, \
				vr); \
		break; \
	case 30: \
		NATIVE_RECOVERY_LOAD_TO_THE_GREG_VR_ATOMIC_QP_OR_Q(addr, opc, \
				30, 31, vr, qp_load); \
		break; \
	case 31: \
		NATIVE_RECOVERY_LOAD_TO_THE_GREG_VR_ATOMIC_QP(addr, opc, 31, \
				vr); \
		break; \
	default: \
		panic("Invalid global register # %d\n", greg_num); \
	} \
} while (0)

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
	asm (	"{puttagd,2 %[val], %[tag], %[tmp]\n" \
		" puttagd,5 %[val_ext], %[tag_ext], %[tmp_ext]}\n" \
		"{strd,2 [ %[addr] + %[opc] ], %[tmp]\n" \
		" strd,5 [ %[addr] + %[opc_ext] ], %[tmp_ext]}\n" \
		: [tmp] "=&r" (tmp), [tmp_ext] "=&r" (tmp_ext) \
		: [addr] "r" (_addr), \
		  [val] "r" ((u64) (_val)), [val_ext] "r" ((u64) (_val_ext)), \
		  [tag] "r" ((u32) (_tag)), [tag_ext] "r" ((u32) (_tag_ext)), \
		  [opc] "ir" (_opc), [opc_ext] "ir" (_opc_ext) \
		: "memory"); \
})

#define NATIVE_RECOVERY_TAGGED_STORE(_addr, _val, _tag, _opc, \
		_val_ext, _tag_ext, _opc_ext, _chan, _quadro) \
({ \
	u64 tmp, tmp_ext; \
	u32 __chan = (u32) (_chan); \
	u32 __chan_q = (_quadro) ? __chan : 4; /* Not existent channel - skip */ \
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
		: [tmp] "=&r" (tmp), [tmp_ext] "=&r" (tmp_ext) \
		: [addr] "r" (_addr), \
		  [val] "r" ((u64) (_val)), [val_ext] "r" ((u64) (_val_ext)), \
		  [tag] "r" ((u32) (_tag)), [tag_ext] "r" ((u32) (_tag_ext)), \
		  [opc] "ir" (_opc), [opc_ext] "ir" (_opc_ext), \
		  [chan] "ir" ((u32) (__chan)), [chan_q] "ir" ((u32) (__chan_q)) \
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
	asm volatile ("{puttagd \t%0, %2, %0\n}" \
		      " strd," #chan_letter " \t[%1 + %3], %0\n" \
		      : "+r" (__tmp_reg) \
		      : "r" ((__e2k_ptr_t) (addr)), \
			"ri" ((__e2k_u32_t) (tag)), \
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


#define	__NATIVE_STORE_TAGGED_QWORD(addr, val_lo, val_hi, \
				    tag_lo, tag_hi, offset) \
({                                                                      \
	u64 reg1, reg2;							\
	E2K_BUILD_BUG_ON(sizeof(val_hi) != 8);                          \
	E2K_BUILD_BUG_ON(sizeof(val_lo) != 8);                          \
	asm volatile (	"{puttagd %3, %5, %0\n"                         \
			" puttagd %4, %6, %1}\n"                        \
			"{strd,2 [%2 + %7], %0\n"                       \
			" strd,5 [%2 + %8], %1}\n"                      \
			: "=&r" (reg1), "=&r" (reg2)                    \
			: "r" (addr),                                   \
			  "r" (val_lo),                                 \
			  "r" (val_hi),                                 \
			  "ri" (tag_lo),                                \
			  "ri" (tag_hi),                                \
			  "i" (TAGGED_MEM_STORE_REC_OPC),               \
			  "ri" (TAGGED_MEM_STORE_REC_OPC | offset)      \
			: "memory");                                    \
})
#define	NATIVE_STORE_TAGGED_QWORD(addr, val_lo, val_hi, tag_lo, tag_hi) \
	__NATIVE_STORE_TAGGED_QWORD((addr), (val_lo), (val_hi), \
				    (tag_lo), (tag_hi), 8UL)

#define	E2K_STORE_NULLPTR_QWORD(addr)                                   \
    _E2K_STORE_NULLPTR_QWORD(addr, TAGGED_MEM_STORE_REC_OPC)


#define	_E2K_STORE_NULLPTR_QWORD(addr, opc)                             \
({                                                                      \
    e2k_addr_t   addr_hi = (e2k_addr_t)addr + 8;                        \
    unsigned long np = 0UL;                                             \
    asm volatile ("{puttagd \t%0, %3, %0}\n"                            \
                  " {strd, 2 \t[%1 + %4], %0\n"                         \
                  "  strd, 5 \t[%2 + %4], %0}\n"                        \
                  : "+r" (np)                                           \
		  : "r" ((__e2k_ptr_t) (addr)),                         \
		    "r" ((__e2k_ptr_t) (addr_hi)),                      \
                    "i" (E2K_NULLPTR_ETAG),                             \
                    "i" ( (opc))                                        \
                   : "memory"                                           \
                 );                                                     \
})

#define NATIVE_MOVE_TAGGED_QWORD(_from_lo, _from_hi, _to_lo, _to_hi)	\
({									\
	u64 __val_lo, __val_hi;						\
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
#define NATIVE_MOVE_TAGGED_DWORD_WITH_OPC_CH_VR(_from, _to, _to_hi, _vr, _opc, \
		_chan, _quadro, _not_single_byte) \
do { \
	u64 prev, val, val_8; \
	u32 __chan = (u32) (_chan); \
	u32 __quadro = (u32) (_quadro); \
	u32 __chan_q = (__quadro) ? __chan : 4 /* Not existent channel - skip */; \
	u64 __opc = (_opc); \
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
		: [prev] "=&r" (prev), [val] "=&r" (val), \
		  [val_8] "=&r" (val_8) \
		: [from] "r" (_from), [to] "r" (_to), [to_hi] "r" (_to_hi), \
		  [vr] "ir" ((u32) (_vr)), [quadro] "r" (__quadro), \
		  [chan] "ir" (__chan), [chan_q] "ir" (__chan_q), \
		  [opc] "r" (__opc), [opc_8] "r" (__opc | 8ull),  \
		  [not_single_byte] "ir" (_not_single_byte), \
		  [opc_ld] "i" (TAGGED_MEM_LOAD_REC_OPC), \
		  [opc_st_byte] "i" (MEM_STORE_REC_OPC_B), \
		  [opc_st] "i" (TAGGED_MEM_STORE_REC_OPC) \
		: "memory", "pred18", "pred19", "pred20", "pred21", \
		  "pred22", "pred23", "pred24", "pred25", "pred26", \
		  "pred27", "pred28"); \
} while (false)

/*
 * As NATIVE_MOVE_TAGGED_DWORD_WITH_OPC_CH_VR but repeats from cellar
 * an aligned atomic 16-bytes load.
 */
#define NATIVE_MOVE_TAGGED_DWORD_WITH_OPC_VR_ATOMIC(_from, _to, _to_hi, \
		_vr, _opc) \
do { \
	u64 prev, val, val_8; \
	u64 __opc = (_opc); \
	asm (	"{cmpesb %[vr], 0, %%pred19}\n" \
		"{ldrd,0 [ %[from] + %[opc] ], %[val]\n" \
		" ldrd,2 [ %[from] + %[opc_8] ], %[val_8]}\n" \
		"{nop 4\n" \
		" ldrd [ %[to] + %[opc_ld] ], %[prev] ? %%pred19}\n" \
		"{movts,1 %[prev], %[val] ? %%pred19}\n" \
		"{strd,2 [ %[to] + %[opc_st] ], %[val]\n" \
		" strd,5 [ %[to_hi] + %[opc_st] ], %[val_8]}\n" \
		: [prev] "=&r" (prev), [val] "=&r" (val), \
		  [val_8] "=&r" (val_8) \
		: [from] "r" (_from), [to] "r" (_to), [to_hi] "r" (_to_hi), \
		  [vr] "ir" ((u32) (_vr)), \
		  [opc] "r" (__opc), [opc_8] "r" (__opc | 8ull), \
		  [opc_ld] "i" (TAGGED_MEM_LOAD_REC_OPC), \
		  [opc_st] "i" (TAGGED_MEM_STORE_REC_OPC) \
		: "memory", "pred19"); \
} while (false)

#define E2K_TAGGED_MEMMOVE_8(__dst, __src)				\
({									\
	u64 __tmp1;							\
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

#define E2K_TAGGED_MEMMOVE_16(__dst, __src)				\
({									\
	u64 __tmp1, __tmp2;						\
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

#define E2K_TAGGED_MEMMOVE_24(__dst, __src)				\
({									\
	u64 __tmp1, __tmp2, __tmp3;					\
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

#define E2K_TAGGED_MEMMOVE_32(__dst, __src)				\
({									\
	u64 __tmp1, __tmp2, __tmp3, __tmp4;				\
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

#define E2K_TAGGED_MEMMOVE_40(__dst, __src)				\
({									\
	u64 __tmp1, __tmp2, __tmp3, __tmp4, __tmp5;			\
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

#define E2K_TAGGED_MEMMOVE_48(__dst, __src)				\
({									\
	u64 __tmp1, __tmp2, __tmp3, __tmp4, __tmp5, __tmp6;		\
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

#define E2K_TAGGED_MEMMOVE_56(__dst, __src)				\
({									\
	u64 __tmp1, __tmp2, __tmp3, __tmp4, __tmp5, __tmp6, __tmp7;	\
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

#define E2K_TAGGED_MEMMOVE_64(__dst, __src)				\
({									\
	u64 __tmp1, __tmp2, __tmp3, __tmp4, __tmp5, __tmp6, __tmp7, __tmp8; \
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

#define E2K_TAGGED_MEMMOVE_128_RF_V2(__dst, __src)			\
({									\
	u64 __tmp1, __tmp2, __tmp3, __tmp4, __tmp5, __tmp6, __tmp7, __tmp8; \
	asm (								\
		"{\n"							\
		"ldrd,2 [ %[src] + %[ld_opc_r0] ], %[tmp1]\n"		\
		"ldrd,5 [ %[src] + %[ld_opc_r1] ], %[tmp2]\n"		\
		"}\n"							\
		"{\n"							\
		"ldrd,2 [ %[src] + %[ld_opc_r2] ], %[tmp3]\n"		\
		"ldrd,5 [ %[src] + %[ld_opc_r3] ], %[tmp4]\n"		\
		"}\n"							\
		"{\n"							\
		"ldrd,2 [ %[src] + %[ld_opc_r4] ], %[tmp5]\n"		\
		"ldrd,5 [ %[src] + %[ld_opc_r5] ], %[tmp6]\n"		\
		"}\n"							\
		"{\n"							\
		"nop 1\n"						\
		"ldrd,2 [ %[src] + %[ld_opc_r6] ], %[tmp7]\n"		\
		"ldrd,5 [ %[src] + %[ld_opc_r7] ], %[tmp8]\n"		\
		"}\n"							\
		"{\n"							\
		"strd,2 [ %[dst] + %[st_opc_r0] ], %[tmp1]\n"		\
		"strd,5 [ %[dst] + %[st_opc_r1] ], %[tmp2]\n"		\
		"}\n"							\
		"{\n"							\
		"strd,2 [ %[dst] + %[st_opc_r2] ], %[tmp3]\n"		\
		"strd,5 [ %[dst] + %[st_opc_r3] ], %[tmp4]\n"		\
		"}\n"							\
		"{\n"							\
		"strd,2 [ %[dst] + %[st_opc_r4] ], %[tmp5]\n"		\
		"strd,5 [ %[dst] + %[st_opc_r5] ], %[tmp6]\n"		\
		"}\n"							\
		"{\n"							\
		"strd,2 [ %[dst] + %[st_opc_r6] ], %[tmp7]\n"		\
		"strd,5 [ %[dst] + %[st_opc_r7] ], %[tmp8]\n"		\
		"}\n"							\
		: [tmp1] "=&r" (__tmp1), [tmp2] "=&r" (__tmp2),		\
		  [tmp3] "=&r" (__tmp3), [tmp4] "=&r" (__tmp4),		\
		  [tmp5] "=&r" (__tmp5), [tmp6] "=&r" (__tmp6),		\
		  [tmp7] "=&r" (__tmp7), [tmp8] "=&r" (__tmp8)		\
		: [src] "r" (__src), [dst] "r" (__dst),			\
		  [ld_opc_r0] "i" (TAGGED_MEM_LOAD_REC_OPC),		\
		  [ld_opc_r1] "i" (TAGGED_MEM_LOAD_REC_OPC | 8),	\
		  [ld_opc_r2] "i" (TAGGED_MEM_LOAD_REC_OPC | 32),	\
		  [ld_opc_r3] "i" (TAGGED_MEM_LOAD_REC_OPC | 40),	\
		  [ld_opc_r4] "i" (TAGGED_MEM_LOAD_REC_OPC | 64),	\
		  [ld_opc_r5] "i" (TAGGED_MEM_LOAD_REC_OPC | 72),	\
		  [ld_opc_r6] "i" (TAGGED_MEM_LOAD_REC_OPC | 96),	\
		  [ld_opc_r7] "i" (TAGGED_MEM_LOAD_REC_OPC | 104),	\
		  [st_opc_r0] "i" (TAGGED_MEM_STORE_REC_OPC),		\
		  [st_opc_r1] "i" (TAGGED_MEM_STORE_REC_OPC | 8),	\
		  [st_opc_r2] "i" (TAGGED_MEM_STORE_REC_OPC | 32),	\
		  [st_opc_r3] "i" (TAGGED_MEM_STORE_REC_OPC | 40),	\
		  [st_opc_r4] "i" (TAGGED_MEM_STORE_REC_OPC | 64),	\
		  [st_opc_r5] "i" (TAGGED_MEM_STORE_REC_OPC | 72),	\
		  [st_opc_r6] "i" (TAGGED_MEM_STORE_REC_OPC | 96),	\
		  [st_opc_r7] "i" (TAGGED_MEM_STORE_REC_OPC | 104)	\
		: "memory");						\
})

/* Store quadro pointer "ptr" at address "addr" */
#define E2K_SET_TAGS_AND_STORE_QUADRO(ptr, addr) \
do { \
	asm ("{\n" \
	     "puttagd %0, 15, %%db[0]\n" \
	     "puttagd %1, 12, %%db[1]\n" \
	     "}\n" \
	     "{\n" \
	     "strd,2 [ %2 + %3 ], %%db[0]\n" \
	     "strd,5 [ %2 + %4 ], %%db[1]\n" \
	     "}\n" \
	     : \
	     : "r" (AW(ptr).lo), "r" (AW(ptr).hi), \
	       "r" ((unsigned long) addr), \
	       "i" (TAGGED_MEM_STORE_REC_OPC), \
	       "i" (TAGGED_MEM_STORE_REC_OPC | 8UL) \
	     : "%b[0]", "%b[1]"); \
} while (0)


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

#define NATIVE_LOAD_TAGD(addr) \
({ \
	u32 __dtag; \
	asm ("ldrd [%1 + %2], %0\n" \
	     "gettagd %0, %0\n" \
	     : "=r"(__dtag) \
	     : "m" (*(unsigned long long *) (addr)), \
	       "i"(TAGGED_MEM_LOAD_REC_OPC)); \
	__dtag; \
})

#define NATIVE_LOAD_VAL_AND_TAGD(addr, val, tag)        \
do {                                                    \
	BUILD_BUG_ON(sizeof(tag) > 4);			\
	asm ("ldrd [%2 + %3], %1\n"			\
	     "gettagd %1, %0\n"				\
	     "puttagd %1, 0, %1\n"			\
	     : "=r" (tag), "=r" (val)			\
	     : "m" (*((unsigned long long *) (addr))),	\
	       "i" (TAGGED_MEM_LOAD_REC_OPC));		\
} while (0)

#define NATIVE_LOAD_VAL_AND_TAGW(addr, val, tag)        \
({                                                      \
	register int __tag;                             \
	register long __word;                           \
	asm ("{ldrd [%2 + %3], %1\n}"			\
	     "{gettagd \t%1, %0\n"			\
	     " puttagd \t%1, 0, %1}\n"			\
	     : "=r"(__tag), "=r"(__word)		\
	     : "m" (*((unsigned long long *) (addr))),	\
	       "i"(TAGGED_MEM_LOAD_REC_OPC_W));		\
	val = __word;					\
	tag = __tag;					\
})

#define	NATIVE_LOAD_TAGGED_QWORD_AND_TAGS(addr, lo, hi, tag_lo, tag_hi)	\
{									\
	NATIVE_LOAD_VAL_AND_TAGD(addr, lo, tag_lo);			\
	NATIVE_LOAD_VAL_AND_TAGD(((__e2k_u64_t *) (addr)) + 1,		\
						hi, tag_hi);		\
}

#define E2K_LOAD_VAL_AND_TAG(addr, val, tag)		\
({							\
	register int __tag;				\
	register long __dword;				\
	asm ("{ldrd [%2 + %3], %1\n}"			\
	     "{gettags \t%1, %0\n"			\
	     " puttags \t%1, 0, %1}\n"			\
	     : "=r"(__tag), "=r"(__dword)		\
	     : "m" (*((unsigned long long *) (addr))),	\
	       "i"(TAGGED_MEM_LOAD_REC_OPC));		\
	val = __dword;					\
	tag = __tag;					\
})

/**
 * Load/stote based data operations
 */
#define E2K_LD_GREG_BASED_B(greg_no, offset, chan_letter) \
({ \
	register unsigned long res; \
	asm volatile ("ldb," #chan_letter "\t%%dg" #greg_no ", [%1], %0" \
			: "=r"(res) \
			: "ri" ((__e2k_u64_t) (offset))); \
	res; \
})
#define E2K_LD_GREG_BASED_H(greg_no, offset, chan_letter) \
({ \
	register unsigned long res; \
	asm volatile ("ldh," #chan_letter "\t%%dg" #greg_no ", [%1], %0" \
			: "=r"(res) \
			: "ri" ((__e2k_u64_t) (offset))); \
	res; \
})
#define E2K_LD_GREG_BASED_W(greg_no, offset, chan_letter) \
({ \
	register unsigned long res; \
	asm volatile ("ldw," #chan_letter "\t%%dg" #greg_no ", [%1], %0" \
			: "=r"(res) \
			: "ri" ((__e2k_u64_t) (offset))); \
	res; \
})
#define E2K_LD_GREG_BASED_D(greg_no, offset, chan_letter) \
({ \
	register unsigned long long res; \
	asm volatile ("ldd," #chan_letter "\t%%dg" #greg_no ", [%1], %0" \
			: "=r"(res) \
			: "ri" ((__e2k_u64_t) (offset))); \
	res; \
})
#define E2K_ST_GREG_BASED_B(greg_no, offset, value, chan_letter) \
({ \
	asm volatile ("stb," #chan_letter "\t%%dg" #greg_no ", [%0], %1" \
			: \
			: "ri" ((__e2k_u64_t) (offset)), \
			  "r" ((__e2k_u8_t) (value))); \
})
#define E2K_ST_GREG_BASED_H(greg_no, offset, value, chan_letter) \
({ \
	asm volatile ("sth," #chan_letter "\t%%dg" #greg_no ", [%0], %1" \
			: \
			: "ri" ((__e2k_u64_t) (offset)), \
			  "r" ((__e2k_u16_t) (value))); \
})
#define E2K_ST_GREG_BASED_W(greg_no, offset, value, chan_letter) \
({ \
	asm volatile ("stw," #chan_letter "\t%%dg" #greg_no ", [%0], %1" \
			: \
			: "ri" ((__e2k_u64_t) (offset)), \
			  "r" ((__e2k_u32_t) (value))); \
})
#define E2K_ST_GREG_BASED_D(greg_no, offset, value, chan_letter) \
({ \
	asm volatile ("std," #chan_letter "\t%%dg" #greg_no ", [%0], %1" \
			: \
			: "ri" ((__e2k_u64_t) (offset)), \
			  "r" ((__e2k_u64_t) (value))); \
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
 * Bytes swapping
 */

#define	E2K_SWAPB_16(addr)	E2K_READ_MAS_H(addr, MAS_BIGENDIAN)
#define	E2K_SWAPB_32(addr)	E2K_READ_MAS_W(addr, MAS_BIGENDIAN)
#define	E2K_SWAPB_64(addr)	E2K_READ_MAS_D(addr, MAS_BIGENDIAN)

#define _E2K_GEN_LABEL(label_name, label_no)  #label_name #label_no

#define _E2K_ASM_LABEL_L(label_name, label_no) \
    asm volatile ("\n" _E2K_GEN_LABEL(label_name, label_no) ":");

#define _E2K_ASM_LABEL_R(label_name, label_no) \
    _E2K_GEN_LABEL(label_name, label_no)


/*
 * Atomic read hardware stacks (procedure and chain) registers
 * in coordinated state.
 * Any interrupt inside registers reading sequence can update
 * some fields of registers and them can be at miscoordinated state
 * So use "wait lock" and "wait unlock" load/store to avoid interrupts
 * Argument 'lock_addr' is used only to provide lock/unlock, so it can be
 * any unused local variable of caller
 */
#define ATOMIC_READ_P_STACK_REGS(psp_lo, psp_hi, pshtp)			\
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
		: "=&r" (psp_lo),					\
		  "=&r" (psp_hi),					\
		  "=&r" (pshtp)						\
		: "r" ((__e2k_ptr_t) (&lock_addr))			\
		: "memory");						\
})
#define ATOMIC_READ_PC_STACK_REGS(pcsp_lo, pcsp_hi, pcshtp)		\
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
		: "=&r" (pcsp_lo),					\
		  "=&r" (pcsp_hi),					\
		  "=&r" (pcshtp)					\
		: "r" ((__e2k_ptr_t) (&lock_addr))			\
		: "memory");						\
})
#define ATOMIC_READ_HW_PS_SIZES(psp_hi, pshtp)				\
({									\
	unsigned long lock_addr;					\
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
		: "r" ((__e2k_ptr_t) (&lock_addr))			\
		: "memory");						\
})
#define ATOMIC_READ_HW_PCS_SIZES(pcsp_hi, pcshtp)			\
({									\
	unsigned long lock_addr;					\
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
		: "r" ((__e2k_ptr_t) (&lock_addr))			\
		: "memory");						\
})
#define ATOMIC_READ_HW_STACKS_SIZES(psp_hi, pshtp, pcsp_hi, pcshtp)	\
({									\
	unsigned long lock_addr;					\
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
		: "r" ((__e2k_ptr_t) (&lock_addr))			\
		: "memory");						\
})
#define ATOMIC_READ_HW_STACKS_REGS(psp_lo, psp_hi, pshtp,		\
					pcsp_lo, pcsp_hi, pcshtp)	\
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
		: "=&r" (psp_lo),					\
		  "=&r" (psp_hi),					\
		  "=&r" (pshtp),					\
		  "=&r" (pcsp_lo),					\
		  "=&r" (pcsp_hi),					\
		  "=&r" (pcshtp)					\
		: "r" ((__e2k_ptr_t) (&lock_addr))			\
		: "memory");						\
})
/*
 * Atomic read all stacks hardware (procedure and chain) and data stack
 * registers in coordinated state.
 */
#define ATOMIC_READ_ALL_STACKS_REGS(psp_lo, psp_hi, pshtp,		\
					pcsp_lo, pcsp_hi, pcshtp,	\
					usd_lo, usd_hi, cr1_hi)		\
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
		"\t rrd    \t %%cr1.hi,  %8\n"				\
									\
		"{\n"							\
			"\t std,2   \t 0, [%9] 2, %0\n"			\
			"\t ibranch \t 1b ? %%MLOCK\n"			\
		"}\n"							\
		: "=&r" (psp_lo),					\
		  "=&r" (psp_hi),					\
		  "=&r" (pshtp),					\
		  "=&r" (pcsp_lo),					\
		  "=&r" (pcsp_hi),					\
		  "=&r" (pcshtp),					\
		  "=&r" (usd_lo),					\
		  "=&r" (usd_hi),					\
		  "=&r" (cr1_hi)					\
		: "r" ((__e2k_ptr_t) (&lock_addr))			\
		: "memory");						\
})

#define NATIVE_ASM_FLUSH_DCACHE_LINE(addr) \
do { \
	asm volatile("{wait st_c=1}\n" \
		     "{std,2 [ %0 + 0 ] %2, %1}\n" \
		     "{wait fl_c=1}\n" \
		     : \
		     : "r" (addr), "r" (0), "i" (MAS_DCACHE_LINE_FLUSH));\
} while (0)

#define NATIVE_CLEAN_LD_ACQ_ADDRESS(_reg1, _reg2, _hwbug_address) \
({ \
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


#if !defined(CONFIG_BOOT_E2K) && !defined(E2K_P2V) && defined(CONFIG_CPU_ES2)

# define HWBUG_ATOMIC_BEGIN(addr) \
	unsigned long __hwbug_atomic_flags = 0; \
	bool __hwbug_atomic_possible = cpu_has(CPU_HWBUG_ATOMIC); \
	if (__hwbug_atomic_possible) { \
		__hwbug_atomic_flags = NATIVE_NV_READ_UPSR_REG_VALUE(); \
		NATIVE_SET_UPSR_IRQ_BARRIER( \
			__hwbug_atomic_flags & ~(UPSR_IE | UPSR_NMIE)); \
		NATIVE_FLUSH_DCACHE_LINE_UNPRIV((unsigned long) (addr)); \
	}
# define HWBUG_ATOMIC_END() \
	if (__hwbug_atomic_possible) \
		NATIVE_SET_UPSR_IRQ_BARRIER(__hwbug_atomic_flags)
#else
# define HWBUG_ATOMIC_BEGIN(addr)
# define HWBUG_ATOMIC_END()
#endif

/*
 * On E2C+ atomic operations have relaxed memory ordering:
 * _st_unlock can be reordered with subsequent loads and stores.
 * Issue an explicit memory barrier if atomic operation returns a value.
 *
 * On E4C with multiple nodes and E2C+ atomic operations have fully
 * relaxed memory ordering because of a hardware bug, must add "wait ma_c".
 */
#if !defined CONFIG_E2K_MACHINE
# define MB_BEFORE_ATOMIC	"{wait st_c=1, ma_c=1}\n"
# define MB_AFTER_ATOMIC	"{wait st_c=1, ma_c=1}\n"
# define MB_AFTER_ATOMIC_LOCK_MB /* E2K_WAIT_ST_C_SAS() */ \
				".word 0x00008001\n" \
				".word 0x30000084\n"
#elif defined CONFIG_E2K_ES2_DSP || defined CONFIG_E2K_ES2_RU
# define MB_BEFORE_ATOMIC	"{wait st_c=1, ma_c=1}\n"
# define MB_AFTER_ATOMIC	"{wait st_c=1, ma_c=1}\n"
# define MB_AFTER_ATOMIC_LOCK_MB /* E2K_WAIT_ST_C_SAS() */ \
				".word 0x00008001\n" \
				".word 0x30000084\n"
#elif defined CONFIG_E2K_E2S && defined CONFIG_NUMA
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

#ifdef CONFIG_DEBUG_LCC_VOLATILE_ATOMIC
# define NOT_VOLATILE volatile
#else
# define NOT_VOLATILE
#endif

#if CONFIG_CPU_ISET >= 5
# define ACQUIRE_MB_ATOMIC_CHANNEL	"5"
# define RELAXED_MB_ATOMIC_CHANNEL	"5"
#else	/* CONFIG_CPU_ISET < 5 */
# define ACQUIRE_MB_ATOMIC_CHANNEL	"2"
# define RELAXED_MB_ATOMIC_CHANNEL	"2"
#endif	/* CONFIG_CPU_ISET >= 5 */
#define RELEASE_MB_ATOMIC_CHANNEL	"2"
#define STRONG_MB_ATOMIC_CHANNEL	"2"
#define LOCK_MB_ATOMIC_CHANNEL		ACQUIRE_MB_ATOMIC_CHANNEL

#if CONFIG_CPU_ISET >= 6
# define LOCK_MB_ATOMIC_MAS	"0x2"
# define ACQUIRE_MB_ATOMIC_MAS	"0x2"
# define RELEASE_MB_ATOMIC_MAS	"0x73"
# define STRONG_MB_ATOMIC_MAS	"0x73"
# define RELAXED_MB_ATOMIC_MAS	"0x2"
#else
# define LOCK_MB_ATOMIC_MAS	"0x2"
# define ACQUIRE_MB_ATOMIC_MAS	"0x2"
# define RELEASE_MB_ATOMIC_MAS	"0x2"
# define STRONG_MB_ATOMIC_MAS	"0x2"
# define RELAXED_MB_ATOMIC_MAS	"0x2"
#endif

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
	HWBUG_ATOMIC_BEGIN(__addr); \
	asm NOT_VOLATILE ( \
		MB_BEFORE_ATOMIC_##mem_model \
		"\n1:" \
		"\n{"\
		"\nnop 4"\
		"\nld" #size_letter ",0 %[addr], %[rval], mas=0x7" \
		"\n}" \
		"\n{"\
		"\n" op " %[rval], %[val], %[rval]" \
		"\n}" \
		"\n{"\
		"\nst" #size_letter "," mem_model##_ATOMIC_CHANNEL \
			" %[addr], %[rval], mas=" mem_model##_ATOMIC_MAS \
		"\nibranch 1b ? %%MLOCK" \
		"\n}" \
		MB_AFTER_ATOMIC_##mem_model \
		: [rval] "=&r" (__rval), [addr] "+m" (*(__addr)) \
		: [val] "ir" (__val) \
		CLOBBERS_##mem_model); \
	HWBUG_ATOMIC_END(); \
} while (0)

#define NATIVE_ATOMIC_FETCH_OP(__val, __addr, __rval, __tmp, \
			size_letter, op, mem_model) \
do { \
	HWBUG_ATOMIC_BEGIN(__addr); \
	asm NOT_VOLATILE ( \
		MB_BEFORE_ATOMIC_##mem_model \
		"\n1:" \
		"\n{"\
		"\nnop 4"\
		"\nld" #size_letter ",0 %[addr], %[rval], mas=0x7" \
		"\n}" \
		"\n{"\
		"\n" op " %[rval], %[val], %[tmp]" \
		"\n}" \
		"\n{"\
		"\nst" #size_letter "," mem_model##_ATOMIC_CHANNEL \
			" %[addr], %[tmp], mas=" mem_model##_ATOMIC_MAS \
		"\nibranch 1b ? %%MLOCK" \
		"\n}" \
		MB_AFTER_ATOMIC_##mem_model \
		: [tmp] "=&r" (__tmp), [addr] "+m" (*(__addr)), \
		  [rval] "=&r" (__rval) \
		: [val] "ir" (__val) \
		CLOBBERS_##mem_model); \
	HWBUG_ATOMIC_END(); \
} while (0)

#define NATIVE_ATOMIC32_ADD_IF_NOT_NEGATIVE(__val, __addr, __rval, mem_model) \
do { \
	HWBUG_ATOMIC_BEGIN(__addr); \
	asm NOT_VOLATILE ( \
		MB_BEFORE_ATOMIC_##mem_model \
		"\n1:" \
		"\n{"\
		"\nnop 4"\
		"\nldw,0 %[addr], %[rval], mas=0x7" \
		"\n}" \
		"\n{" \
		"\nnop 1"\
		"\ncmplsb %[rval], 0, %%pred2" \
		"\n}" \
		"\n{"\
		"\nnop 2" /* bug 92891 - optimize for performance */ \
		"\nadds %[rval], %[val], %[rval] ? ~ %%pred2" \
		"\n}" \
		"\n{"\
		"\nstw," mem_model##_ATOMIC_CHANNEL " %[addr], %[rval], mas=" mem_model##_ATOMIC_MAS \
		"\nibranch 1b ? %%MLOCK" \
		"\n}" \
		MB_AFTER_ATOMIC_##mem_model \
		: [rval] "=&r" (__rval), [addr] "+m" (*(__addr)) \
		: [val] "ir" (__val) \
		CLOBBERS_PRED2_##mem_model);	\
	HWBUG_ATOMIC_END(); \
} while (0)

#define NATIVE_ATOMIC64_ADD_IF_NOT_NEGATIVE(__val, __addr, __rval, mem_model) \
do { \
	HWBUG_ATOMIC_BEGIN(__addr); \
	asm NOT_VOLATILE ( \
		MB_BEFORE_ATOMIC_##mem_model \
		"\n1:" \
		"\n{" \
		"\nnop 4" \
		"\nldd,0 %[addr], %[rval], mas=0x7" \
		"\n}" \
		"\n{" \
		"\nnop 1" \
		"\ncmpldb %[rval], 0, %%pred2" \
		"\n}" \
		"\n{"\
		"\nnop 2" /* bug 92891 - optimize for performance */ \
		"\naddd %[rval], %[val], %[rval] ? ~ %%pred2" \
		"\n}" \
		"\n{"\
		"\nstd," mem_model##_ATOMIC_CHANNEL \
		      	" %[addr], %[rval], mas=" mem_model##_ATOMIC_MAS \
		"\nibranch 1b ? %%MLOCK" \
		"\n}" \
		MB_AFTER_ATOMIC_##mem_model \
		: [rval] "=&r" (__rval), [addr] "+m" (*(__addr)) \
		: [val] "ir" (__val) \
		CLOBBERS_PRED2_##mem_model); \
	HWBUG_ATOMIC_END(); \
} while (0)

/* Atomically add to 16 low bits and return the new 32 bits value */
#define NATIVE_ATOMIC16_ADD_RETURN32_LOCK(val, addr, rval, tmp) \
({ \
	HWBUG_ATOMIC_BEGIN(addr); \
	asm NOT_VOLATILE ( \
		"\n1:" \
		"\n{"\
		"\nnop 4"\
		"\nldw,0\t0x0, [%3] 0x7, %0" \
		"\n}" \
		"\n{"\
		"\nadds %0, %2, %1" \
		"\nands %0, 0xffff0000, %0" \
		"\n}" \
		"\nands %1, 0x0000ffff, %1" \
		"\nadds %0, %1, %0" \
		"\n{"\
		"\nstw," ACQUIRE_MB_ATOMIC_CHANNEL " 0x0, [%3] 0x2, %0" \
		"\nibranch 1b ? %%MLOCK" \
		"\n}" \
		MB_AFTER_ATOMIC_LOCK_MB \
		: "=&r" (rval), "=&r" (tmp) \
		: "i" (val), "r" ((__e2k_ptr_t) (addr)) \
		: "memory");	\
	HWBUG_ATOMIC_END(); \
})

/* Atomically add two 32 bits values packed into one 64 bits value */
/* and return the new 64 bits value */
#define NATIVE_ATOMIC32_PAIR_ADD_RETURN64_LOCK(val_lo, val_hi, addr, rval, \
						tmp1, tmp2, tmp3) \
({ \
	HWBUG_ATOMIC_BEGIN(addr); \
	asm NOT_VOLATILE ( \
		"\n1:" \
		"\n\t{"\
		"\n\tnop 4"\
		"\n\tldd,0\t0x0, [%6] 0x7, %0" \
		"\n\t}"\
		"\n\t{"\
		"\n\tsard %0, 32, %1" \
		"\n\tadds %4, 0, %2" \
		"\n\tadds %5, 0, %3" \
		"\n\t}" \
		"\n\t{"\
		"\n\tadds %1, %3, %1" \
		"\n\tadds %0, %2, %0" \
		"\n\t}" \
		"\n\t{"\
		"\n\tsxt 6, %1, %1" \
		"\n\tsxt 6, %0, %0" \
		"\n\t}" \
		"\n\tshld %1, 32, %1" \
		"\n\tord %1, %0, %0" \
		"\n\t{"\
		"\n\tstd," ACQUIRE_MB_ATOMIC_CHANNEL "0x0, [%6] 0x2, %0" \
		"\n\tibranch 1b ? %%MLOCK" \
		"\n\t}" \
		MB_AFTER_ATOMIC_LOCK_MB \
		: "=&r" (rval), \
		  "=&r" (tmp1), \
		  "=&r" (tmp2), \
		  "=&r" (tmp3) \
		: "ri" (val_lo), \
		  "ri" (val_hi), \
		  "r" ((__e2k_ptr_t) (addr)) \
		: "memory");	\
	HWBUG_ATOMIC_END(); \
})

/* Atomically sub two 32 bits values packed into one 64 bits value */
/* and return the new 64 bits value */
#define NATIVE_ATOMIC32_PAIR_SUB_RETURN64_LOCK(val_lo, val_hi, addr, rval, \
						tmp1, tmp2, tmp3) \
({ \
	HWBUG_ATOMIC_BEGIN(addr); \
	asm NOT_VOLATILE ( \
		"\n1:" \
		"\n\t{"\
		"\n\tnop 4"\
		"\n\tldd,0\t0x0, [%6] 0x7, %0" \
		"\n\t}"\
		"\n\t{"\
		"\n\tsard %0, 32, %1" \
		"\n\tadds %4, 0, %2" \
		"\n\tadds %5, 0, %3" \
		"\n\t}" \
		"\n\t{"\
		"\n\tsubs %1, %3, %1" \
		"\n\tsubs %0, %2, %0" \
		"\n\t}" \
		"\n\t{"\
		"\n\tsxt 6, %1, %1" \
		"\n\tsxt 6, %0, %0" \
		"\n\t}" \
		"\n\tshld %1, 32, %1" \
		"\n\tord %1, %0, %0" \
		"\n\t{"\
		"\n\tstd," ACQUIRE_MB_ATOMIC_CHANNEL "0x0, [%6] 0x2, %0" \
		"\n\tibranch 1b ? %%MLOCK" \
		"\n\t}" \
		MB_AFTER_ATOMIC_LOCK_MB \
		: "=&r" (rval), \
		  "=&r" (tmp1), \
		  "=&r" (tmp2), \
		  "=&r" (tmp3) \
		: "ri" (val_lo), \
		  "ri" (val_hi), \
		  "r" ((__e2k_ptr_t) (addr)) \
		: "memory");	\
	HWBUG_ATOMIC_END(); \
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
	HWBUG_ATOMIC_BEGIN(spinlock); \
	asm NOT_VOLATILE ( \
		"\n1:" \
		"\n{"\
		"\nnop 4"\
		"\nldw,0 %[addr], %[val], mas=0x7" \
		"\n}" \
		"\n{" \
		"\nshrs,0 %[val], 0x10, %[tail]" \
		"\ngetfs,1 %[val], 0x400, %[head]" \
		"\n}" \
		"\n{" \
		"\nnop" \
		"\ncmpesb,0 %[tail], %[head], %%pred2" \
		"\nadds 0, 0, %[rval]" \
		"\n}" \
		"\n{" \
		"\nnop 3" /* bug 92891 - optimize for performance */ \
		"\nadds,0 0, 1, %[rval] ? %%pred2" \
		"\nadds,2 %[val], %[incr], %[val] ? %%pred2" \
		"\n}" \
		"\n{" \
		"\nstw," ACQUIRE_MB_ATOMIC_CHANNEL " %[addr], %[val], mas=" LOCK_MB_ATOMIC_MAS \
		"\nibranch 1b ? %%MLOCK" \
		"\n}" \
		MB_AFTER_ATOMIC_LOCK_MB \
		: [rval] "=&r" (__rval), [val] "=&r" (__val), \
		  [head] "=&r" (__head), [tail] "=&r" (__tail), \
		  [addr] "+m" (*(spinlock)) \
		: [incr] "i" (1 << tail_shift) \
		: "memory", "pred2"); \
	HWBUG_ATOMIC_END(); \
} while (0)

/*
 * Atomic support of new read/write spinlock mechanism.
 * Locking is ordered and later readers cannot outrun former writers.
 * Locking order based on coupons (tickets) received while first try to get
 * lock, if lock is already taken by other.
 *
 * read/write spinlocks initial state allowing 2^32 active readers and
 * only one active writer. But coupon discipline allows simultaniously
 * have only 2^16 registered users of the lock: active + waiters
 */

/*
 * It is test: is read/write lock can be now taken by reader
 * Macros return source state of read/write lock and set bypassed boolean value
 * 'success - locking can be successful'
 *
 * C equivalent:
 *
static rwlock_val_t
atomic_can_lock_reader(arch_rwlock_t *rw, bool success // bypassed)
{
	arch_rwlock_t src_lock;
	u16 ticket;
	u16 head;
	s32 count;

	src_lock.lock = rw->lock;
	ticket = src_lock.ticket;
	head = src_lock.head;
	count = src_lock.count;
	// can lock: none waiters and active writers
	success = (ticket == head) && (count-1 < 0);
	return src_lock.lock;
}
 */
#define NATIVE_ATOMIC_CAN_LOCK_READER(__rw_addr, __success, \
				__head, __ticket, __count, __src) \
({ \
	asm ( \
			"\n\tldd,0	%[addr], %[src]" \
		"\n\t{" \
			"\n\tsard	%[src], 32, %[count]" \
			"\n\tgetfd	%[src], 0x400, %[head]" \
			"\n\tgetfd	%[src], 0x410, %[ticket]" \
		"\n\t}" \
		"\n\t{" \
			"\n\tsubs	%[count], 1, %[count]" \
		"\n\t}" \
		"\n\t{" \
			"\n\tcmplsb	%[count], 0, %%pred3" \
			"\n\tcmpesb	%[head], %[ticket], %%pred2" \
		"\n\t}" \
		"\n\t{" \
			"\n\tpass	%%pred2, @p0" \
			"\n\tpass	%%pred3, @p1" \
			"\n\tlandp	@p0, @p1, @p4"\
			"\n\tpass	@p4, %%pred2" \
		"\n\t}" \
		"\n\t{" \
			"\n\tadds	1, 0, %[success] ? %%pred2" \
			"\n\tadds	0, 0, %[success] ? ~%%pred2" \
		"\n\t}" \
		: [success]	"=&r" (__success), \
		  [src]		"=&r" (__src), \
		  [head]	"=&r" (__head), \
		  [ticket]	"=&r" (__ticket), \
		  [count]	"=&r" (__count) \
		: [addr]	"m" (*(__rw_addr)) \
		: "memory", "pred2", "pred3"); \
})

/*
 * It is test: is read/write lock can be now taken by writer
 * Macros return source state of read/write lock and set bypassed boolean value
 * 'success - locking can be successful'
 *
 * C equivalent:
 *
static rwlock_val_t
atomic_can_lock_writer(arch_rwlock_t *rw, bool success // bypassed)
{
	arch_rwlock_t src_lock;
	u16 ticket;
	u16 head;
	s32 count;

	src_lock.lock = rw->lock;
	ticket = src_lock.ticket;
	head = src_lock.head;
	count = src_lock.count;
	// can lock: none waiters and active readers and writers
	success = (ticket == head) && (count == 0);
	return src_lock.lock;
}
 */
#define NATIVE_ATOMIC_CAN_LOCK_WRITER(__rw_addr, __success, \
				__head, __ticket, __count, __src) \
({ \
	asm ( \
		"\n\t{" \
			"\n\tnop 4" \
			"\n\tldd,0	%[addr], %[src]" \
		"\n\t}" \
		"\n\t{" \
			"\n\tsard	%[src], 32, %[count]" \
			"\n\tgetfd	%[src], 0x400, %[head]" \
			"\n\tgetfd	%[src], 0x410, %[ticket]" \
		"\n\t}" \
		"\n\t{" \
			"\n\tcmpesb	%[count], 0, %%pred3" \
			"\n\tcmpesb	%[head], %[ticket], %%pred2" \
		"\n\t}" \
		"\n\t{" \
			"\n\tpass	%%pred2, @p0" \
			"\n\tpass	%%pred3, @p1" \
			"\n\tlandp	@p0, @p1, @p4"\
			"\n\tpass	@p4, %%pred2" \
		"\n\t}" \
		"\n\t{" \
			"\n\tadds	1, 0, %[success] ? %%pred2" \
			"\n\tadds	0, 0, %[success] ? ~%%pred2" \
		"\n\t}" \
		: [success]	"=&r" (__success), \
		  [src]		"=&r" (__src), \
		  [head]	"=&r" (__head), \
		  [ticket]	"=&r" (__ticket), \
		  [count]	"=&r" (__count) \
		: [addr]	"m" (*(__rw_addr)) \
		: "memory", "pred2", "pred3"); \
})

/*
 * The first try to take read spinlock.
 * Successful locking increment # of ticket and head, decrement active
 * readers counter (negative counter)
 * Macros return source state of read/write lock and set bypassed boolean value
 * 'success - lockin is successful', otherwise reader receives coupon and
 * should be queued as waiter similar mutex implementation
 *
 * C equivalent:
 *
static rwlock_val_t
atomic_add_new_reader(arch_rwlock_t *rw, bool success // bypassed)
{
	arch_rwlock_t src_lock;
	arch_rwlock_t dst_lock;
	u16 ticket;
	u16 head;
	s32 count;

	src_lock.lock = E2K_ATOMIC_LBRACKET_D(rw, MAS_WAIT_LOCK, 0);
	ticket = src_lock.ticket;
	head = src_lock.head;
	count = src_lock.count;
	// can lock: none waiters and active writers
	success = (ticket == head) && (count-1 < 0);
	dst_lock.ticket = ticket + 1;
	if (success) {
		// take lock: increment readers (negative value),
		// increment head to enable follow readers
		count = count - 1;
		head = head + 1;
	}
	dst_lock.count = count;
	dst_lock.head = head;
	E2K_ATOMIC_RBRACKET_D(rw, dst_lock.lock, MAS_WAIT_UNLOCK, 0);
	return src_lock.lock;
}
 */
#define NATIVE_ATOMIC_ADD_NEW_READER(__rw_addr, __success, \
			__head, __ticket, __count, __src, __dst, __tmp) \
({ \
	HWBUG_ATOMIC_BEGIN(__rw_addr); \
	asm NOT_VOLATILE ( \
		"\n1:" \
		"\n\t{" \
			"\n\tnop 4" \
			"\n\tldd,0	%[addr], %[src], mas=0x7" \
		"\n\t}" \
		"\n\t{" \
			"\n\tsard	%[src], 32, %[count]" \
			"\n\tgetfd	%[src], 0x400, %[head]" \
			"\n\tgetfd	%[src], 0x410, %[ticket]" \
		"\n\t}" \
		"\n\t{" \
			"\n\tsubs	%[count], 1, %[tmp]" \
		"\n\t}" \
		"\n\t{" \
			"\n\tcmplsb	%[tmp], 0, %%pred3" \
			"\n\tcmpesb	%[head], %[ticket], %%pred2" \
			"\n\tadds	%[ticket], 1, %[ticket]" \
		"\n\t}" \
		"\n\t{" \
			"\n\tsxt	5, %[ticket], %[ticket]" \
			"\n\tpass	%%pred2, @p0" \
			"\n\tpass	%%pred3, @p1" \
			"\n\tlandp	@p0, @p1, @p4"\
			"\n\tpass	@p4, %%pred2" \
		"\n\t}" \
		"\n\t{" \
			"\n\tadds	%[head], 1, %[head] ? %%pred2" \
			"\n\tsubs	%[count], 1, %[count] ? %%pred2" \
			"\n\tshld	%[ticket], 16, %[dst]" \
		"\n\t}" \
		"\n\t{" \
			"\n\tsxt	5, %[head], %[head] ? %%pred2" \
			"\n\tsxt	2, %[count], %[count] ? %%pred2" \
		"\n\t}" \
		"\n\t{" \
			"\n\tshld	%[count], 32, %[tmp]" \
			"\n\tord	%[dst], %[head], %[dst]" \
		"\n\t}" \
		"\n\t{" \
			"\n\tord	%[dst], %[tmp], %[dst]" \
			"\n\tadds	1, 0, %[success] ? %%pred2" \
			"\n\tadds	0, 0, %[success] ? ~%%pred2" \
		"\n\t}" \
		"\n\t{" \
			"\n\tstd,2	%[addr], %[dst], mas=" LOCK_MB_ATOMIC_MAS \
			"\n\tibranch	1b ? %%MLOCK" \
		"\n\t}" \
		MB_AFTER_ATOMIC_LOCK_MB \
		: [success]	"=&r" (__success), \
		  [src]		"=&r" (__src), \
		  [dst]		"=&r" (__dst), \
		  [head]	"=&r" (__head), \
		  [ticket]	"=&r" (__ticket), \
		  [count]	"=&r" (__count), \
		  [tmp]		"=&r" (__tmp), \
		  [addr]	"+m" (*(__rw_addr)) \
		:: "memory", "pred2", "pred3"); \
	HWBUG_ATOMIC_END(); \
})

/*
 * Only try to take read spinlock.
 * Successful locking increment # of ticket and head, decrement active
 * readers counter (negative counter)
 * Macros return source state of read/write lock and set bypassed boolean value
 * 'success - lockin is successful', otherwise 'success' is false and
 * nothing are not changed
 *
 * C equivalent:
 *
static rwlock_val_t
atomic_try_add_new_reader(arch_rwlock_t *rw, bool success // bypassed)
{
	arch_rwlock_t src_lock;
	arch_rwlock_t dst_lock;
	u16 ticket;
	u16 head;
	s32 count;

	src_lock.lock = E2K_ATOMIC_LBRACKET_D(rw, MAS_WAIT_LOCK, 0);
	ticket = src_lock.ticket;
	head = src_lock.head;
	count = src_lock.count;
	// can lock: none waiters and active writers
	success = (ticket == head) && (count-1 < 0);
	if (success) {
		// take lock: increment readers (negative value),
		// increment head to enable follow readers
		// increment ticket number for next users
		dst_lock.ticket = ticket + 1;
		dst_lock.count = count - 1;
		dst_lock.head = head + 1;
	} else {
		dst_lock.lock = src_lock.lock;
	}
	E2K_ATOMIC_RBRACKET_D(rw, dst_lock.lock, MAS_WAIT_UNLOCK, 0);
	return src_lock.lock;
}
 */
#define NATIVE_ATOMIC_TRY_ADD_NEW_READER(__rw_addr, __success, \
			__head, __ticket, __count, __src, __dst, __tmp) \
({ \
	HWBUG_ATOMIC_BEGIN(__rw_addr); \
	asm NOT_VOLATILE ( \
		"\n1:" \
		"\n\t{" \
			"\n\tnop 4" \
			"\n\tldd,0	%[addr], %[src], mas=0x7" \
		"\n\t}" \
		"\n\t{" \
			"\n\tsard	%[src], 32, %[count]" \
			"\n\tgetfd	%[src], 0x400, %[head]" \
			"\n\tgetfd	%[src], 0x410, %[ticket]" \
		"\n\t}" \
		"\n\t{" \
			"\n\tsubs	%[count], 1, %[tmp]" \
		"\n\t}" \
		"\n\t{" \
			"\n\tcmplsb	%[tmp], 0, %%pred3" \
			"\n\tcmpesb	%[head], %[ticket], %%pred2" \
			"\n\tadds	%[ticket], 1, %[ticket]" \
		"\n\t}" \
		"\n\t{" \
			"\n\tsxt	5, %[ticket], %[ticket]" \
			"\n\tpass	%%pred2, @p0" \
			"\n\tpass	%%pred3, @p1" \
			"\n\tlandp	@p0, @p1, @p4"\
			"\n\tpass	@p4, %%pred2" \
		"\n\t}" \
		"\n\t{" \
			"\n\tadds	%[head], 1, %[head] ? %%pred2" \
			"\n\tsubs	%[count], 1, %[count] ? %%pred2" \
			"\n\tshld	%[ticket], 16, %[dst] ? %%pred2" \
		"\n\t}" \
		"\n\t{" \
			"\n\tsxt	5, %[head], %[head] ? %%pred2" \
			"\n\tsxt	2, %[count], %[count] ? %%pred2" \
		"\n\t}" \
		"\n\t{" \
			"\n\tshld	%[count], 32, %[tmp] ? %%pred2" \
			"\n\tord	%[dst], %[head], %[dst] ? %%pred2" \
		"\n\t}" \
		"\n\t{" \
			"\n\tord	%[dst], %[tmp], %[dst] ? %%pred2" \
			"\n\tadds	1, 0, %[success] ? %%pred2" \
			"\n\taddd	%[src], 0, %[dst] ? ~%%pred2" \
			"\n\tadds	0, 0, %[success] ? ~%%pred2" \
		"\n\t}" \
		"\n\t{" \
			"\n\tstd,2	%[addr], %[dst], mas=" LOCK_MB_ATOMIC_MAS \
			"\n\tibranch	1b ? %%MLOCK" \
		"\n\t}" \
		MB_AFTER_ATOMIC_LOCK_MB \
		: [success]	"=&r" (__success), \
		  [src]		"=&r" (__src), \
		  [dst]		"=&r" (__dst), \
		  [head]	"=&r" (__head), \
		  [ticket]	"=&r" (__ticket), \
		  [count]	"=&r" (__count), \
		  [tmp]		"=&r" (__tmp), \
		  [addr]	"+m" (*(__rw_addr)) \
		:: "memory", "pred2", "pred3"); \
	HWBUG_ATOMIC_END(); \
})

/*
 * The slow try to take read spinlock according to erlier received # of coupon
 * Successful locking increment # of head, decrement active readers counter
 * (negative counter)
 * Macros return current updated state of read/write lock and set bypassed
 * boolean value 'success - lockin is successful', otherwise reader should be
 * queued again
 *
 * C equivalent:
 *
static rwlock_val_t
atomic_add_slow_reader(arch_rwlock_t *rw, u16 ticket, bool success)
{
	arch_rwlock_t dst_lock;
	u16 head;
	s32 count;

	dst_lock.lock = E2K_ATOMIC_LBRACKET_D(rw, MAS_WAIT_LOCK, 0);
	head = src_lock.head;
	count = src_lock.count;
	// can lock: none waiters and active writers
	success = (ticket == head) && (count-1 < 0);
	if (success) {
		// take lock: increment readers (negative value),
		// increment head to enable follow readers
		count = count - 1;
		head = head + 1;
		dst_lock.count = count;
		dst_lock.head = head;
	}
	E2K_ATOMIC_RBRACKET_D(rw, dst_lock.lock, MAS_WAIT_UNLOCK, 0);
	return dst_lock.lock;
}
 */
#define NATIVE_ATOMIC_ADD_SLOW_READER(__rw_addr, __success, \
			__head, __ticket, __count, __dst, __tmp) \
({ \
	HWBUG_ATOMIC_BEGIN(__rw_addr); \
	asm NOT_VOLATILE ( \
		"\n1:" \
		"\n\t{" \
			"\n\tnop 4" \
			"\n\tldd,0	%[addr], %[dst], mas=0x7" \
		"\n\t}" \
		"\n\t{" \
			"\n\tsard	%[dst], 32, %[count]" \
			"\n\tgetfd	%[dst], 0x400, %[head]" \
		"\n\t}" \
		"\n\t{" \
			"\n\tsubs	%[count], 1, %[tmp]" \
		"\n\t}" \
		"\n\t{" \
			"\n\tcmplsb	%[tmp], 0, %%pred3" \
			"\n\tcmpesb	%[head], %[ticket], %%pred2" \
		"\n\t}" \
		"\n\t{" \
			"\n\tpass	%%pred2, @p0" \
			"\n\tpass	%%pred3, @p1" \
			"\n\tlandp	@p0, @p1, @p4"\
			"\n\tpass	@p4, %%pred2" \
		"\n\t}" \
		"\n\t{" \
			"\n\tadds	%[head], 1, %[head] ? %%pred2" \
			"\n\tsubs	%[count], 1, %[count] ? %%pred2" \
			"\n\tandd	%[dst], 0xffff0000, %[dst] ? %%pred2" \
		"\n\t}" \
		"\n\t{" \
			"\n\tsxt	5, %[head], %[head] ? %%pred2" \
			"\n\tsxt	2, %[count], %[count] ? %%pred2" \
		"\n\t}" \
		"\n\t{" \
			"\n\tshld	%[count], 32, %[tmp] ? %%pred2" \
			"\n\tord	%[dst], %[head], %[dst] ? %%pred2" \
		"\n\t}" \
		"\n\t{" \
			"\n\tord	%[dst], %[tmp], %[dst] ? %%pred2" \
			"\n\tadds	1, 0, %[success] ? %%pred2" \
			"\n\tadds	0, 0, %[success] ? ~%%pred2" \
		"\n\t}" \
		"\n\t{" \
			"\n\tstd,2	%[addr], %[dst], mas=" LOCK_MB_ATOMIC_MAS \
			"\n\tibranch	1b ? %%MLOCK" \
		"\n\t}" \
		MB_AFTER_ATOMIC_LOCK_MB \
		: [success]	"=&r" (__success), \
		  [dst]		"=&r" (__dst), \
		  [head]	"=&r" (__head), \
		  [count]	"=&r" (__count), \
		  [tmp]		"=&r" (__tmp), \
		  [addr]	"+m" (*(__rw_addr)) \
		: [ticket]	"r" (__ticket) \
		: "memory", "pred2", "pred3"); \
	HWBUG_ATOMIC_END(); \
})

/*
 * Unlocking of read spinlock.
 * Need only increment active readers counter (negative counter)
 * Macros return current updated state of read/write lock.
 *
 * C equivalent:
 *
static rwlock_val_t
atomic_free_lock_reader(arch_rwlock_t *rw)
{
	arch_rwlock_t dst_lock;

	dst_lock.lock = E2K_ATOMIC_LBRACKET_D(rw, MAS_WAIT_LOCK, 0);
	dst_lock.count++;
	E2K_ATOMIC_RBRACKET_D(rw, dst_lock.lock, MAS_WAIT_UNLOCK, 0);
	return dst_lock.lock;
}
 */
#define NATIVE_ATOMIC_FREE_LOCK_READER(__rw_addr, __dst) \
({ \
	HWBUG_ATOMIC_BEGIN(__rw_addr); \
	asm NOT_VOLATILE ( \
		"\n1:" \
		"\n\t{" \
			"\n\tnop 4" \
			"\n\tldd,0	%[addr], %[dst], mas=0x7" \
		"\n\t}" \
		"\n\t{" \
			"\n\tnop 2" \
			"\n\taddd	%[dst], 0x100000000, %[dst]" \
		"\n\t}" \
		"\n\t{" \
			"\n\tstd,2	%[addr], %[dst], mas=" LOCK_MB_ATOMIC_MAS \
			"\n\tibranch	1b ? %%MLOCK" \
		"\n\t}" \
		MB_AFTER_ATOMIC_LOCK_MB \
		: [dst]		"=&r" (__dst), \
		  [addr]	"+m" (*(__rw_addr)) \
		:: "memory"); \
	HWBUG_ATOMIC_END(); \
})

/*
 * The first try to take write spinlock.
 * Successful locking increment # of ticket and active writers counter
 * (positive value - can be only one active writer, so set counter to 1)
 * Macros return source state of read/write lock and set bypassed boolean value
 * 'success - lockin is successful', otherwise writer receives coupon and
 * should be queued as waiter similar mutex implementation
 *
 * C equivalent:
 *
static rwlock_val_t
atomic_add_new_writer(arch_rwlock_t *rw, bool success // bypassed)
{
	arch_rwlock_t src_lock;
	arch_rwlock_t dst_lock;
	u16 ticket;
	u16 head;
	s32 count;

	src_lock.lock = E2K_ATOMIC_LBRACKET_D(rw, MAS_WAIT_LOCK, 0);
	ticket = src_lock.ticket;
	head = src_lock.head;
	count = src_lock.count;
	// can lock: none waiters and active readers and writers
	success = (ticket == head) && (count == 0);
	dst_lock.head = head;
	dst_lock.ticket = ticket + 1;
	if (success) {
		// take lock: increment writerss,
		count = count + 1;
	}
	dst_lock.count = count;
	E2K_ATOMIC_RBRACKET_D(rw, dst_lock.lock, MAS_WAIT_UNLOCK, 0);
	return src_lock.lock;
}
 */
#define NATIVE_ATOMIC_ADD_NEW_WRITER(__rw_addr, __success, \
			__head, __ticket, __count, __src, __dst, __tmp) \
({ \
	HWBUG_ATOMIC_BEGIN(__rw_addr); \
	asm NOT_VOLATILE ( \
		"\n1:" \
		"\n\t{" \
			"\n\tnop 4" \
			"\n\tldd,0	%[addr], %[src], mas=0x7" \
		"\n\t}" \
		"\n\t{" \
			"\n\tsard	%[src], 32, %[count]" \
			"\n\tgetfd	%[src], 0x400, %[head]" \
			"\n\tgetfd	%[src], 0x410, %[ticket]" \
		"\n\t}" \
		"\n\t{" \
			"\n\tcmpesb	%[count], 0, %%pred3" \
			"\n\tcmpesb	%[head], %[ticket], %%pred2" \
			"\n\tadds	%[ticket], 1, %[ticket]" \
		"\n\t}" \
		"\n\t{" \
			"\n\tsxt	5, %[ticket], %[ticket]" \
			"\n\tpass	%%pred2, @p0" \
			"\n\tpass	%%pred3, @p1" \
			"\n\tlandp	@p0, @p1, @p4"\
			"\n\tpass	@p4, %%pred2" \
		"\n\t}" \
		"\n\t{" \
			"\n\tadds	%[count], 1, %[count] ? %%pred2" \
			"\n\tshld	%[ticket], 16, %[dst]" \
		"\n\t}" \
		"\n\t{" \
			"\n\tsxt	2, %[count], %[count] ? %%pred2" \
		"\n\t}" \
		"\n\t{" \
			"\n\tshld	%[count], 32, %[tmp]" \
			"\n\tord	%[dst], %[head], %[dst]" \
		"\n\t}" \
		"\n\t{" \
			"\n\tord	%[dst], %[tmp], %[dst]" \
			"\n\tadds	1, 0, %[success] ? %%pred2" \
			"\n\tadds	0, 0, %[success] ? ~%%pred2" \
		"\n\t}" \
		"\n\t{" \
			"\n\tstd,2	%[addr], %[dst], mas=" LOCK_MB_ATOMIC_MAS \
			"\n\tibranch	1b ? %%MLOCK" \
		"\n\t}" \
		MB_AFTER_ATOMIC_LOCK_MB \
		: [success]	"=&r" (__success), \
		  [src]		"=&r" (__src), \
		  [dst]		"=&r" (__dst), \
		  [head]	"=&r" (__head), \
		  [ticket]	"=&r" (__ticket), \
		  [count]	"=&r" (__count), \
		  [tmp]		"=&r" (__tmp), \
		  [addr]	"+m" (*(__rw_addr)) \
		:: "memory", "pred2", "pred3"); \
	HWBUG_ATOMIC_END(); \
})

/*
 * Only try to take write spinlock.
 * Successful locking increment # of ticket and active writers counter
 * (positive value - can be only one active writer, so set counter to 1)
 * Macros return source state of read/write lock and set bypassed boolean value
 * 'success - lockin is successful', otherwise 'success' is set to false and
 * nothing are not changed
 *
 * C equivalent:
 *
static rwlock_val_t
atomic_try_add_new_writer(arch_rwlock_t *rw, bool success // bypassed)
{
	arch_rwlock_t src_lock;
	arch_rwlock_t dst_lock;
	u16 ticket;
	u16 head;
	s32 count;

	src_lock.lock = E2K_ATOMIC_LBRACKET_D(rw, MAS_WAIT_LOCK, 0);
	ticket = src_lock.ticket;
	head = src_lock.head;
	count = src_lock.count;
	// can lock: none waiters and active readers and writers
	success = (ticket == head) && (count == 0);
	if (success) {
		// take lock: increment writers counter,
		// increment ticket number for next readers/writers
		dst_lock.head = head;
		dst_lock.ticket = ticket + 1;
		dst_lock.count = count + 1;
	}
	E2K_ATOMIC_RBRACKET_D(rw, dst_lock.lock, MAS_WAIT_UNLOCK, 0);
	return src_lock.lock;
}
 */
#define NATIVE_ATOMIC_TRY_ADD_NEW_WRITER(__rw_addr, __success, \
			__head, __ticket, __count, __src, __dst, __tmp) \
({ \
	HWBUG_ATOMIC_BEGIN(__rw_addr); \
	asm NOT_VOLATILE ( \
		"\n1:" \
		"\n\t{" \
			"\n\tnop 4" \
			"\n\tldd,0	%[addr], %[src], mas=0x7" \
		"\n\t}" \
		"\n\t{" \
			"\n\tsard	%[src], 32, %[count]" \
			"\n\tgetfd	%[src], 0x400, %[head]" \
			"\n\tgetfd	%[src], 0x410, %[ticket]" \
		"\n\t}" \
		"\n\t{" \
			"\n\tcmpesb	%[count], 0, %%pred3" \
			"\n\tcmpesb	%[head], %[ticket], %%pred2" \
			"\n\tadds	%[ticket], 1, %[ticket]" \
		"\n\t}" \
		"\n\t{" \
			"\n\tsxt	5, %[ticket], %[ticket]" \
			"\n\tpass	%%pred2, @p0" \
			"\n\tpass	%%pred3, @p1" \
			"\n\tlandp	@p0, @p1, @p4"\
			"\n\tpass	@p4, %%pred2" \
		"\n\t}" \
		"\n\t{" \
			"\n\tadds	%[count], 1, %[count] ? %%pred2" \
			"\n\tshld	%[ticket], 16, %[dst] ? %%pred2" \
		"\n\t}" \
		"\n\t{" \
			"\n\tsxt	2, %[count], %[count] ? %%pred2" \
		"\n\t}" \
		"\n\t{" \
			"\n\tshld	%[count], 32, %[tmp] ? %%pred2" \
			"\n\tord	%[dst], %[head], %[dst] ? %%pred2" \
		"\n\t}" \
		"\n\t{" \
			"\n\tord	%[dst], %[tmp], %[dst] ? %%pred2" \
			"\n\tadds	1, 0, %[success] ? %%pred2" \
			"\n\taddd	%[src], 0, %[dst] ? ~%%pred2" \
			"\n\tadds	0, 0, %[success] ? ~%%pred2" \
		"\n\t}" \
		"\n\t{" \
			"\n\tstd,2	%[addr], %[dst], mas=" LOCK_MB_ATOMIC_MAS \
			"\n\tibranch	1b ? %%MLOCK" \
		"\n\t}" \
		MB_AFTER_ATOMIC_LOCK_MB \
		: [success]	"=&r" (__success), \
		  [src]		"=&r" (__src), \
		  [dst]		"=&r" (__dst), \
		  [head]	"=&r" (__head), \
		  [ticket]	"=&r" (__ticket), \
		  [count]	"=&r" (__count), \
		  [tmp]		"=&r" (__tmp), \
		  [addr]	"+m" (*(__rw_addr)) \
		:: "memory", "pred2", "pred3"); \
	HWBUG_ATOMIC_END(); \
})

/*
 * The slow try to take write spinlock according to erlier received # of coupon
 * Successful locking increment active writers counter
 * (positive counter - can be only one active writer, so set counter to 1)
 * Macros return current updated state of read/write lock and set bypassed
 * boolean value 'success - lockin is successful', otherwise writer should be
 * queued again
 *
 * C equivalent:
 *
static rwlock_val_t
atomic_add_slow_writer(arch_rwlock_t *rw, u16 ticket, bool success)
{
	arch_rwlock_t dst_lock;
	u16 head;
	s32 count;

	dst_lock.lock = E2K_ATOMIC_LBRACKET_D(rw, MAS_WAIT_LOCK, 0);
	head = src_lock.head;
	count = src_lock.count;
	// can lock: none waiters and active readers and writers
	success = (ticket == head) && (count == 0);
	if (success) {
		// take lock: increment writers,
		count = count + 1;
		dst_lock.count = count;
	}
	E2K_ATOMIC_RBRACKET_D(rw, dst_lock.lock, MAS_WAIT_UNLOCK, 0);
	return dst_lock.lock;
}
 */
#define NATIVE_ATOMIC_ADD_SLOW_WRITER(__rw_addr, __success, \
			__head, __ticket, __count, __dst, __tmp) \
({ \
	HWBUG_ATOMIC_BEGIN(__rw_addr); \
	asm NOT_VOLATILE ( \
		"\n1:" \
		"\n\t{" \
			"\n\tnop 4" \
			"\n\tldd,0	%[addr], %[dst], mas=0x7" \
		"\n\t}" \
		"\n\t{" \
			"\n\tsard	%[dst], 32, %[count]" \
			"\n\tgetfd	%[dst], 0x400, %[head]" \
		"\n\t}" \
		"\n\t{" \
			"\n\tcmpesb	%[count], 0, %%pred3" \
			"\n\tcmpesb	%[head], %[ticket], %%pred2" \
		"\n\t}" \
		"\n\t{" \
			"\n\tpass	%%pred2, @p0" \
			"\n\tpass	%%pred3, @p1" \
			"\n\tlandp	@p0, @p1, @p4"\
			"\n\tpass	@p4, %%pred2" \
		"\n\t}" \
		"\n\t{" \
			"\n\tadds	%[count], 1, %[count] ? %%pred2" \
			"\n\tandd	%[dst], 0xffffffff, %[dst] ? %%pred2" \
		"\n\t}" \
		"\n\t{" \
			"\n\tsxt	2, %[count], %[count] ? %%pred2" \
		"\n\t}" \
		"\n\t{" \
			"\n\tshld	%[count], 32, %[tmp] ? %%pred2" \
		"\n\t}" \
		"\n\t{" \
			"\n\tord	%[dst], %[tmp], %[dst] ? %%pred2" \
			"\n\tadds	1, 0, %[success] ? %%pred2" \
			"\n\tadds	0, 0, %[success] ? ~%%pred2" \
		"\n\t}" \
		"\n\t{" \
			"\n\tstd,2	%[addr], %[dst], mas=" LOCK_MB_ATOMIC_MAS \
			"\n\tibranch	1b ? %%MLOCK" \
		"\n\t}" \
		MB_AFTER_ATOMIC_LOCK_MB \
		: [success]	"=&r" (__success), \
		  [dst]		"=&r" (__dst), \
		  [head]	"=&r" (__head), \
		  [count]	"=&r" (__count), \
		  [tmp]		"=&r" (__tmp), \
		  [addr]	"+m" (*(__rw_addr)) \
		: [ticket]	"r" (__ticket) \
		: "memory", "pred2", "pred3"); \
	HWBUG_ATOMIC_END(); \
})

/*
 * Unlocking of write spinlock.
 * Need only increment # of queue head and decrement active writers counter
 * (positive counter - can be only one writer, so set counter to 0)
 * Macros return current updated state of read/write lock.
 *
 * C equivalent:
 *
static rwlock_val_t
atomic_free_lock_writer(arch_rwlock_t *rw)
{
	arch_rwlock_t dst_lock;

	dst_lock.lock = E2K_ATOMIC_LBRACKET_D(rw, MAS_WAIT_LOCK, 0);
	dst_lock.count++;
	dst_lock.head++;
	E2K_ATOMIC_RBRACKET_D(rw, dst_lock.lock, MAS_WAIT_UNLOCK, 0);
	return dst_lock.lock;
}
 */
#define NATIVE_ATOMIC_FREE_LOCK_WRITER(__rw_addr, \
			__head, __count, __dst, __tmp); \
({ \
	HWBUG_ATOMIC_BEGIN(__rw_addr); \
	asm NOT_VOLATILE ( \
		"\n1:" \
		"\n\t{" \
			"\n\tnop 4" \
			"\n\tldd,0	%[addr], %[dst], mas=0x7" \
		"\n\t}" \
		"\n\t{" \
			"\n\tsard	%[dst], 32, %[count]" \
			"\n\tgetfd	%[dst], 0x400, %[head]" \
		"\n\t}" \
		"\n\t{" \
			"\n\tadds	%[head], 1, %[head]" \
			"\n\tsubs	%[count], 1, %[count]" \
			"\n\tandd	%[dst], 0xffff0000, %[dst]" \
		"\n\t}" \
		"\n\t{" \
			"\n\tsxt	5, %[head], %[head]" \
			"\n\tsxt	2, %[count], %[count]" \
		"\n\t}" \
		"\n\t{" \
			"\n\tshld	%[count], 32, %[tmp]" \
			"\n\tord	%[dst], %[head], %[dst]" \
		"\n\t}" \
		"\n\t{" \
			"\n\tord	%[dst], %[tmp], %[dst]" \
		"\n\t}" \
		"\n\t{" \
			"\n\tstd,2	%[addr], %[dst], mas=" LOCK_MB_ATOMIC_MAS \
			"\n\tibranch	1b ? %%MLOCK" \
		"\n\t}" \
		MB_AFTER_ATOMIC_LOCK_MB \
		: [dst]		"=&r" (__dst), \
		  [head]	"=&r" (__head), \
		  [count]	"=&r" (__count), \
		  [tmp]		"=&r" (__tmp), \
		  [addr]	"+m" (*(__rw_addr)) \
		:: "memory"); \
	HWBUG_ATOMIC_END(); \
})


/*
 * Atomic operations with return value and acquire/release semantics
 */

#define NATIVE_ATOMIC_FETCH_OP_UNLESS(__val, __addr, __unless, __tmp, __rval, \
		size_letter, op, op_pred, add_op, add_op_pred, cmp_op, mem_model) \
do { \
	HWBUG_ATOMIC_BEGIN(__addr); \
	asm NOT_VOLATILE ( \
		MB_BEFORE_ATOMIC_##mem_model \
		"\n1:" \
		"\n{"\
		"\nnop 4"\
		"\nld"#size_letter ",0 %[addr], %[rval], mas=0x7" \
		"\n}" \
		"\n{"\
		"\nnop" \
		"\n" cmp_op " %[rval], %[unless], %%pred2" \
		"\n}" \
		"\n{"\
		"\nnop 2" /* bug 92891 - optimize for performance */ \
		"\n" op " %[rval], %[val], %[tmp] ? " op_pred "%%pred2" \
		"\n" add_op " %[rval], 0, %[tmp] ? " add_op_pred "%%pred2" \
		"\n}" \
		"\n{"\
		"\nst"#size_letter "," mem_model##_ATOMIC_CHANNEL \
		      " %[addr], %[tmp], mas=" mem_model##_ATOMIC_MAS \
		"\nibranch 1b ? %%MLOCK" \
		"\n}" \
		MB_AFTER_ATOMIC_##mem_model \
		: [rval] "=&r" (__rval), [tmp] "=&r" (__tmp), \
		  [addr] "+m" (*(__addr)) \
		: [val] "ir" (__val), [unless] "ir" (__unless) \
		CLOBBERS_PRED2_##mem_model); \
	HWBUG_ATOMIC_END(); \
} while (0)

#define NATIVE_ATOMIC_FETCH_XCHG_UNLESS(__val, __addr, __tmp, __rval, \
		size_letter, merge_op, cmp_op, mem_model) \
do { \
	HWBUG_ATOMIC_BEGIN(__addr); \
	asm NOT_VOLATILE ( \
		MB_BEFORE_ATOMIC_##mem_model \
		"\n1:" \
		"\n{"\
		"\nnop 4"\
		"\nld"#size_letter ",0 %[addr], %[rval], mas=0x7" \
		"\n}" \
		"\n{"\
		"\nnop" \
		"\n" cmp_op " %[rval], %[val], %%pred2" \
		"\n}" \
		"\n{"\
		"\nnop 2" /* bug 92891 - optimize for performance */ \
		"\n" merge_op " %[rval], %[val], %[tmp], %%pred2" \
		"\n}" \
		"\n{"\
		"\nst"#size_letter "," mem_model##_ATOMIC_CHANNEL \
		      " %[addr], %[tmp], mas=" mem_model##_ATOMIC_MAS \
		"\nibranch 1b ? %%MLOCK" \
		"\n}" \
		MB_AFTER_ATOMIC_##mem_model \
		: [rval] "=&r" (__rval), [tmp] "=&r" (__tmp), \
		  [addr] "+m" (*(__addr)) \
		: [val] "ir" (__val) \
		CLOBBERS_PRED2_##mem_model); \
	HWBUG_ATOMIC_END(); \
} while (0)

#define NATIVE_ATOMIC_XCHG_RETURN(__val, __addr, __rval, \
				  size_letter, mem_model) \
do { \
	HWBUG_ATOMIC_BEGIN(__addr); \
	asm NOT_VOLATILE ( \
		MB_BEFORE_ATOMIC_##mem_model \
		"\n2:" \
		"\n{"\
		"\nnop 5" /* bug 92891 - optimize for performance */ \
		"\nld"#size_letter ",0 %[addr], %[rval], mas=0x7" \
		"\n}" \
		"\n{"\
		"\nst"#size_letter "," mem_model##_ATOMIC_CHANNEL \
				" %[addr], %[val], mas=" mem_model##_ATOMIC_MAS \
		"\nibranch 2b ? %%MLOCK" \
		"\n}" \
		MB_AFTER_ATOMIC_##mem_model \
		: [rval] "=&r" (__rval), [addr] "+m" (*(__addr)) \
		: [val] "r" (__val) \
		CLOBBERS_##mem_model); \
	HWBUG_ATOMIC_END(); \
} while (0)

#define CLOBBERS_PRED2_LOCK_MB		: "memory", "pred2"
#define CLOBBERS_PRED2_ACQUIRE_MB	: "memory", "pred2"
#define CLOBBERS_PRED2_RELEASE_MB	: "memory", "pred2"
#define CLOBBERS_PRED2_STRONG_MB	: "memory", "pred2"
#define CLOBBERS_PRED2_RELAXED_MB	: "pred2"


#define CLOBBERS_PRED2_3_R16_17_LOCK_MB		: "memory", "pred2", "pred3",\
								"r16", "r17"
#define CLOBBERS_PRED2_3_R16_17_ACQUIRE_MB	: "memory", "pred2", "pred3",\
								"r16", "r17"
#define CLOBBERS_PRED2_3_R16_17_RELEASE_MB	: "memory", "pred2", "pred3",\
								"r16", "r17"
#define CLOBBERS_PRED2_3_R16_17_STRONG_MB	: "memory", "pred2", "pred3",\
								"r16", "r17"
#define CLOBBERS_PRED2_3_R16_17_RELAXED_MB	:"pred2", "pred3", "r16", "r17"


#define NATIVE_ATOMIC_CMPXCHG_RETURN(__old, __new, __addr, __stored_val, \
			__rval, size_letter, sxt_size, mem_model) \
do { \
	HWBUG_ATOMIC_BEGIN(__addr); \
	asm NOT_VOLATILE ( \
		MB_BEFORE_ATOMIC_##mem_model \
		"\n3:" \
		"\n{"\
		"\nnop 4"\
		"\nld"#size_letter ",0 %[addr], %[rval], mas=0x7" \
		"\n}" \
		"\n{" \
		"\nsxt\t"#sxt_size", %[rval], %[rval]" \
		"\naddd 0x0, %[new], %[stored_val]" \
		"\n}" \
		"\n{" \
		"\nnop 1" \
		"\ncmpedb %[rval], %[old], %%pred2" \
		"\n}" \
		"\n{" \
		"\nnop 1" /* bug 92891 - optimize for performance */ \
		"\naddd 0x0, %[rval], %[stored_val] ? ~ %%pred2" \
		"\n}" \
		"\n{" \
		"\nst"#size_letter "," mem_model##_ATOMIC_CHANNEL \
		      	" %[addr], %[stored_val], mas=" mem_model##_ATOMIC_MAS \
		"\nibranch 3b ? %%MLOCK" \
		"\n}" \
		MB_AFTER_ATOMIC_##mem_model \
		: [rval] "=&r" (__rval), [stored_val] "=&r" (__stored_val), \
		  [addr] "+m" (*(__addr)) \
		: [new] "ir" (__new), [old] "ir" (__old) \
		CLOBBERS_PRED2_##mem_model); \
	HWBUG_ATOMIC_END(); \
} while (0)

#define NATIVE_ATOMIC_CMPXCHG_WORD_RETURN(__old, __new, __addr, \
					  __stored_val, __rval, mem_model) \
do { \
	HWBUG_ATOMIC_BEGIN(__addr); \
	asm NOT_VOLATILE ( \
		MB_BEFORE_ATOMIC_##mem_model \
		"\n3:" \
		"\n{"\
		"\nnop 4"\
		"\nldw,0 %[addr], %[rval], mas=0x7" \
		"\n}" \
		"\n{" \
		"\nnop 1"\
		"\nadds 0x0, %[new], %[stored_val]" \
		"\ncmpesb %[rval], %[old], %%pred2" \
		"\n}" \
		"\n{" \
		"\nnop 2" /* bug 92891 - optimize for performance */ \
		"\nadds 0x0, %[rval], %[stored_val] ? ~ %%pred2" \
		"\n}" \
		"\n{" \
		"\nstw," mem_model##_ATOMIC_CHANNEL \
				" %[addr], %[stored_val], mas=" mem_model##_ATOMIC_MAS \
		"\nibranch 3b ? %%MLOCK" \
		"\n}" \
		MB_AFTER_ATOMIC_##mem_model \
		: [stored_val] "=&r" (__stored_val), \
		  [rval] "=&r" (__rval), [addr] "+m" (*(__addr)) \
		: [new] "ir" (__new), [old] "ir" (__old) \
		CLOBBERS_PRED2_##mem_model); \
	HWBUG_ATOMIC_END(); \
} while (0)

#define NATIVE_ATOMIC_CMPXCHG_DWORD_RETURN(__old, __new, __addr, \
					   __stored_val, __rval, mem_model) \
do { \
	HWBUG_ATOMIC_BEGIN(__addr); \
	asm NOT_VOLATILE ( \
		MB_BEFORE_ATOMIC_##mem_model \
		"\n3:" \
		"\n{"\
		"\nnop 4"\
		"\nldd,0 %[addr], %[rval], mas=0x7" \
		"\n}" \
		"\n{" \
		"\nnop 1"\
		"\naddd 0x0, %[new], %[stored_val]" \
		"\ncmpedb %[rval], %[old], %%pred2" \
		"\n}" \
		"\n{" \
		"\nnop 2" /* bug 92891 - optimize for performance */ \
		"\naddd 0x0, %[rval], %[stored_val] ? ~ %%pred2" \
		"\n}" \
		"\n{" \
		"\nstd," mem_model##_ATOMIC_CHANNEL \
			" %[addr], %[stored_val], mas=" mem_model##_ATOMIC_MAS \
		"\nibranch 3b ? %%MLOCK" \
		"\n}" \
		MB_AFTER_ATOMIC_##mem_model \
		: [stored_val] "=&r" (__stored_val), \
		  [rval] "=&r" (__rval), [addr] "+m" (*(__addr)) \
		: [new] "ir" (__new), [old] "ir" (__old) \
		CLOBBERS_PRED2_##mem_model); \
	HWBUG_ATOMIC_END(); \
} while (0)

#ifdef CONFIG_HAVE_CMPXCHG_DOUBLE
/*
 * Some problem to use ldq/stq operations
 * C language don't use quadro operands
 * To avoid some changes of compiler we use fixed register for those operations
 *  r16 r17
 *
 * C equivalent:
		if (page->freelist == freelist_old &&
					page->counters == counters_old) {
			page->freelist = freelist_new;
			page->counters = counters_new;
 */
#define NATIVE_ATOMIC_CMPXCHG_DWORD_PAIRS(__addr, __old1, __old2, \
	  __new1, __new2, __rval, mem_model) \
do { \
	asm NOT_VOLATILE( \
		MB_BEFORE_ATOMIC_##mem_model \
		"\n3:" \
		"\n{"\
		"\nnop 5" /* bug 92891 - optimize for performance */ \
		"\nldq,0 %[addr], %%r16, mas=0x5" \
		"\naddd 0x1, 0x0, %[rval]" \
		"\n}" \
		"\n{" \
		"\ncmpedb %[old1], %%r16, %%pred2" \
		"\ncmpedb %[old2], %%r17, %%pred3" \
		"\n}" \
		"\n\t{" \
		"\nnop 1"\
			"\n\tpass	%%pred2, @p0" \
			"\n\tpass	%%pred3, @p1" \
			"\n\tlandp	@p0, @p1, @p4"\
			"\n\tpass	@p4, %%pred2" \
		"\n\t}" \
		"\n{" \
		"\naddd 0x0, %[new1], %%r16 ?  %%pred2" \
		"\naddd 0x0, %[new2], %%r17 ?  %%pred2" \
		"\naddd 0x0, 0x0, %[rval]? ~ %%pred2" \
		"\n}" \
		"\n{" \
		"\nstq," mem_model##_ATOMIC_CHANNEL \
				" %[addr], %%r16, mas=" mem_model##_ATOMIC_MAS \
		"\nibranch 3b ? %%MLOCK" \
		"\n}" \
		MB_AFTER_ATOMIC_##mem_model \
		: [rval] "=&r" (__rval), [addr] "+m" (*(__addr)) \
		: [new1] "ir" (__new1), [old1] "ir" (__old1),	 \
		  [new2] "ir" (__new2), [old2] "ir" (__old2) \
		CLOBBERS_PRED2_3_R16_17_##mem_model); \
} while (0)
#endif /* CONFIG_HAVE_CMPXCHG_DOUBLE */

/* Get number of leading zeroes */
#define E2K_LZCNTS(val) \
({ \
	register __e2k_u32_t __res; \
	asm ("lzcnts %1, %0" : "=r" (__res)  : "r" (val)); \
	__res; \
})

#define E2K_LZCNTD(val) \
({ \
	register __e2k_u64_t __res; \
	asm ("lzcntd %1, %0" : "=r" (__res)  : "r" (val)); \
	__res; \
})

/* Get number of 1's */
#define E2K_POPCNTS(val) \
({ \
	register __e2k_u32_t __res; \
	asm ("popcnts %1, %0" : "=r" (__res)  : "r" (val)); \
	__res; \
})

#define E2K_POPCNTD(val) \
({ \
	register __e2k_u64_t __res; \
	asm ("popcntd %1, %0" : "=r" (__res)  : "r" (val)); \
	__res; \
})

#if !defined CONFIG_E2K_MACHINE || \
    defined CONFIG_E2K_ES2_DSP || defined CONFIG_E2K_ES2_RU || \
    (defined CONFIG_E2K_E2S && defined CONFIG_NUMA)

# define WORKAROUND_WAIT_HWBUG(num) (((num) & (_st_c | _all_c | _sas)) ? \
						((num) | _ma_c) : (num))
# define E2K_WAIT_ST_C_SAS()		E2K_WAIT(_st_c)
# define E2K_WAIT_ST_C_SAS_MT()		E2K_WAIT(_st_c)
# define E2K_WAIT_LD_C_LAL()		E2K_WAIT(_ld_c)
# define E2K_WAIT_LD_C_LAL_MT()		E2K_WAIT(_ld_c)
# define E2K_WAIT_LD_C_LAL_SAL()	E2K_WAIT(_ld_c)
# define E2K_WAIT_ST_C_SAS_LD_C_SAL()	E2K_WAIT(_st_c | _ld_c)
# define E2K_WAIT_ST_C_SAS_LD_C_SAL_MT() E2K_WAIT(_st_c | _ld_c)

#else

# define WORKAROUND_WAIT_HWBUG(num)	num

/* BUG 79245 - use .word to encode relaxed barriers */
# define E2K_WAIT_ST_C_SAS() \
({ \
	int unused; \
	_Pragma("no_asm_inline") \
	asm NOT_VOLATILE (".word 0x00008001\n" \
			  ".word 0x30000084\n" \
			  : "=r" (unused) :: "memory"); \
})
# define E2K_WAIT_LD_C_LAL() \
({ \
	int unused; \
	_Pragma("no_asm_inline") \
	asm NOT_VOLATILE (".word 0x00008001\n" \
			  ".word 0x30000408\n" \
			  : "=r" (unused) :: "memory"); \
})
# define E2K_WAIT_ST_C_SAS_MT() \
({ \
	int unused; \
	_Pragma("no_asm_inline") \
	asm NOT_VOLATILE (".word 0x00008001\n" \
			  ".word 0x30000884\n" \
			  : "=r" (unused) :: "memory"); \
})
# define E2K_WAIT_LD_C_LAL_SAL() \
({ \
	int unused; \
	_Pragma("no_asm_inline") \
	asm NOT_VOLATILE (".word 0x00008001\n" \
			  ".word 0x30000508\n" \
			  : "=r" (unused) :: "memory"); \
})
# define E2K_WAIT_LD_C_LAL_MT() \
({ \
	int unused; \
	_Pragma("no_asm_inline") \
	asm NOT_VOLATILE (".word 0x00008001\n" \
			  ".word 0x30000c08\n" \
			  : "=r" (unused) :: "memory"); \
})
# define E2K_WAIT_ST_C_SAS_LD_C_SAL() \
({ \
	int unused; \
	_Pragma("no_asm_inline") \
	asm NOT_VOLATILE (".word 0x00008001\n" \
			  ".word 0x3000018c\n" \
			  : "=r" (unused) :: "memory"); \
})
# define E2K_WAIT_ST_C_SAS_LD_C_SAL_MT() \
({ \
	int unused; \
	_Pragma("no_asm_inline") \
	asm NOT_VOLATILE (".word 0x00008001\n" \
			  ".word 0x3000098c\n" \
			  : "=r" (unused) :: "memory"); \
})
#endif

#define E2K_WAIT_V6(_num) \
({ \
	int unused, num = WORKAROUND_WAIT_HWBUG(_num); \
	/* "trap=1" requires special handling, see C1_wait_trap() */ \
	asm NOT_VOLATILE("{wait mem_mod=%[mem_mod], int=%[intr], mt=%[mt], " \
			 "      lal=%[lal], las=%[las], sal=%[sal], sas=%[sas], " \
			 "      ma_c=%[ma_c], fl_c=%[fl_c], ld_c = %[ld_c], " \
			 "      st_c=%[st_c], all_e=%[all_e], all_c=%[all_c]}"\
			 : "=r" (unused) \
			 : [all_c] "i" (((num) & 0x1)), \
			   [all_e] "i" (((num) & 0x2)  >> 1), \
			   [st_c] "i" (((num) & 0x4)  >> 2), \
			   [ld_c] "i" (((num) & 0x8)  >> 3), \
			   [fl_c] "i" (((num) & 0x10) >> 4), \
			   [ma_c] "i" (((num) & 0x20) >> 5), \
			   [sas] "i" (((num) & 0x80) >> 7), \
			   [sal] "i" (((num) & 0x100) >> 8), \
			   [las] "i" (((num) & 0x200) >> 9), \
			   [lal] "i" (((num) & 0x400) >> 10), \
			   [mt] "i" (((num) & 0x800) >> 11), \
			   [intr] "i" (((num) & 0x1000) >> 12), \
			   [mem_mod] "i" (((num) & 0x2000) >> 13) \
			 : "memory" ); \
	if ((num & (_all_c | _ma_c | _lal | _las)) || \
	    (num & _ld_c) && !(num & _sal) || \
	    (num & _st_c) && !(num & _sas)) \
		NATIVE_HWBUG_AFTER_LD_ACQ(); \
})


#define E2K_WAIT_V5(_num) \
({ \
	int unused, num = WORKAROUND_WAIT_HWBUG(_num); \
	/* "trap=1" requires special handling, see C1_wait_trap() */ \
	asm NOT_VOLATILE ("{wait sal=%[sal], sas=%[sas], ma_c=%[ma_c], " \
			  "      fl_c=%[fl_c], ld_c=%[ld_c], st_c=%[st_c], " \
			  "      all_e=%[all_e], all_c=%[all_c]}" \
			  : "=r" (unused) \
			  : [all_c] "i" (((num) & 0x1)), \
			    [all_e] "i" (((num) & 0x2) >> 1), \
			    [st_c] "i" (((num) & 0x4) >> 2), \
			    [ld_c] "i" (((num) & 0x8) >> 3), \
			    [fl_c] "i" (((num) & 0x10) >> 4), \
			    [ma_c] "i" (((num) & 0x20) >> 5), \
			    [sas] "i" (((num) & 0x80) >> 7), \
			    [sal] "i" (((num) & 0x100) >> 8) \
			  : "memory" ); \
	if ((num & (_all_c | _ma_c)) || \
	    (num & _ld_c) && !(num & _sal) || \
	    (num & _st_c) && !(num & _sas)) \
		NATIVE_HWBUG_AFTER_LD_ACQ(); \
})

#define __E2K_WAIT(_num) \
({ \
	int unused, num = WORKAROUND_WAIT_HWBUG(_num); \
	if ((_num) & ~(_st_c | _ld_c)) \
		asm volatile ("" ::: "memory"); \
	asm NOT_VOLATILE ("{wait ma_c=%6, fl_c=%5, " \
			  "ld_c = %4, st_c=%3, all_e=%2, all_c=%1}" \
			  : "=r" (unused) \
			  : "i" (((num) & 0x1)), \
			    "i" (((num) & 0x2)  >> 1), \
			    "i" (((num) & 0x4)  >> 2), \
			    "i" (((num) & 0x8)  >> 3), \
			    "i" (((num) & 0x10) >> 4), \
			    "i" (((num) & 0x20) >> 5) \
			  : "memory" ); \
	if ((_num) & ~(_st_c | _ld_c)) \
		asm volatile ("" ::: "memory"); \
})

#define E2K_WAIT(num) \
({ \
	__E2K_WAIT(num); \
	if (num & (_st_c | _ld_c | _all_c | _ma_c)) \
		NATIVE_HWBUG_AFTER_LD_ACQ(); \
})

/* Wait for the load to finish before issuing
 * next memory loads/stores. */
#define E2K_RF_WAIT_LOAD(reg) \
do { \
	int unused; \
	asm NOT_VOLATILE ("{adds %1, 0, %%empty}" \
			  : "=r" (unused) \
			  : "r" (reg) \
			  : "memory"); \
	NATIVE_HWBUG_AFTER_LD_ACQ(); \
} while (0)

/*
 * CPU 'WAIT' operation fields structure
 */
#define	E2K_WAIT_OP_MA_C_MASK	0x20	/* wait for all previous memory */
					/* access operatons complete */
#define	E2K_WAIT_OP_FL_C_MASK	0x10	/* wait for all previous flush */
					/* cache operatons complete */
#define	E2K_WAIT_OP_LD_C_MASK	0x08	/* wait for all previous load */
					/* operatons complete */
#define	E2K_WAIT_OP_ST_C_MASK	0x04	/* wait for all previous store */
					/* operatons complete */
#define	E2K_WAIT_OP_ALL_E_MASK	0x02	/* wait for all previous operatons */
					/* issue all possible exceptions */
#define	E2K_WAIT_OP_ALL_C_MASK	0x01	/* wait for all previous operatons */
					/* complete */
#define	E2K_WAIT_OP_ALL_MASK	(E2K_WAIT_OP_MA_C_MASK |	\
				E2K_WAIT_OP_FL_C_MASK |		\
				E2K_WAIT_OP_LD_C_MASK |		\
				E2K_WAIT_OP_ST_C_MASK |		\
				E2K_WAIT_OP_ALL_C_MASK |	\
				E2K_WAIT_OP_ALL_E_MASK)

#define	E2K_WAIT_MA		E2K_WAIT(E2K_WAIT_OP_MA_C_MASK)
#define	E2K_WAIT_FLUSH		E2K_WAIT(E2K_WAIT_OP_FL_C_MASK)
#define	E2K_WAIT_LD		E2K_WAIT(E2K_WAIT_OP_LD_C_MASK)
#define	E2K_WAIT_ST		E2K_WAIT(E2K_WAIT_OP_ST_C_MASK)
#define	E2K_WAIT_ALL_OP		E2K_WAIT(E2K_WAIT_OP_ALL_C_MASK)
#define	E2K_WAIT_ALL_EX		E2K_WAIT(E2K_WAIT_OP_ALL_E_MASK)
#define	E2K_WAIT_ALL		E2K_WAIT(E2K_WAIT_OP_ALL_MASK)
#define	__E2K_WAIT_ALL		__E2K_WAIT(E2K_WAIT_OP_ALL_MASK)

/*
 * Force strict CPU ordering.
 * And yes, this is required on UP too when we're talking
 * to devices.
 *
 * For now, "wmb()" doesn't actually do anything, as all
 * Intel CPU's follow what Intel calls a *Processor Order*,
 * in which all writes are seen in the program order even
 * outside the CPU.
 *
 */

#define _mem_mod	0x2000 /* watch for modification */
#define _int	0x1000	/* stop the conveyor untill interrupt */
#define _mt	0x800
#define _lal	0x400	/* load-after-load modifier for _ld_c */
#define _las	0x200	/* load-after-store modifier for _st_c */
#define _sal	0x100	/* store-after-load modifier for _ld_c */
#define _sas	0x80	/* store-after-store modifier for _st_c */
#define _trap	0x40	/* stop the conveyor untill interrupt */
#define _ma_c	0x20
#define _fl_c	0x10	/* stop until TLB/cache flush operations complete */
#define _ld_c	0x8	/* stop until all load operations complete */
#define _st_c	0x4	/* stop until store operations complete */
#define _all_e	0x2
#define _all_c	0x1

#define E2K_FLUSHTS \
do { \
	_Pragma("no_asm_inline") \
	asm volatile ("flushts"); \
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
	asm volatile ("{nop} {flushr}" ::: "memory"); \
} while (0)

#define	NATIVE_FLUSHC \
do { \
	asm volatile ("{nop 2} {flushc; nop 3}" ::: "memory"); \
} while (0)

#define NATIVE_FLUSHCPU \
do { \
	asm volatile ("{nop 2} {flushc; nop 3} {flushr}" ::: "memory"); \
} while (0)

#define NATIVE_FLUSH_ALL_TC \
({ \
	register __e2k_u64_t res; \
	asm volatile ("{nop 3; invtc 0x0, %0}" \
		      : "=r" (res)); \
	res; \
})

#define	DO_ATOMIC_WRITE_PSR_REG_VALUE(greg_no, psr_off, psr_value, \
					under_upsr_off, under_upsr_bool) \
({ \
	asm volatile ( \
		"{\n\t" \
		"  stw %%dg" #greg_no ", [%0], %2\n\t" \
		"  stb %%dg" #greg_no ", [%1], %3\n\t" \
		"}" \
		: \
		: "ri" ((__e2k_u64_t)(psr_off)), \
		  "ri" ((__e2k_u64_t)(under_upsr_off)), \
		  "r"  ((__e2k_u32_t)(psr_value)), \
		  "r"  ((__e2k_u8_t)(under_upsr_bool))); \
})
#define	KVM_DO_ATOMIC_WRITE_PSR_REG_VALUE(greg_no, psr_off, psr_value, \
					under_upsr_off, under_upsr_bool) \
		DO_ATOMIC_WRITE_PSR_REG_VALUE(greg_no, psr_off, psr_value, \
					under_upsr_off, under_upsr_bool) \

#define	DO_ATOMIC_WRITE_UPSR_REG_VALUE(greg_no, upsr_off, upsr_value) \
({ \
	asm volatile ( \
		"{\n\t" \
		"  rws %1, %%upsr\n\t" \
		"  stw %%dg" #greg_no ", [%0], %1\n\t" \
		"}" \
		: \
		: "ri" ((__e2k_u64_t)(upsr_off)), \
		  "r"  ((__e2k_u32_t)(upsr_value))); \
})
#define	KVM_DO_ATOMIC_WRITE_UPSR_REG_VALUE(greg_no, upsr_off, upsr_value) \
		DO_ATOMIC_WRITE_UPSR_REG_VALUE(greg_no, upsr_off, upsr_value)

#define NATIVE_GET_TCD() \
({ \
    register __e2k_u64_t res; \
    asm volatile ( \
    		"\n\t{gettc \t0x1 , %%ctpr1; nop 5}" \
		"\n\trrd \t%%ctpr1, %0" \
		: "=r" (res) : : "ctpr1" ); \
    res; \
})

#define NATIVE_SET_TCD(val) \
({ \
    asm volatile ("{puttc %0, 0x0 , %%tcd}" \
	    	   : \
		   :"r" (val)); \
})

#define E2K_BUBBLE(num) \
do { \
	asm volatile ("{nop %0}" \
			: \
			: "i" (num & 0x7) \
			: "memory"); \
} while (0)

/* Add ctpr3 to clobbers to explain to lcc that this
 * GNU asm does a return. */
#define E2K_DONE() \
do { \
	/* #80747: must repeat interrupted barriers */ \
	asm volatile ("{nop 3; wait st_c=1} {done}" ::: "ctpr3"); \
} while (0)

#define NATIVE_RETURN() \
do { \
	asm volatile(   "{\n" \
			"return %%ctpr3\n" \
			"}\n" \
			"{\n" \
			"ct %%ctpr3\n" \
			"}\n" \
			: \
			: \
			: "ctpr3"); \
} while (0)

#define NATIVE_RETURN_VALUE(rval) \
do { \
	asm volatile(   "{\n" \
			"return %%ctpr3\n" \
			"addd %[r0], 0, %%dr0\n" \
			"}\n" \
			"{\n" \
			"ct %%ctpr3\n" \
			"}\n" \
			: \
			: [r0] "ir" (rval) \
			: "ctpr3"); \
} while (0)

#define E2K_SYSCALL_RETURN NATIVE_RETURN_VALUE

#define E2K_EMPTY_CMD(input...) \
do { \
	asm volatile ("{nop}" :: input); \
} while (0)

#define E2K_PSYSCALL_RETURN(r0, r1, r2, r3, tag2, tag3) \
do { \
	asm volatile (	"{\n" \
			"return %%ctpr3\n" \
			"puttagd %[_r2], %[_tag2], %%dr2\n" \
			"puttagd %[_r3], %[_tag3], %%dr3\n" \
			"addd %[_r0], 0, %%dr0\n" \
			"addd %[_r1], 0, %%dr1\n" \
			"}\n" \
			"{\n" \
			"ct %%ctpr3\n" \
			"}\n" \
			:: [_r0] "ir" (r0), [_r1] "ir" (r1), \
			   [_r2] "ir" (r2), [_r3] "ir" (r3), \
			   [_tag2] "ir" (tag2), [_tag3] "ir" (tag3) \
			: "ctpr3"); \
} while (0)


#define GET_USER_ASM(_x, _addr, fmt, __ret_gu) \
	asm ( \
	     "1:\n" \
	     ALTERNATIVE_1_ALTINSTR \
	     /* CPU_FEAT_ISET_V6 version */ \
		     "{ld" #fmt "[ %[addr] + 0 ], %[x]\n" \
		     " adds 0, 0, %[ret]\n" \
		     " nop 4}\n" \
	     ALTERNATIVE_2_OLDINSTR \
	     /* Default version */ \
		     "{ld" #fmt "[ %[addr] + 0 ], %[x]\n" \
		     " adds 0, 0, %[ret]\n" \
		     " nop 2}\n" \
	     ALTERNATIVE_3_FEATURE(%[facility]) \
	     "2:\n" \
	     ".section .fixup,\"ax\"\n" \
	     "3:{adds 0, %[efault], %[ret]\n" \
	     "   ibranch 2b}\n" \
	     ".previous\n" \
	     ".section __ex_table,\"a\"\n" \
	     ".dword 1b, 3b\n" \
	     ".previous\n" \
	     : [ret] "=r" (__ret_gu), [x] "=r"(_x) \
	     : [addr] "m" (*(_addr)), [efault] "i" (-EFAULT), \
	       [facility] "i" (CPU_FEAT_ISET_V6)) \

#define PUT_USER_ASM(x, ptr, fmt, retval)			\
	asm ("1:{st" #fmt "%1, %2\n"				\
	     "   adds 0, 0, %0}\n"				\
	     "2:\n"						\
	     ".section .fixup,\"ax\"\n"				\
	     "3:\n{adds 0, %3, %0\n"				\
	     "  ibranch 2b}\n"					\
	     ".previous\n"					\
	     ".section __ex_table,\"a\"\n"			\
	     ".dword 1b, 3b\n"					\
	     ".previous\n"					\
	     : "=r" (retval), "=m" (*ptr)			\
	     : "r" (x), "i" (-EFAULT))

#define LOAD_UNALIGNED_ZEROPAD(_addr) \
({ \
	u64 *__addr = (u64 *) (_addr); \
	u64 _ret, _aligned_addr, _offset; \
	asm (	"1:\n" \
		" ldd [ %[addr] + 0 ], %[ret]\n" \
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
	asm ("1:\n" \
	     "{.word 0x00008001\n" /* SETSFT */ \
	     " .word 0x28000000}\n" \
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
		[entry_size] "i" (sizeof(struct bug_entry)))

#else

# define __EMIT_BUG(_flags) \
	asm ("1:\n" \
	     "{.word 0x00008001\n" /* SETSFT */ \
	     " .word 0x28000000}\n" \
	     ".section __bug_table,\"aw\"\n" \
	     "3:\n" \
	     ".word 1b - 3b\n"    /* bug_entry:bug_addr_disp */ \
	     ".short %[flags]\n"  /* bug_entry:flags */ \
	     ".org 3b + %[entry_size]\n" \
	     ".previous\n" \
	     :: [flags] "i" (_flags), \
		[entry_size] "i" (sizeof(struct bug_entry)))

#endif

#ifndef	__ASSEMBLY__  
/* new version */
/* 
 * this code used before call printk in special procedures
 *  sp register is used to pass parameters for printk 
 */ 
static inline void E2K_SET_USER_STACK(int x)
{
    register __e2k_ptr_t sp asm ("%SP");
    if (__builtin_constant_p(x) ) {
        if (x) {
            asm volatile ("{getsp   -1024, %0\n\t}"
                  : "=r" (sp));
        }
    } else {
     /* special for compiler error */
     /* fix  gcc problem -  warning */
#ifdef __LCC__
    asm ("" : : "i"(x)); /*  hook!!  parameter must be const */
#endif /*  __LCC__ */    
   }
}
#endif /* __ASSEMBLY__ */


#define E2K_GET_FP() \
({ \
    register __e2k_ptr_t res; \
    asm volatile ("addd \t0x0, %F0, %0" \
                  : "=r" (res)); \
    res; \
})

#define E2K_SET_FP( val) \
({ \
    asm volatile ("addd \t0x0, %0, %F0" \
                  : \
                  : "ri" ((__e2k_ptr_t) val)); \
})

#define E2K_GET_SP() \
({ \
    register __e2k_ptr_t res; \
    asm volatile ("addd \t0x0, %S0, %0" \
                  : "=r" (res)); \
    res; \
})

#define E2K_SET_SP( val) \
({ \
    asm volatile ("addd \t0x0, %0, %S0" \
                  : \
                  : "ri" ((__e2k_ptr_t) val)); \
})

#define E2K_NOP(nr) __asm__ __volatile__("{nop " #nr "}" ::: "memory")

#ifdef CONFIG_SMP
# define SMP_ONLY(...) __VA_ARGS__
#else
# define SMP_ONLY(...)
#endif

#ifdef CONFIG_CPU_HAS_FILL_INSTRUCTION
# define NATIVE_FILL_HARDWARE_STACKS() \
		asm volatile ("{fillc; fillr}" ::: "memory")
#else
# define NATIVE_FILL_HARDWARE_STACKS() \
do { \
	asm volatile ( \
		"{\n" \
		"nop 4\n" \
		"return %%ctpr3\n" \
		"movtd [ 0f ], %%dg" __stringify(GUEST_VCPU_STATE_GREG) "\n" \
		"}\n" \
		"{\n" \
		"rrd %%wd, %%dg" __stringify(CURRENT_TASK_GREG) "\n" \
		"}\n" \
		"{\n" \
		"rrd %%br, %%dg" __stringify(SMP_CPU_ID_GREG) "\n" \
		"ct %%ctpr3\n" \
		"}\n" \
		"0:\n" \
		"{\n" \
		"rwd %%dg" __stringify(CURRENT_TASK_GREG) ", %%wd\n" \
		"}\n" \
		"{\n" \
		"rwd %%dg" __stringify(SMP_CPU_ID_GREG) ", %%br\n" \
		"}\n" \
		"{\n" \
		"nop 3\n" \
		SMP_ONLY("ldw %%dg" __stringify(GUEST_VCPU_STATE_GREG) ", " \
		    "%[task_ti_cpu_delta], " \
		    "%%dg" __stringify(SMP_CPU_ID_GREG) "\n") \
		"subd %%dg" __stringify(GUEST_VCPU_STATE_GREG) ", " \
		    "%[task_ti_offset], " \
		    "%%dg" __stringify(CURRENT_TASK_GREG) "\n" \
		"}\n" \
		"{\n" \
		"nop\n" /* For "rwd %wd" */ \
		"}\n" \
		:: SMP_ONLY([task_ti_cpu_delta] "i" (offsetof(struct task_struct, cpu) - \
				   offsetof(struct task_struct, thread_info)),) \
		   [task_ti_offset] "i" (offsetof(struct task_struct, thread_info)) \
		: "ctpr1", "ctpr3", "memory"); \
} while (0)
#endif

#ifndef	__ASSEMBLY__

#define E2K_PARALLEL_WRITE(addr1, val1, addr2, val2) \
{                                                                       \
	asm volatile ("{\n\t"                                               \
		      "  std 0x0, %2, %4\n\t"                               \
		      "  std 0x0, %3, %5\n\t"                               \
		      "}"                                                   \
		      : "=m" (*(addr1)), "=m" (*(addr2))                    \
		      : "r" (addr1), "r" (addr2), "r" (val1), "r" (val2));  \
}

/*
 *                     Macroses to construct alternative return point from trap
 */

#define STICK_ON_REG(reg)	asm( #reg )

#define SAVE_CURRENT_ADDR(_ptr)	\
do { \
	unsigned long long _tmp; \
	_Pragma("no_asm_inline") \
	asm volatile ("movtd [ 0f ], %[tmp]\n" \
		      "std [ %[ptr] ], %[tmp]\n" \
		      "0:" \
		      : [ptr] "=m" (*(_ptr)), [tmp] "=&r" (_tmp)); \
} while (0)

#define	DO_FUNC_TO_NAME(func)	#func
#define	FUNC_TO_NAME(func)	DO_FUNC_TO_NAME(func)

#define GET_LBL_ADDR(name, where)	\
			_Pragma("no_asm_inline") \
			asm ("movtd [" name "], %0" : "=r" (where))

#define E2K_JUMP(func)	E2K_JUMP_WITH_ARGUMENTS(func, 0)

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
			arg1, arg2, arg3, arg4, arg5, arg6, arg7, is_name) \
do { \
	if (is_name) { \
		__E2K_JUMP_FUNC_WITH_ARGUMENTS_7(func, \
			arg1, arg2, arg3, arg4, arg5, arg6, arg7); \
	} else { \
		__E2K_JUMP_FUNC_ADDR_WITH_ARGUMENTS_7(func, \
			arg1, arg2, arg3, arg4, arg5, arg6, arg7); \
	} \
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

#define E2K_GOTO_ARG0(func) \
do { \
	_Pragma("no_asm_inline") \
	asm volatile ("ibranch " #func "\n" :: ); \
} while (0)
#define E2K_GOTO_ARG1(label, arg1)					\
do {									\
_Pragma("no_asm_inline")						\
	asm volatile (							\
		"{\n"							\
		"addd \t 0, %0, %%dr0\n"				\
		"ibranch \t" #label "\n"				\
		"}\n"							\
		:							\
		: "ri" ((__e2k_u64_t) (arg1))				\
	);								\
} while (false)
#define E2K_GOTO_ARG2(label, arg1, arg2)				\
do {									\
_Pragma("no_asm_inline")						\
	asm volatile ("\n"						\
		"{\n"							\
		"addd \t 0, %0, %%dr0\n"				\
		"addd \t 0, %1, %%dr1\n"				\
		"ibranch \t" #label "\n"				\
		"}\n"							\
		:							\
		: "ri" ((__e2k_u64_t) (arg1)),				\
		  "ri" ((__e2k_u64_t) (arg2))				\
	);								\
} while (false)
#define E2K_GOTO_ARG3(label, arg1, arg2, arg3)				\
do {									\
_Pragma("no_asm_inline")						\
	asm volatile ("\n"						\
		"{\n"							\
		"addd \t 0, %0, %%dr0\n"				\
		"addd \t 0, %1, %%dr1\n"				\
		"addd \t 0, %2, %%dr2\n"				\
		"ibranch \t" #label "\n"				\
		"}\n"							\
		:							\
		: "ri" ((__e2k_u64_t) (arg1)),				\
		  "ri" ((__e2k_u64_t) (arg2)),				\
		  "ri" ((__e2k_u64_t) (arg3))				\
	);								\
} while (false)
#define E2K_GOTO_ARG4(label, arg1, arg2, arg3, arg4)			\
do {									\
_Pragma("no_asm_inline")						\
	asm volatile ("\n"						\
		"{\n"							\
		"addd \t 0, %0, %%dr0\n"				\
		"addd \t 0, %1, %%dr1\n"				\
		"addd \t 0, %2, %%dr2\n"				\
		"addd \t 0, %3, %%dr3\n"				\
		"ibranch \t" #label "\n"				\
		"}\n"							\
		:							\
		: "ri" ((__e2k_u64_t) (arg1)),				\
		  "ri" ((__e2k_u64_t) (arg2)),				\
		  "ri" ((__e2k_u64_t) (arg3)),				\
		  "ri" ((__e2k_u64_t) (arg4))				\
	);								\
} while (false)
#define E2K_GOTO_AND_RETURN_ARG6(label,				\
		arg1, arg2, arg3, arg4, arg5, arg6)			\
do {									\
_Pragma("no_asm_inline")						\
	asm volatile ("\n"						\
		"{\n"							\
		"addd \t 0, %0, %%dr0\n"				\
		"addd \t 0, %1, %%dr1\n"				\
		"addd \t 0, %2, %%dr2\n"				\
		"addd \t 0, %3, %%dr3\n"				\
		"addd \t 0, %4, %%dr4\n"				\
		"addd \t 0, %5, %%dr5\n"				\
		"}\n"							\
		"{\n"							\
		"rrd  \t %%nip, %%dr6\n"				\
		"ibranch \t" #label					\
		"}\n"							\
		:							\
		: "ri" ((__e2k_u64_t) (arg1)),				\
		  "ri" ((__e2k_u64_t) (arg2)),				\
		  "ri" ((__e2k_u64_t) (arg3)),				\
		  "ri" ((__e2k_u64_t) (arg4)),				\
		  "ri" ((__e2k_u64_t) (arg5)),				\
		  "ri" ((__e2k_u64_t) (arg6))				\
	);								\
} while (false)
#define E2K_COND_GOTO(label, cond, pred_no)				\
do {									\
_Pragma("no_asm_inline")						\
	asm volatile (							\
		"\ncmpesb \t0, %0, %%pred" #pred_no			\
		"\n{"							\
		"\nibranch \t" #label " ? ~%%pred" #pred_no		\
		"\n}"							\
		:							\
		: "ri" ((__e2k_u32_t) (cond))				\
		: "pred" #pred_no					\
	);								\
} while (false)
#define E2K_COND_GOTO_ARG1(label, cond, pred_no, arg1)			\
do {									\
_Pragma("no_asm_inline")						\
	asm volatile (							\
		"\ncmpesb \t0, %0, %%pred" #pred_no			\
		"\n{"							\
		"\naddd \t 0, %1, %%dr0 ? ~%%pred" #pred_no		\
		"\nibranch \t" #label " ? ~%%pred" #pred_no		\
		"\n}"							\
		:							\
		: "ri" ((__e2k_u32_t) (cond)),				\
		  "ri" ((__e2k_u64_t) (arg1))				\
		: "pred" #pred_no					\
	);								\
} while (false)
#define E2K_COND_GOTO_ARG2(label, cond, pred_no, arg1, arg2)		\
do {									\
_Pragma("no_asm_inline")						\
	asm volatile (							\
		"\ncmpesb \t0, %0, %%pred" #pred_no			\
		"\n{"							\
		"\naddd \t 0, %1, %%dr0 ? ~%%pred" #pred_no		\
		"\naddd \t 0, %2, %%dr1 ? ~%%pred" #pred_no		\
		"\nibranch \t" #label " ? ~%%pred" #pred_no		\
		"\n}"							\
		:							\
		: "ri" ((__e2k_u32_t) (cond)),				\
		  "ri" ((__e2k_u64_t) (arg1)),				\
		  "ri" ((__e2k_u64_t) (arg2))				\
		: "pred" #pred_no					\
	);								\
} while (false)
#define	DEF_COND_GOTO(label, cond)					\
		E2K_COND_GOTO(label, cond, 0)
#define	DEF_COND_GOTO_ARG1(label, cond, arg1)				\
		E2K_COND_GOTO_ARG1(label, cond, 0, arg1)
#define	DEF_COND_GOTO_ARG2(label, cond, arg1, arg2)			\
		E2K_COND_GOTO_ARG2(label, cond, 0, arg1, arg2)

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

#define E2K_GOTO_INTEGER_LABEL_ARGS_0(_func) \
({ \
	asm volatile ( \
		"{\n" \
			"movtd	%[func], %%ctpr1\n" \
		"}\n" \
		"{\n" \
			"ct	%%ctpr1\n" \
		"}\n" \
		: \
		: [func] "r" (_func) \
		: "ctpr1"); \
})

#define __E2K_RESTART_TTABLE_ENTRY10_C(func, arg0, arg1, arg2, arg3, arg4, \
					arg5, arg6, arg7, tags) \
do { \
	asm volatile ("{\n" \
		      "disp %%ctpr1, " #func "\n" \
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
			"ri" (tags) \
		      : "ctpr1", "r0", "r1", "r2", "r3", "r4", "r5", "r6", \
			"r7", "r8"); \
	unreachable(); \
} while (0)

#define __E2K_RESTART_TTABLE_ENTRY8_C(func, _sys_num, arg1, arg2, arg3, arg4, \
		arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12, _tags) \
do { \
	u64 tag_lo, tag_hi; \
	asm volatile ( \
		"{\n" \
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
		  [a11] "ri" (arg11), [a12] "ri" (arg12), [tags] "ri" (_tags) \
		: "ctpr1", "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", \
		  "r8", "r9", "r10", "r11", "r12", "r13"); \
	unreachable(); \
} while (0)

/* Important: delay after FPU reading is 9 cycles for 0 cluster
 * and 11 for 1 cluster, thus the NOPs. */
#define E2K_GETCONTEXT(fpcr, fpsr, pfpfr, pcsp_lo, pcsp_hi) \
do { \
	u64 __pcshtp; \
	asm volatile ("rrs %%fpcr, %0\n" \
		      "rrs %%fpsr, %1\n" \
		      "rrs %%pfpfr, %2\n" \
		      "rrd %%pcshtp, %5\n" \
		      "rrd %%pcsp.lo, %3\n" \
		      "{rrd %%pcsp.hi, %4\n" \
		      "shld %5, 53, %5}\n" \
		      "sard %5, 53, %5\n" \
		      "{addd %4, %5, %4\n" \
		      "nop 5}\n" \
		      : "=r" (fpcr), "=r" (fpsr), "=r" (pfpfr), \
			"=r" (pcsp_lo), "=r" (pcsp_hi), "=r" (__pcshtp) \
		      : ); \
} while (0)

#define E2K_CLEAR_RF_108() \
do { \
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
	__e2k_u64_t	reg;			\
	asm volatile (				\
		"{\n"				\
		"puttagd 0, 5, %0\n"		\
		"}\n"				\
		"{\n"				\
		"movtd,s %0, %%ctpr1\n"		\
		"}\n"				\
		"{\n"				\
		"movtd,s %0, %%ctpr2\n"		\
		"}\n"				\
		"{\n"				\
		"movtd,s %0, %%ctpr3\n"		\
		"}\n"				\
		: "=r" (reg)			\
		:				\
		: "ctpr1", "ctpr2", "ctpr3");	\
} while (0)

#define NATIVE_RESTORE_COMMON_REGS_VALUES(_ctpr1, _ctpr2, _ctpr3, _ctpr1_hi, \
		_ctpr2_hi, _ctpr3_hi, _lsr, _lsr1, _ilcr, _ilcr1) \
do { \
	_Pragma("no_asm_inline") \
	asm volatile ( \
		      "{\n" \
		      "rwd %[ctpr2], %%ctpr2\n" \
		      "}\n" \
 \
		      ALTERNATIVE_1_ALTINSTR \
		      /* CPU_FEAT_TRAP_V5 version */ \
 \
			      "{\n" \
			      "rwd %[ctpr3], %%ctpr3\n" \
			      "}\n" \
			      "{\n" \
			      "rwd %[ctpr1], %%ctpr1\n" \
			      "}\n" \
			      "{\n" \
			      "rwd %[lsr], %%lsr\n" \
			      "addd %[lsr1], 0, %%db[1]\n" \
			      "addd %[ilcr1], 0, %%db[3]\n" \
			      "}\n" \
			      /* rwd %db[1], %%lsr1 */ \
			      ".word 0x04100011; .word 0x3dc001c3\n" \
			      ".word 0x01c00000; .word 0x00000000\n" \
			      "{\n" \
			      "rwd %[ilcr], %%ilcr\n" \
			      "}\n" \
			      /* rwd %db[3], %%ilcr1 */ \
			      ".word 0x04100011; .word 0x3dc003c7\n" \
			      ".word 0x01c00000; .word 0x00000000\n" \
 \
		      ALTERNATIVE_2_ALTINSTR2 \
		      /* CPU_FEAT_TRAP_V6 version */ \
 \
			      "{\n" \
			      "rwd %[ctpr3], %%ctpr3\n" \
			      "addd %[ctpr1_hi], %%db[0]\n" \
			      "addd %[ctpr2_hi], %%db[2]\n" \
			      "}\n" \
			      "{\n" \
			      "rwd %[ctpr1], %%ctpr1\n" \
			      "addd %[ctpr3_hi], %%db[4]\n" \
			      "addd %[lsr1], 0, %%db[1]\n" \
			      "}\n" \
			      /* rwd %db[0], %%ctpr1.hi */ \
			      ".word 0x04100011; .word 0x3dc00019\n" \
			      ".word 0x01c00000; .word 0x00000000\n" \
			      /* rwd %db[2], %%ctpr2.hi */ \
			      ".word 0x04100011; .word 0x3dc0021a\n" \
			      ".word 0x01c00000; .word 0x00000000\n" \
			      /* rwd %db[4], %%ctpr3.hi */ \
			      ".word 0x04100011; .word 0x3dc0041b\n" \
			      ".word 0x01c00000; .word 0x00000000\n" \
			      "{\n" \
			      "rwd %[lsr], %%lsr\n" \
			      "addd %[ilcr1], 0, %%db[3]\n" \
			      "}\n" \
			      /* rwd %db[1], %%lsr1 */ \
			      ".word 0x04100011; .word 0x3dc001c3\n" \
			      ".word 0x01c00000; .word 0x00000000\n" \
			      "{\n" \
			      "rwd %[ilcr], %%ilcr\n" \
			      "}\n" \
			      /* rwd %db[3], %%ilcr1 */ \
			      ".word 0x04100011; .word 0x3dc003c7\n" \
			      ".word 0x01c00000; .word 0x00000000\n" \
 \
		      ALTERNATIVE_3_OLDINSTR2 \
 \
			      "{\n" \
			      "rwd %[ctpr3], %%ctpr3\n" \
			      "}\n" \
			      "{\n" \
			      "rwd %[ctpr1], %%ctpr1\n" \
			      "}\n" \
			      "{\n" \
			      "rwd %[lsr], %%lsr\n" \
			      "}\n" \
			      "{\n" \
			      "rwd %[ilcr], %%ilcr\n" \
			      "}\n" \
 \
		      ALTERNATIVE_4_FEATURE2(%[facility1], %[facility2]) \
		      :: [ctpr1] "r" (_ctpr1), [ctpr2] "r" (_ctpr2), \
			 [ctpr3] "r" (_ctpr3), [ctpr1_hi] "r" (_ctpr1_hi), \
			 [ctpr2_hi] "r" (_ctpr2_hi), [ctpr3_hi] "r" (_ctpr3_hi), \
			 [lsr] "r" (_lsr), [lsr1] "r" (_lsr1), \
			 [ilcr] "r" (_ilcr), [ilcr1] "r" (_ilcr1), \
			 [facility1] "i" (CPU_FEAT_TRAP_V5), \
			 [facility2] "i" (CPU_FEAT_TRAP_V6) \
		      : "memory", "b[0]", "b[1]", "b[2]", "b[3]", "b[4]"); \
} while (0)

#define NATIVE_RESTORE_KERNEL_GREGS(_k_gregs) \
do { \
	u64 f16, f17, f18, f19, tmp1, tmp2; \
	_Pragma("no_asm_inline") \
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
	_Pragma("no_asm_inline") \
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
	asm volatile ("{ldrd [%1], %0\n}"			\
		      : "=r"(__dres)				\
		      : "m" (*((unsigned long long *)(addr))));	\
	__dres;							\
})

#define SIMPLE_RECOVERY_STORE(_addr, _data, _opc) \
do { \
	u32 _fmt = ((ldst_rec_op_t *) &_opc)->fmt; \
	u32 _ind = ((ldst_rec_op_t *) &_opc)->index; \
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
	u32 _ind = ((ldst_rec_op_t *) &_opc)->index; \
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
		  [ind] "r" (_ind), [mas] "r" (_mas) \
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
	u32 _ind = ((ldst_rec_op_t *) &_opc)->index; \
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
		  [first_time] "r" (_first_time), [mas] "r" (_mas) \
		: "memory", "pred19", "pred20", "pred21", "pred22", "pred23" \
	); \
} while (0)

/* Since v6 this got replaced with "wait int=1,mem_mod=1" */
#define C1_WAIT_TRAP_V3() \
do { \
	_Pragma("no_asm_inline") \
	asm volatile ("wait trap=1" ::: "memory"); \
} while (0)

#define C3_WAIT_TRAP_V3(__val, __phys_addr) \
do { \
	u64 _reg; \
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
			"stw %[phys_addr], 0, %[val], mas=%[mas_ioaddr]\n" \
			"wait trap=1\n" \
		ALTERNATIVE_2_OLDINSTR \
		/* Default version */ \
			"stw %[phys_addr], 0, %[val], mas=%[mas_ioaddr]\n" \
			"wait trap=1\n" \
		ALTERNATIVE_3_FEATURE(%[facility]) \
		/* Will never get here */ \
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
		  [mas_ioaddr] "i" (MAS_IOADDR), \
		  [facility] "i" (CPU_HWBUG_C3_WAIT_MA_C) \
		: "memory", "ctpr1", "ctpr2", "ctpr3"); \
} while (0)

/* Preparing to turn the synchoniztion clock off
 * by writing the value __val to register PMC pointed by __phys_addr */
#define C3_WAIT_INT_V6(__val, __phys_addr) \
do { \
	u64 _reg; \
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

/* Hardware virtualized extensions support */

#define E2K_GLAUNCH(_ctpr1, _ctpr1_hi, _ctpr2, _ctpr2_hi, _ctpr3, _ctpr3_hi, \
		    _lsr, _lsr1, _ilcr, _ilcr1) \
do { \
	_Pragma("no_asm_inline")		\
	asm volatile ("{rwd %[ctpr1], %%ctpr1}\n" \
		      "{rwd %[ctpr1_hi], %%ctpr1.hi}\n" \
		      "{rwd %[ctpr3], %%ctpr3}\n" \
		      "{rwd %[ctpr3_hi], %%ctpr3.hi}\n" \
		      "{\n" \
		      "rwd %[lsr], %%lsr\n" \
		      "addd %[lsr1], 0, %%db[1]\n" \
		      "addd %[ilcr1], 0, %%db[3]\n" \
		      "}\n" \
		      /* rwd %db[1], %%lsr1 */ \
		      ".word 0x04100011\n" \
		      ".word 0x3dc001c3\n" \
		      ".word 0x01c00000\n" \
		      ".word 0x00000000\n" \
		      "{\n" \
		      "rwd %[ilcr], %%ilcr\n" \
		      "}\n" \
		      /* rwd %db[3], %%ilcr1 */ \
		      ".word 0x04100011\n" \
		      ".word 0x3dc003c7\n" \
		      ".word 0x01c00000\n" \
		      ".word 0x00000000\n" \
		      /* #80747: must repeat interrupted barriers */ \
		      "{nop 3; wait st_c=1}\n" \
		      "{glaunch}\n" \
		      "{wait fl_c=1\n" \
		      " rrd %%lsr, %[lsr]}\n" \
		      "{rrd %%ilcr, %[ilcr]}\n" \
		      "{rrd %%lsr1, %[lsr1]}\n" \
		      "{rrd %%ilcr1, %[ilcr1]}\n" \
		      "{rrd %%ctpr1, %[ctpr1]}\n" \
		      "{rrd %%ctpr1.hi, %[ctpr1_hi]}\n" \
		      "{rrd %%ctpr2, %[ctpr2]}\n" \
		      "{rrd %%ctpr2.hi, %[ctpr2_hi]}\n" \
		      "{rrd %%ctpr3, %[ctpr3]}\n" \
		      "{rrd %%ctpr3.hi, %[ctpr3_hi]}\n" \
		      ALTERNATIVE_1_ALTINSTR \
		      /* CPU_HWBUG_L1I_STOPS_WORKING version */ \
			      "1:\n" \
			      "{ipd 0; disp %%ctpr1, 1b}" \
			      /* ctpr2 will be cleared after saving AAU */ \
			      "{ipd 0; disp %%ctpr3, 1b}" \
		      ALTERNATIVE_2_OLDINSTR \
		      /* Default version */ \
			      "{nop}" \
		      ALTERNATIVE_3_FEATURE(%[facility]) \
		      : [lsr] "+r" (_lsr), [lsr1] "+r" (_lsr1), \
			[ilcr] "+r" (_ilcr), [ilcr1] "+r" (_ilcr1), \
			[ctpr1] "+r" (_ctpr1), [ctpr1_hi] "+r" (_ctpr1_hi), \
			[ctpr2] "+r" (_ctpr2), [ctpr2_hi] "+r" (_ctpr2_hi), \
		        [ctpr3] "+r" (_ctpr3), [ctpr3_hi] "+r" (_ctpr3_hi) \
		      : [facility] "i" (CPU_HWBUG_L1I_STOPS_WORKING) \
		      : "memory", "b[1]", "b[3]", "ctpr1", "ctpr2", "ctpr3"); \
} while (0)


/* Clobbers "ctpr" are here to tell lcc that there is a call inside */
#define E2K_HCALL_CLOBBERS \
		"ctpr1", "ctpr2", "ctpr3", \
		"b[0]", "b[1]", "b[2]", "b[3]", \
		"b[4]", "b[5]", "b[6]", "b[7]"

#define __E2K_HCALL_0(_trap, _sys_num, _arg1) \
({ \
	register u64 __res; \
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

#define E2K_HRET(_ret) \
do { \
	asm volatile ( \
		"addd 0x0, %[ret], %%r0\n" \
		"{.word 0x00005012\n" /* HRET */ \
		" .word 0xc0000020\n" \
		" .word 0x30000003\n" \
		" .word 0x00000000}\n" \
		: \
		: [ret] "ir" (_ret) \
		: E2K_HRET_CLOBBERS); \
	unreachable(); \
} while (0)


typedef unsigned long long __e2k_syscall_arg_t;

#define E2K_SYSCALL_CLOBBERS \
		"ctpr1", "ctpr2", "ctpr3", \
		"b[0]", "b[1]", "b[2]", "b[3]", \
		"b[4]", "b[5]", "b[6]", "b[7]"

/* Transaction operation transaction of argument type
 * __e2k_syscall_arg_t */
#ifdef __ptr64__
#define __E2K_SYSCAL_ARG_ADD "addd,s"
#else
#define __E2K_SYSCAL_ARG_ADD "adds,s"
#endif

#define __E2K_SYSCALL_0(_trap, _sys_num, _arg1) \
({ \
	register __e2k_syscall_arg_t __res; \
	asm volatile ("{\n" \
		__E2K_SYSCAL_ARG_ADD "  0x0, %[sys_num], %%b[0]\n\t" \
		"sdisp %%ctpr1, %[trap]\n\t" \
		"}\n" \
		"call  %%ctpr1, wbs = %#\n\t" \
		__E2K_SYSCAL_ARG_ADD "  0x0, %%b[0], %[res]" \
		: [res]     "=r" (__res) \
		: [trap]    "i"  ((int) (_trap)), \
		  [sys_num] "ri" ((__e2k_syscall_arg_t) (_sys_num)) \
		: E2K_SYSCALL_CLOBBERS); \
	__res; \
})

#define __E2K_SYSCALL_1(_trap, _sys_num, _arg1) \
({ \
	register __e2k_syscall_arg_t __res; \
	asm volatile ("{\n" \
		__E2K_SYSCAL_ARG_ADD "  0x0, %[sys_num], %%b[0]\n\t" \
		__E2K_SYSCAL_ARG_ADD "  0x0, %[arg1], %%b[1]\n\t" \
		"sdisp %%ctpr1, %[trap]\n\t" \
		"}\n" \
		"call  %%ctpr1, wbs = %#\n\t" \
		__E2K_SYSCAL_ARG_ADD "  0x0, %%b[0], %[res]" \
		: [res]     "=r" (__res) \
		: [trap]    "i"  ((int) (_trap)), \
		  [sys_num] "ri" ((__e2k_syscall_arg_t) (_sys_num)), \
		  [arg1]    "ri" ((__e2k_syscall_arg_t) (_arg1)) \
		: E2K_SYSCALL_CLOBBERS); \
	__res; \
})

#define __E2K_SYSCALL_2(_trap, _sys_num, _arg1, _arg2) \
({ \
	register __e2k_syscall_arg_t __res; \
	asm volatile ("{\n" \
		__E2K_SYSCAL_ARG_ADD "  0x0, %[sys_num], %%b[0]\n\t" \
		__E2K_SYSCAL_ARG_ADD "  0x0, %[arg1], %%b[1]\n\t" \
		__E2K_SYSCAL_ARG_ADD "  0x0, %[arg2], %%b[2]\n\t" \
		"sdisp %%ctpr1, %[trap]\n\t" \
		"}\n" \
		"call  %%ctpr1, wbs = %#\n\t" \
		__E2K_SYSCAL_ARG_ADD "  0x0, %%b[0], %[res]" \
		: [res]     "=r" (__res) \
		: [trap]    "i"  ((int) (_trap)), \
		  [sys_num] "ri" ((__e2k_syscall_arg_t) (_sys_num)), \
		  [arg1]    "ri" ((__e2k_syscall_arg_t) (_arg1)), \
		  [arg2]    "ri" ((__e2k_syscall_arg_t) (_arg2)) \
		: E2K_SYSCALL_CLOBBERS); \
	__res; \
})

#define __E2K_SYSCALL_3(_trap, _sys_num, _arg1, _arg2, _arg3) \
({ \
	register __e2k_syscall_arg_t __res; \
	asm volatile ("{\n" \
		__E2K_SYSCAL_ARG_ADD "  0x0, %[sys_num], %%b[0]\n\t" \
		__E2K_SYSCAL_ARG_ADD "  0x0, %[arg1], %%b[1]\n\t" \
		__E2K_SYSCAL_ARG_ADD "  0x0, %[arg2], %%b[2]\n\t" \
		__E2K_SYSCAL_ARG_ADD "  0x0, %[arg3], %%b[3]\n\t" \
		"sdisp %%ctpr1, %[trap]\n\t" \
		"}\n" \
		"call  %%ctpr1, wbs = %#\n\t" \
		__E2K_SYSCAL_ARG_ADD "  0x0, %%b[0], %[res]" \
		: [res]     "=r" (__res) \
		: [trap]    "i"  ((int) (_trap)), \
		  [sys_num] "ri" ((__e2k_syscall_arg_t) (_sys_num)), \
		  [arg1]    "ri" ((__e2k_syscall_arg_t) (_arg1)), \
		  [arg2]    "ri" ((__e2k_syscall_arg_t) (_arg2)), \
		  [arg3]    "ri" ((__e2k_syscall_arg_t) (_arg3)) \
		: E2K_SYSCALL_CLOBBERS); \
	__res; \
})

#define __E2K_SYSCALL_4(_trap, _sys_num, _arg1, _arg2, _arg3, _arg4) \
({ \
	register __e2k_syscall_arg_t __res; \
	asm volatile ("{\n" \
		__E2K_SYSCAL_ARG_ADD "  0x0, %[sys_num], %%b[0]\n\t" \
		__E2K_SYSCAL_ARG_ADD "  0x0, %[arg1], %%b[1]\n\t" \
		__E2K_SYSCAL_ARG_ADD "  0x0, %[arg2], %%b[2]\n\t" \
		__E2K_SYSCAL_ARG_ADD "  0x0, %[arg3], %%b[3]\n\t" \
		__E2K_SYSCAL_ARG_ADD "  0x0, %[arg4], %%b[4]\n\t" \
		"sdisp %%ctpr1, %[trap]\n\t" \
		"}\n" \
		"call  %%ctpr1, wbs = %#\n\t" \
		__E2K_SYSCAL_ARG_ADD "  0x0, %%b[0], %[res]" \
		: [res]     "=r" (__res) \
		: [trap]    "i"  ((int) (_trap)), \
		 [sys_num] "ri" ((__e2k_syscall_arg_t) (_sys_num)), \
		 [arg1]    "ri" ((__e2k_syscall_arg_t) (_arg1)), \
		 [arg2]    "ri" ((__e2k_syscall_arg_t) (_arg2)), \
		 [arg3]    "ri" ((__e2k_syscall_arg_t) (_arg3)), \
		 [arg4]    "ri" ((__e2k_syscall_arg_t) (_arg4)) \
		: E2K_SYSCALL_CLOBBERS); \
	__res; \
})

#define __E2K_SYSCALL_5(_trap, _sys_num, _arg1, _arg2, _arg3, _arg4, _arg5) \
({ \
	register __e2k_syscall_arg_t __res; \
	asm volatile ("{\n" \
		__E2K_SYSCAL_ARG_ADD "  0x0, %[sys_num], %%b[0]\n\t" \
		__E2K_SYSCAL_ARG_ADD "  0x0, %[arg1], %%b[1]\n\t" \
		__E2K_SYSCAL_ARG_ADD "  0x0, %[arg2], %%b[2]\n\t" \
		__E2K_SYSCAL_ARG_ADD "  0x0, %[arg3], %%b[3]\n\t" \
		__E2K_SYSCAL_ARG_ADD "  0x0, %[arg4], %%b[4]\n\t" \
		__E2K_SYSCAL_ARG_ADD "  0x0, %[arg5], %%b[5]\n\t" \
		"sdisp %%ctpr1, %[trap]\n\t" \
		"}\n" \
		"call  %%ctpr1, wbs = %#\n\t" \
		__E2K_SYSCAL_ARG_ADD "  0x0, %%b[0], %[res]" \
		: [res]     "=r" (__res) \
		: [trap]    "i"  ((int) (_trap)), \
		  [sys_num] "ri" ((__e2k_syscall_arg_t) (_sys_num)), \
		  [arg1]    "ri" ((__e2k_syscall_arg_t) (_arg1)), \
		  [arg2]    "ri" ((__e2k_syscall_arg_t) (_arg2)), \
		  [arg3]    "ri" ((__e2k_syscall_arg_t) (_arg3)), \
		  [arg4]    "ri" ((__e2k_syscall_arg_t) (_arg4)), \
		  [arg5]    "ri" ((__e2k_syscall_arg_t) (_arg5)) \
		: E2K_SYSCALL_CLOBBERS); \
	__res; \
})

#define __E2K_SYSCALL_6(_trap, _sys_num, _arg1, \
			_arg2, _arg3, _arg4, _arg5, _arg6) \
({ \
	register __e2k_syscall_arg_t __res; \
	asm volatile ("{\n" \
		"sdisp %%ctpr1, %[trap]\n\t" \
		__E2K_SYSCAL_ARG_ADD "  0x0, %[sys_num], %%b[0]\n\t" \
		__E2K_SYSCAL_ARG_ADD "  0x0, %[arg1], %%b[1]\n\t" \
		__E2K_SYSCAL_ARG_ADD "  0x0, %[arg2], %%b[2]\n\t" \
		__E2K_SYSCAL_ARG_ADD "  0x0, %[arg3], %%b[3]\n\t" \
		__E2K_SYSCAL_ARG_ADD "  0x0, %[arg4], %%b[4]\n\t" \
		__E2K_SYSCAL_ARG_ADD "  0x0, %[arg5], %%b[5]\n\t" \
		"}\n" \
		"{\n" \
		__E2K_SYSCAL_ARG_ADD "  0x0, %[arg6], %%b[6]\n\t" \
		"call  %%ctpr1, wbs = %#\n\t" \
		"}\n" \
		__E2K_SYSCAL_ARG_ADD "  0x0, %%b[0], %[res]" \
		: [res]     "=r" (__res) \
		: [trap]    "i"  ((int) (_trap)), \
		  [sys_num] "ri" ((__e2k_syscall_arg_t) (_sys_num)), \
		  [arg1]    "ri" ((__e2k_syscall_arg_t) (_arg1)), \
		  [arg2]    "ri" ((__e2k_syscall_arg_t) (_arg2)), \
		  [arg3]    "ri" ((__e2k_syscall_arg_t) (_arg3)), \
		  [arg4]    "ri" ((__e2k_syscall_arg_t) (_arg4)), \
		  [arg5]    "ri" ((__e2k_syscall_arg_t) (_arg5)), \
		  [arg6]    "ri" ((__e2k_syscall_arg_t) (_arg6)) \
		: E2K_SYSCALL_CLOBBERS); \
	__res; \
})

#define __E2K_SYSCALL_7(_trap, _sys_num, _arg1, \
			_arg2, _arg3, _arg4, _arg5, _arg6, _arg7) \
({ \
	register __e2k_syscall_arg_t __res; \
	asm volatile ("{\n" \
		"sdisp %%ctpr1, %[trap]\n\t" \
		__E2K_SYSCAL_ARG_ADD "  0x0, %[sys_num], %%b[0]\n\t" \
		__E2K_SYSCAL_ARG_ADD "  0x0, %[arg1], %%b[1]\n\t" \
		__E2K_SYSCAL_ARG_ADD "  0x0, %[arg2], %%b[2]\n\t" \
		__E2K_SYSCAL_ARG_ADD "  0x0, %[arg3], %%b[3]\n\t" \
		__E2K_SYSCAL_ARG_ADD "  0x0, %[arg4], %%b[4]\n\t" \
		__E2K_SYSCAL_ARG_ADD "  0x0, %[arg5], %%b[5]\n\t" \
		"}\n" \
		"{\n" \
		__E2K_SYSCAL_ARG_ADD "  0x0, %[arg6], %%b[6]\n\t" \
		__E2K_SYSCAL_ARG_ADD "  0x0, %[arg7], %%b[7]\n\t" \
		"call  %%ctpr1, wbs = %#\n\t" \
		"}\n" \
		__E2K_SYSCAL_ARG_ADD "  0x0, %%b[0], %[res]" \
		: [res]     "=r" (__res) \
		: [trap]    "i"  ((int) (_trap)), \
		  [sys_num] "ri" ((__e2k_syscall_arg_t) (_sys_num)), \
		  [arg1]    "ri" ((__e2k_syscall_arg_t) (_arg1)), \
		  [arg2]    "ri" ((__e2k_syscall_arg_t) (_arg2)), \
		  [arg3]    "ri" ((__e2k_syscall_arg_t) (_arg3)), \
		  [arg4]    "ri" ((__e2k_syscall_arg_t) (_arg4)), \
		  [arg5]    "ri" ((__e2k_syscall_arg_t) (_arg5)), \
		  [arg6]    "ri" ((__e2k_syscall_arg_t) (_arg6)), \
		  [arg7]    "ri" ((__e2k_syscall_arg_t) (_arg7)) \
		: E2K_SYSCALL_CLOBBERS); \
	__res; \
})

#define E2K_SYSCALL(trap, sys_num, num_args, args...) \
	__E2K_SYSCALL_##num_args(trap, sys_num, args)

#define ASM_CALL_8_ARGS(func_name_to_call, _arg0, _arg1, _arg2, _arg3, \
				_arg4, _arg5, _arg6, _arg7) \
({ \
	register __e2k_syscall_arg_t __res; \
	asm volatile ( \
		"{\n\t" \
			__E2K_SYSCAL_ARG_ADD "  0x0, %[arg0], %%b[0]\n\t" \
			__E2K_SYSCAL_ARG_ADD "  0x0, %[arg1], %%b[1]\n\t" \
			__E2K_SYSCAL_ARG_ADD "  0x0, %[arg2], %%b[2]\n\t" \
			__E2K_SYSCAL_ARG_ADD "  0x0, %[arg3], %%b[3]\n\t" \
			"disp %%ctpr1, " #func_name_to_call "\n\t" \
		"}\n\t" \
		"{\n\t" \
			__E2K_SYSCAL_ARG_ADD "  0x0, %[arg4], %%b[4]\n\t" \
			__E2K_SYSCAL_ARG_ADD "  0x0, %[arg5], %%b[5]\n\t" \
			__E2K_SYSCAL_ARG_ADD "  0x0, %[arg6], %%b[6]\n\t" \
			__E2K_SYSCAL_ARG_ADD "  0x0, %[arg7], %%b[7]\n\t" \
			"call  %%ctpr1, wbs = %#\n\t" \
		"}\n\t" \
		__E2K_SYSCAL_ARG_ADD "  0x0, %%b[0], %[res]\n\t" \
		:						\
		  [res]  "=r" (__res)				\
		:						\
		  [arg0] "ri" ((__e2k_syscall_arg_t) (_arg0)),	\
		  [arg1] "ri" ((__e2k_syscall_arg_t) (_arg1)),	\
		  [arg2] "ri" ((__e2k_syscall_arg_t) (_arg2)),	\
		  [arg3] "ri" ((__e2k_syscall_arg_t) (_arg3)),	\
		  [arg4] "ri" ((__e2k_syscall_arg_t) (_arg4)),	\
		  [arg5] "ri" ((__e2k_syscall_arg_t) (_arg5)),	\
		  [arg6] "ri" ((__e2k_syscall_arg_t) (_arg6)),	\
		  [arg7] "ri" ((__e2k_syscall_arg_t) (_arg7))	\
		: E2K_SYSCALL_CLOBBERS);			\
	__res;							\
})

#define __arch_this_cpu_read(_var, size) \
({ \
	typeof(_var) __ret; \
	_Pragma("no_asm_inline") \
	asm ("ld" size " %%dg" __stringify(MY_CPU_OFFSET_GREG) ", %[var], %[ret]" \
				: [ret] "=r" (__ret) \
				: [var] "r" (&(_var)) \
				: "memory"); \
	__ret; \
})

#define __arch_this_cpu_write(_var, _val, size) \
do { \
	_Pragma("no_asm_inline") \
	asm ("st" size " %%dg" __stringify(MY_CPU_OFFSET_GREG) ", %[var], %[val]" \
				:: [var] "r" (&(_var)), [val] "r" (_val) \
				: "memory"); \
} while (0)

/* Use relaxed atomics for percpu if they are available */
#if CONFIG_CPU_ISET >= 5

# define __arch_pcpu_atomic_xchg(_val, _var, size) \
({ \
	typeof(_var) __ret; \
	HWBUG_ATOMIC_BEGIN(__my_cpu_offset + &(_var)); \
	asm NOT_VOLATILE ( \
		MB_BEFORE_ATOMIC_RELAXED_MB \
		"\n2:" \
		"\n{"\
		"\nnop 5" /* bug 92891 - optimize for performance */ \
		"\nld" size ",0 %%dg" __stringify(MY_CPU_OFFSET_GREG) ", %[var], %[ret], mas=0x7" \
		"\n}" \
		"\n{"\
		"\nst" size "," RELAXED_MB_ATOMIC_CHANNEL " \
			%%dg" __stringify(MY_CPU_OFFSET_GREG) ", %[var], %[val], mas=" RELAXED_MB_ATOMIC_MAS \
		"\nibranch 2b ? %%MLOCK" \
		"\n}" \
		MB_AFTER_ATOMIC_RELAXED_MB \
		: [ret] "=&r" (__ret) \
		: [var] "r" (&(_var)), [val] "r" ((u64) (_val)) \
		: "memory"); \
	HWBUG_ATOMIC_END(); \
	__ret; \
})

# define __arch_pcpu_atomic_cmpxchg(_old, _new, _var, size, sxt_size) \
({ \
	typeof(_var) __ret, __stored_val; \
	HWBUG_ATOMIC_BEGIN(__my_cpu_offset + &(_var)); \
	asm NOT_VOLATILE ( \
		MB_BEFORE_ATOMIC_RELAXED_MB \
		"\n3:" \
		"\n{" \
		"\nnop 4" \
		"\nld" size ",0 %%dg" __stringify(MY_CPU_OFFSET_GREG) ", %[var], %[ret], mas=0x7" \
		"\n}" \
		"\n{" \
		"\nsxt "#sxt_size", %[ret], %[ret]" \
		"\naddd 0x0, %[new], %[stored_val]" \
		"\n}" \
		"\n{" \
		"\nnop 1" \
		"\ncmpedb %[ret], %[old], %%pred2" \
		"\n}" \
		"\n{" \
		"\nnop 1" /* bug 92891 - optimize for performance */ \
		"\naddd 0x0, %[ret], %[stored_val] ? ~ %%pred2" \
		"\n}" \
		"\n{" \
		"\nst" size "," RELAXED_MB_ATOMIC_CHANNEL " \
			%%dg" __stringify(MY_CPU_OFFSET_GREG) ", %[var], %[stored_val], mas=" RELAXED_MB_ATOMIC_MAS \
		"\nibranch 3b ? %%MLOCK" \
		"\n}" \
		MB_AFTER_ATOMIC_RELAXED_MB \
		: [ret] "=&r" (__ret), [stored_val] "=&r" (__stored_val) \
		: [var] "r" (&(_var)), [new] "ir" (_new), [old] "ir" (_old) \
		: "memory", "pred2"); \
	HWBUG_ATOMIC_END(); \
	__ret; \
})

# define __arch_pcpu_atomic_cmpxchg_word(_old, _new, _var) \
({ \
	typeof(_var) __ret, __stored_val; \
	HWBUG_ATOMIC_BEGIN(__my_cpu_offset + &(_var)); \
	asm NOT_VOLATILE ( \
		MB_BEFORE_ATOMIC_RELAXED_MB \
		"\n3:" \
		"\n{"\
		"\nnop 4"\
		"\nldw,0 %%dg" __stringify(MY_CPU_OFFSET_GREG) ", %[var], %[ret], mas=0x7" \
		"\n}" \
		"\n{" \
		"\nnop 1"\
		"\nadds 0x0, %[new], %[stored_val]" \
		"\ncmpesb %[ret], %[old], %%pred2" \
		"\n}" \
		"\n{" \
		"\nnop 2" /* bug 92891 - optimize for performance */ \
		"\nadds 0x0, %[ret], %[stored_val] ? ~ %%pred2" \
		"\n}" \
		"\n{" \
		"\nstw," RELAXED_MB_ATOMIC_CHANNEL " \
			%%dg" __stringify(MY_CPU_OFFSET_GREG) ", %[var], %[stored_val], mas=" RELAXED_MB_ATOMIC_MAS \
		"\nibranch 3b ? %%MLOCK" \
		"\n}" \
		MB_AFTER_ATOMIC_RELAXED_MB \
		: [ret] "=&r" (__ret), [stored_val] "=&r" (__stored_val) \
		: [var] "r" (&(_var)), [new] "ir" (_new), [old] "ir" (_old) \
		: "memory", "pred2"); \
	HWBUG_ATOMIC_END(); \
	__ret; \
})

# define __arch_pcpu_atomic_cmpxchg_dword(_old, _new, _var) \
({ \
	typeof(_var) __ret, __stored_val; \
	HWBUG_ATOMIC_BEGIN(__my_cpu_offset + &(_var)); \
	asm NOT_VOLATILE ( \
		MB_BEFORE_ATOMIC_RELAXED_MB \
		"\n3:" \
		"\n{"\
		"\nnop 4"\
		"\nldd,0 %%dg" __stringify(MY_CPU_OFFSET_GREG) ", %[var], %[ret], mas=0x7" \
		"\n}" \
		"\n{" \
		"\nnop 1"\
		"\naddd 0x0, %[new], %[stored_val]" \
		"\ncmpedb %[ret], %[old], %%pred2" \
		"\n}" \
		"\n{" \
		"\nnop 2" /* bug 92891 - optimize for performance */ \
		"\naddd 0x0, %[ret], %[stored_val] ? ~ %%pred2" \
		"\n}" \
		"\n{" \
		"\nstd," RELAXED_MB_ATOMIC_CHANNEL " \
			%%dg" __stringify(MY_CPU_OFFSET_GREG) ", %[var], %[stored_val], mas=" RELAXED_MB_ATOMIC_MAS \
		"\nibranch 3b ? %%MLOCK" \
		"\n}" \
		MB_AFTER_ATOMIC_RELAXED_MB \
		: [ret] "=&r" (__ret), [stored_val] "=&r" (__stored_val) \
		: [var] "r" (&(_var)), [new] "ir" ((u64) (_new)), [old] "ir" ((u64) (_old)) \
		: "memory", "pred2"); \
	HWBUG_ATOMIC_END(); \
	__ret; \
})

#define __arch_pcpu_atomic_op(_val, _var, size, op) \
({ \
	typeof(_var) __ret; \
	HWBUG_ATOMIC_BEGIN(__my_cpu_offset + &(_var)); \
	asm NOT_VOLATILE ( \
		MB_BEFORE_ATOMIC_RELAXED_MB \
		"\n1:" \
		"\n{"\
		"\nnop 4"\
		"\nld" size ",0 %%dg" __stringify(MY_CPU_OFFSET_GREG) ", %[var], %[ret], mas=0x7" \
		"\n}" \
		"\n" op " %[ret], %[val], %[ret]" \
		"\n{"\
		"\nst" size "," RELAXED_MB_ATOMIC_CHANNEL " \
			%%dg" __stringify(MY_CPU_OFFSET_GREG) ", %[var], %[ret], mas=" RELAXED_MB_ATOMIC_MAS \
		"\nibranch 1b ? %%MLOCK" \
		"\n}" \
		MB_AFTER_ATOMIC_RELAXED_MB \
		: [ret] "=&r" (__ret) \
		: [var] "r" (&(_var)), [val] "ir" ((u64) (_val)) \
		: "memory"); \
	HWBUG_ATOMIC_END(); \
	__ret; \
})

#endif /* #ifndef CONFIG_CPU_ES2 */

/* Disable %aalda writes on iset v6 (iset correction v6.107).
 * Use alternatives since we cannot do jumps at this point
 * (%ctpr's have been restored already). */
#define NATIVE_SET_ALL_AALDAS(aaldas_p) \
do { \
	u32 *aaldas = (u32 *)(aaldas_p); \
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

/* Force load OSGD->GD */
#define E2K_LOAD_OSGD_TO_GD() \
do { \
	asm volatile ("{nop; sdisp %%ctpr2, 11}\n" \
		      "{call %%ctpr2, wbs=%#}\n" \
		      ::: "call"); \
} while (0)
#endif /* __ASSEMBLY__ */

#endif /* _E2K_API_H_ */
