/*
 * include/asm-e2k/stack.h
 *
 * Copyright 2004 Salavat S. Guiliazov (atic@mcst.ru)
 */

#ifndef _E2K_STACKS_H
#define _E2K_STACKS_H

#include <asm/types.h>

struct hw_stack_area {
	void *base;			/* Hardware stack base pointer */
	long size;			/* Hardware stack total size */
	long offset;			/* Current offset of present part */
					/* of hardware stack */
	long top;			/* Current top of present part */
					/* of hardware stack */
	struct list_head list_entry;	/* Hardware stack areas list entry */
};

/*
 * User's high address space is reserved for tag memory mapping.
 * Tags of all user virtual pages are mapped to user virtual space
 * To each quad-word of data (16 bytes) corresponds 1 byte of tag
 * Virtual pages of tags live at the end of virtual user space
 *
 * 0x0000 0000 0000 1000 - 0x0000 0100 0000 0000 All user virtula space from
 *						 'text' start to 'TASK_SIZE'
 * 0x0000 00f0 0000 0000 - 0x0000 00ff ffff ffff Tags memory virtual space
 */
#define	USER_TAG_MEM_SIZE		(TASK_SIZE / 16)	/* 1/16 of */
								/* total user */
								/* memory */
								/* size */
#define	USER_TAG_MEM_BASE		(TASK_SIZE - USER_TAG_MEM_SIZE)

/*
 * User's high address below tags memory space is reserved for CUT.
 */

#define	USER_CUT_AREA_SIZE		(PAGE_SIZE)
#define	USER_CUT_AREA_BASE		(USER_TAG_MEM_BASE - USER_CUT_AREA_SIZE)

/*
 * Hardware user stacks descriptions.
 */
 
#if defined(CONFIG_E2K_MACHINE) && !defined(CONFIG_CPU_E3M)
# define E2K_MAX_PCSP_SIZE	PAGE_ALIGN_UP(0xffffffffUL)
#else

# if defined(CONFIG_E3M_CPU_VERSION_2)
/* bug of cpu version 2 limits chain stack size (PCSP_hi.size) by 2 pages */
#  define E2K_MAX_PCSP_SIZE	(2 * PAGE_SIZE)
# elif defined(CONFIG_E3M_CPU_VERSION_3)
/* bug of cpu version 3 limits chain stack size (PCSP_hi.size) by 8 pages */
#  define E2K_MAX_PCSP_SIZE	(8 * PAGE_SIZE)
# elif defined(CONFIG_E3M_CPU_VERSION_4)
/* cpu version 4 and greater we hope will not limit chain stack size */
#  define E2K_MAX_PCSP_SIZE	PAGE_ALIGN_UP(0xffffffffUL)
# else
#  error "E2K CPU version does not defined"
# endif

#endif

#define	USER_P_STACKS_MAX_SIZE	(E2K_ALL_STACKS_MAX_SIZE / 1)	/* 128 Gbytes */
#define	USER_P_STACKS_BASE	(USER_CUT_AREA_BASE - USER_P_STACKS_MAX_SIZE)

#ifdef	CONFIG_SET_STACKS_SIZE
#define USER_P_STACK_SIZE		PAGE_ALIGN_DOWN((CONFIG_PSP_STACK_SIZE) * 1024 * 1024U)
#define	USER_P_STACK_INIT_SIZE		PAGE_ALIGN_DOWN(CONFIG_PSP_WIN_SIZE * PAGE_SIZE)
#define	USER_P_STACK_PRESENT_SIZE	PAGE_ALIGN_DOWN(CONFIG_PSP_WIN_SIZE * PAGE_SIZE)
#define	USER_P_STACK_AREA_SIZE		PAGE_ALIGN_DOWN(CONFIG_UPS_AREA_SIZE * PAGE_SIZE)
#define	USER_P_STACK_BYTE_INCR		PAGE_ALIGN_DOWN((CONFIG_PSP_WIN_SIZE / 2) * PAGE_SIZE)
#define	USER_P_STACK_BYTE_DECR		PAGE_ALIGN_DOWN((CONFIG_PSP_WIN_SIZE / 2) * PAGE_SIZE)
#else	/* !CONFIG_SET_STACKS_SIZE */
#define USER_P_STACK_SIZE		PAGE_ALIGN_DOWN(128 * 1024 * 1024U)	/* 128 MBytes */
#define	USER_P_STACK_INIT_SIZE		PAGE_ALIGN_DOWN(8 * PAGE_SIZE)
#define	USER_P_STACK_PRESENT_SIZE	PAGE_ALIGN_DOWN(8 * PAGE_SIZE)
#define	USER_P_STACK_AREA_SIZE		PAGE_ALIGN_DOWN(18 * PAGE_SIZE)
#define	USER_P_STACK_BYTE_INCR		PAGE_ALIGN_DOWN((8 / 2) * PAGE_SIZE)
#define	USER_P_STACK_BYTE_DECR		PAGE_ALIGN_DOWN((8 / 2) * PAGE_SIZE)
#endif	/* CONFIG_SET_STACKS_SIZE */

#define	USER_PC_STACKS_MAX_SIZE		USER_P_STACKS_MAX_SIZE
#define	USER_PC_STACKS_BASE		USER_P_STACKS_BASE
#define USER_PC_STACK_SIZE		PAGE_ALIGN_DOWN(USER_P_STACK_SIZE / 16)

#define USER_HW_STACKS_BASE	min(USER_P_STACKS_BASE, USER_PC_STACKS_BASE)

#ifdef CONFIG_SET_STACKS_SIZE
#define	USER_PC_STACK_AREA_SIZE		(CONFIG_UPCS_AREA_SIZE * PAGE_SIZE)
#else	/* !CONFIG_SET_STACKS_SIZE */
#define	USER_PC_STACK_AREA_SIZE		(4 * PAGE_SIZE)
#endif	/* CONFIG_SET_STACKS_SIZE */

#ifdef CONFIG_E3M_CPU_VERSION_2
/*
 * In the CPU version #2 max chain procedure stack size is only 2 pages
 * So we have to limit user stack by 1 page and kernel part 1 page
 */
#define	USER_PC_STACK_INIT_SIZE		(1 * PAGE_SIZE)
#define	USER_PC_STACK_PRESENT_SIZE	(0 * PAGE_SIZE)

#define	USER_PC_STACK_BYTE_INCR		PAGE_ALIGN_DOWN(USER_PC_STACK_INIT_SIZE)
#define	USER_PC_STACK_BYTE_DECR		PAGE_ALIGN_DOWN(USER_PC_STACK_INIT_SIZE)
#else	/* ! CONFIG_E3M_CPU_VERSION_2 */
#define	USER_PC_STACK_INIT_SIZE							\
		((PAGE_ALIGN_DOWN(USER_P_STACK_INIT_SIZE / 16) <=		\
							E2K_MAX_PCSP_SIZE) ?	\
			(PAGE_ALIGN_DOWN(USER_P_STACK_INIT_SIZE / 16))		\
			:							\
			(E2K_MAX_PCSP_SIZE))

#define	USER_PC_STACK_PRESENT_SIZE						\
		((PAGE_ALIGN_DOWN(USER_P_STACK_PRESENT_SIZE / 16) == 0) ?	\
			(USER_P_STACK_PRESENT_SIZE / 16)			\
			:							\
			((PAGE_ALIGN_DOWN(USER_P_STACK_PRESENT_SIZE / 16) <=	\
							E2K_MAX_PCSP_SIZE) ?	\
				(PAGE_ALIGN_DOWN(USER_P_STACK_PRESENT_SIZE / 	\
									16))	\
				:						\
				(E2K_MAX_PCSP_SIZE)))

#define	USER_PC_STACK_BYTE_INCR		PAGE_ALIGN_DOWN(USER_PC_STACK_INIT_SIZE / 2)
#define	USER_PC_STACK_BYTE_DECR		PAGE_ALIGN_DOWN(USER_PC_STACK_INIT_SIZE / 2)
#endif	/* CONFIG_E3M_CPU_VERSION_2 */

/*
 * Software user stack for 64-bit mode.
 */
#ifdef CONFIG_SET_STACKS_SIZE
# define USER64_MAIN_C_STACK_SIZE ((CONFIG_USER_STACK_SIZE) * 1024 * 1024U)
#else
# define USER64_MAIN_C_STACK_SIZE	(8 * 1024 * 1024U)	/* 8 MBytes */
#endif

#define USER64_MAIN_C_STACK_INIT_SIZE	(0 * PAGE_SIZE)		/* 0 KBytes */

#ifdef CONFIG_USER_STACK_INCR
# define USER64_C_STACK_BYTE_INCR	((CONFIG_USER_STACK_INCR) * PAGE_SIZE)
#else
# define USER64_C_STACK_BYTE_INCR	(4 * PAGE_SIZE)		/* 4 pages */
#endif

#define	USER64_STACK_TOP		(USER_PC_STACKS_BASE)

/*
 * Software user stack for 32-bit mode.
 */
#ifdef CONFIG_SET_STACKS_SIZE
# define USER32_MAIN_C_STACK_SIZE ((CONFIG_USER_STACK_SIZE) * 1024 * 1024U)
#else
# define USER32_MAIN_C_STACK_SIZE	(8 * 1024 * 1024U)	/* 8 MBytes */
#endif

#define	USER32_MAIN_C_STACK_INIT_SIZE	(0 * PAGE_SIZE)		/* 0 KBytes */

#ifdef CONFIG_USER_STACK_INCR
# define USER32_C_STACK_BYTE_INCR	((CONFIG_USER_STACK_INCR) * PAGE_SIZE)
#else
# define USER32_C_STACK_BYTE_INCR	(4 * PAGE_SIZE)		/* 4 pages */
#endif

#define	USER32_STACK_TOP		(TASK32_SIZE)

/*
 * These macro definitions are to unify 32- and 64-bit user stack
 * handling procedures.
 */

#define USER_MAIN_C_STACK_SIZE (current->thread.flags & E2K_FLAG_32BIT ? \
		USER32_MAIN_C_STACK_SIZE : USER64_MAIN_C_STACK_SIZE)

#define USER_MAIN_C_STACK_INIT_SIZE (current->thread.flags & E2K_FLAG_32BIT ? \
		USER32_MAIN_C_STACK_INIT_SIZE : USER64_MAIN_C_STACK_INIT_SIZE)

#define USER_C_STACK_BYTE_INCR (current->thread.flags & E2K_FLAG_32BIT ? \
		USER32_C_STACK_BYTE_INCR : USER64_C_STACK_BYTE_INCR)

/*
 * This macro definition is to limit deafault user stack size
 * (see asm/resource.h)
 */
#define	E2K_STK_LIM		USER64_MAIN_C_STACK_SIZE

/*
 * Kernel stack ((software & hardware) descriptions
 */
#define	KERNEL_C_STACK_SIZE	(8 * PAGE_SIZE)

#define	KERNEL_P_STACK_SIZE	(10 * PAGE_SIZE)
#define KERNEL_P_STACK_PAGES	(KERNEL_P_STACK_SIZE / PAGE_SIZE)

#define	KERNEL_PC_STACK_SIZE						\
		(((2 * PAGE_SIZE) < E2K_MAX_PCSP_SIZE) ?		\
		 (2 * PAGE_SIZE) : /* 8 Kbytes (256 functions calls) */ \
		 (E2K_MAX_PCSP_SIZE))
#define KERNEL_PC_STACK_PAGES	(KERNEL_PC_STACK_SIZE / PAGE_SIZE)

#define	GET_UP_PS_OFFSET_SIZE(cur_sz, cur_off, ps_sz, delta,		\
					 	new_sz, new_off)	\
({									\
	(new_sz) = (cur_sz) + (delta);					\
	(new_off) = (cur_off);						\
	if ((new_sz) + (cur_off) > (ps_sz)) {				\
		(new_sz) = (ps_sz) - (cur_off);				\
	}								\
	if (USER_P_STACK_PRESENT_SIZE != 0 &&				\
			(new_sz) > USER_P_STACK_PRESENT_SIZE) {		\
		(new_off) = (cur_off) + ((new_sz) -			\
					USER_P_STACK_PRESENT_SIZE);	\
		(new_sz) = USER_P_STACK_PRESENT_SIZE;			\
	}								\
})

#define	GET_DOWN_PS_OFFSET_SIZE(cur_sz, cur_off, delta,			\
						new_sz, new_off)	\
({									\
	(new_sz) = (cur_sz) - (delta);					\
	(new_off) = (cur_off) + (delta);				\
	if ((new_off) < 0) {						\
		(new_sz) += (new_off);					\
		(new_off) = 0;						\
	}								\
	if (USER_P_STACK_PRESENT_SIZE != 0 &&				\
			(new_sz) > USER_P_STACK_PRESENT_SIZE) {		\
		(new_sz) = USER_P_STACK_PRESENT_SIZE;			\
	}								\
})

#define	GET_UP_PCS_OFFSET_SIZE(cur_sz, cur_off, pcs_sz, delta,		\
					 new_k_sz, new_sz, new_off)	\
({									\
	(new_sz) = (cur_sz) + (delta);					\
	(new_off) = (cur_off);						\
	if ((new_sz) + (cur_off) > (pcs_sz)) {				\
		(new_sz) = (pcs_sz) - (cur_off);			\
	}								\
	if ((new_sz) + (new_k_sz) > E2K_MAX_PCSP_SIZE) {		\
		(new_off) = (cur_off) + ((new_sz) -			\
				(E2K_MAX_PCSP_SIZE - (new_k_sz)));	\
		(new_sz) = E2K_MAX_PCSP_SIZE - (new_k_sz);		\
	}								\
	if (USER_PC_STACK_PRESENT_SIZE != 0) {				\
		if ((new_sz) > USER_PC_STACK_PRESENT_SIZE) {		\
			(new_off) = (cur_off) + (new_sz) -		\
					USER_PC_STACK_PRESENT_SIZE;	\
			(new_sz) = USER_PC_STACK_PRESENT_SIZE;		\
		}							\
	}								\
})

#define	GET_DOWN_PCS_OFFSET_SIZE(cur_sz, cur_off, delta,		\
					 new_k_sz, new_sz, new_off)	\
({									\
	(new_sz) = (cur_sz) - (delta);					\
	(new_off) = (cur_off) + (delta);				\
	if ((new_off) < 0) {						\
		(new_sz) += (new_off);					\
		(new_off) = 0;						\
	}								\
	if ((new_sz) + (new_k_sz) > E2K_MAX_PCSP_SIZE) {		\
		(new_sz) = E2K_MAX_PCSP_SIZE - (new_k_sz);		\
	}								\
	if (USER_PC_STACK_PRESENT_SIZE != 0) {				\
		if ((new_sz) > USER_PC_STACK_PRESENT_SIZE) {		\
			(new_sz) = USER_PC_STACK_PRESENT_SIZE;		\
		}							\
	}								\
})

#endif /* _E2K_STACKS_H */

