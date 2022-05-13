/*
 * include/asm-e2k/stack.h
 *
 * Copyright 2004 Salavat S. Guiliazov (atic@mcst.ru)
 */

#ifndef _E2K_STACKS_H
#define _E2K_STACKS_H

#include <linux/types.h>
#include <asm/kvm/stacks.h>	/* virtualization support */

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
#define	USER_TAG_MEM_BASE		\
		(TASK_SIZE - USER_VPTB_BASE_SIZE - USER_TAG_MEM_SIZE)

/*
 * User's high address below tags memory space is reserved for CUT.
 */

#define	USER_CUT_AREA_SIZE		(PAGE_SIZE)
#define	USER_CUT_AREA_BASE		(USER_TAG_MEM_BASE - USER_CUT_AREA_SIZE)

#ifndef __ASSEMBLY__
/*
 * The structure define state of all e2k stacks:
 * hardware pointers and registers
 */

typedef struct e2k_stacks {
#ifdef CONFIG_KVM_HOST_MODE
	/* gthread_info uses these fields */
	e2k_addr_t	u_top;
	e2k_usd_lo_t	u_usd_lo;
	e2k_usd_hi_t	u_usd_hi;
#endif
	e2k_addr_t	top;		/* top address (same as SBR pointer) */
	e2k_usd_lo_t	usd_lo;		/* curent state of stack pointer */
	e2k_usd_hi_t	usd_hi;		/* register: base & size */
	e2k_psp_lo_t	psp_lo;		/* Procedure stack pointer: */
	e2k_psp_hi_t	psp_hi;		/* base & index & size */
	e2k_pcsp_lo_t	pcsp_lo;	/* Procedure chain stack */
	e2k_pcsp_hi_t	pcsp_hi;	/* pointer: base & index & size */
	/* %px[c]sp.ind in this structure holds includes %px[c]shtp part,
	 * and saved %px[c]shtp values show how much of user stack has
	 * been SPILLed to kernel. This is done for convenience - add
	 * %px[c]shtp just once instead of pretty much always. */
	e2k_pshtp_t	pshtp;
	e2k_pcshtp_t	pcshtp;
} e2k_stacks_t;

typedef struct data_stack {
	e2k_addr_t	bottom;		/* data stack bottom */
	e2k_size_t	size;		/* data stack size */
	e2k_addr_t	top;		/* Top of the stack (as SBR) */
} data_stack_t;

/*
 * Hardware stacks desription: procedure and chain stacks
 * Both stacks have resident part at current top of the stack to ensure
 * kernel function execution while trap and system calls handling
 */
typedef struct hw_stack_area {
	void		*base;		/* Hardware stack base pointer */
	e2k_size_t	size;		/* Hardware stack total size */
} hw_stack_area_t;

typedef struct hw_stack {
	hw_stack_area_t	ps;		/* Current procedure stack area */
	hw_stack_area_t	pcs;		/* Current chain stack area */
} hw_stack_t;

typedef struct old_pcs_area {
	void	*base;			/* Hardware stack base pointer */
	long	size;			/* Hardware stack total size */
	struct	list_head list_entry;
} old_pcs_area_t;

#define GET_PS_BASE(hw_stacks)		((hw_stacks)->ps.base)
#define GET_PCS_BASE(hw_stacks)		((hw_stacks)->pcs.base)

#define CURRENT_PS_BASE()	(current_thread_info()->u_hw_stack.ps.base)
#define CURRENT_PCS_BASE()	(current_thread_info()->u_hw_stack.pcs.base)

#define SET_PS_BASE(hw_stacks, val)	(GET_PS_BASE(hw_stacks) = (val))
#define SET_PCS_BASE(hw_stacks, val)	(GET_PCS_BASE(hw_stacks) = (val))

#endif	/* ! __ASSEMBLY__ */

/*
 * Data and hardware user stacks descriptions.
 */
#define	USER_P_STACKS_MAX_SIZE	E2K_ALL_STACKS_MAX_SIZE	/* 128 Gbytes */
#define	USER_PC_STACKS_MAX_SIZE	USER_P_STACKS_MAX_SIZE

#define _min_(a, b)	((a) < (b) ? (a) : (b))
#define	USER_P_STACKS_BASE	(USER_CUT_AREA_BASE - USER_P_STACKS_MAX_SIZE)
#define	USER_PC_STACKS_BASE	USER_P_STACKS_BASE
#define USER_HW_STACKS_BASE	_min_(USER_P_STACKS_BASE, USER_PC_STACKS_BASE)

#define	USER_P_STACK_INIT_SIZE	(4 * PAGE_SIZE)
#define	USER_PC_STACK_INIT_SIZE	PAGE_SIZE

#define USER_C_STACK_BYTE_INCR	(4 * PAGE_SIZE)
/* Software user stack for 64-bit mode. */
#define	USER64_STACK_TOP	USER_PC_STACKS_BASE
/* Software user stack for 32-bit mode. */
#define	USER32_STACK_TOP	TASK32_SIZE

/*
 * This macro definition is to limit deafault user stack size
 * (see asm/resource.h)
 */
#define	E2K_STK_LIM		USER64_MAIN_C_STACK_SIZE

/*
 * Kernel stack ((software & hardware) descriptions
 */
#define K_DATA_GAP_SIZE		E2K_ALIGN_STACK
#define	KERNEL_C_STACK_SIZE	(5 * PAGE_SIZE - K_DATA_GAP_SIZE)

/* Maybe implement do_softirq_own_stack() and reduce this to 7 pages
 * Having separate stack for hardware interrupts IRQ handling will allow to
 * reduce this further - prbly to ~4 pages. */
#define	KERNEL_P_STACK_SIZE	(9 * PAGE_SIZE)
#define NATIVE_KERNEL_P_STACK_PAGES (KERNEL_P_STACK_SIZE / PAGE_SIZE)

#define	KERNEL_PC_STACK_SIZE \
		(2 * PAGE_SIZE) /* 8 Kbytes (256 functions calls) */
#define NATIVE_KERNEL_PC_STACK_PAGES	(KERNEL_PC_STACK_SIZE / PAGE_SIZE)

#define MAX_KERNEL_P_STACK_PAGES \
		(NATIVE_KERNEL_P_STACK_PAGES + VIRT_KERNEL_P_STACK_PAGES)
#define MAX_KERNEL_PC_STACK_PAGES \
		(NATIVE_KERNEL_PC_STACK_PAGES + VIRT_KERNEL_PC_STACK_PAGES)
#define MAX_KERNEL_HW_STACK_PAGES \
		(MAX_KERNEL_P_STACK_PAGES + MAX_KERNEL_PC_STACK_PAGES)

/*
 * 3 kernel stacks are allocated together and lie in memory
 * in the following order:
 *
 *   ------------------------------------------------------------------> higher
 *   K_DATA_GAP_SIZE | DATA | PROCEDURE | PAGE_SIZE | CHAIN | PAGE_SIZE
 *
 * Two unused pages are needed to properly handle hardware
 * stack overflow: on overflow PSR.sge checking is disabled
 * and stack will be spilled after its own boundary and then
 * kernel_hw_stack_fatal_error() will print full stack.
 *
 * Arch-independent part expects data stack to be the first
 * one (see end_of_stack()), that's also the reason to skip
 * the first E2K_ALIGN_STACK bytes to keep the magic value
 * intact.
 */
#define KERNEL_STACKS_SIZE (K_DATA_GAP_SIZE + KERNEL_C_STACK_SIZE + \
		KERNEL_P_STACK_SIZE + KERNEL_PC_STACK_SIZE + 2 * PAGE_SIZE)
#define KERNEL_C_STACK_OFFSET	K_DATA_GAP_SIZE
#define KERNEL_P_STACK_OFFSET	(KERNEL_C_STACK_OFFSET + KERNEL_C_STACK_SIZE)
#define KERNEL_PC_STACK_OFFSET	(KERNEL_P_STACK_OFFSET + \
				 KERNEL_P_STACK_SIZE + PAGE_SIZE)

#endif /* _E2K_STACKS_H */

