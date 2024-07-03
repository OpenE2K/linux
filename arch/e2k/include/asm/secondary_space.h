/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Secondary space support for E2K binary compiler
 * asm/secondary_space.h
 */
#ifndef _SECONDARY_SPACE_H
#define	_SECONDARY_SPACE_H

#ifndef __ASSEMBLY__
#include <linux/spinlock.h>

#include <asm/machdep.h>
#include <asm/page.h>
#include <asm/processor.h>
#include <asm/types.h>
#include <asm/smp.h>
#endif /* !__ASSEMBLY__ */

#define BINCO_PROTOCOL_VERSION	5

#define SS_SIZE	0x800000000000UL

#define NATIVE_SS_ADDR_START \
		((machine.native_iset_ver >= E2K_ISET_V6 && \
			READ_CU_HW0_REG().upt_sec_ad_shift_dsbl) ? 0x0L : 0x400000000000L)

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is virtualized guest kernel */
#include <asm/kvm/guest/secondary_space.h>
#else	/* !CONFIG_KVM_GUEST_KERNEL */
/* it is native kernel without any virtualization or host kernel with virtualization support */
#define SS_ADDR_START	NATIVE_SS_ADDR_START
#endif	/* CONFIG_KVM_GUEST_KERNEL */

/*
 * If updating this value - do not forget to update E2K_ARG3_MASK -
 * mask for 63-45 bits and PAGE_OFFSET.
 */
#define SS_ADDR_END		(SS_ADDR_START + SS_SIZE)

#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
#define ADDR_IN_SS(a)		((a >= SS_ADDR_START) && (a < SS_ADDR_END))
#else
#define ADDR_IN_SS(a)		0
#endif

#define	DEBUG_SS_MODE		0	/* Secondary Space Debug */
#define DebugSS(...)		DebugPrint(DEBUG_SS_MODE, ##__VA_ARGS__)

#ifndef __ASSEMBLY__

extern long sys_el_binary(s64 work, s64 arg2, s64 arg3, s64 arg4);

/*
 * Intreface of el_binary() syscall
 * Work argument(arg1) values:
 */
#define GET_SECONDARY_SPACE_OFFSET	0
#define SET_SECONDARY_REMAP_BOUND	1
#define SET_SECONDARY_DESCRIPTOR	2
#define SET_SECONDARY_MTRR_DEPRECATED	3
#define GET_SECONDARY_MTRR_DEPRECATED	4
#define GET_SNXE_USAGE			5
#define TGKILL_INFO_DEPRECATED		6
#define SIG_EXIT_GROUP			7
#define FLUSH_CMD_CACHES_DEPRECATED	8
#define SET_SC_RSTRT_IGNORE_DEPRECATED	9
#define SET_RP_BOUNDS_AND_IP		10
#define SET_SECONDARY_64BIT_MODE	11
#define GET_PROTOCOL_VERSION		12
#define SET_IC_NEED_FLUSH_ON_SWITCH	13
#define GET_UPT_SEC_AD_SHIFT_DSBL	14
#define SET_UPT_SEC_AD_SHIFT_DSBL	15
#define SET_BIN_COMP_INFO		16
#define GET_BIN_COMP_INFO		17
#define SET_RLIM			18
#define GET_RLIM			19
#define SET_BIN_COMP_FD			20
#define BIN_COMP_FD_WRITE		21
#define IS_BIN_COMP_FD_SET		22
#define SET_BIN_COMP_SEARCH_PATH	23
#define SET_CHILD_IS_SERVING_THREAD	24
#define GET_OUTMOST_NS_TID		25
#define SEND_SIGNAL_TO_OUTMOST_TID	26
#define CLOSE_BIN_COMP_FD		27

/* Selector numbers for GET_SECONDARY_SPACE_OFFSET */
enum sel_num {
	CS_SELECTOR		= 0,
	DS_SELECTOR		= 1,
	ES_SELECTOR		= 2,
	SS_SELECTOR		= 3,
	FS_SELECTOR		= 4,
	GS_SELECTOR		= 5,
};

#define E2K_ARG3_MASK	(0xffffe000ffffffffLL)
#define I32_ADDR_TO_E2K(arg)				\
({							\
	s64 argm;					\
	argm = arg;					\
	if (machine.native_iset_ver < E2K_ISET_V3) {	\
		argm &= E2K_ARG3_MASK;			\
		argm |= SS_ADDR_START;			\
	}						\
	argm;						\
})

#define BIN_COMP_INFO_MAX_VERSION	0
struct bincomp_info_header_v0 {
	u64	version;
	u64	args_offsets_offset;
};

union bincomp_info_header {
	struct bincomp_info_header_v0 v0;
};

#define BIN_COMP_FD_TABLE_SIZE	6
struct pid_namespace;

typedef struct bin_comp_info {
	struct file		*exe_file;
	struct file		*rtc32;
	struct file		*rtc64;
	struct pid_namespace    *startx86_pid_ns;
	struct file		**fd_table;
	void			*info;
	e2k_size_t		info_size;
	rwlock_t		lock;
} bin_comp_info_t;

extern void free_bin_comp_info(bin_comp_info_t *bi);
extern int copy_bin_comp_info(bin_comp_info_t *oldbi, bin_comp_info_t *bi);

#define BC_RLIMIT_X86_DATA	0
#define BC_RLIMIT_X86_STACK	1
#define BC_RLIMIT_X86_AS	2
#define BINCOMP_RLIM_NLIMITS	3

extern int bc_set_outmost_ns(struct task_struct *t, u64 clone_flags);
extern int bc_set_outmost_parent(struct task_struct *t);

#endif /* !__ASSEMBLY__ */
#endif /* _SECONDARY_SPACE_H */
