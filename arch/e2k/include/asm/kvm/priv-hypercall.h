/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * KVM host <-> guest Linux-specific hypervisor handling.
 */

#ifndef _ASM_E2K_PRIV_HYPERCALL_H
#define _ASM_E2K_PRIV_HYPERCALL_H

#include <linux/types.h>
#include <linux/kvm_types.h>
#include <linux/errno.h>

#include <asm/e2k_api.h>
#include <asm/cpu_regs_types.h>
#include <asm/trap_def.h>

static inline unsigned long priv_hypercall(unsigned long nr,
				unsigned long arg1, unsigned long arg2,
				unsigned long arg3, unsigned long arg4,
				unsigned long arg5, unsigned long arg6,
				unsigned long arg7)
{
	unsigned long ret;

	ret = E2K_SYSCALL(PRIV_HYPERCALL_TRAPNUM, nr, 7,
			arg1, arg2, arg3, arg4, arg5, arg6, arg7);

	return ret;
}
static inline unsigned long priv_hypercall0(unsigned long nr)
{
	return priv_hypercall(nr, 0, 0, 0, 0, 0, 0, 0);
}

static inline unsigned long priv_hypercall1(unsigned long nr,
				unsigned long arg1)
{
	return priv_hypercall(nr, arg1, 0, 0, 0, 0, 0, 0);
}

static inline unsigned long priv_hypercall2(unsigned long nr,
				unsigned long arg1, unsigned long arg2)
{
	return priv_hypercall(nr, arg1, arg2, 0, 0, 0, 0, 0);
}

static inline unsigned long priv_hypercall3(unsigned long nr,
				unsigned long arg1, unsigned long arg2,
				unsigned long arg3)
{
	return priv_hypercall(nr, arg1, arg2, arg3, 0, 0, 0, 0);
}

static inline unsigned long priv_hypercall4(unsigned long nr,
				unsigned long arg1, unsigned long arg2,
				unsigned long arg3, unsigned long arg4)
{
	return priv_hypercall(nr, arg1, arg2, arg3, arg4, 0, 0, 0);
}

static inline unsigned long priv_hypercall5(unsigned long nr,
				unsigned long arg1, unsigned long arg2,
				unsigned long arg3, unsigned long arg4,
				unsigned long arg5)
{
	return priv_hypercall(nr, arg1, arg2, arg3, arg4, arg5, 0, 0);
}

static inline unsigned long priv_hypercall6(unsigned long nr,
				unsigned long arg1, unsigned long arg2,
				unsigned long arg3, unsigned long arg4,
				unsigned long arg5, unsigned long arg6)
{
	return priv_hypercall(nr, arg1, arg2, arg3, arg4, arg5, arg6, 0);
}

static inline unsigned long priv_hypercall7(unsigned long nr,
				unsigned long arg1, unsigned long arg2,
				unsigned long arg3, unsigned long arg4,
				unsigned long arg5, unsigned long arg6,
				unsigned long arg7)
{
	return priv_hypercall(nr, arg1, arg2, arg3, arg4, arg5, arg6, arg7);
}

/*
 * KVM hypervisor (host) <-> guest privileged actions hypercalls list
 */
#define	KVM_PRIV_HCALL_FAST_TAGGED_MEMORY_COPY	1	/* fast tagged memory copy */
#define	KVM_PRIV_HCALL_FAST_TAGGED_MEMORY_SET	2	/* fast tagged memory set */
#define	KVM_PRIV_HCALL_FAST_TAGGED_MEMORY_COPY_USER 3	/* fast tagged memory copy */
							/* to/from user */
#define	KVM_PRIV_HCALL_FAST_TAGGED_MEMORY_SET_USER  4	/* fast tagged memory set */
							/* at user */
#define KVM_PRIV_HCALL_RETURN_FROM_FAST_SYSCALL	5
#define	KVM_PRIV_HCALL_SWITCH_RETURN_IP		8	/* switch current return */
							/* IP to return to other */
							/* kernel guest function */
#define	KVM_PRIV_HCALL_RECOVERY_FAULTED_STORE	10	/* recovery faulted store */
							/* tagged value operations */
#define	KVM_PRIV_HCALL_RECOVERY_FAULTED_LOAD	11	/* recovery faulted load */
							/* value and tag */
#define	KVM_PRIV_HCALL_RECOVERY_FAULTED_MOVE	12	/* recovery faulted move */
							/* value and tag to register */
							/* into procedure stack */
#define	KVM_PRIV_HCALL_RECOVERY_FAULTED_LOAD_TO_GREG 13	/* recovery faulted load */
							/* value and tag to global */
							/* register */

#ifdef	CONFIG_PRIV_HYPERCALLS
static inline unsigned long
HYPERVISOR_priv_tagged_memory_copy(void *dst, const void *src, size_t len,
			unsigned long strd_opcode, unsigned long ldrd_opcode,
			int prefetch)
{
	return priv_hypercall6(KVM_PRIV_HCALL_FAST_TAGGED_MEMORY_COPY,
			(unsigned long)dst, (unsigned long)src,
			len, strd_opcode, ldrd_opcode, prefetch);
}
static inline unsigned long
HYPERVISOR_priv_tagged_memory_set(void *addr, u64 val, u64 tag, size_t len,
					 u64 strd_opcode)
{
	return priv_hypercall5(KVM_PRIV_HCALL_FAST_TAGGED_MEMORY_SET,
			(unsigned long)addr, val, tag, len, strd_opcode);
}
static inline unsigned long
HYPERVISOR_priv_tagged_memory_copy_user(void *dst, const void *src,
			size_t len, size_t *copiedp,
			unsigned long strd_opcode, unsigned long ldrd_opcode,
			int prefetch)
{
	return priv_hypercall6(KVM_PRIV_HCALL_FAST_TAGGED_MEMORY_COPY_USER,
			(unsigned long)dst, (unsigned long)src,
			len, strd_opcode, ldrd_opcode, prefetch);
}
static inline unsigned long
HYPERVISOR_priv_tagged_memory_set_user(void *addr, u64 val, u64 tag,
					size_t len, size_t *clearedp,
					u64 strd_opcode)
{
	return priv_hypercall5(KVM_PRIV_HCALL_FAST_TAGGED_MEMORY_SET_USER,
			(unsigned long)addr, val, tag, len, strd_opcode);
}

static inline unsigned long
HYPERVISOR_priv_return_from_fast_syscall(long ret_val)
{
	return priv_hypercall1(KVM_PRIV_HCALL_RETURN_FROM_FAST_SYSCALL, ret_val);
}

static inline unsigned long
HYPERVISOR_priv_switch_retutn_ip(unsigned long new_ip)
{
	return priv_hypercall1(KVM_PRIV_HCALL_SWITCH_RETURN_IP, new_ip);
}

static inline long
HYPERVISOR_priv_recovery_faulted_store(e2k_addr_t addr, u64 wr_data,
			u64 st_rec_opc, u64 data_ext, u64 opc_ext,
			recovery_faulted_arg_t args)
{
	return priv_hypercall6(KVM_PRIV_HCALL_RECOVERY_FAULTED_STORE,
			addr, wr_data, st_rec_opc, data_ext, opc_ext,
			args.entire);
}
static inline long
HYPERVISOR_priv_recovery_faulted_load(e2k_addr_t addr, u64 *ld_val, u8 *data_tag,
				      u64 ld_rec_opc, int chan)
{
	return priv_hypercall5(KVM_PRIV_HCALL_RECOVERY_FAULTED_LOAD,
			addr, (unsigned long)ld_val, (unsigned long)data_tag,
			ld_rec_opc, chan);
}
static inline long
HYPERVISOR_priv_recovery_faulted_move(e2k_addr_t addr_from, e2k_addr_t addr_to,
		e2k_addr_t addr_to_hi, u64 ld_rec_opc,
		recovery_faulted_arg_t args, u32 first_time)
{
	return priv_hypercall6(KVM_PRIV_HCALL_RECOVERY_FAULTED_MOVE,
			addr_from, addr_to, addr_to_hi, ld_rec_opc,
			args.entire, first_time);
}
static inline long
HYPERVISOR_priv_recovery_faulted_load_to_greg(e2k_addr_t addr, u32 greg_num_d,
		u64 ld_rec_opc, recovery_faulted_arg_t args,
		u64 *saved_greg_lo, u64 *saved_greg_hi)
{
	return priv_hypercall6(KVM_PRIV_HCALL_RECOVERY_FAULTED_LOAD_TO_GREG,
			addr, (u64)greg_num_d, ld_rec_opc, args.entire,
			(unsigned long)saved_greg_lo, (unsigned long)saved_greg_hi);
}


#else	/* !CONFIG_PRIV_HYPERCALLS */

#include <asm/kvm/hypercall.h>

static inline unsigned long
HYPERVISOR_priv_tagged_memory_copy(void *dst, const void *src, size_t len,
			unsigned long strd_opcode, unsigned long ldrd_opcode,
			int prefetch)
{
	return HYPERVISOR_fast_kernel_tagged_memory_copy(dst, src, len,
					strd_opcode, ldrd_opcode, prefetch);
}
static inline unsigned long
HYPERVISOR_priv_tagged_memory_set(void *addr, u64 val, u64 tag, size_t len,
					 u64 strd_opcode)
{
	return HYPERVISOR_fast_kernel_tagged_memory_set(addr, val, tag, len,
							strd_opcode);
}
static inline unsigned long
HYPERVISOR_priv_tagged_memory_copy_user(void *dst, const void *src,
			size_t len, size_t *copied,
			unsigned long strd_opcode, unsigned long ldrd_opcode,
			int prefetch)
{
	return HYPERVISOR_fast_tagged_memory_copy_user(dst, src, len, copied,
					strd_opcode, ldrd_opcode, prefetch);
}
static inline unsigned long
HYPERVISOR_priv_tagged_memory_set_user(void *addr, u64 val, u64 tag,
					size_t len, size_t *cleared,
					u64 strd_opcode)
{
	return HYPERVISOR_fast_tagged_memory_set_user(addr, val, tag, len, cleared,
							strd_opcode);
}

static inline long
HYPERVISOR_priv_recovery_faulted_store(e2k_addr_t address, u64 wr_data,
			u64 st_rec_opc, u64 data_ext, u64 opc_ext,
			recovery_faulted_arg_t args)
{
	return HYPERVISOR_recovery_faulted_tagged_store(address, wr_data,
			st_rec_opc, data_ext, opc_ext, args);
}
static inline long
HYPERVISOR_priv_recovery_faulted_load(e2k_addr_t addr, u64 *ld_val, u8 *data_tag,
				      u64 ld_rec_opc, int chan)
{
	return HYPERVISOR_recovery_faulted_load(addr, ld_val, data_tag,
						ld_rec_opc, chan);
}
static inline long
HYPERVISOR_priv_recovery_faulted_move(e2k_addr_t addr_from, e2k_addr_t addr_to,
		e2k_addr_t addr_to_hi, u64 ld_rec_opc,
		recovery_faulted_arg_t args, u32 first_time)
{
	return HYPERVISOR_recovery_faulted_move(addr_from, addr_to, addr_to_hi,
				args.vr, ld_rec_opc, args.chan, args.qp,
				args.atomic, first_time);
}
static inline long
HYPERVISOR_priv_recovery_faulted_load_to_greg(e2k_addr_t addr, u32 greg_num_d,
		u64 ld_rec_opc, recovery_faulted_arg_t args,
		u64 *saved_greg_lo, u64 *saved_greg_hi)
{
	return HYPERVISOR_recovery_faulted_load_to_greg(addr, greg_num_d,
			args.vr, ld_rec_opc, args.chan, args.qp, args.atomic,
			saved_greg_lo, saved_greg_hi);
}

#endif	/* CONFIG_PRIV_HYPERCALLS */

#endif /* _ASM_E2K_PRIV_HYPERCALL_H */
