/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _ASM_E2K_ATOMIC_API_H_
#define _ASM_E2K_ATOMIC_API_H_

#include <linux/types.h>

#include <asm/alternative.h>
#include <asm/e2k_api.h>
#include <asm/cpu_features.h>
#include <asm/native_dcache_regs_access.h>

#ifdef	__KERNEL__

#ifndef	__ASSEMBLY__

/*
 * Special page that is accessible for reading by every user
 * process is used for hardware bug #89242 workaround.
 */
#define NATIVE_HWBUG_WRITE_MEMORY_BARRIER_ADDRESS 0xff6000000000UL

#if !defined(CONFIG_BOOT_E2K) && !defined(E2K_P2V)

# define NATIVE_HWBUG_AFTER_LD_ACQ_ADDRESS	\
		NATIVE_HWBUG_WRITE_MEMORY_BARRIER_ADDRESS
# define NATIVE_HAS_HWBUG_AFTER_LD_ACQ_ADDRESS		\
		virt_cpu_has(CPU_HWBUG_WRITE_MEMORY_BARRIER)
# ifdef E2K_FAST_SYSCALL
#  define NATIVE_HWBUG_AFTER_LD_ACQ_CPU NATIVE_GET_DSREG_OPEN(clkr)
# else
#  ifndef __ASSEMBLY__
#   include <asm/glob_regs.h>
register unsigned long long __cpu_preempt_reg DO_ASM_GET_GREG_MEMONIC(SMP_CPU_ID_GREG);
#  endif
#  define NATIVE_HWBUG_AFTER_LD_ACQ_CPU ((unsigned int) __cpu_preempt_reg)
# endif

#elif defined(E2K_P2V)

# define NATIVE_HWBUG_AFTER_LD_ACQ_ADDRESS	\
		(NATIVE_GET_DSREG_OPEN(ip) & ~0x3fUL)
# define NATIVE_HWBUG_AFTER_LD_ACQ_CPU 0
# if !defined(CONFIG_E2K_MACHINE) || defined(CONFIG_E2K_E8C)
#  define NATIVE_HAS_HWBUG_AFTER_LD_ACQ_ADDRESS 1
# else
#  define NATIVE_HAS_HWBUG_AFTER_LD_ACQ_ADDRESS 0
# endif

#else /* CONFIG_BOOT_E2K */

# define NATIVE_HWBUG_AFTER_LD_ACQ_ADDRESS	\
		(NATIVE_GET_DSREG_OPEN(ip) & ~0x3fUL)
# define NATIVE_HAS_HWBUG_AFTER_LD_ACQ_ADDRESS 0
# define NATIVE_HWBUG_AFTER_LD_ACQ_CPU 0

#endif

#ifdef CONFIG_CPU_E8C
/* Define these here to avoid include hell... */
# define _UPSR_IE      0x20U
# define _UPSR_NMIE    0x80U

# define NATIVE_HWBUG_AFTER_LD_ACQ() \
do { \
	unsigned long long __reg1, __reg2; \
	if (NATIVE_HAS_HWBUG_AFTER_LD_ACQ_ADDRESS) { \
		unsigned long __hwbug_cpu = NATIVE_HWBUG_AFTER_LD_ACQ_CPU; \
		unsigned long __hwbug_address = \
				NATIVE_HWBUG_AFTER_LD_ACQ_ADDRESS + \
				(__hwbug_cpu & 0x3) * 4096; \
		unsigned long __hwbug_atomic_flags; \
		__hwbug_atomic_flags = NATIVE_GET_DSREG_OPEN(upsr); \
		NATIVE_SET_UPSR_IRQ_BARRIER( \
			__hwbug_atomic_flags & ~(_UPSR_IE | _UPSR_NMIE)); \
		NATIVE_CLEAN_LD_ACQ_ADDRESS(__reg1, __reg2, __hwbug_address); \
		NATIVE_WRITE_MAS_D(__hwbug_address + 0 * 4096 + 0 * 64, 0UL, \
				MAS_DCACHE_LINE_FLUSH); \
		NATIVE_WRITE_MAS_D(__hwbug_address + 0 * 4096 + 4 * 64, 0UL, \
				MAS_DCACHE_LINE_FLUSH); \
		NATIVE_WRITE_MAS_D(__hwbug_address + 8 * 4096 + 1 * 64, 0UL, \
				MAS_DCACHE_LINE_FLUSH); \
		NATIVE_WRITE_MAS_D(__hwbug_address + 8 * 4096 + 5 * 64, 0UL, \
				MAS_DCACHE_LINE_FLUSH); \
		NATIVE_WRITE_MAS_D(__hwbug_address + 16 * 4096 + 2 * 64, 0UL, \
				MAS_DCACHE_LINE_FLUSH); \
		NATIVE_WRITE_MAS_D(__hwbug_address + 16 * 4096 + 6 * 64, 0UL, \
				MAS_DCACHE_LINE_FLUSH); \
		NATIVE_WRITE_MAS_D(__hwbug_address + 24 * 4096 + 3 * 64, 0UL, \
				MAS_DCACHE_LINE_FLUSH); \
		NATIVE_WRITE_MAS_D(__hwbug_address + 24 * 4096 + 7 * 64, 0UL, \
				MAS_DCACHE_LINE_FLUSH); \
		__E2K_WAIT(_fl_c); \
		NATIVE_SET_UPSR_IRQ_BARRIER(__hwbug_atomic_flags); \
	} \
} while (0)
#else
# define NATIVE_HWBUG_AFTER_LD_ACQ()	do { } while (0)
#endif

/* FIXME: here will be only hardware bugs workaround macroses */
/* but in guest general case these bugs can be workarounded only on host and */
/* guest should call appropriate hypercalls to make all atomic */
/* sequence on host, because of they contain privileged actions */

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is virtualized guest kernel */
#include <asm/kvm/guest/atomic_api.h>
#else /* !CONFIG_KVM_GUEST_KERNEL */
/* it is native kernel with or without virtualization support */

/* examine bare hardware bugs */
#define	virt_cpu_has(hwbug)		cpu_has(hwbug)

#define	VIRT_HWBUG_AFTER_LD_ACQ()	NATIVE_HWBUG_AFTER_LD_ACQ()
#endif /* CONFIG_KVM_GUEST_KERNEL */

#define VIRT_HWBUG_AFTER_LD_ACQ_STRONG_MB	VIRT_HWBUG_AFTER_LD_ACQ
#define VIRT_HWBUG_AFTER_LD_ACQ_LOCK_MB		VIRT_HWBUG_AFTER_LD_ACQ
#define VIRT_HWBUG_AFTER_LD_ACQ_ACQUIRE_MB	VIRT_HWBUG_AFTER_LD_ACQ
#define VIRT_HWBUG_AFTER_LD_ACQ_RELEASE_MB()
#define VIRT_HWBUG_AFTER_LD_ACQ_RELAXED_MB()


/* Atomically add to 16 low bits and return the new 32 bits value */
#define __api_atomic16_add_return32_lock(val, addr) \
({ \
	register int	rval, tmp;	\
	NATIVE_ATOMIC16_ADD_RETURN32_LOCK(val, addr, rval, tmp); \
	VIRT_HWBUG_AFTER_LD_ACQ(); \
	rval; \
})

#define __api_atomic_ticket_trylock(spinlock, tail_shift) \
({ \
 	register int	__rval;	\
	register int	__val; \
	register int	__head; \
	register int	__tail; \
	NATIVE_ATOMIC_TICKET_TRYLOCK(spinlock, tail_shift, \
				__val, __head, __tail, __rval); \
	VIRT_HWBUG_AFTER_LD_ACQ_LOCK_MB(); \
	__rval; \
})

#define __api_atomic_op(val, addr, size_letter, op, mem_model) \
({ \
	typeof(val) rval; \
	NATIVE_ATOMIC_OP(val, addr, rval, size_letter, op, mem_model); \
	VIRT_HWBUG_AFTER_LD_ACQ_##mem_model(); \
	rval; \
})

#define __api_atomic_fetch_op(val, addr, size_letter, op, mem_model) \
({ \
	typeof(val) rval, stored_val; \
	NATIVE_ATOMIC_FETCH_OP(val, addr, rval, stored_val, \
			       size_letter, op, mem_model); \
	VIRT_HWBUG_AFTER_LD_ACQ_##mem_model(); \
	rval; \
})

#define __api_user_atomic32_op(insn, oparg, uaddr, mem_model, oldval) \
({ \
	int __ret; \
	typeof(oparg) __stored_val; \
	USER_ATOMIC_FETCH_OP(oparg, uaddr, oldval, __stored_val, \
			       w, insn, mem_model, __ret); \
	VIRT_HWBUG_AFTER_LD_ACQ_##mem_model(); \
	__builtin_expect(__ret, 0); \
})

#define __api_user_cmpxchg_word(old, new, addr, mem_model, oldval) \
({ \
	int __ret, __stored_val; \
	USER_ATOMIC_CMPXCHG_WORD_RETURN(old, new, addr, __stored_val, \
			oldval, mem_model, __ret); \
	VIRT_HWBUG_AFTER_LD_ACQ_##mem_model(); \
	__builtin_expect(__ret, 0); \
})

#define __api_user_xchg(val, addr, size_letter, mem_model, oldval) \
({ \
	int __ret; \
	USER_ATOMIC_XCHG_RETURN(val, addr, oldval, size_letter, mem_model, __ret); \
	VIRT_HWBUG_AFTER_LD_ACQ_##mem_model(); \
	__ret; \
})


/*
 * Atomic operations with return value and acquire/release semantics
 */

#define __api_atomic32_fetch_inc_unless_negative(addr) \
({ \
	register int rval, tmp; \
	NATIVE_ATOMIC_FETCH_OP_UNLESS(1, addr, 0, tmp, rval, \
			w, "adds", "~ ", "adds", "", "cmplsb", STRONG_MB); \
	VIRT_HWBUG_AFTER_LD_ACQ(); \
	rval; \
})

#define __api_atomic64_fetch_inc_unless_negative(addr) \
({ \
	register long long rval, tmp; \
	NATIVE_ATOMIC_FETCH_OP_UNLESS(1ull, addr, 0ull, tmp, rval, \
			d, "addd", "~ ", "addd", "", "cmpldb", STRONG_MB); \
	VIRT_HWBUG_AFTER_LD_ACQ(); \
	rval; \
})

#define __api_atomic32_fetch_dec_unless_positive(addr) \
({ \
	register int rval, tmp; \
	NATIVE_ATOMIC_FETCH_OP_UNLESS(1, addr, 0, tmp, rval, \
			w, "subs", "", "adds", "~ ", "cmplesb", STRONG_MB); \
	VIRT_HWBUG_AFTER_LD_ACQ(); \
	rval; \
})

#define __api_atomic64_fetch_dec_unless_positive(addr) \
({ \
	register long long rval, tmp; \
	NATIVE_ATOMIC_FETCH_OP_UNLESS(1ull, addr, 0ull, tmp, rval, \
			d, "subd", "", "addd", "~ ", "cmpledb", STRONG_MB); \
	VIRT_HWBUG_AFTER_LD_ACQ(); \
	rval; \
})

#define __api_atomic32_fetch_dec_if_positive(addr) \
({ \
	register int rval, tmp; \
	NATIVE_ATOMIC_FETCH_OP_UNLESS(1, addr, 0, tmp, rval, \
			w, "subs", "~ ", "adds", "", "cmplesb", STRONG_MB); \
	VIRT_HWBUG_AFTER_LD_ACQ(); \
	rval; \
})

#define __api_atomic64_fetch_dec_if_positive(addr) \
({ \
	register long long rval, tmp; \
	NATIVE_ATOMIC_FETCH_OP_UNLESS(1ull, addr, 0ull, tmp, rval, \
			d, "subd", "~ ", "addd", "", "cmpledb", STRONG_MB); \
	VIRT_HWBUG_AFTER_LD_ACQ(); \
	rval; \
})

#define __api_atomic32_fetch_add_unless(val, addr, unless) \
({ \
	register int rval, tmp; \
	NATIVE_ATOMIC_FETCH_OP_UNLESS(val, addr, unless, tmp, rval, \
			w, "adds", "~ ", "adds", "", "cmpesb", STRONG_MB); \
	VIRT_HWBUG_AFTER_LD_ACQ(); \
	rval; \
})

#define __api_atomic64_fetch_add_unless(val, addr, unless) \
({ \
	register long long rval, tmp; \
	NATIVE_ATOMIC_FETCH_OP_UNLESS(val, addr, unless, tmp, rval, \
			d, "addd", "~ ", "addd", "", "cmpedb", STRONG_MB); \
	VIRT_HWBUG_AFTER_LD_ACQ(); \
	rval; \
})

#define __api_atomic64_fetch_xchg_if_below_or_inc(val, addr, mem_model) \
({ \
	register long long rval, tmp; \
	NATIVE_ATOMIC_FETCH_XCHG_UNLESS_INC(val, addr, tmp, rval, d, d, \
			"merged", "cmpbdb", mem_model); \
	VIRT_HWBUG_AFTER_LD_ACQ_##mem_model(); \
	rval; \
})

#define __api_xchg_return(val, addr, size_letter, mem_model) \
({ \
 	register long	rval;	\
	NATIVE_ATOMIC_XCHG_RETURN(val, addr, rval, size_letter, mem_model); \
	VIRT_HWBUG_AFTER_LD_ACQ_##mem_model(); \
	rval; \
})

#define __api_cmpxchg_return(old, new, addr, size_letter, sxt_size, mem_model) \
({ \
 	register long	rval;	\
	register long	stored_val; \
	NATIVE_ATOMIC_CMPXCHG_RETURN(old, new, addr, stored_val, rval, \
					size_letter, sxt_size, mem_model); \
	VIRT_HWBUG_AFTER_LD_ACQ_##mem_model(); \
	rval; \
})

#define __api_cmpxchg_word_return(old, new, addr, mem_model) \
({ \
	int rval, stored_val; \
	NATIVE_ATOMIC_CMPXCHG_WORD_RETURN(old, new, addr, stored_val, rval, mem_model); \
	VIRT_HWBUG_AFTER_LD_ACQ_##mem_model(); \
	rval; \
})

#define __api_cmpxchg_dword_return(old, new, addr, mem_model) \
({ \
	long long rval, stored_val; \
	NATIVE_ATOMIC_CMPXCHG_DWORD_RETURN(old, new, addr, stored_val, \
					   rval, mem_model); \
	VIRT_HWBUG_AFTER_LD_ACQ_##mem_model(); \
	rval; \
})

#define __api_cmpxchg_double(addr1, addr2, old1, old2, new1, new2, mem_model) \
({ \
	register long	rval;	\
	NATIVE_ATOMIC_CMPXCHG_DWORD_PAIRS(addr1, old1, old2, new1, new2, rval, mem_model); \
	VIRT_HWBUG_AFTER_LD_ACQ_##mem_model(); \
	rval; \
})

/* Atomically add and return the old value */
#define __api_atomic32_add_oldval(val, addr) \
		__api_atomic_fetch_op(val, addr, w, "adds", STRONG_MB)

#define __api_atomic32_add_oldval_lock(val, addr) \
		__api_atomic_fetch_op(val, addr, w, "adds", LOCK_MB)

#endif /* ! __ASSEMBLY__ */

#endif /* __KERNEL__ */

#endif /* _ASM_E2K_ATOMIC_API_H_ */
