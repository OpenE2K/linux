
#define ARCH_HAS_GET_CYCLES

#define ARCH_HAS_ATOMIC_CMPXCHG

#define el_atomic_cmpxchg_acq(x, uaddr, oldval, newval) \
		__el_atomic_cmpxchg_acq(&x, uaddr, oldval, newval)
static inline int __el_atomic_cmpxchg_acq(int *x, int *uaddr, int oldval,
		int newval)
{
	int ret;

	__asm__ __volatile__(
			"\n1:	casa	[%4] %%asi, %3, %1\n"
			"2:\n"
			"	.section .fixup,#alloc,#execinstr\n"
			"	.align	4\n"
			"3:	sethi	%%hi(2b), %0\n"
			"	jmpl	%0 + %%lo(2b), %%g0\n"
			"	 mov	%5, %0\n"
			"	.previous\n"
			"	.section __ex_table,\"a\"\n"
			"	.align	4\n"
			"	.word	1b, 3b\n"
			"	.previous\n"
			: "=&r" (ret), "=r" (newval)
			: "1" (newval), "r" (oldval), "r" (uaddr),
			  "i" (-EFAULT), "0" (0)
			: "memory");
	smp_mb();
	*x = newval;

	return ret;
}

#define el_atomic_cmpxchg_rel(x, uaddr, oldval, newval) \
		__el_atomic_cmpxchg_rel(&x, uaddr, oldval, newval)
static inline int __el_atomic_cmpxchg_rel(int *x, int *uaddr, int oldval,
		int newval)
{
	int ret;

	smp_mb();
	__asm__ __volatile__(
			"\n1:	casa	[%4] %%asi, %3, %1\n"
			"2:\n"
			"	.section .fixup,#alloc,#execinstr\n"
			"	.align	4\n"
			"3:	sethi	%%hi(2b), %0\n"
			"	jmpl	%0 + %%lo(2b), %%g0\n"
			"	 mov	%5, %0\n"
			"	.previous\n"
			"	.section __ex_table,\"a\"\n"
			"	.align	4\n"
			"	.word	1b, 3b\n"
			"	.previous\n"
			: "=&r" (ret), "=r" (newval)
			: "1" (newval), "r" (oldval), "r" (uaddr),
			  "i" (-EFAULT), "0" (0)
			: "memory");
	*x = newval;

	return ret;
}

#define el_atomic_xchg_acq(x, uaddr, value) \
		__el_atomic_xchg_acq(&x, uaddr, value)
static inline int __el_atomic_xchg_acq(int *x, int *uaddr, int val)
{
	int ret;

	__asm__ __volatile__(
			"\n1:	swapa	[%3] %%asi, %1\n\t"
			"2:\n"
			"	.section .fixup,#alloc,#execinstr\n"
			"	.align	4\n"
			"3:	sethi	%%hi(2b), %0\n"
			"	jmpl	%0 + %%lo(2b), %%g0\n"
			"	 mov	%4, %0\n"
			"	.previous\n"
			"	.section __ex_table,\"a\"\n"
			"	.align	4\n"
			"	.word	1b, 3b\n"
			"	.previous\n"
			: "=&r" (ret), "=&r" (val)
			: "1" (val), "r" (uaddr), "i" (-EFAULT), "0" (0)
			: "memory");
	smp_mb();

	*x = val;

	return ret;
}
