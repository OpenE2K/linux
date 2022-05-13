/* linux/arch/e2k/kernel/protected_mq_notify.c, v 1.0 02/11/2019.
 *
 * This is implementation of the system call mq_notify:
 *	int mq_notify(mqd_t mqdes, const struct sigevent *sevp)
 * for E2K protected mode.
 *
 * Copyright (C) 2019 MCST
 */


#include <linux/syscalls.h>
#include <linux/compat.h>

#include <asm/e2k_debug.h>
#include <asm/convert_array.h>
#include <asm/syscalls.h>


#undef	DEBUG_SYSCALLP
#define	DEBUG_SYSCALLP	0	/*Protected  System Calls trace */
#if DEBUG_SYSCALLP
#define DbgSCP(...)		DebugPrint(DEBUG_SYSCALLP, ##__VA_ARGS__)
#else
#define DbgSCP(...)
#define DbgSCP_print_array(...)
#endif


#ifdef CONFIG_PROTECTED_MODE

#define USER_SIVAL_PTR_OFFSET_LO 0
#define USER_SIVAL_PTR_OFFSET_HI 8

#define get_user_space(x)	arch_compat_alloc_user_space(x)


#if DEBUG_SYSCALLP
static void DbgSCP_print_array(void *array, int wordnum)
{
int *ptr = (int *) array;
int i;
	if (!array || !wordnum)
		return;
	DbgSCP("print_array 0x%px of %d words:\n", array, wordnum);
	for (i = 0; i < wordnum; i++) {
		DbgSCP("\t0x%.8x\n", *ptr);
		ptr++;
	}
}
#endif /* DEBUG_SYSCALLP */

long protected_sys_mq_notify(const long arg1 /*mqdes*/,
			     const unsigned long __user arg2 /*sevp*/)
{
	unsigned int size;
	long rval = -EINVAL;
	/*
	 * struct sigevent: {int/(f)ptr} [int][int] {int,ptr,[fptr,ptr]}
	 * MASK_type_INT:       0b 11 10 00 00 00   int-int-int-fptr-ptr
	 * MASK_type_PTR:       0b 11 10 00 00 11   ptr-int-int-fptr-ptr
	 * MASK_type_FPTR:      0b 11 10 00 00 10  fptr-int-int-fptr-ptr
	 * MASK_align:          0b 11 11 11 00 11   16b- 4b-16b- 16b-16b
	 * NB> {...} - union; [...] - field/structure.
	 */
#define MQ_NOTIFY_MASK_typeI 0x0 /* integers in fields 1-3 */
#define MQ_NOTIFY_MASK_typeP 0x3 /* pointer at the 1st union field */
#define MQ_NOTIFY_MASK_typeF 0x2 /* ptr-to-function at the 1st union field */
#define MQ_NOTIFY_MASK_type2 0x380 /* fptr/ptr in the 4th/5th fields */
#define MQ_NOTIFY_MASK_align1 0x33  /* fields 1-3 */
#define MQ_NOTIFY_MASK_align2 0x3c0 /* fields 4-5 */
#define MQ_NOTIFY_STRING "Bad sigevent stack descriptor for mq_notify\n"
#define PROT_SIZEOF_SIGEVENT 80 /* structure size in the user space (in PM) */
#define PROT_SIGEV_NOTIFY_OFFSET_DELTA 2 /* field offset shift in PM */
	void *ev = NULL;
	void *kernel_ptr = NULL;
	long user_ptr_lo = 0, user_ptr_hi = 0;
	int sival_ptr_tags = 0;
	int signum = 0;

	DbgSCP("arg1 = %ld, arg2 = %px\n", arg1, (void *)arg2);
	if (arg2) {
		long mask_type;
		long align_type = MQ_NOTIFY_MASK_align1;
		int  tag;
		int *sigev_notify_ptr; /* pointer to the sigev_notify field */

		size = PROT_SIZEOF_SIGEVENT;

		TRY_USR_PFAULT {
			NATIVE_LOAD_VAL_AND_TAGD(arg2 +
				USER_SIVAL_PTR_OFFSET_LO,
				user_ptr_lo, sival_ptr_tags);
			NATIVE_LOAD_VAL_AND_TAGD(arg2 +
				USER_SIVAL_PTR_OFFSET_HI,
				user_ptr_hi, tag);
		} CATCH_USR_PFAULT {
			return -EFAULT;
		} END_USR_PFAULT
		sival_ptr_tags |= tag << 4;

		switch (sival_ptr_tags) {
		case ETAGNUM:
			mask_type = MQ_NOTIFY_MASK_typeI;
			break;
		case ETAGAPQ:
			mask_type = MQ_NOTIFY_MASK_typeP;
			break;
		case ETAGPLD:
			mask_type = MQ_NOTIFY_MASK_typeF;
			break;
		case ETAGPLQ: /* this is for future Elbrus arch V6 */
			pr_err("__NR_mq_notify: unsupported tag ETAGPLQ (0x%x)\n",
			       sival_ptr_tags);
			DbgSCP("\tptr_lo=0x%lx ptr_hi=0x%lx\n",
			       user_ptr_lo, user_ptr_hi);
			DbgSCP_print_array((long *)arg2, size);
			return -EINVAL;
		default:
			mask_type = MQ_NOTIFY_MASK_typeI;
		}
		/* Checking the content of the 'sigev_notify' field: */
		sigev_notify_ptr = (int *)(&(((sigevent_t *)arg2)->sigev_notify)
					+ PROT_SIGEV_NOTIFY_OFFSET_DELTA);
		if (*sigev_notify_ptr == SIGEV_THREAD) {
			align_type |= MQ_NOTIFY_MASK_align2;
			mask_type  |= MQ_NOTIFY_MASK_type2;
		}

		ev = get_user_space(size);

		rval = convert_array((long *)arg2, ev, size,
			5, 1, mask_type, align_type);
		if (rval) {
			DbgSCP(MQ_NOTIFY_STRING);
			return rval;
		}
		kernel_ptr = ((sigevent_t *)ev)->sigev_value.sival_ptr;
		signum     = ((sigevent_t *)ev)->sigev_signo;
	}
	DbgSCP("sys_mq_notify(%ld, %px)\n", arg1, ev);
	rval = sys_mq_notify((mqd_t)arg1, (const sigevent_t *) ev);

	if (rval || !arg2)
		return rval;

	/* Saving sival_ptr in sival_ptr_list: */
	store_descriptor_attrs(kernel_ptr, user_ptr_lo, user_ptr_hi,
			       sival_ptr_tags, signum);

	return rval;
}

#endif  /* CONFIG_PROTECTED_MODE */
