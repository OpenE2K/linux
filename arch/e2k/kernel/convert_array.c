/* linux/arch/e2k/kernel/convert_array.c, v 1.0 02/11/2019.
 *
 * This is a utility to support interactions between kernel and
 *                                E2K protected mode user layer.
 *
 * The function 'convert_array' converts complex protected area structures,
 * which can contain protected user pointers to memory (descriptors),
 * and/or function pointers (descriptors), into regular C-structures
 * (non-protected).
 *
 * Copyright (C) 2019 MCST
 */

#include <linux/slab.h>
#include <linux/printk.h>
#include <asm/e2k_debug.h>
#include <linux/uaccess.h>
#include <asm/syscalls.h>
#include <asm/protected_syscalls.h>
#include <asm/convert_array.h>

#ifdef CONFIG_PROTECTED_MODE

#if (DYNAMIC_DEBUG_SYSCALLP_ENABLED)
	/* NB> PM debug module must have been initialized by
	 *     the moment of 'convert_array' invocation;
	 *     we can use simple defines over here.
	 * For full ones see <asm/protected_syscalls.h>.
	 */
#undef DbgSCP
#if defined(CONFIG_THREAD_INFO_IN_TASK) && defined(CONFIG_SMP)
#define DbgSCP(fmt, ...) \
do { \
	if (pm_sc_debug_mode & PM_SC_DBG_MODE_CONV_STRUCT) \
		pr_info("%s [%.3d#%d]: %s: " fmt, current->comm, \
				current->cpu, current->pid, \
				__func__,  ##__VA_ARGS__); \
} while (0)
#else /* no 'cpu' field in 'struct task_struct' */
#define DbgSCP(fmt, ...) \
do { \
	if (pm_sc_debug_mode & PM_SC_DBG_MODE_CONV_STRUCT) \
		pr_info("%s [#%d]: %s: " fmt, current->comm, \
				current->pid, \
				__func__,  ##__VA_ARGS__); \
} while (0)
#endif /* no 'cpu' field in 'struct task_struct' */

#undef DbgSCP_ERRMSG
#define DbgSCP_ERRMSG(ErrMsgHeader, fmt, ...) \
do { \
	if (pm_sc_debug_mode & PM_SC_DBG_MODE_CHECK \
		&& !(current->mm->context.pm_sc_debug_mode \
					& PM_SC_DBG_MODE_NO_ERR_MESSAGES)) \
		pr_err("%s [%d]:: %s: " fmt, current->comm, current->pid, \
				ErrMsgHeader, ##__VA_ARGS__); \
} while (0)

#undef DbgSCP_ERR
#define DbgSCP_ERR(fmt, ...) DbgSCP_ERRMSG(__func__, fmt, ##__VA_ARGS__)

#undef DbgSCP_ALERT
#define DbgSCP_ALERT(fmt, ...) \
do { \
	if (pm_sc_debug_mode & PM_SC_DBG_MODE_CHECK \
		&& !(current->mm->context.pm_sc_debug_mode \
					& PM_SC_DBG_MODE_NO_ERR_MESSAGES)) \
		pr_alert("%s [%d]:: %s(): " fmt, current->comm, current->pid, \
				__func__,  ##__VA_ARGS__); \
} while (0)

#undef DbgSCP_WARN
#define DbgSCP_WARN(fmt, ...) \
do { \
	if (pm_sc_debug_mode & PM_SC_DBG_MODE_CHECK \
		&& !(current->mm->context.pm_sc_debug_mode \
					& PM_SC_DBG_MODE_NO_ERR_MESSAGES)) \
		pr_alert("%s [%d]:: %s(): " fmt, current->comm, current->pid, \
				__func__,  ##__VA_ARGS__); \
} while (0)

#undef PM_SYSCALL_WARN_ONLY
#define PM_SYSCALL_WARN_ONLY \
		(pm_sc_debug_mode & PM_SC_DBG_MODE_WARN_ONLY)

#endif /* DYNAMIC_DEBUG_SYSCALLP_ENABLED */

#define CONVERT_WARN_ONLY PM_SYSCALL_WARN_ONLY
		/* Backward compatibility execution mode.
		 * When legacy soft delivers to convert_array data to process,
		 *       it may contain data that don't match specified masks.
		 *       This is mainly the case when descriptor expected by
		 *       mask specified is not found in the array structure.
		 * Normally convert_array reports error to journal and exits
		 * with corresponding error code. If this var is set,
		 * convert_array still reports error message but leaves input
		 * data intact, and returns as if everything were OK (i.e. 0).
		 */

/* Aligning pointer to the upper bound: */

static inline
int *align_ptr_up(int *ptr, const int alignment)
{
	if (((unsigned long) ptr) % alignment)
		ptr = (int *) (((unsigned long) ptr
			+ alignment - 1) & ~(alignment - 1));

	return ptr;
}

/* TODO: Get rid of PUT_USER_OR_KERNEL when entry #10 is gone and
 *		Replace 'PUT_USER_OR_KERNEL' with 'put_user'
 */
#define PUT_USER_OR_KERNEL(_mode, ptr, val)		\
do {							\
	if (_mode) {					\
		if (put_user(val, ptr)) {		\
			failed_2_write = 1;		\
			goto out;			\
		}					\
	} else {					\
		*ptr = val;				\
	}						\
} while (0)

/*
 * This function converts the array of structures, which can contain
 * protected user pointers to memory, function descriptors, and int values.
 * prot_array - pointer to original (user-type) array
 * new_array - pointer for putting of converted array
 * max_prot_array_size - the maximum size, which protected array should take
 * fields - number of enries in each element
 * items - number of identical elements in the array to convert
 * mask_type - mask for encoding of field type in each element
 * 4 bits per each entry:
 * --- 0000 (0x0) - int
 * --- 0001 (0x1) - long
 * --- 0010 (0x2) - pointer to function
 * --- 0011 (0x3) - descriptor (pointer to memory)
 * --- 0100 (0x4) - descriptor or int
 * --- 0101 (0x5) - descriptor or long
 * --- 0110 (0x6) - descriptor or Fptr
 * --- 0111 (0x7) - everything is possible
 * --- 1*** (0x8) - may be uninitialized (empty tag allowed)
 * mask_align - mask for encoding of alignment of the NEXT! field
 * 4 bits per each entry:
 * --- 00 (0x0) - next field aligned as int (to 4 bytes)
 * --- 01 (0x1) - next field aligned as long (to 8 bytes)
 * --- 10 (0x2) - not used yet
 * --- 11 (0x3) - next field aligned as pointer (to 16 bytes)
 * mask_rw - mask for encoding access type of the structure elements
 * 4 bits per each entry:
 * --- 01 (0x1) - the field's content gets read by syscall (READ-able)
 * --- 10 (0x2) - the field's content gets updated by syscall (WRITE-able)
 * --- 11 (0x3) - the field is both READ-able and WRITE-able
 * --- 00 (0x0) - default type; the same as (READ-able)
 * rval_mode - error (return value) reporting mode mask:
 *	0 - report only critical problems in prot_array structure;
 *	1 - return with -EFAULT if wrong tag in 'int' field;
 *	2 -         --'--           --'--       'long' field;
 *	4 -         --'--           --'--       'func' field;
 *	8 -         --'--           --'--       'descr' field;
 *	16 - ignore errors in 'int' field;
 *	32 -  --'--   --'--   'long' field;
 *	64 -  --'--   --'--   'func' field;
 *	128 - --'--   --'--   'descr' field.
 * Returns: 0 - if converted OK;
 *     error number - otherwise.
 */

extern int get_pm_struct(long __user *prot_array,
			 long		*new_array,
			 const int max_prot_array_size, const int fields,
			 const int items, const long mask_type,
			 const long mask_align, const long mask_rw,
			 const int rval_mode)
{
/* Field type, 4 bits: (mask_type & 0xf) */
#define _INT_FIELD		0x0  /* int value */
#define _LONG_FIELD		0x1  /* long value */
#define _FUNC_FIELD		0x2  /* pointer to function */
#define _PTR_FIELD		0x3  /* pointer to memory */
#define _INT_PTR_FIELD		0x4  /* int or pointer value */
#define _LONG_PTR_FIELD		0x5  /* long or pointer value */
#define _PTR__FUNC_FIELD	0x6  /* descriptor or func.ptr */
#define _TAG_DEFINED_FIELD	0x7  /* everything is possible */
#define _UNINITIALIZED_FIELD	0x8 /* tag may be ETAGEWS or ETAGEWD */

/* Alignment of the NEXT! field, 2 bits: mask_align & 0x3 */
#define _INT_ALIGN      0x0  /* next field aligned as int (to 4 bytes) */
#define _LONG_ALIGN     0x1  /* next field aligned as long (to 8 bytes) */
#define _PTR_ALIGN      0x3  /* next field aligned as pointer (to 16 bytes) */

/* Access field type, 2 bits: mask_rw & 0x3 */
#define _READABLE       0x1  /* field gets read by syscall */
#define _WRITEABLE      0x2  /* field gets updated by syscall */

	int struct_len, prot_len;
	int elem_type, alignment;
	long pat_type, pat_align, pat_rw, val_long;
	int __user *ptr_from;
	int __user *ptr_to;
	int user_mode = 0;
	int may_be_uninitialized;
	unsigned long pm_sc_debug_mode = current->mm->context.pm_sc_debug_mode;
	int misaligned_ptr_from = 0; /* normally ptr_from must be aligned */
	int rval = 0; /* result of the function */
	int failed_2_write = 0;
	int val_int, tag;
	int i, j;

	DbgSCP("struct128 = 0x%lx, struct64 = 0x%lx, size = %d\n",
		prot_array, new_array, max_prot_array_size);
	DbgSCP("fields = %d, items = %d, mask_t = 0x%lx, mask_a = 0x%lx, mask_rw = 0x%lx\n",
		fields, items, mask_type, mask_align, mask_rw);

	if (!prot_array) {
		DbgSCP("Empty prot.array to convert\n");
		return -EINVAL;
	}

	/* Check main parameters for validity */
	if (!new_array || !fields || (items <= 0)) {
		DbgSCP_ERR("pid#%d: Wrong parameters for convert_array\n",
			current->pid);
		return -EINVAL;
	}

	if ((uintptr_t)prot_array & 0x7) {
		DbgSCP_ERR("pid#%d: Unaligned input protected array (0x%lx)\n",
			current->pid, prot_array);
		return -EINVAL;
	}

	/* Counting protected structure size: */
	pat_align = mask_align;
	struct_len = 0;
	ptr_from = (int *) prot_array;

	for (i = 0; i < fields; i++) {
		alignment = ((pat_align & 0xf) + 1) * sizeof(int);
		if (((unsigned long) ptr_from) % alignment) {
			misaligned_ptr_from = 1;
			struct_len += ((((unsigned long) ptr_from
				+ alignment - 1) & ~(alignment - 1))
				- ((unsigned long) ptr_from));
			ptr_from = (int *) (((unsigned long) ptr_from
				+ alignment - 1) & ~(alignment - 1));
		} else {
			struct_len += alignment;
			ptr_from += (alignment / sizeof(int));
		}
		pat_align >>= 4;
	}

	if (struct_len & 0x7) {
		/* Input structure size must be factor of 8. */
		/* Extending size (required by NATIVE_LOAD_VAL_AND_TAGW): */
		struct_len = (struct_len + 8) & ~0x7;
	}

	/* Count the size of the whole array */
	prot_len = struct_len * items;

	/* Nothing to be converted if real size of the array is zero */
	if (prot_len == 0) {
		DbgSCP("prot_len == 0; returning 0\n");
		return 0;
	}

	/*
	 * Real size of the array can't be more than maximum
	 * size of this array in user space
	 */
	if (prot_len > max_prot_array_size) {
		DbgSCP_ERR("prot_len (%d) > max_prot_array_size(%d)\n",
			   prot_len, max_prot_array_size);
		if (misaligned_ptr_from)
			DbgSCP_ERR("prot_array (0x%lx) must be properly aligned\n",
				   prot_array);
		return -EFAULT;
	}

	if (arch_init_pm_sc_debug_mode(PM_SC_DBG_MODE_CONV_STRUCT)) {
		/* Displaying input (protected) array: */
		long *lptr = kmalloc(prot_len + 16, GFP_KERNEL);
		long *mem_lptr = lptr;

		/* NB> Alignment required not to lose tags */
		lptr = (long *) (((uintptr_t) lptr + 15) & ~0xf);
		/* Copy original array with tags to tmp array for converting */
		if (copy_from_user_with_tags(lptr, prot_array, prot_len)) {
			DbgSCP_ERR("pid#%d Copying original array (0x%lx : %d) failed\n",
				   current->pid, (long) lptr, prot_len);
			kfree(lptr);
			rval = -EFAULT;
			goto out;
		}
		pr_info("get_pm_struct: sizeof(struct128) = %zd (words):\n",
			items * (struct_len / sizeof(int)));
		if (items > 1)
			pr_info("[array size: %d]\n", items);
		for (j = 0; j < items; j++) {
			if (items > 1)
				pr_info("[element #%d]\n", j);
			for (i = 0; i < (struct_len / sizeof(long)); i++) {
				NATIVE_LOAD_VAL_AND_TAGD((long *) lptr,
							val_long, tag);
				pr_info("\t[0x%x] 0x%.8x.%.8x\n", tag,
					(int)(*lptr >> 32), (int)*lptr);
				lptr++;
			}
		}
		kfree(mem_lptr);
	}

	/* Check ptr_to: user or kernel address */
	ptr_to = (int *) new_array;
	if ((long) ptr_to < TASK_SIZE) {
		user_mode = 1;
	}

TRY_USR_PFAULT {

	/* Detailed analysis of data encoded in the input structure(s): */
	for (i = 0; i < items; i++) {
		ptr_from = (int *)((uintptr_t) prot_array + struct_len * i);
		pat_type = mask_type;
		pat_align = mask_align;
		pat_rw = mask_rw;

		/* Handle each entry in the strcut */
		for (j = 0; j < fields; j++) {

			elem_type = pat_type & 0x7;
			may_be_uninitialized = pat_type & _UNINITIALIZED_FIELD;
/*
			DbgSCP("round %d: type=%d from=0x%lx  to=0x%lx\n",
			       j, elem_type, (long)ptr_from, (long)ptr_to);
*/
			/* Load the field by type specified in mask_type */
load_current_element:
			switch (elem_type) {
			case _INT_FIELD:
				/* Load word (4 bytes) with tags */
				NATIVE_LOAD_VAL_AND_TAGW((int *) ptr_from,
							val_int, tag);

				if ((tag == ETAGEWS) && may_be_uninitialized)
					val_int = 0; /* we don't copy trash */
				/* Check for valid 'int' field */
				else if (likely((pat_rw & 0xf) != _WRITEABLE)
					&& (tag != ETAGNUM)
					&& !(rval_mode
					     & CONV_ARR_IGNORE_INT_FLD_ERR)) {
#define ERROR_UNINIT_FLDI \
	"uninitialized value (tag=0x%x) at struct128[%d]: 0x%x\n"
#define ERROR_UNEXPECTED_VALI \
	"unexpected value (tag=0x%x) at struct128[%d]: 0x%x\n"
					if (tag == ETAGEWS)
						DbgSCP_ALERT(ERROR_UNINIT_FLDI,
						   tag, j, val_int);
					else
						DbgSCP_ALERT(ERROR_UNEXPECTED_VALI,
						   tag, j, val_int);
#define IGNORING_ARR_ELEM \
	"ignoring struct128[%d]; replaced with zero\n"
					/* Don't copy field of another type */
					if (val_int && (!CONVERT_WARN_ONLY)) {
						DbgSCP_ALERT(IGNORING_ARR_ELEM,
							     i);
						val_int = 0;
					}
					if (rval_mode & CONV_ARR_WRONG_INT_FLD)
						rval = -EFAULT;
				}
				if ((long)ptr_to & 1) { /* write at higher word */
					PUT_USER_OR_KERNEL(user_mode,
						(int *) ptr_to, val_int);
				} else { /* write at lower word */
					/* NB> To avoid trash in higher word,
					 *     we save it as long val.
					 */
					val_long = (long) val_int;
					PUT_USER_OR_KERNEL(user_mode,
						(long *) ptr_to, val_long);
				}

				/* Move on ptr_from and ptr_to: */
				ptr_from++;
				ptr_to++;

				break;
			case _LONG_FIELD:
				/* Load dword (8 bytes) with tags */
				NATIVE_LOAD_VAL_AND_TAGD((long *) ptr_from,
							val_long, tag);

				if ((tag == ETAGEWD) && may_be_uninitialized)
					val_long = 0; /* we don't copy trash */
				/* Check for valid 'long' field */
				else if (likely((pat_rw & 0xf) != _WRITEABLE)
					&& (tag != ETAGNUM)
					&& !(rval_mode
					     & CONV_ARR_IGNORE_LONG_FLD_ERR)) {
#define ERROR_UNINIT_FLDL \
	"uninitialized value (tag=0x%x) at struct128[%d]: 0x%lx\n"
#define ERROR_UNEXPECTED_VALL \
	"unexpected value (tag=0x%x) at struct128[%d]: 0x%lx\n"
					if (tag == ETAGEWD)
						DbgSCP_ALERT(ERROR_UNINIT_FLDL,
							     tag, j, val_long);
					else
						DbgSCP_ALERT(ERROR_UNEXPECTED_VALL,
							     tag, j, val_long);
					/* Don't copy field of another type */
					if (val_long && (!CONVERT_WARN_ONLY)) {
						DbgSCP_ALERT(IGNORING_ARR_ELEM,
							     i);
						val_long = 0;
					}
					if (rval_mode & CONV_ARR_WRONG_LONG_FLD)
						rval = -EFAULT;
				}
				PUT_USER_OR_KERNEL(user_mode,
						(long *) ptr_to, val_long);

				/* Move on ptr_from and ptr_to: */
				ptr_from += 2;
				ptr_to += 2;

				break;
			case _FUNC_FIELD:
				/* Load dword (8 bytes) with tags */
				NATIVE_LOAD_VAL_AND_TAGD((long *) ptr_from,
							val_long, tag);

				if ((tag == ETAGEWD) && may_be_uninitialized)
					val_long = 0; /* we don't copy trash */
				/* Check for valid func field */
				else if (likely((pat_rw & 0xf) != _WRITEABLE)
					&& (tag != ETAGPLD) && val_long
					&& (!(rval_mode
					      & CONV_ARR_IGNORE_FUNC_FLD_ERR))
						|| tag) {
#define ERROR_UNEXPECTED_ELEMENTF \
	"not function pointer (tag=0x%x) at struct128[%d]: 0x%lx\n"
					DbgSCP_ALERT(ERROR_UNEXPECTED_ELEMENTF,
						   tag, j, val_long);
					if (rval_mode & CONV_ARR_WRONG_FUNC_FLD)
						rval = -EFAULT;
					if (!CONVERT_WARN_ONLY)
						goto out;
				}
				PUT_USER_OR_KERNEL(user_mode,
						(long *) ptr_to, val_long);

				/* Move on ptr_from and ptr_to: */
				ptr_from += 4;
				ptr_to += 2;

				break;
			case _PTR_FIELD: {
				/*
				 * Load dword (8 bytes) with tags
				 * (the first half of descriptor)
				 */
				NATIVE_LOAD_VAL_AND_TAGD((long *) ptr_from,
							val_long, tag);

				long next_val_long;
				int dtag;
				e2k_ptr_t __ptr__;

				/*
				 * The next dword (8 bytes) is
				 * the second half of descriptor
				 */
				ptr_from += 2;
				NATIVE_LOAD_VAL_AND_TAGD((long *) ptr_from,
							next_val_long, dtag);
				dtag = tag | (dtag << 4);

				/* Copy valid pointer field */
				if ((dtag == ETAGAPQ) ||
					(pat_rw & 0xf) == _WRITEABLE) {
					AW(__ptr__).lo = val_long;
					AW(__ptr__).hi = next_val_long;
					PUT_USER_OR_KERNEL(
						user_mode, (long *) ptr_to,
						E2K_PTR_PTR(__ptr__,
							    GET_SBR_HI()));
					goto eo_ptr_field;
				}
				if ((tag == ETAGEWD) && may_be_uninitialized)
					val_long = 0; /* we don't copy trash */
				/* Something different found: */
				else if ((val_long || next_val_long)
					&& (!(rval_mode
					      & CONV_ARR_IGNORE_DSCR_FLD_ERR))
						|| tag) {
#define ERR_NOT_DSCR \
	"not descriptor (tag=0x%x) at struct128[%d]: 0x%lx : 0x%lx\n"
					DbgSCP_ALERT(ERR_NOT_DSCR, dtag, j,
						val_long, next_val_long);
					if (rval_mode & CONV_ARR_WRONG_DSCR_FLD)
						rval = -EFAULT;
					if (!CONVERT_WARN_ONLY)
						goto out;
				}
				PUT_USER_OR_KERNEL(user_mode,
						(long *) ptr_to, val_long);
eo_ptr_field:
				/* Move on ptr_from and ptr_to: */
				ptr_from += 2;
				ptr_to += 2;

				break;
			}
			case _INT_PTR_FIELD:
			case _LONG_PTR_FIELD: {
				/* Check for descriptor tag in the field: */
				NATIVE_LOAD_VAL_AND_TAGD((long *) ptr_from,
							val_long, tag);
				if (tag == E2K_AP_LO_ETAG)
					/* This must be descriptor: */
					elem_type = _PTR_FIELD;
				else /* This is 'int' or 'long' */
					elem_type &= 0x3;
					/* _INT_PTR_FIELD -> _INT_FIELD */
					/* _LONG_PTR_FIELD -> _LONG_FIELD */
				goto load_current_element;
			}
			case _PTR__FUNC_FIELD: {
				/* Check for descriptor tag in the field: */
				NATIVE_LOAD_VAL_AND_TAGD((long *) ptr_from,
							val_long, tag);
				elem_type = (tag == E2K_AP_LO_ETAG) ? _PTR_FIELD
								: _FUNC_FIELD;
				goto load_current_element;
			}
			case _TAG_DEFINED_FIELD: {
				/* Check for tag in the field: */
				NATIVE_LOAD_VAL_AND_TAGD((long *) ptr_from,
							val_long, tag);
				if (tag == E2K_AP_LO_ETAG)
					elem_type = _PTR_FIELD;
				else if (tag == E2K_PL_ETAG)
					elem_type = _FUNC_FIELD;
				else /* This is 'int' or 'long' */
					elem_type = _INT_FIELD;
				goto load_current_element;
			}
			default:
				/* Otherwise it is something invalid. */
				return -EFAULT;
			}

			/* Fixing ptr_from/ptr_to alignment: */
			alignment = pat_align & 0xf;
			ptr_from = align_ptr_up(ptr_from, /* 128 bit */
						(alignment + 1) * sizeof(int));
			if (alignment)
				ptr_to = align_ptr_up(ptr_to, 8); /* 64 bit */
/*
			DbgSCP("alignment=%d   from->0x%lx  to->0x%lx\n",
			       alignment, (long)ptr_from, (long)ptr_to);
*/
			/* Moving on structure field masks: */
			pat_type >>= 4;
			pat_align >>= 4;
			pat_rw >>= 4;
		}
	}

} CATCH_USR_PFAULT {
#define ERR_FATAL "FATAL ERROR: failed to read from 0x%lx (field %d) !!!\n"
			DbgSCP_ALERT(ERR_FATAL, (long) ptr_from, j);
			return -EFAULT;
} END_USR_PFAULT

	DbgSCP("The array was converted successfully\n");

	if (!arch_init_pm_sc_debug_mode(PM_SC_DBG_MODE_CONV_STRUCT))
		goto out;
	/* Printing out the converted array content: */
	ptr_to = (int *) new_array;
	for (i = 0; i < items; i++) {
		pat_type = mask_type;
		pat_align = mask_align;
		for (j = 0; j < fields; j++) {
			pr_info("convert_array struct128[%d]=",
				i * fields + j);
			/* Outputs a field based upon mask_type */
			switch (pat_type & 0x7) {
			case _INT_FIELD: {
				pr_info("[INT] \t%d / 0x%x\n",
				       *(int *)ptr_to, *(int *)ptr_to);
				ptr_to++;
				break;
			}
			case _LONG_FIELD: {
				pr_info("[LONG]\t%ld / 0x%lx\n",
				       *(long *)ptr_to, *(long *)ptr_to);
				ptr_to += 2;
				break;
			}
			case _FUNC_FIELD: {
				pr_info("[FPTR]\t0x%lx\n",
				       *(unsigned long *)ptr_to);
				ptr_to += 2;
				break;
			}
			case _INT_PTR_FIELD:
			case _LONG_PTR_FIELD:
			case _PTR_FIELD: {
				pr_info("[PTR] \t0x%lx\n",
				       *(unsigned long *)ptr_to);
				ptr_to += 2;
				break;
			}
			default:
				/* Otherwise it is something invalid. */
				pr_err("Error in %s print:\n", __func__);
				pr_err("\t\titem=%d field=%d pat_type=%d\n",
					 i, j, (int)pat_type & 0xf);
			}
			/* Check for correct alignment: */
			if ((pat_align & 0xf) != _INT_ALIGN)
				if ((unsigned long)ptr_to & 0x7)
					ptr_to++; /* even address */
			pat_type >>= 4;
			pat_align >>= 4;
		}
	}
	struct_len = ((unsigned long) ptr_to - (unsigned long) new_array)
			/ sizeof(int); /* in words */
	ptr_to = (int *)new_array;
	pr_info("%s: sizeof(ptr_to=0x%lx) = %d (words):\n",
		__func__, (long) ptr_to, struct_len);
	for (i = 0; i < struct_len; i++) {
		pr_info("\t0x%.8x\n", *ptr_to);
		ptr_to++;
	}

out:
	if (failed_2_write) {
#define ERR_FATAL_WRITE "FATAL ERROR: failed to write at 0x%lx (field %d) !!!\n"
		DbgSCP_ALERT(ERR_FATAL_WRITE, (long) ptr_to, j /*field*/);

	}

	return rval;
}


/*
 * This function checks protected syscall arguments on correspondence with
 * the given mask:
 * args_array - pointer to argument array (tag-less)
 * tags - argument tags (4 bits per arg; lower to higher bits ordered)
 * arg_num - number of arguments
 * mask_type - mask for encoding of field type in each element
 * 4 bits per each entry:
 * --- 00 (0x0) - int
 * --- 01 (0x1) - long
 * --- 10 (0x2) - pointer to function
 * --- 11 (0x3) - pointer to memory
 * --- 0100 (0x4) - descriptor or int
 * --- 0101 (0x5) - descriptor or long
 * rval_mode - error (return value) reporting mode mask:
 *	0 - report only critical problems;
 *	1 - return with -EFAULT if wrong tag in 'int' field;
 *	2 -         --'--           --'--       'long' field;
 *	4 -         --'--           --'--       'func' field;
 *	8 -         --'--           --'--       'descr' field;
 *	16 - ignore errors in 'int' field;
 *	32 -  --'--   --'--   'long' field;
 *	64 -  --'--   --'--   'func' field;
 *	128 - --'--   --'--   'descr' field.
 * Returns: 0 - if converted OK;
 *     error number - otherwise.
 */
extern int check_args_array4(const long *args_array,
			     const long arg_tags,
			     const int arg_num,
			     const long mask_type,
			     const int rval_mode,
			     const char *ErrMsgHeader)
{
	long arg_types;
	long *argument;
	long tag;
	unsigned long pm_sc_debug_mode = current->mm->context.pm_sc_debug_mode;
	int rval = 0; /* result of the function */
	int  j, t, uninit;

	DbgSCP("args_array=0x%lx, tags=0x%lx, arg_num=%d, mask_type=x%lx\n",
		args_array, arg_tags, arg_num, mask_type);

	/* Check main parameters for validity */
	if (!args_array || !arg_num) {
		DbgSCP_ERR("Wrong parameters for %s\n", __func__);
		return -EINVAL;
	}

	/* Checking for correctness of each argument type: */
	argument = (long *) args_array;
	tag = arg_tags;
	arg_types = mask_type;
	for (j = 0; j < arg_num;
	     j++, argument += 2, tag >>= 8, arg_types >>= 4) {

		uninit = arg_types & _UNINITIALIZED_FIELD;
		t = tag & 0xf;
		switch (arg_types & 0x7) {
		case _INT_FIELD:
			if ((t == ETAGNUM) || ((t == ETAGEWS) && uninit))
				break;
			if (!(rval_mode & CONV_ARR_IGNORE_INT_FLD_ERR)) {
#define ERROR_UNEXPECTED_ARG_TYPE_I \
	"unexpected value (tag=0x%lx) at arg #%d: %d\n"
				DbgSCP_ERRMSG(ErrMsgHeader,
					      ERROR_UNEXPECTED_ARG_TYPE_I,
					(tag & 0xf), j + 1, (int) *argument);
				if (rval_mode & CONV_ARR_WRONG_INT_FLD)
					rval = -EFAULT;
			}
			break;
		case _LONG_FIELD:
			if ((t == ETAGNUM) || ((t == ETAGEWD) && uninit))
				break;
			if (!(rval_mode & CONV_ARR_IGNORE_LONG_FLD_ERR)) {
#define ERROR_UNEXPECTED_ARG_TYPE_L \
	"unexpected value (tag=0x%lx) at arg #%d: %ld\n"
				DbgSCP_ERRMSG(ErrMsgHeader,
					      ERROR_UNEXPECTED_ARG_TYPE_L,
					   (tag & 0xf), j + 1, *argument);
				if (rval_mode & CONV_ARR_WRONG_LONG_FLD)
					rval = -EFAULT;
			}
			break;
		case _FUNC_FIELD:
			if ((t == ETAGPLD) || ((t == ETAGEWD) && uninit))
				break;
			if (*argument
				&& (!(rval_mode & CONV_ARR_IGNORE_FUNC_FLD_ERR))
				|| (tag & 0xf)) {
#define ERROR_UNEXPECTED_ARG_TYPE_F \
	"not function pointer (tag=0x%lx) at prot_array[%d]: %ld\n"
				DbgSCP_ERRMSG(ErrMsgHeader,
					      ERROR_UNEXPECTED_ARG_TYPE_L,
					   (tag & 0xf), j + 1, *argument);
				if (rval_mode & CONV_ARR_WRONG_FUNC_FLD)
					rval = -EFAULT;
				if (!CONVERT_WARN_ONLY)
					goto out;
			}
			break;
		case _PTR_FIELD: {
			long val_long, next_val_long;
			int dtag;

			dtag = tag & 0xff;

			if ((dtag == ETAGAPQ) || ((t == ETAGEWD) && uninit))
				break;
			/* Something different found: */
			val_long = *argument;
			next_val_long = *(argument + 1);
			if ((val_long || next_val_long)
				&& (!(rval_mode
				      & CONV_ARR_IGNORE_DSCR_FLD_ERR))
					|| dtag) {
#define ERR_NOT_DSCR_P \
	"not descriptor (tag=0x%x) at arg #%d: 0x%lx : 0x%lx\n"
				DbgSCP_ERRMSG(ErrMsgHeader,
					      ERR_NOT_DSCR_P, dtag, j + 1,
					val_long, next_val_long);
				if (rval_mode & CONV_ARR_WRONG_DSCR_FLD)
					rval = -EFAULT;
				if (!CONVERT_WARN_ONLY)
					goto out;
			}
			break;
		case _INT_PTR_FIELD:
		case _LONG_PTR_FIELD:
			/* any type may be over here */
			break;
		}
		default:
			/* Otherwise it is something invalid. */
			return -EFAULT;
		}
	}
out:
	return rval;
}


static inline
unsigned long get_mask4_from_mask2(unsigned long mask2)
{
	unsigned long mask4 = 0;
	int i;

	for (i = 0; mask2; i++, mask2 >>= 2)
		mask4 |= (mask2 & 0x3) << (i * 4);
	if (current->mm->context.pm_sc_debug_mode & PM_SC_DBG_MODE_CONV_STRUCT)
		pr_info("%s : mask4  = 0x%lx\n", __func__, mask4);
	return mask4;
}

/* This function realizes old mask format with 2 bits per structure field */

extern int convert_array_3(long __user *prot_array, long *new_array,
			 const int max_prot_array_size,
			 const int fields, const int items,
			 unsigned long mask_type, unsigned long mask_align,
			 unsigned long mask_rw, const int rval_mode)
{
	long mask_type4, mask_align4, mask_rw4;

	mask_type4 = get_mask4_from_mask2(mask_type);
	mask_align4 = get_mask4_from_mask2(mask_align);
	mask_rw4 = get_mask4_from_mask2(mask_rw);

	return get_pm_struct(prot_array, new_array,
				max_prot_array_size, fields, items,
				mask_type4, mask_align4, mask_rw4, rval_mode);
}

/* This function realizes old mask format with 2 bits per structure field */

extern int check_args_array(const long *args_array,
			    const long	arg_tags,
			    const int	arg_num,
			    unsigned long mask_type,
			    const int	rval_mode,
			    const char *ErrMsgHeader)
{
	long mask_type4;

	mask_type4 = get_mask4_from_mask2(mask_type);

	return check_args_array4(args_array, arg_tags, arg_num,
				mask_type4, rval_mode, ErrMsgHeader);
}

#endif /* CONFIG_PROTECTED_MODE */
