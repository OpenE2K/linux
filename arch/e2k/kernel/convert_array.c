/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * This is a utility to support interactions between kernel and E2K protected mode user layer.
 *
 * The function 'convert_array' converts complex protected area structures,
 * which can contain protected user pointers to memory (descriptors),
 * and/or function pointers (descriptors), into regular C-structures
 * (non-protected).
 */

// #define pr_fmt(fmt) "%s:%d : " fmt, __FILE__, __LINE__

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
void __user *align_user_ptr_up(void __user *ptr, const int alignment)
{
	if ((uintptr_t) ptr & (alignment - 1))
		ptr += alignment - ((uintptr_t)ptr & (alignment - 1));
	return ptr;
}

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
#define ERR_FATAL "FATAL ERROR: failed to read from 0x%lx (field %d) !!!\n"
int get_pm_struct(const void	__user *prot_array,
		  void		__user *new_array,
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
	long pat_type, pat_align, pat_rw;
	u64 val_long, next_val_long;
	int __user *ptr_from;
	int __user *ptr_to;
	int user_mode = 0;
	int may_be_uninitialized;
	int misaligned_ptr_from = 0; /* normally ptr_from must be aligned */
	int rval = 0; /* result of the function */
	int failed_2_write = 0;
	int val_int, tag, dtag;
	int i, j;
#if (DYNAMIC_DEBUG_SYSCALLP_ENABLED)
	unsigned long pm_sc_debug_mode = current->mm->context.pm_sc_debug_mode;
#endif /* DYNAMIC_DEBUG_SYSCALLP_ENABLED */

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
		pr_err("pid#%d: Wrong (empty) argument set for %s(fields=%d, items=%d)\n",
			current->pid, __func__, fields, items);
		return -EINVAL;
	}

	if ((uintptr_t)prot_array & 0x7) {
		PROTECTED_MODE_ALERT(PMSCERRMSG_STRUCT_UNALIGNED_DESCR,
				     __func__, prot_array);
		PM_EXCEPTION_IF_ORTH_MODE(SIGILL, ILL_ILLOPN, EINVAL);
		return -EINVAL;
	}

	/* Counting protected structure size: */
	pat_align = mask_align;
	struct_len = 0;
	ptr_from = (int __user *) prot_array;

	for (i = 0; i < fields; i++) {
		alignment = ((pat_align & 0xf) + 1) * sizeof(int);
		if (((unsigned long) ptr_from) % alignment) {
			misaligned_ptr_from = 1;
			struct_len += ((((unsigned long) ptr_from
				+ alignment - 1) & ~(alignment - 1))
				- ((unsigned long) ptr_from));
			ptr_from = (int __user *) (((unsigned long) ptr_from
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
		PROTECTED_MODE_ALERT(PMCNVSTRMSG_STRUCT_SIZE_EXCEEDS_MAX,
				     __func__, prot_len, max_prot_array_size);
		if (misaligned_ptr_from)
			protected_mode_message(0, PMCNVSTRMSG_STRUCT_DESCR_UNALIGNED,
					     __func__, "prot_array", prot_array);
		PM_EXCEPTION_IF_ORTH_MODE(SIGILL, ILL_ILLOPN, EINVAL);
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
			pr_err("pid#%d Copying original structure (0x%lx : %d) failed\n",
			       current->pid, (long) lptr, prot_len);
			kfree(lptr);
			rval = -EFAULT;
			goto out;
		}
		pr_info("%s: sizeof(struct128) = %zd (words):\n",
			__func__, items * (struct_len / sizeof(int)));
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
	ptr_to = (int __user *) new_array;
	if ((long) ptr_to < TASK_SIZE) {
		user_mode = 1;
	}

	/* Detailed analysis of data encoded in the input structure(s): */
	for (i = 0; i < items; i++) {
		ptr_from = (int __user *)((uintptr_t) prot_array + struct_len * i);
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
				if (get_user_tagged_4(val_int, tag, ptr_from)) {
					PROTECTED_MODE_ALERT(PMSCERRMSG_STRUCT_FAILED_TO_READ_FIELD,
							__func__, (long) ptr_from, j);
					return -EFAULT;
				}

				if ((tag == ETAGEWS) && may_be_uninitialized) {
					val_int = 0; /* we don't copy trash */
				} else if (likely((pat_rw & 0xf) != _WRITEABLE) &&
						tag != ETAGNUM &&
						!(rval_mode & CONV_ARR_IGNORE_INT_FLD_ERR)) {
					/* Check for valid 'int' field failed */
					if (tag == ETAGEWS) {
						PROTECTED_MODE_ALERT(
							PMSCERRMSG_STRUCT_UNINIT_INT_FIELD,
							((uintptr_t) prot_array + struct_len * i),
							tag, j, (long) val_int);
						PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL,
									  EINVAL);
					} else {
						PROTECTED_MODE_ALERT(
							PMSCERRMSG_STRUCT_BAD_TAG_INT_FIELD,
							((uintptr_t) prot_array + struct_len * i),
							tag, j, (long) val_int);
						PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL,
									  EINVAL);
					}
					/* Don't copy field of another type */
					if (val_int && (!CONVERT_WARN_ONLY)) {
						protected_mode_message(0,
							PMSCERRMSG_STRUCT_FIELD_VAL_IGNORED, i);
						val_int = 0;
					}
					if (rval_mode & CONV_ARR_WRONG_INT_FLD)
						rval = -EFAULT;
				}
				if ((long) ptr_to & 1) { /* write at higher word */
					put_user(val_int, ptr_to);
				} else { /* write at lower word */
					/* NB> To avoid trash in higher word,
					 *     we save it as long val.
					 */
					val_long = (long) val_int;
					put_user(val_long, (long __user *) ptr_to);
				}

				/* Move on ptr_from and ptr_to: */
				ptr_from++;
				ptr_to++;

				break;
			case _LONG_FIELD:
				/* Load dword (8 bytes) with tags */
				if (get_user_tagged_8(val_long, tag, (u64 __user *) ptr_from)) {
					PROTECTED_MODE_ALERT(PMSCERRMSG_STRUCT_FAILED_TO_READ_FIELD,
							__func__, (long) ptr_from, j);
					return -EFAULT;
				}

				if ((tag == ETAGEWD) && may_be_uninitialized) {
					val_long = 0; /* we don't copy trash */
				} else if (likely((pat_rw & 0xf) != _WRITEABLE) &&
						tag != ETAGNUM &&
						!(rval_mode & CONV_ARR_IGNORE_LONG_FLD_ERR)) {
					/* Check for valid 'long' field failed */
					if (tag == ETAGEWD) {
						PROTECTED_MODE_ALERT(
							PMSCERRMSG_STRUCT_UNINIT_INT_FIELD,
							((uintptr_t) prot_array + struct_len * i),
							tag, j, val_long);
						PM_EXCEPTION_IF_ORTH_MODE(SIGILL, ILL_ILLOPN,
									  EINVAL);
					} else {
						PROTECTED_MODE_ALERT(
							PMSCERRMSG_STRUCT_BAD_TAG_INT_FIELD,
							((uintptr_t) prot_array + struct_len * i),
							tag, j, val_long);
						PM_EXCEPTION_IF_ORTH_MODE(SIGILL, ILL_ILLOPN,
									  EINVAL);
					}
					/* Don't copy field of another type */
					if (val_long && (!CONVERT_WARN_ONLY)) {
						protected_mode_message(0,
							PMSCERRMSG_STRUCT_FIELD_VAL_IGNORED, i);
						val_long = 0;
					}
					if (rval_mode & CONV_ARR_WRONG_LONG_FLD)
						rval = -EFAULT;
				}
				put_user(val_long, (long __user *) ptr_to);

				/* Move on ptr_from and ptr_to: */
				ptr_from += 2;
				ptr_to += 2;

				break;
			case _FUNC_FIELD:
				/* Load func.pointer (two dwords - 16 bytes) with tags */
				if (get_user_tagged_16(val_long, next_val_long, dtag, ptr_from)) {
					PROTECTED_MODE_ALERT(PMSCERRMSG_STRUCT_FAILED_TO_READ_FIELD,
							__func__, (long) ptr_from, j);
					return -EFAULT;
				}
				tag = dtag & 0xf;

				if ((tag == ETAGEWD) && may_be_uninitialized) {
					val_long = 0; /* we don't copy trash */
				} else if (tag || likely((pat_rw & 0xf) != _WRITEABLE) &&
						dtag != ETAGPLD && dtag != ETAGPLQ && val_long &&
						!(rval_mode & CONV_ARR_IGNORE_FUNC_FLD_ERR)) {
					/* Check for valid func field failed */
					PROTECTED_MODE_ALERT(
						PMSCERRMSG_STRUCT_NOT_PL_IN_FIELD,
						((uintptr_t) prot_array + struct_len * i),
						tag, j, val_long);
					if (rval_mode & CONV_ARR_WRONG_FUNC_FLD)
						rval = -EFAULT;
					if (!CONVERT_WARN_ONLY)
						goto out;
				}
				put_user(val_long, (long __user *) ptr_to);

				/* Move on ptr_from and ptr_to: */
				ptr_from += 4;
				ptr_to += 2;

				break;
			case _PTR_FIELD: {
				e2k_ptr_t __ptr__;

				/* Load descriptor (two dwords - 16 bytes) with tags: */
				if (get_user_tagged_16(val_long, next_val_long, dtag, ptr_from)) {
					PROTECTED_MODE_ALERT(PMSCERRMSG_STRUCT_FAILED_TO_READ_FIELD,
							__func__, (long) ptr_from, j);
					return -EFAULT;
				}
				tag = dtag & 0xf;

				/* Copy valid pointer field */
				if ((dtag == ETAGAPQ) ||
					(pat_rw & 0xf) == _WRITEABLE) {
					__ptr__.lo = val_long;
					__ptr__.hi = next_val_long;
					put_user(E2K_PTR_PTR(__ptr__),
						 (long __user *) ptr_to);
					goto eo_ptr_field;
				}
				if ((tag == ETAGEWD) && may_be_uninitialized)
					val_long = 0; /* we don't copy trash */
				/* Something different found: */
				else if (tag || (val_long || next_val_long) &&
						!(rval_mode & CONV_ARR_IGNORE_DSCR_FLD_ERR)) {
					PROTECTED_MODE_ALERT(
						PMSCERRMSG_STRUCT_NOT_DSCR_IN_FIELD,
						((uintptr_t) prot_array + struct_len * i),
						dtag, j, val_long, next_val_long);
					if (rval_mode & CONV_ARR_WRONG_DSCR_FLD)
						rval = -EFAULT;
					if (!CONVERT_WARN_ONLY)
						goto out;
				}
				put_user(val_long, (long __user *) ptr_to);
eo_ptr_field:
				/* Move on ptr_from and ptr_to: */
				ptr_from += 4;
				ptr_to += 2;

				break;
			}
			case _INT_PTR_FIELD:
			case _LONG_PTR_FIELD: {
				/* Check for descriptor tag in the field: */
				if (get_user_tagged_8(val_long, tag, (long __user *) ptr_from)) {
					PROTECTED_MODE_ALERT(PMSCERRMSG_STRUCT_FAILED_TO_READ_FIELD,
							__func__, (long) ptr_from, j);
					return -EFAULT;
				}
				if (tag == E2K_AP_LO_ETAG) {
					/* This must be descriptor: */
					elem_type = _PTR_FIELD;
				} else {/* This is 'int' or 'long' */
					elem_type &= 0x3;
					/* _INT_PTR_FIELD -> _INT_FIELD */
					/* _LONG_PTR_FIELD -> _LONG_FIELD */
				}
				goto load_current_element;
			}
			case _PTR__FUNC_FIELD: {
				/* Check for descriptor tag in the field: */
				u64 next_val_long;
				if (get_user_tagged_16(val_long, next_val_long,
						tag, (long __user *) ptr_from)) {
					PROTECTED_MODE_ALERT(PMSCERRMSG_STRUCT_FAILED_TO_READ_FIELD,
							__func__, (long) ptr_from, j);
					return -EFAULT;
				}
				elem_type = (tag == ETAGAPQ) ? _PTR_FIELD : _FUNC_FIELD;
				goto load_current_element;
			}
			case _TAG_DEFINED_FIELD: {
				/* Check for tag in the field: */
				u64 next_val_long;
				if (!IS_ALIGNED((unsigned long) ptr_from, 16) &&
				    get_user_tagged_8(val_long, tag, (long __user *) ptr_from) ||
				    IS_ALIGNED((unsigned long) ptr_from, 16) &&
				    get_user_tagged_16(val_long, next_val_long,
						tag, (long __user *) ptr_from)) {
					PROTECTED_MODE_ALERT(PMSCERRMSG_STRUCT_FAILED_TO_READ_FIELD,
							__func__, (long) ptr_from, j);
					return -EFAULT;
				}
				tag &= 0xf;
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
			ptr_from = align_user_ptr_up(ptr_from, /* 128 bit */
						(alignment + 1) * sizeof(int));
			if (alignment)
				ptr_to = align_user_ptr_up(ptr_to, 8); /* 64 bit */
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

	DbgSCP("The structure was converted successfully\n");

	if (arch_init_pm_sc_debug_mode(PM_SC_DBG_MODE_CONV_STRUCT) == 0)
		goto out;
	/* Printing out the converted array content: */
	ptr_to = (int __user *) new_array;
	for (i = 0; i < items; i++) {
		pat_type = mask_type;
		pat_align = mask_align;
		for (j = 0; j < fields; j++) {
			pr_info("%s struct128[%d]=", __func__, i * fields + j);
			/* Outputs a field based upon mask_type */
			switch (pat_type & 0x7) {
			case _INT_FIELD: {
				if (get_user(val_int, ptr_to))
					goto err_read_to;
				pr_info("[INT] \t%d / 0x%x\n", val_int, val_int);
				ptr_to++;
				break;
			}
			case _LONG_FIELD: {
				if (get_user(val_long, (long __user *) ptr_to))
					goto err_read_to;
				pr_info("[LONG]\t%lld / 0x%llx\n", val_long, val_long);
				ptr_to += 2;
				break;
			}
			case _FUNC_FIELD: {
				if (get_user(val_long, (unsigned long __user *) ptr_to))
					goto err_read_to;
				pr_info("[FPTR]\t0x%llx\n", val_long);
				ptr_to += 2;
				break;
			}
			case _INT_PTR_FIELD:
			case _LONG_PTR_FIELD:
			case _PTR_FIELD: {
				if (get_user(val_long, (unsigned long __user *) ptr_to))
					goto err_read_to;
				pr_info("[PTR] \t0x%llx\n", val_long);
				ptr_to += 2;
				break;
			}
			default:
				/* Otherwise it is something invalid. */
				pr_err("%s:%d : Error in print:\n",
				       __FILE__, __LINE__);
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
	ptr_to = (int __user *)new_array;
	pr_info("%s: sizeof(ptr_to=0x%lx) = %d (words):\n",
		__func__, (long) ptr_to, struct_len);
	for (j = 0; j < struct_len; j++) {
		if (get_user(val_int, ptr_to))
			goto err_read_to;
		pr_info("\t0x%.8x\n", val_int);
		ptr_to++;
	}

out:
	if (failed_2_write) {
		PROTECTED_MODE_ALERT(PMSCERRMSG_FATAL_WRITE_AT_FIELD,
				     __func__, (long) ptr_to, j /*field*/);
		PM_EXCEPTION_IF_ORTH_MODE(SIGILL, ILL_ILLOPN, EINVAL);
	}

	return rval;

err_read_to:
	PROTECTED_MODE_ALERT(PMSCERRMSG_STRUCT_FAILED_TO_READ_FIELD, __func__,
			     (long) ptr_to, j);
	PM_EXCEPTION_IF_ORTH_MODE(SIGILL, ILL_ILLOPN, EINVAL);
	return -EFAULT;
}
EXPORT_SYMBOL(get_pm_struct);



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

int convert_array_3(const void __user *prot_array, void __user *new_array,
		    const int max_prot_array_size, const int fields, const int items,
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

#endif /* CONFIG_PROTECTED_MODE */
