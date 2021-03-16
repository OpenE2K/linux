/*
 * convert_array.h - Linux syscall interfaces (arch-specific)
 *
 * Copyright (c) 2019 MCST
 *
 * This file is released under the GPLv2.
 * See the file COPYING for more details.
 */

#ifndef _ASM_E2K_UAPI_CONVERT_ARRAY_H
#define _ASM_E2K_UAPI_CONVERT_ARRAY_H


#ifdef CONFIG_PROTECTED_MODE

#define convert_array(prot_array, new_array, max_prot_array_size, fields, \
			 items, mask_type, mask_align) \
	convert_array_3(prot_array, new_array, max_prot_array_size, fields, \
			 items, mask_type, mask_align, 0, 0)

extern int convert_array_3(long __user *prot_array, long *new_array,
			 const int max_prot_array_size, const int fields,
			 const int items, const long mask_type,
			 const long mask_align, const long mask_rw,
			 const int rval_mode);
/*
 * Converts the given array of structures, which can contain
 * protected user pointers to memory, function descriptors, and int values.
 * prot_array - pointer to the original (user-space) array
 * new_array  - pointer to area where to put converted array
 * max_prot_array_size - the maximum size, which prot_array can occupy
 * fileds     - number of enries in each element
 * items      - number of identical elements in the array to convert
 * mask_type  - mask for encoding of field type in each element:
 *	 2 bits per each entry:
 *	 --- 00 (0x0) - int
 *	 --- 01 (0x1) - long
 *	 --- 10 (0x2) - pointer to function
 *	 --- 11 (0x3) - pointer to memory (descriptor)
 * mask_align - mask for encoding of alignment of the NEXT! field
 *	 2 bits per each entry:
 *	 --- 00 (0x0) - next field aligned as int (to 4 bytes)
 *	 --- 01 (0x1) - next field aligned as long (to 8 bytes)
 *	 --- 10 (0x2) - not used yet
 *	 --- 11 (0x3) - next field aligned as pointer (to 16 bytes)
 * mask_rw - mask for encoding access type of the structure elements
 * 2 bits per each entry:
 * --- 01 (0x1) - the field's content gets read by syscall (READ-able)
 * --- 02 (0x2) - the field's content gets updated by syscall (WRITE-able)
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

#define CONV_ARR_WRONG_INT_FLD   1
#define CONV_ARR_WRONG_LONG_FLD  2
#define CONV_ARR_WRONG_FUNC_FLD  4
#define CONV_ARR_WRONG_DSCR_FLD  8
#define CONV_ARR_WRONG_ANY_FLD  15 /* error if any field appeared bad */
#define CONV_ARR_IGNORE_INT_FLD_ERR  16
#define CONV_ARR_IGNORE_LONG_FLD_ERR 32
#define CONV_ARR_IGNORE_FUNC_FLD_ERR 64
#define CONV_ARR_IGNORE_DSCR_FLD_ERR 128


extern int check_args_array(const long __user *args_array,
			    const long tags,
			    const int arg_num,
			    const long mask_type,
			    const int rval_mode,
			    const char *ErrMsgHeader);

/*
 * This function checks protected syscall arguments on correspondence with
 * the given mask:
 * args_array - pointer to argument array
 * tags - argument tags (4 bits per arg; lower to higher bits ordered)
 * arg_num - number of arguments
 * mask_type - mask for encoding of field type in each element
 * 2 bits per each entry:
 * --- 00 (0x0) - int
 * --- 01 (0x1) - long
 * --- 10 (0x2) - pointer to function
 * --- 11 (0x3) - pointer to memory.
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

#else
# define convert_array(...)		0
#endif /* CONFIG_PROTECTED_MODE */

#endif /* _ASM_E2K_UAPI_CONVERT_ARRAY_H */
