/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Linux syscall interfaces (arch-specific)
 */

#ifndef _ASM_E2K_UAPI_CONVERT_ARRAY_H
#define _ASM_E2K_UAPI_CONVERT_ARRAY_H


#ifdef CONFIG_PROTECTED_MODE

/* New mask format: 4 bits per structure field */
#define get_pm_struct_simple(struct128, struct64,	\
			max_prot_array_size, fields, \
			items, mask_type, mask_align) \
	get_pm_struct(struct128, struct64,	\
			max_prot_array_size, fields, \
			items, mask_type, mask_align, 0, 0)


extern int get_pm_struct(const void	__user *struct128,
			 void		__user *struct64,
			 const int max_prot_array_size, const int fieldnum,
			 const int items, const long mask_type,
			 const long mask_align, const long mask_rw,
			 const int rval_mode);
/*
 * Converts protected structure (array of structures), which can contain
 * protected user pointers to memory, function descriptors, and int values.
 * struct128 - pointer to the protected (user-space) structure (128 bit).
 * struct64  - pointer to allocated area where to put converted structure.
 * max_prot_array_size - estimated maximum size, which struct128 occupies
 * filednum   - number of fields in the given structure.
 * items      - number of elements (structures) in array (items == array size)
 *              if 'struct128' is array of structures to be converted.
 * mask_type  - mask for encoding structure field types:
 *	(4 bits per each entry):
 *	--- 0000 (0x0) - int
 *	--- 0001 (0x1) - long
 *	--- 0010 (0x2) - Fptr (pointer to function)
 *	--- 0011 (0x3) - descriptor (pointer to memory)
 *	--- 0100 (0x4) - descriptor or int
 *	--- 0101 (0x5) - descriptor or long
 *	--- 0110 (0x6) - descriptor or Fptr
 *	--- 0111 (0x7) - everything is possible (i/P/F)
 *	--- 1*** (0x8) - may be uninitialized (empty tag allowed)
 * mask_align - mask for encoding alignment of the NEXT (!!!) structure field;
 *		for example, bits #0-3 code alignment of the 2nd structure field
 *	(4 bits per each entry):
 *	--- 00 (0x0) - next field aligned as int (to 4 bytes)
 *	--- 01 (0x1) - next field aligned as long (to 8 bytes)
 *	--- 10 (0x2) - not used yet
 *	--- 11 (0x3) - next field aligned as pointer (to 16 bytes)
 * mask_rw - mask for encoding access type of structure fields
 *	(4 bits per each entry):
 *	--- 01 (0x1) - the field's content gets read by syscall (READ-able)
 *	--- 02 (0x2) - the field's content gets updated by syscall (WRITE-able)
 *	--- 11 (0x3) - the field is both READ-able and WRITE-able
 *	--- 00 (0x0) - default type; the same as (READ-able)
 * rval_mode - error (return value) reporting mode mask:
 *	0 - report only critical problems in struct128 structure;
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


/* This function realizes compact mask format: 2 bits per structure field */
extern int convert_array_3(const void	__user *prot_array,
			   void		__user *new_array,
			 const int max_prot_array_size, const int fields,
			 const int items, unsigned long mask_type,
			 unsigned long mask_align, unsigned long mask_rw,
			 const int rval_mode);


/* This is deprecated. Not recommended to use.
 * Old mask format: 2 bits per structure field
 */
#define convert_array(prot_array, new_array, max_prot_array_size, fields, \
			items, mask_type, mask_align) \
	convert_array_3(prot_array, new_array, max_prot_array_size, fields, \
			items, mask_type, mask_align, 0, 0)

#else
# define convert_array(...)		0
#endif /* CONFIG_PROTECTED_MODE */

#endif /* _ASM_E2K_UAPI_CONVERT_ARRAY_H */
