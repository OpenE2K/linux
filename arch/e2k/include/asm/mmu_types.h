#ifndef _E2K_MMU_TYPES_H_
#define _E2K_MMU_TYPES_H_


/* This is definition of MMU TRAP_CELLAR types */

struct mmu_tc_dst {
	unsigned address	:8;	// [0-7]
	unsigned vr		:1;	// [8]
	unsigned vl		:1;	// [9]
};

typedef union {
	unsigned word;
	struct   mmu_tc_dst fields;
} tc_dst_t;

/* Maximum size for memory access from single channel is 8
 * (16 since e8c2) */
#define E2K_MAX_FORMAT 16
struct mmu_tc_opcode {
	unsigned fmt		:3;	// [0-2]
	unsigned npsp		:1;	// [3]
};

typedef union {
	unsigned word;
	struct   mmu_tc_opcode fields;
} tc_opcode_t;

struct mmu_tc_fault_type {
	unsigned global_sp		:1;	/* [35] */
	unsigned page_bound		:1;	/* [36] */
	unsigned exc_mem_lock		:1;	/* [37] */
	unsigned ph_pr_page		:1;	/* [38] */
	unsigned io_page		:1;	/* [39] */
	unsigned isys_page		:1;	/* [40] */
	unsigned prot_page		:1;	/* [41] */
	unsigned priv_page		:1;	/* [42] */
	unsigned illegal_page		:1;	/* [43] */
	unsigned nwrite_page		:1;	/* [44] */
	unsigned page_miss		:1;	/* [45] */
	unsigned ph_bound		:1;	/* [46] */
	unsigned intl_res_bits		:1;	/* [47] */
};

typedef union {
	unsigned word;
	struct   mmu_tc_fault_type fields;
} tc_fault_type_t;

struct mmu_tc_cond_dword {
	unsigned dst		:10;	// [0-9]
	unsigned opcode		:4;	// [10-13]
	unsigned r0		:3;	// [14-16]
	unsigned store		:1;	// [17]
	unsigned mode_80	:1;	// [18]
	unsigned s_f		:1;	// [19]
	unsigned mas		:7;	// [20-26]
	unsigned root		:1;	// [27]
	unsigned scal		:1;	// [28]
	unsigned sru		:1;	// [29]
	unsigned spec		:1;	// [30]
	unsigned pm		:1;	// [31]
	unsigned chan		:2;	// [32-33]
	unsigned r1		:1;	// [34]
	unsigned fault_type	:13;	// [35-47]
	unsigned miss_lvl	:2;	// [48-49]
	unsigned num_align	:1;	// [50]
	unsigned empt		:1;	// [51]
	unsigned clw		:1;	// [52]
	unsigned dst_rcv	:10;	// [53-62]
	unsigned rcv		:1;	// [63]
};

typedef union {
	unsigned long word;
	struct mmu_tc_cond_dword fields;
} tc_cond_t;

/* Trap cellar flags */

#define TC_DONE_FLAG		0x1
#define TC_NESTED_EXC_FLAG	0x2

/*
 * Trap cellar as it is in hardware plus additional fields
 */
typedef struct {
	unsigned long	address;
	unsigned long	data;
	tc_cond_t	condition;
	unsigned char	flags;
} trap_cellar_t;

/*
 * Trap cellar as it is in hardware
 */
typedef struct {
	unsigned long	address;
	unsigned long	data;
	tc_cond_t	condition;
} kernel_trap_cellar_t;

/*
 * Second operand of Load and Store recovery instruction (LDRD & STRD):
 *
 *	operation code and MAS flags
 */

typedef struct ld_st_rec_opcode {
	unsigned long index	: LDST_REC_OPC_INDEX_SIZE;	// [31- 0]
	unsigned long mas	: LDST_REC_OPC_MAS_SIZE;	// [38-32]
	unsigned long prot	: LDST_REC_OPC_PROT_SIZE;	//    [39]
	unsigned long fmt	: LDST_REC_OPC_FMT_SIZE;	// [42-40]
	unsigned long root	: LDST_REC_OPC_ROOT_SIZE;	//    [43]
	unsigned long rg	: LDST_REC_OPC_RG_SIZE;		// [51-44]
	unsigned long unused	: LDST_REC_OPC_UNUZED_SIZE;	// [63-52]
} ld_st_rec_opcode_t;

typedef union {
	unsigned long word;
	ld_st_rec_opcode_t fields;
} ldst_rec_op_t;

#endif /* _E2K_MMU_TYPES_H_ */
