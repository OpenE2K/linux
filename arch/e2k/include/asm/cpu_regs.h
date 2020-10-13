#ifndef	_E2K_CPU_REGS_H_
#define	_E2K_CPU_REGS_H_

#ifdef __KERNEL__

#include <asm/types.h>

#ifndef __ASSEMBLY__
#include <asm/e2k.h>

/*
 * Read/Write Pointer (RWP) (64 bits)
 */
typedef	struct e2k_rwp_fields {		/* Structure of Read/write pointer */
	u64	base	: E2K_VA_SIZE;		/* [47: 0] */
	u64	unused2	: 53 - E2K_VA_MSB;	/* [53:48] */
	u64	stub5	:  1;			/* [54] */
	u64	stub4	:  1;			/* [55] */
	u64	stub3	:  1;			/* [56] */
	u64	stub2	:  1;			/* [57] */
	u64	stub1	:  1;			/* [58] */
	u64	unused	:  5;			/* [63:59] */
} e2k_rwp_fields_t;
typedef	union e2k_rwp_struct {		/* Structure of lower word */
	e2k_rwp_fields_t	fields;	/* as fields */
	u64			word;	/* as entire register */
} e2k_rwp_struct_t;
#define	E2K_RWP_stub1		fields.stub1
#define	E2K_RWP_stub2		fields.stub2
#define	E2K_RWP_stub3		fields.stub3
#define	E2K_RWP_stub4		fields.stub4
#define	E2K_RWP_stub5		fields.stub5
#define	E2K_RWP_base		fields.base
#define	E2K_RWP_reg		word

/*
 * Read/Write Array Pointer (RWAP)
 */
typedef	struct e2k_rwap_lo_fields {	/* Fields of lower word */
	u64	base	: E2K_VA_SIZE;		/* [47: 0] */
	u64	unused2	: 55 - E2K_VA_MSB;	/* [55:48] */
	u64	stub3	:  1;			/* [56] */
	u64	stub2	:  1;			/* [57] */
	u64	stub1	:  1;			/* [58] */
	u64	rw	:  2;			/* [60:59] */
	u64	itag	:  3;			/* [63:61] */
} e2k_rwap_lo_fields_t;
typedef	struct e2k_rusd_lo_fields {	/* Fields of lower word */
	u64	base	: E2K_VA_SIZE;		/* [47: 0] */
	u64	unused2	: 57 - E2K_VA_MSB;	/* [57:48] */
	u64	p	:  1;			/* [58] */
	u64	rw	:  2;			/* [60:59] */
	u64	unused	:  3;			/* [63:61] */
} e2k_rusd_lo_fields_t;
typedef	union e2k_rwap_lo_struct {	/* Structure of lower word */
	e2k_rwap_lo_fields_t	ap_fields;	/* as AP fields */
	e2k_rusd_lo_fields_t	fields;		/* as USD fields */
	u64			word;	/* as entire register */
} e2k_rwap_lo_struct_t;
#define	E2K_RWAP_lo_itag	ap_fields.itag
#define	E2K_RWAP_lo_rw		ap_fields.rw
#define	E2K_RWAP_lo_stub1	ap_fields.stub1
#define	E2K_RWAP_lo_stub2	ap_fields.stub2
#define	E2K_RWAP_lo_stub3	ap_fields.stub3
#define	E2K_RWAP_lo_base	ap_fields.base
#define	E2K_RUSD_lo_rw		fields.rw
#define	E2K_RUSD_lo_p		fields.p
#define	E2K_RUSD_lo_p_bit	58	/* do not forget to modify if changed */
#define	E2K_RUSD_lo_base	fields.base
#define	E2K_RWAP_lo_half	word
#define	E2K_RUSD_lo_half	word

typedef	struct e2k_rwap_hi_fields {	/* Fields of high word */
	u64	curptr	: 32;			/* [31: 0] */
	u64	size	: 32;			/* [63:32] */
} e2k_rwap_hi_fields_t;
typedef	struct e2k_rpsp_hi_fields {	/* Fields of high word */
	u64	ind	: 32;			/* [31: 0] */
	u64	size	: 32;			/* [63:32] */
} e2k_rpsp_hi_fields_t;
typedef	union e2k_rwap_hi_struct {	/* Structure of high word */
	e2k_rwap_hi_fields_t	ap_fields;	/* as AP fields */
	e2k_rpsp_hi_fields_t	fields;		/* as PSP fields */
	u64			word;	/* as entire register */
} e2k_rwap_hi_struct_t;
#define	E2K_RWAP_hi_size	ap_fields.size
#define	E2K_RWAP_hi_curptr	ap_fields.curptr
#define	E2K_RWAP_hi_half	word
#define	E2K_RPSP_hi_size	fields.size
#define	E2K_RPSP_hi_ind		fields.ind
#define	E2K_RPSP_hi_half	word

typedef	struct e2k_rwap_struct {	/* quad-word register */
	e2k_rwap_lo_struct_t	lo;
	e2k_rwap_hi_struct_t	hi;
} e2k_rwap_struct_t;
#define	E2K_RWAP_lo_struct	lo
#define	E2K_RUSD_lo_struct	lo
#define	E2K_RWAP_hi_struct	hi
#define	E2K_RPSP_hi_struct	hi
#define	E2K_RWAP_itag		lo.E2K_RWAP_lo_itag
#define	E2K_RWAP_rw		lo.E2K_RWAP_lo_rw
#define	E2K_RWAP_stub1		lo.E2K_RWAP_lo_stub1
#define	E2K_RWAP_stub2		lo.E2K_RWAP_lo_stub2
#define	E2K_RWAP_stub3		lo.E2K_RWAP_lo_stub3
#define	E2K_RWAP_base		lo.E2K_RWAP_lo_base
#define	E2K_RUSD_rw		lo.E2K_RUSD_lo_rw
#define	E2K_RUSD_p		lo.E2K_RUSD_lo_p
#define	E2K_RUSD_p_bit		E2K_RUSD_lo_p_bit	/* protected flag */
#define	E2K_RUSD_p_flag		(1 << E2K_RUSD_p_bit)	/* as value */
#define	E2K_RUSD_base		lo.E2K_RUSD_lo_base
#define	E2K_RWAP_size		hi.E2K_RWAP_hi_size
#define	E2K_RWAP_curptr		hi.E2K_RWAP_hi_curptr
#define	E2K_RPSP_size		hi.E2K_RPSP_hi_size
#define	E2K_RPSP_ind		hi.E2K_RPSP_hi_ind
#define	E2K_RWAP_lo_reg		lo.E2K_RWAP_lo_half
#define	E2K_RUSD_lo_reg		lo.E2K_RUSD_lo_half
#define	E2K_RWAP_hi_reg		hi.E2K_RWAP_hi_half
#define	E2K_RPSP_hi_reg		hi.E2K_RPSP_hi_half

#define	E2_RWAR_R_ENABLE	0x1
#define	E2_RWAR_W_ENABLE	0x2
#define	E2_RWAR_RW_ENABLE	(E2_RWAR_R_ENABLE | E2_RWAR_W_ENABLE)
#define	E2_RWAR_C_TRUE		0x1

#define	R_ENABLE		0x1
#define	W_ENABLE		0x2
#define	RW_ENABLE		0x3

/*
 * Read/Write Stack Array Pointer (RWSAP)
 */
typedef	struct e2k_rwsap_lo_fields {	/* Fields of lower word */
	u64	base	: 32;			/* [31: 0] */
	u64	psl	: 16;			/* [47:32] */
	u64	unused2	:  8;			/* [55:48] */
	u64	stub3	:  1;			/* [56] */
	u64	stub2	:  1;			/* [57] */
	u64	stub1	:  1;			/* [58] */
	u64	rw	:  2;			/* [60:59] */
	u64	itag	:  3;			/* [63:61] */
} e2k_rwsap_lo_fields_t;
typedef	struct e2k_rpusd_lo_fields {	/* Fields of lower word */
	u64	base	: 32;			/* [31: 0] */
	u64	psl	: 16;			/* [47:32] */
	u64	unused2	: 10;			/* [57:48] */
	u64	p	:  1;			/* [58] */
	u64	rw	:  2;			/* [60:59] */
	u64	unused	:  3;			/* [63:61] */
} e2k_rpusd_lo_fields_t;
typedef	union e2k_rwsap_lo_struct {	/* Structure of lower word */
	e2k_rwsap_lo_fields_t	sap_fields;	/* as SAP fields */
	e2k_rpusd_lo_fields_t	fields;		/* as PUSD fields */
	u64			word;	/* as entire register */
} e2k_rwsap_lo_struct_t;
#define	E2K_RWSAP_lo_itag	sap_fields.itag
#define	E2K_RWSAP_lo_rw		sap_fields.rw
#define	E2K_RWSAP_lo_stub1	sap_fields.stub1
#define	E2K_RWSAP_lo_stub2	sap_fields.stub2
#define	E2K_RWSAP_lo_stub3	sap_fields.stub3
#define	E2K_RWSAP_lo_psl	sap_fields.psl
#define	E2K_RWSAP_lo_base	sap_fields.base
#define	E2K_RPUSD_lo_rw		fields.rw
#define	E2K_RPUSD_lo_p		fields.p
#define	E2K_RPUSD_lo_psl	fields.psl
#define	E2K_RPUSD_lo_base	fields.base
#define	E2K_RWSAP_lo_half	word
#define	E2K_RPUSD_lo_half	word

typedef	struct e2k_rwsap_hi_fields {	/* Fields of high word */
	u64	curptr	: 32;			/* [31: 0] */
	u64	size	: 32;			/* [63:32] */
} e2k_rwsap_hi_fields_t;
typedef	union e2k_rwsap_hi_struct {	/* Structure of high word */
	e2k_rwsap_hi_fields_t	fields;	/* as fields */
	u64			word;	/* as entire register */
} e2k_rwsap_hi_struct_t;
#define	E2K_RWSAP_hi_size	fields.size
#define	E2K_RWSAP_hi_curptr	fields.curptr
#define	E2K_RWSAP_hi_half	word

typedef	struct e2k_rwsap_struct {	/* quad-word register */
	e2k_rwsap_lo_struct_t	lo;
	e2k_rwsap_hi_struct_t	hi;
} e2k_rwsap_struct_t;
#define	E2K_RWSAP_lo_struct	lo
#define	E2K_RPUSD_lo_struct	lo
#define	E2K_RWSAP_hi_struct	hi
#define	E2K_RWSAP_itag		lo.E2K_RWSAP_lo_itag
#define	E2K_RWSAP_rw		lo.E2K_RWSAP_lo_rw
#define	E2K_RWSAP_stub1		lo.E2K_RWSAP_lo_stub1
#define	E2K_RWSAP_stub2		lo.E2K_RWSAP_lo_stub2
#define	E2K_RWSAP_stub3		lo.E2K_RWSAP_lo_stub3
#define	E2K_RWSAP_psl		lo.E2K_RWSAP_lo_psl
#define	E2K_RWSAP_base		lo.E2K_RWSAP_lo_base
#define	E2K_RPUSD_rw		lo.E2K_RPUSD_lo_rw
#define	E2K_RPUSD_p		lo.E2K_RPUSD_lo_p
#define	E2K_RPUSD_psl		lo.E2K_RPUSD_lo_psl
#define	E2K_RPUSD_base		lo.E2K_RPUSD_lo_base
#define	E2K_RWSAP_size		hi.E2K_RWSAP_hi_size
#define	E2K_RWSAP_curptr	hi.E2K_RWSAP_hi_curptr
#define	E2K_RWSAP_lo_reg	lo.E2K_RWSAP_lo_half
#define	E2K_RPUSD_lo_reg	lo.E2K_RPUSD_lo_half
#define	E2K_RWSAP_hi_reg	hi.E2K_RWSAP_hi_half

/*
 * Compilation Unit Descriptor (CUD)
 * describes the memory containing codes of the current compilation unit
 */

	/*
	 * Structure of lower word
	 * access CUD.lo.CUD_lo_xxx or CUD -> lo.CUD_lo_xxx
	 *	or CUD_lo.CUD_lo_xxx or CUD_lo -> CUD_lo_xxx
	 */
typedef	e2k_rwap_lo_struct_t	e2k_cud_lo_t;
#define	_CUD_lo_rw	E2K_RWAP_lo_rw		/* [60:59] - read/write flags */
						/* should be "R" */
#define	E2K_CUD_RW_PROTECTIONS			E2_RWAR_R_ENABLE
#define	CUD_lo_c	E2K_RWAP_lo_stub1	/* [58] - checked flag, */
						/* if set then literal CT */
						/* is correct */
#define	E2K_CUD_CHECKED_FLAG			E2_RWAR_C_TRUE
#define	CUD_lo_base	E2K_RWAP_lo_base	/* [47: 0] - base address */
#define	CUD_lo_half	E2K_RWAP_lo_half	/* [63: 0] - entire lower */
						/* double-word of register */
	/*
	 * Structure of high word
	 * access CUD.hi.CUD_hi_xxx or CUD -> hi.CUD_hi_xxx
	 *	or CUD_hi.CUD_hi_xxx or CUD_hi -> CUD_hi_xxx
	 */
typedef	e2k_rwap_hi_struct_t	e2k_cud_hi_t;
#define	CUD_hi_size	E2K_RWAP_hi_size	/* [63:32] - size */
#define	_CUD_hi_curptr	E2K_RWAP_hi_curptr	/* [31: 0] - should be 0 */
#define	CUD_hi_half	E2K_RWAP_hi_half	/* [63: 0] - entire high */
						/* double-word of register */

	/*
	 * Structure of quad-word register
	 * access CUD.CUD_xxx or CUD -> CUD_xxx
	 */
typedef	e2k_rwap_struct_t	cud_struct_t;
#define	_CUD_rw		E2K_RWAP_rw		/* [60:59] - read/write flags */
						/* should be "R" */
#define	CUD_c		E2K_RWAP_stub1		/* [58] - checked flag, */
						/* if set then literal CT */
						/* is correct */
#define	CUD_base	E2K_RWAP_base		/* [47: 0] - base address */
#define	CUD_size	E2K_RWAP_size		/* [63:32] - size */
#define	_CUD_curptr	E2K_RWAP_curptr		/* [31: 0] - should be 0 */
#define	CUD_lo_reg	E2K_RWAP_lo_reg		/* [63: 0] - entire lower */
						/* double-word of register */
#define	CUD_hi_reg	E2K_RWAP_hi_reg		/* [63: 0] - entire high */
						/* double-word of register */
#define	CUD_lo_struct	E2K_RWAP_lo_struct	/* low register structure */
#define	CUD_hi_struct	E2K_RWAP_hi_struct	/* high register structure */

#define	READ_CUD_LO_REG_VALUE()	E2K_GET_DSREG(cud.lo)
#define	READ_CUD_HI_REG_VALUE()	E2K_GET_DSREG(cud.hi)

#define	WRITE_CUD_LO_REG_VALUE(CUD_lo_value) \
		E2K_SET_DSREG(cud.lo, CUD_lo_value)
#define	WRITE_CUD_HI_REG_VALUE(CUD_hi_value) \
		E2K_SET_DSREG(cud.hi, CUD_hi_value)
#define	WRITE_CUD_REG_VALUE(CUD_hi_value, CUD_lo_value) \
({ \
	WRITE_CUD_HI_REG_VALUE(CUD_hi_value); \
	WRITE_CUD_LO_REG_VALUE(CUD_lo_value); \
})
#endif /* !(__ASSEMBLY__) */

#define	E2K_ALIGN_CODES		12		/* Codes area boundaries */
						/* alignment (2's exponent */
						/* value */
#ifndef __ASSEMBLY__
#define	E2K_ALIGN_CODES_MASK	((1UL << E2K_ALIGN_CODES) - 1)
#else	/* __ASSEMBLY__ */
#define	E2K_ALIGN_CODES_MASK	((1 << E2K_ALIGN_CODES) - 1)
#endif /* !(__ASSEMBLY__) */

#ifndef __ASSEMBLY__
/*
 * Compilation Unit Globals Descriptor (GD)
 * describes the global variables memory of the current compilation unit
 */

	/*
	 * Structure of lower word
	 * access GD.lo.GD_lo_xxx or GD -> lo.GD_lo_xxx
	 *	or GD_lo.GD_lo_xxx or GD_lo -> GD_lo_xxx
	 */
typedef	e2k_rwap_lo_struct_t	e2k_gd_lo_t;
#define	_GD_lo_rw	E2K_RWAP_lo_rw		/* [60:59] - read/write flags */
						/* should be "RW" */
#define	E2K_GD_RW_PROTECTIONS			E2_RWAR_RW_ENABLE;
#define	GD_lo_base	E2K_RWAP_lo_base	/* [47: 0] - base address */
#define	GD_lo_half	E2K_RWAP_lo_half	/* [63: 0] - entire lower */
						/* double-word of register */

	/*
	 * Structure of high word
	 * access GD.hi.GD_hi_xxx or GD -> hi.GD_hi_xxx
	 *	or GD_hi.GD_hi_xxx or GD_hi -> GD_hi_xxx
	 */
typedef	e2k_rwap_hi_struct_t	e2k_gd_hi_t;
#define	GD_hi_size	E2K_RWAP_hi_size	/* [63:32] - size */
#define	_GD_hi_curptr	E2K_RWAP_hi_curptr	/* [31: 0] - should be 0 */
#define	GD_hi_half	E2K_RWAP_hi_half	/* [63: 0] - entire high */
						/* double-word of register */

	/*
	 * Structure of quad-word register
	 * access GD.GD_xxx or GD -> GD_xxx
	 */
typedef	e2k_rwap_struct_t	gd_struct_t;
#define	_GD_rw		E2K_RWAP_rw		/* [60:59] - read/write flags */
						/* should be "RW" */
#define	GD_base		E2K_RWAP_base		/* [47: 0] - base address */
#define	GD_size		E2K_RWAP_size		/* [63:32] - size */
#define	_GD_curptr	E2K_RWAP_curptr		/* [31: 0] - should be 0 */
#define	GD_lo_reg	E2K_RWAP_lo_reg		/* [63: 0] - entire lower */
						/* double-word of register */
#define	GD_hi_reg	E2K_RWAP_hi_reg		/* [63: 0] - entire high */
						/* double-word of register */
#define	GD_lo_struct	E2K_RWAP_lo_struct	/* low register structure */
#define	GD_hi_struct	E2K_RWAP_hi_struct	/* high register structure */

#define	READ_GD_LO_REG_VALUE()	E2K_GET_DSREG(gd.lo)
#define	READ_GD_HI_REG_VALUE()	E2K_GET_DSREG(gd.hi)

#define	WRITE_GD_LO_REG_VALUE(GD_lo_value) \
		E2K_SET_DSREG(gd.lo, GD_lo_value)
#define	WRITE_GD_HI_REG_VALUE(GD_hi_value) \
		E2K_SET_DSREG(gd.hi, GD_hi_value)
#define	WRITE_GD_REG_VALUE(GD_hi_value, GD_lo_value) \
({ \
	WRITE_GD_HI_REG_VALUE(GD_hi_value); \
	WRITE_GD_LO_REG_VALUE(GD_lo_value); \
})
#endif /* !(__ASSEMBLY__) */

#define	E2K_ALIGN_GLOBALS	12		/* Globals area boundaries */
						/* alignment (2's exponent */
						/* value */
#ifndef __ASSEMBLY__
#define	E2K_ALIGN_GLOBALS_MASK	((1UL << E2K_ALIGN_GLOBALS) - 1)
#else	/* __ASSEMBLY__ */
#define	E2K_ALIGN_GLOBALS_MASK	((1 << E2K_ALIGN_GLOBALS) - 1)
#endif /* !(__ASSEMBLY__) */

#ifndef __ASSEMBLY__
/*
 * OS Compilation Unit Descriptor (OSCUD)
 * describes the global variables memory containing interface codes of the OS
 */

	/*
	 * Structure of lower word
	 * access OSCUD.lo.OSCUD_xxx or OSCUD -> lo.OSCUD_xxx
	 *	or OSCUD_lo.OSCUD_xxx or OSCUD_lo -> OSCUD_xxx
	 */
typedef	e2k_rwap_lo_struct_t	e2k_oscud_lo_t;
#define	_OSCUD_lo_rw	E2K_RWAP_lo_rw		/* [60:59] - read/write flags */
						/* should be "R" */
#define	E2K_OSCUD_RW_PROTECTIONS		E2_RWAR_R_ENABLE;
#define	OSCUD_lo_c	E2K_RWAP_lo_stub1	/* [58] - checked flag, */
						/* if set then literal CT */
						/* is correct */
#define	OSCUD_lo_base	E2K_RWAP_lo_base	/* [47: 0] - base address */
#define	OSCUD_lo_half	E2K_RWAP_lo_half	/* [63: 0] - entire lower */
						/* double-word of register */

	/*
	 * Structure of high word
	 * access OSCUD.hi.OSCUD_xxx or OSCUD -> hi.OSCUD_xxx
	 *	or OSCUD_hi.OSCUD_xxx or OSCUD_hi -> OSCUD_xxx
	 */
typedef	e2k_rwap_hi_struct_t	e2k_oscud_hi_t;
#define	OSCUD_hi_size	E2K_RWAP_hi_size	/* [63:32] - size */
#define	_OSCUD_hi_curptr \
			E2K_RWAP_hi_curptr	/* [31: 0] - should be 0 */
#define	OSCUD_hi_half	E2K_RWAP_hi_half	/* [63: 0] - entire high */
						/* double-word of register */

	/*
	 * Structure of quad-word register
	 * access OSCUD.OSCUD_xxx or OSCUD -> OSCUD_xxx
	 */
typedef	e2k_rwap_struct_t	oscud_struct_t;
#define	_OSCUD_rw	E2K_RWAP_rw		/* [60:59] - read/write flags */
						/* should be "R" */
#define	OSCUD_c		E2K_RWAP_stub1		/* [58] - checked flag, */
						/* if set then literal CT */
						/* is correct */
#define	OSCUD_base	E2K_RWAP_base		/* [47: 0] - base address */
#define	OSCUD_size	E2K_RWAP_size		/* [63:32] - size */
#define	_OSCUD_curptr	E2K_RWAP_curptr		/* [31: 0] - should be 0 */
#define	OSCUD_lo_reg	E2K_RWAP_lo_reg		/* [63: 0] - entire lower */
						/* double-word of register */
#define	OSCUD_hi_reg	E2K_RWAP_hi_reg		/* [63: 0] - entire high */
						/* double-word of register */
#define	OSCUD_lo_struct	E2K_RWAP_lo_struct	/* low register structure */
#define	OSCUD_hi_struct	E2K_RWAP_hi_struct	/* high register structure */

#define	READ_OSCUD_LO_REG_VALUE()	E2K_GET_DSREG(oscud.lo)
#define	READ_OSCUD_HI_REG_VALUE()	E2K_GET_DSREG(oscud.hi)

#define	WRITE_OSCUD_LO_REG_VALUE(OSCUD_lo_value) \
		E2K_SET_DSREG(oscud.lo, OSCUD_lo_value);
#define	WRITE_OSCUD_HI_REG_VALUE(OSCUD_hi_value) \
		E2K_SET_DSREG(oscud.hi, OSCUD_hi_value);
#define	WRITE_OSCUD_REG_VALUE(OSCUD_hi_value, OSCUD_lo_value) \
({ \
	WRITE_OSCUD_HI_REG_VALUE(OSCUD_hi_value); \
	WRITE_OSCUD_LO_REG_VALUE(OSCUD_lo_value); \
})
#endif /* !(__ASSEMBLY__) */

#define	E2K_ALIGN_OSCU		12		/* OS codes area boundaries */
						/* alignment (2's exponent */
						/* value */
#ifndef __ASSEMBLY__
#define	E2K_ALIGN_OSCU_MASK	((1UL << E2K_ALIGN_OSCU) - 1)
#else	/* __ASSEMBLY__ */
#define	E2K_ALIGN_OSCU_MASK	((1 << E2K_ALIGN_OSCU) - 1)
#endif /* !(__ASSEMBLY__) */

#ifndef __ASSEMBLY__
/*
 * OS Compilation Unit Globals Descriptor (OSGD)
 * describes the OS global variables memory
 */

	/*
	 * Structure of lower word
	 * access OSGD.lo.OSGD_lo_xxx or OSGD -> lo.OSGD_lo_xxx
	 *	or OSGD_lo.OSGD_lo_xxx or OSGD_lo -> OSGD_lo_xxx
	 */
typedef	e2k_rwap_lo_struct_t	e2k_osgd_lo_t;
#define	_OSGD_lo_rw	E2K_RWAP_lo_rw		/* [60:59] - read/write flags */
						/* should be "RW" */
#define	E2K_OSGD_RW_PROTECTIONS			E2_RWAR_RW_ENABLE;
#define	OSGD_lo_base	E2K_RWAP_lo_base	/* [47: 0] - base address */
#define	OSGD_lo_half	E2K_RWAP_lo_half	/* [63: 0] - entire lower */
						/* double-word of register */

	/*
	 * Structure of high word
	 * access OSGD.hi.OSGD_hi_xxx or OSGD -> hi.OSGD_hi_xxx
	 *	or OSGD_hi.OSGD_hi_xxx or OSGD_hi -> OSGD_hi_xxx
	 */
typedef	e2k_rwap_hi_struct_t	e2k_osgd_hi_t;
#define	OSGD_hi_size	E2K_RWAP_hi_size	/* [63:32] - size */
#define	_OSGD_hi_curptr	E2K_RWAP_hi_curptr	/* [31: 0] - should be 0 */
#define	OSGD_hi_half	E2K_RWAP_hi_half	/* [63: 0] - entire high */
						/* double-word of register */

	/*
	 * Structure of quad-word register
	 * access OSGD.OSGD_xxx or OSGD -> OSGD_xxx
	 */
typedef	e2k_rwap_struct_t	osgd_struct_t;
#define	_OSGD_rw	E2K_RWAP_rw		/* [60:59] - read/write flags */
						/* should be "RW" */
#define	OSGD_base	E2K_RWAP_base		/* [47: 0] - base address */
#define	OSGD_size	E2K_RWAP_size		/* [63:32] - size */
#define	_OSGD_curptr	E2K_RWAP_curptr		/* [31: 0] - should be 0 */
#define	OSGD_lo_reg	E2K_RWAP_lo_reg		/* [63: 0] - entire lower */
						/* double-word of register */
#define	OSGD_hi_reg	E2K_RWAP_hi_reg		/* [63: 0] - entire high */
						/* double-word of register */
#define	OSGD_lo_struct	E2K_RWAP_lo_struct	/* low register structure */
#define	OSGD_hi_struct	E2K_RWAP_hi_struct	/* high register structure */

#define	READ_OSGD_LO_REG_VALUE()	E2K_GET_DSREG(osgd.lo);
#define	READ_OSGD_HI_REG_VALUE()	E2K_GET_DSREG(osgd.hi);

#define	WRITE_OSGD_LO_REG_VALUE(OSGD_lo_value) \
		E2K_SET_DSREG(osgd.lo, OSGD_lo_value)
#define	WRITE_OSGD_HI_REG_VALUE(OSGD_hi_value) \
		E2K_SET_DSREG(osgd.hi, OSGD_hi_value)
#define	WRITE_OSGD_REG_VALUE(OSGD_hi_value, OSGD_lo_value) \
({ \
	WRITE_OSGD_HI_REG_VALUE(OSGD_hi_value); \
	WRITE_OSGD_LO_REG_VALUE(OSGD_lo_value); \
})
#endif /* !(__ASSEMBLY__) */

#define	E2K_ALIGN_OS_GLOBALS	12		/* OS Globals area boundaries */
						/* alignment (2's exponent */
						/* value */
#ifndef __ASSEMBLY__
#define	E2K_ALIGN_OS_GLOBALS_MASK	((1UL << E2K_ALIGN_OS_GLOBALS) - 1)
#else	/* __ASSEMBLY__ */
#define	E2K_ALIGN_OS_GLOBALS_MASK	((1 << E2K_ALIGN_OS_GLOBALS) - 1)
#endif /* !(__ASSEMBLY__) */

#ifndef __ASSEMBLY__
/*
 * Procedure Stack Pointer (PSP)
 * describes the full procedure stack memory as well as the current pointer
 * to the top of a procedure stack memory part.
 */

	/*
	 * Structure of lower word
	 * access PSP.lo.PSP_lo_xxx or PSP -> lo.PSP_lo_xxx
	 *	or PSP_lo.PSP_lo_xxx or PSP_lo -> PSP_lo_xxx
	 */
typedef	e2k_rwap_lo_struct_t	e2k_psp_lo_t;
#define	_PSP_lo_rw	E2K_RWAP_lo_rw		/* [60:59] - read/write flags */
						/* should be "RW" */
#define	E2K_PSP_RW_PROTECTIONS			E2_RWAR_RW_ENABLE;
#define	PSP_lo_base	E2K_RWAP_lo_base	/* [47: 0] - base address */
#define	PSP_lo_half	E2K_RWAP_lo_half	/* [63: 0] - entire lower */
						/* double-word of register */

	/*
	 * Structure of high word
	 * access PSP.hi.PSP_hi_xxx or PSP -> hi.PSP_hi_xxx
	 *	or PSP_hi.PSP_hi_xxx or PSP_hi -> PSP_hi_xxx
	 */
typedef	e2k_rwap_hi_struct_t	e2k_psp_hi_t;
#define	PSP_hi_size	E2K_RPSP_hi_size	/* [63:32] - size */
#define	PSP_hi_ind	E2K_RPSP_hi_ind		/* [31: 0] - index for SPILL */
						/*		and FILL */
#define	PSP_hi_half	E2K_RPSP_hi_half	/* [63: 0] - entire high */
						/* double-word of register */

#define READ_PSP_LO_REG_VALUE()	E2K_GET_DSREG_NV(psp.lo)

#ifdef	CONFIG_BOOT_E2K
# define READ_PSP_HI_REG_VALUE()	E2K_GET_DSREG_NV(psp.hi)
# define RAW_READ_PSP_HI_REG_VALUE	READ_PSP_HI_REG_VALUE
#else
# define READ_PSP_HI_REG_VALUE() \
({ \
	e2k_psp_hi_t __psp_hi; \
	__psp_hi.word = E2K_GET_DSREG_NV(psp.hi); \
	if (!test_ts_flag(TS_HW_STACKS_EXPANDED)) \
		__psp_hi.PSP_hi_size += KERNEL_P_STACK_SIZE; \
	__psp_hi.word; \
})
# define RAW_READ_PSP_HI_REG_VALUE()	E2K_GET_DSREG_NV(psp.hi)
#endif

#define	WRITE_PSP_LO_REG_VALUE(PSP_lo_value) \
		E2K_SET_DSREG_NV(psp.lo, PSP_lo_value)

#ifdef	CONFIG_BOOT_E2K
# define WRITE_PSP_HI_REG_VALUE(PSP_hi_value) \
		E2K_SET_DSREG_NV_NOIRQ(psp.hi, (PSP_hi_value))
# define RAW_WRITE_PSP_HI_REG_VALUE WRITE_PSP_HI_REG_VALUE
#else /* CONFIG_BOOT_E2K */
# define WRITE_PSP_HI_REG_VALUE(PSP_hi_value) \
({ \
	e2k_psp_hi_t __psp_hi; \
	__psp_hi.word = (PSP_hi_value); \
	if (!test_ts_flag(TS_HW_STACKS_EXPANDED)) \
		__psp_hi.PSP_hi_size -= KERNEL_P_STACK_SIZE; \
	E2K_SET_DSREG_NV_NOIRQ(psp.hi, __psp_hi.word); \
})
# define RAW_WRITE_PSP_HI_REG_VALUE(PSP_hi_value) \
		E2K_SET_DSREG_NV_NOIRQ(psp.hi, (PSP_hi_value))
#endif /* CONFIG_BOOT_E2K */


	/*
	 * Structure of LSR -Loop status register
         */

typedef struct  e2k_lsr_fields {
	u64	lcnt	: 32;   		/* [31: 0] (loop counter) */
	u64	ecnt    :  5;               	/* [36:32] (epilogue counter)*/
	u64	vlc	:  1;			/* [37] (loop counter valid bit) */
	u64	over	:  1;			/* [38] */
	u64	ldmc	:  1;			/* [39] (loads manual control)*/
	u64	ldovl	:  8;			/* [47:40] (load overlap)*/
	u64	pcnt	:  5;			/* [52:48] (prologue counter)*/
	u64	strmd	:  7;			/* [59:53] (store remainder counter)*/
	u64	semc	:  1;			/* [60] (side effects manual control */ 
	u64	unused	:  3;			/* [63:61] */
}e2k_lsr_fields_t;
/*   see C.19.1. О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫ */
#define ls_prlg(x)              ((x).fields.pcnt != 0)
#define ls_lst_itr(x)           ((x).fields.vlc &&((x).fields.lcnt < 2))
#define ls_loop_end(x)          (ls_lst_itr(x) && ((x).fields.ecnt == 0))

#define E2K_LSR_VLC (1UL << 37)


typedef	union e2k_lsr_struct_t {	/* quad-word register */
	e2k_lsr_fields_t	fields;		/* as fields */
	u64			word;		/* as entire register */
} lsr_struct_t;

/* see C.17.1.2. */
typedef struct  e2k_ct_operation_fields{
	u32	psrc    :  5;               	/* [4:0] (pointer to condition)*/
	u32	ct	:  4;   		/* [8:5] (condition type) */
}e2k_ct_operation_fields_t;

typedef	union e2k_ct_struct_t {	
	e2k_ct_operation_fields_t	fields;	/* as fields */
	u64			word;		/* as entire register */
} ct_struct_t;

#define CT_PSRC(x)          ((x).fields.psrc)
#define CT_CT(x)            ((x).fields.ct)

	/*
	 * Structure of quad-word register
	 * access PSP.PSP_xxx or PSP -> PSP_xxx
	 */
typedef	e2k_rwap_struct_t	psp_struct_t;
#define	_PSP_rw		E2K_RWAP_rw		/* [60:59] - read/write flags */
						/* should be "RW" */
#define	PSP_base	E2K_RWAP_base		/* [47: 0] - base address */
#define	PSP_size	E2K_RPSP_size		/* [63:32] - size */
#define	PSP_ind		E2K_RPSP_ind		/* [31: 0] - index for SPILL */
						/*		and FILL */
#define	PSP_lo_reg	E2K_RWAP_lo_reg		/* [63: 0] - entire lower */
						/* double-word of register */
#define	PSP_hi_reg	E2K_RPSP_hi_reg		/* [63: 0] - entire high */
						/* double-word of register */
#define	PSP_lo_struct	E2K_RWAP_lo_struct	/* low register structure */
#define	PSP_hi_struct	E2K_RPSP_hi_struct	/* high register structure */
#endif /* !(__ASSEMBLY__) */

#define	E2K_ALIGN_PSTACK	12		/* Procedure stack boundaries */
						/* alignment (2's exponent */
						/* value) */
#define	E2K_ALIGN_PSTACK_TOP	5		/* Procedure stack top */
						/* boundaries alignment */
						/* (2's exponent value) */
#ifndef __ASSEMBLY__
#define	E2K_ALIGN_PSTACK_MASK		((1UL << E2K_ALIGN_PSTACK) - 1)
#define	E2K_ALIGN_PSTACK_TOP_MASK	((1UL << E2K_ALIGN_PSTACK_TOP) - 1)
#else	/* __ASSEMBLY__ */
#define	E2K_ALIGN_PSTACK_MASK		((1 << E2K_ALIGN_PSTACK) - 1)
#define	E2K_ALIGN_PSTACK_TOP_MASK	((1 << E2K_ALIGN_PSTACK_TOP) - 1)
#endif /* !(__ASSEMBLY__) */

#ifndef __ASSEMBLY__
/*
 * Procedure Chain Stack Pointer (PCSP)
 * describes the full procedure chain stack memory as well as the current
 * pointer to the top of a procedure chain stack memory part.
 */

	/*
	 * Structure of lower word
	 * access PCSP.lo.PCSP_lo_xxx or PCSP -> lo.PCSP_lo_xxx
	 *	or PCSP_lo.PCSP_lo_xxx or PCSP_lo -> PCSP_lo_xxx
	 */
typedef	e2k_rwap_lo_struct_t	e2k_pcsp_lo_t;
#define	_PCSP_lo_rw	E2K_RWAP_lo_rw		/* [60:59] - read/write flags */
						/* should be "RW" */
#define	E2K_PCSR_RW_PROTECTIONS			E2_RWAR_RW_ENABLE;
#define	PCSP_lo_base	E2K_RWAP_lo_base	/* [47: 0] - base address */
#define	PCSP_lo_half	E2K_RWAP_lo_half	/* [63: 0] - entire lower */
						/* double-word of register */
	/*
	 * Structure of high word
	 * access PCSP.hi.PCSP_hi_xxx or PCSP -> hi.PCSP_hi_xxx
	 *	or PCSP_hi.PCSP_hi_xxx or PCSP_hi -> PCSP_hi_xxx
	 */
typedef	e2k_rwap_hi_struct_t	e2k_pcsp_hi_t;
#define	PCSP_hi_size	E2K_RPSP_hi_size	/* [63:32] - size */
#define	PCSP_hi_ind	E2K_RPSP_hi_ind		/* [31: 0] - index for SPILL */
						/*		and FILL */
#define	PCSP_hi_half	E2K_RPSP_hi_half	/* [63: 0] - entire high */

	/*
	 * Structure of quad-word register
	 * access PCSP.PCSP_xxx or PCSP -> PCSP_xxx
	 */
typedef	e2k_rwap_struct_t	pcsp_struct_t;
#define	_PCSP_rw	E2K_RWAP_rw		/* [60:59] - read/write flags */
						/* should be "RW" */
#define	PCSP_base	E2K_RWAP_base		/* [47: 0] - base address */
#define	PCSP_size	E2K_RPSP_size		/* [63:32] - size */
#define	PCSP_ind	E2K_RPSP_ind		/* [31: 0] - index for SPILL */
						/*		and FILL */
#define	PCSP_lo_reg	E2K_RWAP_lo_reg		/* [63: 0] - entire lower */
						/* double-word of register */
#define	PCSP_hi_reg	E2K_RPSP_hi_reg		/* [63: 0] - entire high */
						/* double-word of register */
#define	PCSP_lo_struct	E2K_RWAP_lo_struct	/* low register structure */
#define	PCSP_hi_struct	E2K_RPSP_hi_struct	/* high register structure */

#define	READ_PCSP_LO_REG_VALUE()	E2K_GET_DSREG_NV(pcsp.lo)

#ifdef	CONFIG_BOOT_E2K
# define READ_PCSP_HI_REG_VALUE()	E2K_GET_DSREG_NV(pcsp.hi)
# define RAW_READ_PCSP_HI_REG_VALUE	READ_PCSP_HI_REG_VALUE
#else
# define READ_PCSP_HI_REG_VALUE() \
({ \
	e2k_pcsp_hi_t __pcsp_hi; \
	__pcsp_hi.word = E2K_GET_DSREG_NV(pcsp.hi); \
	if (!test_ts_flag(TS_HW_STACKS_EXPANDED)) \
		__pcsp_hi.PCSP_hi_size += KERNEL_PC_STACK_SIZE; \
	__pcsp_hi.word; \
})
# define RAW_READ_PCSP_HI_REG_VALUE()	E2K_GET_DSREG_NV(pcsp.hi)
#endif

#define	WRITE_PCSP_LO_REG_VALUE(PCSP_lo_value) \
		E2K_SET_DSREG_NV(pcsp.lo, PCSP_lo_value)

#ifdef	CONFIG_BOOT_E2K
# define WRITE_PCSP_HI_REG_VALUE(PCSP_hi_value) \
		E2K_SET_DSREG_NV_NOIRQ(pcsp.hi, (PCSP_hi_value))
# define RAW_WRITE_PCSP_HI_REG_VALUE WRITE_PCSP_HI_REG_VALUE
#else
# define WRITE_PCSP_HI_REG_VALUE(PCSP_hi_value) \
({ \
	e2k_pcsp_hi_t __pcsp_hi; \
	__pcsp_hi.word = (PCSP_hi_value); \
	if (!test_ts_flag(TS_HW_STACKS_EXPANDED)) \
		__pcsp_hi.PCSP_hi_size -= KERNEL_PC_STACK_SIZE; \
	E2K_SET_DSREG_NV_NOIRQ(pcsp.hi, __pcsp_hi.word); \
})
# define RAW_WRITE_PCSP_HI_REG_VALUE(PCSP_hi_value) \
		E2K_SET_DSREG_NV_NOIRQ(pcsp.hi, (PCSP_hi_value))
#endif
#endif /* !(__ASSEMBLY__) */

#define	E2K_ALIGN_PCSTACK	12		/* Procedure chain stack */
						/* boundaries alignment */
						/* (2's exponent value) */
#define	E2K_ALIGN_PCSTACK_TOP	5		/* Procedure chain stack top */
						/* boundaries alignment */
						/* (2's exponent value) */

#ifndef __ASSEMBLY__
#define	E2K_ALIGN_PCSTACK_MASK		((1UL << E2K_ALIGN_PCSTACK) - 1)
#define	E2K_ALIGN_PCSTACK_TOP_MASK	((1UL << E2K_ALIGN_PCSTACK_TOP) - 1)
#else	/* __ASSEMBLY__ */
#define	E2K_ALIGN_PCSTACK_MASK		((1 << E2K_ALIGN_PCSTACK) - 1)
#define	E2K_ALIGN_PCSTACK_TOP_MASK	((1 << E2K_ALIGN_PCSTACK_TOP) - 1)
#endif /* !(__ASSEMBLY__) */


/*
 * ==========   numeric registers (register file)  ===========
 */

#define	E2K_MAXCR	64			/* The total number of */
						/* chain registers */
#define	E2K_MAXCR_q	E2K_MAXCR		/* The total number of */
						/* chain quad-registers */
#define	E2K_ALIGN_CHAIN_WINDOW	5		/* Chain registers Window */
						/* boundaries alignment */
#define	E2K_CWD_MSB	9			/* The number of the */
						/* most significant bit */
						/* of CWD_base */
#define	E2K_CWD_SIZE	(E2K_CWD_MSB + 1)	/* The number of bits in */
						/* CWD_base field */
#define	E2K_PCSHTP_MSB	(E2K_CWD_MSB + 1)	/* The number of the */
						/* most significant bit */
						/* of PCSHTP */
#define	E2K_PCSHTP_SIZE	(E2K_PCSHTP_MSB + 1)	/* The number of bits in */
						/* PCSHTP */
#ifndef __ASSEMBLY__

/* Current chain registers window descriptor (CWD) */

typedef	unsigned int	e2k_cwd_t;

/*
 * Structure of procedure chain stack hardare top register PCSHTP
 * Register is signed value, so read from register get signed value
 * and write to put signed value.
 */

typedef	unsigned int	e2k_pcshtp_t;

#define	PCSHTP_SIGN_EXTEND(pcshtp) \
		(((s64) (pcshtp) << (64 - E2K_PCSHTP_SIZE)) \
				 >> (64 - E2K_PCSHTP_SIZE))


/*
 * User Stack Base Register (USBR/SBR)
 * SBR - contains the base (top) virtual address of the current User Stack area.
 */
typedef	unsigned long	e2k_sbr_t;

	/*
	 * Structure of double-word register
	 * access USBR.USBR_xxx or USBR -> USBR_xxx
	 * access SBR.SBR_xxx or SBR -> SBR_xxx
	 */
typedef	e2k_rwp_struct_t	usbr_struct_t;
typedef	e2k_rwp_struct_t	sbr_struct_t;
#define	USBR_base	E2K_RWP_base		/* [47: 0] - base address */
#define	USBR_reg	E2K_RWP_reg		/* [63: 0] - entire */
						/* double-word register */
#define	SBR_base	USBR_base		/* [47: 0] - base address */
#define	SBR_reg		USBR_reg		/* [63: 0] - entire */

#define	READ_USBR_REG_VALUE()	E2K_GET_DSREG_NV(sbr)
#define	WRITE_USBR_REG_VALUE(USBR_value) E2K_SET_DSREG_NV(sbr, USBR_value)

#define	READ_SBR_REG_VALUE()	E2K_GET_DSREG_NV(sbr)
#define	WRITE_SBR_REG_VALUE(SBR_value)	E2K_SET_DSREG_NV(sbr, SBR_value)
#endif /* !(__ASSEMBLY__) */

#define	E2K_ALIGN_STACKS_BASE		12	/* User stacks boundaries */
						/* alignment */
						/* (2's exponent value) */
#define	E2K_ALIGN_ALL_STACKS_BASE	37	/* All User stacks area */
						/* boundaries alignment */
						/* (2's exponent value) */
#define E2K_PROTECTED_STACK_BASE_BITS	32	/* Protected mode stack */
						/* does not cross 4 Gb	*/
						/* boundary.		*/

#define	E2K_ALIGN_STACKS_BASE_MASK	((1UL << E2K_ALIGN_STACKS_BASE) - 1)
#define	E2K_ALL_STACKS_MAX_SIZE		(1UL << E2K_ALIGN_ALL_STACKS_BASE)
#define	E2K_PROTECTED_STACK_BASE_MASK \
	((1UL << E2K_PROTECTED_STACK_BASE_BITS) - 1)


#ifndef __ASSEMBLY__

/*
 * Non-Protected User Stack Descriptor (USD)
 * contains free memory space dedicated for user stack data and
 * is supposed to grow from higher memory addresses to lower ones
 */

	/*
	 * Structure of lower word
	 * access USD.lo.USD_lo_xxx or USD -> lo.USD_lo_xxx
	 *	or USD.USD_lo_xxx or USD -> USD_lo_xxx
	 */
typedef	e2k_rwap_lo_struct_t	e2k_usd_lo_t;
#define	_USD_lo_rw	E2K_RUSD_lo_rw		/* [60:59] - read/write flags */
						/* should be "RW" */
#define	USD_lo_p	E2K_RUSD_lo_p		/* [58] - flag of "protected" */
						/* mode: should be */
						/* 0 - non-protected */
#define	USD_lo_p_bit	E2K_RUSD_lo_p_bit	/* protected flag as value */
#define	USD_lo_p_flag	(1UL << USD_lo_p_bit)

#define	USD_lo_base	E2K_RUSD_lo_base	/* [47: 0] - base address */
#define	USD_lo_half	E2K_RUSD_lo_half	/* [63: 0] - entire lower */
						/* double-word of register */

	/*
	 * Structure of high word
	 * access USD.hi.USD_hi_xxx or USD -> hi.USD_hi_xxx
	 *	or USD_hi.USD_hi_xxx or USD_hi -> USD_hi_xxx
	 */
typedef	e2k_rwap_hi_struct_t	e2k_usd_hi_t;
#define	USD_hi_size	E2K_RWAP_hi_size	/* [63:32] - size */
#define	_USD_hi_curptr	E2K_RWAP_hi_curptr	/* [31: 0] - should be 0 */
#define	USD_hi_half	E2K_RWAP_hi_half	/* [63: 0] - entire high */
						/* double-word of register */

#define MAX_USD_HI_SIZE	(4ULL * 1024 * 1024 * 1024 - 16ULL)

	/*
	 * Structure of quad-word register
	 * access USD.USD_xxx or USD -> USD_xxx
	 */
typedef	e2k_rwap_struct_t	usd_struct_t;
#define	_USD_rw		E2K_RUSD_rw		/* [60:59] - read/write flags */
						/* should be "RW" */
#define	USD_p		E2K_RUSD_p		/* [58] - flag of "protected" */
						/* mode: 1 - protected */
#define	USD_base	E2K_RUSD_base		/* [31: 0] - base address */
#define	USD_size	E2K_RWAP_size		/* [63:32] - size */
#define	_USD_curptr	E2K_RWAP_curptr		/* [31: 0] - should be 0 */
#define	USD_lo_reg	E2K_RUSD_lo_reg		/* [63: 0] - entire lower */
						/* double-word of register */
#define	USD_hi_reg	E2K_RWAP_hi_reg		/* [63: 0] - entire high */
						/* double-word of register */
#define	USD_lo_struct	E2K_RUSD_lo_struct	/* low register structure */
#define	USD_hi_struct	E2K_RWAP_hi_struct	/* high register structure */

#define	READ_USD_LO_REG_VALUE()	E2K_GET_DSREG_NV(usd.lo)
#define	READ_USD_HI_REG_VALUE()	E2K_GET_DSREG_NV(usd.hi)

#define	WRITE_USD_LO_REG_VALUE(USD_lo_value) \
		E2K_SET_DSREG_NV(usd.lo, USD_lo_value)
#define	WRITE_USD_HI_REG_VALUE(USD_hi_value) \
		E2K_SET_DSREG_NV(usd.hi, USD_hi_value)

#define	WRITE_USD_REG_VALUE(USD_hi_value, USD_lo_value) \
({ \
	WRITE_USD_HI_REG_VALUE(USD_hi_value); \
	WRITE_USD_LO_REG_VALUE(USD_lo_value); \
})

/*
 * Protected User Stack Descriptor (PUSD)
 * contains free memory space dedicated for user stack data and
 * is supposed to grow from higher memory addresses to lower ones
 */

	/*
	 * Structure of lower word
	 * access PUSD.lo.PUSD_lo_xxx or PUSD -> lo.PUSD_lo_xxx
	 *	or PUSD.PUSD_lo_xxx or PUSD -> PUSD_lo_xxx
	 */
typedef	e2k_rwsap_lo_struct_t	e2k_pusd_lo_t;
#define	_PUSD_lo_rw	E2K_RPUSD_lo_rw		/* [60:59] - read/write flags */
						/* should be "RW" */
#define	PUSD_lo_p	E2K_RPUSD_lo_p		/* [58] - flag of "protected" */
						/* mode: should be */
						/* 1 - protected */
#define	PUSD_lo_psl	E2K_RPUSD_lo_psl	/* {47:32} - dynamic level of */
						/* the current procedure in a */
						/* stack of called procedures */
#define	PUSD_lo_base	E2K_RPUSD_lo_base	/* [31: 0] - base address */
#define	PUSD_lo_half	E2K_RPUSD_lo_half	/* [63: 0] - entire lower */
						/* double-word of register */

	/*
	 * Structure of high word
	 * access PUSD.hi.PUSD_hi_xxx or PUSD -> hi.PUSD_hi_xxx
	 *	or PUSD_hi.PUSD_hi_xxx or PUSD_hi -> PUSD_hi_xxx
	 */
typedef	e2k_rwsap_hi_struct_t	e2k_pusd_hi_t;
#define	PUSD_hi_size	E2K_RWSAP_hi_size	/* [63:32] - size */
#define	_PUSD_hi_curptr	E2K_RWSAP_hi_curptr	/* [31: 0] - should be 0 */
#define	PUSD_hi_half	E2K_RWSAP_hi_half	/* [63: 0] - entire high */
						/* double-word of register */

	/*
	 * Structure of quad-word register
	 * access PUSD.PUSD_xxx or PUSD -> PUSD_xxx
	 */
typedef	e2k_rwsap_struct_t	pusd_struct_t;
#define	_PUSD_rw	E2K_RPUSD_rw		/* [60:59] - read/write flags */
						/* should be "RW" */
#define	PUSD_p		E2K_RPUSD_p		/* [58] - flag of "protected" */
						/* mode: should be */
						/* 1 - protected */
#define	PUSD_psl	E2K_RPUSD_psl		/* {47:32} - dynamic level of */
						/* the current procedure in a */
						/* stack of called procedures */
#define	PUSD_base	E2K_RUSD_base		/* [31: 0] - base address */
#define	PUSD_size	E2K_RWSAP_size		/* [63:32] - size */
#define	_PUSD_curptr	E2K_RWSAP_curptr	/* [31: 0] - should be 0 */
#define	PUSD_lo_reg	E2K_RPUSD_lo_reg	/* [63: 0] - entire lower */
						/* double-word of register */
#define	PUSD_hi_reg	E2K_RWSAP_hi_reg	/* [63: 0] - entire high */
						/* double-word of register */
#define	PUSD_lo_struct	E2K_RUSD_lo_struct	/* low register structure */
#define	PUSD_hi_struct	E2K_RWSAP_hi_struct	/* high register structure */

#define	READ_PUSD_LO_REG_VALUE()	E2K_GET_DSREG_NV(usd.lo)
#define	READ_PUSD_HI_REG_VALUE()	E2K_GET_DSREG_NV(usd.hi)

#define	WRITE_PUSD_LO_REG_VALUE(PUSD_lo_value) \
		E2K_SET_DSREG_NV(usd.lo, PUSD_lo_value)
#define	WRITE_PUSD_HI_REG_VALUE(PUSD_hi_value) \
		E2K_SET_DSREG_NV(usd.hi, PUSD_hi_value)

#define	WRITE_PUSD_REG_VALUE(PUSD_hi_value, PUSD_lo_value) \
({ \
	WRITE_PUSD_HI_REG_VALUE(PUSD_hi_value); \
	WRITE_PUSD_LO_REG_VALUE(PUSD_lo_value); \
})

#endif /* !(__ASSEMBLY__) */

#define	E2K_ALIGN_USTACK	4		/* Non-Protected User Stack */
						/* boundaries alignment */
						/* (2's exponent value) */
#define	E2K_ALIGN_PUSTACK	5		/* Protected User Stack */
						/* boundaries alignment */
						/* (2's exponent value) */

#define E2K_ALIGN_USTACK_SIZE	(1UL << E2K_ALIGN_USTACK)
#define E2K_ALIGN_PUSTACK_SIZE	(1UL << E2K_ALIGN_PUSTACK)

#define E2K_ALIGN_STACK	max(E2K_ALIGN_USTACK_SIZE, E2K_ALIGN_PUSTACK_SIZE)

#ifndef __ASSEMBLY__
#define	E2K_ALIGN_USTACK_MASK	((1UL << E2K_ALIGN_USTACK) - 1)
#define E2K_ALIGN_PUSTACK_MASK   ((1UL << E2K_ALIGN_PUSTACK) - 1)
#else	/* __ASSEMBLY__ */
#define	E2K_ALIGN_USTACK_MASK	((1 << E2K_ALIGN_USTACK) - 1)
#define E2K_ALIGN_PUSTACK_MASK   ((1 << E2K_ALIGN_PUSTACK) - 1)
#endif /* !(__ASSEMBLY__) */

#ifndef __ASSEMBLY__

/*
 * Instruction structure
 */

typedef	u64		instr_item_t;	/* min. item of instruction */
					/* is double-word */

#define	E2K_INSTR_MAX_SYLLABLES_NUM	8	/* max length of instruction */
						/* in terms of min item of */
						/* instruction */
#define	E2K_INSTR_MAX_SIZE		(E2K_INSTR_MAX_SYLLABLES_NUM * \
						sizeof (instr_item_t))

/* Asynchonous program instruction 'fapb' is always 16 bytes long */
#define E2K_ASYNC_INSTR_SIZE		16
/* Asynchonous program can contain maximum 32 instructions */
#define MAX_ASYNC_PROGRAM_INSTRUCTIONS	32

typedef	u16		instr_semisyl_t; /* instruction semi-syllable */
					/* is short */

typedef	u32		instr_syl_t;	/* instruction syllable */
					/* is word */

/*
 * Order of fixed syllables of instruction
 */
#define	E2K_INSTR_HS_NO		0	/* header syllable */
#define E2K_INSTR_SS_NO		1	/* stubs syllable (if present) */

#define	E2K_GET_INSTR_SEMISYL(instr_addr, semisyl_no)			\
		(((instr_semisyl_t *)(instr_addr))			\
			[((semisyl_no) & 0x1) ? ((semisyl_no) - 1) :	\
						((semisyl_no) + 1)])
#define	E2K_GET_INSTR_SYL(instr_addr, syl_no)	\
		(((instr_syl_t *)(instr_addr))[syl_no])

#define	E2K_GET_INSTR_HS(instr_addr)	E2K_GET_INSTR_SYL(instr_addr, \
							E2K_INSTR_HS_NO)
#define	E2K_GET_INSTR_SS(instr_addr)	E2K_GET_INSTR_SYL(instr_addr, \
							E2K_INSTR_SS_NO)
#define E2K_GET_INSTR_ALS0(instr_addr, ss_flag)				\
		E2K_GET_INSTR_SYL(instr_addr,				\
					(ss_flag) ? E2K_INSTR_SS_NO + 1 \
							:		\
							E2K_INSTR_SS_NO)
#define E2K_GET_INSTR_ALES0(instr_addr, mdl)				\
		E2K_GET_INSTR_SEMISYL(instr_addr, ((mdl) + 1) * 2)
/*
 * Header syllable structure
 */

typedef	struct instr_hs_fields {
	u32	mdl	:  4;	/* [ 3: 0] middle pointer in terms of */
					/*	   syllables - 1 */
	u32	lng	:  3;	/* [ 6: 4] length of instruction in */
					/*	   terms of double-words - 1 */
	u32	nop	:  3;	/* [ 9: 7] no operation code */
	u32	lm	:  1;	/*    [10] loop mode flag */
	u32	x	:  1;	/*    [11] unused field */
	u32	s	:  1;	/*    [12] Stubs syllable presence bit */
	u32	sw	:  1;	/*    [13] bit used by software */
	u32	c	:  2;	/* [15:14] Control syllables presence */
					/*	   mask */
	u32	cd	:  2;	/* [17:16] Conditional execution */
					/*	   syllables number */
	u32	pl	:  2;	/* [19:18] Predicate logic channel */
					/*	   syllables number */
	u32	ale	:  6;	/* [25:20] Arithmetic-logic channel */
					/*	   syllable extensions */
					/*	   presence mask */
	u32	al	:  6;	/* [31:26] Arithmetic-logic channel */
					/*	   syllables presence mask */
} instr_hs_fields_t;

typedef	union instr_hs {
	instr_hs_fields_t	fields;		/* as fields 		*/
	instr_syl_t		word;		/* as entire syllable 	*/
} instr_hs_t;

#define	E2K_GET_INSTR_SIZE(hs)	((AS_STRUCT(hs).lng + 1) * sizeof (instr_item_t))

/*
 * Stubs sullable structure
 */

typedef	struct instr_ss_fields {
	u32	ctcond	:  9;	/* [ 8: 0] control transfer condition */
	u32	x	:  1;	/* [    9] unused field */
	u32	ctop	:  2;	/* [11:10] control transfer opcode */
	u32	aa	:  4;	/* [15:12] mask of AAS */
	u32	alc	:  2;	/* [17:16] advance loop counters */
	u32	abp	:  2;	/* [19:18] advance predicate base */
	u32	xx	:  1;	/*    [20] unused field */
	u32	abn	:  2;	/* [22:21] advance numeric base */
	u32	abg	:  2;	/* [24:23] advance global base */
	u32	xxx	:  1;	/*    [25] unused field */
	u32	vfdi	:  1;	/*    [26] verify deferred interrupt */
	u32	srp	:  1;	/*    [27] store recovery point */
	u32	bap	:  1;	/*    [28] begin array prefetch */
	u32	eap	:  1;	/*    [29] end array prefetch */
	u32	ipd	:  2;	/* [31:30] instruction prefetch depth */
} instr_ss_fields_t;

typedef	union instr_ss {
	instr_ss_fields_t	fields;		/* as fields 		*/
	instr_syl_t		word;		/* as entire syllable 	*/
} instr_ss_t;

#define SS_IPD(w)    (((instr_ss_fields_t*)&w)->ipd)
#define SS_EAP(w)    (((instr_ss_fields_t*)&w)->eap)
#define SS_BAP(w)    (((instr_ss_fields_t*)&w)->bap)
#define SS_SRP(w)    (((instr_ss_fields_t*)&w)->srp)
#define SS_VFDI(w)   (((instr_ss_fields_t*)&w)->vfdi)
#define SS_ABP(w)    (((instr_ss_fields_t*)&w)->abp)
#define SS_ABG(w)    (((instr_ss_fields_t*)&w)->abg)
#define SS_ABN(w)    (((instr_ss_fields_t*)&w)->abn)
#define SS_AA(w)     (((instr_ss_fields_t*)&w)->aa)
#define SS_CTOP(w)   (((instr_ss_fields_t*)&w)->ctop)
#define SS_CTCOND(w) (((instr_ss_fields_t*)&w)->ctcond)


/*
 * ALU sullables structure
 */

typedef	struct instr_alsf2_fields {
	u32	dst	:  8;	/* [ 7: 0] destination */
	u32	src2	:  8;	/* [15: 8] source register #2 */
	u32	opce	:  8;	/* [23:16] opcode extension */
	u32	cop	:  7;	/* [30:24] code of operation */
	u32	spec	:  1;	/*    [31] speculative mode */
} instr_alsf2_fields_t;

typedef	union instr_alsf2 {
	instr_alsf2_fields_t	fields;		/* as fields 		*/
	instr_syl_t		word;		/* as entire syllable 	*/
} instr_alsf2_t;

typedef	union instr_als {
	instr_alsf2_fields_t	f2;		/* as fields 		*/
	instr_syl_t		word;		/* as entire syllable 	*/
} instr_als_t;

typedef	struct instr_alesf2_fields {
	u32	opce	:  8;	/* [ 7: 0] opcode 2 extension */
	u32	opc2	:  8;	/* [15: 8] opcode 2 */
} instr_alesf2_fields_t;

typedef	union instr_alesf2 {
	instr_alesf2_fields_t	fields;		/* as fields 		*/
	instr_semisyl_t		word;		/* as entire syllable 	*/
} instr_alesf2_t;

typedef	union instr_ales {
	instr_alesf2_fields_t	f2;		/* as fields 		*/
	instr_semisyl_t		word;		/* as entire syllable 	*/
} instr_ales_t;

/*
 * ALU syllable code of operations and opcode extentions
 */
#define	DRTOAP_ALS_COP		0x62		/* DRTOAP */
#define	GETSP_ALS_COP		0x58		/* GETSP */
#define	EXT_ALES_OPC2		0x01		/* EXTension  */
#define	USD_ALS_OPCE		0xec		/* USD  */

/*
 * ==========   numeric registers (register file)  ===========
 */

#define	E2K_MAXNR	128			/* The total number of */
						/* quad-NRs */
#define	E2K_MAXGR	16			/* The total number of global */
						/* quad-NRs */
#define	E2K_MAXSR	(E2K_MAXNR - E2K_MAXGR)	/* The total number of stack */
						/* quad-NRs */
#define	E2K_MAXNR_d	(E2K_MAXNR * 2)		/* The total number of */
						/* double-NRs */
#define	E2K_MAXGR_d	(E2K_MAXGR * 2)		/* The total number of global */
						/* double-NRs */
#define	E2K_MAXSR_d	(E2K_MAXSR * 2)		/* The total number of stack */
						/* double-NRs */
#define	E2K_ALIGN_WINDOW	4		/* Window boundaries */
						/* alignment */
#define	E2K_WD_MSB	10			/* The number of bits in WD */
						/* fields */
#define	E2K_WD_SIZE	(E2K_WD_MSB + 1)	/* The number of bits in WD */
						/* fields */
#define	E2K_NR_SIZE	16			/* Byte size of quad-NR */

/* Current window descriptor (WD) */
typedef	struct e2k_wd_fields {
	u64	base	: E2K_WD_SIZE;		/* [10: 0] window base - the */
						/* absolute (physical) */
						/* address of the first NR */
						/* in the window */
	u64	unused1	: 16 - E2K_WD_SIZE;	/* [15:11] unused field */
	u64	size	: E2K_WD_SIZE;		/* [26:16] window size */
	u64	unused2	: 16 - E2K_WD_SIZE;	/* [31:27] unused field */
	u64	psize	: E2K_WD_SIZE;		/* [42:32] parameters area */
						/* size */
	u64	unused3	: 16 - E2K_WD_SIZE;	/* [47:43] unused field */
	u64	fx	: 1;			/* [48]    spill/fill */
						/* extended flag; indicates */
						/* that the current procedure */
						/* has variables of FX type */
	u64	unused4	: 15;			/* [63:49] unused field */
} e2k_wd_fields_t;

typedef	union e2k_wd {
	e2k_wd_fields_t		fields;		/* as fields 		*/
	u64			word;		/* as entire opcode 	*/
} e2k_wd_t;

/* Structure of dword register PSHTP */
typedef	struct e2k_pshtp_fields {		/* PSHTP fields */
	u64	ind	: E2K_WD_SIZE + 1;	/* [WD_MSB + 1 : 0] */
	u64	unused1	: 16 - E2K_WD_SIZE - 1;	/* [15: WD_MSB + 2] */
	u64	fxind	: E2K_WD_SIZE;		/* [16 + WD_MSB : 16] */
	u64	unused2	: 32 - E2K_WD_SIZE - 16;/* [31: 16+ WD_MSB + 1] */
	u64	tind	: E2K_WD_SIZE;		/* [32 + WD_MSB : 32] */
	u64	unused3	: 48 - E2K_WD_SIZE - 32;/* [47: 32+ WD_MSB + 1] */
	u64	fx	:  1;			/* [48 : 48] */
	u64	unused4	: 15;			/* [63 : 49] */
} e2k_pshtp_fields_t;

typedef	union e2k_pshtp_struct {		/* Register */
	e2k_pshtp_fields_t	fields;		/* as fields */
	u64			word;		/* as entire register */
} e2k_pshtp_t;

#define	PSHTP_ind		fields.ind
#define	PSHTP_tind		fields.tind
#define	PSHTP_fxind		fields.fxind
#define	PSHTP_fx		fields.fx

#define	PSHTP_SIGN_EXTEND(pshtp) \
	((u64) (((s64) ((pshtp).PSHTP_ind) << (64 - (E2K_WD_SIZE + 1))) \
					   >> (64 - (E2K_WD_SIZE + 1))))
/* Multiply pshtp by 2 to account for the extended part. */
#define	GET_PSHTP_INDEX(pshtp)	(2 * PSHTP_SIGN_EXTEND(pshtp))

#define	SET_PSHTP_INDEX(pshtp, signed_index) \
		((pshtp).PSHTP_ind = (signed_index))

#define	READ_PSHTP_REG_VALUE()	E2K_GET_DSREG(pshtp)
#define	WRITE_PSHTP_REG_VALUE(PSHTP_value)	\
		E2K_SET_DSREG(pshtp, PSHTP_value)


/* Numeric Register in a rotatable area: %br# or %dbr# (OPCODE) */
typedef	struct e2k_nbr_fields {
	u8	index	: 7;			/* [ 6: 0] NR index in a */
						/*	   rotatable area */
	u8	rt7	: 1;			/* [ 7]	   should be 0 */
} e2k_nbr_fields_t;
typedef	union e2k_nbr {	
	e2k_nbr_fields_t	fields;		/* as fields 		*/
	u8			word;		/* as entire opcode 	*/
} e2k_nbr_t;

/* Numeric Register in a window: %r# or %dr# (OPCODE) */
typedef	struct e2k_nr_fields {
	u8	index	: 6;			/* [ 5: 0] NR index in a */
						/*	   window */
	u8	rt6	: 1;			/* [ 6]	   should be 0 */
	u8	rt7	: 1;			/* [ 7]	   should be 1 */
} e2k_nr_fields_t;
typedef	union e2k_nr {	
	e2k_nr_fields_t		fields;		/* as fields 		*/
	u8			word;		/* as entire opcode 	*/
} e2k_nr_t;

/* Numeric results */
/* Result destination (destination(ALS.dst)) is encoded in dst fields */
/* of ALS or AAS syllables as follows: */

typedef	union e2k_dst {
	e2k_nbr_t		nbr;		/* as rotatable register */
	e2k_nr_t		nr;		/* as window register */
	u8			word;		/* as entire opcode 	*/
} e2k_dst_t;

#define	DST_IS_NBR(dst)		(AS_STRUCT(dst.nbr).rt7 == 0)
#define	DST_IS_NR(dst)		(AS_STRUCT(dst.nr).rt7 == 1 && \
					AS_STRUCT(dst.nr).rt6 == 0)
#define	DST_NBR_INDEX(dst)	AS_STRUCT(dst.nbr).index
#define	DST_NR_INDEX(dst)	AS_STRUCT(dst.nr).index
#define	DST_NBR_RNUM_d(dst)	DST_NBR_INDEX(dst)
#define	DST_NR_RNUM_d(dst)	DST_NR_INDEX(dst)

/* The effective address of NR in a rotatable area (in terms of double-NR) */
#define	NBR_IND_d(BR, rnum_d)	(AS_STRUCT(BR).rbs * 2 + \
					(AS_STRUCT(BR).rcur * 2 + rnum_d) % \
						(AS_STRUCT(BR).rsz * 2 + 2))
#define	NBR_REA_d(WD, ind_d)	((AS_STRUCT(WD).base / 8 + ind_d) % \
					E2K_MAXSR_d)

/* The effective address of NR in a window (in terms of double-NR) */
#define	NR_REA_d(WD, rnum_d)	((AS_STRUCT(WD).base / 8 + rnum_d) % \
					E2K_MAXSR_d)


/* 
 * ==========   chain regs & usd regs    =========== 
 * To work with reg as with word use AS_WORD
 * To work with reg as with struct use AS_STRUCT
 */


#define AS_WORD(x)		((x).word)
#define AS_STRUCT(x)		((x).fields)
#define AS_SAP_STRUCT(x)	((x).sap_fields)
#define AS_AP_STRUCT(x)		((x).ap_fields)
#define AS_WORD_P(xp)		((xp)->word)
#define AS_STRUCT_P(xp)		((xp)->fields)
#define AS_SAP_STRUCT_P(xp)	((xp)->sap_fields)
#define AS_AP_STRUCT_P(xp)	((xp)->ap_fields)

#define AW(x)	AS_WORD(x)
#define AS(x)	AS_STRUCT(x)
#define AWP(xp)	AS_WORD_P(xp)
#define ASP(xp)	AS_STRUCT_P(xp)


/* BR */
typedef	struct e2k_br_fields {	/* Structure of br reg */
	u32	rbs	: 6;		/* [ 5: 0] 	*/
	u32	rsz	: 6;		/* [11: 6] 	*/
	u32	rcur	: 6;		/* [17:12] 	*/
	u32	psz	: 5;		/* [22:18] 	*/
	u32	pcur	: 5;		/* [27:23] 	*/
} e2k_br_fields_t;
typedef	union e2k_br {
	e2k_br_fields_t	fields;		/* as fields 		*/
	u32		word;		/* as entire register 	*/
} e2k_br_t;

/* see 5.25.1. (RPR) */

typedef	union e2k_rpr_lo_struct {	
	e2k_rwp_fields_t	fields;	/* as fields */
	u64			word;	/* as entire register */
} rpr_lo_struct_t;

typedef union e2k_rpr_hi_struct {
	e2k_br_fields_t   	fields;	/* as fields */
	u64			word;	/* as entire register */
} rpr_hi_struct_t;

#define RPR_IP(x)          ((x).fields.base)
#define RPR_STP(x)         ((x).fields.stub1)
#define RPR_BR_CUR(x)      ((x).fields.rcur)
#define RPR_BR_PCUR(x)     ((x).fields.pcur)

/*
 * BGR. Rotation base of global registers.
 * 11 bits wide. Rounded to 32-bit, because 16-bit memory & sysreg access
 * makes no sense in this case
 */
typedef	struct e2k_bgr_fields {	/* Structure of bgr reg */
	u32	val	: 8;		/* [ 7: 0] 	*/
	u32	cur	: 3;		/* [10: 8] 	*/
} e2k_bgr_fields_t;
typedef	union e2k_bgr {
	e2k_bgr_fields_t	fields;	/* as fields 		*/
	u32			word;	/* as entire register 	*/
} e2k_bgr_t;

#define	E2K_GB_START_REG_NO_d	24
#define	E2K_GB_REGS_NUM_d	(E2K_MAXGR_d - E2K_GB_START_REG_NO_d)
#define	E2K_INITIAL_BGR		((e2k_bgr_t) { {cur : 0, val : 0xff} })

#define	READ_BGR_REG_VALUE()	E2K_GET_SREG(bgr)
#define	WRITE_BGR_REG_VALUE(BGR_value) 	E2K_SET_SREG(bgr, BGR_value)


/* CR0 */

typedef	struct e2k_cr0_hi_fields {	/* Structure of cr0_hi chain reg */
	u64	unused	: 3;		/* [ 2: 0] 	*/
	u64	ip	: 61;		/* [63: 3] 	*/
} e2k_cr0_hi_fields_t;
typedef	union e2k_cr0_hi {	
	e2k_cr0_hi_fields_t	fields;	/* as fields 		*/
	u64			word;	/* as entire register 	*/
} e2k_cr0_hi_t;

typedef	struct e2k_cr0_lo_fields {	/* Structure of cr0_lo chain reg */
	u64	pf	: 64;		/* [63: 0] 	*/
} e2k_cr0_lo_fields_t;
typedef	union e2k_cr0_lo {	
	e2k_cr0_lo_fields_t	fields;	/* as fields 		*/
	u64			word;	/* as entire register 	*/
} e2k_cr0_lo_t;

/* CR1 */

typedef	union e2k_cr1_hi_fields {	/* Structure of cr1_hi chain reg */
	struct {
		u64 br		: 28;	/* [27: 0] 	*/
		u64 unused	: 7;	/* [34:28] 	*/
		u64 wdbl	: 1;	/* [35:35]	*/
		u64 ussz	: 28;	/* [63:36] 	*/
	};
	struct {
		u64 rbs		: 6;	/* [5 :0 ]	*/
		u64 rsz		: 6;	/* [11:6 ]	*/
		u64 rcur	: 6;	/* [17:12]	*/
		u64 psz		: 5;	/* [22:18]	*/
		u64 pcur	: 5;	/* [27:23]	*/
		u64 __x1	: 36;	/* [63:28]	*/
	};
} e2k_cr1_hi_fields_t;
typedef	union e2k_cr1_hi {	
	e2k_cr1_hi_fields_t	fields;	/* as fields 		*/
	u64			word;	/* as entire register 	*/
} e2k_cr1_hi_t;

typedef union e2k_cr1_lo_fields {	/* Structure of cr1_lo chain reg */
	struct {
		u64 tr		: 15;	/* [14: 0] 	*/
		u64 unused1	:  1;	/* [15] 	*/
		u64 ein		:  8;	/* [23:16] 	*/
		u64 ss		:  1;	/* [24]		*/
		u64 wfx		:  1;	/* [25] 	*/
		u64 wpsz	:  7;	/* [32:26] 	*/
		u64 wbs		:  7;	/* [39:33] 	*/
		u64 cuir	: 17;	/* [56:40] 	*/
		u64 psr		:  7;	/* [63:57]	*/
	};
	struct {
		u64 __x1	: 40;	/* [39:0]	*/
		u64 cui		: 16;	/* [40:55]	*/
		u64 ic		: 1;	/* [56]		*/
		u64 pm		: 1;	/* [57] 	*/
		u64 ie		: 1;	/* [58] 	*/
		u64 sge		: 1;	/* [59] 	*/
		u64 lw		: 1;	/* [60] last wish */
		u64 uie		: 1;	/* [61] user interrupts enable */
		u64 nmie	: 1;	/* [62] not masked interrupts enable */
		u64 unmie	: 1;	/* [63] user not masked interrupts */
					/*	enable */
	};
} e2k_cr1_lo_fields_t;
typedef	union e2k_cr1_lo {
	e2k_cr1_lo_fields_t	fields;	/* as fields 		*/
	u64			word;	/* as entire register 	*/
} e2k_cr1_lo_t;


#define	E2K_ALIGN_INS		3		/* number of least */
						/* significant  bits of IP */
						/* are zeroed */

/*
 * Control Transfer Preparation Register (CTPR)
 */

	/*
	 * Structure of double-word register
	 * access CTPR.CTPR_xxx or CTPR -> CTPR_xxx
	 */
typedef	struct e2k_ctpr_fields {	/* Structure of CTPR */
	u64		ta_base	: E2K_VA_SIZE;		/* [47: 0] */
	u64		unused2	: 53 - E2K_VA_MSB;	/* [53:48] */
	u64		ta_tag	:  3;			/* [56:54] */
	u64		opc	:  2;			/* [58:57] */
	u64		ipd	:  2;			/* [60:59] */
	u64		unused	:  3;			/* [63:61] */
} e2k_ctpr_fields_t;
typedef	union e2k_ctpr {		/* Structure of lower word */
	e2k_ctpr_fields_t	fields;	/* as fields */
	u64			word;	/* as entire register */
} e2k_ctpr_t;
#define	CTPR_ta_base	fields.ta_base		/* [47: 0] - transfer address */
#define	CTPR_ta_tag	fields.ta_tag		/* [56:54] - tag */
#define	CTPR_opc	fields.opc		/* [58:57] - opcode */
#define	CTPR_ipd	fields.ipd		/* [58:57] - prefetch level */
#define	CTPR_reg	word			/* [63: 0] - entire */
						/* double-word register */
/* Control Transfer Opcodes */
#define	DISP_CT_OPC	0
#define	LDISP_CT_OPC	1
#define	RETURN_CT_OPC	3

/* Control Transfer Tag */
#define	CTPEW_CT_TAG	0	/* empty word */
#define	CTPDW_CT_TAG	1	/* diagnostic word */
#define	CTPPL_CT_TAG	2	/* procedure label */
#define	CTPLL_CT_TAG	3	/* local label */
#define	CTPNL_CT_TAG	4	/* numeric label */
#define	CTPSL_CT_TAG	5	/* system label */

/* Control Transfer Prefetch Level */
#define	NONE_CT_IPD	0	/* none any prefetching */
#define	ONE_IP_CT_IPD	1	/* only one instruction on 'ta_base' IP */
#define	TWO_IP_CT_IPD	2	/* two instructions on 'ta_base' and next IP */


/* PSR */
typedef	struct e2k_psr_fields {	/* Structure of psr reg */
	u32	pm	:  1;		/* [ 0] 	*/
	u32	ie	:  1;		/* [ 1] 	*/
	u32	sge	:  1;		/* [ 2] 	*/
	u32	lw	:  1;		/* [ 3] last wish */
	u32	uie	:  1;		/* [ 4] user interrupts enable */
	u32	nmie	:  1;		/* [ 5] not masked interrupts enable */
	u32	unmie	:  1;		/* [ 6] user not masked interrupts */
					/*	enable */
	u32	unused	: 25;		/* [31: 7]	*/
} e2k_psr_fields_t;
typedef	union e2k_psr {	
	e2k_psr_fields_t	fields;	/* as fields 		*/
	u32			word;	/* as entire register 	*/
} e2k_psr_t;

#define	PSR_pm		fields.pm		/* [ 0] */
#define	PSR_ie		fields.ie		/* [ 1] */
#define	PSR_sge		fields.sge		/* [ 2] */
#define	PSR_lw		fields.lw		/* [ 3] */
#define	PSR_uie		fields.uie		/* [ 4] */
#define	PSR_nmie	fields.nmie		/* [ 5] */
#define	PSR_unmie	fields.unmie		/* [ 6] */
#define	PSR_reg		word			/* [31: 0] - entire */
						/* single-word register */
#endif /* !(__ASSEMBLY__) */

#define	PSR_PM		0x01U
#define	PSR_IE		0x02U
#define	PSR_SGE		0x04U
#define	PSR_LW		0x08U
#define	PSR_UIE		0x10U
#define	PSR_NMIE	0x20U
#define	PSR_UNMIE	0x40U

#ifndef __ASSEMBLY__

/* CUT entry */

typedef	struct e2k_cute_dw0_fields {	/* Structure of the first d-word */
					/* of CUT entry */
	u64	cud_base	: E2K_VA_SIZE;		/* [47: 0] 	*/
	u64	unused1		: 57 - E2K_VA_MSB;	/* [57:48] 	*/
	u64	cud_c		: 1;			/* [58:58] 	*/
	u64	unused2		: 5;			/* [63:59] 	*/
} e2k_cute_dw0_fields_t;

typedef	union e2k_cute_dw0 {	
	e2k_cute_dw0_fields_t	fields;	/* as fields 		*/
	u64			word;	/* as entire register 	*/
} e2k_cute_dw0_t;


typedef	struct e2k_cute_dw1_fields {	/* Structure of the second d-word */
					/* of CUT entry 		*/
	u64	unused1		: 32;			/* [31: 0] 	*/
	u64	cud_size	: 32;			/* [63:32] 	*/
} e2k_cute_dw1_fields_t;

typedef	union e2k_cute_dw1 {	
	e2k_cute_dw1_fields_t	fields;	/* as fields 		*/
	u64			word;	/* as entire register 	*/
} e2k_cute_dw1_t;


typedef	struct e2k_cute_dw2_fields {	/* Structure of the third d-word */
					/* of CUT entry 		*/
	u64	gd_base		: E2K_VA_SIZE;		/* [47: 0] 	*/
	u64	unused1		: 63 - E2K_VA_MSB;	/* [63:48] 	*/
} e2k_cute_dw2_fields_t;

typedef	union e2k_cute_dw2 {	
	e2k_cute_dw2_fields_t	fields;	/* as fields 		*/
	u64			word;	/* as entire register 	*/
} e2k_cute_dw2_t;

typedef	struct e2k_cute_dw3_fields {	/* Structure of the fourth d-word */
					/* of CUT entry			*/
	u64	tsd_base	: 15;			/* [14: 0] 	*/
	u64	unused1		: 1;			/* [15:15] 	*/
	u64	tsd_size	: 15;			/* [30:16] 	*/
	u64	unused2		: 1;			/* [31:31] 	*/
	u64	gd_size		: 32;			/* [63:32] 	*/
} e2k_cute_dw3_fields_t;

typedef	union e2k_cute_dw3 {	
	e2k_cute_dw3_fields_t	fields;	/* as fields 		*/
	u64			word;	/* as entire register 	*/
} e2k_cute_dw3_t;

/* Structure of entire CUT entry */
typedef	struct e2k_cute {
	e2k_cute_dw0_t	dw0;
	e2k_cute_dw1_t	dw1;
	e2k_cute_dw2_t	dw2;
	e2k_cute_dw3_t	dw3;
} e2k_cute_t;

#define	CUTE_CUD_BASE(p)	AS_STRUCT(p->dw0).cud_base
#define	CUTE_CUD_SIZE(p)	AS_STRUCT(p->dw1).cud_size
#define	CUTE_CUD_C(p)		AS_STRUCT(p->dw0).cud_c

#define	CUTE_GD_BASE(p)		AS_STRUCT(p->dw2).gd_base
#define	CUTE_GD_SIZE(p)		AS_STRUCT(p->dw3).gd_size

#define	CUTE_TSD_BASE(p)	AS_STRUCT(p->dw3).tsd_base
#define	CUTE_TSD_SIZE(p)	AS_STRUCT(p->dw3).tsd_size

#endif /* !(__ASSEMBLY__) */

#define	E2K_ALIGN_CUT		5		/* Compilation units table */
						/* boundaries alignment */
						/* (2's exponent value */
#ifndef __ASSEMBLY__
#define	E2K_ALIGN_CUT_MASK	((1UL << E2K_ALIGN_CUT) - 1)
#else	/* __ASSEMBLY__ */
#define	E2K_ALIGN_CUT_MASK	((1 << E2K_ALIGN_CUT) - 1)
#endif /* !(__ASSEMBLY__) */

#ifndef __ASSEMBLY__

/* CUTD */

typedef	e2k_rwp_struct_t	e2k_cutd_t;
#define	CUTD_base		E2K_RWP_base	/* [47: 0] - base address */
#define	CUTD_reg		E2K_RWP_reg	/* [63: 0] - entire double- */
						/*           word register */

#define	READ_CUTD_REG_VALUE()	E2K_GET_DSREG_NV(cutd)
#define	WRITE_CUTD_REG_VALUE(CUTD_value) E2K_SET_DSREG_NV_NOIRQ(cutd, CUTD_value)

/* CUIR */

typedef	struct e2k_cuir_fields {	/* Structure of the CUIR reg	*/
	u32	index		: 16;			/* [15: 0] 	*/
	u32	checkup		: 1;			/* [16:16] 	*/
	u32	unused1		: 15;			/* [31:17] 	*/
} e2k_cuir_fields_t;

typedef	union e2k_cuir {
	e2k_cuir_fields_t	fields;	/* as fields 		*/
	u32			word;	/* as entire register 	*/
} e2k_cuir_t;
#define	CUIR_index		fields.index
#define	CUIR_checkup		fields.checkup
#define	CUIR_reg		word

#define	CUD_CFLAG_CEARED	0	/* intermodule security verification */
					/* (ISV) have not passed	     */
#define	CUD_CFLAG_SET		1	/* ISV have passed		     */

#define	READ_CUIR_REG_VALUE()	E2K_GET_SREG(cuir)
#define	WRITE_CUIR_REG_VALUE(CUIR_value) E2K_SET_SREG(cuir, CUIR_value)

/* Chain stack memory mapping (one record, LE) */

typedef	struct e2k_mem_crstack {
	e2k_cr0_lo_t		cr0_lo;
	e2k_cr0_hi_t		cr0_hi;
	e2k_cr1_lo_t		cr1_lo;
	e2k_cr1_hi_t		cr1_hi;
} e2k_mem_crs_t;

/*
 * relative offset from cr_ind for pcsp
 */

#define	CR0_LO_I 0
#define	CR0_HI_I (1 * 8)
#define	CR1_LO_I (2 * 8)
#define	CR1_HI_I (3 * 8)

/*
 * cr1.lo.wbs is size of prev proc in term of size of 4 32 bit reegs.
 * But in hard stack these regs are in extended format (*2)
 */
#define	EXT_4_NR_SZ	((4 * 4) * 2)
#define	SZ_OF_CR	sizeof(e2k_mem_crs_t)


/*
 * Trap Info Registers
 */

typedef	e2k_rwp_struct_t	tir_lo_struct_t;

typedef	struct tir_hi_fields {		/* Structure of the TIR_hi reg	*/
	u64	exc	: 44;	/* exceptions mask [43: 0] 	*/
	u64	al	:  6;	/* ALS mask	   [49:44] 	*/
	u64	unused1	:  2;	/* unused bits	   [51:50] 	*/
	u64	aa	:  4;	/* MOVA mask	   [55:52] 	*/
	u64	j	:  8;	/* # of TIR	   [63:56] 	*/
} tir_hi_fields_t;

typedef	union tir_hi_struct {
	tir_hi_fields_t	fields;	/* as fields 		*/
	u64		word;	/* as entire register 	*/
} tir_hi_struct_t;

typedef struct e2k_tir_reg {		/* simple TIRj register desc */
	union {
		tir_lo_struct_t	TIR_lo;
		tir_lo_struct_t	lo;
	};
	union {
		tir_hi_struct_t	TIR_hi;
		tir_hi_struct_t	hi;
	};
} e2k_tir_t;

	/*
	 * Structure of low word of the register
	 * access TIR_lo.TIR_lo_xxx or TIR_lo -> TIR_lo_xxx
	 */
#define	TIR_lo_ip	E2K_RWP_base		/* [47: 0] - IP of trap */
#define	TIR_lo_reg	E2K_RWP_reg		/* [63: 0] - entire */
						/* double-word register */

	/*
	 * Structure of hi word of the register
	 * access TIR_hi.TIR_hi_xxx or TIR_hi -> TIR_hi_xxx
	 */
#define TIR_hi_reg	word			/* [63: 0] - entire */
//#define TIR_hi		TIR_hi_struct.TIR_hi_reg /* double-word register */

#define	TIR_hi_exc	fields.exc
#define	TIR_hi_al	fields.al
#define	TIR_hi_aa	fields.aa
#define	TIR_hi_j	fields.j

/* ALS mask structure */
#define	ALS0_mask	0x01
#define	ALS1_mask	0x02
#define	ALS2_mask	0x04
#define	ALS3_mask	0x08
#define	ALS4_mask	0x10
#define	ALS5_mask	0x20


/*
 *  User processor status register (UPSR)
 */
typedef	struct e2k_upsr_fields {
	u32	fe	: 1;	/* float-poting enable */
	u32	se	: 1;	/* supervisor mode enable (only for Intel) */
	u32	ac	: 1;	/* not-aligned access control */
	u32	di	: 1;	/* delayed interrupt (only for Intel) */
	u32	wp	: 1;	/* write protection (only for Intel) */
	u32	ie	: 1;	/* interrupt enable */
	u32	a20	: 1;	/* emulation of 1 Mb memory (only for Intel) */
				/* should be 0 for Elbrus */
	u32	nmie	: 1;	/* not masked interrupt enable */
	/* next field of register exist only on E3S/ES2/E2S/E8C/E1C+ CPUs */
	u32	fsm	: 1;	/* floating comparison mode flag */
				/* 1 - compatible with x86/x87 */
	u32	impt	: 1;	/* ignore Memory Protection Table flag */
	u32	iuc	: 1;	/* ignore access right for uncached pages */

} e2k_upsr_fields_t;
typedef	union e2k_upsr {
	e2k_upsr_fields_t	fields;	/* as fields 		*/
	u32			word;	/* as entire register 	*/
} e2k_upsr_t;

#define	READ_UPSR_REG_VALUE()	E2K_GET_SREG_NV(upsr)
#define	WRITE_UPSR_REG_VALUE(UPSR_value)	E2K_SET_SREG(upsr, UPSR_value)

#endif /* !(__ASSEMBLY__) */

#define	UPSR_FE		0x01U
#define	UPSR_SE		0x02U
#define	UPSR_AC		0x04U
#define	UPSR_DI		0x08U
#define	UPSR_WP		0x10U
#define	UPSR_IE		0x20U
#define	UPSR_A20	0x40U
#define	UPSR_NMIE	0x80U
/* next field of register exist only on E3S/ES2/E2S/E8C/E1C+ CPUs */
#define	UPSR_FSM	0x100U
#define	UPSR_IMPT	0x200U
#define	UPSR_IUC	0x400U

#ifndef __ASSEMBLY__
/*
 *  Processor Identification Register (IDR)
 */
typedef	struct e2k_idr_fields {
	u64	mdl	:  8;	/* CPU model number */
	u64	rev	:  4;	/* revision number */
	u64	wbl	:  3;	/* write back length of L2 */
	u64	ms	: 49;	/* model specific info */
} e2k_idr_fields_t;
typedef	union e2k_idr {
	e2k_idr_fields_t	fields;	/* as fields 		*/
	u64			word;	/* as entire register 	*/
} e2k_idr_t;

#define IDR_reg		word		/* [63: 0] - entire */

#define	IDR_mdl		fields.mdl
#define	IDR_rev		fields.rev
#define	IDR_wbl		fields.wbl
#define	IDR_ms		fields.ms

/* Cache write back length */
#define	IDR_0_WBL		0x0	/* none CPU internal cache */
#define	IDR_32_WBL		0x1
#define	IDR_64_WBL		0x2
#define	IDR_128_WBL		0x3
#define	IDR_256_WBL		0x4

/* Convert IDR register write back length code to number of bytes */
/* using current WBL code presentation */
#define	IDR_WBL_TO_BYTES(wbl)	((wbl) ? (1 << (wbl + 4)) : 1)

#define	READ_IDR_REG_VALUE()	E2K_GET_SREG(idr)


/*
 *  Packed Floating Point Flag Register (PFPFR)
 */
typedef	struct e2k_pfpfr_fields {
	u32	ie	: 1;		/* [0] 	*/
	u32	de	: 1;		/* [1] 	*/
	u32	ze	: 1;		/* [2] 	*/
	u32	oe	: 1;		/* [3] 	*/
	u32	ue	: 1;		/* [4] 	*/
	u32	pe	: 1;		/* [5] 	*/
	u32	zero1	: 1;		/* [6] 	*/
	u32	im	: 1;		/* [7] 	*/
	u32	dm	: 1;		/* [8] 	*/
	u32	zm	: 1;		/* [9] 	*/
	u32	om	: 1;		/* [10] */
	u32	um	: 1;		/* [11] */
	u32	pm	: 1;		/* [12] */
	u32	rc	: 2;		/* [14:13] */
	u32	fz	: 1;		/* [15] */
	u32	zero2	: 10;		/* [25:16] */
	u32	die	: 1;		/* [26] */
	u32	dde	: 1;		/* [27] */
	u32	dze	: 1;		/* [28] */
	u32	doe	: 1;		/* [29] */
	u32	due	: 1;		/* [30] */
	u32	dpe	: 1;		/* [31] */
} e2k_pfpfr_fields_t;
typedef	union e2k_pfpfr {	
	e2k_pfpfr_fields_t	fields;	/* as fields 		*/
	u32		word;	/* as entire register 	*/
} e2k_pfpfr_t;

/*
 *  Floating point control register (FPCR)
 */
typedef	struct e2k_fpcr_fields {
	u32	im	: 1;		/* [0] 	*/
	u32	dm	: 1;		/* [1] 	*/
	u32	zm	: 1;		/* [2] 	*/
	u32	om	: 1;		/* [3] 	*/
	u32	um	: 1;		/* [4] 	*/
	u32	pm	: 1;		/* [5] 	*/
	u32	one1	: 1;		/* [6] 	*/
	u32	zero1	: 1;		/* [7] 	*/
	u32	pc	: 2;		/* [9:8] */
	u32	rc	: 2;		/* [11:10] */
	u32	ic	: 1;		/* [12] */
	u32	zero2	: 3;		/* [15:13] */
} e2k_fpcr_fields_t;
typedef	union e2k_fpcr {	
	e2k_fpcr_fields_t	fields;	/* as fields 		*/
	u32			word;	/* as entire register 	*/
} e2k_fpcr_t;


/*
 * Floating point status register (FPSR)
 */
typedef	struct e2k_fpsr_fields {
	u32	ie	: 1;		/* [0] 	*/
	u32	de	: 1;		/* [1] 	*/
	u32	ze	: 1;		/* [2] 	*/
	u32	oe	: 1;		/* [3] 	*/
	u32	ue	: 1;		/* [4] 	*/
	u32	pe	: 1;		/* [5] 	*/
	u32	zero1	: 1;		/* [6] 	*/
	u32	es	: 1;		/* [7]  */
	u32	zero2	: 1;		/* [8]  */
	u32	c1	: 1;		/* [9]  */
	u32	zero3	: 5;		/* [14:10] */
	u32	bf	: 1;		/* [15] */
} e2k_fpsr_fields_t;
typedef	union e2k_fpsr {	
	e2k_fpsr_fields_t	fields;	/* as fields 		*/
	u32			word;	/* as entire register 	*/
} e2k_fpsr_t;

typedef union {
	struct {               /* structure of register */
		u32 user    : 1;     /*  [ 0: 0] */
		u32 system  : 1;     /*  [ 1: 1] */
		u32 trap    : 1;     /*  [ 2: 2] */
		u32 unused  : 13;    /* [15: 3] */
		u32 event   : 7;     /* [22:16] */
		u32 unused2 : 9;     /* [31:23] */
	} fields[2];
	u64 word;
} e2k_ddmcr_t;

typedef	union {
	struct {
		u32 user    : 1;
		u32 system  : 1;
		u32 trap    : 1;
		u32 unused1 : 13;
		u32 event   : 7;
		u32 unused2 : 9;
	} fields[2];
	u64 word;
} e2k_dimcr_t;

typedef union {
	struct {               /* structure of register */
		u32 b0    : 1;       /* [0] */
		u32 b1    : 1;       /*     */
		u32 b2    : 1;       /*     */
		u32 b3    : 1;       /*     */
		u32 bt    : 1;       /* [4] */
		u32 m0    : 1;       /* [5] */
		u32 m1    : 1;       /* [6] */
		u32 ss    : 1;       /* [7] */
		u32 btf   : 1;       /* [8] */
	} fields;
	u32 word;
} e2k_dibsr_t;

typedef union {
	struct {                
		u32  v0    : 1;
		u32  t0    : 1;
		u32  v1    : 1;
		u32  t1    : 1;
		u32  v2    : 1;
		u32  t2    : 1;
		u32  v3    : 1;
		u32  t3    : 1;
		u32  bt    : 1;
		u32  stop  : 1;
		u32  btf   : 1;
	} fields;
	u32 word;
} e2k_dibcr_t;

typedef union {
	union {
		struct {
			u64 sprg0 : 1;
			u64 spec0 : 1;
			u64 aprg0 : 1;
			u64 psf0  : 1;
			u64 csf0  : 1;
			u64 cut0  : 1;
			u64 pt0   : 1;
			u64 clw0  : 1;
			u64       : 4;

			u64 sprg1 : 1;
			u64 spec1 : 1;
			u64 aprg1 : 1;
			u64 psf1  : 1;
			u64 csf1  : 1;
			u64 cut1  : 1;
			u64 pt1   : 1;
			u64 clw1  : 1;
			u64       : 4;

			u64 sprg2 : 1;
			u64 spec2 : 1;
			u64 aprg2 : 1;
			u64 psf2  : 1;
			u64 csf2  : 1;
			u64 cut2  : 1;
			u64 pt2   : 1;
			u64 clw2  : 1;
			u64       : 4;

			u64 sprg3 : 1;
			u64 spec3 : 1;
			u64 aprg3 : 1;
			u64 psf3  : 1;
			u64 csf3  : 1;
			u64 cut3  : 1;
			u64 pt3   : 1;
			u64 clw3  : 1;
			u64       : 4;

			u64       : 1;
			u64 m0    : 1;
			u64 m1    : 1;
			u64       : 13;
		};
		struct {
			u64 b0    : 8;
			u64       : 4;
			u64 b1    : 8;
			u64       : 4;
			u64 b2    : 8;
			u64       : 4;
			u64 b3    : 8;
			u64       : 4;
			u64       : 16;
		};
	} fields;
	u64 word;
} e2k_ddbsr_t;

typedef	union {
	struct {
		u64 v0    : 1;
		u64 root0 : 1;
		u64 rw0   : 2;
		u64 lng0  : 3;
		u64 sync0 : 1;
		u64 spec0 : 1;
		u64 ap0   : 1;
		u64 sf0   : 1;
		u64 hw0   : 1;
		u64 t0    : 1;
		u64 __x0  : 1;
		u64 v1    : 1;
		u64 root1 : 1;
		u64 rw1   : 2;
		u64 lng1  : 3;
		u64 sync1 : 1;
		u64 spec1 : 1;
		u64 ap1   : 1;
		u64 sf1   : 1;
		u64 hw1   : 1;
		u64 t1    : 1;
		u64 __x1  : 1;
		u64 v2    : 1;
		u64 root2 : 1;
		u64 rw2   : 2;
		u64 lng2  : 3;
		u64 sync2 : 1;
		u64 spec2 : 1;
		u64 ap2   : 1;
		u64 sf2   : 1;
		u64 hw2   : 1;
		u64 t2    : 1;
		u64 __x2  : 1;
		u64 v3    : 1;
		u64 root3 : 1;
		u64 rw3   : 2;
		u64 lng3  : 3;
		u64 sync3 : 1;
		u64 spec3 : 1;
		u64 ap3   : 1;
		u64 sf3   : 1;
		u64 hw3   : 1;
		u64 t3    : 1;
		u64 __x3  : 1;
	} fields;
	u64 word;
} e2k_ddbcr_t;

/* CU_HW0 register */
#define _CU_HW0_IB_SNOOP_DISABLE_MASK  0x00000200 /* Disable IB snooping */

#endif /* ! __ASSEMBLY__ */

#endif /* __KERNEL__ */

#endif  /* _E2K_CPU_REGS_H_ */
