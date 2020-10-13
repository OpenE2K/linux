/*
 * $Id: mlt.h,v 1.15 2009/11/05 12:30:21 kravtsunov_e Exp $
 */
#ifndef _E2K_MLT_H_
#define _E2K_MLT_H_


#include <asm/cpu_regs.h>
#include <asm/types.h>
#include <uapi/asm/mlt.h>

#define E3M_MLT_SIZE		15
#define E3S_MLT_SIZE		16
#define E2K_MAX_MLT_SIZE	E3S_MLT_SIZE
#define	E2K_MLT_SIZE		((IS_MACHINE_E3M) ? E3M_MLT_SIZE : E3S_MLT_SIZE)

#define REG_MLT_N_SHIFT		7

typedef unsigned long	e2k_mlt_line_t;

typedef struct e2k_mlt_first_fields
{
	e2k_mlt_line_t	resc		: 4;	/* [3:0] */
	e2k_mlt_line_t	mask		: 8;	/* [11:4] */
	e2k_mlt_line_t	page		: 28;	/* [39:12]*/
	e2k_mlt_line_t	opcod_size	: 3;	/* [42:40] */
	e2k_mlt_line_t	rg		: 8;	/* [50:43] */
	e2k_mlt_line_t	st_ld_lock	: 1;	/* [51] */
	e2k_mlt_line_t	hit		: 1;	/* [52] */
	e2k_mlt_line_t	val		: 1;	/* [53] */
	e2k_mlt_line_t	unresolved	: 10; 	/* [63:54] */
} e2k_mlt_first_fields_t;

typedef struct e2k_mlt_second_fields
{
	e2k_mlt_line_t	byte		: 3;	/* [2:0] */
	e2k_mlt_line_t	word		: 9;	/* [11:3] */
	e2k_mlt_line_t	virt_page	: 36;	/* [47:12]*/
	e2k_mlt_line_t	unresolved	: 16; 	/* [63:48] */
} e2k_mlt_second_fields_t;

typedef struct e2k_mlt_third_fields
{
	e2k_mlt_line_t	sec_resc	: 4;	/* [3:0] */
	e2k_mlt_line_t	mask_sec	: 8;	/* [11:4] */
	e2k_mlt_line_t	next		: 9;	/* [20:12]*/
	e2k_mlt_line_t	sec_page	: 2;	/* [22:20] */
	e2k_mlt_line_t	second		: 1;	/* [23] */
	e2k_mlt_line_t	pbv		: 1;	/* [24] */
	e2k_mlt_line_t	unresolved	: 39; 	/* [63:25] */
} e2k_mlt_third_fields_t;

/* One reg (string) in MLT table */
typedef struct e2k_mlt_entry {
	union e2k_mlt_first_struct {
		e2k_mlt_first_fields_t	fields;
		e2k_mlt_line_t		word;
	} first_part;
	union e2k_mlt_second_struct {
		e2k_mlt_second_fields_t	fields;
		e2k_mlt_line_t		word;
	} second_part;
	union e2k_mlt_third_struct {
		e2k_mlt_third_fields_t	fields;
		e2k_mlt_line_t		word;
	} third_part;
} e2k_mlt_entry_t;

typedef struct e2k_mlt {
	int num;	/* number of entries in the MLT */
	e2k_mlt_entry_t mlt[E2K_MAX_MLT_SIZE];	/* valid MLT entries */
} e2k_mlt_t;

extern void invalidate_MLT_context(void);
extern void get_and_invalidate_MLT_context(e2k_mlt_t *mlt_state);
extern const e2k_addr_t	reg_addr_part1;

#define MLT_NOT_EMPTY()                                                 \
({									\
	register long res0, res1, res2, res3, res4;			\
	register long res5, res6, res7, res8, res9;			\
	register long res10, res11, res12, res13, res14, res15;		\
	register long all_mlt;						\
	register long reg_addr_part;					\
									\
	reg_addr_part = reg_addr_part1;					\
									\
        res0 = E2K_READ_MLT_REG((reg_addr_part |                        \
					(0 << REG_MLT_N_SHIFT)));       \
        res1 = E2K_READ_MLT_REG((reg_addr_part |                        \
					(1 << REG_MLT_N_SHIFT)));       \
        res2 = E2K_READ_MLT_REG((reg_addr_part |                        \
					(2 << REG_MLT_N_SHIFT)));       \
        res3 = E2K_READ_MLT_REG((reg_addr_part |                        \
					(3 << REG_MLT_N_SHIFT)));       \
        res4 = E2K_READ_MLT_REG((reg_addr_part |                        \
					(4 << REG_MLT_N_SHIFT)));       \
        res5 = E2K_READ_MLT_REG((reg_addr_part |                        \
					(5 << REG_MLT_N_SHIFT)));       \
        res6 = E2K_READ_MLT_REG((reg_addr_part |                        \
					(6 << REG_MLT_N_SHIFT)));       \
        res7 = E2K_READ_MLT_REG((reg_addr_part |                        \
					(7 << REG_MLT_N_SHIFT)));       \
        res8 = E2K_READ_MLT_REG((reg_addr_part |                        \
					(8 << REG_MLT_N_SHIFT)));       \
        res9 = E2K_READ_MLT_REG((reg_addr_part |                        \
					(9 << REG_MLT_N_SHIFT)));       \
        res10 = E2K_READ_MLT_REG((reg_addr_part |                       \
					(10 << REG_MLT_N_SHIFT)));      \
        res11 = E2K_READ_MLT_REG((reg_addr_part |                       \
					(11 << REG_MLT_N_SHIFT)));      \
        res12 = E2K_READ_MLT_REG((reg_addr_part |                       \
					(12 << REG_MLT_N_SHIFT)));      \
        res13 = E2K_READ_MLT_REG((reg_addr_part |                       \
					(13 << REG_MLT_N_SHIFT)));      \
        res14 = E2K_READ_MLT_REG((reg_addr_part |                       \
					(14 << REG_MLT_N_SHIFT)));      \
        if (E2K_MLT_SIZE > 15) {                                        \
                res15 = E2K_READ_MLT_REG((reg_addr_part |               \
					(15 << REG_MLT_N_SHIFT)));      \
	} else {                                                        \
		res15 = 0;						\
	}								\
	all_mlt = (res0 | res1) | (res2 | res3) | (res4 | res5) |       \
		(res6 | res7) | (res8 | res9) | (res10 | res11) |       \
		(res12 | res13 | res14 | res15);                        \
	all_mlt = (all_mlt >> 53) & 0x1;                                \
	unlikely(all_mlt);						\
})

typedef unsigned long	e2k_dam_t;

#define REG_DAM_N_SHIFT		7
#define	REG_DAM_TYPE_SHIFT	0
#define REG_DAM_TYPE		4

#define	E2K_READ_DAM_REG(addr) \
		_E2K_READ_MAS(addr, MAS_DAM_REG, e2k_dam_t, d, 2)

#define SAVE_BINCO_REGS_FOR_PTRACE(regs)				\
do {									\
	regs->rpr_lo = E2K_GET_DSREG(rpr.lo);				\
	regs->rpr_hi = E2K_GET_DSREG(rpr.hi);				\
} while (0)

#endif
