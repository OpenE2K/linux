#ifndef	_E2K_KVM_CPU_HV_REGS_TYPES_H_
#define	_E2K_KVM_CPU_HV_REGS_TYPES_H_

#ifdef __KERNEL__

#include <asm/types.h>

#ifndef __ASSEMBLY__

typedef	union virt_ctrl_cu {
	struct {
		u64 evn_c		: 16;	/* [15: 0]	*/
		u64 exc_c		:  8;	/* [23:16]	*/
		u64 glnch		:  2;	/* [25:24]	*/
		u64 __pad1		: 38;	/* [63:26]	*/
	};
	struct {
		/* env_c:	*/
		u64 rr_idr		:  1;	/*    [ 0]	*/
		u64 rr_clkr		:  1;	/*    [ 1]	*/
		u64 rr_sclkr		:  1;	/*    [ 2]	*/
		u64 rr_dbg		:  1;	/*    [ 3]	*/
		u64 rw_core_mode	:  1;	/*    [ 4]	*/
		u64 rw_clkr		:  1;	/*    [ 5]	*/
		u64 rw_sclkr		:  1;	/*    [ 6]	*/
		u64 rw_sclkm3		:  1;	/*    [ 7]	*/
		u64 rw_dbg		:  1;	/*    [ 8]	*/
		u64 hcem		:  1;	/*    [ 9]	*/
		u64 virt		:  1;	/*    [10]	*/
		u64 stop		:  1;	/*    [11]	*/
		u64 evn_c_res		:  4;	/* [15:12]	*/
		/* exc_c:	*/
		u64 exc_instr_debug	:  1;	/*    [16]	*/
		u64 exc_data_debug	:  1;	/*    [17]	*/
		u64 exc_instr_page	:  1;	/*    [18]	*/
		u64 exc_data_page	:  1;	/*    [19]	*/
		u64 exc_mova		:  1;	/*    [20]	*/
		u64 exc_interrupt	:  1;	/*    [21]	*/
		u64 exc_nm_interrupt	:  1;	/*    [22]	*/
		u64 exc_c_res		:  1;	/*    [23]	*/
		/* glnch:	*/
		u64 g_th		:  1;	/*    [24]	*/
		u64 tir_fz		:  1;	/*    [25]	*/
		u64 tir_rst		:  1;	/*    [26]	*/
		u64 __resb		: 37;	/* [63:27]	*/
	};
	u64			word;	/* as entire register	*/
} virt_ctrl_cu_t;
#define	VIRT_CTRL_CU_evn_c		evn_c	/* events mask to intercept */
#define	VIRT_CTRL_CU_rr_idr		rr_idr
#define	VIRT_CTRL_CU_rr_clkr		rr_clkr
#define	VIRT_CTRL_CU_rr_sclkr		rr_sclkr
#define	VIRT_CTRL_CU_rr_dbg		rr_dbg
#define	VIRT_CTRL_CU_rw_core_mode	rw_core_mode
#define	VIRT_CTRL_CU_rw_clkr		rw_clkr
#define	VIRT_CTRL_CU_rw_sclkr		rw_sclkr
#define	VIRT_CTRL_CU_rw_sclkm3		rw_sclkm3
#define	VIRT_CTRL_CU_rw_dbg		rw_dbg
#define	VIRT_CTRL_CU_hcem		hcem
#define	VIRT_CTRL_CU_virt		virt
#define	VIRT_CTRL_CU_stop		stop
#define	VIRT_CTRL_CU_exc_c		exc_c	/* exceptions mask */
						/* to intercept */
#define	VIRT_CTRL_CU_exc_instr_debug	exc_instr_debug
#define	VIRT_CTRL_CU_exc_data_debug	exc_data_debug
#define	VIRT_CTRL_CU_exc_instr_page	exc_instr_page
#define	VIRT_CTRL_CU_exc_data_page	exc_data_page
#define	VIRT_CTRL_CU_exc_mova		exc_mova
#define	VIRT_CTRL_CU_exc_interrupt	exc_interrupt
#define	VIRT_CTRL_CU_exc_nm_interrupt	exc_nm_interrupt
#define	VIRT_CTRL_CU_glnch		glnch	/* modes of guest launch */
						/* instruction execution */
#define	VIRT_CTRL_CU_glnch_g_th		g_th
#define	VIRT_CTRL_CU_glnch_tir_fz	tir_fz
#define	VIRT_CTRL_CU_tir_rst		tir_rst /* mode of TIR registers */
						/* restore */
#define	VIRT_CTRL_CU_reg	word		/* [63: 0] - entire register */

#endif /* ! __ASSEMBLY__ */

#define	INTC_CU_COND_EVENT_NO		0
#define	INTC_CU_COND_EVENT_MAX		16
#define	INTC_CU_COND_EXC_NO		(INTC_CU_COND_EVENT_NO + \
					INTC_CU_COND_EVENT_MAX)
#define	INTC_CU_COND_EXC_MAX		8
#define	INTC_CU_UNCOND_EVENT_NO		(INTC_CU_COND_EXC_NO + \
					INTC_CU_COND_EXC_MAX)
#define	INTC_CU_UNCOND_EVENT_MAX	8
#define	INTC_CU_EVENTS_NUM_MAX		(INTC_CU_COND_EVENT_MAX + \
					INTC_CU_COND_EXC_MAX + \
					INTC_CU_UNCOND_EVENT_MAX)
typedef union {
	struct {
		u64 evn_c	: INTC_CU_COND_EVENT_MAX;
		u64 exc_c	: INTC_CU_COND_EXC_MAX;
		u64 evn_u	: INTC_CU_UNCOND_EVENT_MAX;
		u64 hi_half	: 32;
	};
	struct {
		/* evn_c fields */
		u64 rr_idr		: 1;
		u64 rr_clkr		: 1;
		u64 rr_sclkr		: 1;
		u64 rr_dbg		: 1;
		u64 rw_core_mode	: 1;
		u64 rw_clkr		: 1;
		u64 rw_sclkr		: 1;
		u64 rw_sclkm3		: 1;
		u64 rw_dbg		: 1;
		u64 hcem		: 1;
		u64 virt		: 1;
		u64 stop		: 1;
		u64 hret_last_wish	: 1;
		u64 __reserved_evn_c	: 3;
		/* exc_c fields */
		u64 exc_instr_debug	: 1;
		u64 exc_data_debug	: 1;
		u64 exc_instr_page	: 1;
		u64 exc_data_page	: 1;
		u64 exc_mova		: 1;
		u64 exc_interrupt	: 1;
		u64 exc_nm_interrupt	: 1;
		u64 __reserved_exc_c	: 1;
		/* evn_u fields */
		u64 hv_int		: 1;
		u64 hv_nm_int		: 1;
		u64 g_tmr		: 1;
		u64 rr			: 1;
		u64 rw			: 1;
		u64 exc_mem_error	: 1;
		u64 wait_trap		: 1;
		u64 dbg			: 1;
		/* high half of hdr_lo */
		u64 tir_fz		: 1;
		u64 __reserved		: 31;
	};
	u64 word;
} intc_info_cu_hdr_lo_t;

/* evn_c fields bit # */
#define INTC_CU_RR_IDR_NO		0
#define INTC_CU_RR_CLKR_NO		1
#define INTC_CU_RR_SCLKR_NO		2
#define INTC_CU_RR_DBG_NO		3
#define INTC_CU_RW_CORE_MODE_NO		4
#define INTC_CU_RW_CLKR_NO		5
#define INTC_CU_RW_SCLKR_NO		6
#define INTC_CU_RW_SCLKM3_NO		7
#define INTC_CU_RW_DBG_NO		8
#define INTC_CU_HCEM_NO			9
#define INTC_CU_VIRT_NO			10
#define INTC_CU_STOP_NO			11
#define	INTC_CU_HRET_LAST_WISH_NO	12

/* INTC_INFO_CU.evn_c fields mask */
#define intc_cu_evn_c_rr_idr_mask	(1UL << INTC_CU_RR_IDR_NO)
#define intc_cu_evn_c_rr_clkr_mask	(1UL << INTC_CU_RR_CLKR_NO)
#define intc_cu_evn_c_rr_sclkr_mask	(1UL << INTC_CU_RR_SCLKR_NO)
#define intc_cu_evn_c_rr_dbg_mask	(1UL << INTC_CU_RR_DBG_NO)
#define intc_cu_evn_c_rw_core_mode_mask	(1UL << INTC_CU_RW_CORE_MODE_NO)
#define intc_cu_evn_c_rw_clkr_mask	(1UL << INTC_CU_RW_CLKR_NO)
#define intc_cu_evn_c_rw_sclkr_mask	(1UL << INTC_CU_RW_SCLKR_NO)
#define intc_cu_evn_c_rw_sclkm3_mask	(1UL << INTC_CU_RW_SCLKM3_NO)
#define intc_cu_evn_c_rw_dbg_mask	(1UL << INTC_CU_RW_DBG_NO)
#define intc_cu_evn_c_hcem_mask		(1UL << INTC_CU_HCEM_NO)
#define intc_cu_evn_c_virt_mask		(1UL << INTC_CU_VIRT_NO)
#define intc_cu_evn_c_stop_mask		(1UL << INTC_CU_STOP_NO)
#define	intc_cu_evn_c_hret_last_wish_mask (1UL << INTC_CU_HRET_LAST_WISH_NO)

/* common mask of all 'read registers' interceptions */
#define intc_cu_evn_c_rr_mask		(intc_cu_evn_c_rr_idr_mask | \
					intc_cu_evn_c_rr_clkr_mask | \
					intc_cu_evn_c_rr_sclkr_mask | \
					intc_cu_evn_c_rr_dbg_mask)
/* common mask of all 'write registers' interceptions */
#define intc_cu_evn_c_rw_mask		(intc_cu_evn_c_rw_core_mode_mask | \
					intc_cu_evn_c_rw_clkr_mask | \
					intc_cu_evn_c_rw_sclkr_mask | \
					intc_cu_evn_c_rw_sclkm3_mask | \
					intc_cu_evn_c_rw_dbg_mask)
/* INTC_INFO_CU.hdr.evn_c fields mask */
#define intc_cu_hdr_lo_rr_idr_mask	\
		(intc_cu_evn_c_rr_idr_mask << INTC_CU_COND_EVENT_NO)
#define intc_cu_hdr_lo_rr_clkr_mask	\
		(intc_cu_evn_c_rr_clkr_mask << INTC_CU_COND_EVENT_NO)
#define intc_cu_hdr_lo_rr_sclkr_mask	\
		(intc_cu_evn_c_rr_sclkr_mask << INTC_CU_COND_EVENT_NO)
#define intc_cu_hdr_lo_rr_dbg_mask	\
		(intc_cu_evn_c_rr_dbg_mask << INTC_CU_COND_EVENT_NO)
#define intc_cu_hdr_lo_rw_core_mode_mask \
		(intc_cu_evn_c_rw_core_mode_mask << INTC_CU_COND_EVENT_NO)
#define intc_cu_hdr_lo_rw_clkr_mask	\
		(intc_cu_evn_c_rw_clkr_mask << INTC_CU_COND_EVENT_NO)
#define intc_cu_hdr_lo_rw_sclkr_mask	\
		(intc_cu_evn_c_rw_sclkr_mask << INTC_CU_COND_EVENT_NO)
#define intc_cu_hdr_lo_rw_sclkm3_mask	\
		(intc_cu_evn_c_rw_sclkm3_mask << INTC_CU_COND_EVENT_NO)
#define intc_cu_hdr_lo_rw_dbg_mask	\
		(intc_cu_evn_c_rw_dbg_mask << INTC_CU_COND_EVENT_NO)
#define intc_cu_hdr_lo_hcem_mask	\
		(intc_cu_evn_c_hcem_mask << INTC_CU_COND_EVENT_NO)
#define intc_cu_hdr_lo_virt_mask	\
		(intc_cu_evn_c_virt_mask << INTC_CU_COND_EVENT_NO)
#define intc_cu_hdr_lo_stop_mask	\
		(intc_cu_evn_c_stop_mask << INTC_CU_COND_EVENT_NO)
#define	intc_cu_hdr_lo_hret_last_wish_mask \
		(intc_cu_evn_c_hret_last_wish_mask << INTC_CU_COND_EVENT_NO)

/* common mask of all 'read registers' interceptions */
#define intc_cu_hrd_lo_rr_mask		(intc_cu_hdr_lo_rr_idr_mask | \
					intc_cu_hdr_lo_rr_clkr_mask | \
					intc_cu_hdr_lo_rr_sclkr_mask | \
					intc_cu_hdr_lo_rr_dbg_mask)
/* common mask of all 'write registers' interceptions */
#define intc_cu_hrd_lo_rw_mask		(intc_cu_hdr_lo_rw_core_mode_mask | \
					intc_cu_hdr_lo_rw_clkr_mask | \
					intc_cu_hdr_lo_rw_sclkr_mask | \
					intc_cu_hdr_lo_rw_sclkm3_mask | \
					intc_cu_hdr_lo_rw_dbg_mask)

/* exc_c fields bit # */
#define INTC_CU_EXC_INSTR_DEBUG_NO		0
#define INTC_CU_EXC_DATA_DEBUG_NO		1
#define INTC_CU_EXC_INSTR_PAGE_NO		2
#define INTC_CU_EXC_DATA_PAGE_NO		3
#define INTC_CU_EXC_MOVA_NO			4
#define INTC_CU_EXC_INTERRUPT_NO		5
#define INTC_CU_EXC_NM_INTERRUPT_NO		6
/* exc_c fields mask */
#define intc_cu_exc_c_exc_instr_debug_mask	\
		(1UL << INTC_CU_EXC_INSTR_DEBUG_NO)
#define intc_cu_exc_c_exc_data_debug_mask	\
		(1UL << INTC_CU_EXC_DATA_DEBUG_NO)
#define intc_cu_exc_c_exc_instr_page_mask	\
		(1UL << INTC_CU_EXC_INSTR_PAGE_NO)
#define intc_cu_exc_c_exc_data_page_mask	\
		(1UL << INTC_CU_EXC_DATA_PAGE_NO)
#define intc_cu_exc_c_exc_mova_mask		\
		(1UL << INTC_CU_EXC_MOVA_NO)
#define intc_cu_exc_c_exc_interrupt_mask	\
		(1UL << INTC_CU_EXC_INTERRUPT_NO)
#define intc_cu_exc_c_exc_nm_interrupt_mask	\
		(1UL << INTC_CU_EXC_NM_INTERRUPT_NO)
/* INTC_INFO_CU.exc_c fields mask */
#define intc_cu_hdr_lo_exc_instr_debug_mask	\
		(intc_cu_exc_c_exc_instr_debug_mask << INTC_CU_COND_EXC_NO)
#define intc_cu_hdr_lo_exc_data_debug_mask	\
		(intc_cu_exc_c_exc_data_debug_mask << INTC_CU_COND_EXC_NO)
#define intc_cu_hdr_lo_exc_instr_page_mask	\
		(intc_cu_exc_c_exc_instr_page_mask << INTC_CU_COND_EXC_NO)
#define intc_cu_hdr_lo_exc_data_page_mask	\
		(intc_cu_exc_c_exc_data_page_mask << INTC_CU_COND_EXC_NO)
#define intc_cu_hdr_lo_exc_mova_mask		\
		(intc_cu_exc_c_exc_mova_mask << INTC_CU_COND_EXC_NO)
#define intc_cu_hdr_lo_exc_interrupt_mask	\
		(intc_cu_exc_c_exc_interrupt_mask << INTC_CU_COND_EXC_NO)
#define intc_cu_hdr_lo_exc_nm_interrupt_mask	\
		(intc_cu_exc_c_exc_nm_interrupt_mask << INTC_CU_COND_EXC_NO)

/* evn_u fields bit # */
#define INTC_CU_HV_INT_NO			0
#define INTC_CU_HV_NM_INT_NO			1
#define INTC_CU_G_TMR_NO			2
#define INTC_CU_RR_NO				3
#define INTC_CU_RW_NO				4
#define INTC_CU_EXC_MEM_ERROR_NO		5
#define INTC_CU_WAIT_TRAP_NO			6
#define INTC_CU_DBG_NO				7
/* evn_u fields mask */
#define intc_cu_evn_u_hv_int_mask		(1UL << INTC_CU_HV_INT_NO)
#define intc_cu_evn_u_hv_nm_int_mask		(1UL << INTC_CU_HV_NM_INT_NO)
#define intc_cu_evn_u_g_tmr_mask		(1UL << INTC_CU_G_TMR_NO)
#define intc_cu_evn_u_rr_mask			(1UL << INTC_CU_RR_NO)
#define intc_cu_evn_u_rw_mask			(1UL << INTC_CU_RW_NO)
#define intc_cu_evn_u_exc_mem_error_mask	\
		(1UL << INTC_CU_EXC_MEM_ERROR_NO)
#define intc_cu_evn_u_wait_trap_mask		(1UL << INTC_CU_WAIT_TRAP_NO)
#define intc_cu_evn_u_dbg_mask			(1UL << INTC_CU_DBG_NO)
/* INT_INFO_CU.evn_u fields mask */
#define intc_cu_hdr_lo_hv_int_mask		\
		(intc_cu_evn_u_hv_int_mask << INTC_CU_UNCOND_EVENT_NO)
#define intc_cu_hdr_lo_hv_nm_int_mask		\
		(intc_cu_evn_u_hv_nm_int_mask << INTC_CU_UNCOND_EVENT_NO)
#define intc_cu_hdr_lo_g_tmr_mask		\
		(intc_cu_evn_u_g_tmr_mask << INTC_CU_UNCOND_EVENT_NO)
#define intc_cu_hdr_lo_rr_mask			\
		(intc_cu_evn_u_rr_mask << INTC_CU_UNCOND_EVENT_NO)
#define intc_cu_hdr_lo_rw_mask			\
		(intc_cu_evn_u_rw_mask << INTC_CU_UNCOND_EVENT_NO)
#define intc_cu_hdr_lo_exc_mem_error_mask	\
		(intc_cu_evn_u_exc_mem_error_mask << INTC_CU_UNCOND_EVENT_NO)
#define intc_cu_hdr_lo_wait_trap_mask	\
		(intc_cu_evn_u_wait_trap_mask << INTC_CU_UNCOND_EVENT_NO)
#define intc_cu_hdr_lo_dbg_mask	\
		(intc_cu_evn_u_dbg_mask << INTC_CU_UNCOND_EVENT_NO)

#if	(1UL << INTC_CU_EVENTS_NUM_MAX) < intc_cu_hdr_lo_dbg_mask
#error	"INTC_CU_EVENTS_NUM_MAX value is out of real events number"
#endif

#define	INTC_CU_TIR_FZ_NO			32
#define intc_cu_hdr_lo_tir_fz_mask		(1UL << INTC_CU_TIR_FZ_NO)

typedef union {
	u64 word;
} intc_info_cu_hdr_hi_t;

typedef struct e2k_intc_info_cu_hdr {
	intc_info_cu_hdr_lo_t lo;
	intc_info_cu_hdr_hi_t hi;
} intc_info_cu_hdr_t;

typedef union {
	struct {
		u64 event_code		: 8;
		u64 ch_code		: 4;
		u64 reg_num		: 8;
		u64 dst			: 8;
		u64 vm_dst		: 3;
		u64 __reserved		: 33;
	};
	u64 word;
} intc_info_cu_entry_lo_t;

#define intc_cu_info_lo_get_event_code(x) ((x) & 0xff)

/* Possible values for `INTC_INFO_CU[2 * j].event_code' */
typedef enum info_cu_event_code {
	ICE_FORCED = 0,
	ICE_READ_CU = 1,
	ICE_WRITE_CU = 2,
	ICE_MASKED_HCALL = 3,
	ICE_GLAUNCH = 4,
	ICE_HRET = 5,
} info_cu_event_code_t;

typedef u64 intc_info_cu_entry_hi_t;

typedef struct e2k_intc_info_cu_entry {
	intc_info_cu_entry_lo_t lo;
	intc_info_cu_entry_hi_t hi;
	bool no_restore;
} intc_info_cu_entry_t;

#define INTC_INFO_CU_MAX	6
#define	INTC_INFO_CU_HDR_MAX	2
#define INTC_INFO_CU_ENTRY_MAX (INTC_INFO_CU_MAX - INTC_INFO_CU_HDR_MAX)
#define INTC_INFO_CU_PAIRS_MAX (INTC_INFO_CU_ENTRY_MAX / 2)

typedef struct {
	intc_info_cu_hdr_t header;
	intc_info_cu_entry_t entry[INTC_INFO_CU_PAIRS_MAX];
} intc_info_cu_t;

typedef union {
	struct {
		u64 tmr		: 32;
		u64 v		: 1;
		u64 __reserved	: 31;
	};
	u64 word;
} g_preempt_tmr_t;

#endif /* __KERNEL__ */

#endif  /* _E2K_KVM_CPU_HV_REGS_TYPES_H_ */
