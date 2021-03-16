/*
 * asm-e2k/mmu_regs.h: E2K MMU structures & registers.
 *
 * Copyright 2001 Salavat S. Guiliazov (atic@mcst.ru)
 */

#ifndef	_E2K_KVM_MMU_HV_REGS_TYPES_H_
#define	_E2K_KVM_MMU_HV_REGS_TYPES_H_

#include <linux/types.h>
#include <asm/mmu_regs_types.h>

/*
 * Structures of MMU registers for hardware virtualized extensions
 */

/* MMU address to access to MMU internal registers */

#define	_MMU_VIRT_CTRL_NO	0x40	/* MMU virtualization control */
#define	_MMU_GID_NO		0x41	/* guest machine ID */
#define	_MMU_GP_PPTB_NO		0x43	/* physical base of guest PTs */
#define	_MMU_INTC_INFO_NO	0x44	/* MMU intercept info */
#define	_MMU_INTC_PTR_NO	0x45	/* MMU intercept info pointer */
#define	_MMU_SH_OS_VPTB_NO	0x46	/* virtual base of guest shadow PTs */
#define	_MMU_SH_OS_PPTB_NO	0x47	/* physical base of guest shadow PTs */
#define	_MMU_CR_G_W_IMASK_NO	0x48	/* mask of MMU_CR bits access to */
					/* control intercepts */
#define	_MMU_SH_PID_NO		0x49	/* shadow register of process ID */
#define	_MMU_SH_MMU_CR_NO	0x4a	/* shadow register of control reg. */

#define	MMU_ADDR_VIRT_CTRL	MMU_REG_NO_TO_MMU_ADDR(_MMU_VIRT_CTRL_NO)
#define	MMU_ADDR_GID		MMU_REG_NO_TO_MMU_ADDR(_MMU_GID_NO)
#define	MMU_ADDR_GP_PPTB	MMU_REG_NO_TO_MMU_ADDR(_MMU_GP_PPTB_NO)
#define	MMU_ADDR_INTC_INFO	MMU_REG_NO_TO_MMU_ADDR(_MMU_INTC_INFO_NO)
#define	MMU_ADDR_INTC_PTR	MMU_REG_NO_TO_MMU_ADDR(_MMU_INTC_PTR_NO)
#define	MMU_ADDR_SH_OS_VPTB	MMU_REG_NO_TO_MMU_ADDR(_MMU_SH_OS_VPTB_NO)
#define	MMU_ADDR_SH_OS_PPTB	MMU_REG_NO_TO_MMU_ADDR(_MMU_SH_OS_PPTB_NO)
#define	MMU_ADDR_CR_G_W_IMASK	MMU_REG_NO_TO_MMU_ADDR(_MMU_CR_G_W_IMASK_NO)
#define	MMU_ADDR_SH_PID		MMU_REG_NO_TO_MMU_ADDR(_MMU_SH_PID_NO)
#define	MMU_ADDR_SH_MMU_CR	MMU_REG_NO_TO_MMU_ADDR(_MMU_SH_MMU_CR_NO)

/* MMU internel register contents */

/*
 * MMU Guest Process (machine #) ID MMU_GID
 */

#define	MMU_GID_SIZE		MMU_PID_SIZE

/*
 * Kernel virtual memory context
 */
#define	E2K_KERNEL_GID		0x000	/* defined by hardware */

#define	MMU_GID(gid)		MMU_PID(gid)
#define	MMU_KERNEL_GID		MMU_GID(E2K_KERNEL_GID)

/*
 * MMU Virtual Control register
 */

typedef	union virt_ctrl_mu {
	struct {
		u64 evn_c		: 36;	/* [35: 0]	*/
		u64 __resf		: 28;	/* [63:38]	*/
	};
	struct {
		/* env_c:	*/
		u64 rr_mmu_cr		:  1;	/*    [ 0]	*/
		u64 rr_pptb		:  1;	/*    [ 1]	*/
		u64 rr_vptb		:  1;	/*    [ 2]	*/
		u64 rr_apic_base	:  1;	/*    [ 3]	*/
		u64 rr_mtrr_pat		:  1;	/*    [ 4]	*/
		u64 rr_ph_pci_b		:  1;	/*    [ 5]	*/
		u64 rr_dbg		:  1;	/*    [ 6]	*/
		u64 rr_dbg1		:  1;	/*    [ 7]	*/
		u64 rw_mmu_cr		:  1;	/*    [ 8]	*/
		u64 rw_pptb		:  1;	/*    [ 9]	*/
		u64 rw_vptb		:  1;	/*    [10]	*/
		u64 rw_apic_base	:  1;	/*    [11]	*/
		u64 rw_mtrr_pat		:  1;	/*    [12]	*/
		u64 rw_ph_pci_b		:  1;	/*    [13]	*/
		u64 rw_dbg		:  1;	/*    [14]	*/
		u64 rw_dbg1		:  1;	/*    [15]	*/
		u64 pma			:  1;	/*    [16]	*/
		u64 fl_dc		:  1;	/*    [17]	*/
		u64 fl_dcl		:  1;	/*    [18]	*/
		u64 fl_ic		:  1;	/*    [19]	*/
		u64 fl_icl_u		:  1;	/*    [20]	*/
		u64 fl_icl_p		:  1;	/*    [21]	*/
		u64 fl_tlb		:  1;	/*    [22]	*/
		u64 fl_tlbpg		:  1;	/*    [23]	*/
		u64 fl_tlb2pg		:  1;	/*    [24]	*/
		u64 prb_entry		:  1;	/*    [25]	*/
		u64 evn_c_res		: 10;	/* [35:26]	*/
		/* other fields	*/
		u64 gp_pt_en		:  1;	/*    [36]	*/
		u64 sh_pt_en		:  1;	/*    [37]	*/
		u64 __resb		: 26;	/* [63:38]	*/
	};
	u64			word;	/* as entire register	*/
} virt_ctrl_mu_t;
#define	VIRT_CTRL_MU_evn_c		evn_c	/* events mask to intercept */
#define	VIRT_CTRL_MU_rr_mmu_cr		rr_mmu_cr
#define	VIRT_CTRL_MU_rr_u_pptb		rr_pptb
#define	VIRT_CTRL_MU_rr_u_vptb		rr_vptb
#define	VIRT_CTRL_MU_rr_apic_base	rr_apic_base
#define	VIRT_CTRL_MU_rr_mtrr_pat	rr_mtrr_pat
#define	VIRT_CTRL_MU_rr_ph_pci_b	rr_ph_pci_b
#define	VIRT_CTRL_MU_rr_dbg		rr_dbg
#define	VIRT_CTRL_MU_rr_dbg1		rr_dbg1
#define	VIRT_CTRL_MU_rw_mmu_cr		rw_mmu_cr
#define	VIRT_CTRL_MU_rw_u_pptb		rw_pptb
#define	VIRT_CTRL_MU_rw_u_vptb		rw_vptb
#define	VIRT_CTRL_MU_rw_apic_base	rw_apic_base
#define	VIRT_CTRL_MU_rw_mtrr_pat	rw_mtrr_pat
#define	VIRT_CTRL_MU_rw_ph_pci_b	rw_ph_pci_b
#define	VIRT_CTRL_MU_rw_dbg		rw_dbg
#define	VIRT_CTRL_MU_rw_dbg1		rw_dbg1
#define	VIRT_CTRL_MU_pma		pma
#define	VIRT_CTRL_MU_fl_dc		fl_dc
#define	VIRT_CTRL_MU_fl_dcl		fl_dcl
#define	VIRT_CTRL_MU_fl_ic		fl_ic
#define	VIRT_CTRL_MU_fl_icl_u		fl_icl_u
#define	VIRT_CTRL_MU_fl_icl_p		fl_icl_p
#define	VIRT_CTRL_MU_fl_tlb		fl_tlb
#define	VIRT_CTRL_MU_fl_tlbpg		fl_tlbpg
#define	VIRT_CTRL_MU_fl_tlb2pg		fl_tlb2pg
#define	VIRT_CTRL_MU_prb_entry		prb_entry
					/* GPA -> PA translation enable */
#define	VIRT_CTRL_MU_gp_pt_en		gp_pt_en
					/* shadow Page Tables enable */
#define	VIRT_CTRL_MU_sh_pt_en		sh_pt_en
#define	VIRT_CTRL_MU_reg	word	/* [63: 0] - entire register */

/* Bits mask of VIRT_CTRL_MU fields and flags */
#define VIRT_CTRL_MU_ENV_C_MASK		\
		((virt_ctrl_mu_t) { .VIRT_CTRL_MU_evn_c = -1, }.word)
#define VIRT_CTRL_MU_RR_MMU_CR_MASK	\
		((virt_ctrl_mu_t) { .VIRT_CTRL_MU_rr_mmu_cr = 1, }.word)
#define VIRT_CTRL_MU_RR_U_PPTB_MASK	\
		((virt_ctrl_mu_t) { .VIRT_CTRL_MU_rr_pptb = 1, }.word)
#define VIRT_CTRL_MU_RR_U_VPTB_MASK	\
		((virt_ctrl_mu_t) { .VIRT_CTRL_MU_rr_vptb = 1, }.word)
#define VIRT_CTRL_MU_RR_APIC_BASE_MASK	\
		((virt_ctrl_mu_t) { .VIRT_CTRL_MU_rr_apic_base = 1, }.word)
#define VIRT_CTRL_MU_RR_MTRR_PAT_MASK	\
		((virt_ctrl_mu_t) { .VIRT_CTRL_MU_rr_mtrr_pat = 1, }.word)
#define VIRT_CTRL_MU_RR_PH_PCI_B_MASK	\
		((virt_ctrl_mu_t) { .VIRT_CTRL_MU_rr_ph_pci_b = 1, }.word)
#define VIRT_CTRL_MU_RR_DBG_MASK	\
		((virt_ctrl_mu_t) { .VIRT_CTRL_MU_rr_dbg = 1, }.word)
#define VIRT_CTRL_MU_RR_DBG1_MASK	\
		((virt_ctrl_mu_t) { .VIRT_CTRL_MU_rr_dbg1 = 1, }.word)
#define VIRT_CTRL_MU_RW_MMU_CR_MASK	\
		((virt_ctrl_mu_t) { .VIRT_CTRL_MU_rw_mmu_cr = 1, }.word)
#define VIRT_CTRL_MU_RW_U_PPTB_MASK	\
		((virt_ctrl_mu_t) { .VIRT_CTRL_MU_rw_pptb = 1, }.word)
#define VIRT_CTRL_MU_RW_U_VPTB_MASK	\
		((virt_ctrl_mu_t) { .VIRT_CTRL_MU_rw_vptb = 1, }.word)
#define VIRT_CTRL_MU_RW_APIC_BASE_MASK	\
		((virt_ctrl_mu_t) { .VIRT_CTRL_MU_rw_apic_base = 1, }.word)
#define VIRT_CTRL_MU_RW_MTRR_PAT_MASK	\
		((virt_ctrl_mu_t) { .VIRT_CTRL_MU_rw_mtrr_pat = 1, }.word)
#define VIRT_CTRL_MU_RW_PH_PCI_B_MASK	\
		((virt_ctrl_mu_t) { .VIRT_CTRL_MU_rw_ph_pci_b = 1, }.word)
#define VIRT_CTRL_MU_RW_DBG_MASK	\
		((virt_ctrl_mu_t) { .VIRT_CTRL_MU_rw_dbg = 1, }.word)
#define VIRT_CTRL_MU_RW_DBG1_MASK	\
		((virt_ctrl_mu_t) { .VIRT_CTRL_MU_rw_dbg1 = 1, }.word)
#define VIRT_CTRL_MU_PMA_MASK		\
		((virt_ctrl_mu_t) { .VIRT_CTRL_MU_pma = 1, }.word)
#define VIRT_CTRL_MU_FL_DC_MASK		\
		((virt_ctrl_mu_t) { .VIRT_CTRL_MU_fl_dc = 1, }.word)
#define VIRT_CTRL_MU_FL_DCL_MASK	\
		((virt_ctrl_mu_t) { .VIRT_CTRL_MU_fl_dcl = 1, }.word)
#define VIRT_CTRL_MU_FL_IC_MASK		\
		((virt_ctrl_mu_t) { .VIRT_CTRL_MU_fl_ic = 1, }.word)
#define VIRT_CTRL_MU_FL_ICL_U_MASK	\
		((virt_ctrl_mu_t) { .VIRT_CTRL_MU_fl_icl_u = 1, }.word)
#define VIRT_CTRL_MU_FL_ICL_P_MASK	\
		((virt_ctrl_mu_t) { .VIRT_CTRL_MU_fl_icl_p = 1, }.word)
#define VIRT_CTRL_MU_FL_TLB_MASK	\
		((virt_ctrl_mu_t) { .VIRT_CTRL_MU_fl_tlb = 1, }.word)
#define VIRT_CTRL_MU_FL_TLBPG_MASK	\
		((virt_ctrl_mu_t) { .VIRT_CTRL_MU_fl_tlbpg = 1, }.word)
#define VIRT_CTRL_MU_FL_TLB2PG_MASK	\
		((virt_ctrl_mu_t) { .VIRT_CTRL_MU_fl_tlb2pg = 1, }.word)
#define VIRT_CTRL_MU_PRB_ENTRY_MASK	\
		((virt_ctrl_mu_t) { .VIRT_CTRL_MU_prb_entry = 1, }.word)
#define VIRT_CTRL_MU_GP_PT_EN_MASK	\
		((virt_ctrl_mu_t) { .VIRT_CTRL_MU_gp_pt_en = 1, }.word)
#define VIRT_CTRL_MU_SH_PT_EN_MASK	\
		((virt_ctrl_mu_t) { .VIRT_CTRL_MU_sh_pt_en = 1, }.word)

typedef union {
	struct {
		u64 event_code		: 8;
		u64 guest_pt_lev_fin	: 1;
		u64 guest_pt_lev	: 3;
		u64 ignore_wr_rights	: 1;
		u64 __reserved		: 51;
	};
	u64 word;
} intc_info_mu_hdr_t;

#define intc_mu_info_lo_get_event_code(x) ((x) & 0xff)

/* Possible values for `INTC_INFO_MU[2 * j].event_code' */
typedef enum e2k_int_info_mu_event_code {
	IME_FORCED = 0,
	IME_FORCED_GVA = 1,
	IME_SHADOW_DATA = 2,
	IME_GPA_DATA = 3,
	IME_GPA_INSTR = 4,
	IME_GPA_AINSTR = 5,
	IME_RESERVED_6 = 6,
	IME_RESERVED_7 = 7,
	IME_MAS_IOADDR = 8,
	IME_READ_MU = 9,
	IME_WRITE_MU = 10,
	IME_CACHE_FLUSH = 11,
	IME_CACHE_LINE_FLUSH = 12,
	IME_ICACHE_FLUSH = 13,
	IME_ICACHE_LINE_FLUSH_USER = 14,
	IME_ICACHE_LINE_FLUSH_SYSTEM = 15,
	IME_TLB_FLUSH = 16,
	IME_TLB_PAGE_FLUSH_LAST = 17,
	IME_TLB_PAGE_FLUSH_UPPER = 18,
	IME_TLB_ENTRY_PROBE = 19,
	MU_INTC_EVENTS_MAX
} intc_info_mu_event_code_t;

typedef struct {
	intc_info_mu_hdr_t hdr;
	unsigned long gpa;
	unsigned long gva;
	unsigned long data;
	tc_cond_t condition;
	unsigned long data_ext;
	tc_mask_t mask;
	bool no_restore;
	bool modify_data;
	unsigned long mod_data;
	unsigned long mod_data_ext;
} intc_info_mu_t;

#define INTC_INFO_MU_MAX	77
#define	INTC_PTR_MU_SIZE	7
#define	INTC_INFO_MU_ITEM_SIZE	7
#define	INTC_INFO_MU_ITEM_MAX	(INTC_INFO_MU_MAX / INTC_INFO_MU_ITEM_SIZE)

#endif  /* _E2K_KVM_MMU_HV_REGS_TYPES_H_ */
