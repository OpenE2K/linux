
#ifndef	_E2K_SIC_REGS_H_
#define	_E2K_SIC_REGS_H_

#ifdef __KERNEL__

#include <asm/types.h>
#include <asm/cpu_regs.h>
#include <asm/e2k_sic.h>
#include <asm/sic_regs_access.h>

#ifndef __ASSEMBLY__
#include <asm/e2k_api.h>
#endif	/* __ASSEMBLY__ */

#undef	DEBUG_ERALY_NBSR_MODE
#undef	DebugENBSR
#define	DEBUG_ERALY_NBSR_MODE	0	/* early NBSR access */
#ifndef	CONFIG_BOOT_E2K
#define DebugENBSR(...)		DebugPrint(DEBUG_ERALY_NBSR_MODE ,##__VA_ARGS__)
#else  /* CONFIG_BOOT_E2K */
#define	DebugENBSR		if (DEBUG_ERALY_NBSR_MODE) rom_printk
#endif /* ! CONFIG_BOOT_E2K */

#undef DEBUG_NBSR_MODE
#undef DebugNBSR
#define        DEBUG_NBSR_MODE         0       /* NBSR access */
#define DebugNBSR(...)		DebugPrint(DEBUG_NBSR_MODE ,##__VA_ARGS__)

#define SIC_IO_LINKS_COUNT	((IS_MACHINE_E3S) ? 1 : 2)
#define SIC_CPU_LINKS_COUNT	3

/*
 * NBSR registers addresses (offsets in NBSR area)
 */

#define SIC_st_p	0x00

#define	SIC_st_core0	0x100
#define	SIC_st_core1	0x104
#define	SIC_st_core2	0x108
#define	SIC_st_core3	0x10c
#define	SIC_st_core4	0x110
#define	SIC_st_core5	0x114
#define	SIC_st_core6	0x118
#define	SIC_st_core7	0x11c

#define	SIC_rt_ln	0x08

#define SIC_rt_lcfg0	0x10
#define SIC_rt_lcfg1	0x14
#define SIC_rt_lcfg2	0x18
#define SIC_rt_lcfg3	0x1c

#define SIC_rt_mhi0	0x20
#define SIC_rt_mhi1	0x24
#define SIC_rt_mhi2	0x28
#define SIC_rt_mhi3	0x2c

#define SIC_rt_mlo0	0x30
#define SIC_rt_mlo1	0x34
#define SIC_rt_mlo2	0x38
#define SIC_rt_mlo3	0x3c

#define SIC_rt_pcim0	0x40
#define SIC_rt_pcim1	0x44
#define SIC_rt_pcim2	0x48
#define SIC_rt_pcim3	0x4c

#define SIC_rt_pcim10	0x1040
#define SIC_rt_pcim11	0x1044
#define SIC_rt_pcim12	0x1048
#define SIC_rt_pcim13	0x104c

#define SIC_rt_pciio0	0x50
#define SIC_rt_pciio1	0x54
#define SIC_rt_pciio2	0x58
#define SIC_rt_pciio3	0x5c

#define SIC_rt_pciio10	0x1050
#define SIC_rt_pciio11	0x1054
#define SIC_rt_pciio12	0x1058
#define SIC_rt_pciio13	0x105c

#define SIC_rt_ioapic0  0x60
#define SIC_rt_ioapic1  0x64
#define SIC_rt_ioapic2  0x68
#define SIC_rt_ioapic3  0x6c

#define SIC_rt_ioapic10  0x1060
#define SIC_rt_ioapic11  0x1064
#define SIC_rt_ioapic12  0x1068
#define SIC_rt_ioapic13  0x106c

#define SIC_rt_pcimp_b0	 0x70
#define SIC_rt_pcimp_b1	 0x74
#define SIC_rt_pcimp_b2	 0x78
#define SIC_rt_pcimp_b3	 0x7c

#define SIC_rt_pcimp_e0	 0x80
#define SIC_rt_pcimp_e1	 0x84
#define SIC_rt_pcimp_e2	 0x88
#define SIC_rt_pcimp_e3	 0x8c

#define SIC_rt_ioapicintb 0x94
#define SIC_rt_lapicintb 0xa0

#define SIC_rt_pcimp_b10 0x1070
#define SIC_rt_pcimp_b11 0x1074
#define SIC_rt_pcimp_b12 0x1078
#define SIC_rt_pcimp_b13 0x107c

#define SIC_rt_pcimp_e10 0x1080
#define SIC_rt_pcimp_e11 0x1084
#define SIC_rt_pcimp_e12 0x1088
#define SIC_rt_pcimp_e13 0x108c

#define SIC_rt_lapic	0x0c

/* IOMMU */
#define SIC_iommu_ctrl		0x0380
#define SIC_iommu_ba_lo		0x0390
#define SIC_iommu_ba_hi		0x0394
#define SIC_iommu_flush		0x03a0
#define SIC_iommu_flushP	0x03a4
#define SIC_iommu_err		0x03b0
#define SIC_iommu_err1		0x03b4

/* CPU links */
#define SIC_pl_csr1		0x614
#define SIC_pl_csr2		0x624
#define SIC_pl_csr3		0x634

/* IO link & RDMA */
#define	SIC_iol_csr		0x900
#define	SIC_io_vid		0x700
#define	SIC_io_csr		0x704
#define	SIC_io_csr_hi		0x724
#define	SIC_io_tmr		0x708
#define	SIC_io_tmr_hi		0x728
#define	SIC_io_str		0x70c
#define	SIC_io_str_hi		0x72c
#define	SIC_rdma_vid		0x880
#define	SIC_rdma_cs		0x888

/* Second IO link */
#define	SIC_iol_csr1	0x1900
#define	SIC_io_vid1	0x1700
#define	SIC_io_csr1	0x1704
#define	SIC_io_tmr1	0x1708
#define	SIC_io_str1	0x170c
#define	SIC_rdma_vid1	0x1880
#define	SIC_rdma_cs1	0x1888

/* DSP */
#define SIC_ic_ir0	0x2004
#define SIC_ic_ir1      0x2008
#define SIC_ic_mr0      0x2010
#define SIC_ic_mr1      0x2014

/* Monitors */
#define SIC_sic_mcr	0xc30
#define SIC_sic_mar0_lo	0xc40
#define SIC_sic_mar0_hi	0xc44
#define SIC_sic_mar1_lo	0xc48
#define SIC_sic_mar1_hi	0xc4c

/* Interrupt register */
#define SIC_sic_int	0xc60

/* 
 * MC
 */

#define SIC_MAX_MC_COUNT	4
#define SIC_MC_COUNT							\
({									\
	int ret = 0;							\
	if (IS_MACHINE_E3S || IS_MACHINE_ES2 || IS_MACHINE_E1CP)	\
		ret = 2;						\
	else if (IS_MACHINE_E2S)					\
		ret = 3;						\
	else if (IS_MACHINE_E8C || IS_MACHINE_E8C2)			\
		ret = 4;						\
	ret;								\
})

#define SIC_mc0_ecc	0x400
#define SIC_mc1_ecc	((IS_MACHINE_E3S || IS_MACHINE_ES2) ? 0x500 : 0x440)
#define SIC_mc2_ecc	0x480
#define SIC_mc3_ecc	0x4c0
#define SIC_mc0_opmb	0x414
#define SIC_mc1_opmb	0x454
#define SIC_mc2_opmb	0x494
#define SIC_mc3_opmb	0x4d4

/* IPCC */
#define SIC_IPCC_LINKS_COUNT	3
#define SIC_ipcc_csr1		0x604
#define SIC_ipcc_csr2		0x644
#define SIC_ipcc_csr3		0x684
#define SIC_ipcc_pmr1		0x608
#define SIC_ipcc_pmr2		0x648
#define SIC_ipcc_pmr3		0x688
#define SIC_ipcc_str1		0x60c
#define SIC_ipcc_str2		0x64c
#define SIC_ipcc_str3		0x68c

/* Power management */
#define SIC_pwr_mgr	0x280

#ifndef __ASSEMBLY__
/*
 *   Read/Write RT_LCFGj Regs
 */
#define	E3S_PN_MSB	5	/* 4 - cluster # + 2 processor # */
 #define E3S_CLN_BITS	4	/* 4 bits - cluster # */
 #define E3S_PLN_BITS	2	/* 2 bits - processor # */
#define	E2S_PN_MSB	5	/* 4 - cluster # + 2 processor # */
 #define E2S_CLN_BITS	4	/* 4 bits - cluster # */
 #define E2S_PLN_BITS	2	/* 2 bits - processor # */
#define	E8C_PN_MSB	3	/* 2 - cluster # + 2 processor # */
 #define E8C_CLN_BITS	2	/* 2 bits - cluster # */
 #define E8C_PLN_BITS	2	/* 2 bits - processor # */
#if	defined(CONFIG_E3S) || defined(CONFIG_ES2) || defined(CONFIG_E2S)
#define	E2K_MAX_CL_NUM	((1 << E3S_CLN_BITS) - 1)
#elif	defined(CONFIG_E8C) || defined(CONFIG_E8C2)
#define	E2K_MAX_CL_NUM	((1 << E8C_CLN_BITS) - 1)
#endif	/* CONFIG_E3S || CONFIG_ES2 || CONFIG_E2S */

/* SCCFG */
#define SIC_sccfg	0xc00

typedef	unsigned int	e2k_rt_lcfg_t;	/* Read/write pointer (32 bits) */
typedef	struct e3s_rt_lcfg_fields {
	e2k_rt_lcfg_t   vp	:  1;			/* [0] */
	e2k_rt_lcfg_t   vb	:  1;			/* [1] */
	e2k_rt_lcfg_t   vics	:  1;			/* [2] */
	e2k_rt_lcfg_t   vio	:  1;			/* [3] */
	e2k_rt_lcfg_t   pln	:  2;			/* [5:4] */
	e2k_rt_lcfg_t   cln	:  4;			/* [9:6] */
	e2k_rt_lcfg_t   unused	:  22;			/* [31:10] */
} e3s_rt_lcfg_fields_t;
typedef	struct e8c_rt_lcfg_fields {
	e2k_rt_lcfg_t   vp	:  1;			/* [0] */
	e2k_rt_lcfg_t   vb	:  1;			/* [1] */
	e2k_rt_lcfg_t   vics	:  1;			/* [2] */
	e2k_rt_lcfg_t   vio	:  1;			/* [3] */
	e2k_rt_lcfg_t   pln	:  2;			/* [5:4] */
	e2k_rt_lcfg_t   cln	:  2;			/* [7:6] */
	e2k_rt_lcfg_t   unused	:  24;			/* [31:8] */
} e8c_rt_lcfg_fields_t;
typedef e3s_rt_lcfg_fields_t	es2_rt_lcfg_fields_t;
typedef e3s_rt_lcfg_fields_t	e2s_rt_lcfg_fields_t;
typedef	union e2k_rt_lcfg_struct {		/* Structure of lower word */
	e3s_rt_lcfg_fields_t	e3s_fields;	/* as fields */
	e8c_rt_lcfg_fields_t	e8c_fields;	/* as fields */
	e2k_rt_lcfg_t		word;		/* as entire register */
} e2k_rt_lcfg_struct_t;

#define	E3S_RT_LCFG_vp(__reg)	((__reg).e3s_fields.vp)
#define	E3S_RT_LCFG_vb(__reg)	((__reg).e3s_fields.vb)
#define	E3S_RT_LCFG_vics(__reg)	((__reg).e3s_fields.vics)
#define	E3S_RT_LCFG_vio(__reg)	((__reg).e3s_fields.vio)
#define	E3S_RT_LCFG_pln(__reg)	((__reg).e3s_fields.pln)
#define	E3S_RT_LCFG_cln(__reg)	((__reg).e3s_fields.cln)
#define	E3S_RT_LCFG_reg(__reg)	((__reg).word)

#define	ES2_RT_LCFG_vp		E3S_RT_LCFG_vp
#define	ES2_RT_LCFG_vb		E3S_RT_LCFG_vb
#define	ES2_RT_LCFG_vics	E3S_RT_LCFG_vics
#define	ES2_RT_LCFG_vio		E3S_RT_LCFG_vio
#define	ES2_RT_LCFG_pln		E3S_RT_LCFG_pln
#define	ES2_RT_LCFG_cln		E3S_RT_LCFG_cln
#define	ES2_RT_LCFG_reg		E3S_RT_LCFG_reg

#define	E2S_RT_LCFG_vp		E3S_RT_LCFG_vp
#define	E2S_RT_LCFG_vb		E3S_RT_LCFG_vb
#define	E2S_RT_LCFG_vics	E3S_RT_LCFG_vics
#define	E2S_RT_LCFG_vio		E3S_RT_LCFG_vio
#define	E2S_RT_LCFG_pln		E3S_RT_LCFG_pln
#define	E2S_RT_LCFG_cln		E3S_RT_LCFG_cln
#define	E2S_RT_LCFG_reg		E3S_RT_LCFG_reg

#define	E8C_RT_LCFG_vp(__reg)	((__reg).e8c_fields.vp)
#define	E8C_RT_LCFG_vb(__reg)	((__reg).e8c_fields.vb)
#define	E8C_RT_LCFG_vics(__reg)	((__reg).e8c_fields.vics)
#define	E8C_RT_LCFG_vio(__reg)	((__reg).e8c_fields.vio)
#define	E8C_RT_LCFG_pln(__reg)	((__reg).e8c_fields.pln)
#define	E8C_RT_LCFG_cln(__reg)	((__reg).e8c_fields.cln)
#define	E8C_RT_LCFG_reg(__reg)	((__reg).word)

#define	E2K_RT_LCFG_vp		E3S_RT_LCFG_vp
#define	E2K_RT_LCFG_vb		E3S_RT_LCFG_vb
#define	E2K_RT_LCFG_vics	E3S_RT_LCFG_vics
#define	E2K_RT_LCFG_vio		E3S_RT_LCFG_vio
#if	defined(CONFIG_E3S) || defined(CONFIG_ES2) || defined(CONFIG_E2S)
#define	E2K_RT_LCFG_pln		E3S_RT_LCFG_pln
#define	E2K_RT_LCFG_cln		E3S_RT_LCFG_cln
#elif	defined(CONFIG_E8C) || defined(CONFIG_E8C2)
#define	E2K_RT_LCFG_pln		E8C_RT_LCFG_pln
#define	E2K_RT_LCFG_cln		E8C_RT_LCFG_cln
#endif	/* CONFIG_E3S || CONFIG_ES2 || CONFIG_E2S */
#define	E2K_RT_LCFG_reg		E3S_RT_LCFG_reg

/*
 *   Read/Write RT_PCIIOj Regs
 */
typedef	unsigned int	e2k_rt_pciio_t;	/* Read/write pointer (32 bits) */
typedef	struct e2k_rt_pciio_fields {
	e2k_rt_pciio_t   unused1 :  12;			/* [11:0] */
	e2k_rt_pciio_t   bgn	 :  4;			/* [15:12] */
	e2k_rt_pciio_t   unused2 :  12;			/* [27:16] */
	e2k_rt_pciio_t   end	 :  4;			/* [31:28] */
} e2k_rt_pciio_fields_t;
typedef	union e2k_rt_pciio_struct {		/* Structure of lower word */
	e2k_rt_pciio_fields_t	fields;		/* as fields */
	e2k_rt_pciio_t		word;		/* as entire register */
} e2k_rt_pciio_struct_t;

#define	E2K_SIC_ALIGN_RT_PCIIO	12			/* 4 Kb */
#define	E2K_SIC_SIZE_RT_PCIIO	(1 << E2K_SIC_ALIGN_RT_PCIM)
#define	E2K_RT_PCIIO_bgn	fields.bgn
#define	E2K_RT_PCIIO_end	fields.end
#define	E2K_RT_PCIIO_reg	word

/*
 *   Read/Write RT_PCIMj Regs
 */
typedef	unsigned int	e2k_rt_pcim_t;	/* Read/write pointer (32 bits) */
typedef	struct e2k_rt_pcim_fields {
	e2k_rt_pcim_t   unused1 :  11;			/* [10:0] */
	e2k_rt_pcim_t   bgn	:  5;			/* [15:11] */
	e2k_rt_pcim_t   unused2 :  11;			/* [26:16] */
	e2k_rt_pcim_t   end	:  5;			/* [31:27] */
} e2k_rt_pcim_fields_t;
typedef	union e2k_rt_pcim_struct {		/* Structure of lower word */
	e2k_rt_pcim_fields_t	fields;		/* as fields */
	e2k_rt_pcim_t		word;		/* as entire register */
} e2k_rt_pcim_struct_t;

#define	E2K_SIC_ALIGN_RT_PCIM	27			/* 128 Mb */
#define	E2K_SIC_SIZE_RT_PCIM	(1 << E2K_SIC_ALIGN_RT_PCIM)
#define	E2K_RT_PCIM_bgn		fields.bgn
#define	E2K_RT_PCIM_end		fields.end
#define	E2K_RT_PCIM_reg		word

/*
 *   Read/Write RT_MLOj Regs
 */
typedef	unsigned int	e2k_rt_mlo_t;	/* Read/write pointer (32 bits) */
typedef	struct e2k_rt_mlo_fields {
	e2k_rt_mlo_t   unused1 	:  11;			/* [10:0] */
	e2k_rt_mlo_t   bgn	:  5;			/* [15:11] */
	e2k_rt_mlo_t   unused2 	:  11;			/* [26:16] */
	e2k_rt_mlo_t   end	:  5;			/* [31:27] */
} e2k_rt_mlo_fields_t;
typedef	union e2k_rt_mlo_struct {		/* Structure of lower word */
	e2k_rt_mlo_fields_t	fields;		/* as fields */
	e2k_rt_mlo_t		word;		/* as entire register */
} e2k_rt_mlo_struct_t;

#define	E2K_SIC_ALIGN_RT_MLO	27		/* 128 Mb */
#define	E2K_SIC_SIZE_RT_MLO	(1 << E2K_SIC_ALIGN_RT_MLO)
#define E2K_RT_MLO_bgn		fields.bgn
#define E2K_RT_MLO_end		fields.end
#define E2K_RT_MLO_reg		word

/* memory *bank minimum size, so base address of bank align */
#define	E2K_SIC_MIN_MEMORY_BANK	(256 * 1024 * 1024)	/* 256 Mb */

/*
 *   Read/Write RT_MHIj Regs
 */
typedef	unsigned int	e2k_rt_mhi_t;	/* Read/write pointer (32 bits) */
typedef	struct e2k_rt_mhi_fields {
	e2k_rt_mhi_t   bgn 	:  8;			/* [7:0] */
	e2k_rt_mhi_t   unused1	:  8;			/* [15:8] */
	e2k_rt_mhi_t   end 	:  8;			/* [23:16] */
	e2k_rt_mhi_t   unused2	:  8;			/* [31:24] */
} e2k_rt_mhi_fields_t;
typedef	union e2k_rt_mhi_struct {		/* Structure of lower word */
	e2k_rt_mhi_fields_t	fields;		/* as fields */
	e2k_rt_mhi_t		word;		/* as entire register */
} e2k_rt_mhi_struct_t;

#define	E2K_SIC_ALIGN_RT_MHI	32		/* 4 Gb */
#define	E2K_SIC_SIZE_RT_MHI	(1UL << E2K_SIC_ALIGN_RT_MHI)
#define E2K_RT_MHI_bgn		fields.bgn
#define E2K_RT_MHI_end		fields.end
#define E2K_RT_MHI_reg		word

/*
 *   Read/Write RT_IOAPICj Regs
 */
typedef	unsigned int	e2k_rt_ioapic_t;	/* Read/write pointer (32 bits) */
typedef	struct e2k_rt_ioapic_fields {
	e2k_rt_ioapic_t   unused1 : 12;			/* [11:0] */
	e2k_rt_ioapic_t	  bgn	  : 9;			/* [20:12] */
	e2k_rt_ioapic_t   unused2 : 11;			/* [31:21] */
} e2k_rt_ioapic_fields_t;
typedef	union e2k_rt_ioapic_struct {		/* Structure of lower word */
	e2k_rt_ioapic_fields_t	fields;		/* as fields */
	e2k_rt_ioapic_t		word;		/* as entire register */
} e2k_rt_ioapic_struct_t;

#define	E2K_RT_IOAPIC_bgn	fields.bgn
#define	E2K_RT_IOAPIC_reg	word

/*
 *   Read/Write RT_LAPICj Regs
 */
typedef	unsigned int	e2k_rt_lapic_t;	/* Read/write pointer (32 bits) */
typedef	struct e2k_rt_lapic_fields {
	e2k_rt_lapic_t   unused1 : 12;			/* [11:0] */
	e2k_rt_lapic_t	  bgn	  : 9;			/* [20:12] */
	e2k_rt_lapic_t   unused2 : 11;			/* [31:21] */
} e2k_rt_lapic_fields_t;
typedef	union e2k_rt_lapic_struct {		/* Structure of lower word */
	e2k_rt_lapic_fields_t	fields;		/* as fields */
	e2k_rt_lapic_t		word;		/* as entire register */
} e2k_rt_lapic_struct_t;

#define	E2K_RT_LAPIC_bgn	fields.bgn
#define	E2K_RT_LAPIC_reg	word

/*
 *   Read/Write ST_P Regs
 */
typedef	unsigned int	e2k_st_p_t;		/* Read/write pointer (32 bits) */
typedef	struct e3s_st_p_fields {
	e2k_st_p_t   	type 		: 4;		/* [3:0] */
	e2k_st_p_t	wait_init	: 1;		/* [4] */
	e2k_st_p_t   	wait_trap 	: 1;		/* [5] */
	e2k_st_p_t   	stop_dbg 	: 1;		/* [6] */
	e2k_st_p_t   	pl_val 		: 3;		/* [9:7] */
	e2k_st_p_t   	mlc 		: 1;		/* [10] */
	e2k_st_p_t   	pn 		: 6;		/* [16:11] */
	e2k_st_p_t   	unused 		: 15;		/* [31:17] */
} e3s_st_p_fields_t;
typedef	struct es2_st_p_fields {
	e2k_st_p_t   	type 		: 4;		/* [3:0] */
	e2k_st_p_t	id		: 8;		/* [11:4] */
	e2k_st_p_t   	pn	 	: 8;		/* [19:12] */
	e2k_st_p_t   	coh_on	 	: 1;		/* [20] */
	e2k_st_p_t   	pl_val 		: 3;		/* [23:21] */
	e2k_st_p_t   	mlc 		: 1;		/* [24] */
	e2k_st_p_t   	unused 		: 7;		/* [31:25] */
} es2_st_p_fields_t;
typedef es2_st_p_fields_t	e2s_st_p_fields_t;
typedef es2_st_p_fields_t	e8c_st_p_fields_t;
typedef	union e2k_st_p_struct {			/* Structure of lower word */
	e3s_st_p_fields_t	e3s_fields;	/* as fields for e3s */
	es2_st_p_fields_t	es2_fields;	/* as fields for es2 */
	e2k_st_p_t		word;		/* as entire register */
} e2k_st_p_struct_t;

#define	E3S_ST_P_type		e3s_fields.type
#define	E3S_ST_P_wait_init	e3s_fields.wait_init
#define	E3S_ST_P_wait_trap	e3s_fields.wait_trap
#define	E3S_ST_P_stop_dbg	e3s_fields.stop_dbg
#define	E3S_ST_P_pl_val		e3s_fields.pl_val
#define	E3S_ST_P_mlc		e3s_fields.mlc
#define	E3S_ST_P_pn		e3s_fields.pn
#define	E3S_ST_P_reg		word

#define	ES2_ST_P_type		es2_fields.type
#define	ES2_ST_P_id		es2_fields.id
#define	ES2_ST_P_coh_on		es2_fields.coh_on
#define	ES2_ST_P_pl_val		es2_fields.pl_val
#define	ES2_ST_P_mlc		es2_fields.mlc
#define	ES2_ST_P_pn		es2_fields.pn
#define	ES2_ST_P_reg		word

#define	E2S_ST_P_type		ES2_ST_P_type
#define	E2S_ST_P_id		ES2_ST_P_id
#define	E2S_ST_P_coh_on		ES2_ST_P_coh_on
#define	E2S_ST_P_pl_val		ES2_ST_P_pl_val
#define	E2S_ST_P_mlc		ES2_ST_P_mlc
#define	E2S_ST_P_pn		ES2_ST_P_pn
#define	E2S_ST_P_reg		ES2_ST_P_reg

#define	E8C_ST_P_type		ES2_ST_P_type
#define	E8C_ST_P_id		ES2_ST_P_id
#define	E8C_ST_P_coh_on		ES2_ST_P_coh_on
#define	E8C_ST_P_pl_val		ES2_ST_P_pl_val
#define	E8C_ST_P_mlc		ES2_ST_P_mlc
#define	E8C_ST_P_pn		ES2_ST_P_pn
#define	E8C_ST_P_reg		ES2_ST_P_reg

#define	E2K_ST_P_type		E3S_ST_P_type
#define	E2K_ST_P_reg		E3S_ST_P_reg

#ifdef	CONFIG_E3S
#define	E2K_ST_P_pl_val		E3S_ST_P_pl_val
#define	E2K_ST_P_mlc		E3S_ST_P_mlc
#define	E2K_ST_P_pn		E3S_ST_P_pn
#elif	defined(CONFIG_ES2) || defined(CONFIG_E2S) || defined(CONFIG_E8C) || \
	defined(CONFIG_E8C2)
#define	E2K_ST_P_pl_val		ES2_ST_P_pl_val
#define	E2K_ST_P_mlc		ES2_ST_P_mlc
#define	E2K_ST_P_pn		ES2_ST_P_pn
#endif	/* CONFIG_E3S or CONFIG_ES2 or CONFIG_E2S or CONFIG_E8C or */
	/* CONFIG_E8C2 */

/*
 *   ST_CORE core state register
 */
typedef	unsigned int	e2k_st_core_t;		/* single word (32 bits) */
typedef	struct e2k_st_core_fields {
	e2k_st_core_t	val		:  1;		/* [0] */
	e2k_st_core_t	wait_init	:  1;		/* [1] */
	e2k_st_core_t	wait_trap	:  1;		/* [2] */
	e2k_st_core_t	stop_dbg	:  1;		/* [3] */
	e2k_st_core_t	clk_off		:  1;		/* [4] */
	e2k_st_core_t	unused		: 27;		/* [31:5] */
} e2k_st_core_fields_t;
typedef e2k_st_core_fields_t	es2_st_core_fields_t;
typedef e2k_st_core_fields_t	e2s_st_core_fields_t;
typedef e2k_st_core_fields_t	e8c_st_core_fields_t;
typedef	union e2k_st_core_struct {		/* Structure of word */
	e2k_st_core_fields_t	fields;		/* as fields for e2k */
	e2k_st_core_t		word;		/* as entire register */
} e2k_st_core_struct_t;
typedef e2k_st_core_struct_t	es2_st_core_struct_t;
typedef e2k_st_core_struct_t	e2s_st_core_struct_t;
typedef e2k_st_core_struct_t	e8c_st_core_struct_t;
#define	E2K_ST_CORE_val(__reg)		((__reg).fields.val)
#define	E2K_ST_CORE_wait_init(__reg)	((__reg).fields.wait_init)
#define	E2K_ST_CORE_wait_trap(__reg)	((__reg).fields.wait_trap)
#define	E2K_ST_CORE_stop_dbg(__reg)	((__reg).fields.stop_dbg)
#define	E2K_ST_CORE_clk_off(__reg)	((__reg).fields.clk_off)
#define	E2K_ST_CORE_reg(__reg)		((__reg).word)

#define	ES2_ST_CORE_val		E2K_ST_CORE_val
#define	ES2_ST_CORE_wait_init	E2K_ST_CORE_wait_init
#define	ES2_ST_CORE_wait_trap	E2K_ST_CORE_wait_trap
#define	ES2_ST_CORE_stop_dbg	E2K_ST_CORE_stop_dbg
#define	ES2_ST_CORE_clk_off	E2K_ST_CORE_clk_off
#define	ES2_ST_CORE_reg		E2K_ST_CORE_reg

#define	E2S_ST_CORE_val		E2K_ST_CORE_val
#define	E2S_ST_CORE_wait_init	E2K_ST_CORE_wait_init
#define	E2S_ST_CORE_wait_trap	E2K_ST_CORE_wait_trap
#define	E2S_ST_CORE_stop_dbg	E2K_ST_CORE_stop_dbg
#define	E2S_ST_CORE_clk_off	E2K_ST_CORE_clk_off
#define	E2S_ST_CORE_reg		E2K_ST_CORE_reg

#define	E8C_ST_CORE_val		E2K_ST_CORE_val
#define	E8C_ST_CORE_wait_init	E2K_ST_CORE_wait_init
#define	E8C_ST_CORE_wait_trap	E2K_ST_CORE_wait_trap
#define	E8C_ST_CORE_stop_dbg	E2K_ST_CORE_stop_dbg
#define	E8C_ST_CORE_clk_off	E2K_ST_CORE_clk_off
#define	E8C_ST_CORE_reg		E2K_ST_CORE_reg

/*
 *   IO Link control state register
 */
typedef	unsigned int	e2k_iol_csr_t;		/* single word (32 bits) */
typedef	struct e2k_iol_csr_fields {
	e2k_iol_csr_t	mode 		: 1;		/* [0] */
	e2k_iol_csr_t	abtype		: 7;		/* [7:1] */
	e2k_iol_csr_t  	unused 		: 24;		/* [31:8] */
} e2k_iol_csr_fields_t;
typedef	union e2k_iol_csr_struct {		/* Structure of word */
	e2k_iol_csr_fields_t	fields;		/* as fields */
	e2k_iol_csr_t		word;		/* as entire register */
} e2k_iol_csr_struct_t;

#define	E2K_IOL_CSR_mode	fields.mode	/* type of controller */
						/* on the link */
#define	E2K_IOL_CSR_abtype	fields.abtype	/* type of abonent */
						/* on the link */
#define	E2K_IOL_CSR_reg		word
#define	IOHUB_IOL_MODE		1	/* controller is IO HUB */
#define	RDMA_IOL_MODE		0	/* controller is RDMA */
#define	IOHUB_ONLY_IOL_ABTYPE	1	/* abonent has only IO HUB */
					/* controller */
#define	RDMA_ONLY_IOL_ABTYPE	2	/* abonent has only RDMA */
					/* controller */
#define	RDMA_IOHUB_IOL_ABTYPE	3	/* abonent has RDMA and */
					/* IO HUB controller */

/*
 * IO controller vendor ID
 */
typedef	unsigned int	e2k_io_vid_t;		/* single word (32 bits) */
typedef	struct e2k_io_vid_fields {
	e2k_io_vid_t	vid 		: 16;		/* [15:0] */
	e2k_io_vid_t  	unused		: 16;		/* [31:16] */
} e2k_io_vid_fields_t;
typedef	union e2k_io_vid_struct {		/* Structure of word */
	e2k_io_vid_fields_t	fields;		/* as fields */
	e2k_io_vid_t		word;		/* as entire register */
} e2k_io_vid_struct_t;
#define	E2K_IO_VID_vid		fields.vid	/* vendor ID */
#define	E2K_IO_VID_reg		word

/*
 *   IO channel control/status register
 */
typedef	unsigned int	e2k_io_csr_t;		/* single word (32 bits) */
typedef	struct e2k_io_csr_fields {
	e2k_io_csr_t	srst 		: 1;		/* [0] */
	e2k_io_csr_t	unused1		: 3;		/* [3:1] */
	e2k_io_csr_t	bsy_ie		: 1;		/* [4] */
	e2k_io_csr_t	err_ie		: 1;		/* [5] */
	e2k_io_csr_t	to_ie		: 1;		/* [6] */
	e2k_io_csr_t	lsc_ie		: 1;		/* [7] */
	e2k_io_csr_t	unused2		: 4;		/* [11:8] */
	e2k_io_csr_t	bsy_ev		: 1;		/* [12] */
	e2k_io_csr_t	err_ev		: 1;		/* [13] */
	e2k_io_csr_t	to_ev		: 1;		/* [14] */
	e2k_io_csr_t	lsc_ev		: 1;		/* [15] */
	e2k_io_csr_t	unused3		: 14;		/* [29:16] */
	e2k_io_csr_t	link_tu		: 1;		/* [30] */
	e2k_io_csr_t	ch_on		: 1;		/* [31] */
} e2k_io_csr_fields_t;
typedef	union e2k_io_csr_struct {		/* Structure of word */
	e2k_io_csr_fields_t	fields;		/* as fields */
	e2k_io_csr_t		word;		/* as entire register */
} e2k_io_csr_struct_t;

#define	E2K_IO_CSR_srst		fields.srst	/* sofrware reset flag */
#define	E2K_IO_CSR_bsy_ie	fields.bsy_ie	/* flag of interrupt enable */
						/* on receiver busy */
#define	E2K_IO_CSR_err_ie	fields.err_ie	/* flag of interrupt enable */
						/* on CRC-error */
#define	E2K_IO_CSR_to_ie	fields.to_ie	/* flag of interrupt enable */
						/* on timeout */
#define	E2K_IO_CSR_lsc_ie	fields.lsc_ie	/* flag of interrupt enable */
						/* on link state changed */
#define	E2K_IO_CSR_bsy_ev	fields.bsy_ev	/* flag of interrupt */
						/* on receiver busy */
#define	E2K_IO_CSR_err_ev	fields.err_ev	/* flag of interrupt */
						/* on CRC-error */
#define	E2K_IO_CSR_to_ev	fields.to_ev	/* flag of interrupt */
						/* on timeout */
#define	E2K_IO_CSR_lsc_ev	fields.lsc_ev	/* flag of interrupt */
						/* on link state changed */
#define	E2K_IO_CSR_link_tu	fields.link_tu	/* flag of trening */
						/* in progress */
#define	E2K_IO_CSR_ch_on	fields.ch_on	/* flag of chanel */
						/* is ready and online */
#define	E2K_IO_CSR_reg		word
#define	IO_IS_ON_IO_CSR		1		/* IO controller is ready */
						/* and online */
/*
 *   IO channel timer register
 */
typedef	unsigned int	e2k_io_tmr_t;		/* single word (32 bits) */
typedef	struct e2k_io_tmr_fields {
	e2k_io_tmr_t	ptocl		: 16;		/* [15:0] */
	e2k_io_tmr_t	pbrn		: 16;		/* [31:16] */
} e2k_io_tmr_fields_t;
typedef	union e2k_io_tmr_struct {		/* Structure of word */
	e2k_io_tmr_fields_t	fields;		/* as fields */
	e2k_io_tmr_t		word;		/* as entire register */
} e2k_io_tmr_struct_t;

#define	E2K_IO_TMR_ptocl	fields.ptocl	/* packet time out counter */
						/* load */
#define	E2K_IO_TMR_pbrn		fields.pbrn	/* packet busy repeat counter */
						/* number */
#define	E2K_IO_TMR_reg		word

/*
 *   IO channel statistic register
 */
typedef	unsigned int	e2k_io_str_t;		/* single word (32 bits) */
typedef	struct e2k_io_str_fields {
	e2k_io_str_t	rc		: 24;		/* [23:0] */
	e2k_io_str_t	rcol		: 1;		/* [24] */
	e2k_io_str_t	reserved	: 4;		/* [28:25] */
	e2k_io_str_t	bsy_rce		: 1;		/* [29] */
	e2k_io_str_t	err_rce		: 1;		/* [30] */
	e2k_io_str_t	to_rce		: 1;		/* [31] */
} e2k_io_str_fields_t;
typedef	union e2k_io_str_struct {		/* Structure of word */
	e2k_io_str_fields_t	fields;		/* as fields */
	e2k_io_str_t		word;		/* as entire register */
} e2k_io_str_struct_t;

#define	E2K_IO_STR_rc		fields.rc	/* repeat counter */
#define	E2K_IO_STR_rcol		fields.rcol	/* repeat counter overload */
#define	E2K_IO_STR_bsy_rce	fields.bsy_rce	/* busy repeat count enable */
#define	E2K_IO_STR_err_rce	fields.err_rce	/* CRC-error repeat count */
						/* enable */
#define	E2K_IO_STR_to_rce	fields.to_rce	/* TO repeat count enable */
#define	E2K_IO_STR_reg		word

/*
 *   CPU channel control/status register
 */
typedef	unsigned int	e2k_pl_csr_t;		/* single word (32 bits) */
typedef	struct e2k_pl_csr_fields {
	e2k_pl_csr_t	rc		: 24;		/* [23:0] */
	e2k_pl_csr_t	rcol		: 1;		/* [24] */
	e2k_pl_csr_t	rce		: 1;		/* [25] */
	e2k_pl_csr_t	reserved	: 2;		/* [27:26] */
	e2k_pl_csr_t	link_tu		: 1;		/* [28] */
	e2k_pl_csr_t	ch_on		: 1;		/* [29] */
	e2k_pl_csr_t	lerr		: 1;		/* [30] */
	e2k_pl_csr_t	srst		: 1;		/* [31] */
} e2k_pl_csr_fields_t;
typedef	union e2k_pl_csr_struct {		/* Structure of word */
	e2k_pl_csr_fields_t	fields;		/* as fields */
	e2k_pl_csr_t		word;		/* as entire register */
} e2k_pl_csr_struct_t;

#define	E2K_PL_CSR_rc		fields.rc	/* repeat counter */
#define	E2K_PL_CSR_rcol		fields.rcol	/* repeat counter overload */
#define	E2K_PL_CSR_rce		fields.rce	/* repeat counter enable */
#define	E2K_PL_CSR_link_tu	fields.link_tu	/* link trening */
#define	E2K_PL_CSR_ch_on	fields.ch_on	/* channel status */
#define	E2K_PL_CSR_lerr		fields.lerr	/* link error */
#define	E2K_PL_CSR_srst		fields.srst	/* soft reset */
#define	E2K_PL_CSR_reg		word

/*
 * RDMA controller vendor ID
 */
typedef	unsigned int	e2k_rdma_vid_t;		/* single word (32 bits) */
typedef	struct e2k_rdma_vid_fields {
	e2k_rdma_vid_t	vid 		: 16;		/* [15:0] */
	e2k_rdma_vid_t  unused		: 16;		/* [31:16] */
} e2k_rdma_vid_fields_t;
typedef	union e2k_rdma_vid_struct {		/* Structure of word */
	e2k_rdma_vid_fields_t	fields;		/* as fields */
	e2k_rdma_vid_t		word;		/* as entire register */
} e2k_rdma_vid_struct_t;

#define	E2K_RDMA_VID_vid	fields.vid	/* vendor ID */
#define	E2K_RDMA_VID_reg	word

/*
 *   RDMA controller state register
 */
typedef	unsigned int	e2k_rdma_cs_t;		/* single word (32 bits) */
typedef	struct e2k_rdma_cs_fields {
	e2k_rdma_cs_t	ptocl		: 16;		/* [15:0] */
	e2k_rdma_cs_t	unused1		: 10;		/* [25:16] */
	e2k_rdma_cs_t	srst 		: 1;		/* [26] */
	e2k_rdma_cs_t	mor		: 1;		/* [27] */
	e2k_rdma_cs_t	mow		: 1;		/* [28] */
	e2k_rdma_cs_t	fch_on		: 1;		/* [29] */
	e2k_rdma_cs_t	link_tu		: 1;		/* [30] */
	e2k_rdma_cs_t	ch_on		: 1;		/* [31] */
} e2k_rdma_cs_fields_t;
typedef	union e2k_rdma_cs_struct {		/* Structure of word */
	e2k_rdma_cs_fields_t	fields;		/* as fields */
	e2k_rdma_cs_t		word;		/* as entire register */
} e2k_rdma_cs_struct_t;

#define	E2K_RDMA_CS_ptocl	fields.ptocl	/* timeout clock */
#define	E2K_RDMA_CS_srst	fields.srst	/* sofrware reset flag */
#define	E2K_RDMA_CS_mor		fields.mor	/* flag of not completed */
						/* readings */
#define	E2K_RDMA_CS_mow		fields.mow	/* flag of not completed */
						/* writings */
#define	E2K_RDMA_CS_fch_on	fields.fch_on	/* flag of chanel */
						/* forced set on */
#define	E2K_RDMA_CS_link_tu	fields.link_tu	/* flag of trenning */
						/* in progress */
#define	E2K_RDMA_CS_ch_on	fields.ch_on	/* flag of chanel */
						/* is ready and online */
#define	E2K_RDMA_CS_reg		word

/*
 *   Read/Write PWR_MGR0 register
 */
typedef unsigned int    e2k_pwr_mgr_t; /* single word (32 bits) */
typedef struct e2k_pwr_mgr_fields {
	e2k_pwr_mgr_t	core0_clk	:  1;		/* [0] */
	e2k_pwr_mgr_t	core1_clk	:  1;		/* [1] */
	e2k_pwr_mgr_t	ic_clk		:  1;		/* [2] */
	e2k_pwr_mgr_t	unused1		:  13;		/* [15:3] */
	e2k_pwr_mgr_t	snoop_wait	:  2;		/* [17:16] */
	e2k_pwr_mgr_t	unused2		:  14;		/* [31:18] */
} e2k_pwr_mgr_fields_t;
typedef union e2k_pwr_mgr_struct {	/* Structure of word */
	e2k_pwr_mgr_fields_t	fields;	/* as fields */
	e2k_pwr_mgr_t		word;	/* as entire register */
} e2k_pwr_mgr_struct_t;

#define E2K_PWR_MGR0_core0_clk	fields.core0_clk    /* core #0 clock on/off  */
#define E2K_PWR_MGR0_core1_clk	fields.core1_clk    /* core #1 clock on/off  */
#define E2K_PWR_MGR0_ic_clk	fields.ic_clk       /* dsp clock on/off   */
#define E2K_PWR_MGR0_snoop_wait	fields.snoop_wait   /* delay before off   */
                                                    /* for snoop-requests */
                                                    /* handling           */
#define E2K_PWR_MGR0_reg	word

/*
 * Monitor control register (SIC_MCR)
 */
typedef unsigned int	e2k_sic_mcr_t;		/* single word (32 bits) */
typedef struct e2k_sic_mcr_fields {
	e2k_sic_mcr_t	v0		: 1;		/* [0] */
	e2k_sic_mcr_t	unused1		: 1;		/* [1] */
	e2k_sic_mcr_t	es0		: 6;		/* [7:2] */
	e2k_sic_mcr_t	v1		: 1;		/* [8] */
	e2k_sic_mcr_t	unused2		: 1;		/* [9] */
	e2k_sic_mcr_t	es1		: 6;		/* [15:10] */
	e2k_sic_mcr_t	unused3		: 16;		/* [31:16] */
} e2k_sic_mcr_fields_t;
typedef union e2k_sic_mcr_struct {		/* Structure of word */
	e2k_sic_mcr_fields_t	fields;		/* as fields */
	e2k_sic_mcr_t		word;		/* as entire register */
} e2k_sic_mcr_struct_t;

#define E2K_SIC_MCR_v0		fields.v0	/* monitor #0 valid */
#define E2K_SIC_MCR_es0		fields.es0	/* monitor #0 event */
						/* specifier */
#define E2K_SIC_MCR_v1		fields.v1	/* monitor #1 valid */
#define E2K_SIC_MCR_es1		fields.es1	/* monitor #1 event */
						/* specifier */
#define E2K_SIC_MCR_reg		word

/*
 * Monitor accumulator register hi part (SIC_MAR0_hi, SIC_MAR1_hi)
 */
typedef unsigned int	e2k_sic_mar_hi_t;	/* single word (32 bits) */
typedef struct e2k_sic_mar_hi_fields {
	e2k_sic_mar_hi_t	val	: 31;	/* [30:0] */
	e2k_sic_mar_hi_t	of	: 1;	/* [31] */
} e2k_sic_mar_hi_fields_t;
typedef union e2k_sic_mar_hi_struct {		/* Structure of word */
	e2k_sic_mar_hi_fields_t	fields;		/* as fields */
	e2k_sic_mar_hi_t	word;		/* as entire register */
} e2k_sic_mar_hi_struct_t;

#define E2K_SIC_MAR_HI_val	fields.val	/* high part of events */
						/* counter */
#define E2K_SIC_MAR_HI_of	fields.of	/* overflow flag */
#define E2K_SIC_MAR_HI_reg	word

/*
 * Monitor accumulator register lo part (SIC_MAR0_lo, SIC_MAR1_lo)
 */
typedef unsigned int	e2k_sic_mar_lo_t;	/* single word (32 bits) */
typedef struct e2k_sic_mar_lo_fields {
	e2k_sic_mar_lo_t	val;		/* [31:0] */
} e2k_sic_mar_lo_fields_t;
typedef union e2k_sic_mar_lo_struct {		/* Structure of word */
	e2k_sic_mar_lo_fields_t	fields;		/* as fields */
	e2k_sic_mar_lo_t	word;		/* as entire register */
} e2k_sic_mar_lo_struct_t;

#define E2K_SIC_MAR_LO_val	fields.val	/* low part of events */
						/* counter */
#define E2K_SIC_MAR_LO_reg	word

/*
 * Read/Write MCX_ECC (X={0, 1, 2, 3}) registers
 */
typedef	unsigned int	e2k_mc_ecc_t;	/* single word (32 bits) */
typedef	struct e2k_mc_ecc_fields {
	e2k_mc_ecc_t	ee		: 1;	/* [0] */
	e2k_mc_ecc_t	dmode		: 1;	/* [1] */
	e2k_mc_ecc_t	of		: 1;	/* [2] */
	e2k_mc_ecc_t	ue		: 1;	/* [3] */
	e2k_mc_ecc_t	reserved	: 12;	/* [15:4] */
	e2k_mc_ecc_t	secnt		: 16;	/* [31:16] */
} e2k_mc_ecc_fields_t;
typedef	union e2k_mc_ecc_struct {		/* Structure word */
	e2k_mc_ecc_fields_t	fields;		/* as fields */
	e2k_mc_ecc_t		word;		/* as entire register */
} e2k_mc_ecc_struct_t;

#define E2K_MC_ECC_ee		fields.ee	/* ECC mode on/off */
#define E2K_MC_ECC_dmode	fields.dmode	/* diagnostic mode on/off */
#define E2K_MC_ECC_of		fields.of	/* single error counter */
						/* overflow flag */
#define E2K_MC_ECC_ue		fields.ue	/* multiple-error flag */
#define E2K_MC_ECC_secnt	fields.secnt	/* single error counter */
#define E2K_MC_ECC_reg		word

/*
 * Read/Write MCX_OPMb (X={0, 1, 2, 3}) registers
 */
typedef	unsigned int	e2k_mc_opmb_t;	/* single word (32 bits) */
typedef	struct e2k_mc_opmb_fields {
	e2k_mc_opmb_t	ct0		: 3;	/* [2:0] */
	e2k_mc_opmb_t	ct1		: 3;	/* [5:3] */
	e2k_mc_opmb_t	pbm0		: 2;	/* [7:6] */
	e2k_mc_opmb_t	pbm1		: 2;	/* [9:8] */
	e2k_mc_opmb_t	rm		: 1;	/* [10] */
	e2k_mc_opmb_t	rdodt		: 1;	/* [11] */
	e2k_mc_opmb_t	wrodt		: 1;	/* [12] */
	e2k_mc_opmb_t	bl8int		: 1;	/* [13] */
	e2k_mc_opmb_t	mi_fast		: 1;	/* [14] */
	e2k_mc_opmb_t	mt		: 1;	/* [15] */
	e2k_mc_opmb_t	il		: 1;	/* [16] */
	e2k_mc_opmb_t	rcven_del	: 2;	/* [18:17] */
	e2k_mc_opmb_t	mc_ps		: 1;	/* [19] */
	e2k_mc_opmb_t	arp_en		: 1;	/* [20] */
	e2k_mc_opmb_t	flt_brop	: 1;	/* [21] */
	e2k_mc_opmb_t	flt_rdpr	: 1;	/* [22] */
	e2k_mc_opmb_t	flt_blk		: 1;	/* [23] */
	e2k_mc_opmb_t	parerr		: 1;	/* [24] */
	e2k_mc_opmb_t	cmdpack		: 1;	/* [25] */
	e2k_mc_opmb_t	sldwr		: 1;	/* [26] */
	e2k_mc_opmb_t	sldrd		: 1;	/* [27] */
	e2k_mc_opmb_t	mirr		: 1;	/* [28] */
	e2k_mc_opmb_t	twrwr		: 2;	/* [30:29] */
	e2k_mc_opmb_t	mcln		: 1;	/* [31] */
} e2k_mc_opmb_fields_t;
typedef	union e2k_mc_opmb_struct {		/* Structure word */
	e2k_mc_opmb_fields_t	fields;		/* as fields */
	e2k_mc_opmb_t		word;		/* as entire register */
} e2k_mc_opmb_struct_t;

#define E2K_MC_OPMB_ct0		fields.ct0	 /* chip technology for slot #0 */
#define E2K_MC_OPMB_ct1		fields.ct1	 /* chip technology for slot #1 */
#define E2K_MC_OPMB_pbm0	fields.pbm0	 /* physical bank map for slot #0 */
#define E2K_MC_OPMB_pbm1	fields.pbm1	 /* physical bank map for slot #1 */
#define E2K_MC_OPMB_rm		fields.rm	 /* registered module */
#define E2K_MC_OPMB_rdodt	fields.rdodt	 /* enable ODT for read */
#define E2K_MC_OPMB_wrodt	fields.wrodt	 /* enable dynamic ODT for write */
#define E2K_MC_OPMB_bl8int	fields.bl8int	 /* enable burst termination */
#define E2K_MC_OPMB_mi_fast	fields.mi_fast	 /* parallel memory initializing */
#define E2K_MC_OPMB_mt		fields.mt	 /* address phase extension mode */
#define E2K_MC_OPMB_il		fields.il	 /* physical bank interleaving */
#define E2K_MC_OPMB_rcven_del	fields.rcven_del /* RCVEN delay */
#define E2K_MC_OPMB_mc_ps	fields.mc_ps	 /* power-save mode */
#define E2K_MC_OPMB_arp_en	fields.arp_en	 /* posted refresh */
#define E2K_MC_OPMB_flt_brop	fields.flt_brop	 /* reopen row filter control */
#define E2K_MC_OPMB_flt_rdpr	fields.flt_rdpr	 /* read priority filter control */
#define E2K_MC_OPMB_flt_blk	fields.flt_blk	 /* protocol block filter control */
#define E2K_MC_OPMB_parerr	fields.parerr	 /* parity check enable */
#define E2K_MC_OPMB_cmdpack	fields.cmdpack	 /* DDR command aggressive packing */
#define E2K_MC_OPMB_sldwr	fields.sldwr	 /* detection of sealed writes */
#define E2K_MC_OPMB_sldrd	fields.sldrd	 /* detection of sealed reads */
#define E2K_MC_OPMB_mirr	fields.mirr	 /* UDIMM address mirroring */
#define E2K_MC_OPMB_twrwr	fields.twrwr	 /* write-to-write additive latency */
#define E2K_MC_OPMB_mcln	fields.mcln	 /* memory clean start */
#define E2K_MC_OPMB_reg		word

/*
 * Read/Write IPCC_CSRX (X={1, 2, 3}) registers
 */
typedef	unsigned int	e2k_ipcc_csr_t;	/* single word (32 bits) */
typedef	struct e2k_ipcc_csr_fields {
	e2k_ipcc_csr_t	link_scale	: 4;	/* [3:0] */
	e2k_ipcc_csr_t	cmd_code	: 3;	/* [6:4] */
	e2k_ipcc_csr_t	cmd_active	: 1;	/* [7] */
	e2k_ipcc_csr_t	reserved	: 1;	/* [8] */
	e2k_ipcc_csr_t	terr_vc_num	: 3;	/* [11:9] */
	e2k_ipcc_csr_t	rx_oflw_uflw	: 1;	/* [12] */
	e2k_ipcc_csr_t	event_imsk	: 3;	/* [15:13] */
	e2k_ipcc_csr_t	ltssm_state	: 5;	/* [20:16] */
	e2k_ipcc_csr_t	cmd_cmpl_sts	: 3;	/* [23:21] */
	e2k_ipcc_csr_t	link_width	: 4;	/* [27:24] */
	e2k_ipcc_csr_t	event_sts	: 3;	/* [30:28] */
	e2k_ipcc_csr_t	link_state	: 1;	/* [31] */
} e2k_ipcc_csr_fields_t;
typedef	union e2k_ipcc_csr_struct {		/* Structure word */
	e2k_ipcc_csr_fields_t	fields;		/* as fields */
	e2k_ipcc_csr_t		word;		/* as entire register */
} e2k_ipcc_csr_struct_t;

#define E2K_IPCC_CSR_link_scale		fields.link_scale
#define E2K_IPCC_CSR_cmd_code		fields.cmd_code
#define E2K_IPCC_CSR_cmd_active		fields.cmd_active
#define E2K_IPCC_CSR_terr_vc_num	fields.terr_vc_num
#define E2K_IPCC_CSR_rx_oflw_uflw	fields.rx_oflw_uflw
#define E2K_IPCC_CSR_event_imsk		fields.event_imsk
#define E2K_IPCC_CSR_ltssm_state	fields.ltssm_state
#define E2K_IPCC_CSR_cmd_cmpl_sts	fields.cmd_cmpl_sts
#define E2K_IPCC_CSR_link_width		fields.link_width
#define E2K_IPCC_CSR_event_sts		fields.event_sts
#define E2K_IPCC_CSR_link_state		fields.link_state
#define E2K_IPCC_CSR_reg		word

/*
 * Read/Write IPCC_PMRX (X={1, 2, 3}) registers
 */
typedef	unsigned int	e2k_ipcc_pmr_t;	/* single word (32 bits) */
typedef	struct e2k_ipcc_pmr_fields {
	e2k_ipcc_pmr_t	reserved	: 1;	/* [0] */
	e2k_ipcc_pmr_t	force_rxdet	: 1;	/* [1] */
	e2k_ipcc_pmr_t	ctc_en		: 1;	/* [2] */
	e2k_ipcc_pmr_t	scramble	: 1;	/* [3] */
	e2k_ipcc_pmr_t	rcvr_tmrl	: 6;	/* [9:4] */
	e2k_ipcc_pmr_t	phle_lmt	: 5;	/* [14:10] */
	e2k_ipcc_pmr_t	dlle_lmt	: 5;	/* [19:15] */
	e2k_ipcc_pmr_t	irqpp		: 4;	/* [23:20] */
	e2k_ipcc_pmr_t	crqpp		: 4;	/* [27:24] */
	e2k_ipcc_pmr_t	drqpp		: 4;	/* [31:28] */
} e2k_ipcc_pmr_fields_t;
typedef	union e2k_ipcc_pmr_struct {		/* Structure word */
	e2k_ipcc_pmr_fields_t	fields;		/* as fields */
	e2k_ipcc_pmr_t		word;		/* as entire register */
} e2k_ipcc_pmr_struct_t;

#define E2K_IPCC_PMR_force_rxdet	fields.force_rxdet
#define E2K_IPCC_PMR_ctc_en		fields.ctc_en
#define E2K_IPCC_PMR_scramble		fields.scramble
#define E2K_IPCC_PMR_rcvr_tmrl		fields.rcvr_tmrl
#define E2K_IPCC_PMR_phle_lmt		fields.phle_lmt
#define E2K_IPCC_PMR_dlle_lmt		fields.dlle_lmt
#define E2K_IPCC_PMR_irqpp		fields.irqpp
#define E2K_IPCC_PMR_crqpp		fields.crqpp
#define E2K_IPCC_PMR_drqpp		fields.drqpp
#define E2K_IPCC_PMR_reg		word

/*
 * Read/Write IPCC_STRX (X={1, 2, 3}) registers
 */
typedef	unsigned int	e2k_ipcc_str_t;	/* single word (32 bits) */
typedef	struct e2k_ipcc_str_fields {
	e2k_ipcc_str_t	ecnt		: 29;	/* [28:0] */
	e2k_ipcc_str_t	eco		: 1;	/* [29] */
	e2k_ipcc_str_t	ecf		: 2;	/* [31:30] */
} e2k_ipcc_str_fields_t;
typedef	union e2k_ipcc_str_struct {		/* Structure word */
	e2k_ipcc_str_fields_t	fields;		/* as fields */
	e2k_ipcc_str_t		word;		/* as entire register */
} e2k_ipcc_str_struct_t;

#define E2K_IPCC_STR_ecnt	fields.ecnt	/* event counter */
#define E2K_IPCC_STR_eco	fields.eco	/* event counter overflow */
#define E2K_IPCC_STR_ecf	fields.ecf	/* event counter filter */
#define E2K_IPCC_STR_reg	word

/*
 * Read/Write SIC_SCCFG register
 */
typedef	unsigned int	e2k_sic_sccfg_t;	/* single word (32 bits) */
typedef	struct e2k_sic_sccfg_fields {
	e2k_sic_sccfg_t	diren		: 1;	/* [0] */
	e2k_sic_sccfg_t	dircacheen	: 1;	/* [1] */
	e2k_sic_sccfg_t	unused		: 30;	/* [31:2] */
} e2k_sic_sccfg_fields_t;
typedef	union e2k_sic_sccfg_struct {		/* Structure word */
	e2k_sic_sccfg_fields_t	fields;		/* as fields */
	e2k_sic_sccfg_t		word;		/* as entire register */
} e2k_sic_sccfg_struct_t;

#define E2K_SIC_SCCFG_diren	 fields.diren	   /* directory enabled */
#define E2K_SIC_SCCFG_dircacheen fields.dircacheen /* directory cache enabled */
#define E2K_SIC_SCCFG_reg	 word

#endif /* ! __ASSEMBLY__ */
#endif /* __KERNEL__ */
#endif  /* _E2K_SIC_REGS_H_ */
