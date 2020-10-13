
#ifndef	_SPARC64_SIC_REGS_H_
#define	_SPARC64_SIC_REGS_H_

#include <linux/topology.h>
#include <asm/types.h>
#include <asm/e90s.h>
#include <asm/io.h>
#include <asm/topology.h>

#ifndef	__ASSEMBLY__

/*
 * IO controller vendor ID
 */
typedef	unsigned int	e90s_io_vid_t;		/* single word (32 bits) */
typedef	struct e90s_io_vid_fields {
	e90s_io_vid_t	unused		: 16;	/* [31:16] */
	e90s_io_vid_t	vid		: 16;	/* [15:0] */
} e90s_io_vid_fields_t;
typedef	union e90s_io_vid_struct {		/* Structure of word */
	e90s_io_vid_fields_t	fields;		/* as fields */
	e90s_io_vid_t		word;		/* as entier register */
} e90s_io_vid_struct_t;
#define	NBSR_IO_VID_vid(REG)		\
		((REG).fields.vid)		/* vendor ID */
#define	NBSR_IO_VID_reg(REG)		\
		((REG).word)

/*
 *   IO controller state register
 */
typedef	unsigned int	e90s_io_csr_t;		/* single word (32 bits) */
typedef	struct e90s_io_csr_fields {
	e90s_io_csr_t	ch_on		: 1;		/* [31] */
	e90s_io_csr_t	link_tu		: 1;		/* [30] */
	e90s_io_csr_t	unused3		: 15;		/* [29:15] */
	e90s_io_csr_t	to_ev		: 1;		/* [14] */
	e90s_io_csr_t	err_ev		: 1;		/* [13] */
	e90s_io_csr_t	bsy_ev		: 1;		/* [12] */
	e90s_io_csr_t	unused2		: 5;		/* [11:7] */
	e90s_io_csr_t	to_ie		: 1;		/* [6] */
	e90s_io_csr_t	err_ie		: 1;		/* [5] */
	e90s_io_csr_t	bsy_ie		: 1;		/* [4] */
	e90s_io_csr_t	unused1		: 3;		/* [3:1] */
	e90s_io_csr_t	srst		: 1;		/* [0] */
} e90s_io_csr_fields_t;
typedef	union e90s_io_csr_struct {		/* Structure of word */
	e90s_io_csr_fields_t	fields;		/* as fields */
	e90s_io_csr_t		word;		/* as entier register */
} e90s_io_csr_struct_t;

#define	NBSR_IO_CSR_srst(REG)		\
		((REG).fields.srst)		/* sofrware reset flag */
#define	NBSR_IO_CSR_bsy_ie(REG)		\
		((REG).fields.bsy_ie)		/* flag of interrupt enable */
						/* on receiver busy */
#define	NBSR_IO_CSR_err_ie(REG)		\
		((REG).fields.err_ie)		/* flag of interrupt enable */
						/* on CRC-error */
#define	NBSR_IO_CSR_to_ie(REG)		\
		((REG).fields.to_ie)		/* flag of interrupt enable */
						/* on timeout */
#define	NBSR_IO_CSR_bsy_ev(REG)		\
		((REG).fields.bsy_ev)		/* flag of interrupt */
						/* on receiver busy */
#define	NBSR_IO_CSR_err_ev(REG)		\
		((REG).fields.err_ev)		/* flag of interrupt */
						/* on CRC-error */
#define	NBSR_IO_CSR_to_ev(REG)		\
		((REG).fields.to_ev)		/* flag of interrupt */
						/* on timeout */
#define	NBSR_IO_CSR_link_tu(REG)	\
		((REG).fields.link_tu)		/* flag of trening */
						/* in progress */
#define	NBSR_IO_CSR_ch_on(REG)		\
		((REG).fields.ch_on)		/* flag of chanel */
						/* is ready and online */
#define	NBSR_IO_CSR_reg(REG)		\
		((REG).word)
#define	IO_IS_ON_IO_CSR		1		/* IO controller is ready */
						/* and online */

/*
 * Node Configuration
 */
typedef	unsigned int	e90s_ncfg_t;		/* single word (32 bits) */
typedef	struct e90s_ncfg_fields {
	e90s_ncfg_t	unused1		:  8;		/* [31:24] */
	e90s_ncfg_t	ApicIoPresentMask :  4;		/* [23:20] */
	e90s_ncfg_t	ApicNodePresentMask :  4;	/* [19:16] */
	e90s_ncfg_t	unused2		:  2;		/* [15:14] */
	e90s_ncfg_t	CoreCmpMode	:  1;		/* [13] */
	e90s_ncfg_t	CohModeHb	:  1;		/* [12] */
	e90s_ncfg_t	CoreHardMask	:  4;		/* [11:8] */
	e90s_ncfg_t	IoLinkRdmaMode	:  1;		/* [7] */
	e90s_ncfg_t	Bootstrap	:  1;		/* [6] */
	e90s_ncfg_t	BootMode	:  1;		/* [5] */
	e90s_ncfg_t	CohModeL2	:  1;		/* [4] */
	e90s_ncfg_t	CoreSoftMask	:  4;		/* [3:0] */
} e90s_ncfg_fields_t;
typedef	union e90s_ncfg_struct {		/* Structure of word */
	e90s_ncfg_fields_t	fields;		/* as fields */
	e90s_ncfg_t		word;		/* as entier register */
} e90s_ncfg_struct_t;
#define	NBSR_NCFG_ApicIoPresentMask(REG)	\
		((REG).fields.ApicIoPresentMask)	/* present IO */
							/* links mask */
#define	NBSR_NCFG_ApicNodePresentMask(REG)	\
		((REG).fields.ApicNodePresentMask)	/* present */
							/* CPUS link */
							/* mask */
#define	NBSR_NCFG_CoreCmpMode(REG)		\
		((REG).fields.CoreCmpMode)		/* core comparision */
							/* mode flag */
#define	NBSR_NCFG_CohModeHb(REG)		\
		((REG).fields.CohModeHb)		/* IO coherent mode */
#define	NBSR_NCFG_CoreHardMask(REG)		\
		((REG).fields.CoreHardMask)		/* present core */
							/* hardware mask */
#define	NBSR_NCFG_IoLinkRdmaMode(REG)		\
		((REG).fields.IoLinkRdmaMode)		/* IO link is RDMA */
#define	NBSR_NCFG_Bootstrap(REG)		\
		((REG).fields.Bootstrap)		/* bootstrap CPU */
#define	NBSR_NCFG_BootMode(REG)			\
		((REG).fields.BootMode)			/* boot mode */
#define	NBSR_NCFG_CohModeL2(REG)		\
		((REG).fields.CohModeL2)		/* L2 coherent mode */
#define	NBSR_NCFG_CoreSoftMask(REG)		\
		((REG).fields.CoreSoftMask)		/* present core */
							/* software mask */
#define	NBSR_NCFG_reg(REG)			\
		((REG).word)

#define	IOHUB_IOL_MODE		0	/* controller is IO HUB */
#define	RDMA_IOL_MODE		1	/* controller is RDMA */

/*
 * Node Configuration Information
 */
typedef	unsigned int	e90s_nc_info_t;		/* single word (32 bits) */
typedef	struct e90s_nc_info_fields {
	e90s_nc_info_t  unused1		:  6;		/* [31:26] */
	e90s_nc_info_t	IoccLinkTu	:  1;		/* [25] */
	e90s_nc_info_t	IoccLinkUp	:  1;		/* [24] */
	e90s_nc_info_t	unused2		:  1;		/* [23] */
	e90s_nc_info_t  IoccLinkRtype	:  7;		/* [22:16] */
	e90s_nc_info_t  unused3		:  8;		/* [15:8] */
	e90s_nc_info_t  ClkDiv		:  8;		/* [7:0] */
} e90s_nc_info_fields_t;
typedef	union e90s_nc_info_struct {		/* Structure of word */
	e90s_nc_info_fields_t	fields;		/* as fields */
	e90s_nc_info_t		word;		/* as entier register */
} e90s_nc_info_struct_t;
#define	NBSR_NC_INFO_IoccLinkTu(REG)	\
		((REG).fields.IoccLinkTu)	/* training flag */
#define	NBSR_NC_INFO_IoccLinkUp(REG)	\
		((REG).fields.IoccLinkUp)	/* IO link UP */
#define	NBSR_NC_INFO_IoccLinkRtype(REG)	\
		((REG).fields.IoccLinkRtype)	/* abonent type */
#define	NBSR_NC_INFO_ClkDiv(REG)	\
		((REG).fields.ClkDiv)
#define	NBSR_NC_INFO_reg(REG)		\
		((REG).word)

#define	IOHUB_ONLY_IOL_ABTYPE	1	/* abonent has only IO HUB */
					/* controller */
#define	RDMA_ONLY_IOL_ABTYPE	2	/* abonent has only RDMA */
					/* controller */
#define	RDMA_IOHUB_IOL_ABTYPE	3	/* abonent has RDMA and */
					/* IO HUB controller */

/*
 * RDMA controller vendor ID
 */
typedef	unsigned int	e90s_rdma_vid_t;	/* single word (32 bits) */
typedef	struct e90s_rdma_vid_fields {
	e90s_rdma_vid_t  unused		: 16;		/* [31:16] */
	e90s_rdma_vid_t	vid		: 16;		/* [15:0] */
} e90s_rdma_vid_fields_t;
typedef	union e90s_rdma_vid_struct {		/* Structure of word */
	e90s_rdma_vid_fields_t	fields;		/* as fields */
	e90s_rdma_vid_t		word;		/* as entier register */
} e90s_rdma_vid_struct_t;

#define	NBSR_RDMA_VID_vid(REG)		\
		((REG).fields.vid)		/* vendor ID */
#define	NBSR_RDMA_VID_reg(REG)		\
		((REG).word)

/*
 *   RDMA controller state register
 */
typedef	unsigned int	e90s_rdma_cs_t;		/* single word (32 bits) */
typedef	struct e90s_rdma_cs_fields {
	e90s_rdma_cs_t	ch_on		: 1;		/* [31] */
	e90s_rdma_cs_t	link_tu		: 1;		/* [30] */
	e90s_rdma_cs_t	fch_on		: 1;		/* [29] */
	e90s_rdma_cs_t	mow		: 1;		/* [28] */
	e90s_rdma_cs_t	mor		: 1;		/* [27] */
	e90s_rdma_cs_t	srst		: 1;		/* [26] */
	e90s_rdma_cs_t  unused1		: 10;		/* [25:16] */
	e90s_rdma_cs_t	ptocl		: 16;		/* [15:0] */
} e90s_rdma_cs_fields_t;
typedef	union e90s_rdma_cs_struct {		/* Structure of word */
	e90s_rdma_cs_fields_t	fields;		/* as fields */
	e90s_rdma_cs_t		word;		/* as entier register */
} e90s_rdma_cs_struct_t;

#define	NBSR_RDMA_CS_ptocl(REG)		\
		((REG).fields.ptocl)		/* timeout clock */
#define	NBSR_RDMA_CS_srst(REG)		\
		((REG).fields.srst)		/* sofrware reset flag */
#define	NBSR_RDMA_CS_mor(REG)		\
		((REG).fields.mor)		/* flag of not completed */
						/* readings */
#define	NBSR_RDMA_CS_mow(REG)		\
		((REG).fields.mow)		/* flag of not completed */
						/* writings */
#define	NBSR_RDMA_CS_fch_on(REG)	\
		((REG).fields.fch_on)		/* flag of chanel */
						/* forced set on */
#define	NBSR_RDMA_CS_link_tu(REG)	\
		((REG).fields.link_tu)		/* flag of trenning */
						/* in progress */
#define	NBSR_RDMA_CS_ch_on(REG)		\
		((REG).fields.ch_on)		/* flag of chanel */
						/* is ready and online */
#define	NBSR_RDMA_CS_reg(REG)		\
		((REG).word)

#endif /* ! __ASSEMBLY__ */

#define	nbsr_early_read(addr)		__raw_readl((addr))
#define	nbsr_early_write(value, addr)	__raw_writel((value), (addr))

#define	nbsr_read(addr)			__raw_readl((addr))
#define	nbsr_write(value, addr)		__raw_writel((value), (addr))

#include <asm-l/sic_regs.h>

#endif  /* _SPARC64_SIC_REGS_H_ */
