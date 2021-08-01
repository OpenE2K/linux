#ifndef _SPARC64_E90_H
#define _SPARC64_E90_H


#include <linux/const.h>
#include <linux/init.h>

/* ��������� ����� */		
#define E90S_DCACHE_SIZE		(32 * 1024)
#define E90S_DCACHE_LINE_SHIFT	6
#define E90S_DCACHE_LINE_SIZE	(1 << E90S_DCACHE_LINE_SHIFT)
#define E90S_ICACHE_SIZE		(16 * 1024)
#define E90S_ICACHE_LINE_SIZE	(64)
#define E90S_ECACHE_SIZE		(2 * 1024 * 1024)
#define E90S_ECACHE_LINE_SIZE	(64)
		
/* ����������� ������� MMU MCNTL */

#define E90S_MCNTL	0x8

/* 	�������� 		����	����� ������� 	Reset 	��������*/
#define E90S_MCNTL_IRM_8K	(0<<16)	/*	RW	00	sITLB RAM Mode ? ������ �������, ���������� � sITLB. */
#define E90S_MCNTL_IRM_64K	(1<<16)	/*			������ ���������� ���� DRM01. */
#define E90S_MCNTL_IRM_512K	(2<<16)	/*			������ sITLB �������� ����� ���� ����������� � ���� TTE.size*/
#define E90S_MCNTL_IRM_1M	(3<<16)	/*			*/

#define E90S_MCNTL_FW_FITLB	(1<<15)	/*	RW	 0	������ � ITLB ����� Data \
								In Register ����� ���������� � fITLB \
 								���������� �� ������� �������� � TTE*/
#define E90S_MCNTL_FW_FDTLB	(1<<14)	/*	RW	 0	������ � DTLB ����� Data \
									In Register ����� ���������� � fITLB \
 									���������� �� ������� �������� � TTE**/
#define E90S_MCNTL_DRM23_8K	(0<<12)	/*	RW	00	sDTLB RAM Mode 23 ? ������ �������, */
#define E90S_MCNTL_DRM23_64K	(1<<12)	/*			���������� �� ������ � ������� �������� sDTLB.*/
#define E90S_MCNTL_DRM23_512K	(2<<12)	/*			������ ���������� ���� DRM01*/
#define E90S_MCNTL_DRM23_4M	(3<<12)	/*			*/
#define E90S_MCNTL_DRM23_MSK	(3<<12)

#define E90S_MCNTL_DRM01_8K	(0<<10)	/*	RW	00	sDTLB RAM Mode 01 ? ������ �������, */
#define E90S_MCNTL_DRM01_64K	(1<<10)	/*			���������� � ������� � ������ �������� sDTLB*/
#define E90S_MCNTL_DRM01_512K	(2<<10)	/*			*/
#define E90S_MCNTL_DRM01_4M	(3<<10)	/*			*/
#define E90S_MCNTL_DRM01_MSK	(3<<10)

#define E90S_MCNTL_NC_CACHE	(1<<9)	/*	RW	0	����������� ���������� ��� �����ޣ���� L1I. ��� ��������.*/
#define E90S_MCNTL_JPS1_TSBP	(1<<8)	/*	RW	0	��������� � TSB ����������� � ������������ � JPS1 ��� Ultra I/II*/

#if PAGE_SHIFT == 13
#define E90S_MCNTL_IRM_DEFAULT		E90S_MCNTL_IRM_8K
#define E90S_MCNTL_DRM01_DEFAULT	E90S_MCNTL_DRM01_8K
#define E90S_MCNTL_DRM23_DEFAULT	E90S_MCNTL_DRM23_8K
#elif PAGE_SHIFT == 16
#define E90S_MCNTL_IRM_DEFAULT		E90S_MCNTL_IRM_64K
#define E90S_MCNTL_DRM01_DEFAULT	E90S_MCNTL_DRM01_64K
#define E90S_MCNTL_DRM23_DEFAULT	E90S_MCNTL_DRM23_64K
#elif PAGE_SHIFT == 19
#define E90S_MCNTL_IRM_DEFAULT		E90S_MCNTL_IRM_512K
#define E90S_MCNTL_DRM01_DEFAULT	E90S_MCNTL_DRM01_512K
#define E90S_MCNTL_DRM23_DEFAULT	E90S_MCNTL_DRM23_512K
#elif PAGE_SHIFT == 22
#define E90S_MCNTL_IRM_DEFAULT		E90S_MCNTL_IRM_4M
#define E90S_MCNTL_DRM01_DEFAULT	E90S_MCNTL_DRM01_4M
#define E90S_MCNTL_DRM23_DEFAULT	E90S_MCNTL_DRM23_4M
#else
#error No page size specified in kernel configuration
#endif


#define E90S_ICJR		0x10

#define ICJR_GHR_SHIFT		10
#define ICJR_GHR_MASK		0x3ff


#define E90S_DBGJMP		0x20

#define DBGJMP_MM_MASK		(3<<22)
#define DBGJMP_MM_PSTATE_MM	(0<<22)
#define DBGJMP_MM_TSO		(1<<22)
#define DBGJMP_MM_RMO		(2<<22)


	/*������������� ��������� ������������*/

/*������������ ��������� ������� */
#define BASE_DRAM	_AC(0,UL)	/*������������ ����������� ������*/
#define BASE_PCIMEM 	_AC(0,UL)	/*������������ PCI MMIO */


/*����� ������ ������� PCI	 		������ 	�����������*/
#define BASE_BOOT 	_AC(0xFFFF000000,UL)	/*256M 	��� � ���������� ��������� */
						/*������������ ������� � �������� ��*/
#define BASE_PCIIO 	_AC(0xFF20000000,UL)	/*256M 	������������ PCIIO.*/
 			/*��������� ������������� � IO hub � �������� I/O Read � I/O Write.*/
#define BASE_PEXCFG 	_AC(0xFF10000000,UL) 	/*256M 	����������� ������������ ������������ PCI Express.*/
 				/*����� ������������ � ������������ � ������� 7.2.2*/
 				/*������������ PCI Express.*/

#define PCI_CONFIG_BASE		BASE_PEXCFG

/*
 * �������� ������������ ����
 * Nodes configuration area (NODESREG)
 */

#define	NODES_CONF_AREA_BASE	_AC(0xFE00000000, UL)	/* base of area */
#define	NODES_CONF_AREA_SIZE	_AC(0x0100000000, UL)	/* size of area */
#define	NODE_CONF_AREA_SIZE	_AC(0x0010000000, UL)	/* node area size */
#define NODE_OFF		NODE_CONF_AREA_SIZE
#define	NODE_CONF_AREA_BASE(nodeid)	/* the node conf area base */ \
		(NODES_CONF_AREA_BASE + (NODE_CONF_AREA_SIZE * (nodeid)))
#define	NODE0_CONF_AREA_BASE	NODE_CONF_AREA_BASE(0)
#define	NODE1_CONF_AREA_BASE	NODE_CONF_AREA_BASE(1)
#define	NODE2_CONF_AREA_BASE	NODE_CONF_AREA_BASE(2)
#define	NODE3_CONF_AREA_BASE	NODE_CONF_AREA_BASE(3)
#define	BASE_NODE0	NODE0_CONF_AREA_BASE	/* node #0*/
#define	BASE_NODE1	NODE1_CONF_AREA_BASE	/* node #1*/
#define	BASE_NODE2	NODE2_CONF_AREA_BASE	/* node #2*/
#define	BASE_NODE3	NODE3_CONF_AREA_BASE	/* node #3*/

#define	NODES_PFREG_AREA_BASE	_AC(0xFD00000000, UL)	/* base of area */
#define	NODES_PFREG_AREA_SIZE	_AC(0x0100000000, UL)	/* size of area */
#define	NODE_PFREG_AREA_SIZE	_AC(0x0010000000, UL)	/* node area size */
#define	NODE_PFREG_AREA_BASE(nodeid)	/* the node PFREG area base */ \
		(NODES_PFREG_AREA_BASE + (NODE_PFREG_AREA_SIZE * (nodeid)))
#define	NODE0_PFREG_AREA_BASE	NODE_PFREG_AREA_BASE(0)
#define	NODE1_PFREG_AREA_BASE	NODE_PFREG_AREA_BASE(1)
#define	NODE2_PFREG_AREA_BASE	NODE_PFREG_AREA_BASE(2)
#define	NODE3_PFREG_AREA_BASE	NODE_PFREG_AREA_BASE(3)

#ifndef	__ASSEMBLY__
/*
 * Nodes processor system registers (north bridge)
 * NBSR = { NBSR0 ... NBSRj ... }
 * NBSR is some part of node system registers area NSR
 */
#define	NODE_NBSR_OFFSET	0x0000000	/* offset of NBSR base into */
						/* node configuration area */
#define	NODE_NBSR_SIZE		0x0100000	/* 1 Mb - size of NBSR area */
#define	THE_NODE_NBSR_PHYS_BASE(node)					\
		((unsigned char *)(NODE_CONF_AREA_BASE(node) +		\
						NODE_NBSR_OFFSET))

#ifdef	CONFIG_NUMA
static inline unsigned char *
sic_get_node_nbsr_base(int node_id)
{
	return THE_NODE_NBSR_PHYS_BASE(node_id);
}
#else	/* ! CONFIG_NUMA */
/*
 * NUMA mode is not supported, but each node can has online IO link
 * IO links have numeration same as nodes:
 * IO link #0 is link on node 0 (CPUs 0-3)
 * IO link #1 is link on node 1 (CPUs 4-7)
 * ...
 * So in this case node # is always only 0 and IO link # can be considered
 * as node #
 */
static inline unsigned char *
sic_get_node_nbsr_base(int link)
{
	return THE_NODE_NBSR_PHYS_BASE(link);
}
extern void __init create_nodes_config(void);
#endif	/* CONFIG_NUMA */

extern int __init e90s_sic_init(void);
extern int __init e90s_early_iohub_online(int node, int link);

#endif	/* ! __ASSEMBLY__ */

/*
 * ������ ��������� ������������ NBSR
 */
	/* �������� [15:0] 	������ (����) 	������� */
	
	/* ������������ ����������� ������ */
#define NBSR_MEM_EN        0x0000	/* 4 	Memory Enable */
#define NBSR_MEM_DEL       0x0004	/* 4 	Memory Delay */
#define NBSR_FAULT_ST      0x0008	/* 4	Fault Status */
#define NBSR_VIDEO_CONF    0x000c	/* 4 	Video Configuration */
#define NBSR_FAULT0        0x0010	/* 4 	Fault Address 0 */
#define NBSR_FAULT1        0x0014	/* 4 	Fault Address 1 */
#define NBSR_ECC_DIAG      0x0018	/* 4 	ECC Diagnostics */
#define NBSR_EX_MEM_CTRL0  0x0100	/* 4 	Extended Memory Control 0 */
#define NBSR_EX_MEM_CTRL1  0x0104	/* 4 	Extended Memory Control 1 */
#define NBSR_EX_MEM_CTRL2  0x0108	/* 4 	Extended Memory Control 2 */
#define NBSR_EX_MEM_CTRL3  0x010c	/* 4 	Extended Memory Control 3 */
#define NBSR_SPD_ST        0x0110	/* 4 	SPD status */
#define NBSR_SPD_DATA0     0x0200	/* 128 	SPD Data slot_0 */
#define NBSR_SPD_DATA1     0x0280	/*  128 	SPD Data slot_1 */

	/* ������������ address mapping */
#define NBSR_DRAM_BASE0    0x1000	/* 4 	DRAM Base 0 */
#define NBSR_DRAM_LIMIT0   0x1004	/* 4 	DRAM Limit 0  */
#define NBSR_DRAM_BASE1    0x1008	/* 4 	DRAM Base 1 */
#define NBSR_DRAM_LIMIT1   0x100c	/* 4 	DRAM Limit 1 */
#define NBSR_DRAM_BASE2    0x1010	/* 4 	DRAM Base 2 */
#define NBSR_DRAM_LIMIT2   0x1014	/* 4 	DRAM Limit 2 */
#define NBSR_DRAM_BASE3    0x1018	/* 4 	DRAM Base 3 */
#define NBSR_DRAM_LIMIT3   0x101c	/* 4 	DRAM Limit 3 */
#define NBSR_MMIO_BASE0    0x1020	/* 4 	MMIO Base 0 */
#define NBSR_MMIO_LIMIT0   0x1024	/* 4 	MMIO Limit 0 */
#define NBSR_MMIO_BASE1    0x1028	/* 4 	MMIO Base 1 */
#define NBSR_MMIO_LIMIT1   0x102c	/* 4 	MMIO Limit 1 */
#define NBSR_MMIO_BASE2    0x1030	/* 4 	MMIO Base 2 */
#define NBSR_MMIO_LIMIT2   0x1034	/* 4 	MMIO Limit 2 */
#define NBSR_MMIO_BASE3    0x1038	/* 4 	MMIO Base 3 */
#define NBSR_MMIO_LIMIT3   0x103c	/* 4 	MMIO Limit 3 */
#define NBSR_PCIIO_BASE0   0x1040	/* 4 	PCIIO Base 0 */
#define NBSR_PCIIO_LIMIT0  0x1044	/* 4 	PCIIO Limit 0 */
#define NBSR_PCIIO_BASE1   0x1048	/* 4 	PCIIO Base 1 */
#define NBSR_PCIIO_LIMIT1  0x104c	/* 4 	PCIIO Limit 1 */
#define NBSR_PCIIO_BASE2   0x1050	/* 4 	PCIIO Base 2 */
#define NBSR_PCIIO_LIMIT2  0x1054	/* 4 	PCIIO Limit 2 */
#define NBSR_PCIIO_BASE3   0x1058	/* 4 	PCIIO Base 3 */
#define NBSR_PCIIO_LIMIT3  0x105c	/* 4 	PCIIO Limit 3 */
#define NBSR_PEXCFG0       0x1060	/* 4 	PEXCFG Base and Limit 0 */
#define NBSR_PEXCFG1       0x1064	/* 4 	PEXCFG Base and Limit 1 */
#define NBSR_PEXCFG2       0x1068	/* 4 	PEXCFG Base and Limit 2 */
#define NBSR_PEXCFG3       0x106c	/* 4 	PEXCFG Base and Limit 3 */
#define NBSR_DRAM_HOLE_BASE     0x1070	/* 4 	DRAM Hole Base */
#define NBSR_DRAM_HOLE_LIMIT    0x1074	/* 4 	DRAM Hole Limit */
#define NBSR_IOAPIC_BASE   0x1078	/* 4 	IOAPIC Message base */
#define NBSR_LAPIC_BASE    0x107c	/* 4 	LAPIC Message base */
#define NBSR_MC_CONFIG     0x10a0	/* 4	MC Configuration */
# define NBSR_MC_INTERLEAVE_BIT_OFFSET    4
# define NBSR_MC_INTERLEAVE_BIT_MASK    0xf
# define NBSR_MC_INTERLEAVE_BIT_MIN    6
# define NBSR_MC_INTERLEAVE_BIT_MAX    23
# define NBSR_MC_ENABLE_MC1    (1 << 1)
# define NBSR_MC_ENABLE_MC0    (1 << 0)
#define NBSR_EPIC_UP_MSG_BASE     0x10a4	/* 4	EPIC Upstream Message Base */
 #define NBSR_EPIC_UP_MSG_BASE_TO_ADDR(__v) (__v << (20 - 12))

		/* ������������ ������ */
#define NBSR_IO_VID        0x2000	/* 4	IO Channel VID (IO_VID) */
#define NBSR_IO_CSR        0x2004	/* 4	IO Control/Status Register (IO_CSR) */
#define NBSR_IO_TMR        0x2008	/* 4	IO Timer Register (IO_TMR) */
#define NBSR_IO_STR        0x200c	/* 4	IO Statistic Register (IO_STR) */
#define NBSR_IO_FHR0       0x2104	/* 4	IO Fault Header Register0 (IO_FHR0) */
#define NBSR_IO_FHR1       0x2108	/* 4	IO Fault Header Register1 (IO_FHR1) */
#define NBSR_IO_FHR2       0x210c	/* 4	IO Fault Header Register2 (IO_FHR2) */
#define NBSR_IO_FHR3       0x2110	/* 4	IO Fault Header Register3 (IO_FHR3) */
#define NBSR_VID           0x3080	/* 4	RDMA VID VID */
#define NBSR_CH_IDT        0x3084	/* 4	RDMAChannel ID/Type (CH_IDT) */
#define NBSR_CS            0x3088	/* 4	RDMA Control/Status (CS) */
#define NBSR_DD_ID         0x3000	/* 4	Data Destination ID (DD_ID) */
#define NBSR_IDDMD_ID      0x3004	/* 4	Data_Message Destination (IDDMD_ID) */
#define NBSR_N_IDT         0x3008	/* 4	Neighbour ID/Type (N_IDT) */
#define NBSR_ES            0x300c	/* 4	Event Status (ES) */
#define NBSR_IRQ_MC        0x3010	/* 4	Interrupt Mask Control (IRQ_MC) */
#define NBSR_DMA_TCS       0x3014	/* 4	DMA Tx Control/Status (DMA_TCS) */
#define NBSR_DMA_TSA       0x3018	/* 4	DMA Tx Start Address (DMA_TSA) */
#define NBSR_DMA_TBC       0x301c	/* 4	DMA Tx Byte Counter (DMA_TBC) */
#define NBSR_DMA_RCS       0x3020	/* 4	DMA Rx Control/Status(DMA_RCS) */
#define NBSR_DMA_RSA       0x3024	/* 4	DMA Rx Start Address(DMA_RSA) */
#define NBSR_DMA_RBC       0x3028	/* 4	DMA Rx Byte Counter (DMA_RBC) */
#define NBSR_MSG_SC        0x302c	/* 4	Message Control/Status (MSG_CS) */
#define NBSR_TDMSG         0x3030	/* 4	Tx Data_Message Buffer (TDMSG) */
#define NBSR_RDMSG         0x3034	/* 4	Rx Data_Message Buffer (RDMSG) */
#define NBSR_CAM	   0x3038	/* 4	Channel Alive Management (CAM) */

#define NBSR_LINK0_VID     0x4000	/* 4 	Link0 Channel VID (LNK0_VID) */
#define NBSR_LINK0_CSR     0x4004	/* 4 	Link0 Control/Status Register (LNK0_CSR) */
#define NBSR_LINK0_TMR     0x4008	/* 4 	Link0 Timer Register (LNK0_TMR) */
#define NBSR_LINK0_STR     0x4100	/* 4 	Link0 Statistic Register (LNK0_STR) */
#define NBSR_LINK0_FHR0    0x4104	/* 4 	Link0 Fault Header Register0 (LNK0_FHR0) */
#define NBSR_LINK0_FHR1    0x4108	/* 4 	Link0 Fault Header Register1 (LNK0_FHR1) */
#define NBSR_LINK0_FHR2    0x410c	/* 4 	Link0 Fault Header Register2 (LNK0_FHR2) */
#define NBSR_LINK0_FHR3    0x4110	/* 4 	Link0 Fault Header Register3 (LNK0_FHR3) */
#define NBSR_LINK1_VID     0x5000	/* 4 	Link1 Channel VID (LNK1_VID) */
#define NBSR_LINK1_CSR     0x5004	/* 4 	Link1 Control/Status Register (LNK1_CSR) */
#define NBSR_LINK1_TMR     0x5008	/* 4 	Link1 Timer Register (LNK1_TMR) */
#define NBSR_LINK1_STR     0x5100	/* 4 	Link1 Statistic Register (LNK1_STR) */
#define NBSR_LINK1_FHR0    0x5104	/* 4 	Link1 Fault Header Register0 (LNK1_FHR0) */
#define NBSR_LINK1_FHR1    0x5108	/* 4 	Link1 Fault Header Register1 (LNK1_FHR1) */
#define NBSR_LINK1_FHR2    0x510c	/* 4 	Link1 Fault Header Register2 (LNK1_FHR2) */
#define NBSR_LINK1_FHR3    0x5110	/* 4 	Link1 Fault Header Register3 (LNK1_FHR3) */
#define NBSR_LINK2_VID     0x6000	/* 4 	Link2 Channel VID (LNK2_VID) */
#define NBSR_LINK2_CSR     0x6004	/* 4 	Link2 Control/Status Register (LNK2_CSR) */
#define NBSR_LINK2_TMR     0x6008	/* 4 	Link2 Timer Register (LNK2_TMR) */
#define NBSR_LINK2_STR     0x6100	/* 4 	Link2 Statistic Register (LNK2_STR) */
#define NBSR_LINK2_FHR0    0x6104	/* 4 	Link2 Fault Header Register0 (LNK2_FHR0) */
#define NBSR_LINK2_FHR1    0x6108	/* 4 	Link2 Fault Header Register1 (LNK2_FHR1) */
#define NBSR_LINK2_FHR2    0x610c	/* 4 	Link2 Fault Header Register2 (LNK2_FHR2) */
#define NBSR_LINK2_FHR3    0x6110	/* 4 	Link2 Fault Header Register3 (LNK2_FHR3) */

	/* ������������ ������������� */
#define NBSR_NODE_ID       0x7000	/* 4	NodeId */
#define NBSR_NODE_CFG      0x7004	/* 4	NodeConfig */
#define NBSR_ROUTE_TBL0    0x7010	/* 4	RouteTbl 0 */
#define NBSR_ROUTE_TBL1    0x7014	/* 4	RouteTbl 1 */
#define NBSR_ROUTE_TBL2    0x7018	/* 4	RouteTbl 2 */
#define NBSR_ROUTE_TBL3    0x701c	/* 4	RouteTbl 3  */
#define NBSR_INT_CFG       0x7080	/* 4	Node Interrupt Configuration */
#define NBSR_NODE_CFG_INFO 0x7088	/* 4	Node Config Information */
#define NBSR_JUMPER        0x70b0	/* 4	Node Jumper Register */
# define NBSR_JUMPER_R2000P_JmpIommuMirrorEn (1 << 12)
#define NBSR_NODE_CFG2     0x70b4	/* 4	NodeConfig2 */

/* e90s has only one IO link on each node */
#define	SIC_io_reg_offset(io_link, reg)	((reg))

		/* �������� IOMMU */
#define NBSR_IOMMU_CTRL		0x8000 	/* 4 	IOMMU Control */
#define NBSR_IOMMU_BA		0x8004 	/* 4 	IOMMU Base Address */
#define NBSR_IOMMU_FLUSH_ALL	0x8014 	/* 4 	Flush All TLB Entries */
#define NBSR_IOMMU_FLUSH_ADDR	0x8018 	/* 4 	Flush on Address Match */
		/*0x8100-0x813f*/	/* 4 	IOMMU CAM */
#define NBSR_IOMMU_VA		0x8140 	/* 4 	Virtual Address */
#define NBSR_IOMMU_TLB_COMPR	0x8150 	/* 4 	TLB Comparator */
#define NBSR_IOMMU_FSR		0x8160 	/* 4 	Fault Status Register */
#define NBSR_IOMMU_FAULT_SOURCE_ID 0x8164 /* 4	Fault Source ID.
						Exists at cpu > r2000+ */
#define NBSR_IOMMU_FAH		0x8170 	/* 4 	Fault Address High */
#define NBSR_IOMMU_FAL		0x8174 	/* 4 	Fault Address Low */
		/*0x8200-0x823f*/ 	/* 4 	IOMMU RAM */

#define NBSR_IOMMU_1_OFFSET	(0xA000 - NBSR_IOMMU_CTRL)
#define NBSR_IOMMU_2TO4_OFFSET	(0x400)

#define NBSR_NODE_CFG_CPU_MASK      0xf


#define IOMMU_FSR_MUTIPLE_ERR		(1 << 4) /* ������� ������������� ������ */
#define IOMMU_FSR_MULTIHIT		(1 << 3) /* ������������� ��������� ���������� ����� � IOMMU tlb.*/
#define IOMMU_FSR_WRITE_PROTECTION	(1 << 2) /* ������� ������ � �������� �� ������ �������� */
#define IOMMU_FSR_PAGE_MISS		(1 << 1) /* ���������� ������������ TTE � ������� �������. */
#define IOMMU_FSR_ADDR_RNG_VIOLATION	(1 << 0) /* ������������ �������� ���������*/
						/*(�������� �� �������� � ���������,*/
						/*���������� ��� ���������� �����-������). */
#define IOMMU_FSR_ERR_MASK (IOMMU_FSR_MULTIHIT | IOMMU_FSR_MULTIHIT |	\
		IOMMU_FSR_WRITE_PROTECTION| IOMMU_FSR_PAGE_MISS |	\
		IOMMU_FSR_ADDR_RNG_VIOLATION)

/* FIXME: PREPIC */
#define	SIC_prepic_version	0x8000
#define	SIC_prepic_ctrl		0x8010
#define	SIC_prepic_id		0x8020
#define	SIC_prepic_ctrl2	0x8030
#define	SIC_prepic_err_stat	0x8040
#define	SIC_prepic_err_msg_lo	0x8050
#define	SIC_prepic_err_msg_hi	0x8054
#define	SIC_prepic_err_int	0x8060
#define	SIC_prepic_mcr		0x8070
#define	SIC_prepic_mid		0x8074
#define	SIC_prepic_mar0_lo	0x8080
#define	SIC_prepic_mar0_hi	0x8084
#define	SIC_prepic_mar1_lo	0x8090
#define	SIC_prepic_mar1_hi	0x8094
#define	SIC_prepic_linp		0x8c00

#ifndef __ASSEMBLY__

#define	E90S_LMS_HALT_OK \
({ \
	asm volatile (".word \t0xff680000"); \
})
#define E90S_LMS_HALT_ERROR(err_no) \
({ \
	asm volatile (".word \t0xff680000 | %0" \
			: \
			: "i" (err_no)); \
})

#define IS_MACHINE_HW	1

/*
 * IO links and IO controllers specifications
 * E90S machines use IO links and own chipset.
 * Main IO buses controller is IOHUB.
 */

#ifdef	CONFIG_NUMA

#define	E90S_MAX_NODE_IOLINKS	1	/* each node can has only 1 IO link */
					/* connected to IOHUB or RDMA */
#define	MACH_NODE_NUMIOLINKS	E90S_MAX_NODE_IOLINKS
#define	MACH_MAX_NUMIOLINKS	(E90S_MAX_NODE_IOLINKS * MAX_NUMNODES)
#define mach_early_sic_init()

#else	/* ! CONFIG_NUMA */

#define	E90S_MAX_NODE_IOLINKS	1 /* all IO links are considered */
					  /* as links on single node # 0 */
#define	MACH_NODE_NUMIOLINKS	1
#define	MACH_MAX_NUMIOLINKS	(E90S_MAX_NODE_IOLINKS * MACH_NODE_NUMIOLINKS)
#define mach_early_sic_init()	create_nodes_config()

#endif	/* CONFIG_NUMA */

#define	for_each_iolink_of_node(link)					\
		for ((link) = 0; (link) < MACH_NODE_NUMIOLINKS; (link)++)


static inline unsigned get_cpu_revision(void)
{
#ifdef CONFIG_E90S
	unsigned long ver;
	__asm__ __volatile__("rdpr %%ver, %0" : "=r" (ver));
#endif
	return (ver >> 24) & 0xff;
}

#define	E90S_CPU_R1000		1
#define	E90S_CPU_R2000		2
#define	E90S_CPU_R2000P		3

static inline int e90s_get_cpu_type(void)
{
	unsigned rev = get_cpu_revision();
	if (rev < 0x10)
		return E90S_CPU_R1000;
	else if (rev < 0x20)
		return E90S_CPU_R2000;

	return E90S_CPU_R2000P;
}

#define        E90S_R1000_MAX_NR_NODE_CPUS		4

static inline int e90s_max_nr_node_cpus(void)
{
	switch (e90s_get_cpu_type()) {
	case E90S_CPU_R1000:
		return E90S_R1000_MAX_NR_NODE_CPUS;
	case E90S_CPU_R2000:
		return 16;
	case E90S_CPU_R2000P:
		return 2;
	}
	return 0;
}

static inline bool cpu_has_epic(void)
{
	return e90s_get_cpu_type() >= E90S_CPU_R2000P;
}

static inline bool has_external_iohub(void)
{
	return e90s_get_cpu_type() < E90S_CPU_R2000P;
}


#define	HAS_MACHINE_E90S_SIC		(1)
#define	HAS_MACHINE_E2K_SIC		HAS_MACHINE_E90S_SIC
#define	HAS_MACHINE_E2K_FULL_SIC	HAS_MACHINE_E90S_SIC
#define	HAS_MACHINE_E2K_IOHUB		(1)
#define	HAS_MACHINE_L_SIC		HAS_MACHINE_E90S_SIC
#define	HAS_MACHINE_L_FULL_SIC		HAS_MACHINE_E2K_FULL_SIC
#define	HAS_MACHINE_L_IOHUB		HAS_MACHINE_E2K_IOHUB

extern void flush_locked_tte(void);
extern void smp_synchronize_one_tick(int cpu);
extern long long delta_ticks[];
extern long long do_sync_cpu_clocks;

extern void __init e90s_late_time_init(void);
#endif	/*__ASSEMBLY__*/

#define CYCL_SYNC_GAP_BIT	11
#define CYCL_SYNC_GAP	(1 << CYCL_SYNC_GAP_BIT)

#endif /*_SPARC64_E90_H*/
