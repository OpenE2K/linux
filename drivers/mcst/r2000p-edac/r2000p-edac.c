/*
 * r2000+ processor Error Detection And Correction (EDAC) driver
 * based on drivers/edac/synopsys_edac.c
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/regmap.h>
#include <linux/platform_device.h>
#include <linux/edac.h>
#include "../../edac/edac_module.h"


/* Number of cs_rows needed per memory controller */
#define SYNPS_EDAC_NR_CSROWS		1

/* Number of channels per memory controller */
#define SYNPS_EDAC_NR_CHANS		1

/* Granularity of reported error in bytes */
#define SYNPS_EDAC_ERR_GRAIN		1

#define SYNPS_EDAC_MSG_SIZE		256

#define SYNPS_EDAC_MOD_STRING		"synps_edac"
#define SYNPS_EDAC_MOD_VER		"1"

/* Synopsys DDR memory controller registers that are relevant to ECC */
#define CTRL_OFST			0x0
#define T_ZQ_OFST			0xA4

/* ECC control register */
#define ECC_CTRL_OFST			0xC4
/* ECC log register */
#define CE_LOG_OFST			0xC8
/* ECC address register */
#define CE_ADDR_OFST			0xCC
/* ECC data[31:0] register */
#define CE_DATA_31_0_OFST		0xD0

/* Uncorrectable error info registers */
#define UE_LOG_OFST			0xDC
#define UE_ADDR_OFST			0xE0
#define UE_DATA_31_0_OFST		0xE4

#define STAT_OFST			0xF0
#define SCRUB_OFST			0xF4

/* Control register bit field definitions */
#define CTRL_BW_MASK			0xC
#define CTRL_BW_SHIFT			2

#define DDRCTL_WDTH_16			1
#define DDRCTL_WDTH_32			0

/* ZQ register bit field definitions */
#define T_ZQ_DDRMODE_MASK		0x2

/* ECC control register bit field definitions */
#define ECC_CTRL_CLR_CE_ERR		0x2
#define ECC_CTRL_CLR_UE_ERR		0x1

/* ECC correctable/uncorrectable error log register definitions */
#define LOG_VALID			0x1
#define CE_LOG_BITPOS_MASK		0xFE
#define CE_LOG_BITPOS_SHIFT		1

/* ECC correctable/uncorrectable error address register definitions */
#define ADDR_COL_MASK			0xFFF
#define ADDR_ROW_MASK			0xFFFF000
#define ADDR_ROW_SHIFT			12
#define ADDR_BANK_MASK			0x70000000
#define ADDR_BANK_SHIFT			28

/* ECC statistic register definitions */
#define STAT_UECNT_MASK			0xFF
#define STAT_CECNT_MASK			0xFF00
#define STAT_CECNT_SHIFT		8

/* ECC scrub register definitions */
#define SCRUB_MODE_MASK			0x7
#define SCRUB_MODE_SECDED		0x4

/* DDR ECC Quirks */
#define DDR_ECC_INTR_SUPPORT		BIT(0)
#define DDR_ECC_DATA_POISON_SUPPORT	BIT(1)

/* ZynqMP Enhanced DDR memory controller registers that are relevant to ECC */
/* ECC Configuration Registers */
#define ECC_CFG0_OFST			0x70
#define ECC_CFG1_OFST			0x74

/* ECC Status Register */
#define ECC_STAT_OFST			0x78

/* ECC Clear Register */
#define ECC_CLR_OFST			0x7C

/* ECC Error count Register */
#define ECC_ERRCNT_OFST			0x80

/* ECC Corrected Error Address Register */
#define ECC_CEADDR0_OFST		0x84
#define ECC_CEADDR1_OFST		0x88

/* ECC Syndrome Registers */
#define ECC_CSYND0_OFST			0x8C
#define ECC_CSYND1_OFST			0x90
#define ECC_CSYND2_OFST			0x94

/* ECC Bit Mask0 Address Register */
#define ECC_BITMASK0_OFST		0x98
#define ECC_BITMASK1_OFST		0x9C
#define ECC_BITMASK2_OFST		0xA0

/* ECC UnCorrected Error Address Register */
#define ECC_UEADDR0_OFST		0xA4
#define ECC_UEADDR1_OFST		0xA8

/* ECC Syndrome Registers */
#define ECC_UESYND0_OFST		0xAC
#define ECC_UESYND1_OFST		0xB0
#define ECC_UESYND2_OFST		0xB4

/* ECC Poison Address Reg */
#define ECC_POISON0_OFST		0xB8
#define ECC_POISON1_OFST		0xBC

#define ECC_ADDRMAP0_OFFSET		0x200

/* Control register bitfield definitions */
#define ECC_CTRL_BUSWIDTH_MASK		0x3000
#define ECC_CTRL_BUSWIDTH_SHIFT		12
#define ECC_CTRL_CLR_CE_ERRCNT		BIT(2)
#define ECC_CTRL_CLR_UE_ERRCNT		BIT(3)

/* DDR Control Register width definitions  */
#define DDRCTL_EWDTH_16			2
#define DDRCTL_EWDTH_32			1
#define DDRCTL_EWDTH_64			0

/* ECC status register definitions */
#define ECC_STAT_UECNT_MASK		0xF0000
#define ECC_STAT_UECNT_SHIFT		16
#define ECC_STAT_CECNT_MASK		0xF00
#define ECC_STAT_CECNT_SHIFT		8
#define ECC_STAT_BITNUM_MASK		0x7F

/* DDR QOS Interrupt register definitions */
#define DDR_QOS_IRQ_STAT_OFST		0x20200
#define DDR_QOSUE_MASK			0x4
#define	DDR_QOSCE_MASK			0x2
#define	ECC_CE_UE_INTR_MASK		0x6
#define DDR_QOS_IRQ_EN_OFST		0x20208
#define DDR_QOS_IRQ_DB_OFST		0x2020C

/* ECC Corrected Error Register Mask and Shifts*/
#define ECC_CEADDR0_RW_MASK		0x3FFFF
#define ECC_CEADDR0_RNK_MASK		BIT(24)
#define ECC_CEADDR1_BNKGRP_MASK		0x3000000
#define ECC_CEADDR1_BNKNR_MASK		0x70000
#define ECC_CEADDR1_BLKNR_MASK		0xFFF
#define ECC_CEADDR1_BNKGRP_SHIFT	24
#define ECC_CEADDR1_BNKNR_SHIFT		16

/* ECC Poison register shifts */
#define ECC_POISON0_RANK_SHIFT		24
#define ECC_POISON0_RANK_MASK		BIT(24)
#define ECC_POISON0_COLUMN_SHIFT	0
#define ECC_POISON0_COLUMN_MASK		0xFFF
#define ECC_POISON1_BG_SHIFT		28
#define ECC_POISON1_BG_MASK		0x30000000
#define ECC_POISON1_BANKNR_SHIFT	24
#define ECC_POISON1_BANKNR_MASK		0x7000000
#define ECC_POISON1_ROW_SHIFT		0
#define ECC_POISON1_ROW_MASK		0x3FFFF

/* DDR Memory type defines */
#define MEM_TYPE_DDR3			0x1
#define MEM_TYPE_LPDDR3			0x8
#define MEM_TYPE_DDR2			0x4
#define MEM_TYPE_DDR4			0x10
#define MEM_TYPE_LPDDR4			0x20

/* DDRC Software control register */
#define DDRC_SWCTL			0x320

/* DDRC ECC CE & UE poison mask */
#define ECC_CEPOISON_MASK		0x3
#define ECC_UEPOISON_MASK		0x1

/* DDRC Device config masks */
#define DDRC_MSTR_CFG_MASK		0xC0000000
#define DDRC_MSTR_CFG_SHIFT		30
#define DDRC_MSTR_CFG_X4_MASK		0x0
#define DDRC_MSTR_CFG_X8_MASK		0x1
#define DDRC_MSTR_CFG_X16_MASK		0x2
#define DDRC_MSTR_CFG_X32_MASK		0x3

#define DDR_MAX_ROW_SHIFT		18
#define DDR_MAX_COL_SHIFT		14
#define DDR_MAX_BANK_SHIFT		3
#define DDR_MAX_BANKGRP_SHIFT		2

#define ROW_MAX_VAL_MASK		0xF
#define COL_MAX_VAL_MASK		0xF
#define BANK_MAX_VAL_MASK		0x1F
#define BANKGRP_MAX_VAL_MASK		0x1F
#define RANK_MAX_VAL_MASK		0x1F

#define ROW_B0_BASE			6
#define ROW_B1_BASE			7
#define ROW_B2_BASE			8
#define ROW_B3_BASE			9
#define ROW_B4_BASE			10
#define ROW_B5_BASE			11
#define ROW_B6_BASE			12
#define ROW_B7_BASE			13
#define ROW_B8_BASE			14
#define ROW_B9_BASE			15
#define ROW_B10_BASE			16
#define ROW_B11_BASE			17
#define ROW_B12_BASE			18
#define ROW_B13_BASE			19
#define ROW_B14_BASE			20
#define ROW_B15_BASE			21
#define ROW_B16_BASE			22
#define ROW_B17_BASE			23

#define COL_B2_BASE			2
#define COL_B3_BASE			3
#define COL_B4_BASE			4
#define COL_B5_BASE			5
#define COL_B6_BASE			6
#define COL_B7_BASE			7
#define COL_B8_BASE			8
#define COL_B9_BASE			9
#define COL_B10_BASE			10
#define COL_B11_BASE			11
#define COL_B12_BASE			12
#define COL_B13_BASE			13

#define BANK_B0_BASE			2
#define BANK_B1_BASE			3
#define BANK_B2_BASE			4

#define BANKGRP_B0_BASE			2
#define BANKGRP_B1_BASE			3

#define RANK_B0_BASE			6

/**
 * struct ecc_error_info - ECC error log information.
 * @row:	Row number.
 * @col:	Column number.
 * @bank:	Bank number.
 * @bitpos:	Bit position.
 * @data:	Data causing the error.
 * @bankgrpnr:	Bank group number.
 * @blknr:	Block number.
 */
struct ecc_error_info {
	u32 row;
	u32 col;
	u32 bank;
	u32 bitpos;
	u32 data;
	u32 bankgrpnr;
	u32 blknr;
};

/**
 * struct synps_ecc_status - ECC status information to report.
 * @ce_cnt:	Correctable error count.
 * @ue_cnt:	Uncorrectable error count.
 * @ceinfo:	Correctable error log information.
 * @ueinfo:	Uncorrectable error log information.
 */
struct synps_ecc_status {
	u32 ce_cnt;
	u32 ue_cnt;
	struct ecc_error_info ceinfo;
	struct ecc_error_info ueinfo;
};

/**
 * struct r2000p_edac - DDR memory controller private instance data.
 * @baseaddr:		Base address of the DDR controller.
 * @message:		Buffer for framing the event specific info.
 * @stat:		ECC status information.
 * @p_data:		Platform data.
 * @ce_cnt:		Correctable Error count.
 * @ue_cnt:		Uncorrectable Error count.
 * @poison_addr:	Data poison address.
 * @row_shift:		Bit shifts for row bit.
 * @col_shift:		Bit shifts for column bit.
 * @bank_shift:		Bit shifts for bank bit.
 * @bankgrp_shift:	Bit shifts for bank group bit.
 * @rank_shift:		Bit shifts for rank bit.
 */
struct r2000p_edac {
	struct msix_entry msix_entry;
	struct regmap *rm;
	char message[SYNPS_EDAC_MSG_SIZE];
	struct synps_ecc_status stat;
	const struct synps_platform_data *p_data;
	u32 ce_cnt;
	u32 ue_cnt;
#ifdef CONFIG_EDAC_DEBUG
	ulong poison_addr;
	u32 row_shift[18];
	u32 col_shift[14];
	u32 bank_shift[3];
	u32 bankgrp_shift[2];
	u32 rank_shift[1];
#endif
};

#define MC_DDR_PHY_REGISTER_ADDRESS	0
#define MC_REGISTER_DATA		4
#define MC_DDR_PHY_CONTROL		0xc

static int r2000p_mc_reg_read(void *context, unsigned reg,
				  unsigned *result)
{
	nbsr_writel(reg, MC_DDR_PHY_REGISTER_ADDRESS, 0);
	*result = nbsr_readl(MC_REGISTER_DATA, 0);
	return 0;
}

static int r2000p_mc_reg_write(void *context, unsigned reg,
				  unsigned value)
{
	nbsr_writel(reg, MC_DDR_PHY_REGISTER_ADDRESS, 0);
	nbsr_writel(value, MC_REGISTER_DATA, 0);
	return 0;
}


static const struct regmap_range r2000p_mc_no_reg_ranges[] = {
	regmap_reg_range(0xc, 0xc),
	regmap_reg_range(0x28, 0x28),
	regmap_reg_range(0x5c, 0x5c),
	regmap_reg_range(0x6c, 0x6c),
	regmap_reg_range(0xc8, 0xc8),
	regmap_reg_range(0xf8, 0xfc),
	regmap_reg_range(0x140, 0x140),
	regmap_reg_range(0x3f4, 0x3f8),
	regmap_reg_range(0xff8, 0x11b0),
	regmap_reg_range(0x1ef4, 0x201c),
	regmap_reg_range(0x2428, 0x301c),
	regmap_reg_range(0x33e0, 0x401c),

	regmap_reg_range(0x148, 0x14c),
	regmap_reg_range(0x154, 0x17c),
	regmap_reg_range(0x1ac, 0x1ac),  regmap_reg_range(0x1c8, 0x1fc),
	regmap_reg_range(0x230, 0x23c),
	regmap_reg_range(0x248, 0x24c),
	regmap_reg_range(0x258, 0x260),
	regmap_reg_range(0x268, 0x2fc),
	regmap_reg_range(0x314, 0x31c),
	regmap_reg_range(0x32c, 0x368),
	regmap_reg_range(0x378, 0x378),  regmap_reg_range(0x388, 0x3ec),
	regmap_reg_range(0x40c, 0x48c),
	regmap_reg_range(0x4a4, 0x4b0),
	regmap_reg_range(0x4bc, 0x53c),
	regmap_reg_range(0x554, 0x5ec),
	regmap_reg_range(0x604, 0x610),
	regmap_reg_range(0x61c, 0x69c),
	regmap_reg_range(0x6b4, 0x6c0),
	regmap_reg_range(0x6cc, 0x74c),
	regmap_reg_range(0x764, 0x770),
	regmap_reg_range(0x77c, 0x7fc),
	regmap_reg_range(0x814, 0x820),
	regmap_reg_range(0x82c, 0x8ac),
	regmap_reg_range(0x8c4, 0x8d0),
	regmap_reg_range(0x8dc, 0x95c),
	regmap_reg_range(0x974, 0x980),
	regmap_reg_range(0x98c, 0xa0c),
	regmap_reg_range(0xa24, 0xa30),
	regmap_reg_range(0xa3c, 0xabc),
	regmap_reg_range(0xad4, 0xf20),
	regmap_reg_range(0xf34, 0xf34),  regmap_reg_range(0xf48, 0xfec),
	regmap_reg_range(0x11b4, 0x1ef0),
	regmap_reg_range(0x2028, 0x2030),
	regmap_reg_range(0x2038, 0x2040),
	regmap_reg_range(0x2054, 0x2060),
	regmap_reg_range(0x206c, 0x20d8),
	regmap_reg_range(0x20e4, 0x20e4), regmap_reg_range(0x20f0, 0x20f0),
	regmap_reg_range(0x20f8, 0x20fc),
	regmap_reg_range(0x2140, 0x2140), regmap_reg_range(0x2148, 0x214c),
	regmap_reg_range(0x2154, 0x217c),
	regmap_reg_range(0x2184, 0x218c),
	regmap_reg_range(0x2198, 0x21b0),
	regmap_reg_range(0x21bc, 0x223c),
	regmap_reg_range(0x2244, 0x23cc),
	regmap_reg_range(0x23e0, 0x2424),
	regmap_reg_range(0x3020, 0x33dc),
	regmap_reg_range(0x4028, 0x4028), regmap_reg_range(0x405c, 0x405c),
	regmap_reg_range(0x406c, 0x40c8),
	regmap_reg_range(0x40f8, 0x40fc),
	regmap_reg_range(0x4140, 0x4140), regmap_reg_range(0x4148, 0x414c),
	regmap_reg_range(0x4154, 0x417c),
	regmap_reg_range(0x41ac, 0x41ac), regmap_reg_range(0x41c8, 0x41fc),
	regmap_reg_range(0x4230, 0x423c),
	regmap_reg_range(0x4248, 0x424c),
	regmap_reg_range(0x4258, 0x4258), regmap_reg_range(0x4260, 0x4260),
	regmap_reg_range(0x4268, 0x4268), regmap_reg_range(0x4270, 0x42fc),
	regmap_reg_range(0x4314, 0x431c),
	regmap_reg_range(0x432c, 0x4368),
	regmap_reg_range(0x4378, 0x4378),
	regmap_reg_range(0x4388, 0x4388),
	regmap_reg_range(0x438c, 0x438c),
	regmap_reg_range(0x4390, 0x4390),
	regmap_reg_range(0x4394, 0x4394),
	regmap_reg_range(0x4398, 0x4398),
	regmap_reg_range(0x439c, 0x439c),
	regmap_reg_range(0x43a0, 0x43a0),
	regmap_reg_range(0x43a4, 0x43a4),
	regmap_reg_range(0x43a8, 0x43a8),
	regmap_reg_range(0x43ac, 0x43ac),
	regmap_reg_range(0x43b0, 0x43b0),
	regmap_reg_range(0x43b4, 0x43b4),
	regmap_reg_range(0x43b8, 0x43b8),
	regmap_reg_range(0x43bc, 0x43bc),
	regmap_reg_range(0x43c0, 0x43c0),
	regmap_reg_range(0x43c4, 0x43c4),
	regmap_reg_range(0x43c8, 0x43c8),
	regmap_reg_range(0x43cc, 0x43cc),
};

static const struct regmap_access_table r2000p_mc_no_reg_table = {
	.no_ranges = r2000p_mc_no_reg_ranges,
	.n_no_ranges = ARRAY_SIZE(r2000p_mc_no_reg_ranges),
};

static const struct regmap_config r2000p_mc_regmap_config = {
	.name = "mc-regs",
	.reg_bits	= 32,
	.val_bits	= 32,
	.reg_stride	= 4,
	.max_register	= 0x43dc,
	.fast_io = true,

	.reg_read = r2000p_mc_reg_read,
	.reg_write = r2000p_mc_reg_write,
	.rd_table	= &r2000p_mc_no_reg_table,
	.wr_table	= &r2000p_mc_no_reg_table,
};

#define edac_rd(__off)				\
({						\
	u32 __v;				\
	regmap_read(rdc->rm, __off, &__v);	\
	__v;				\
})

#define edac_wr(_v, __off) do {			\
	u32 __v = _v;				\
	regmap_write(rdc->rm, __off, __v);	\
} while (0)

/**
 * r2000p_get_error_info - Get the current ECC error info.
 * @rdc:	DDR memory controller private instance data.
 *
 * Return: one if there is no error otherwise returns zero.
 */
static int r2000p_get_error_info(struct r2000p_edac *rdc)
{
	struct synps_ecc_status *p;
	u32 regval, clearval = 0;

	p = &rdc->stat;

	regval = edac_rd(ECC_STAT_OFST);
	if (!regval)
		return 1;
	p->ce_cnt = (regval & ECC_STAT_CECNT_MASK) >> ECC_STAT_CECNT_SHIFT;
	p->ue_cnt = (regval & ECC_STAT_UECNT_MASK) >> ECC_STAT_UECNT_SHIFT;
	if (!p->ce_cnt)
		goto ue_err;

	p->ceinfo.bitpos = (regval & ECC_STAT_BITNUM_MASK);

	regval = edac_rd(ECC_CEADDR0_OFST);
	p->ceinfo.row = (regval & ECC_CEADDR0_RW_MASK);
	regval = edac_rd(ECC_CEADDR1_OFST);
	p->ceinfo.bank = (regval & ECC_CEADDR1_BNKNR_MASK) >>
					ECC_CEADDR1_BNKNR_SHIFT;
	p->ceinfo.bankgrpnr = (regval &	ECC_CEADDR1_BNKGRP_MASK) >>
					ECC_CEADDR1_BNKGRP_SHIFT;
	p->ceinfo.blknr = (regval & ECC_CEADDR1_BLKNR_MASK);
	p->ceinfo.data = edac_rd(ECC_CSYND0_OFST);
	edac_dbg(2, "ECCCSYN0: 0x%08X ECCCSYN1: 0x%08X ECCCSYN2: 0x%08X\n",
		 edac_rd(ECC_CSYND0_OFST), edac_rd(ECC_CSYND1_OFST),
		 edac_rd(ECC_CSYND2_OFST));
ue_err:
	if (!p->ue_cnt)
		goto out;

	regval = edac_rd(ECC_UEADDR0_OFST);
	p->ueinfo.row = (regval & ECC_CEADDR0_RW_MASK);
	regval = edac_rd(ECC_UEADDR1_OFST);
	p->ueinfo.bankgrpnr = (regval & ECC_CEADDR1_BNKGRP_MASK) >>
					ECC_CEADDR1_BNKGRP_SHIFT;
	p->ueinfo.bank = (regval & ECC_CEADDR1_BNKNR_MASK) >>
					ECC_CEADDR1_BNKNR_SHIFT;
	p->ueinfo.blknr = (regval & ECC_CEADDR1_BLKNR_MASK);
	p->ueinfo.data = edac_rd(ECC_UESYND0_OFST);
out:
	clearval = edac_rd(ECC_CLR_OFST);
	clearval |= ECC_CTRL_CLR_CE_ERR | ECC_CTRL_CLR_CE_ERRCNT;
	clearval |= ECC_CTRL_CLR_UE_ERR | ECC_CTRL_CLR_UE_ERRCNT;
	edac_wr(clearval, ECC_CLR_OFST);

	return 0;
}

/**
 * handle_error - Handle Correctable and Uncorrectable errors.
 * @mci:	EDAC memory controller instance.
 * @p:		Synopsys ECC status structure.
 *
 * Handles ECC correctable and uncorrectable errors.
 */
static void handle_error(struct mem_ctl_info *mci, struct synps_ecc_status *p)
{
	struct r2000p_edac *rdc = mci->pvt_info;
	struct ecc_error_info *pinf;

	if (p->ce_cnt) {
		pinf = &p->ceinfo;
		snprintf(rdc->message, SYNPS_EDAC_MSG_SIZE,
				"DDR ECC error type:%s Row %d Bank %d Col %d BankGroup Number %d Block Number %d Bit Position: %d Data: 0x%08x",
				"CE", pinf->row, pinf->bank, pinf->col,
				pinf->bankgrpnr, pinf->blknr,
				pinf->bitpos, pinf->data);
		edac_mc_handle_error(HW_EVENT_ERR_CORRECTED, mci,
				     p->ce_cnt, 0, 0, 0, 0, 0, -1,
				     rdc->message, "");
	}

	if (p->ue_cnt) {
		pinf = &p->ueinfo;
		snprintf(rdc->message, SYNPS_EDAC_MSG_SIZE,
				"DDR ECC error type :%s Row %d Bank %d Col %d BankGroup Number %d Block Number %d",
				"UE", pinf->row, pinf->bank, pinf->col,
				pinf->bankgrpnr, pinf->blknr);
		edac_mc_handle_error(HW_EVENT_ERR_UNCORRECTED, mci,
				     p->ue_cnt, 0, 0, 0, 0, 0, -1,
				     rdc->message, "");
	}

	memset(p, 0, sizeof(*p));
}

/**
 * intr_handler - Interrupt Handler for ECC interrupts.
 * @irq:        IRQ number.
 * @dev_id:     Device ID.
 *
 * Return: IRQ_NONE, if interrupt not set or IRQ_HANDLED otherwise.
 */
static irqreturn_t intr_handler(int irq, void *dev_id)
{
	const struct synps_platform_data *p_data;
	struct mem_ctl_info *mci = dev_id;
	struct r2000p_edac *rdc;
	int status;

	rdc = mci->pvt_info;
	p_data = rdc->p_data;

	status = r2000p_get_error_info(rdc);
	if (status)
		return IRQ_NONE;

	rdc->ce_cnt += rdc->stat.ce_cnt;
	rdc->ue_cnt += rdc->stat.ue_cnt;
	handle_error(mci, &rdc->stat);

	edac_dbg(3, "Total error count CE %d UE %d\n",
		 rdc->ce_cnt, rdc->ue_cnt);

	return IRQ_HANDLED;
}
/**
 * r2000p_get_dtype - Return the controller memory width.
 * @base:	DDR memory controller base address.
 *
 * Get the EDAC device type width appropriate for the current controller
 * configuration.
 *
 * Return: a device type width enumeration.
 */
static enum dev_type r2000p_get_dtype(struct r2000p_edac *rdc)
{
	enum dev_type dt;
	u32 width;

	width = edac_rd(CTRL_OFST);
	width = (width & ECC_CTRL_BUSWIDTH_MASK) >> ECC_CTRL_BUSWIDTH_SHIFT;
	switch (width) {
	case DDRCTL_EWDTH_16:
		dt = DEV_X2;
		break;
	case DDRCTL_EWDTH_32:
		dt = DEV_X4;
		break;
	case DDRCTL_EWDTH_64:
		dt = DEV_X8;
		break;
	default:
		dt = DEV_UNKNOWN;
	}

	return dt;
}

/**
 * r2000p_get_ecc_state - Return the controller ECC enable/disable status.
 * @base:	DDR memory controller base address.
 *
 * Get the ECC enable/disable status for the controller.
 *
 * Return: a ECC status boolean i.e true/false - enabled/disabled.
 */
static bool r2000p_get_ecc_state(struct r2000p_edac *rdc)
{
	enum dev_type dt;
	u32 ecctype;

	dt = r2000p_get_dtype(rdc);
	if (dt == DEV_UNKNOWN)
		return false;

	ecctype = edac_rd(ECC_CFG0_OFST) & SCRUB_MODE_MASK;
	if ((ecctype == SCRUB_MODE_SECDED) &&
	    ((dt == DEV_X2) || (dt == DEV_X4) || (dt == DEV_X8)))
		return true;

	return false;
}

/**
 * get_memsize - Read the size of the attached memory device.
 *
 * Return: the memory size in bytes.
 */
static u32 get_memsize(void)
{
	struct sysinfo inf;

	si_meminfo(&inf);

	return inf.totalram * inf.mem_unit;
}

/**
 * r2000p_get_mtype - Returns controller memory type.
 * @base:	Synopsys ECC status structure.
 *
 * Get the EDAC memory type appropriate for the current controller
 * configuration.
 *
 * Return: a memory type enumeration.
 */
static enum mem_type r2000p_get_mtype(struct r2000p_edac *rdc)
{
	enum mem_type mt;
	u32 memtype;

	memtype = edac_rd(CTRL_OFST);

	if ((memtype & MEM_TYPE_DDR3) || (memtype & MEM_TYPE_LPDDR3))
		mt = MEM_DDR3;
	else if (memtype & MEM_TYPE_DDR2)
		mt = MEM_RDDR2;
	else if ((memtype & MEM_TYPE_LPDDR4) || (memtype & MEM_TYPE_DDR4))
		mt = MEM_DDR4;
	else
		mt = MEM_EMPTY;

	return mt;
}

/**
 * init_csrows - Initialize the csrow data.
 * @mci:	EDAC memory controller instance.
 *
 * Initialize the chip select rows associated with the EDAC memory
 * controller instance.
 */
static void init_csrows(struct mem_ctl_info *mci)
{
	struct r2000p_edac *rdc = mci->pvt_info;
	const struct synps_platform_data *p_data;
	struct csrow_info *csi;
	struct dimm_info *dimm;
	u32 size, row;
	int j;

	p_data = rdc->p_data;

	for (row = 0; row < mci->nr_csrows; row++) {
		csi = mci->csrows[row];
		size = get_memsize();

		for (j = 0; j < csi->nr_channels; j++) {
			dimm		= csi->channels[j]->dimm;
			dimm->edac_mode	= EDAC_SECDED;
			dimm->mtype	= r2000p_get_mtype(rdc);
			dimm->nr_pages	= (size >> PAGE_SHIFT) / csi->nr_channels;
			dimm->grain	= SYNPS_EDAC_ERR_GRAIN;
			dimm->dtype	= r2000p_get_dtype(rdc);
		}
	}
}

/**
 * mc_init - Initialize one driver instance.
 * @mci:	EDAC memory controller instance.
 * @pdev:	platform device.
 *
 * Perform initialization of the EDAC memory controller instance and
 * related driver-private data associated with the memory controller the
 * instance is bound to.
 */
static void mc_init(struct mem_ctl_info *mci, struct device *dev)
{
	mci->pdev = dev;
	dev_set_drvdata(dev, mci);

	/* Initialize controller capabilities and configuration */
	mci->mtype_cap = MEM_FLAG_DDR3 | MEM_FLAG_DDR2;
	mci->edac_ctl_cap = EDAC_FLAG_NONE | EDAC_FLAG_SECDED;
	mci->scrub_cap = SCRUB_HW_SRC;
	mci->scrub_mode = SCRUB_NONE;

	mci->edac_cap = EDAC_FLAG_SECDED;
	mci->ctl_name = "synps_ddr_controller";
	mci->dev_name = SYNPS_EDAC_MOD_STRING;
	mci->mod_name = SYNPS_EDAC_MOD_VER;

	edac_op_state = EDAC_OPSTATE_INT;

	mci->ctl_page_to_phys = NULL;

	init_csrows(mci);
}

#ifdef CONFIG_EDAC_DEBUG
#define to_mci(k) container_of(k, struct mem_ctl_info, dev)

/**
 * ddr_poison_setup -	Update poison registers.
 * @rdc:		DDR memory controller private instance data.
 *
 * Update poison registers as per DDR mapping.
 * Return: none.
 */
static void ddr_poison_setup(struct r2000p_edac *rdc)
{
	int col = 0, row = 0, bank = 0, bankgrp = 0, rank = 0, regval;
	int index;
	ulong hif_addr = 0;

	hif_addr = rdc->poison_addr >> 3;

	for (index = 0; index < DDR_MAX_ROW_SHIFT; index++) {
		if (rdc->row_shift[index])
			row |= (((hif_addr >> rdc->row_shift[index]) &
						BIT(0)) << index);
		else
			break;
	}

	for (index = 0; index < DDR_MAX_COL_SHIFT; index++) {
		if (rdc->col_shift[index] || index < 3)
			col |= (((hif_addr >> rdc->col_shift[index]) &
						BIT(0)) << index);
		else
			break;
	}

	for (index = 0; index < DDR_MAX_BANK_SHIFT; index++) {
		if (rdc->bank_shift[index])
			bank |= (((hif_addr >> rdc->bank_shift[index]) &
						BIT(0)) << index);
		else
			break;
	}

	for (index = 0; index < DDR_MAX_BANKGRP_SHIFT; index++) {
		if (rdc->bankgrp_shift[index])
			bankgrp |= (((hif_addr >> rdc->bankgrp_shift[index])
						& BIT(0)) << index);
		else
			break;
	}

	if (rdc->rank_shift[0])
		rank = (hif_addr >> rdc->rank_shift[0]) & BIT(0);

	regval = (rank << ECC_POISON0_RANK_SHIFT) & ECC_POISON0_RANK_MASK;
	regval |= (col << ECC_POISON0_COLUMN_SHIFT) & ECC_POISON0_COLUMN_MASK;
	edac_wr(regval, ECC_POISON0_OFST);

	regval = (bankgrp << ECC_POISON1_BG_SHIFT) & ECC_POISON1_BG_MASK;
	regval |= (bank << ECC_POISON1_BANKNR_SHIFT) & ECC_POISON1_BANKNR_MASK;
	regval |= (row << ECC_POISON1_ROW_SHIFT) & ECC_POISON1_ROW_MASK;
	edac_wr(regval, ECC_POISON1_OFST);
}

static ssize_t inject_data_error_show(struct device *dev,
				      struct device_attribute *mattr,
				      char *data)
{
	struct mem_ctl_info *mci = to_mci(dev);
	struct r2000p_edac *rdc = mci->pvt_info;

	return sprintf(data, "Poison0 Addr: 0x%08x\n\rPoison1 Addr: 0x%08x\n\r"
			"Error injection Address: 0x%lx\n\r",
			edac_rd(ECC_POISON0_OFST),
			edac_rd(ECC_POISON1_OFST),
			rdc->poison_addr);
}

static ssize_t inject_data_error_store(struct device *dev,
				       struct device_attribute *mattr,
				       const char *data, size_t count)
{
	struct mem_ctl_info *mci = to_mci(dev);
	struct r2000p_edac *rdc = mci->pvt_info;

	if (kstrtoul(data, 0, &rdc->poison_addr))
		return -EINVAL;

	ddr_poison_setup(rdc);

	return count;
}

static ssize_t inject_data_poison_show(struct device *dev,
				       struct device_attribute *mattr,
				       char *data)
{
	struct mem_ctl_info *mci = to_mci(dev);
	struct r2000p_edac *rdc = mci->pvt_info;
	u32 v = edac_rd(ECC_CFG1_OFST) & 0x3;
	return sprintf(data, "Data Poisoning: %s\n\r",
			v == 0x3 ? "Correctable Error" :
			v == 0x1 ? "UnCorrectable Error" : "Off");
}

static ssize_t inject_data_poison_store(struct device *dev,
					struct device_attribute *mattr,
					const char *data, size_t count)
{
	struct mem_ctl_info *mci = to_mci(dev);
	struct r2000p_edac *rdc = mci->pvt_info;

	edac_wr(0, DDRC_SWCTL);
	if (strncmp(data, "CE", 2) == 0)
		edac_wr(ECC_CEPOISON_MASK, ECC_CFG1_OFST);
	else if (strncmp(data, "UE", 2) == 0)
		edac_wr(ECC_CEPOISON_MASK, ECC_CFG1_OFST);
	else
		edac_wr(0, ECC_CFG1_OFST);

	edac_wr(1, DDRC_SWCTL);

	return count;
}

static DEVICE_ATTR_RW(inject_data_error);
static DEVICE_ATTR_RW(inject_data_poison);

static int edac_create_sysfs_attributes(struct mem_ctl_info *mci)
{
	int rc;

	rc = device_create_file(&mci->dev, &dev_attr_inject_data_error);
	if (rc < 0)
		return rc;
	rc = device_create_file(&mci->dev, &dev_attr_inject_data_poison);
	if (rc < 0)
		return rc;
	return 0;
}

static void edac_remove_sysfs_attributes(struct mem_ctl_info *mci)
{
	device_remove_file(&mci->dev, &dev_attr_inject_data_error);
	device_remove_file(&mci->dev, &dev_attr_inject_data_poison);
}

static void setup_row_address_map(struct r2000p_edac *rdc, u32 *addrmap)
{
	u32 addrmap_row_b2_10;
	int index;

	rdc->row_shift[0] = (addrmap[5] & ROW_MAX_VAL_MASK) + ROW_B0_BASE;
	rdc->row_shift[1] = ((addrmap[5] >> 8) &
			ROW_MAX_VAL_MASK) + ROW_B1_BASE;

	addrmap_row_b2_10 = (addrmap[5] >> 16) & ROW_MAX_VAL_MASK;
	if (addrmap_row_b2_10 != ROW_MAX_VAL_MASK) {
		for (index = 2; index < 11; index++)
			rdc->row_shift[index] = addrmap_row_b2_10 +
				index + ROW_B0_BASE;

	} else {
		rdc->row_shift[2] = (addrmap[9] &
				ROW_MAX_VAL_MASK) + ROW_B2_BASE;
		rdc->row_shift[3] = ((addrmap[9] >> 8) &
				ROW_MAX_VAL_MASK) + ROW_B3_BASE;
		rdc->row_shift[4] = ((addrmap[9] >> 16) &
				ROW_MAX_VAL_MASK) + ROW_B4_BASE;
		rdc->row_shift[5] = ((addrmap[9] >> 24) &
				ROW_MAX_VAL_MASK) + ROW_B5_BASE;
		rdc->row_shift[6] = (addrmap[10] &
				ROW_MAX_VAL_MASK) + ROW_B6_BASE;
		rdc->row_shift[7] = ((addrmap[10] >> 8) &
				ROW_MAX_VAL_MASK) + ROW_B7_BASE;
		rdc->row_shift[8] = ((addrmap[10] >> 16) &
				ROW_MAX_VAL_MASK) + ROW_B8_BASE;
		rdc->row_shift[9] = ((addrmap[10] >> 24) &
				ROW_MAX_VAL_MASK) + ROW_B9_BASE;
		rdc->row_shift[10] = (addrmap[11] &
				ROW_MAX_VAL_MASK) + ROW_B10_BASE;
	}

	rdc->row_shift[11] = (((addrmap[5] >> 24) & ROW_MAX_VAL_MASK) ==
				ROW_MAX_VAL_MASK) ? 0 : (((addrmap[5] >> 24) &
				ROW_MAX_VAL_MASK) + ROW_B11_BASE);
	rdc->row_shift[12] = ((addrmap[6] & ROW_MAX_VAL_MASK) ==
				ROW_MAX_VAL_MASK) ? 0 : ((addrmap[6] &
				ROW_MAX_VAL_MASK) + ROW_B12_BASE);
	rdc->row_shift[13] = (((addrmap[6] >> 8) & ROW_MAX_VAL_MASK) ==
				ROW_MAX_VAL_MASK) ? 0 : (((addrmap[6] >> 8) &
				ROW_MAX_VAL_MASK) + ROW_B13_BASE);
	rdc->row_shift[14] = (((addrmap[6] >> 16) & ROW_MAX_VAL_MASK) ==
				ROW_MAX_VAL_MASK) ? 0 : (((addrmap[6] >> 16) &
				ROW_MAX_VAL_MASK) + ROW_B14_BASE);
	rdc->row_shift[15] = (((addrmap[6] >> 24) & ROW_MAX_VAL_MASK) ==
				ROW_MAX_VAL_MASK) ? 0 : (((addrmap[6] >> 24) &
				ROW_MAX_VAL_MASK) + ROW_B15_BASE);
	rdc->row_shift[16] = ((addrmap[7] & ROW_MAX_VAL_MASK) ==
				ROW_MAX_VAL_MASK) ? 0 : ((addrmap[7] &
				ROW_MAX_VAL_MASK) + ROW_B16_BASE);
	rdc->row_shift[17] = (((addrmap[7] >> 8) & ROW_MAX_VAL_MASK) ==
				ROW_MAX_VAL_MASK) ? 0 : (((addrmap[7] >> 8) &
				ROW_MAX_VAL_MASK) + ROW_B17_BASE);
}

static void setup_column_address_map(struct r2000p_edac *rdc, u32 *addrmap)
{
	u32 width, memtype;
	int index;

	memtype = edac_rd(CTRL_OFST);
	width = (memtype & ECC_CTRL_BUSWIDTH_MASK) >> ECC_CTRL_BUSWIDTH_SHIFT;

	rdc->col_shift[0] = 0;
	rdc->col_shift[1] = 1;
	rdc->col_shift[2] = (addrmap[2] & COL_MAX_VAL_MASK) + COL_B2_BASE;
	rdc->col_shift[3] = ((addrmap[2] >> 8) &
			COL_MAX_VAL_MASK) + COL_B3_BASE;
	rdc->col_shift[4] = (((addrmap[2] >> 16) & COL_MAX_VAL_MASK) ==
			COL_MAX_VAL_MASK) ? 0 : (((addrmap[2] >> 16) &
					COL_MAX_VAL_MASK) + COL_B4_BASE);
	rdc->col_shift[5] = (((addrmap[2] >> 24) & COL_MAX_VAL_MASK) ==
			COL_MAX_VAL_MASK) ? 0 : (((addrmap[2] >> 24) &
					COL_MAX_VAL_MASK) + COL_B5_BASE);
	rdc->col_shift[6] = ((addrmap[3] & COL_MAX_VAL_MASK) ==
			COL_MAX_VAL_MASK) ? 0 : ((addrmap[3] &
					COL_MAX_VAL_MASK) + COL_B6_BASE);
	rdc->col_shift[7] = (((addrmap[3] >> 8) & COL_MAX_VAL_MASK) ==
			COL_MAX_VAL_MASK) ? 0 : (((addrmap[3] >> 8) &
					COL_MAX_VAL_MASK) + COL_B7_BASE);
	rdc->col_shift[8] = (((addrmap[3] >> 16) & COL_MAX_VAL_MASK) ==
			COL_MAX_VAL_MASK) ? 0 : (((addrmap[3] >> 16) &
					COL_MAX_VAL_MASK) + COL_B8_BASE);
	rdc->col_shift[9] = (((addrmap[3] >> 24) & COL_MAX_VAL_MASK) ==
			COL_MAX_VAL_MASK) ? 0 : (((addrmap[3] >> 24) &
					COL_MAX_VAL_MASK) + COL_B9_BASE);
	if (width == DDRCTL_EWDTH_64) {
		if (memtype & MEM_TYPE_LPDDR3) {
			rdc->col_shift[10] = ((addrmap[4] &
				COL_MAX_VAL_MASK) == COL_MAX_VAL_MASK) ? 0 :
				((addrmap[4] & COL_MAX_VAL_MASK) +
				 COL_B10_BASE);
			rdc->col_shift[11] = (((addrmap[4] >> 8) &
				COL_MAX_VAL_MASK) == COL_MAX_VAL_MASK) ? 0 :
				(((addrmap[4] >> 8) & COL_MAX_VAL_MASK) +
				 COL_B11_BASE);
		} else {
			rdc->col_shift[11] = ((addrmap[4] &
				COL_MAX_VAL_MASK) == COL_MAX_VAL_MASK) ? 0 :
				((addrmap[4] & COL_MAX_VAL_MASK) +
				 COL_B10_BASE);
			rdc->col_shift[13] = (((addrmap[4] >> 8) &
				COL_MAX_VAL_MASK) == COL_MAX_VAL_MASK) ? 0 :
				(((addrmap[4] >> 8) & COL_MAX_VAL_MASK) +
				 COL_B11_BASE);
		}
	} else if (width == DDRCTL_EWDTH_32) {
		if (memtype & MEM_TYPE_LPDDR3) {
			rdc->col_shift[10] = (((addrmap[3] >> 24) &
				COL_MAX_VAL_MASK) == COL_MAX_VAL_MASK) ? 0 :
				(((addrmap[3] >> 24) & COL_MAX_VAL_MASK) +
				 COL_B9_BASE);
			rdc->col_shift[11] = ((addrmap[4] &
				COL_MAX_VAL_MASK) == COL_MAX_VAL_MASK) ? 0 :
				((addrmap[4] & COL_MAX_VAL_MASK) +
				 COL_B10_BASE);
		} else {
			rdc->col_shift[11] = (((addrmap[3] >> 24) &
				COL_MAX_VAL_MASK) == COL_MAX_VAL_MASK) ? 0 :
				(((addrmap[3] >> 24) & COL_MAX_VAL_MASK) +
				 COL_B9_BASE);
			rdc->col_shift[13] = ((addrmap[4] &
				COL_MAX_VAL_MASK) == COL_MAX_VAL_MASK) ? 0 :
				((addrmap[4] & COL_MAX_VAL_MASK) +
				 COL_B10_BASE);
		}
	} else {
		if (memtype & MEM_TYPE_LPDDR3) {
			rdc->col_shift[10] = (((addrmap[3] >> 16) &
				COL_MAX_VAL_MASK) == COL_MAX_VAL_MASK) ? 0 :
				(((addrmap[3] >> 16) & COL_MAX_VAL_MASK) +
				 COL_B8_BASE);
			rdc->col_shift[11] = (((addrmap[3] >> 24) &
				COL_MAX_VAL_MASK) == COL_MAX_VAL_MASK) ? 0 :
				(((addrmap[3] >> 24) & COL_MAX_VAL_MASK) +
				 COL_B9_BASE);
			rdc->col_shift[13] = ((addrmap[4] &
				COL_MAX_VAL_MASK) == COL_MAX_VAL_MASK) ? 0 :
				((addrmap[4] & COL_MAX_VAL_MASK) +
				 COL_B10_BASE);
		} else {
			rdc->col_shift[11] = (((addrmap[3] >> 16) &
				COL_MAX_VAL_MASK) == COL_MAX_VAL_MASK) ? 0 :
				(((addrmap[3] >> 16) & COL_MAX_VAL_MASK) +
				 COL_B8_BASE);
			rdc->col_shift[13] = (((addrmap[3] >> 24) &
				COL_MAX_VAL_MASK) == COL_MAX_VAL_MASK) ? 0 :
				(((addrmap[3] >> 24) & COL_MAX_VAL_MASK) +
				 COL_B9_BASE);
		}
	}

	if (width) {
		for (index = 9; index > width; index--) {
			rdc->col_shift[index] = rdc->col_shift[index - width];
			rdc->col_shift[index - width] = 0;
		}
	}

}

static void setup_bank_address_map(struct r2000p_edac *rdc, u32 *addrmap)
{
	rdc->bank_shift[0] = (addrmap[1] & BANK_MAX_VAL_MASK) + BANK_B0_BASE;
	rdc->bank_shift[1] = ((addrmap[1] >> 8) &
				BANK_MAX_VAL_MASK) + BANK_B1_BASE;
	rdc->bank_shift[2] = (((addrmap[1] >> 16) &
				BANK_MAX_VAL_MASK) == BANK_MAX_VAL_MASK) ? 0 :
				(((addrmap[1] >> 16) & BANK_MAX_VAL_MASK) +
				 BANK_B2_BASE);

}

static void setup_bg_address_map(struct r2000p_edac *rdc, u32 *addrmap)
{
	rdc->bankgrp_shift[0] = (addrmap[8] &
				BANKGRP_MAX_VAL_MASK) + BANKGRP_B0_BASE;
	rdc->bankgrp_shift[1] = (((addrmap[8] >> 8) & BANKGRP_MAX_VAL_MASK) ==
				BANKGRP_MAX_VAL_MASK) ? 0 : (((addrmap[8] >> 8)
				& BANKGRP_MAX_VAL_MASK) + BANKGRP_B1_BASE);

}

static void setup_rank_address_map(struct r2000p_edac *rdc, u32 *addrmap)
{
	rdc->rank_shift[0] = ((addrmap[0] & RANK_MAX_VAL_MASK) ==
				RANK_MAX_VAL_MASK) ? 0 : ((addrmap[0] &
				RANK_MAX_VAL_MASK) + RANK_B0_BASE);
}

/**
 * setup_address_map -	Set Address Map by querying ADDRMAP registers.
 * @rdc:		DDR memory controller private instance data.
 *
 * Set Address Map by querying ADDRMAP registers.
 *
 * Return: none.
 */
static void setup_address_map(struct r2000p_edac *rdc)
{
	u32 addrmap[12];
	int index;

	for (index = 0; index < 12; index++) {
		u32 addrmap_offset;

		addrmap_offset = ECC_ADDRMAP0_OFFSET + (index * 4);
		addrmap[index] = edac_rd(addrmap_offset);
	}

	setup_row_address_map(rdc, addrmap);

	setup_column_address_map(rdc, addrmap);

	setup_bank_address_map(rdc, addrmap);

	setup_bg_address_map(rdc, addrmap);

	setup_rank_address_map(rdc, addrmap);
}
#endif /* CONFIG_EDAC_DEBUG */


#define ECC_UNCORRECTABLE_ERROR_MASK     (1 << 26)
#define ECC_CORRECTABLE_ERROR_MASK       (1 << 25)
#define DERATE_TEMP_MASK                 (1 << 24)
#define DFI_ALERT_ERROR_MASK             (1 << 23)
#define PHY_PARITY_ERROR_MASK            (1 << 22)
#define PHY_INTERRUPT_MASK               (1 << 21)
#define DFI_ERROR_VALID_MASK             (1 << 20)

#define MC_UNMASK_ALL (ECC_UNCORRECTABLE_ERROR_MASK | \
			ECC_CORRECTABLE_ERROR_MASK   | \
			DERATE_TEMP_MASK             | \
			DFI_ALERT_ERROR_MASK         | \
			PHY_PARITY_ERROR_MASK        | \
			PHY_INTERRUPT_MASK           | \
			DFI_ERROR_VALID_MASK)

#define ECC_UNCORRECTABLE_ERROR      (1 << 15)
#define ECC_CORRECTABLE_ERROR        (1 << 14)
#define DERATE_TEMP                  (1 << 13)
#define DFI_ALERT_ERROR              (1 << 12)
#define	PHY_PARITY_ERROR              (1 << 7)
#define	PHY_INTERRUPT                 (1 << 6)

#define MC_CLEAR_ALL (ECC_UNCORRECTABLE_ERROR | \
			ECC_CORRECTABLE_ERROR   | \
			DERATE_TEMP             | \
			DFI_ALERT_ERROR         | \
			PHY_PARITY_ERROR        | \
			PHY_INTERRUPT)



#define ECCCFG0	0x70
# define ECCCFG0_ENABLE ((1 << 5) | 3)

#define ECCCTL  0x7c
#define ECC_CORRECTED_ERR_INTR_FORCE (1 << 16)

static irqreturn_t r2000p_edac_irq_handler(int irq, void *arg)
{
	int ret = IRQ_HANDLED, len;
	u32 c = nbsr_readl(MC_DDR_PHY_CONTROL, 0);
	char s[1024];
	const char *err =
		c & ECC_UNCORRECTABLE_ERROR ? "ecc uncorrectable error" :
		c & ECC_CORRECTABLE_ERROR   ? "ecc correctable error"   :
		c & DERATE_TEMP             ? "derate temp"             :
		c & DFI_ALERT_ERROR         ? "dfi alert error"         :
		c & PHY_PARITY_ERROR        ? "phy parity error"        :
		c & PHY_INTERRUPT           ? "phy interrupt"           :
		"unknown error";

	len = snprintf(s, sizeof(s), "memory controller interrupt: %s\n"
			"\t(mc/ddrphy control: 0x%x).\n", err, c);

	c &= ~MC_UNMASK_ALL;
	nbsr_writel(c, MC_DDR_PHY_CONTROL, 0);


	if (ECC_CORRECTABLE_ERROR & c || ECC_UNCORRECTABLE_ERROR & c)
		WARN_ON_ONCE(intr_handler(irq, arg) == IRQ_NONE);

	if (ECC_CORRECTABLE_ERROR == (c & MC_CLEAR_ALL)) {
		pr_err_ratelimited("%s", s);
		ret = IRQ_NONE;
		goto out;
	}
	panic(s);
out:
	c |= MC_UNMASK_ALL;
	nbsr_writel(c, MC_DDR_PHY_CONTROL, 0);

	return IRQ_HANDLED;
}

static int r2000p_edac_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	u32 v;
	int irq, ret;
	struct device *dev = &pdev->dev;
	struct edac_mc_layer layers[2];
	struct r2000p_edac *rdc;
	struct mem_ctl_info *mci;

	layers[0].type = EDAC_MC_LAYER_CHIP_SELECT;
	layers[0].size = SYNPS_EDAC_NR_CSROWS;
	layers[0].is_virt_csrow = true;
	layers[1].type = EDAC_MC_LAYER_CHANNEL;
	layers[1].size = SYNPS_EDAC_NR_CHANS;
	layers[1].is_virt_csrow = false;

	mci = edac_mc_alloc(0, ARRAY_SIZE(layers), layers,
			    sizeof(struct r2000p_edac));
	if (!mci) {
		edac_printk(KERN_ERR, EDAC_MC,
			    "Failed memory allocation for mc instance\n");
		return -ENOMEM;
	}

	if ((ret = pci_enable_device(pdev)))
		goto out;

	pci_set_master(pdev);

	rdc = mci->pvt_info;
	rdc->rm = devm_regmap_init(dev, NULL, rdc, &r2000p_mc_regmap_config);
	if (WARN_ON(IS_ERR(rdc->rm))) {
		ret = PTR_ERR(rdc->rm);
		goto out;
	}
	rdc->msix_entry.entry = 8;/* 0-7 - PMC, 8 - MC/DDRPHY. */
	ret = pci_enable_msix_range(pdev, &rdc->msix_entry, 1, 1);
	if (WARN_ON(ret < 0))
		goto out;

	irq = rdc->msix_entry.vector;
	ret = devm_request_irq(dev, irq, r2000p_edac_irq_handler,
				0, "edac", mci);
	if (WARN_ON(ret < 0))
		goto out;

	if (!r2000p_get_ecc_state(rdc)) {
		edac_printk(KERN_INFO, EDAC_MC, "ECC not enabled\n");
		ret = -ENXIO;
		goto free_edac_mc;
	}

	mc_init(mci, dev);

	ret = edac_mc_add_mc(mci);
	if (ret) {
		edac_printk(KERN_ERR, EDAC_MC,
			    "Failed to register with EDAC core\n");
		goto free_edac_mc;
	}

#ifdef CONFIG_EDAC_DEBUG
	if (edac_create_sysfs_attributes(mci)) {
		edac_printk(KERN_ERR, EDAC_MC,
				"Failed to create sysfs entries\n");
		goto free_edac_mc;
	}

	setup_address_map(rdc);
#endif

	pci_set_drvdata(pdev, mci);
	/*
	 * Start capturing the correctable and uncorrectable errors. A write of
	 * 0 starts the counters.
	 */
	edac_wr(0x0, ECC_CTRL_OFST);

	v = nbsr_readl(MC_DDR_PHY_CONTROL, 0);
	v |= MC_UNMASK_ALL | MC_CLEAR_ALL;
	nbsr_writel(v, MC_DDR_PHY_CONTROL, 0);

	return ret;
free_edac_mc:
	edac_mc_free(mci);
out:
	if (ret)
		pci_disable_device(pdev);
	return ret;
}

static void r2000p_edac_remove(struct pci_dev *pdev)
{
	struct device *dev = &pdev->dev;
	struct mem_ctl_info *mci = pci_get_drvdata(pdev);
	struct r2000p_edac *rdc = mci->pvt_info;
	int irq = rdc->msix_entry.vector;

#ifdef CONFIG_EDAC_DEBUG
	edac_remove_sysfs_attributes(mci);
#endif
	edac_mc_del_mc(&pdev->dev);
	edac_mc_free(mci);

	/* Just to make pci_disable_msix() happy: */
	devm_free_irq(dev, irq, mci);
	pci_disable_msix(pdev);
	pci_disable_device(pdev);
	pci_set_drvdata(pdev, NULL);
}

static const struct pci_device_id r2000p_edac_pciidlist[] = {
	{ PCI_VDEVICE(MCST_TMP, 0x803d) },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(pci, r2000p_edac_pciidlist);

static struct pci_driver r2000p_edac_driver = {
	.name = "r2000p-edac",
	.id_table = r2000p_edac_pciidlist,
	.probe = r2000p_edac_probe,
	.remove = r2000p_edac_remove,
};

module_pci_driver(r2000p_edac_driver);

MODULE_AUTHOR("MCST");
MODULE_DESCRIPTION("r2000+ edac driver");
MODULE_LICENSE("GPL");
