/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Low-Level PCI Access
 *
 * For more information, please consult the following manuals (look at
 * http://www.pcisig.com/ for how to get them):
 *
 * PCI BIOS Specification
 * PCI Local Bus Specification
 * PCI to PCI Bridge Specification
 * PCI System Design Guide
 */

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/init.h>
#include <linux/ioport.h>
#include <linux/errno.h>
#include <linux/delay.h>
#include <linux/vgaarb.h>
#include <linux/moduleparam.h>
#include "../../../drivers/pci/pci.h"

static unsigned long l_slink_freq;

static int __init l_slink_freq_setup(char *str)
{
	l_slink_freq = memparse(str, &str);
	return 1;
}

__setup("slink=", l_slink_freq_setup);

#define SLINK_PLL_MULTIPLIER			0x6c
#define SLINK_PLL_STROB				0x6e
# define SLPLLM_STB_UP				0xa5
#define SLINK_PLLSTS				0x6f
# define SLINK_PLLSTS_0_LOCKED			0x3

struct l_slink_freqs {
	unsigned long dflt, min, max, mult, div;
} l_slink_freqs[] = {
	{
	.dflt = 14, .min = 7, .max = 25, .mult = 50 * 1000 * 1000, .div = 3}, {
	.dflt = 19, .min = 9, .max = 25, .mult = 25 * 1000 * 1000, .div = 1}
};

#define SLINK_TIMEOUT_10USEC	(1 * 1000 * 100)
static void l_quirk_slink_freq(struct pci_dev *pdev)
{
	struct l_slink_freqs *f;
	int i;
	unsigned short v, curr;
	if (l_slink_freq == 0)
		return;
	pci_write_config_byte(pdev, SLINK_PLL_STROB, 0);
	pci_read_config_word(pdev, SLINK_PLL_MULTIPLIER, &curr);
	for (i = 0; i < ARRAY_SIZE(l_slink_freqs); i++) {
		f = &l_slink_freqs[i];
		if (f->dflt == curr)
			break;
	}
	if (i == ARRAY_SIZE(l_slink_freqs)) {
		pr_err("slink: unknown default multiplier: %d\n", curr);
		return;
	}
	if (l_slink_freq > (f->max + 1) * f->mult / f->div ||
	    l_slink_freq < (f->min +1) * f->mult / f->div) {
		pr_err("slink: requested frequency out of bounds: %ld\n",
		       l_slink_freq);
		return;
	}
	v = ((l_slink_freq + (f->mult / f->div / 2)) * f->div) / f->mult - 1;
	do {
		unsigned short last;
		if (v == curr) {
			pr_info("slink: frequency set to: %ld (SLPLLM=%d)\n",
			       (v + 1) * f->mult / f->div, v);
			break;
		}
		if (v < f->dflt)
			curr--;
		else
			curr++;
		pci_write_config_byte(pdev, SLINK_PLL_STROB, 0);
		pci_write_config_word(pdev, SLINK_PLL_MULTIPLIER, curr);
		pci_write_config_byte(pdev, SLINK_PLL_STROB, SLPLLM_STB_UP);
		for (i = 0; i < SLINK_TIMEOUT_10USEC; i++) {
			unsigned char sts;
			pci_read_config_byte(pdev, SLINK_PLLSTS, &sts);
			if ((sts & SLINK_PLLSTS_0_LOCKED) ==
			    SLINK_PLLSTS_0_LOCKED)
				break;
			udelay(10);
		}
		if (i == SLINK_TIMEOUT_10USEC) {
			panic("slink: timeout\n");
		}
		pci_write_config_byte(pdev, SLINK_PLL_STROB, 0);
		pci_read_config_word(pdev, SLINK_PLL_MULTIPLIER, &last);
		if (last != curr) {
			panic("slink: failed to set frequency to: %ld (SLPLLM=%d)\n",
			       (curr + 1)  * f->mult / f->div, curr);
			break;
		}
	} while (1);

}
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_MCST_TMP, PCI_DEVICE_ID_MCST_VPPB,
			 l_quirk_slink_freq);

static void fixup_milandr(struct pci_dev *pdev)
{
	struct resource *r = &pdev->resource[0];
	/* Milandr shows wrong bar size */
	if (r->flags)
		r->end = r->start + (16 << 20) - 1;

}
DECLARE_PCI_FIXUP_HEADER(0x16c3, 0xabcd, fixup_milandr);
DECLARE_PCI_FIXUP_HEADER(0x16c3, 0x0bad, fixup_milandr);

#define PCI_SCBA_0	0xf0    /* System commutator base address [31:00] */
#define	B0_BCTRL		0x13e	/* 8/0x03		PCIe bridge control	    0:N:0{0x3e}	     */
#define B1_BCTRL		0x23e   /* 8/0x1c		PCI bridge control	    m:0:0{0x3e}      */

static const struct pci_device_id l_iohub_bridges[] = {
	{
		PCI_DEVICE(PCI_VENDOR_ID_MCST_PCIE_BRIDGE,
		      PCI_DEVICE_ID_MCST_PCIE_BRIDGE)
	},
	{
		PCI_DEVICE(PCI_VENDOR_ID_MCST_TMP,
			   PCI_DEVICE_ID_MCST_PCI_BRIDGE),
	},
	{}
};
static int l_check_iohub_vga_enable(struct pci_dev *pdev)
{
	int ret = 0, reg_off = 0;
	struct pci_dev *dev;
	struct pci_bus *bus;

	/*	iohub errata:
	 *	ERR 48 -  PCI-Express root hub (pcie)
	 *	vga-enable bit is missing from PCI-Express root hub's
	 *	configuration space
	 */

	bus = pdev->bus;

	while (bus) {
		struct pci_dev *bridge = bus->self;
		const struct pci_device_id *id;
		if (!bridge)
			goto next;

		id = pci_match_id(l_iohub_bridges, bridge);
		if (!id)
			goto next;
		if (id->device == PCI_DEVICE_ID_MCST_PCIE_BRIDGE) {
			reg_off = B0_BCTRL;
			break;
		} else if (id->device == PCI_DEVICE_ID_MCST_PCI_BRIDGE) {
			reg_off = B1_BCTRL;
			break;
		} else {
			u16 l;
			pci_read_config_word(bridge, PCI_BRIDGE_CONTROL,
					     &l);
			if (!(l & PCI_BRIDGE_CTL_VGA))
				goto out;
		}
next:
		bus = bus->parent;
	}
	if (reg_off == 0)
		goto out;

	dev = NULL;
	if ((dev = pci_get_device(PCI_VENDOR_ID_ELBRUS,
			PCI_DEVICE_ID_MCST_VIRT_PCI_BRIDGE, dev))) {
		u32 addr;
		void __iomem *scrb;
		pci_read_config_dword(dev, PCI_SCBA_0, &addr);
		addr &= ~3;
		scrb = ioremap(addr, 0x1000);
		if (readb(scrb + reg_off) & PCI_BRIDGE_CTL_VGA)
			ret = 1;
		iounmap(scrb);
	}
out:
	return ret;
}

static const struct pci_device_id l_iohub2_bridges[] = {
	{
		PCI_DEVICE(PCI_VENDOR_ID_MCST_TMP,
		      PCI_DEVICE_ID_MCST_PCIe1),
	},
	{
		PCI_DEVICE(PCI_VENDOR_ID_MCST_TMP,
			   PCI_DEVICE_ID_MCST_PCIe8),
	},
	{
		PCI_DEVICE(PCI_VENDOR_ID_MCST_TMP,
			   PCI_DEVICE_ID_MCST_VPPB),
	},
	{}
};

static int l_check_iohub2_vga_enable(struct pci_dev *pdev)
{
	int ret = 1;
	struct pci_bus *bus;

	/*	iohub2 errata: ERR 02 - vga_mode (pcie):
	 *	PCIE Root Complexes do not support VGA Mode which means
	 *	that "VGA Enable" and "VGA 16 bit Decode" registers are
	 *	read-only and set to 0 by default.
	 *	So set up the first device we come across.
	 */

	bus = pdev->bus;

	while (bus) {
		struct pci_dev *bridge = bus->self;
		const struct pci_device_id *id;
		u16 l;
		if (!bridge)
			goto next;

		pci_read_config_word(bridge, PCI_BRIDGE_CONTROL, &l);

		id = pci_match_id(l_iohub2_bridges, bridge);
		if (id) {
			l |= PCI_BRIDGE_CTL_VGA;
			pci_write_config_word(bridge, PCI_BRIDGE_CONTROL, l);
		} else {
			if (!(l & PCI_BRIDGE_CTL_VGA)) {
				ret = 0;
				goto out;
			}
		}
next:
		bus = bus->parent;
	}
out:
	return ret;
}

static void fixup_vga(struct pci_dev *pdev)
{
	u16 cmd;

	if (vga_default_device())
		return;

	pci_read_config_word(pdev, PCI_COMMAND, &cmd);
	if ((pdev->class >> 8) != PCI_CLASS_DISPLAY_VGA) { /* mgam83 */
		if ((cmd & (PCI_COMMAND_MEMORY)) != (PCI_COMMAND_MEMORY))
			return;
	} else if ((cmd & (PCI_COMMAND_IO | PCI_COMMAND_MEMORY)) !=
				(PCI_COMMAND_IO | PCI_COMMAND_MEMORY)) {
		return;
	}

	if ((iohub_generation(pdev) == 0 &&
				l_check_iohub_vga_enable(pdev)) ||
		 (iohub_generation(pdev) == 1 &&
				l_check_iohub2_vga_enable(pdev))) {
		vga_set_default_device(pdev);
	}
}
DECLARE_PCI_FIXUP_CLASS_FINAL(PCI_ANY_ID, PCI_ANY_ID,
			      PCI_CLASS_DISPLAY_VGA, 8, fixup_vga);
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_MGAM83, PCI_DEVICE_ID_MGAM83, fixup_vga);

#define	 MGA2_REGS_SIZE	(512 * 1024)
#define	 MGA2_DC0_CTRL		0x00800
# define MGA2_DC_CTRL_NATIVEMODE        (1 << 0)
# define MGA2_DC_CTRL_DIS_VGAREGS       (1 << 1)
# define MGA2_DC_CTRL_SOFT_RESET        (1 << 31)

#define PCI_VCFG	0x40
# define PCI_MGA2_TRANSACTIONS_PENDING	(1 << 3)

static void __iomem *mga2_regs_base;
static u32 mga2_ctrl_val;
static void freeze_mga2(struct pci_dev *dev)
{
	int i;
	u32 r;
	u16 cmd, vcfg;

	pci_read_config_dword(dev, PCI_BASE_ADDRESS_2, &r);
	r &= ~(MGA2_REGS_SIZE - 1);
	if (r == 0) {
		/* BAR is not allocated, ignore for now */
		pr_err("%s: MGA2 registers BAR #2 is not allocated\n",
			pci_name(dev));
		return;
	}
	mga2_regs_base = ioremap(r, MGA2_REGS_SIZE);
	if (WARN_ON(mga2_regs_base == NULL))
		return;

	mga2_ctrl_val = readl(mga2_regs_base + MGA2_DC0_CTRL);
	writel(mga2_ctrl_val | MGA2_DC_CTRL_SOFT_RESET  | MGA2_DC_CTRL_NATIVEMODE |
				MGA2_DC_CTRL_DIS_VGAREGS,
			mga2_regs_base + MGA2_DC0_CTRL);

	pci_read_config_word(dev, PCI_COMMAND, &cmd);
	pci_write_config_word(dev, PCI_COMMAND, cmd & ~PCI_COMMAND_MASTER);
	for (i = 0; i < 200 * 10; i++) {
		pci_read_config_word(dev, PCI_VCFG, &vcfg);
		if (!(vcfg & PCI_MGA2_TRANSACTIONS_PENDING))
			break;
		udelay(100);
	}
	WARN_ON(i == 200 * 10);
	pci_write_config_word(dev, PCI_COMMAND, cmd);
}
DECLARE_PCI_FIXUP_EARLY(PCI_VENDOR_ID_MCST_TMP, PCI_DEVICE_ID_MCST_MGA2, freeze_mga2);

static void thaw_mga2(struct pci_dev *dev)
{
	if (!mga2_regs_base)
		return;
	writel(mga2_ctrl_val, mga2_regs_base + MGA2_DC0_CTRL);
	iounmap(mga2_regs_base);
	mga2_regs_base = NULL;
	dev_info(&dev->dev, "mga2 fixup done\n");
}
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_MCST_TMP, PCI_DEVICE_ID_MCST_MGA2, thaw_mga2);

#define PCI_MCST_CFG	0x40
# define PCI_MCST_RESET		(1 << 6)
# define PCI_MCST_IOMMU_DSBL	(1 << 5)
/*
 * disable iommu translation to prevent iommu fault at vga-console
*/
static void mga25_disable_iommu_translation(struct pci_dev *dev)
{
	u8 tmp;
	pci_read_config_byte(dev, PCI_MCST_CFG, &tmp);
	pci_write_config_byte(dev, PCI_MCST_CFG, tmp | PCI_MCST_IOMMU_DSBL);
}
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_MCST_TMP, PCI_DEVICE_ID_MCST_MGA25,
			  mga25_disable_iommu_translation);

static int pci_disable_extended_tags(struct pci_dev *dev, void *ign)
{
	u32 cap;
	u16 ctl;
	int ret;

	if (!pci_is_pcie(dev))
		return 0;

	ret = pcie_capability_read_dword(dev, PCI_EXP_DEVCAP, &cap);
	if (ret)
		return 0;

	if (!(cap & PCI_EXP_DEVCAP_EXT_TAG))
		return 0;

	ret = pcie_capability_read_word(dev, PCI_EXP_DEVCTL, &ctl);
	if (ret)
		return 0;

	if (ctl & PCI_EXP_DEVCTL_EXT_TAG) {
		pci_info(dev, "iohub2: disabling Extended Tags\n");
		pcie_capability_clear_word(dev, PCI_EXP_DEVCTL,
						PCI_EXP_DEVCTL_EXT_TAG);
	}
	return 0;
}

static void l_quirk_no_ext_tags(struct pci_dev *pdev)
{
	if (iohub_generation(pdev) != 1 || iohub_revision(pdev) > 3)
		return;

	pci_disable_extended_tags(pdev, NULL);
	if (pdev->subordinate) {
		pci_walk_bus(pdev->subordinate,
			     pci_disable_extended_tags, NULL);
	}
}
/* Must override pci_configure_device() */
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_MCST_TMP, PCI_DEVICE_ID_MCST_PCIe1, l_quirk_no_ext_tags);
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_MCST_TMP, PCI_DEVICE_ID_MCST_PCIe8, l_quirk_no_ext_tags);

#define LINK_RETRAIN_TIMEOUT HZ
static bool pcie_retrain_link(struct pci_dev *parent)
{
	unsigned long end_jiffies;
	u16 reg16;

	pcie_capability_read_word(parent, PCI_EXP_LNKCTL, &reg16);
	reg16 |= PCI_EXP_LNKCTL_RL;
	pcie_capability_write_word(parent, PCI_EXP_LNKCTL, reg16);
	if (parent->clear_retrain_link) {
		/*
		 * Due to an erratum in some devices the Retrain Link bit
		 * needs to be cleared again manually to allow the link
		 * training to succeed.
		 */
		reg16 &= ~PCI_EXP_LNKCTL_RL;
		pcie_capability_write_word(parent, PCI_EXP_LNKCTL, reg16);
	}

	/* Wait for link training end. Break out after waiting for timeout */
	end_jiffies = jiffies + LINK_RETRAIN_TIMEOUT;
	do {
		pcie_capability_read_word(parent, PCI_EXP_LNKSTA, &reg16);
		if (!(reg16 & PCI_EXP_LNKSTA_LT))
			break;
		msleep(1);
	} while (time_before(jiffies, end_jiffies));
	return !(reg16 & PCI_EXP_LNKSTA_LT);
}

/*
 * Force retrain pcie link into specified generation,
 * list of comma separated entries, for example:
 * l_pcie_retrain=0000:01:06.0=3,0000:01:05.0=2
 */
static char *l_pcie_retrain;
core_param(l_pcie_retrain, l_pcie_retrain, charp, 0400);
static int l_pcie_retrain_check_cmdline(struct pci_dev *pdev)
{
	const char *p, *name = pci_name(pdev);
	size_t len;
	if (!l_pcie_retrain)
		return 0;

	for (p = l_pcie_retrain; *p; p += len) {
		len = strcspn(p, "=");
		if (strlen(name) != len)
			return -1;
		if (p[len] != '=')
			return -1;
		if (p[len + 1] == 0)
			return -1;
		if (!memcmp(name, p, len)) {
			char c = p[len + 1];
			if (c == '1')
				return PCIE_SPEED_2_5GT;
			if (c == '2')
				return PCIE_SPEED_5_0GT;
			if (c == '3')
				return PCIE_SPEED_8_0GT;
			return -1;
		}
		len += 2;
		if (p[len] == ',')
			len++;
	}
	return 0;
}

static void l_pcie_retrain_link_quirk(struct pci_dev *pdev)
{
	int r;
	u16 linksta, v;
	struct pci_dev *pd;
	struct pci_bus *bus = pdev->subordinate;
	enum pci_bus_speed s, sm = bus->max_bus_speed;
	if (list_empty(&bus->devices))
		return;
	pd = list_entry(bus->devices.next, struct pci_dev, bus_list);

	r = l_pcie_retrain_check_cmdline(pdev);
	if (WARN_ONCE(r < 0, "pcie retrain:failed to parse cmdline: '%s'",
			l_pcie_retrain)) {
		return;
	}
	if (r > 0) {
		sm = r;
	} else if (r == 0 && pd->vendor == PCI_VENDOR_ID_PLX &&
			pd->device == 0x8724) {
		/* Only Gen2 works with bridge PLX Technology, Inc. PEX 8724 */
		sm = PCI_EXP_LNKCTL2_TLS_5_0GT;
	}
	s = pcie_get_speed_cap(pd);
	if (s < sm)
		sm = s;

	if (sm == bus->cur_bus_speed)
		return;
	if (sm > bus->max_bus_speed)
		return;
	s = bus->cur_bus_speed;

	pcie_capability_read_word(pdev, PCI_EXP_LNKCTL2, &v);
	v &= ~PCI_EXP_LNKCTL2_TLS;
	if (sm == PCIE_SPEED_8_0GT) /* gen3 */
		v |= PCI_EXP_LNKCTL2_TLS_8_0GT;
	else if (sm == PCIE_SPEED_5_0GT) /* gen2 */
		v |= PCI_EXP_LNKCTL2_TLS_5_0GT;
	else /* gen1 */
		v |= PCI_EXP_LNKCTL2_TLS_2_5GT;
	pcie_capability_write_word(pdev, PCI_EXP_LNKCTL2, v);

	if (WARN(!pcie_retrain_link(pdev),
		"%s: failed to retrain link\n", pci_name(pdev))) {
		return;
	}
	pcie_capability_read_word(pdev, PCI_EXP_LNKSTA, &linksta);
	pcie_update_link_speed(bus, linksta);

	pci_info(pdev, "retrain link %s -> %s\n", pci_speed_string(s),
			pci_speed_string(bus->cur_bus_speed));
}
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_MCST_TMP, PCI_DEVICE_ID_MCST_PCIE_X16,
			 l_pcie_retrain_link_quirk);
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_MCST_TMP, PCI_DEVICE_ID_MCST_PCIE_X4,
			 l_pcie_retrain_link_quirk);
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_MCST_TMP,
				PCI_DEVICE_ID_MCST_R2000P_PCIE_X4,
			 l_pcie_retrain_link_quirk);


