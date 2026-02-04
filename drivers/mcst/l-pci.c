/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/pci-ecam.h>
#include <linux/platform_device.h>
#include <linux/of.h>

#include <asm/mpspec.h>
#include <asm/pic.h>
#include <asm/sic_regs.h>

#include "../../../drivers/pci/pci.h"


typedef struct iohub_sysdata {
	int	domain;		/* IOHUB (PCI) domain */
	int	node;		/* NUMA node */
	int	link;		/* local number of IO link on the node */
	/* IOHUB can be connected to EIOHUB and vice versa */
	bool	has_iohub;
	u8	iohub_revision;		/* IOHUB revision */
	u8	iohub_generation;	/* IOHUB generation */
	bool	has_eioh;
	u8	eioh_generation;	/* EIOHUB generation */
	u8	eioh_revision;		/* EIOHUB revision */

	struct resource		mem_space; /* pci registers memory */
	void *l_iommu;
} iohub_sysdata_t;


int iohub_revision(struct pci_dev *pdev)
{
	struct pci_config_window *_cfg = pdev->bus->sysdata;
	struct iohub_sysdata *_sd = _cfg->priv;
	u8 _rev = l_eioh_device(pdev) ?
			_sd->eioh_revision & 0xf :
			_sd->iohub_revision >> 1;
	return _rev;
}
EXPORT_SYMBOL(iohub_revision);

int iohub_generation(struct pci_dev *pdev)
{
	struct pci_config_window *_cfg = pdev->bus->sysdata;
	struct iohub_sysdata *_sd = _cfg->priv;
	return l_eioh_device(pdev) ? _sd->eioh_generation :
					_sd->iohub_generation;
}
EXPORT_SYMBOL(iohub_generation);

bool is_iohub_asic(struct pci_dev *pdev)
{
	struct pci_config_window *_cfg = pdev->bus->sysdata;
	struct iohub_sysdata *_sd = _cfg->priv;
	u8 _rev = l_eioh_device(pdev) ?
			!(_sd->eioh_revision & 0xf0) :
			_sd->iohub_revision & 1;
	return _rev;
}
EXPORT_SYMBOL(is_iohub_asic);

static const struct pci_device_id l_iohub_root_devices[] = {
	{
		PCI_DEVICE(PCI_VENDOR_ID_ELBRUS,
			   PCI_DEVICE_ID_MCST_VIRT_PCI_BRIDGE),
	},
	{
		PCI_DEVICE(PCI_VENDOR_ID_MCST_PCIE_BRIDGE,
		      PCI_DEVICE_ID_MCST_PCIE_BRIDGE)
	},
	{}
};

static const struct pci_device_id l_eioh_proto_root_devices[] = {
	{
		PCI_DEVICE(PCI_VENDOR_ID_MCST_TMP,
			   PCI_DEVICE_ID_MCST_EIOH_PROTO_PCIE_SWITCH_PORT),
	},
	{
		PCI_DEVICE(PCI_VENDOR_ID_MCST_TMP,
			   PCI_DEVICE_ID_MCST_EIOH_PROTO_PCIE_SWITCH_PORT_R2000P),
	},
	{}
};

static bool __l_eioh_device(struct pci_dev *pdev)
{
	struct pci_bus *b = pdev->bus;
	if (pdev->vendor == PCI_VENDOR_ID_MCST_TMP &&
			pdev->device == PCI_DEVICE_ID_MCST_VPPB) {
		return pdev->revision >= 0x10 ? true : false;
	} else if (pci_match_id(l_iohub_root_devices, pdev)) {
		return false;
	} else if (pci_match_id(l_eioh_proto_root_devices, pdev)) {
		return true;
	}
	if (pci_is_root_bus(b)) {
		u16 vid = 0, did = 0;
		u8 rev;
		pci_bus_read_config_word(b, 0, PCI_VENDOR_ID, &vid);
		pci_bus_read_config_word(b, 0, PCI_DEVICE_ID, &did);
		pci_bus_read_config_byte(b, 0, PCI_REVISION_ID, &rev);
		if (vid == PCI_VENDOR_ID_MCST_TMP &&
			did == PCI_DEVICE_ID_MCST_VPPB) {
			return rev >= 0x10 ? true : false;
		}
		return false;
	}
	return __l_eioh_device(b->self);
}

bool l_eioh_device(struct pci_dev *pdev)
{
	struct pci_config_window *cfg = pdev->bus->sysdata;
	struct iohub_sysdata *sd = cfg->priv;
	if (!sd->has_eioh)
		return false;
	if (!sd->has_iohub)
		return true;
	return __l_eioh_device(pdev);
}
EXPORT_SYMBOL(l_eioh_device);

static bool e2k_is_eioh(void)
{
	u16 v;
	conf_inw(0, 0, CONFIG_CMD(0, PCI_DEVFN(0, 0), PCI_DEVICE_ID), &v);
	return v == PCI_DEVICE_ID_MCST_VPPB;
}

static bool e2k_is_multi_domain(void)
{
	return cpu_has(CPU_FEAT_ISET_V7) &&
		 !e2k_is_eioh() /* Check for hybrid proto */;
}

static void l_pci_unmap_cfg(void *ptr)
{
	pci_ecam_free((struct pci_config_window *)ptr);
}

static struct pci_config_window *l_pci_init(struct platform_device *pdev,
		struct pci_host_bridge *bridge, const struct pci_ecam_ops *ops)
{
	int err;
	struct pci_config_window *cfg;
	struct device *dev = &pdev->dev;
	struct resource *cfgres = platform_get_resource_byname(pdev, IORESOURCE_MEM, "cfg");
	struct resource bus = {
		.start	= 0,
		.end	= 255,
		.flags	= IORESOURCE_BUS,
	};

	if (!cfgres) {
		dev_err(dev, "missing cfg resource\n");
		return ERR_PTR(-EINVAL);
	}

	cfg = pci_ecam_create(dev, cfgres, &bus, ops);
	if (WARN_ON(IS_ERR(cfg)))
		return cfg;

	err = devm_add_action_or_reset(dev, l_pci_unmap_cfg, cfg);
	if (WARN_ON(err))
		return ERR_PTR(err);

	return cfg;
}

static int e2k_get_iohub_generation(void)
{
	switch (machine.native_iset_ver) {
	case E2K_ISET_V3:
		return 0;
	case E2K_ISET_V4:
	case E2K_ISET_V5:
		return 1;
	case E2K_ISET_V6:
		return 2;
	case E2K_ISET_V7:
		return 3;
	default:
		BUG();
	}
	return -1;
}

static void e2k_init_iohub_sysdata(struct device *dev, struct iohub_sysdata *sd)
{
	int gen = e2k_get_iohub_generation();
	u8 rev = -1;

	/*
	 * Use RT_MSI address instead of the address from IOAPIC BARs if:
	 * - IOHub2 is plugged into an EPIC machine
	 * - EIOHub is plugged into an APIC machine (paravirt. guest)
	 */
	if (cpu_has_epic() || paravirt_enabled()) {
		rev = raw_my_cpu_data.revision;
	} else if (gen < 2) {
		/* Read from i2c-spi controller */
		conf_inb(0, 1,  CONFIG_CMD(1, PCI_DEVFN(2, 1), PCI_REVISION_ID),
			&rev);
	}
	switch (gen) {
	case 0:
	case 1:
		sd->iohub_generation = gen;
		sd->has_iohub = true;
		sd->iohub_revision = rev;
		break;
	case 2:
	case 3:
		sd->eioh_generation = gen;
		sd->has_eioh = true;
		sd->eioh_revision = rev;
		break;
	default:
		BUG();
	}
	dev_info(dev, "IOHUB generation: %d, revision: %x\n", gen, rev);
}

static int e2k_reg32_to_resources(struct device *dev,
				  struct resource **res, int *nr)
{
	u64 v;
	unsigned psize;
	const __be32 *prop;
	const char **names;
	struct resource *r;
	struct device_node *np = dev->of_node;
	int i, ret, n = of_n_addr_cells(of_root);
	if (n != 1)
		return -EINVAL;
	*res = NULL;
	prop = of_get_property(np, "reg32", &psize);
	if (WARN_ON(prop == NULL))
		return -EEXIST;

	if (WARN_ON((psize % 16)))
		return -EINVAL;

	psize /= 16;
	r = kcalloc(psize, sizeof(*r), GFP_KERNEL);
	if (!r)
		return -ENOMEM;

	names = devm_kcalloc(dev, psize, sizeof(*names), GFP_KERNEL);
	if (!names) {
		ret = -ENOMEM;
		goto out;
	}
	ret = of_property_read_string_array(np, "reg-names", names, psize);
	if (ret < 0)
		goto out;
	ret = 0;

	for (i = 0; i < psize; i++, prop += 4) {
		v = be32_to_cpu(prop[0]);
		v = (v << 32) | be32_to_cpu(prop[1]);
		r[i].start = v;
		v = be32_to_cpu(prop[2]);
		v = (v << 32) | be32_to_cpu(prop[3]);
		r[i].end = r[i].start + v - 1;
		r[i].flags = IORESOURCE_MEM;
		r[i].name = names[i] ? names[i] : dev_name(dev);
	}
	*nr = psize;
	*res = r;
out:
	if (ret)
		kfree(r);
	return ret;
}

static int e2k_add_reg32_resources(struct platform_device *pdev)
{
	int ret, nr, i;
	struct device *dev = &pdev->dev;
	struct resource *r = NULL;
	ret = e2k_reg32_to_resources(dev, &r, &nr);
	if (ret)
		return ret;

	ret = platform_device_add_resources(pdev, r, nr);
	if (ret)
		goto out;

	for (i = 0; ret && i < pdev->num_resources; i++)
		ret = insert_resource(&iomem_resource, &pdev->resource[i]);
out:
	kfree(r);
	return ret;
}

static int l_pci_fix_resources(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct device_node *np = dev->of_node;
	if (!of_get_property(np, "reg32", NULL))
		return 0;
	return e2k_add_reg32_resources(pdev);
}

static int l_pci_get_prf_resource(struct platform_device *pdev, struct resource *m)
{
	e2k_rt_pcimp_t b;
	e2k_rt_pcimp_t e;
	struct resource *rb = platform_get_resource_byname(pdev, IORESOURCE_MEM, "pref-bgn");
	struct resource *re = platform_get_resource_byname(pdev, IORESOURCE_MEM, "pref-end");

	if (!rb || !re)
		return -ENOENT;
	if (WARN_ON(!m))
		return -ENOMEM;

	AW(b) = boot_readl((void *)rb->start);
	AW(e) = boot_readl((void *)re->start);
	if (IS_MACHINE_E1CP) {
		/*TODO:*/
		m->start = ~0UL;
		m->end   = ~0UL;
	} else {
		m->start = (u64)b.bgn << E2K_SIC_ALIGN_RT_PCIMP;
		m->end   = (((u64)e.end + 1) << E2K_SIC_ALIGN_RT_PCIMP) - 1;
	}

	m->name = "PCI prefetch";
	m->flags = IORESOURCE_MEM | IORESOURCE_PREFETCH;
	if (m->start >= m->end)
		return -ENOSPC;
	return 0;
}

static int l_pci_get_mem_resource(struct platform_device *pdev, struct resource *m)
{
	e2k_rt_pcim_t v;
	struct resource *res = platform_get_resource_byname(pdev, IORESOURCE_MEM, "mem");
	if (!res)
		return -ENOENT;
	if (WARN_ON(!m))
		return -ENOMEM;

	AW(v) = boot_readl((void *)res->start);
	if (IS_MACHINE_E1CP) {
		m->start = AW(v);
		m->end   = 0xffffFFFF;
	} else {
		m->start = (u32)v.bgn << E2K_SIC_ALIGN_RT_PCIM;
		m->end   = (((u32)v.end + 1) << E2K_SIC_ALIGN_RT_PCIM) - 1;
	}

	m->name = "PCI mem";
	m->flags = IORESOURCE_MEM;
	return 0;
}

static int l_pci_get_io_resource(struct platform_device *pdev, struct resource *m)
{
	e2k_rt_pciio_v7_t v;
	struct resource *res = platform_get_resource_byname(pdev, IORESOURCE_MEM, "io");
	if (IS_MACHINE_E1CP) {
		m->start = 0;
		m->end   = IO_SPACE_LIMIT;
		goto out;
	}
	if (!res)
		return -ENOENT;

	AW(v) = boot_readl((void *)res->start);
	if (e2k_is_multi_domain()) {
		m->start = (u32)v.bgn << E2K_SIC_ALIGN_RT_PCIIO;
		m->end   = (((u32)v.end + 1) << E2K_SIC_ALIGN_RT_PCIIO) - 1;
	} else {
		e2k_rt_pciio_t a;
		AW(a) = AW(v);
		m->start = (u32)a.bgn << E2K_SIC_ALIGN_RT_PCIIO;
		m->end   = (((u32)a.end + 1) << E2K_SIC_ALIGN_RT_PCIIO) - 1;
	}
out:
	if (m->start < 0x400) /* cut out io-vga area */
		m->start = 0x400;
	m->name = "PCI IO";
	m->flags = IORESOURCE_IO;
	return 0;
}

static int l_pci_host_probe(struct platform_device *pdev)
{
	int ret;
	unsigned long offset;
	struct device *dev = &pdev->dev;
	struct device_node *dn = dev->of_node;
	struct pci_host_bridge *bridge;
	struct pci_config_window *cfg;
	int node = dev_to_node(dev);
	struct iohub_sysdata *sd = devm_kzalloc(dev, sizeof(*sd), GFP_KERNEL);
	const struct pci_ecam_ops *ops = &pci_generic_ecam_ops;
	struct resource *io  = devm_kzalloc(dev, sizeof(*io),  GFP_KERNEL);
	struct resource *mem = devm_kzalloc(dev, sizeof(*mem), GFP_KERNEL);
	struct resource *prf = devm_kzalloc(dev, sizeof(*prf), GFP_KERNEL);

	if (!io || !mem || !prf || !sd) {
		pr_err("PCI: OOM, skipping PCI bus\n");
		return -ENOMEM;
	}
	if ((ret = l_pci_fix_resources(pdev)))
		return ret;

	if ((ret = l_pci_get_io_resource(pdev, io)))
		io = NULL;
	if ((ret = l_pci_get_mem_resource(pdev, mem)))
		mem = NULL;
	if ((ret = l_pci_get_prf_resource(pdev, prf)))
		prf = NULL;
	/* ignore uninitianized filter */
	if (prf && prf->start <= mem->end)
		prf = NULL;

	if (node < 0)
		node = 0;
	sd->domain = of_get_pci_domain_nr(dn);
	if (WARN_ON(sd->domain < 0))
		return sd->domain;
	sd->node = node;
	sd->link = 0;
	e2k_init_iohub_sysdata(dev, sd);

	/* We can not fill bridge resoursed in devtree*/
	dev->of_node = NULL;
	bridge = devm_pci_alloc_host_bridge(dev, 0);
	if (WARN_ON(!bridge))
		return -ENOMEM;
	dev->of_node = dn;

	platform_set_drvdata(pdev, bridge);
	bridge->dev.archdata.iommu_dev = dev->parent;
	bridge->domain_nr = sd->domain;

	/* Parse and map our Configuration Space windows */
	cfg = l_pci_init(pdev, bridge, ops);
	if (IS_ERR(cfg))
		return PTR_ERR(cfg);

	cfg->priv = sd;
	/* Do not reassign resources if probe only */
	if (!paravirt_enabled()) /* Bug 154114 */
		pci_add_flags(PCI_PROBE_ONLY);

	bridge->sysdata = cfg;
	bridge->ops = (struct pci_ops *)&ops->pci_ops;

	ret = io ? request_resource(&ioport_resource, io) : 0;
	if (ret) {
		pr_err("%s: request resource failed (%d): %pR\n",
				dev_name(dev), ret, io);
		return ret;
	}
	ret = mem ? request_resource(&iomem_resource, mem) : 0;
	if (ret) {
		pr_err("%s: request resource failed (%d): %pR\n",
				dev_name(dev), ret, mem);
		return ret;
	}
	ret = prf ? request_resource(&iomem_resource, prf) : 0;
	if (ret) {
		pr_err("%s: request resource failed (%d): %pR\n",
				dev_name(dev), ret, prf);
		return ret;
	}

	/* host supports just 16-bit */
	offset = io ? io->start & (~0xffffUL) : 0;

	if (io)
		pci_add_resource_offset(&bridge->windows, io, offset);
	if (mem)
		pci_add_resource_offset(&bridge->windows, mem,
					L_IOMEM_RESOURCE_OFFSET);
	if (prf)
		pci_add_resource_offset(&bridge->windows, prf,
					L_IOMEM_RESOURCE_OFFSET);


	return WARN_ON(pci_host_probe(bridge));
}

static int l_pci_host_remove(struct platform_device *pdev)
{
	struct pci_host_bridge *bridge = platform_get_drvdata(pdev);

	pci_lock_rescan_remove();
	pci_stop_root_bus(bridge->bus);
	pci_remove_root_bus(bridge->bus);
	pci_unlock_rescan_remove();

	platform_set_drvdata(pdev, NULL);

	return 0;
}

static const struct of_device_id l_pci_dt_ids[] = {
	{.compatible = "mcst,l-pci"},
	{}
};

static struct platform_driver l_pci_driver = {
	.driver = {
		.name = "l-pci-host",
		.of_match_table = of_match_ptr(l_pci_dt_ids),

	},
	.probe = l_pci_host_probe,
	.remove = l_pci_host_remove,
};
module_platform_driver(l_pci_driver);

MODULE_LICENSE("GPL v2");
