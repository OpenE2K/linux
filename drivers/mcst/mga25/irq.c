/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#define DEBUG
#include "drv.h"


#define	 MGA2_INTENA		0x00000
#define	 MGA2_INTREQ		0x00004
#define	 MGA2_INTLEVEL		0x00008
#define	 MGA2_INTMODE		0x0000C

# define MGA2_INT_B_SETRST (1U << 31)

struct mga25_pic {
	struct irq_domain *irq_domain;
	struct msix_entry msix_entries[1];
	void __iomem *regs;
	int dev_id;
	u32 irq_en_mask;
	spinlock_t mask_lock;
};

#define __rint(__offset)	 ({				\
	unsigned __v = 0;					\
	__v = readl(mpic->regs + MGA2_ ## __offset);	\
	__v;				\
})
#define __wint(__val, __offset)	do {		\
	writel(__val, mpic->regs + MGA2_ ## __offset); \
} while (0)


#ifdef DEBUG
#define rint(__offset)						\
({								\
	unsigned __val = __rint(__offset);			\
	DRM_DEBUG_KMS("R: %x: %s\n", __val, # __offset);	\
	__val;							\
})

#define wint(__val, __offset) do {				\
	unsigned __val2 = __val;				\
	DRM_DEBUG_KMS("W: %x: %s\n", __val2, # __offset);	\
	__wint(__val2, __offset);				\
} while(0)

#else
#define		rint		__rint
#define		wint		__wint
#endif


static irqreturn_t mga25_pic_irq_handler(int irq, void *arg)
{
	struct mga25_pic *mpic = arg;
	u32 ena;
	unsigned long flags;
	u32 intr = __rint(INTREQ);

	/* r2000+ has edge interrupt, so we have to mask/unmask interrupts
	  in order not to lose any interrupt */
	spin_lock_irqsave(&mpic->mask_lock, flags);
	ena = READ_ONCE(mpic->irq_en_mask);
	__wint(ena, INTENA);
	spin_unlock_irqrestore(&mpic->mask_lock, flags);

	intr &= ena;
	__wint(intr, INTREQ);

	while (intr) {
		irq_hw_number_t hwirq = fls(intr) - 1;
		raw_local_irq_save(flags);
		generic_handle_irq(irq_find_mapping(
				mpic->irq_domain, hwirq));
		raw_local_irq_restore(flags);
		intr &= ~(1 << hwirq);
	}
	spin_lock_irqsave(&mpic->mask_lock, flags);
	ena = READ_ONCE(mpic->irq_en_mask);
	__wint(ena | MGA2_INT_B_SETRST, INTENA);
	spin_unlock_irqrestore(&mpic->mask_lock, flags);

	return IRQ_HANDLED;
}

static void mga25_pic_irq_mask(struct irq_data *d)
{
	unsigned long flags;
	struct mga25_pic *mpic = irq_data_get_irq_chip_data(d);
	spin_lock_irqsave(&mpic->mask_lock, flags);
	mpic->irq_en_mask &= ~(1 << d->hwirq);
	wint(1 << d->hwirq, INTENA);
	spin_unlock_irqrestore(&mpic->mask_lock, flags);
}

static void mga25_pic_irq_unmask(struct irq_data *d)
{
	unsigned long flags;
	struct mga25_pic *mpic = irq_data_get_irq_chip_data(d);
	spin_lock_irqsave(&mpic->mask_lock, flags);
	mpic->irq_en_mask |= 1 << d->hwirq;
	wint((1 << d->hwirq) | MGA2_INT_B_SETRST, INTENA);
	spin_unlock_irqrestore(&mpic->mask_lock, flags);
}

static struct irq_chip mga25_pic_irq_chip = {
	.name = "mga2-mpic",
	.irq_mask = mga25_pic_irq_mask,
	.irq_unmask = mga25_pic_irq_unmask,
};

static int mga25_pic_irqdomain_map(struct irq_domain *d,
				unsigned int irq, irq_hw_number_t hwirq)
{
	struct mga25_pic *mpic = d->host_data;
	irq_set_chip_and_handler(irq,
				 &mga25_pic_irq_chip, handle_simple_irq);
	irq_set_chip_data(irq, mpic);
	return 0;
}

static const struct irq_domain_ops mga25_pic_hw_irqdomain_ops = {
	.xlate = irq_domain_xlate_onecell,
	.map = mga25_pic_irqdomain_map,
};

static int mga25_pic_probe(struct platform_device *pdev)
{
	int ret, irq;
	struct pci_dev *pci_dev;
	struct device *dev = &pdev->dev;
	struct resource *res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	struct mga25_pic *mpic = devm_kzalloc(dev, sizeof(*mpic),
						GFP_KERNEL);
	if (!mpic)
		return -ENOMEM;

	if (WARN_ON(!dev_is_pci(dev->parent))) {
		ret = -ENODEV;
		goto out;
	}
	pci_dev = to_pci_dev(dev->parent);

	spin_lock_init(&mpic->mask_lock);
	mpic->regs = devm_ioremap_resource(dev, res);
	if (IS_ERR(mpic->regs))
		return PTR_ERR(mpic->regs);

	mpic->dev_id = mga25_get_version(dev->parent);
	irq = pci_dev->irq;
	if (mpic->dev_id == MGA20) {
		irq++;
	} else if (pci_dev->msix_cap) {
		int i, numvecs = ARRAY_SIZE(mpic->msix_entries);

		for (i = 0; i < numvecs; i++)
			mpic->msix_entries[i].entry = i;

		ret = pci_enable_msix_range(pci_dev,
					mpic->msix_entries,
					numvecs,
					numvecs);
		if (WARN_ON(ret < 0))
			goto out;
		irq = mpic->msix_entries[0].vector;
	}
	ret = devm_request_irq(dev, irq, mga25_pic_irq_handler,
				0, dev_name(dev), mpic);
	if (WARN_ON(ret))
		goto out;

	mpic->irq_domain = irq_domain_add_linear(dev->of_node, 31,
					&mga25_pic_hw_irqdomain_ops, mpic);
	if (WARN_ON(!mpic->irq_domain)) {
		ret = -ENODEV;
		goto out;
	}

	dev_set_drvdata(dev, mpic);
out:
	return ret;
}

static int mga25_pic_remove(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct pci_dev *pci_dev;
	struct mga25_pic *mpic = dev_get_drvdata(dev);
	irq_domain_remove(mpic->irq_domain);
	if (WARN_ON(!dev_is_pci(dev->parent)))
		goto out;

	pci_dev = to_pci_dev(dev->parent);
	if (pci_dev->msix_cap) {
		int irq = mpic->msix_entries[0].vector;
		/*Just to make pci_disable_msix() happy */
		devm_free_irq(dev, irq, mpic);
		pci_disable_msix(pci_dev);
	}
out:
	dev_set_drvdata(dev, NULL);

	return 0;
}

static const struct of_device_id mga25_pic_dt_match[] = {
	{ .compatible = "mcst,mga2x-pic" },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, mga25_pic_dt_match);

struct platform_driver mga25_pic_driver = {
	.probe = mga25_pic_probe,
	.remove = mga25_pic_remove,
	.driver = {
		.name = "mga2-pic",
		.of_match_table = of_match_ptr(mga25_pic_dt_match),
	},
};
