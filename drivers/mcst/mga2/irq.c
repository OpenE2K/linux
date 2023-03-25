#define DEBUG
#include "drv.h"


#define	 MGA2_INTENA		0x00000	/* разрешение генерации прерывания */
#define	 MGA2_INTREQ		0x00004	/* состояние запросов прерывания */
#define	 MGA2_INTLEVEL		0x00008	/* указывает активный уровень входного сигнала */
#define	 MGA2_INTMODE		0x0000C	/* указывает режим обработки входных сигналов */

# define MGA2_INT_B_SETRST (1U << 31)

struct mga2_pic {
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


static irqreturn_t mga2_pic_irq_handler(int irq, void *arg)
{
	struct mga2_pic *mpic = arg;
	u32 ena;
	unsigned long flags;
	u32 intr = __rint(INTREQ);

	spin_lock_irqsave(&mpic->mask_lock, flags);
	ena = READ_ONCE(mpic->irq_en_mask);
	spin_unlock_irqrestore(&mpic->mask_lock, flags);

	__wint(ena, INTENA);
	intr &= ena;
	__wint(intr, INTREQ);

	while (intr) {
		irq_hw_number_t hwirq = fls(intr) - 1;
		generic_handle_irq(irq_find_mapping(
				mpic->irq_domain, hwirq));
		intr &= ~(1 << hwirq);
	}
	spin_lock_irqsave(&mpic->mask_lock, flags);
	ena = READ_ONCE(mpic->irq_en_mask);
	spin_unlock_irqrestore(&mpic->mask_lock, flags);
	__wint(ena | MGA2_INT_B_SETRST, INTENA);

	return IRQ_HANDLED;
}

static void mga2_pic_irq_mask(struct irq_data *d)
{
	unsigned long flags;
	struct mga2_pic *mpic = irq_data_get_irq_chip_data(d);
	spin_lock_irqsave(&mpic->mask_lock, flags);
	mpic->irq_en_mask &= ~(1 << d->hwirq);
	spin_unlock_irqrestore(&mpic->mask_lock, flags);
	__wint(1 << d->hwirq, INTENA);
}

static void mga2_pic_irq_unmask(struct irq_data *d)
{
	unsigned long flags;
	struct mga2_pic *mpic = irq_data_get_irq_chip_data(d);
	spin_lock_irqsave(&mpic->mask_lock, flags);
	mpic->irq_en_mask |= 1 << d->hwirq;
	spin_unlock_irqrestore(&mpic->mask_lock, flags);
	__wint((1 << d->hwirq) | MGA2_INT_B_SETRST, INTENA);
}

static struct irq_chip mga2_pic_irq_chip = {
	.name = "mga2-mpic",
	.irq_mask = mga2_pic_irq_mask,
	.irq_unmask = mga2_pic_irq_unmask,
};

static int mga2_pic_irqdomain_map(struct irq_domain *d,
				unsigned int irq, irq_hw_number_t hwirq)
{
	struct mga2_pic *mpic = d->host_data;
	irq_set_chip_and_handler(irq,
				 &mga2_pic_irq_chip, handle_simple_irq);
	irq_set_chip_data(irq, mpic);
	return 0;
}

static const struct irq_domain_ops mga2_pic_hw_irqdomain_ops = {
	.xlate = irq_domain_xlate_onecell,
	.map = mga2_pic_irqdomain_map,
};

static int mga2_pic_probe(struct platform_device *pdev)
{
	int ret, irq;
	struct device *dev = &pdev->dev;
	struct device *parent = dev->parent;
	struct resource *res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	struct mga2_pic *mpic = devm_kzalloc(dev, sizeof(*mpic),
						GFP_KERNEL);
	if (!mpic)
		return -ENOMEM;
	if (WARN_ON(!dev_is_pci(parent))) {
		ret = -ENODEV;
		goto out;
	}

	mpic->dev_id = mga2_get_version(parent);
	irq = to_pci_dev(parent)->irq;
	if (mpic->dev_id == MGA20) {
		irq++;
	} else if (mpic->dev_id == MGA26 || mpic->dev_id == MGA26_PROTO) {
		int i, numvecs = ARRAY_SIZE(mpic->msix_entries);

		for (i = 0; i < numvecs; i++)
			mpic->msix_entries[i].entry = i;

		ret = pci_enable_msix_range(to_pci_dev(parent),
					mpic->msix_entries,
					numvecs,
					numvecs);
		if (WARN_ON(ret < 0))
			goto out;
		irq = mpic->msix_entries[0].vector;
	}
	ret = devm_request_irq(dev, irq, mga2_pic_irq_handler,
				0, dev_name(dev), mpic);
	if (WARN_ON(ret))
		goto out;


	mpic->regs = devm_ioremap_resource(dev, res);
	if (IS_ERR(mpic->regs))
		return PTR_ERR(mpic->regs);

	mpic->irq_domain = irq_domain_add_linear(dev->of_node, 31,
					&mga2_pic_hw_irqdomain_ops, mpic);
	if (WARN_ON(!mpic->irq_domain)) {
		ret = -ENODEV;
		goto out;
	}

	dev_set_drvdata(dev, mpic);
out:
	return ret;
}

static int mga2_pic_remove(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct device *parent = dev->parent;
	struct mga2_pic *mpic = dev_get_drvdata(dev);
	irq_domain_remove(mpic->irq_domain);
	if (mpic->dev_id == MGA26 || mpic->dev_id == MGA26_PROTO) {
		int irq = mpic->msix_entries[0].vector;
		/*Just to make pci_disable_msix() happy */
		devm_free_irq(dev, irq, mpic);
		pci_disable_msix(to_pci_dev(parent));
	}
	dev_set_drvdata(dev, NULL);

	return 0;
}

static const struct of_device_id mga2_pic_dt_match[] = {
	{ .compatible = "mcst,mga2x-pic" },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, mga2_pic_dt_match);

struct platform_driver mga2_pic_driver = {
	.probe = mga2_pic_probe,
	.remove = mga2_pic_remove,
	.driver = {
		.name = "mga2-pic",
		.of_match_table = of_match_ptr(mga2_pic_dt_match),
	},
};
