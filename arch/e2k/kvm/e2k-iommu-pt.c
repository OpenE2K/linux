/*
 * This file contains simple support for passthrough using two-stage IOMMU translation.
 *
 * 1. Save a list of all passed devices using e2k_iommu_set_kvm_device
 * 2. When guest enables IOMMU (e2k_iommu_guest_write_ctrl) -
 * call e2k_iommu_setup_guest_2d_dte for each device from the list
 * 3. Shutdown the VM, if guest enabled IOMMU with device tree support
 * (only e2k-iommu=no-domains is supported)
 * 4. Implement guest flushes in KVM. No need to forward them to QEMU (it doesn't have caches)
 */

#undef	DEBUG_PASSTHROUGH_MODE
#undef	DebugPT
#define	DEBUG_PASSTHROUGH_MODE	0	/* IOMMU Passthrough debugging */
#define	DebugPT(fmt, args...)					\
({								\
	if (DEBUG_PASSTHROUGH_MODE || kvm_debug)		\
		pr_info("%s(): " fmt, __func__, ##args);	\
})

#ifdef CONFIG_KVM_HOST_MODE
/* Handle intercepted guest writes and reads */
void e2k_iommu_guest_write_ctrl(u32 reg_value)
{
	if (reg_value & IOMMU_CTRL_ENAB)
		DebugPT("e2k-iommu: guest enabled IOMMU support %s\n",
			reg_value & IOMMU_CTRL_DEV_TABLE_EN ?
			"with device table enabled: passthrough not supported" :
			"with device table disabled: passthrough supported");
}

void e2k_iommu_flush_guest(struct kvm *kvm, u64 command)
{
	struct irq_remap_table *irt = kvm->arch.irt;
	u32 edid = (u32) kvm->arch.vmid.nr | E2K_IOMMU_EDID_GUEST_MASK;
	struct device *dev;
	struct e2k_iommu *iommu;
	union iommu_cmd_c reg;

	dev = &irt->vfio_dev->dev;
	iommu = dev_to_iommu(dev);

	reg.raw = command;

	if (!reg.bits.rs) {
		pr_err("e2k-iommu: ignore guests's command without cmd_c.rs\n");
		return;
	}

	switch (reg.bits.code) {
	case FL_PTE:
		e2k_iommu_flush(iommu, reg.bits.addr << IO_PAGE_SHIFT, edid,
			FL_PTE);
		break;
	case FL_ALL:
		e2k_iommu_flush(iommu, 0, edid, FL_ID);
		break;
	default:
		pr_err("e2k-iommu: ignore unsupported guest's command %d\n",
			reg.bits.code);
		break;
	}
}

/* Enable second level of guest DMA translation */
void e2k_iommu_setup_guest_2d_dte(struct kvm *kvm, u64 g_page_table)
{
	struct irq_remap_table *irt = kvm->arch.irt;
	struct device *dev;
	struct e2k_iommu *iommu;
	struct e2k_iommu_domain *domain;
	struct dte *dte_old, dte_new;
	unsigned long flags;

	dev = &irt->vfio_dev->dev;
	iommu = dev_to_iommu(dev);
	domain = to_e2k_domain(iommu_get_domain_for_dev(dev));
	dte_old = dev_to_dte(iommu, dev);

	memcpy(&dte_new, dte_old, sizeof(struct dte));

	dte_new.g_enable = 1;
	dte_new.g_cached = 1;
	dte_new.g_addr_width = E2K_DTE_HVAW_48_BITS;
	dte_new.g_page_table = g_page_table >> IO_PAGE_SHIFT;

	spin_lock_irqsave(&iommu->lock, flags);

	memcpy(dte_old, &dte_new, sizeof(struct dte));

	spin_unlock_irqrestore(&iommu->lock, flags);

	e2k_iommu_flush_domain(domain);
}
#endif
