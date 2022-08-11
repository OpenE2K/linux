#include <linux/kvm_host.h>
#include <linux/kvm.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/smp.h>
#include <linux/hrtimer.h>
#include <linux/io.h>
#include <linux/pci.h>
#include <asm/processor.h>
#include <asm/page.h>
#include <asm/current.h>
#include <asm/e2k_debug.h>
#include <trace/events/kvm.h>
#include <asm/kvm/trace_kvm.h>

#include <asm/io_epic.h>

#include "ioepic.h"
#include "pic.h"
#include "irq.h"
#include "mmu.h"

#if 0
#define ioepic_debug(fmt, arg...) pr_err(fmt, ##arg)
#else
#define ioepic_debug(fmt, arg...)
#endif

#undef	DEBUG_IRQ_DELIVER_MODE
#undef	DebugIRQ
#define	DEBUG_IRQ_DELIVER_MODE	0	/* IRQ deliver debugging */
#define	DebugIRQ(fmt, args...)						\
({									\
	if (DEBUG_IRQ_DELIVER_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_COALESCED_IRQ_MODE
#undef	DebugCIRQ
#define	DEBUG_COALESCED_IRQ_MODE	0	/* Coalesced IRQ debugging */
#define	DebugCIRQ(fmt, args...)						\
({									\
	if (DEBUG_COALESCED_IRQ_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_IOEPIC_MODE
#undef	DebugIOEPIC
#define	DEBUG_IOEPIC_MODE	0	/* IOEPIC base debugging */
#define	DebugIOEPIC(fmt, args...)					\
({									\
	if (DEBUG_IOEPIC_MODE || kvm_debug)				\
		pr_info("%s(): " fmt, __func__, ##args);		\
})


static int ioepic_deliver_to_cepic(struct kvm_ioepic *ioepic, int irq);

static int ioepic_service(struct kvm_ioepic *ioepic, unsigned int idx)
{
	struct IO_EPIC_route_entry *entry;
	int injected = -1;

	entry = &ioepic->redirtbl[idx];

	if (!entry->int_ctrl.bits.mask) {
		injected = ioepic_deliver_to_cepic(ioepic, idx);
		/* Set delivery_status bit for level interrupts */
		if (injected && entry->int_ctrl.bits.trigger)
			entry->int_ctrl.bits.delivery_status = 1;
		DebugIRQ("IRQ #%d was %s\n", idx,
			(injected) ? "injected" : "not injected");
	}

	return injected;
}

void kvm_make_scan_ioepic_request(struct kvm *kvm)
{
	kvm_make_all_cpus_request(kvm, KVM_REQ_SCAN_IOEPIC);
}

void kvm_vcpu_request_scan_ioepic(struct kvm *kvm)
{
	int i;

	for (i = 0; i < kvm->arch.num_numa_nodes; i++) {
		struct kvm_ioepic *ioepic = kvm->arch.ioepic[i];

		if (!ioepic)
			return;
	}
	kvm_make_scan_ioepic_request(kvm);
}

int ioepic_deliver_to_cepic(struct kvm_ioepic *ioepic, int irq)
{
	struct IO_EPIC_route_entry *entry = &ioepic->redirtbl[irq];
	struct kvm_cepic_irq irqe;

	ioepic_debug("dest=%x vector=%x trig_mode=%x dlvm=%x\n",
		     entry->addr_low.bits.dst, entry->msg_data.bits.vector,
		     entry->int_ctrl.bits.trigger, entry->msg_data.bits.dlvm);

	irqe.dest_id = entry->addr_low.bits.dst;
	irqe.vector = entry->msg_data.bits.vector;
	irqe.trig_mode = entry->int_ctrl.bits.trigger;
	irqe.delivery_mode = entry->msg_data.bits.dlvm;
	irqe.shorthand = CEPIC_ICR_DST_FULL;

	return kvm_irq_delivery_to_epic(ioepic->kvm, ioepic->id, &irqe);
}

int kvm_ioepic_set_irq(struct kvm_ioepic *ioepic, int irq, int pin_status)
{
	u32 old_irr;
	u32 mask = 1 << irq;
	struct IO_EPIC_route_entry entry;
	int ret = 1;

	mutex_lock(&ioepic->lock);
	old_irr = ioepic->irr;
	if (irq >= 0 && irq < IOEPIC_NUM_PINS) {
		entry = ioepic->redirtbl[irq];
		if (!pin_status) {
			ioepic->irr &= ~mask;
		} else {
			int level = entry.int_ctrl.bits.trigger;

			ioepic->irr |= mask;
			if ((!level && old_irr != ioepic->irr) ||
			    (level && !entry.int_ctrl.bits.delivery_status)) {
				ret = ioepic_service(ioepic, irq);
			} else {
				DebugCIRQ("IRQ #%d is coalesced\n", irq);
				ret = 0; /* report coalesced interrupt */
			}
		}
		trace_kvm_ioepic_set_irq(entry.addr_low.bits.dst,
			entry.msg_data.bits.vector, entry.msg_data.bits.dlvm,
			entry.int_ctrl.bits.trigger, entry.int_ctrl.bits.mask,
			irq, pin_status, ret == 0);
	}
	mutex_unlock(&ioepic->lock);

	return ret;
}

/* TODO Only node 0 is supported */
static void ioepic_notify_acked_irq(struct kvm_ioepic *ioepic, unsigned int pin)
{
	/*
	 * We are dropping lock while calling ack notifiers because ack
	 * notifier callbacks for assigned devices call into IOEPIC
	 * recursively
	 */
	mutex_unlock(&ioepic->lock);
	kvm_notify_acked_irq(ioepic->kvm, KVM_IRQCHIP_IOEPIC_NODE0, pin);
	mutex_lock(&ioepic->lock);
}

static void __kvm_ioepic_update_eoi(struct kvm_ioepic *ioepic, int vector,
				     int trigger_mode)
{
	int i;

	for (i = 0; i < IOEPIC_NUM_PINS; i++) {
		struct IO_EPIC_route_entry *ent = &ioepic->redirtbl[i];

		if (ent->msg_data.bits.vector != vector)
			continue;

		ioepic_notify_acked_irq(ioepic, i);
	}
}

/* In ioapic, this is called from LAPIC's EOI */
void kvm_ioepic_update_eoi(struct kvm_vcpu *vcpu, int vector, int trigger_mode)
{
	struct kvm_ioepic *ioepic = vcpu->kvm->arch.ioepic[vcpu->arch.node_id];

	mutex_lock(&ioepic->lock);
	__kvm_ioepic_update_eoi(ioepic, vector, trigger_mode);
	mutex_unlock(&ioepic->lock);
}

static inline struct kvm_ioepic *to_ioepic(struct kvm_io_device *dev)
{
	return container_of(dev, struct kvm_ioepic, dev);
}

static inline int ioepic_in_range(struct kvm_ioepic *ioepic, gpa_t addr)
{
	return ((addr >= ioepic->base_address &&
		 (addr < ioepic->base_address + IOEPIC_MEM_LENGTH)));
}

/* Only latest version of IOEPIC is supported */
static inline unsigned int ioepic_read_version(void)
{
	union IO_EPIC_VERSION reg;

	reg.raw = 0;
	reg.bits.version = IOEPIC_VERSION_2;
	reg.bits.entries = IOEPIC_NUM_PINS;

	return reg.raw;
}

static int ioepic_mmio_read(struct kvm_vcpu *vcpu, struct kvm_io_device *this,
				gpa_t addr, int len, void *val)
{
	struct kvm_ioepic *ioepic = to_ioepic(this);
	unsigned int offset = addr - ioepic->base_address;
	unsigned int reg_offset = offset & 0xfff;
	unsigned int pin = offset >> 12;
	unsigned int result;
	struct irq_remap_table *irt = vcpu->kvm->arch.irt;

	if (!ioepic_in_range(ioepic, addr))
		return -EOPNOTSUPP;

	ASSERT(len == 4); /* 4 bytes access */

	/* In case of passthrough device, read directly from real IOEPIC */
	if (irt->enabled && pin == irt->guest_pin) {
		unsigned int host_pin_offset = irt->host_pin << 12;
		unsigned int node = irt->host_node;

		E2K_LMS_HALT_ERROR(1);
		pr_err("%s(): error: IOEPIC passthrough page not mapped\n",
			__func__);

		result = io_epic_read(node, host_pin_offset + reg_offset);
		*(u32 *) val = result;
		ioepic_debug("passthrough ioepic read offset %x val %x\n",
			offset, result);
		return 0;
	}

	mutex_lock(&ioepic->lock);
	switch (reg_offset) {
	case IOEPIC_ID:
		result = ioepic->id;
		break;
	case IOEPIC_VERSION:
		result = ioepic_read_version();
		break;
	case IOEPIC_TABLE_INT_CTRL(0):
		result = ioepic->redirtbl[pin].int_ctrl.raw;
		break;
	case IOEPIC_TABLE_MSG_DATA(0):
		result = ioepic->redirtbl[pin].msg_data.raw;
		break;
	case IOEPIC_TABLE_ADDR_HIGH(0):
		result = ioepic->redirtbl[pin].addr_high;
		break;
	case IOEPIC_TABLE_ADDR_LOW(0):
		result = ioepic->redirtbl[pin].addr_low.raw;
		break;
	default:
		if (reg_offset >= IOEPIC_INT_RID(0) &&
			reg_offset < IOEPIC_INT_RID(IOEPIC_NUM_PINS)) {
			result = 0;
		} else {
			ioepic_debug("unknown ioepic reg 0x%x\n", offset);
			result = 0xffffffff;
		}
		break;
	}
	mutex_unlock(&ioepic->lock);

	*(u32 *) val = result;

	ioepic_debug("%s offset %x val %x\n", __func__, offset, result);

	return 0;
}

/* TODO software interrupts not fully supported */
static void ioepic_write_int_ctrl(struct kvm_ioepic *ioepic, unsigned int pin,
					unsigned int data)
{
	union IO_EPIC_INT_CTRL old_val, new_val;
	bool eoi, sint_eoi, unmasking, irr_pending;

	old_val.raw = ioepic->redirtbl[pin].int_ctrl.raw;
	new_val.raw = data;

	eoi = new_val.bits.delivery_status;
	sint_eoi = new_val.bits.software_int;

	/*
	 * Fire ack notifiers (used by irqfd resampler for INTx passthrough)
	 * Notifier will de-assert the pin; check interrupt status in the device and
	 * either unmask the interrupt, or re-assert the pin without unmasking.
	 * Keeping devlivery_status asserted to make sure we don't inject an interrupt twice
	 */
	if (eoi)
		ioepic_notify_acked_irq(ioepic, pin);

	/* Writing R/W1C fields does not change the RW bits (IOEPIC ver. 2) */
	if (eoi || sint_eoi) {
		new_val.raw = old_val.raw;

		if (eoi)
			new_val.bits.delivery_status = 0;

		if (sint_eoi)
			new_val.bits.software_int = 0;
	}
	ioepic->redirtbl[pin].int_ctrl.raw = new_val.raw;

	unmasking = old_val.bits.mask && !new_val.bits.mask;
	irr_pending = ioepic->irr & (1 << pin);

	if (!new_val.bits.mask && irr_pending) {
		if (!eoi && !unmasking)
			pr_err("kvm_ioepic: firing pin %d, not eoi/unmasking\n", pin);

		ioepic_service(ioepic, pin);
	}
}

static int ioepic_mmio_write(struct kvm_vcpu *vcpu, struct kvm_io_device *this,
				 gpa_t addr, int len, const void *val)
{
	struct kvm_ioepic *ioepic = to_ioepic(this);
	unsigned int offset = addr - ioepic->base_address;
	unsigned int reg_offset = offset & 0xfff;
	unsigned int pin = offset >> 12;
	unsigned int data = *(u32 *) val;
	struct irq_remap_table *irt = vcpu->kvm->arch.irt;

	if (!ioepic_in_range(ioepic, addr))
		return -EOPNOTSUPP;

	ASSERT(len == 4); /* 4 bytes access */

	/* In case of passthrough device, write directly to real IOEPIC */
	if (irt->enabled && pin == irt->guest_pin) {
		unsigned int host_pin_offset = irt->host_pin << 12;
		unsigned int node = irt->host_node;
		struct iohub_sysdata *sd = irt->vfio_dev->bus->sysdata;

		E2K_LMS_HALT_ERROR(1);
		pr_err("%s(): error: IOEPIC passthrough page not mapped\n",
			__func__);

		switch (reg_offset) {
		case IOEPIC_TABLE_ADDR_HIGH(0):
			if (data != sd->pci_msi_addr_hi) {
				pr_err("kvm_ioepic: guest's RT_MSI_HI (0x%x) does not match host's RT_MSI_HI (0x%x)\n",
					data, sd->pci_msi_addr_hi);
				data = sd->pci_msi_addr_hi;
			}
			break;
		case IOEPIC_TABLE_ADDR_LOW(0):
			if (data != sd->pci_msi_addr_lo) {
				pr_err("kvm_ioepic: guest's RT_MSI_LO (0x%x) does not match host's RT_MSI_LO (0x%x)\n",
					data, sd->pci_msi_addr_lo);
				data = sd->pci_msi_addr_lo;
			}
			break;
		}

		ioepic_debug("passthrough ioepic write offset %x val %x\n",
			offset, data);
		io_epic_write(node, host_pin_offset + reg_offset, data);
		return 0;
	}

	ioepic_debug("%s offset %x val %x\n", __func__, offset, data);

	mutex_lock(&ioepic->lock);
	switch (reg_offset) {
	case IOEPIC_ID:
		ioepic->id = data;
		break;
	case IOEPIC_VERSION:
		break;
	case IOEPIC_TABLE_INT_CTRL(0):
		ioepic_write_int_ctrl(ioepic, pin, data);
		break;
	case IOEPIC_TABLE_MSG_DATA(0):
		ioepic->redirtbl[pin].msg_data.raw = data;
		break;
	case IOEPIC_TABLE_ADDR_HIGH(0):
		ioepic->redirtbl[pin].addr_high = data;
		break;
	case IOEPIC_TABLE_ADDR_LOW(0):
		ioepic->redirtbl[pin].addr_low.raw = data;
		break;
	default:
		if (!(reg_offset >= IOEPIC_INT_RID(0) &&
			reg_offset < IOEPIC_INT_RID(IOEPIC_NUM_PINS)))
			ioepic_debug("unknown ioepic reg 0x%x\n", offset);
		break;
	}
	mutex_unlock(&ioepic->lock);

	return 0;
}

void kvm_ioepic_reset(struct kvm_ioepic *ioepic)
{
	int i;

	for (i = 0; i < IOEPIC_NUM_PINS; i++)
		ioepic->redirtbl[i].int_ctrl.bits.mask = 1;

	ioepic->base_address = IOEPIC_DEFAULT_BASE_ADDRESS;
	ioepic->id = 0;
}

static const struct kvm_io_device_ops ioepic_mmio_ops = {
	.read     = ioepic_mmio_read,
	.write    = ioepic_mmio_write,
};

int kvm_ioepic_init(struct kvm *kvm)
{
	struct kvm_ioepic *ioepic;
	int i;
	int ret = -EPERM;

	for (i = 0; i < kvm->arch.num_numa_nodes; i++) {
		ioepic = kzalloc(sizeof(struct kvm_ioepic), GFP_KERNEL);
		if (!ioepic) {
			ret = -ENOMEM;
			goto out;
		}
		mutex_init(&ioepic->lock);
		kvm->arch.ioepic[i] = ioepic;
		kvm_ioepic_reset(ioepic);
		kvm_iodevice_init(&ioepic->dev, &ioepic_mmio_ops);
		ioepic->kvm = kvm;
		ret = kvm_io_bus_register_dev(kvm, KVM_MMIO_BUS,
			ioepic->base_address, IOEPIC_MEM_LENGTH, &ioepic->dev);
out:		if (ret < 0) {
again:			kfree(kvm->arch.ioepic[i]);
			kvm->arch.ioepic[i] = NULL;
			if (i) {
				i--;
				kvm_io_bus_unregister_dev(kvm, KVM_MMIO_BUS,
					&kvm->arch.ioepic[i]->dev);
				goto again;
			}
			return ret;
		}
	}

	return ret;
}

void kvm_ioepic_destroy(struct kvm *kvm)
{
	int i;

	for (i = 0; i < kvm->arch.num_numa_nodes; i++) {
		struct kvm_ioepic *ioepic = kvm->arch.ioepic[i];

		if (!ioepic)
			return;

		mutex_lock(&kvm->slots_lock);
		kvm_io_bus_unregister_dev(kvm, KVM_MMIO_BUS, &ioepic->dev);
		mutex_unlock(&kvm->slots_lock);
		kvm->arch.ioepic[i] = NULL;
		kfree(ioepic);
	}
}

int kvm_ioepic_set_base(struct kvm *kvm, unsigned long new_base, int node_id)
{
	struct kvm_ioepic *ioepic;
	int ret;
	struct irq_remap_table *irt = kvm->arch.irt;

	ioepic = kvm->arch.ioepic[node_id];

	if (!ioepic) {
		pr_err("%s(): IOEPIC is not yet created, ignore setup\n",
			__func__);
		return -ENODEV;
	}
	if (ioepic->base_address == new_base) {
		DebugIOEPIC("%s(): IOEPIC base 0x%lx is the same, "
			"so ignore update\n",
			__func__, new_base);
		return 0;
	} else if (new_base == 0xffffffff) {
		DebugIOEPIC("%s(): ignore probing write to IOEPIC BAR\n", __func__);
		return 0;
	}

	mutex_lock(&kvm->slots_lock);
	kvm_io_bus_unregister_dev(kvm, KVM_MMIO_BUS, &ioepic->dev);
	ioepic->base_address = new_base;
	kvm_iodevice_init(&ioepic->dev, &ioepic_mmio_ops);
	ret = kvm_io_bus_register_dev(kvm, KVM_MMIO_BUS, new_base,
				      IOEPIC_MEM_LENGTH, &ioepic->dev);
	mutex_unlock(&kvm->slots_lock);
	if (ret < 0) {
		kvm->arch.ioepic[node_id] = NULL;
		kfree(ioepic);
		pr_err("%s(): could not register IOEPIC as MMIO bus device, "
			"error %d\n",
			__func__, ret);

		return ret;
	}

	if (kvm->arch.is_hv && irt->enabled && irt->guest_node == node_id) {
		gpa_t new_gpa = new_base + (irt->guest_pin << PAGE_SHIFT);

		if (irt->gpa) {
			/*
			 * Not first time mapping this page, need to unmap first
			 */

			gfn_t gfn = gpa_to_gfn(irt->gpa);

			/* This will request TLB flushes */
			direct_unmap_prefixed_mmio_gfn(kvm, gfn);
			pr_info("%s(): Unmapping IOEPIC passthrough page GPA 0x%llx -> HPA 0x%llx\n",
				__func__, irt->gpa, irt->hpa);
		}

		/*
		 * Mapping is done on demand (nonpaging/tdp_page_fault)
		 * Prefetching is impossible, since we don't know, which
		 * VCPU changed base from VM IOCTL
		 */
		irt->gpa = new_gpa;
	}

	return 0;
}

/* KVM_GET/SET_IRQCHIP is not yet supported for IOEPIC */

#if 0
int kvm_get_ioepic(struct kvm *kvm, struct kvm_ioepic_state *state)
{
	struct kvm_ioepic *ioepic = ioepic_irqchip(kvm);

	if (!ioepic)
		return -EINVAL;

	mutex_lock(&ioepic->lock);
	memcpy(state, ioepic, sizeof(struct kvm_ioepic_state));
	mutex_unlock(&ioepic->lock);
	return 0;
}

int kvm_set_ioepic(struct kvm *kvm, struct kvm_ioepic_state *state)
{
	struct kvm_ioepic *ioepic = ioepic_irqchip(kvm);

	if (!ioepic)
		return -EINVAL;

	mutex_lock(&ioepic->lock);
	memcpy(ioepic, state, sizeof(struct kvm_ioepic_state));
	mutex_unlock(&ioepic->lock);
	return 0;
}
#endif
