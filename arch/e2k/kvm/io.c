/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */


#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/init.h>
#include <linux/tty.h>
#include <linux/kvm_host.h>
#include <kvm/iodev.h>

#include <asm/io.h>
#include <asm/spmc_regs.h>

#include <asm/kvm/hypercall.h>

#include "cpu.h"
#include "mmu.h"
#include "io.h"
#include "pic.h"
#include "intercepts.h"
# ifdef CONFIG_KVM_PARAVIRTUALIZATION
#include "paravirt_sw/gaccess.h"
#include <asm/kvm/paravirt_sw/host_printk.h>
# endif /* CONFIG_KVM_PARAVIRTUALIZATION */

#include <trace/events/kvm.h>
#include <asm/kvm/trace_kvm_hv.h>
#include <asm/kvm/trace_kvm.h>

#undef	DEBUG_KVM_IO_MODE
#undef	DebugKVMIO
#define	DEBUG_KVM_IO_MODE	0	/* kernel virt machine IO debugging */
#define	DebugKVMIO(fmt, args...)					\
({									\
	if (DEBUG_KVM_IO_MODE)						\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_IO_FAULT_MODE
#undef	DebugIOPF
#define	DEBUG_IO_FAULT_MODE	0	/* IO port page fault debugging */
#define	DebugIOPF(fmt, args...)						\
({									\
	if (DEBUG_IO_FAULT_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_MMIO_FAULT_MODE
#undef	DebugMMIOPF
#define	DEBUG_MMIO_FAULT_MODE	0	/* MMIO page fault debugging */
#define	DebugMMIOPF(fmt, args...)					\
({									\
	if (DEBUG_MMIO_FAULT_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#define	DIRECT_IO_PORT_ACCESS	0	/* do direct access to IO port from */
					/* here */

static int copy_io_intc_info_data(void *mmio_data, volatile void *intc_data,
		volatile void *intc_data_ext, gpa_t gpa, int size, bool to_intc)
{
	switch (size) {
	case 1: {
		u8 *mmio = mmio_data;
		volatile u8 *intc = intc_data;

		if (to_intc) {
			*intc = *mmio;
		} else {
			int u8_no = (gpa & (sizeof(u64) - 1)) >> 0;
			*mmio = intc[u8_no];
		}
		return 0;
	}
	case 2: {
		u16 *mmio = mmio_data;
		volatile u16 *intc = intc_data;

		if (to_intc) {
			*intc = *mmio;
		} else {
			int u16_no = (gpa & (sizeof(u64) - 1)) >> 1;
			*mmio = intc[u16_no];
		}
		return 0;
	}
	case 4: {
		u32 *mmio = mmio_data;
		volatile u32 *intc = intc_data;

		if (to_intc) {
			*intc = *mmio;
		} else {
			int u32_no = (gpa & (sizeof(u64) - 1)) >> 2;
			u64 val;
			u8 tag;

			load_value_and_tagd(intc, &val, &tag);
			if (!u32_no && (tag & 0x3) || u32_no && (tag & 0xc))
				pr_info_ratelimited("kvm: tagged write to I/O 0x%llx\n", gpa);

			*mmio = (u32_no) ? (val >> 32) : (u32)val;
		}
		return 0;
	}
	case 8: {
		u64 *mmio = mmio_data;
		volatile u64 *intc = intc_data;

		if (to_intc) {
			*intc = *mmio;
		} else {
			u64 val;
			u8 tag;

			load_value_and_tagd(intc, &val, &tag);
			if (tag)
				pr_info_ratelimited("kvm: tagged write to I/O 0x%llx\n", gpa);

			*mmio = val;
		}
		return 0;
	}
	case 16: {
		u64 *mmio = mmio_data;
		volatile u64 *intc = intc_data;
		volatile u64 *intc_ext = intc_data_ext;

		if (!intc_ext)
			return -EINVAL;

		if (to_intc) {
			*intc = mmio[0];
			*intc_ext = mmio[1];
		} else {
			u64 val_lo, val_hi;
			u8 tag_lo, tag_hi;

			load_value_and_tagd(intc, &val_lo, &tag_lo);
			load_value_and_tagd(intc_ext, &val_hi, &tag_hi);
			if (tag_lo || tag_hi)
				pr_info_ratelimited("kvm: tagged write to I/O 0x%llx\n", gpa);

			mmio[0] = val_lo;
			mmio[1] = val_hi;
		}
		return 0;
	}
	default:
		return -EINVAL;
	}
}

int vcpu_mmio_write(struct kvm_vcpu *vcpu, gpa_t addr, int len,
			   const void *v)
{
	if (vcpu->arch.apic && !kvm_iodevice_write(vcpu, &vcpu->arch.apic->dev, addr, len, v))
		return 0;

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	if (vcpu->arch.epic &&
		!kvm_iodevice_write(vcpu, &vcpu->arch.epic->dev, addr, len, v))
		return 0;
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

	return kvm_io_bus_write(vcpu, KVM_MMIO_BUS, addr, len, v);
}

int vcpu_mmio_read(struct kvm_vcpu *vcpu, gpa_t addr, int len, void *v)
{
	if (vcpu->arch.apic && !kvm_iodevice_read(vcpu, &vcpu->arch.apic->dev, addr, len, v))
		return 0;

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	if (vcpu->arch.epic &&
		!kvm_iodevice_read(vcpu, &vcpu->arch.epic->dev, addr, len, v))
		return 0;
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

	return kvm_io_bus_read(vcpu, KVM_MMIO_BUS, addr, len, v);
}

static void complete_intc_info_io_write(struct kvm_vcpu *vcpu,
					intc_info_mu_t *intc_info_mu)
{
	/*
	 * For stores - delete this entry from INTC_INFO_MU.
	 *
	 * For qword/qword_qp handling see restore_intc_info_mu().
	 */
	kvm_delete_intc_info_mu(vcpu, intc_info_mu);
	trace_complete_intc_info_io_write(intc_info_mu->gpa,
		intc_info_mu->data, intc_info_mu->data_ext);
}

static void complete_intc_info_io_read(struct kvm_vcpu *vcpu,
					intc_info_mu_t *intc_info_mu)
{
	/*
	 * For loads - change the event_code to MMU reg read.
	 * Data will be read from the INTC_INFO_MU.
	 *
	 * For qword/qword_qp handling see restore_intc_info_mu().
	 */
	intc_info_mu->hdr.event_code = IME_READ_MU;
	kvm_set_intc_info_mu_is_updated(vcpu);
	trace_complete_intc_info_io_read(intc_info_mu->gpa,
		intc_info_mu->data, intc_info_mu->data_ext);
}

static int vcpu_mmio_local_write(struct kvm_vcpu *vcpu, gpa_t gpa,
				int size, intc_info_mu_t *intc_info_mu)
{
	unsigned long data;
	int ret;

	ret = copy_io_intc_info_data(&data, &intc_info_mu->data,
			&intc_info_mu->data_ext, gpa, size, false);
	if (ret)
		return ret;

	ret = vcpu_mmio_write(vcpu, gpa, size, &data);
	if (ret != 0) {
		/* cannot be handled locally */
		return ret;
	}

	complete_intc_info_io_write(vcpu, intc_info_mu);
	return 0;
}

static int vcpu_mmio_local_read(struct kvm_vcpu *vcpu, gpa_t gpa,
				int size, intc_info_mu_t *intc_info_mu)
{
	unsigned long data[2];
	int ret;

	ret = vcpu_mmio_read(vcpu, gpa, size, &data);
	if (ret != 0) {
		/* cannot be handled locally */
		return ret;
	}

	ret = copy_io_intc_info_data(&data, &intc_info_mu->data,
			&intc_info_mu->data_ext, gpa, size, true);
	if (ret)
		return ret;

	complete_intc_info_io_read(vcpu, intc_info_mu);
	return 0;
}

static void vcpu_mmio_prepare_request(struct kvm_vcpu *vcpu,
			gpa_t gpa, void *mmio_data, int size, bool is_write)
{
	struct kvm_mmio_fragment *frag = NULL;

	BUG_ON(vcpu->mmio_nr_fragments != 0);

	frag = &vcpu->mmio_fragments[vcpu->mmio_nr_fragments++];
	vcpu->mmio_needed = 1;
	frag->gpa = gpa;
	frag->len = size;
	frag->data = mmio_data;
	vcpu->mmio_is_write = is_write;

	vcpu->arch.exit_reason = EXIT_REASON_MMIO_REQ;
}

static pf_res_t kvm_hv_mmio_page_fault(struct kvm_vcpu *vcpu, gpa_t gpa,
		int size, bool is_write, intc_info_mu_t *intc_info_mu)
{
	int ret;

	DebugMMIOPF("started for GPA 0x%llx %s size %d byte(s)\n",
		gpa, (is_write) ? "write" : "read", size);
	/*
	 * Is this MMIO handled locally?
	 */
	if (is_write) {
		ret = vcpu_mmio_local_write(vcpu, gpa, size, intc_info_mu);
	} else {
		ret = vcpu_mmio_local_read(vcpu, gpa, size, intc_info_mu);
	}
	if (ret == 0) {
		/* Yes, MMIO is hadled locally */
		DebugMMIOPF("access to GPA 0x%llx %s size %d byte(s) was "
			"handled locally\n",
			gpa, (is_write) ? "write" : "read", size);
		return PFRES_NO_ERR;
	}

	/* MMIO request should be passed to user space emulation */
	if (is_write) {
		ret = copy_io_intc_info_data(vcpu->arch.mmio_data, &intc_info_mu->data,
				&intc_info_mu->data_ext, gpa, size, false);
		if (ret)
			return ret;

		DebugMMIOPF("write data 0x%llx data_ext 0x%llx to 0x%llx size %d byte(s)\n",
			vcpu->arch.mmio_data[0], vcpu->arch.mmio_data[1], gpa, size);
	}
	vcpu_mmio_prepare_request(vcpu, gpa, vcpu->arch.mmio_data, size,
					is_write);
	E2K_KVM_BUG_ON(vcpu->arch.io_intc_info != NULL);
	vcpu->arch.io_intc_info = intc_info_mu;

	DebugMMIOPF("access to GPA 0x%llx %s size %d byte(s) is passing "
		"to emulate at user space\n",
		gpa, (is_write) ? "write" : "read", size);
	return PFRES_TRY_MMIO;
}

static void vcpu_io_port_prepare_request(struct kvm_vcpu *vcpu,
			u16 port, int size, bool is_write)
{
	vcpu->arch.ioport.port = port;
	vcpu->arch.ioport.size = size;
	vcpu->arch.ioport.is_out = is_write;
	vcpu->arch.ioport.count = 1;
	vcpu->arch.ioport.string = 0;

	vcpu->arch.ioport.needed = 1;
	vcpu->arch.ioport.completed = 0;
	vcpu->arch.exit_reason = EXIT_REASON_IOPORT_REQ;
}

static pf_res_t kvm_hv_io_port_page_fault(struct kvm_vcpu *vcpu, gpa_t gpa,
			int size, bool is_write, intc_info_mu_t *intc_info_mu)
{
	u16 port = gpa - IO_AREA_PHYS_BASE;

	DebugIOPF("started for GPA 0x%llx, port 0x%x %s size %d byte(s)\n",
		gpa, port, (is_write) ? "write" : "read", size);

	/* IO port request should be passed to user space emulation */
	if (is_write) {
		int ret = copy_io_intc_info_data(&vcpu->arch.ioport.data,
				&intc_info_mu->data, NULL, gpa, size, false);
		if (ret)
			return ret;

		DebugIOPF("write data 0x%llx to port 0x%x size %d byte(s)\n",
			vcpu->arch.ioport.data, port, size);
	}
	vcpu_io_port_prepare_request(vcpu, port, size, is_write);
	E2K_KVM_BUG_ON(vcpu->arch.io_intc_info != NULL);
	vcpu->arch.io_intc_info = intc_info_mu;

	DebugIOPF("access to GPA 0x%llx port 0x%x %s size %d byte(s) is "
		"passing to emulate at user space\n",
		gpa, port, (is_write) ? "write" : "read", size);
	return PFRES_TRY_MMIO;
}

pf_res_t kvm_hv_io_page_fault(struct kvm_vcpu *vcpu, gpa_t gpa, intc_info_mu_t *intc_info_mu)
{
	tc_cond_t cond;
	tc_opcode_t opcode;
	bool is_write;
	bool spec;
	int size;

	cond = intc_info_mu->condition;
	is_write = !!cond.store;
	spec = !!cond.spec;

	if (spec && !is_write) {
		NATIVE_STORE_VALUE_WITH_TAG(&intc_info_mu->data, ITAGDWD_IO_DEBUG, ETAGDWD);
		NATIVE_STORE_VALUE_WITH_TAG(&intc_info_mu->data_ext, ITAGDWD_IO_DEBUG, ETAGDWD);
		complete_intc_info_io_read(vcpu, intc_info_mu);
		DebugKVMIO("speculative read from IO area - return diag value\n");
		return 0;
	}

	AW(opcode) = cond.opcode;
	E2K_KVM_BUG_ON(opcode.fmt == 0);
	size = 1 << (opcode.fmt - 1);

	if (gpa >= IO_AREA_PHYS_BASE &&
			gpa < IO_AREA_PHYS_BASE + IO_AREA_PHYS_SIZE) {
		return kvm_hv_io_port_page_fault(vcpu, gpa, size, is_write,
						intc_info_mu);
	} else {
		return kvm_hv_mmio_page_fault(vcpu, gpa, size, is_write,
						intc_info_mu);
	}
}

static int kvm_complete_hv_io_page_fault(struct kvm_vcpu *vcpu, gpa_t gpa,
			void *io_data, int size, bool is_write)
{
	intc_info_mu_t *intc_info_mu = vcpu->arch.io_intc_info;

	E2K_KVM_BUG_ON(intc_info_mu == NULL);
	vcpu->arch.io_intc_info = NULL;

	if (!is_write) {
		int ret = copy_io_intc_info_data(io_data, &intc_info_mu->data,
				&intc_info_mu->data_ext, gpa, size, true);
		if (ret)
			return ret;

		DebugIOPF("read from 0x%llx size %d byte(s)\n", gpa, size);
		complete_intc_info_io_read(vcpu, intc_info_mu);
	} else {
		complete_intc_info_io_write(vcpu, intc_info_mu);
	}
	return 0;
}

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
static unsigned long
kvm_complete_guest_mmio_read(struct kvm_vcpu *vcpu,
	u64 phys_addr, u64 *mmio_data, u64 *user_data, u8 size)
{
	int error;

	error = kvm_vcpu_copy_to_guest(vcpu, user_data, mmio_data,
					sizeof(*user_data));
	if (error) {
		DebugKVMIO("copy to guest (%px) to read from 0x%llx "
			"size %d failed\n",
			user_data, phys_addr, size);
		return error;
	}
	return 0;
}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

unsigned long kvm_complete_guest_mmio_request(struct kvm_vcpu *vcpu)
{
	struct kvm_mmio_fragment *frag = NULL;
	u64 *mmio_data;
	u64 phys_addr;
	u8 is_write;
	u8 size;
	int ret = 0;

	BUG_ON(vcpu->mmio_nr_fragments != 1);
	frag = &vcpu->mmio_fragments[--vcpu->mmio_nr_fragments];
	mmio_data = frag->data;
	phys_addr = frag->gpa;
	size = frag->len;
	is_write = vcpu->mmio_is_write;

	if (vcpu->mmio_read_completed) {
		if (!is_write) {
			*mmio_data &= (~0UL >> (64-(size*8)));
			DebugKVMIO("read data 0x%llx size %d from "
				"addr 0x%llx\n",
				*mmio_data, size, phys_addr);
		}
		vcpu->mmio_read_completed = 0;
	} else {
		DebugKVMIO("mmio request is not completed: data 0x%llx, "
			"size %d, addr 0x%llx\n",
			*mmio_data, size, phys_addr);
		*mmio_data = ~0UL;
	}
	if (vcpu->arch.io_intc_info != NULL) {
		ret = kvm_complete_hv_io_page_fault(vcpu, phys_addr,
					mmio_data, size, is_write);
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	} else {
		if (!is_write) {
			ret = kvm_complete_guest_mmio_read(vcpu, phys_addr,
					mmio_data, vcpu->arch.mmio_user_data, size);
		}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
	}

	frag->data = NULL;
	frag->len = 0;

	return ret;
}

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
unsigned long kvm_guest_mmio_request(struct kvm_vcpu *vcpu,
		u64 phys_addr, u64 *user_data, u8 size, u8 is_write)
{
	u64 *mmio_data = vcpu->arch.mmio_data;

	if (is_write) {
		int error;

		error = kvm_vcpu_copy_from_guest(vcpu, mmio_data, user_data,
						sizeof(*user_data));
		if (error) {
			DebugKVMIO("copy from guest (%px) to write to 0x%llx "
				"size %d failed\n",
				user_data, phys_addr, size);
			return error;
		}
		DebugKVMIO("started to write data 0x%llx size %d to "
			"addr 0x%llx\n",
			*mmio_data, size, phys_addr);
	} else {
		DebugKVMIO("started to read data size %d from addr 0x%llx\n",
			size, phys_addr);
	}

	/*
	 * Is this MMIO handled locally?
	 */
	if (is_write) {
		if (!vcpu_mmio_write(vcpu, phys_addr, size, mmio_data)) {
			trace_kvm_mmio(KVM_TRACE_MMIO_WRITE,
				size, phys_addr, mmio_data);
			DebugKVMIO("MMIO handled locally: phys addr 0x%llx "
				"size %d writen data 0x%llx\n",
				phys_addr, size, *mmio_data);
			return 0;
		}
	} else {
		*mmio_data = 0;
		if (!vcpu_mmio_read(vcpu, phys_addr, size, mmio_data)) {
			trace_kvm_mmio(KVM_TRACE_MMIO_READ,
				size, phys_addr, mmio_data);
			DebugKVMIO("MMIO handled locally: phys addr 0x%llx "
				"size %d read data 0x%llx\n",
				phys_addr, size, *mmio_data);
			return kvm_complete_guest_mmio_read(vcpu,
					phys_addr, mmio_data, user_data, size);
		}
	}

	vcpu_mmio_prepare_request(vcpu, phys_addr, mmio_data, size, is_write);
	vcpu->arch.mmio_user_data = user_data;

	if (!vcpu->arch.is_hv) {
		return RETURN_TO_HOST_APP_HCRET;
	} else {
		/* inject intercept as hypercall return to switch to */
		/* vcpu run thread and handle VM exit on IO access */
		kvm_inject_vcpu_exit(vcpu);
		return 0;
	}

	return kvm_complete_guest_mmio_request(vcpu);
}

static unsigned long
kvm_complete_guest_ioport_read(struct kvm_vcpu *vcpu,
			u32 port, u32 *data, u32 *user_data, u8 size)
{
	int error;

	error = kvm_vcpu_copy_to_guest(vcpu, user_data, &data[0],
					sizeof(*user_data));
	if (error) {
		DebugKVMIO("copy to guest (%px) to read from port 0x%x "
			"size %d failed\n",
			user_data, port, size);
		return error;
	}
	return 0;
}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

unsigned long kvm_complete_guest_ioport_request(struct kvm_vcpu *vcpu)
{
	u32 data[1];
	u32 port;
	u32 *user_data;
	u8 size;
	u8 is_out;
	int ret = 0;

	port = vcpu->arch.ioport.port;
	size = vcpu->arch.ioport.size;
	is_out = vcpu->arch.ioport.is_out;
	user_data = vcpu->arch.ioport.user_data;

	if (vcpu->arch.ioport.completed) {
		if (!is_out) {
			data[0] = vcpu->arch.ioport.data;
			data[0] &= (~0UL >> (64-(size*8)));
			DebugKVMIO("read data 0x%x size %d from port 0x%x\n",
				data[0], size, port);
		}
		vcpu->arch.ioport.completed = 0;
	} else {
		DebugKVMIO("IO port request is not completed: data 0x%llx, "
			"size %d, port 0x%x\n",
			vcpu->arch.ioport.data, size, port);
		data[0] = U32_MAX;
	}

	if (vcpu->arch.io_intc_info != NULL) {
		ret = kvm_complete_hv_io_page_fault(vcpu,
					port, data, size, is_out);
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	} else {
		if (!is_out) {
			ret = kvm_complete_guest_ioport_read(vcpu,
						port, data, user_data, size);
		}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
	}

	return ret;
}

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
unsigned long kvm_guest_ioport_request(struct kvm_vcpu *vcpu,
			u16 port, u32 *user_data, u8 size, u8 is_out)
{
	u32 data[1];
	unsigned long ret;

	if (is_out) {
		int error;

		error = kvm_vcpu_copy_from_guest(vcpu, &data[0], user_data,
						sizeof(*user_data));
		if (error) {
			DebugKVMIO("copy from guest (%px) to write to "
				"port 0x%x size %d failed\n",
				user_data, port, size);
			ret = error;
			goto out;
		}
		DebugKVMIO("write data 0x%x size %d to port 0x%x\n",
			data[0], size, port);
	} else {
		DebugKVMIO("read data size %d from port 0x%x\n",
			size, port);
	}

	if (DIRECT_IO_PORT_ACCESS) {
		if (is_out) {
			switch (size) {
			case 1:
				native_outb(data[0], port);
				break;
			case 2:
				native_outw(data[0], port);
				break;
			case 4:
				native_outl(data[0], port);
				break;
			default:
				DebugKVMIO("invalid size %d\n", size);
			}
		} else {
			switch (size) {
			case 1:
				data[0] = native_inb(port);
				break;
			case 2:
				data[0] = native_inw(port);
				break;
			case 4:
				data[0] = native_inl(port);
				break;
			default:
				DebugKVMIO("invalid size %d\n", size);
				data[0] = ~0U;
			}
			ret = kvm_complete_guest_ioport_read(vcpu,
						port, data, user_data, size);
			goto out;
		}
		ret = 0;
		goto out;
	}

	vcpu_io_port_prepare_request(vcpu, port, size, is_out);
	if (is_out) {
		vcpu->arch.ioport.data = data[0];
	}
	vcpu->arch.ioport.user_data = user_data;

	if (!vcpu->arch.is_hv) {
		return RETURN_TO_HOST_APP_HCRET;
	} else {
		/* inject intercept as hypercall return to switch to */
		/* vcpu run thread and handle VM exit on IO access */
		kvm_inject_vcpu_exit(vcpu);
		return 0;
	}

	return kvm_complete_guest_ioport_request(vcpu);

out:
	return ret;
}

unsigned long kvm_guest_ioport_string_request(struct kvm_vcpu *vcpu,
		u16 port, void *data, u8 size, u32 count, u8 is_out)
{
	unsigned long ret;

	DebugKVMIO("%s %px size %d count 0x%x to port 0x%x\n",
		(is_out) ? "write data from" : "read data to",
		data, size, count, port);

	if (count * size > vcpu->arch.ioport_data_size) {
		panic("kvm_guest_ioport_string_request() IO data area size 0x%llx < string size 0x%x\n",
			vcpu->arch.ioport_data_size, count * size);
	}
	if (DIRECT_IO_PORT_ACCESS) {
		if (is_out) {
			kvm_vcpu_copy_from_guest(vcpu,
				vcpu->arch.ioport_data, data, size * count);
			switch (size) {
			case 1:
				native_outsb(port, vcpu->arch.ioport_data, count);
				break;
			case 2:
				native_outsw(port, vcpu->arch.ioport_data, count);
				break;
			case 4:
				native_outsl(port, vcpu->arch.ioport_data, count);
				break;
			default:
				DebugKVMIO("invalid size %d\n", size);
			}
		} else {
			switch (size) {
			case 1:
				native_insb(port, vcpu->arch.ioport_data, count);
				break;
			case 2:
				native_insw(port, vcpu->arch.ioport_data, count);
				break;
			case 4:
				native_insl(port, vcpu->arch.ioport_data, count);
				break;
			default:
				DebugKVMIO("invalid size %d\n", size);
				data = NULL;
			}
			if (data != NULL) {
				kvm_vcpu_copy_to_guest(vcpu,
					data, vcpu->arch.ioport_data,
					size * count);
			}
		}
		ret = (data) ? 0 : -EINVAL;
		goto out;
	}

	vcpu->arch.ioport.port = port;
	vcpu->arch.ioport.size = size;
	vcpu->arch.ioport.data = (u64)data;
	vcpu->arch.ioport.count = count;
	vcpu->arch.ioport.cur_count = count;
	vcpu->arch.ioport.string = 1;
	vcpu->arch.ioport.is_out = is_out;
	if (is_out) {
		kvm_vcpu_copy_from_guest(vcpu, vcpu->arch.ioport_data, data, size * count);
	}

	vcpu->arch.ioport.needed = 1;
	vcpu->arch.ioport.completed = 0;
	vcpu->arch.exit_reason = EXIT_REASON_IOPORT_REQ;

	ret = RETURN_TO_HOST_APP_HCRET;

	if (vcpu->arch.ioport.completed) {
		if (!is_out) {
			kvm_vcpu_copy_to_guest(vcpu, data, vcpu->arch.ioport_data, size * count);
			DebugKVMIO("read data to %px size %d count 0x%x "
				"from port 0x%x\n",
				data, size, count, port);
		}
		vcpu->arch.ioport.completed = 0;
	} else {
		DebugKVMIO("IO port request is not completed: data at %px, "
			"size %d, count 0x%x, port 0x%x\n",
			data, size, count, port);
		data = NULL;
		if (ret == 0)
			ret = -EINVAL;
	}

out:
	return ret;
}

long kvm_guest_console_io(struct kvm_vcpu *vcpu, int io_cmd, int count, char *str)
{
	char buffer[512];
	struct tty_struct *tty;
	long ret;

	DebugKVMIO("%s console: count 0x%x, string %px\n",
		(io_cmd == CONSOLEIO_write) ? "write string to" :
							"read string from",
		count, str);

	if (count > sizeof(buffer) - 1) {
		pr_err("%s(): string size 0x%x > max buffer size 0x%lx\n",
			__func__, count, sizeof(buffer) - 1);
		count = sizeof(buffer) - 1;
	}
	if (io_cmd == CONSOLEIO_write) {
		ret = kvm_vcpu_copy_from_guest(vcpu, buffer, str, count);
		if (ret) {
			DebugKVMIO("could not copy string from user, err %ld\n",
				ret);
			count = ret;
			goto out;
		}
		buffer[count] = '\0';
		tty = get_current_tty();
		if (!tty) {
			DebugKVMIO("could not get current tty of guest\n");
			pr_err("%s", buffer);
			goto out;
		}
		tty_write_message(tty, buffer);
		tty_kref_put(tty);
	} else {
		/* read from console */
		DebugKVMIO("read string from console is not supported\n");
		count = -ENOENT;
		goto out;
	}
out:
	return count;
}

unsigned long
kvm_guest_notify_io(struct kvm_vcpu *vcpu, unsigned int notifier_io)
{
	vcpu->arch.notifier_io = notifier_io;
	vcpu->arch.exit_reason = EXIT_NOTIFY_IO;

	return RETURN_TO_HOST_APP_HCRET;
}

int kvm_guest_printk_on_host(struct kvm_vcpu *vcpu, char *msg, int size)
{
	char buffer[HOST_PRINTK_BUFFER_MAX + 1];
	int ret;

	if (size > sizeof(buffer) - 1)
		size = sizeof(buffer) - 1;
	ret = kvm_vcpu_copy_from_guest(vcpu, buffer, msg, size);
	if (ret) {
		DebugKVMIO("could not copy string from user, err %d\n",
			ret);
		size = ret;
		goto out;
	}
	buffer[size] = '\0';
	size = pr_info("%s", buffer);
out:
	return size;
}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

/*
 * Prefetching is disabled: prefixed MMIO pages are populated on demand, in
 * nonpaging/tdp_page_fault. FIXME: support shadow PT mode
 *
 * Alternatively, we could try to keep prefixed MMIO populated at all times,
 * but that is hard to do, since guest (Lintel) may change IOEPIC base GPA on
 * the fly. And prefetching pages from kvm_ioepic_set_base is impossible,
 * since we don't know, which VCPU wrote the new base
 */
int kvm_prefetch_mmio_areas(struct kvm_vcpu *vcpu)
{
	return 0;
}
