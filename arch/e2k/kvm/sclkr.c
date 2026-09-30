/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 MCST
 */

/*
 * Simplified KVM model for sclkr.  To avoid a lot of complexities
 * around "int"/"ext" modes of operation (and cooperation with
 * RTC model in QEMU) we ignore writes and instead provide a stable
 * monotonic time counter in "ext" mode.
 *
 * This corresponds to how hardware sclkr behaves in guests when present.
 */

#include <linux/kvm_host.h>
#include <linux/time64.h>
#include <linux/timekeeping.h>

#include <asm/cpu_regs.h>
#include <asm/kvm/cpu_hv_regs_access.h>
#include <asm/pci.h>


static u32 sclkr_freq __ro_after_init;
static e2k_sclkm1_t sclkm1 __ro_after_init;
static e2k_sclkm2_t sclkm2 __ro_after_init;
static __init int init_sclkr_freq(void)
{
	sclkr_freq = (is_prototype()) ? 1000000 : 100000000;

	AW(sclkm1) = 0;
	sclkm1.div = sclkr_freq;
	sclkm1.mdiv = 0;
	sclkm1.mode = 1;
	sclkm1.trn = 0;
	sclkm1.sw = 0;
	sclkm1.w_sclkr_hi = 0;
	sclkm1.sclkm3 = 1;

	AW(sclkm2) = 0;
	sclkm2.min = 0;
	sclkm2.max = -1u;

	return 0;
}
pure_initcall(init_sclkr_freq);

static inline struct timespec64 guest_time(const struct kvm_vcpu *vcpu)
{
	u64 now = ktime_get_raw_ns();
	return ns_to_timespec64(now + vcpu->kvm->arch.raw_clock_offset);
}

void kvm_sclkr_read(struct kvm_vcpu *vcpu, intc_info_cu_entry_t *entry)
{
	struct timespec64 ts = guest_time(vcpu);

	entry->hi = (e2k_sclkr_t) {
		.lo = (u64) ts.tv_nsec * sclkr_freq / NSEC_PER_SEC,
		.hi = ts.tv_sec,
	}.word;
}

void kvm_sclkm1_read(struct kvm_vcpu *vcpu, intc_info_cu_entry_t *entry)
{
	entry->hi = AW(sclkm1);
}

void kvm_sclkm2_read(struct kvm_vcpu *vcpu, intc_info_cu_entry_t *entry)
{
	entry->hi = AW(sclkm2);
}

void kvm_sclkr_write(struct kvm_vcpu *vcpu, intc_info_cu_entry_t *entry)
{
	entry->lo.event_code = ICE_FORCED;
}

void kvm_sclkm1_write(struct kvm_vcpu *vcpu, intc_info_cu_entry_t *entry)
{
	entry->lo.event_code = ICE_FORCED;
}

void kvm_sclkm2_write(struct kvm_vcpu *vcpu, intc_info_cu_entry_t *entry)
{
	entry->lo.event_code = ICE_FORCED;
}

void kvm_sclkm3_write(struct kvm_vcpu *vcpu, intc_info_cu_entry_t *entry)
{
	entry->lo.event_code = ICE_FORCED;

	if (cpu_has(CPU_HWBUG_VIRT_SCLKM3_INTC)) {
		WRITE_SH_SCLKM3_REG_VALUE(vcpu->kvm->arch.sh_sclkm3);
	}
}