/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef __ASM_E2K_IOMMU_H
#define __ASM_E2K_IOMMU_H

#include <linux/kvm_host.h>

extern int iommu_panic_off;

extern void e2k_iommu_error_interrupt(struct pt_regs *regs);
extern void e2k_iommu_shutdown(void);
extern void e2k_iommu_set_kvm_device(struct device *dev, struct kvm *kvm);

extern void kvm_iommu_write_ctrl_ptbar(struct kvm *kvm, u32 ctrl, u64 ptbar);
extern void kvm_iommu_flush(struct kvm *kvm, u64 command);

#endif /* __ASM_E2K_IOMMU_H */
