/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */


#ifndef	__E2K_KVM_GUEST_IO_H_
#define	__E2K_KVM_GUEST_IO_H_

#include <linux/types.h>
#include <linux/kvm_host.h>

#include <asm/io.h>

extern unsigned long kvm_notify_io(unsigned int notifier_io);
extern unsigned long kvm_handle_guest_mmio(void __iomem *mmio_addr,
					u64 value, u8 size, u8 is_write);

#endif  /* __E2K_KVM_GUEST_IO_H_ */
