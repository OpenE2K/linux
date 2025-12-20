/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * KVM guest printk() on host implementation.
 */

#include <stdarg.h>
#include <linux/types.h>
#include <linux/kernel.h>

#include <asm/host_printk.h>
#include <asm/kvm/hypercall.h>

int kvm_host_printk(const char *fmt, ...)
{
	va_list args;
	char buf[HOST_PRINTK_BUFFER_MAX];
	int size;

	va_start(args, fmt);
	size = vsnprintf(buf, HOST_PRINTK_BUFFER_MAX, fmt, args);
	va_end(args);

	if (size <= 0)
		return size;
	size = HYPERVISOR_host_printk(buf, size);
	return size;
}
EXPORT_SYMBOL(kvm_host_printk);
