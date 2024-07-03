/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <asm/p2v/boot_v2p.h>
#include <linux/ptrace.h>
#include <linux/init.h>
#include <linux/irq.h>
#include <linux/delay.h>
#include <linux/smp.h>
#include <linux/seq_file.h>
#include <linux/export.h>
#include <linux/cpu.h>

#include <asm/apic.h>
#include <asm/e2k_api.h>
#include <asm/e2k.h>
#include <asm/mmu_context.h>
#include <asm/io.h>
#include <asm/iolinkmask.h>
#include <asm/machdep.h>
#include <asm/smp.h>
#include <asm/p2v/boot_head.h>
#include <asm/console.h>
#include <asm/host_printk.h>

#include <asm/kvm/hypercall.h>

#include "cpu.h"
#include "time.h"

#undef	DEBUG_KVM_SHUTDOWN_MODE
#undef	DebugKVMSH
#define	DEBUG_KVM_SHUTDOWN_MODE	1	/* KVM shutdown debugging */
#define	DebugKVMSH(fmt, args...)					\
({									\
	if (DEBUG_KVM_SHUTDOWN_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

void __init
boot_e2k_virt_setup_arch(void)
{
	boot_machine.io_area_base = E2K_VIRT_CPU_IO_AREA_PHYS_BASE;
	boot_machine.guest.rev = E2K_VIRT_CPU_REVISION;
	boot_machine.guest.iset_ver = E2K_VIRT_CPU_ISET;
	boot_machine.max_nr_node_cpus = E2K_VIRT_MAX_NR_NODE_CPUS;
	boot_machine.nr_node_cpus = E2K_VIRT_NR_NODE_CPUS;
	boot_machine.node_iolinks = E2K_VIRT_NODE_IOLINKS;
}

/*
 * Panicing.
 */

void boot_kvm_panic(const char *fmt_v, ...)
{
	register va_list ap;

	va_start(ap, fmt_v);
	boot_vprintk(fmt_v, ap);
	va_end(ap);
	HYPERVISOR_kvm_shutdown("boot-time panic", KVM_SHUTDOWN_PANIC);
}
