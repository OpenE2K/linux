/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * This is the GNU ld script to construct E2K Linux kernel
 */

/* No __ro_after_init data in the .rodata section - which will always be ro */
#define RO_AFTER_INIT_DATA

#include <generated/asm-offsets.h>
#include <asm/thread_info.h>
#include <asm/cache.h>
#include <asm/cpu_regs_types.h>
#include <asm/vmlinux.lds.h>
#include <asm/head.h>
#include <uapi/asm/kvm.h>

OUTPUT_FORMAT("elf64-e2k", "elf64-e2k", "elf64-e2k")

#ifdef	CONFIG_E2K_MACHINE
 #if defined(CONFIG_E2K_E2S)
 OUTPUT_ARCH(elbrus-v3)
 #elif defined(CONFIG_E2K_E8C)
 OUTPUT_ARCH(elbrus-v4)
 #elif defined(CONFIG_E2K_E1CP)
 OUTPUT_ARCH(elbrus-v4)
 #elif defined(CONFIG_E2K_E8C2)
 OUTPUT_ARCH(elbrus-v5)
 #elif defined(CONFIG_E2K_E2C3)
 OUTPUT_ARCH(elbrus-v6)
 #elif defined(CONFIG_E2K_E12C)
 OUTPUT_ARCH(elbrus-v6)
 #elif defined(CONFIG_E2K_E16C)
 OUTPUT_ARCH(elbrus-v6)
 #elif defined(CONFIG_E2K_E48C)
 OUTPUT_ARCH(elbrus-v7)
 #elif defined(CONFIG_E2K_E8V7)
 OUTPUT_ARCH(elbrus-v7)
 #else
 error "Invalid e2k machine type"
 #endif	/* all machines types */
#else	/* ! CONFIG_E2K_MACHINE */
OUTPUT_ARCH(e2k)
#endif	/* CONFIG_E2K_MACHINE */

ENTRY(_start)
jiffies = jiffies_64;
SECTIONS
{
  . = E2K_KERNEL_IMAGE_AREA_BASE;	/* KERNEL BASE VA ~ 14 * 2^44 */
  _start = .;				/* Start of kernel image */
  _text = .;				/* Text and read-only data */
  _stext = .;				/* Text and read-only data */
  .text : {
		__ttable_start = .;
		_t_entry = .;
			*(.ttable_entry0)
			. = _t_entry + 0x800;
			*(.native_ttable_entry1)
			. = _t_entry + 0x1800;
			*(.native_ttable_entry3)
			. = _t_entry + 0x2000;
			*(.native_ttable_entry4)
			. = _t_entry + 0x2800;
#ifdef CONFIG_COMPAT
			*(.ttable_entry5)
			*(.ttable_entry5_table)
			*(.ttable_entry5_C)
#endif
			. = _t_entry + 0x3000;
			*(.ttable_entry6)
			*(.ttable_entry6_table)
			*(.ttable_entry6_C)
#ifdef CONFIG_PROTECTED_MODE
			. = _t_entry + 0x3800;
			*(.ttable_entry7)
			*(.ttable_entry7_table)
			*(.ttable_entry7_C)
#endif
#ifdef CONFIG_PROTECTED_MODE
			. = _t_entry + 0x4000;
			*(.ttable_entry8)
			*(.ttable_entry8_C)
			. = _t_entry + 0x5000;
			*(.ttable_entry10)
			*(.ttable_entry10_C)
#endif
			. = _t_entry + 0x5800;
			*(.ttable_entry11)
			. = _t_entry + 0x6000;
			*(.ttable_entry12)

#ifdef CONFIG_KVM_HOST_MODE
/* or native host kernel with virtualization support */
/* hypervisor and host features is not supported on guest mode */

			. = _t_entry + 0x8000;		/* hypercalls */
				*(.ttable_entry16)	/* generic */
			. = _t_entry + 0x8800;
				*(.ttable_entry17)	/* light */
			. = _t_entry + 0x9000;
			__priv_host_entries_start = .;
				*(.ttable_entry18)	/* privileged actions */
			__priv_host_entries_end = .;
			. = _t_entry + 0x9800;

#endif	/* CONFIG_KVM_HOST_MODE */

		_t_entry_end = .;
		__ttable_end = .;

#ifdef CONFIG_KVM_GUEST_KERNEL
		/* 0x10_000 */
		. = _t_entry + KVM_GUEST_STARTUP_ENTRY_NUM *
					E2K_SYSCALL_TRAP_ENTRY_SIZE;
		*(.kvm_guest_startup_entry)

		/* 0x12_000 */
		. = _t_entry + (KVM_PV_VCPU_TRAP_ENTRY_NUM + 0) *
					E2K_SYSCALL_TRAP_ENTRY_SIZE;
		__kvm_pv_vcpu_ttable_entry0 = .;
			*(.kvm_pv_vcpu_ttable_entry0)
			. = _t_entry + (KVM_PV_VCPU_TRAP_ENTRY_NUM + 1) *
						E2K_SYSCALL_TRAP_ENTRY_SIZE;
			*(.kvm_guest_ttable_entry1)
			. = _t_entry + (KVM_PV_VCPU_TRAP_ENTRY_NUM + 3) *
						E2K_SYSCALL_TRAP_ENTRY_SIZE;
			*(.kvm_guest_ttable_entry3)
			. = _t_entry + (KVM_PV_VCPU_TRAP_ENTRY_NUM + 4) *
						E2K_SYSCALL_TRAP_ENTRY_SIZE;
			*(.kvm_guest_ttable_entry4)
			. = _t_entry + (KVM_PV_VCPU_TRAP_ENTRY_NUM + 5) *
						E2K_SYSCALL_TRAP_ENTRY_SIZE;
			*(.kvm_guest_ttable_entry5)
			. = _t_entry + (KVM_PV_VCPU_TRAP_ENTRY_NUM + 6) *
						E2K_SYSCALL_TRAP_ENTRY_SIZE;
			*(.kvm_guest_ttable_entry6)
		__kvm_pv_vcpu_ttable_end = .;
#endif	/* CONFIG_KVM_GUEST_KERNEL */
		. = _t_entry + (KVM_PV_VCPU_TRAP_ENTRY_NUM + 7) *
					E2K_SYSCALL_TRAP_ENTRY_SIZE;

#ifdef	CONFIG_KVM_HOST_MODE
		/* Hypercalls entry points */
		. = ALIGN(PAGE_SIZE);
		__hypercalls_begin = .;
		*(.hcall_entry0)	/* generic hypercalls */
		. = __hypercalls_begin + 0x1000;
		*(.hcall_entry1)	/* light hypercalls */
#endif	/* CONFIG_KVM_HOST_MODE */

		__entry_handlers_start = .;
		__entry_handlers_hcalls_start = .;
		*(.text.entry_hcalls)
		__entry_handlers_hcalls_end = .;
#ifdef	CONFIG_KVM_HOST_MODE
		__entry_priv_handlers_hcalls_start = .;
		*(.text.entry_priv_hcalls)
		__entry_priv_handlers_hcalls_end = .;
#endif	/* CONFIG_KVM_HOST_MODE */
		ENTRY_TEXT
		IRQENTRY_TEXT
		__entry_handlers_end = .;
		SOFTIRQENTRY_TEXT
		HEAD_TEXT
#ifdef CONFIG_KPROBES
		KPROBES_TEXT
#endif
		__C1_wait_trap_start = .;
		*(.C1_wait_trap.text)
		__C1_wait_trap_end = .;
		__C3_wait_trap_start = .;
		*(.C3_wait_trap.text)
		__C3_wait_trap_end = .;
		__uaccess_start = .;
		*(.uaccess_functions)
		__uaccess_end = .;
		TEXT_TEXT
		SCHED_TEXT
		LOCK_TEXT
		CPUIDLE_TEXT
		*(.fixup)
#ifdef CONFIG_CPU_HWBUG_IBRANCH
		/* Add NOPs after ibranch in .fixup section */
		QUAD(0)
		QUAD(0)
#endif
		*(.gnu.warning)
#ifdef CONFIG_E2K_KEXEC
		. = ALIGN(PAGE_SIZE);
		*(.switch_to_phys)
#endif
	} /*:text*/
	.dummy : {
		*(.dummy)
	} /*:kernel*/

	. = ALIGN(E2K_MAX_PAGE_SIZE);  /* To map .text/.rodata with large pages */
	_etext = .;			/* End of text section */

	__start_rodata_notes = .;
		/* everything from this point to _sdata will be marked RO NX */
		RO_DATA(PAGE_SIZE)
  		E2K_BOOT_SETUP(16)
		NOTES

		. = ALIGN(E2K_MAX_PAGE_SIZE); /* To map .rodata with large pages */
	__end_rodata_notes = .;

	. = ALIGN(E2K_MAX_PAGE_SIZE); /* To map .data/.bss with large pages */
	_sdata_bss = .;
	__common_data_begin = .;
		BSS_SECTION(0, 0, 0)

		_sdata = .;

		/* We want to use OSGD for quick data access */
		RW_DATA(L2_CACHE_BYTES, PAGE_SIZE, E2K_ALIGN_GLOBALS_SZ)

		.got : {
			*(.got)
		}
		.sdata : {
			*(.sdata)
		}

		. = ALIGN(E2K_MAX_PAGE_SIZE); /* To map .data/.bss with large pages */
	__common_data_end = .;

	__special_data_begin = .;
		__node_data_start = .;
			.node.data : { *(.node.data) }
			. = ALIGN(PAGE_SIZE);
		__node_data_end = .;

		. = ALIGN(PAGE_SIZE);
		__start_ro_after_init = .;
		.data..ro_after_init : {
			 *(.data..ro_after_init)
		}
		EXCEPTION_TABLE(16)
		. = ALIGN(PAGE_SIZE);
		__end_ro_after_init = .;

		. = ALIGN(PAGE_SIZE);
		empty_zero_page = .;
		. += PAGE_SIZE;
	__special_data_end = .;

	_edata = .;	/* End of data section */
	_edata_bss = .;


	__init_begin = .;

	/* Will be freed after init */
	__init_text_begin = .;
	INIT_TEXT_SECTION(PAGE_SIZE)
	/*
	 * .exit.text is discarded at runtime, not link time,
	 * to deal with references from __bug_table
	 */
	.exit.text : {
		EXIT_TEXT
	}

	. = ALIGN(PAGE_SIZE);
	__init_text_end = .;

	__init_data_begin = .;
	.exit.data : {
		EXIT_DATA
	}
	INIT_DATA_SECTION(16)
	PERCPU_SECTION(INTERNODE_CACHE_BYTES)

	. = ALIGN(8);
	.apicdrivers : AT(ADDR(.apicdrivers) - LOAD_OFFSET) {
		__apicdrivers = .;
		*(.apicdrivers);
		__apicdrivers_end = .;
	}

	/*
	 * Alternative instructions for different CPU types or capabilities
	 */
	. = ALIGN(8);
	.altinstructions : {
		__alt_instructions = .;
		*(.altinstructions)
		__alt_instructions_end = .;
	}
	. = ALIGN(8);
	.altinstr_replacement : {
		*(.altinstr_replacement)
	}

	/*
	 * cpu_has() initializers
	 */
	. = ALIGN(8);
	.cpuhas_initcall : {
		__cpuhas_initcalls = .;
		*(.cpuhas_initcall)
		__cpuhas_initcalls_end = .;
	}

	. = ALIGN(PAGE_SIZE);
	__init_data_end = .;

	__init_end = .;

	_end = .;

	.mdebug 0 : {
		*(.mdebug)
	}

	STABS_DEBUG
	DWARF_DEBUG

	DISCARDS
}
