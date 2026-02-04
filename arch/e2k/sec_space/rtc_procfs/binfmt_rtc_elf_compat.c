/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/elfcore-compat.h>
#include <linux/time.h>
#include "internal.h"

#define ELF_COMPAT	1

/*
 * Rename the basic ELF layout types to refer to the 32-bit class of files.
 */
#undef	ELF_CLASS
#define ELF_CLASS	ELFCLASS32

#undef	elfhdr
#undef	elf_phdr
#undef	elf_shdr
#undef	elf_note
#undef	elf_addr_t
#undef	ELF_GNU_PROPERTY_ALIGN
#define elfhdr		elf32_hdr
#define elf_phdr	elf32_phdr
#define elf_shdr	elf32_shdr
#define elf_note	elf32_note
#define elf_addr_t	Elf32_Addr
#define ELF_GNU_PROPERTY_ALIGN	ELF32_GNU_PROPERTY_ALIGN

/*
 * Some data types as stored in coredump.
 */
#define user_long_t		compat_long_t
#define user_siginfo_t		compat_siginfo_t
#define copy_siginfo_to_external	copy_siginfo_to_external32

/*
 * The machine-dependent core note format types are defined in elfcore-compat.h,
 * which requires asm/elf.h to define compat_elf_gregset_t et al.
 */
#define elf_prstatus	compat_elf_prstatus
#define elf_prpsinfo	compat_elf_prpsinfo

#undef ns_to_kernel_old_timeval
#define ns_to_kernel_old_timeval ns_to_old_timeval32

/*
 * To use this file, asm/elf.h must define compat_elf_check_arch.
 * The other following macros can be defined if the compat versions
 * differ from the native ones, or omitted when they match.
 */

#undef	elf_check_arch
#define	elf_check_arch	compat_elf_check_arch

#ifdef	COMPAT_ELF_PLATFORM
#undef	ELF_PLATFORM
#define	ELF_PLATFORM		COMPAT_ELF_PLATFORM
#endif

#ifdef	COMPAT_ELF_HWCAP
#undef	ELF_HWCAP
#define	ELF_HWCAP		COMPAT_ELF_HWCAP
#endif

#ifdef	COMPAT_ELF_HWCAP2
#undef	ELF_HWCAP2
#define	ELF_HWCAP2		COMPAT_ELF_HWCAP2
#endif

#ifdef	COMPAT_ARCH_DLINFO
#undef	ARCH_DLINFO
#define	ARCH_DLINFO		COMPAT_ARCH_DLINFO
#endif

#ifdef COMPAT_ELF_EXEC_PAGESIZE
#undef	ELF_EXEC_PAGESIZE
#define	ELF_EXEC_PAGESIZE	COMPAT_ELF_EXEC_PAGESIZE
#endif

#define X86_VDSO_CALL_OFFSET	0x400
/**
 * sycall wrapper
 *
 * 0xcd, 0x80,	int 0x80
 * 0xc3		ret
 */
#define X86_VDSO_CALL_WRAPPER {'\xcd', '\x80', '\xc3'}
#define X86_VDSO_SIGRETURN_OFFSET 0x420
/**
 * sigreturn
 *
 * 0x58,				pop eax
 * 0xb8, 0x77, 0x00, 0x00, 0x00,	mov _NR_sigreturn eax
 * 0xcd, 0x80,			int 0x80
 * 0xc3,				ret
 * 0x90				nop
 */
#define X86_VDSO_SIGRETURN_WRAPPER \
		{'\x58', '\xb8', '\x77', '\x00', '\x00', '\x00', '\xcd', '\x80', '\xc3', '\x90'}

#define X86_VDSO_RT_SIGRETURN_OFFSET 0x440
/**
 * rt_sigreturn
 *
 * 0xb8, 0xad, 0x00, 0x00, 0x00,	mov _NR_rt_sigreturn eax
 * 0xcd, 0x80,			int 0x80
 * 0x90				nop
 */
#define X86_VDSO_RT_SIGRETURN_WRAPPER \
		{'\xb8', '\xad', '\x00', '\x00', '\x00', '\xcd', '\x80', '\x90'}

/*
 * We share all the actual code with the native (64-bit) version.
 */
#include "binfmt_rtc_elf.c"
