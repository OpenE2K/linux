/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _L_BOOTINFO_H_
#define _L_BOOTINFO_H_

#if defined(__KERNEL__) || defined(__KVM_BOOTINFO_SUPPORT__)

#include <uapi/asm/setup.h>

/*
 * 0x0:
 * 0x1: extended command line
 * 0x2: command line pointer
 */
#define BOOTBLOCK_VER				0x2

#define	BOOT_VER_STR_SIZE			128
#define	BOOTBLOCK_SIZE				0x1000

#define	BOOTBLOCK_BOOT_SIGNATURE		0x8086
#define	BOOTBLOCK_ROMLOADER_SIGNATURE		0xe200
#define	BOOTBLOCK_KVM_GUEST_SIGNATURE		0x20e2

#define	KSTRMAX_SIZE				128
#define	KSTRMAX_SIZE_EX				512
#define KSTRMAX_SIZE_PNT			COMMAND_LINE_SIZE

#define KERNEL_ARGS_STRING_EX_SIGN_SIZE		22
#define KERNEL_ARGS_STRING_EX_SIGNATURE		"KERNEL_ARGS_STRING_EX"
#define BOOT_KERNEL_ARGS_STRING_EX_SIGNATURE	boot_va_to_pa(KERNEL_ARGS_STRING_EX_SIGNATURE)

/* L_MAX_NODE_PHYS_BANKS = 4 sometimes is not enough, so we increase it to an arbitary value
 * (8 now). The old L_MAX_NODE_PHYS_BANKS we rename to L_MAX_NODE_PHYS_BANKS_FUSTY and take in
 * mind for boot_info compatibility.
 *
 * L_MAX_NODE_PHYS_BANKS_FUSTY and L_MAX_MEM_NUMNODES describe max size of array of memory banks
 * on all nodes and should be in accordance with old value of L_MAX_PHYS_BANKS for compatibility
 * with boot_info old structure (bank) size, so L_MAX_NODE_PHYS_BANKS_FUSTY * L_MAX_MEM_NUMNODES
 * should be equal to 32.
 */
#define L_MAX_NODE_PHYS_BANKS		64	/* max number of memory banks on one node */
#define L_MAX_NODE_PHYS_BANKS_FUSTY	4	/* fusty max number of memory banks on one node */
#define L_MAX_PHYS_BANKS_EX		64	/* max number of memory banks in banks_ex field */
						/* of boot_info */
#define L_MAX_MEM_NUMNODES		8	/* max number of nodes in the list of memory */
						/* banks on each node */
#define	L_MAX_BUSY_AREAS	4	/* max number of busy areas occupied by BIOS and should */
					/* be kept unchanged by kernel to support recovery mode */

#ifndef	__ASSEMBLY__

typedef struct bank_info {
	__u64	address;	/* start address of bank */
	__u64	size;		/* size of bank in bytes */
} bank_info_t;

typedef struct node_banks {
	bank_info_t banks[L_MAX_NODE_PHYS_BANKS_FUSTY];	/* memory banks array of a node */
} node_banks_t;

typedef struct boot_times {
	__u64 arch;
	__u64 unpack;
	__u64 pci;
	__u64 drivers1;
	__u64 drivers2;
	__u64 menu;
	__u64 sm;
	__u64 kernel;
	__u64 reserved[8];
} boot_times_t;

typedef struct jb_info {
	__u64 ram_addr;		/* RAM address of JSON_dflt string */
	__u64 size;		/* size in bytes of JSON_dflt string */
} jb_info_t;

typedef struct s3_info {
	__u64 ram_addr;		/* RAM address of DDR4-PHY Mem registers */
	__u64 rom_addr;		/* FLASH address of DDR4-PHY Mem registers */
	__u64 size;		/* size in bytes of DDR4-PHY Mem registers */
} s3_info_t;


typedef struct ioh_eth_mac_table_entry_t {
	struct ioh_eth_mac_table_entry_t *next; /* next entry ptr */
	__u8 pci_domain;
	__u8 bus; /* PCI Bus number */
	__u8 slot; /* PCI Device number */
	__u8 func; /* PCI function number */
	__u8 mac_addr[6]; /* MAC Address for Ethernet node */
} ioh_eth_mac_table_entry_t;

typedef struct boot_info {
	__u16	signature;	/* signature 0x8086 */
	__u8	target_mdl;	/* target cpu model number */
	__u8	target_iset_min;/* target minimal iset version number */
	__u8	target_iset_max;/* target maximum iset version number */
	__u8	progr_divf;	/* e2k v6 cpu freq divider value */
	__u8	vga_mode;	/* vga mode */
	__u8	num_of_banks;	/* number of available physical memory banks, total number on all */
				/* nodes or 0 */
	__u64	kernel_base;	/* base address to load kernel image */
	__u64	kernel_size;	/* kernel image size in bytes */
	__u64	ramdisk_base;	/* base address to load RAM-disk */
	__u64	ramdisk_size;	/* RAM-disk byte size in bytes */
	__u16	num_of_cpus;	/* number of started physical CPUs */
	__u16	mach_flags;	/* machine identifacition flags, should be set by our romloader */
				/* and BIOS */
	__u16	num_of_busy;	/* number of busy areas occupied by BIOS */
	__u16	num_of_nodes;	/* number of nodes on NUMA system */
	__u64	mp_table_base;	/* MP-table base address */
	__u64	serial_base;	/* base address of serial port for Am85c30 */
	__u64	nodes_map;	/* online nodes map */
	__u64	mach_serialn;	/* serial number of the machine */
	__u8	mac_addr[6];	/* base MAC address for ethernet cards */
	__u16	reserved1;	/* reserved1 */
	char	kernel_args_string[KSTRMAX_SIZE]; /* command line of kernel used to pass command */
						  /* line from e2k BIOS */
	node_banks_t	nodes_mem[L_MAX_MEM_NUMNODES]; /* array of descriptors of banks of */
						       /* available physical memory on each node */
	bank_info_t	busy[L_MAX_BUSY_AREAS];	       /* descriptors of areas occupied by BIOS */
	__u64	reserved2[52];	/* reserved2 */
	__u64	mac_table_ptr;	/* Pointer to the beginning of the list of MAC addresses */
	__u64	reserved3[10];	/* reserved3 */
	__u64	kernel_args_string_pnt;	  /* pointer to command line of kernel passed by BIOS */
	__u64	dmi_info;	/* smbios and dmi address */
	__u8	mb_name[16];	/* Motherboard product name */
	__u32	reserved4;	/* reserved4 */
	__u32	kernel_csum;	/* kernel image control sum */
	__u64	reserved5;				/* reserved5 */
	__u8	boot_ver[BOOT_VER_STR_SIZE];		/* boot version */
	__u8	mb_type;				/* mother board type */
	__u8	reserved6;				/* reserved6 */
	__u8	cpu_type;				/* cpu type */
	__u8	kernel_args_string_ex[KSTRMAX_SIZE_EX];	/* extended command line of kernel */
							/* used to pass command line from e2k */
							/* BIOS */
	__u8		reset_type;			/* reset type */
	__u32		cache_lines_damaged;		/* number of damaged cache lines */
	jb_info_t	jb_info;			/* jb info */
	s3_info_t	s3_info;			/* S3 info */
	__u64		reserved7[47];			/* reserved7 */
	bank_info_t	banks_ex[L_MAX_PHYS_BANKS_EX];	/* extended array of descriptors of */
							/* banks of available physical memory */
	__u64	devtree;				/* devtree pointer */
	__u32	bootlog_addr;				/* bootlog address */
	__u32	bootlog_len;				/* bootlog length */
	__u8	uuid[16];				/* UUID boot device */
} boot_info_t;

typedef struct bootblock_struct {
	boot_info_t	info;			/* general kernel<->BIOS info */

	__u8		gap[BOOTBLOCK_SIZE -	/* zip area to make size of bootblock struct */
						/* constant */
				sizeof (boot_info_t)  -
				sizeof (boot_times_t) -
				1 -		/* u8: bootblock_ver */
				4 -		/* u32: reserved1 */
				2 -		/* u16: kernel_flags */
				2 -		/* u16: reserved2 */
				4 -		/* u32: reserved3 */
				16 -		/* u128: reserved4 */
				4 -		/* u32: reserved5 */
				2 -		/* u16: boot_flags */
				2];		/* u16: bootblock_marker */

	__u8		bootblock_ver;		/* bootblock version number */
	__u32		reserved1;		/* reserved1 */
	boot_times_t	boot_times;		/* boot load times */
	__u16	kernel_flags_deprecated;	/* kernel flags */
	__u16	reserved2;			/* reserved2 */
	__u32	reserved3;			/* reserved3 */
	__u64	reserved4[2];			/* reserved4 */
	__u32	reserved5;			/* reserved5 */
	__u16	boot_flags;			/* boot flags */
	__u16	bootblock_marker;		/* marker of the end of boot block (0xAA55) */
} bootblock_struct_t;

extern	bootblock_struct_t *bootblock_virt;	/* bootblock structure virtual pointer */
#endif /* ! __ASSEMBLY__ */

/*
 * Boot block flags to elaborate boot modes
 */

/* if non zero then this structure is recovery info structure instead of boot info structure. */
/* BIOS should not clear memory and should keep current state of physical memory. */
#define	RECOVERY_BB_FLAG		0x0001
/* kernel restarted in the mode of control point creation. BIOS should read kernel image from */
/* the disk to the specified area of the memory and start kernel (this flag should be used with */
/* RECOVERY_BB_FLAG flag). */
#define NO_READ_IMAGE_BB_FLAG		0x0004

/*
 * The machine identification flags
 */

#define	SIMULATOR_MACH_FLAG		0x0001	/* system is running on simulator */
#define	IOHUB_MACH_FLAG_DEPRECATED	0x0004	/* machine has IOHUB */
#define	MSI_MACH_FLAG			0x0020	/* boot inits right values in apic to support */
						/* MSI. Meanfull for e2k only. For v9 it always */
						/* true */

extern char *mcst_mb_name;

#endif /* __KERNEL__ || __KVM_BOOTINFO_SUPPORT__ */

#endif /* _L_BOOTINFO_H_ */

