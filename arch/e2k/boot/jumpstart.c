/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/types.h>
#include <linux/mmzone.h>
#include <linux/log2.h>

#include "bios/printk.h"

#include <asm/cpu_regs_types.h>
#include <asm/bootinfo.h>
#include <asm/machdep.h>
#include <asm/head.h>
#include <asm/sections.h>
#ifdef	CONFIG_SMP
#include <asm/atomic.h>
#endif	/* CONFIG_SMP */

#include "pic.h"

#include <asm/e2k_api.h>
#include <asm/mpspec.h>
#ifdef	CONFIG_E2K_SIC
#include <asm/sic_regs.h>
#endif	/* CONFIG_E2K_SIC */
#include <asm/hb_regs.h>
#include "e2k_sic.h"

#include "topology.h"
#include "boot.h"
#include "bios/pci.h"

#include <linux/mc146818rtc.h>

#undef	DEBUG_RT_MODE
#undef	DebugRT
#define DEBUG_RT_MODE		0	/* routing registers */
#define DebugRT			if (DEBUG_RT_MODE) rom_printk

#undef	DEBUG_MRT_MODE
#undef	DebugMRT
#define DEBUG_MRT_MODE		1	/* memory routing registers */
#define DebugMRT		if (DEBUG_MRT_MODE) rom_printk

#undef	DEBUG_IORT_MODE
#undef	DebugIORT
#define DEBUG_IORT_MODE		1	/* IO memory routing registers */
#define DebugIORT		if (DEBUG_IORT_MODE) rom_printk

#define	BOOT_VER_STR		"BOOT SIMULATOR"

extern long input_data, input_data_end, input_data_noncomp_size;
extern long boot_mode;

#ifdef CONFIG_BLK_DEV_INITRD
extern long initrd_data, initrd_data_end;
#endif /* CONFIG_BLK_DEV_INITRD */

#ifdef CONFIG_CMDLINE
#define CMDLINE CONFIG_CMDLINE
#else
#define CMDLINE "";
#endif

#define	ALIGN_DOWN_TO_MASK(addr, mask)	((addr) & ~(mask))
#define	ALIGN_UP_TO_MASK(addr, mask)	(((addr) + (mask)) & ~(mask))
#define	ALIGN_DOWN_TO_SIZE(addr, size)	\
		(((size) == 0) ? (addr) : ALIGN_DOWN_TO_MASK(addr, ((size)-1)))
#define	ALIGN_UP_TO_SIZE(addr, size)	\
		(((size) == 0) ? (addr) : ALIGN_UP_TO_MASK(addr, ((size)-1)))

char cmd_preset[] = CMDLINE;
char cmd_buf[KSTRMAX_SIZE_EX + KSTRMAX_SIZE];
char *cmd_line = cmd_buf;
char *free_memory_p;

#ifdef	CONFIG_SMP
extern atomic_t cpu_count;
extern int phys_cpu_num;
extern void do_smp_commence(void);
extern volatile unsigned long	phys_cpu_pres_map;
#endif	/* CONFIG_SMP */

volatile unsigned long	phys_node_pres_map = 0;
int			phys_node_num = 0;
volatile unsigned long	online_iohubs_map = 0;
int			online_iohubs_num = 0;
volatile unsigned long	possible_iohubs_map = 0;
int			possible_iohubs_num = 0;
volatile unsigned long	online_rdmas_map = 0;
int			online_rdmas_num = 0;
volatile unsigned long	possible_rdmas_map = 0;
int			possible_rdmas_num = 0;

static	e2k_addr_t	kernel_areabase;
static	e2k_size_t	kernel_areasize;
bootblock_struct_t	*bootblock;
boot_info_t		*boot_info;
bios_info_t		*bios_info;
#ifdef	CONFIG_RECOVERY
int			recovery_flag = 0;
int			not_read_image;
#endif	/* CONFIG_RECOVERY */
int			banks_ex_num = 0;

void set_kernel_image_pointers(void);

#ifdef CONFIG_BIOS
extern void bios_first(void);
extern void bios_rest(void);
#ifdef CONFIG_ENABLE_ELBRUS_PCIBIOS
extern void pci_bios(void);
#endif
extern void video_bios(void);
#endif

/* Memory probing definitions block */

#define	_1MB	(1024 * 1024UL)
#define	_1GB	(1024 * _1MB)
#define	_64MB	(64 * _1MB)
#define	_2MB	( 2 * _1MB)

#ifndef CONFIG_MEMLIMIT
#define	CONFIG_MEMLIMIT		(2 * 1024)
#endif

#define	PROBE_MEM_LIMIT	(CONFIG_MEMLIMIT * _1MB)

#ifndef CONFIG_EXT_MEMLIMIT
#define	CONFIG_EXT_MEMLIMIT	(60 * 1024)
#endif

#define	PROBE_EXT_MEM_LIMIT	(CONFIG_EXT_MEMLIMIT * _1MB)

#define LO_MEMORY_START			0x00000000000ULL
#define	E2S_HI_MEMORY_START		0x02000000000ULL
#define	E2S_HI_MEMORY_NODE_MAX_SIZE	0x02000000000ULL
#define	E8C_HI_MEMORY_START		E2S_HI_MEMORY_START
#define	E8C_HI_MEMORY_NODE_MAX_SIZE	E2S_HI_MEMORY_NODE_MAX_SIZE
#define	E16C_HI_MEMORY_START		0x10000000000ULL
#define	E16C_HI_MEMORY_NODE_MAX_SIZE	0x10000000000ULL

#if defined(CONFIG_E1CP) || defined(CONFIG_E2S)
 #define HI_MEMORY_START		E2S_HI_MEMORY_START
 #define HI_MEMORY_NODE_MAX_SIZE	E2S_HI_MEMORY_NODE_MAX_SIZE
#elif defined(CONFIG_E8C) || defined(CONFIG_E8C2)
 #define HI_MEMORY_START		E8C_HI_MEMORY_START
 #define HI_MEMORY_NODE_MAX_SIZE	E8C_HI_MEMORY_NODE_MAX_SIZE
#elif defined(CONFIG_E2C3) || defined(CONFIG_E12C) || defined(CONFIG_E16C) || \
	defined(CONFIG_E48C) || defined(CONFIG_E8V7)
 #define HI_MEMORY_START		E16C_HI_MEMORY_START
 #define HI_MEMORY_NODE_MAX_SIZE	E16C_HI_MEMORY_NODE_MAX_SIZE
#else
 #error	"Unknown MicroProcessor type"
#endif

#if	defined(CONFIG_VRAM_SIZE_128)
#define	EG_VRAM_SIZE_FLAGS	EG_CFG_VRAM_SIZE_128
#define	EG_VRAM_MBYTES_SIZE	(128 * 1024 * 1024)
#elif	defined(CONFIG_VRAM_SIZE_256)
#define	EG_VRAM_SIZE_FLAGS	EG_CFG_VRAM_SIZE_256
#define	EG_VRAM_MBYTES_SIZE	(256 * 1024 * 1024)
#elif	defined(CONFIG_VRAM_SIZE_512)
#define	EG_VRAM_SIZE_FLAGS	EG_CFG_VRAM_SIZE_512
#define	EG_VRAM_MBYTES_SIZE	(512 * 1024 * 1024)
#elif	defined(CONFIG_VRAM_SIZE_1024)
#define	EG_VRAM_SIZE_FLAGS	EG_CFG_VRAM_SIZE_1024
#define	EG_VRAM_MBYTES_SIZE	(1024 * 1024 * 1024)
#elif	defined(CONFIG_VRAM_DISABLE)
#define	EG_VRAM_MBYTES_SIZE	0
#else
 #error	"Undefined embeded graphic VRAM size"
#endif	/* CONFIG_VRAM_SIZE_ */

#define	START_KERNEL_SYSCALL	12

#define	ALIGN_UP(addr, size) (((u64)(addr) + ((size)-1)) & ~((size)-1))

u64	size_real;
#ifdef	CONFIG_ENABLE_EXTMEM
u64	hi_memory_start = HI_MEMORY_START;
#endif	/* CONFIG_ENABLE_EXTMEM */
#ifdef	CONFIG_ONLY_BSP_MEMORY
#define	only_BSP_has_memory	(memory_pres_map == 0x1)
#define	memory_pres_map		CONFIG_MEMORY_PRES_MAP
#else	/* ! CONFIG_ONLY_BSP_MEMORY */
#define	only_BSP_has_memory	0
#define	memory_pres_map		0xffff
#endif	/* CONFIG_ONLY_BSP_MEMORY */

inline void scall2(bootblock_struct_t *bootblock)
{
	(void) E2K_SYSCALL(START_KERNEL_SYSCALL,	/* Trap number */
			   0,				/* empty sysnum */
			   1,				/* single argument */
			   (long) bootblock);		/* the argument */
}

size_t
bios_strlen(const char *s)
{
	int len = 0;
	while (*s++) len++;
	return len;
}

static inline u64 get_hi_memory_start(int node_id)
{
	return HI_MEMORY_START + (HI_MEMORY_START * node_id);
}
static inline u64 get_lo_memory_size(int node_id)
{
	return (PCI_MEM_START - LO_MEMORY_START) / phys_node_num;
}
static inline u64 get_lo_memory_start(int node_id)
{
	return LO_MEMORY_START +  get_lo_memory_size(node_id) * node_id;
}

#ifdef	CONFIG_E2K_SIC
static inline e2k_rt_mhi_struct_t
get_rt_mhi(int mhi_no, int node_on, int node_for)
{
	e2k_rt_mhi_struct_t rt_mhi;

	AS_WORD(rt_mhi) = 0x000000ff;
	if (mhi_no != 0 && mhi_no != node_for) {
		rom_printk("BUG: memory router setting is implemented on "
			"node #0 for all other nodes\n");
		return rt_mhi;
	}
	switch (mhi_no) {
	case 0:
		AS_WORD(rt_mhi) = NATIVE_GET_SICREG(rt_mhi0, 0, node_on);
		return rt_mhi;
	case 1:
		AS_WORD(rt_mhi) = NATIVE_GET_SICREG(rt_mhi1, 0, node_on);
		return rt_mhi;
	case 2:
		AS_WORD(rt_mhi) = NATIVE_GET_SICREG(rt_mhi2, 0, node_on);
		return rt_mhi;
	case 3:
		AS_WORD(rt_mhi) = NATIVE_GET_SICREG(rt_mhi3, 0, node_on);
		return rt_mhi;
	default:
		rom_printk("BUG : get_rt_mhi() : invalid RT_MHI #%d >= "
			"%d (max node numbers), ignored\n",
			mhi_no, MAX_NUMNODES);
		return rt_mhi;
	}
}
static inline void
set_rt_mhi(e2k_rt_mhi_struct_t rt_mhi, int mhi_no, int node_on, int node_for)
{
	if (mhi_no != 0 && mhi_no != node_for) {
		rom_printk("BUG: memory router setting is only implemented on "
			"node #0 for all other nodes\n");
		return;
	}
	switch (mhi_no) {
	case 0:
		NATIVE_SET_SICREG(rt_mhi0, AS_WORD(rt_mhi), 0, node_on);
		return;
	case 1:
		NATIVE_SET_SICREG(rt_mhi1, AS_WORD(rt_mhi), 0, node_on);
		return;
	case 2:
		NATIVE_SET_SICREG(rt_mhi2, AS_WORD(rt_mhi), 0, node_on);
		return;
	case 3:
		NATIVE_SET_SICREG(rt_mhi3, AS_WORD(rt_mhi), 0, node_on);
		return;
	default:
		rom_printk("BUG : get_rt_mhi() : invalid RT_MHI #%d >= "
			"%d (max node numbers), ignored\n",
			mhi_no, MAX_NUMNODES);
		return;
	}
}
#endif	/* CONFIG_E2K_SIC */

static void
add_memory_region(boot_info_t *boot_info, int node_id, e2k_addr_t start_addr,
			e2k_size_t size)
{
	u64 end_addr = start_addr + size;
	bank_info_t *node_banks = boot_info->nodes_mem[node_id].banks;
	int bank;

#ifdef	CONFIG_DISCONTIGMEM
	if (node_id >= MAX_NUMNODES) {
		rom_printk("BUG : add_memory_region() : invalid node #%d >= "
			"%d (max node numbers), ignored\n",
			node_id, MAX_NUMNODES);
		return;
	} else
#endif	/* CONFIG_DISCONTIGMEM */
		if (node_id >= L_MAX_MEM_NUMNODES) {
		rom_printk("BUG : add_memory_region() : node #%d >= "
			"%d (max nodes in nodes_mem table), ignored\n",
			node_id, L_MAX_MEM_NUMNODES);
		return;
	}
	for (bank = 0; bank < L_MAX_NODE_PHYS_BANKS_FUSTY; bank++) {
		if (node_banks->size == 0)
			break;
		node_banks++;
	}
	if (start_addr == 0 && size == 0) {
		if (bank == L_MAX_NODE_PHYS_BANKS_FUSTY) {
			banks_ex_num++;
			rom_printk("Count of busy banks of memory in extended "
				"area was corrected from 0x%X to 0x%X\n",
				banks_ex_num - 1, banks_ex_num);
		}
		return;
	}
	if (bank >= L_MAX_NODE_PHYS_BANKS_FUSTY) {
		rom_printk("Node #%d has banks of memory in extended area\n",
			node_id);
		bank = -1;
		if (banks_ex_num >= L_MAX_PHYS_BANKS_EX) {
			rom_printk("BUG : add_memory_region() : banks of "
				"memory extended area is full, ignored\n");
			return;
		}
		node_banks = boot_info->bios.banks_ex + banks_ex_num++;
	}
	node_banks->address = start_addr;
	node_banks->size = size;
	if (bank != -1)
		rom_printk("Node #%d : physical memory bank #%d:  base from "
			"0x%X to 0x%X (%d Mgb)\n",
			node_id, bank, start_addr, end_addr,
			(int)(size / _1MB));
	else
		rom_printk("Node #%d : extended physical memory bank #%d: "
			"base from 0x%X to 0x%X (%d Mgb)\n",
			node_id, banks_ex_num - 1, start_addr, end_addr,
			(int)(size / _1MB));
	boot_info->num_of_banks ++;
}

static u64
probe_memory_region(boot_info_t *boot_info, e2k_addr_t start_addr,
			e2k_size_t size)
{
	u64 addr = start_addr;
	u64 address = start_addr;
	u64 end_addr = start_addr + size;
	u64 len;
	u64 memory_size = 0;
	u64 tmpvar;

	if (start_addr >= E2K_MAIN_MEM_REGION_START &&
		start_addr < E2K_MAIN_MEM_REGION_END) {
		if (start_addr + size > E2K_MAIN_MEM_REGION_END) {
			size = E2K_MAIN_MEM_REGION_END - start_addr;
			end_addr = start_addr + size;
		}
	} else if (start_addr >= E2K_MAIN_MEM_REGION_END &&
			start_addr < hi_memory_start) {
		rom_printk("no low memory for node");
		return 0;
	}
#ifdef	CONFIG_E2K_LEGACY_SIC
	/* Set memory range probing at TOP register of host bridge */
	if (end_addr >= APIC_DEFAULT_PHYS_BASE) {
		end_addr = APIC_DEFAULT_PHYS_BASE;
	}
	__boot_writel_hb_reg(end_addr, HB_PCI_TOM);

#endif	/* CONFIG_E2K_LEGACY_SIC */
	rom_printk("     from addr 0x%X to 0x%X ... ",
		start_addr, start_addr + size);
	while (address < end_addr) {

		if (address < _2MB) {
			addr = _2MB;
		}
		for ( ;  addr < end_addr; addr += _1MB) {
			/* Skip addresses reserved by PIC */
			if (addr == PIC_DEFAULT_PHYS_BASE
					|| addr == IO_PIC_DEFAULT_PHYS_BASE)
				break;

			/*
			    !!! WARNING !!! NEEDSWORK !!!
			     Improper tagged variable handling!
			 */
			tmpvar = NATIVE_READ_MAS_D(addr, MAS_IOADDR);

			NATIVE_WRITE_MAS_D(addr, 0x0123456789abcdef,
								 MAS_IOADDR);
			if (NATIVE_READ_MAS_D(addr, MAS_IOADDR) !=
							0x0123456789abcdef)
				break;
#ifdef	CONFIG_E2K_SIC
			if ((addr - start_addr) / E2K_SIC_MIN_MEMORY_BANK) {
				u64 offset = addr % E2K_SIC_MIN_MEMORY_BANK;
				u64 start_bank = start_addr + offset;

				if (NATIVE_READ_MAS_D(start_bank, MAS_IOADDR) ==
					0x0123456789abcdef) {
					/*
					 * New bank address point to start
					 * bank address, so enable memory size
					 * limit is reached
					 */
					NATIVE_WRITE_MAS_D(addr, tmpvar,
								MAS_IOADDR);
					break;
				}
			}
#endif	/* CONFIG_E2K_SIC */
			/*
			    !!! WARNING !!! NEEDSWORK !!!
		 	    Improper tagged variable handling!
			 */
			NATIVE_WRITE_MAS_D(addr, tmpvar, MAS_IOADDR);

			rom_putc('+');
		}
		len = addr - address;
		rom_putc('\n');
		memory_size = len;
		address = addr;
		/*
		 * Memory on e2k with SIC cannot be holed, so no more memory
		 */
		break;
		if (address >= end_addr)
			break;
		for ( ;  addr < end_addr; addr += _1MB) {
			/* Skip addresses reserved by PIC */
			if (addr == PIC_DEFAULT_PHYS_BASE
					|| addr == IO_PIC_DEFAULT_PHYS_BASE) {
				rom_putc('-');
				continue;
			}

			/*
			    !!! WARNING !!! NEEDSWORK !!!
			     Improper tagged variable handling!
			 */
			tmpvar = NATIVE_READ_MAS_D(addr, MAS_IOADDR);

			NATIVE_WRITE_MAS_D(addr, 0x0123456789abcdef,
								 MAS_IOADDR);
			if (NATIVE_READ_MAS_D(addr, MAS_IOADDR) ==
							0x0123456789abcdef) {

				/*
				    !!! WARNING !!! NEEDSWORK !!!
		 		    Improper tagged variable handling!
				 */
				NATIVE_WRITE_MAS_D(addr, tmpvar, MAS_IOADDR);
				rom_putc('\n');
				rom_printk("Physical memory hole:  base 0x%X "
					"size 0x%X  (%d Mgb)\n",
					address, addr - address,
					(int)((addr - address) / _1MB));
				break;
			}

			rom_putc('-');
		}
		address = addr;
	}

	rom_putc('\n');
	return memory_size;
}

static u64
probe_memory(boot_info_t *boot_info, int mhi_no, int node_on, int node_for)
{
	u64 address = 0;
	u64 size = 0;
#ifdef	CONFIG_E2K_SIC
	u64 hi_start, hi_end;
	e2k_rt_mhi_struct_t rt_mhi;
#endif

	if (mhi_no == 0) {
		rom_printk("Physical memory probing\n");
		boot_info->num_of_banks = 0;
	}
	address = E2K_MAIN_MEM_REGION_START;
	size = PROBE_MEM_LIMIT;
#if defined(CONFIG_E2K_SIC) && defined(CONFIG_ENABLE_EXTMEM)
	address = get_hi_memory_start(node_for);
	size = ALIGN_UP(size, E2K_SIC_SIZE_RT_MLO);
	size += PROBE_EXT_MEM_LIMIT;
#endif /* CONFIG_E2K_SIC && CONFIG_ENABLE_EXTMEM */
#ifdef	CONFIG_E2K_SIC
	if (!is_power_of_2(size)) {
		/* all memory banks size can be only 2^n */
		size = __roundup_pow_of_two(size);
	}
#endif	/* CONFIG_E2K_SIC */

#ifdef	CONFIG_E2K_SIC
	if (!is_power_of_2(size)) {
		/* all memory banks size can be only 2^n */
		size = __rounddown_pow_of_two(size);
	}
#else	/* ! CONFIG_E2K_SIC */
	if (size == 0)
		size = E2K_MAIN_MEM_REGION_END - address;
	if (address + size > E2K_MAIN_MEM_REGION_END)
		size = E2K_MAIN_MEM_REGION_END - address;
#endif	/* CONFIG_E2K_SIC */

	rom_printk("	init addr = 0x%X, init size = 0x%X\n", address, size);

#ifdef	CONFIG_E2K_SIC
	rt_mhi = get_rt_mhi(mhi_no, node_on, node_for);
	DebugMRT("get_memory_filters: on node #%d rt_mhi%d = 0x%x\n",
		node_on, mhi_no, AS_WORD(rt_mhi));
	hi_start = ALIGN_DOWN_TO_SIZE(address, E2K_SIC_SIZE_RT_MHI);
	hi_end = ALIGN_UP_TO_SIZE(address + size, E2K_SIC_SIZE_RT_MHI);
	AS_STRUCT(rt_mhi).bgn = hi_start >> E2K_SIC_ALIGN_RT_MHI;
	AS_STRUCT(rt_mhi).end = (hi_end - 1) >> E2K_SIC_ALIGN_RT_MHI;
	DebugMRT("set_memory_filters: on node #%d set rt_mhi%d to 0x%x\n",
		node_on, mhi_no,
		AS_WORD(get_rt_mhi(mhi_no, node_on, node_for)));
	set_rt_mhi(rt_mhi, mhi_no, node_on, node_for);
	if (mhi_no != 0) {
		/* setup rt_mhi0 on node 'for' */
		DebugMRT("set_memory_filters: on node #%d set rt_mhi%d "
			"to 0x%x\n",
			node_for, 0,
			AS_WORD(get_rt_mhi(0, node_for, node_for)));
		set_rt_mhi(rt_mhi, 0, node_for, node_for);
	}
	rom_printk("NODE #%d high memory router set from 0x%X to 0x%X\n",
		node_on, hi_start, hi_end);
#endif

	size_real = probe_memory_region(boot_info, address, size);
	return size_real;
}

static void
add_busy_memory_area(boot_info_t *boot_info,
			e2k_addr_t area_start, e2k_addr_t area_end)
{
	int num_of_busy = boot_info->num_of_busy;
	bank_info_t *busy_area = &boot_info->busy[num_of_busy];

	busy_area->address = area_start;
	busy_area->size = area_end - area_start;

	rom_printk("ROM loader busy memory area #%d start 0x%X, end 0x%X\n",
		num_of_busy, area_start, area_end);

	num_of_busy ++;
	boot_info->num_of_busy = num_of_busy;
}

#ifdef	CONFIG_L_IO_APIC
#ifndef CONFIG_ENABLE_BIOS_MPTABLE
static int
mpf_do_checksum(unsigned char *mp, int len)
{
	int sum = 0;

	while (len--)
		sum += *mp++;

	return 0x100 - (sum & 0xFF);
}

static void
set_mpt_config(struct intel_mp_floating *mpf)
{

	mpf->mpf_signature[0]	= '_';		/* "_MP_" */
	mpf->mpf_signature[1]	= 'M';
	mpf->mpf_signature[2]	= 'P';
	mpf->mpf_signature[3]	= '_';
	mpf->mpf_physptr	= 0;		/* MP Configuration Table */
						/* does not exist	*/
	mpf->mpf_length		= 0x01;
	mpf->mpf_specification	= 0x01;
	mpf->mpf_checksum	= 0;		/* ??? */
	mpf->mpf_feature1	= 1;		/* If 0 MP CT exist, */
						/* else # default CT */
	mpf->mpf_feature2	= 1<<7;		/* PIC mode */
	mpf->mpf_feature3	= 0;
	mpf->mpf_feature4	= 0;
	mpf->mpf_feature5	= 0;
	mpf->mpf_checksum	= mpf_do_checksum((unsigned char *)mpf,
								sizeof (*mpf));
}
#endif
#endif	/* CONFIG_L_IO_APIC */

static inline e2k_addr_t
allocate_mpf_structure(void)
{
#ifndef	CONFIG_L_IO_APIC
	return (e2k_addr_t)0;
#else

	return (e2k_addr_t) malloc_aligned(PAGE_SIZE, PAGE_SIZE);
#endif	/* ! (CONFIG_L_IO_APIC) */
}

static void
create_smp_config(boot_info_t *boot_info)
{

#ifndef	CONFIG_SMP
	boot_info->num_of_cpus = 1;
	boot_info->num_of_nodes = 1;
	boot_info->nodes_map = 0x1;
#else
	boot_info->num_of_cpus = phys_cpu_num;
	boot_info->num_of_nodes = phys_node_num;
	boot_info->nodes_map = phys_node_pres_map;
#endif	/* CONFIG_SMP */

	boot_info->mp_table_base = allocate_mpf_structure();

#ifdef	CONFIG_L_IO_APIC
#ifndef CONFIG_ENABLE_BIOS_MPTABLE
	set_mpt_config((struct intel_mp_floating *)boot_info->mp_table_base);
#else
	write_smp_table((struct intel_mp_floating *)boot_info->mp_table_base,
				boot_info->num_of_cpus);
#endif /* CONFIG_BIOS */
	rom_printk("MP-table is starting at: 0x%X size 0x%x\n",
		boot_info->mp_table_base, PAGE_SIZE);

#endif	/* CONFIG_L_IO_APIC */
}

#ifdef	CONFIG_RECOVERY
static void
recover_smp_config(boot_info_t *recovery_info)
{
	(void) allocate_mpf_structure();

#ifdef	CONFIG_SMP
	if (recovery_info->num_of_cpus != phys_cpu_num) {
		rom_puts("ERROR: Invalid number of live CPUs to recover "
			"kernel\n");
		rom_printk("Number of live CPUs %d is not %d as from "
			"'recovery_info'\n",
			phys_cpu_num, recovery_info->num_of_cpus);
	}
#endif	/* CONFIG_SMP */

}
#endif	/* CONFIG_RECOVERY */

#ifdef CONFIG_CMDLINE_PROMPT

static void kernel_command_prompt(char *line, char *preset)
{
	char *cp, ch; 
	int sec_start, sec_stop;

#define	COMMAND_PROMPT_TIMEOUT		3

	rom_printk("\nCommand: ");
	cp = line;

	/* Simple PC-keyboard manager */
	memcpy(line, preset, bios_strlen(preset));
	while ( *cp ) rom_putc(*cp++);

	sec_start = CMOS_READ(RTC_SECONDS);
	sec_stop = sec_start + COMMAND_PROMPT_TIMEOUT;
	if (sec_stop > 60)
		sec_stop = sec_stop - 60;

	while (CMOS_READ(RTC_SECONDS) != sec_stop) {
		if (keyb_tstc()) {	
			while ((ch = rom_getc()) != '\n' &&
							ch != '\r') {
				if (ch == '\b') {
					if (cp != line) {
						cp--;
						rom_puts("\b \b");
					};
				} else {
					*cp++ = ch;
					rom_putc(ch);
				};
			}
			break;  /* Exit 'timer' loop */
		}
	}

	*cp = 0;
	rom_putc('\n');
}

#endif

#ifdef	CONFIG_E2K_SIC
#ifdef	CONFIG_E2K_FULL_SIC
static void configure_routing_regs(void)
{
	e2k_rt_lcfg_struct_t	rt_lcfg;
	e2k_rt_mlo_struct_t	rt_mlo;
	e2k_st_p_struct_t	st_p;

	E2K_RT_LCFG_reg(rt_lcfg) = NATIVE_GET_SICREG(rt_lcfg0, E2K_MAX_CL_NUM, 0);
	DebugRT("configure_routing_regs: before setting up: rt_lcfg = 0x%x\n",
		E2K_RT_LCFG_reg(rt_lcfg));

	DebugRT("configure_routing_regs: configure RT_LCFGj\n");
	phys_node_num = 1;
	phys_node_pres_map = 0x1;

	AS_WORD(st_p) = NATIVE_GET_SICREG(st_p, E2K_MAX_CL_NUM, 0);
	DebugRT("configure_routing_regs: st_p = 0x%x\n", AS_WORD(st_p));

if (st_p.E2K_ST_P_pl_val & 0x1){ // 001 - CPU 1 is present
/***********************  CONFIGURE KNOB 1  ***********************************/
	phys_node_num ++;
	phys_node_pres_map |= 0x02;
	/* Open link CPU 0 -> CPU 1 */
	E2K_RT_LCFG_reg(rt_lcfg) = NATIVE_GET_SICREG(rt_lcfg1, E2K_MAX_CL_NUM, 0);
	E2K_RT_LCFG_vp(rt_lcfg) = 1;
	E2K_RT_LCFG_vb(rt_lcfg) = 0;
	E2K_RT_LCFG_vio(rt_lcfg) = 0;
	NATIVE_SET_SICREG(rt_lcfg1, E2K_RT_LCFG_reg(rt_lcfg), E2K_MAX_CL_NUM, 0);
	
		/* setup LCFG0 for knob 1; initially knob 1 = knob 3 */
		E2K_RT_LCFG_reg(rt_lcfg) =
			NATIVE_GET_SICREG(rt_lcfg0, E2K_MAX_CL_NUM, 3);
		/* open all links for knob 3 */
		E2K_RT_LCFG_vp(rt_lcfg) = 1;
		E2K_RT_LCFG_vb(rt_lcfg) = 0;
		E2K_RT_LCFG_vio(rt_lcfg) = 0;
		/* setting knob cluster to 0 */
		E2K_RT_LCFG_cln(rt_lcfg) = 0;
		/* setting knob number 3 to 1 */
		E2K_RT_LCFG_pln(rt_lcfg) = 1;
		NATIVE_SET_SICREG(rt_lcfg0, E2K_RT_LCFG_reg(rt_lcfg),
				E2K_MAX_CL_NUM, 3);

/* setup LCFGj for knob 1;*/

	/* change parameters for BSP (due to new params for knob 1: cln = 0| pln = 1) */
	E2K_RT_LCFG_reg(rt_lcfg) = NATIVE_GET_SICREG(rt_lcfg0, E2K_MAX_CL_NUM, 0);
	E2K_RT_LCFG_cln(rt_lcfg) = 0;
	NATIVE_SET_SICREG(rt_lcfg0, E2K_RT_LCFG_reg(rt_lcfg), E2K_MAX_CL_NUM, 0);
	/* change parameters for link CPU 0 -> CPU 1 (due to new params for knob 1: pln = 1) */
	E2K_RT_LCFG_reg(rt_lcfg) = NATIVE_GET_SICREG(rt_lcfg1, 0, 0);
	E2K_RT_LCFG_pln(rt_lcfg) = 1;
	NATIVE_SET_SICREG(rt_lcfg1, E2K_RT_LCFG_reg(rt_lcfg), 0, 0);
		/****************************/
	if (st_p.E2K_ST_P_pl_val & 0x2){ // 010 - Node 2 is present
		/**** setup LCFG1 params ****/
		E2K_RT_LCFG_reg(rt_lcfg) = NATIVE_GET_SICREG(rt_lcfg1, 0, 1);
		/* open all links for knob 1 */
		E2K_RT_LCFG_vp(rt_lcfg) = 1;
		E2K_RT_LCFG_vb(rt_lcfg) = 0;
		E2K_RT_LCFG_vio(rt_lcfg) = 0;
		/* setting link CPU 1 -> CPU 2 */
		E2K_RT_LCFG_pln(rt_lcfg) = 2;
		NATIVE_SET_SICREG(rt_lcfg1, E2K_RT_LCFG_reg(rt_lcfg), 0, 1);
	}else{
		/* close link CPU 1 -> CPU 2 */
		E2K_RT_LCFG_reg(rt_lcfg) = NATIVE_GET_SICREG(rt_lcfg1, 0, 1);
		E2K_RT_LCFG_vp(rt_lcfg) = 0;
		NATIVE_SET_SICREG(rt_lcfg1, E2K_RT_LCFG_reg(rt_lcfg), 0, 1);
	}
	if (st_p.E2K_ST_P_pl_val & 0x4){ // 100 - Node 3 is present	
		/**** setup LCFG2 params ****/
		E2K_RT_LCFG_reg(rt_lcfg) = NATIVE_GET_SICREG(rt_lcfg2, 0, 1);
		/* open all links for knob 1 */
		E2K_RT_LCFG_vp(rt_lcfg) = 1;
		E2K_RT_LCFG_vb(rt_lcfg) = 0;
		E2K_RT_LCFG_vio(rt_lcfg) = 0;
		/* setiing link CPU 1 -> CPU 3 */
		E2K_RT_LCFG_pln(rt_lcfg) = 3;
		NATIVE_SET_SICREG(rt_lcfg2, E2K_RT_LCFG_reg(rt_lcfg), 0, 1);
	}else{
		/* close link CPU 1 -> CPU 3 */
		E2K_RT_LCFG_reg(rt_lcfg) = NATIVE_GET_SICREG(rt_lcfg2, 0, 1);
		E2K_RT_LCFG_vp(rt_lcfg) = 0;
		NATIVE_SET_SICREG(rt_lcfg2, E2K_RT_LCFG_reg(rt_lcfg), 0, 1);
	}

		/**** setup LCFG3 params ****/
		E2K_RT_LCFG_reg(rt_lcfg) = NATIVE_GET_SICREG(rt_lcfg3, 0, 1);
		/* open all links for knob 1 */
		E2K_RT_LCFG_vp(rt_lcfg) = 1;
		E2K_RT_LCFG_vb(rt_lcfg) = 1;
		E2K_RT_LCFG_vio(rt_lcfg) = 1;
		/* setiing link CPU 1 -> CPU 0 */
		E2K_RT_LCFG_pln(rt_lcfg) = 0;
		NATIVE_SET_SICREG(rt_lcfg3, E2K_RT_LCFG_reg(rt_lcfg), 0, 1);
		/*****************************/
		/*#####################################################*/
		/* configure own link CPU 1 to own ioapic space */
		/* configure link CPU 1 to pcim space through CPU 0 */
		/* configure link CPU 1 to mlo space through CPU 0 */
		AS_WORD(rt_mlo) = NATIVE_GET_SICREG(rt_mlo0, 0, 0);
		NATIVE_SET_SICREG(rt_mlo3, AS_WORD(rt_mlo), 0, 1);
		/* May be the same for mhi ????????? */
		/*#####################################################*/

	/* Restore previous values for BSP */
	E2K_RT_LCFG_reg(rt_lcfg) = NATIVE_GET_SICREG(rt_lcfg0, 0, 0);
	E2K_RT_LCFG_cln(rt_lcfg) = E2K_MAX_CL_NUM;
	NATIVE_SET_SICREG(rt_lcfg0, E2K_RT_LCFG_reg(rt_lcfg), 0, 0);
	/* Close link CPU 0 -> CPU 1 */
	E2K_RT_LCFG_reg(rt_lcfg) = NATIVE_GET_SICREG(rt_lcfg1, E2K_MAX_CL_NUM, 0);
	E2K_RT_LCFG_vp(rt_lcfg) = 0;
	E2K_RT_LCFG_vb(rt_lcfg) = 0;
	E2K_RT_LCFG_vio(rt_lcfg) = 0;
	NATIVE_SET_SICREG(rt_lcfg1, E2K_RT_LCFG_reg(rt_lcfg), E2K_MAX_CL_NUM, 0);
/*****************************************************************************/
}
if (st_p.E2K_ST_P_pl_val & 0x2){ // 010 - Node 2 is present
/***********************  CONFIGURE KNOB 2  ***********************************/
	phys_node_num ++;
	phys_node_pres_map |= 0x04;

	/* Open link CPU 0 -> CPU 2 */
	E2K_RT_LCFG_reg(rt_lcfg) = NATIVE_GET_SICREG(rt_lcfg2, E2K_MAX_CL_NUM, 0);
	E2K_RT_LCFG_vp(rt_lcfg) = 1;
	E2K_RT_LCFG_vb(rt_lcfg) = 0;
	E2K_RT_LCFG_vio(rt_lcfg) = 0;
	NATIVE_SET_SICREG(rt_lcfg2, E2K_RT_LCFG_reg(rt_lcfg), E2K_MAX_CL_NUM, 0);
	
		/* setup LCFG0 for knob 2; initially knob 2 = knob 3 */
		E2K_RT_LCFG_reg(rt_lcfg) =
			NATIVE_GET_SICREG(rt_lcfg0, E2K_MAX_CL_NUM, 3);
		/* open all links for knob 2 */
		E2K_RT_LCFG_vp(rt_lcfg) = 1;
		E2K_RT_LCFG_vb(rt_lcfg) = 0;
		E2K_RT_LCFG_vio(rt_lcfg) = 0;
		/* setting knob cluster to 0 */
		E2K_RT_LCFG_cln(rt_lcfg) = 0;
		/* setting knob number 3 to 2 */
		E2K_RT_LCFG_pln(rt_lcfg) = 2;
		NATIVE_SET_SICREG(rt_lcfg0, E2K_RT_LCFG_reg(rt_lcfg),
				E2K_MAX_CL_NUM, 3);

/* setup LCFGj for knob 2 */
		
	/* change parameters for BSP (due to new params for knob 2: cln = 0| pln = 2) */
	E2K_RT_LCFG_reg(rt_lcfg) = NATIVE_GET_SICREG(rt_lcfg0, E2K_MAX_CL_NUM, 0);
	E2K_RT_LCFG_cln(rt_lcfg) = 0;
	NATIVE_SET_SICREG(rt_lcfg0, E2K_RT_LCFG_reg(rt_lcfg), E2K_MAX_CL_NUM, 0);
	/* change parameters for link CPU 0 -> CPU 2 (due to new params for knob 2: pln = 2) */
	E2K_RT_LCFG_reg(rt_lcfg) = NATIVE_GET_SICREG(rt_lcfg2, 0, 0);
	E2K_RT_LCFG_pln(rt_lcfg) = 2;
	NATIVE_SET_SICREG(rt_lcfg2, E2K_RT_LCFG_reg(rt_lcfg), 0, 0);
		/****************************/
	if (st_p.E2K_ST_P_pl_val & 0x4){ // 100 - Node 3 is present
		/**** setup LCFG1 params ****/
		E2K_RT_LCFG_reg(rt_lcfg) = NATIVE_GET_SICREG(rt_lcfg1, 0, 2);
		/* open all links for knob 2 */
		E2K_RT_LCFG_vp(rt_lcfg) = 1;
		E2K_RT_LCFG_vb(rt_lcfg) = 0;
		E2K_RT_LCFG_vio(rt_lcfg) = 0;
		/* setting link CPU 2 -> CPU 3 */
		E2K_RT_LCFG_pln(rt_lcfg) = 3;
		NATIVE_SET_SICREG(rt_lcfg1, E2K_RT_LCFG_reg(rt_lcfg), 0, 2);
	}else{
		/* close link CPU 2 -> CPU 3 */
		E2K_RT_LCFG_reg(rt_lcfg) = NATIVE_GET_SICREG(rt_lcfg1, 0, 2);
		E2K_RT_LCFG_vp(rt_lcfg) = 0;
		NATIVE_SET_SICREG(rt_lcfg1, E2K_RT_LCFG_reg(rt_lcfg), 0, 2);
	}	
		
		/**** setup LCFG2 params ****/
		E2K_RT_LCFG_reg(rt_lcfg) = NATIVE_GET_SICREG(rt_lcfg2, 0, 2);
		/* open all links for knob 1 */
		E2K_RT_LCFG_vp(rt_lcfg) = 1;
		E2K_RT_LCFG_vb(rt_lcfg) = 1;
		E2K_RT_LCFG_vio(rt_lcfg) = 1;
		/* setiing link CPU 2 -> CPU 0 */
		E2K_RT_LCFG_pln(rt_lcfg) = 0;
		NATIVE_SET_SICREG(rt_lcfg2, E2K_RT_LCFG_reg(rt_lcfg), 0, 2);
		/*#####################################################*/
		/* configure link CPU 2 to mlo space through CPU 0 */
		AS_WORD(rt_mlo) = NATIVE_GET_SICREG(rt_mlo0, 0, 0);
		NATIVE_SET_SICREG(rt_mlo2, AS_WORD(rt_mlo), 0, 2);
		/* May be the same for mhi ????????? */
		/*#####################################################*/
	if (st_p.E2K_ST_P_pl_val & 0x1){ // 001 - Node 1 is present
		/**** setup LCFG3 params ****/
		E2K_RT_LCFG_reg(rt_lcfg) = NATIVE_GET_SICREG(rt_lcfg3, 0, 2);
		/* open all links for knob 1 */
		E2K_RT_LCFG_vp(rt_lcfg) = 1;
		E2K_RT_LCFG_vb(rt_lcfg) = 0;
		E2K_RT_LCFG_vio(rt_lcfg) = 0;
		/* setiing link CPU 2 -> CPU 1 */
		E2K_RT_LCFG_pln(rt_lcfg) = 1;
		NATIVE_SET_SICREG(rt_lcfg3, E2K_RT_LCFG_reg(rt_lcfg), 0, 2);
		/*****************************/		
	}else{
		/* close link CPU 2 -> CPU 1 */
		E2K_RT_LCFG_reg(rt_lcfg) = NATIVE_GET_SICREG(rt_lcfg3, 0, 2);
		E2K_RT_LCFG_vp(rt_lcfg) = 0;
		NATIVE_SET_SICREG(rt_lcfg3, E2K_RT_LCFG_reg(rt_lcfg), 0, 2);
	}
	/* Restore previous values for BSP */
	E2K_RT_LCFG_reg(rt_lcfg) = NATIVE_GET_SICREG(rt_lcfg0, 0, 0);
	E2K_RT_LCFG_cln(rt_lcfg) = E2K_MAX_CL_NUM;
	NATIVE_SET_SICREG(rt_lcfg0, E2K_RT_LCFG_reg(rt_lcfg), 0, 0);
	/* Close link CPU 0 -> CPU 2 */
	E2K_RT_LCFG_reg(rt_lcfg) = NATIVE_GET_SICREG(rt_lcfg2, E2K_MAX_CL_NUM, 0);
	E2K_RT_LCFG_vp(rt_lcfg) = 0;
	E2K_RT_LCFG_vb(rt_lcfg) = 0;
	E2K_RT_LCFG_vio(rt_lcfg) = 0;
	NATIVE_SET_SICREG(rt_lcfg2, E2K_RT_LCFG_reg(rt_lcfg), E2K_MAX_CL_NUM, 0);
/*****************************************************************************/
}
if (st_p.E2K_ST_P_pl_val & 0x4){ // 100 - Node 3 is present
/***********************  CONFIGURE KNOB 3  ***********************************/
	phys_node_num ++;
	phys_node_pres_map |= 0x08;

	/* Open link CPU 0 -> CPU 3 */
	E2K_RT_LCFG_reg(rt_lcfg) = NATIVE_GET_SICREG(rt_lcfg3, E2K_MAX_CL_NUM, 0);
	E2K_RT_LCFG_vp(rt_lcfg) = 1;
	E2K_RT_LCFG_vb(rt_lcfg) = 0;
	E2K_RT_LCFG_vio(rt_lcfg) = 0;
	NATIVE_SET_SICREG(rt_lcfg3, E2K_RT_LCFG_reg(rt_lcfg), E2K_MAX_CL_NUM, 0);
	
		/* setup LCFG0 for knob 3 */
		E2K_RT_LCFG_reg(rt_lcfg) =
			NATIVE_GET_SICREG(rt_lcfg0, E2K_MAX_CL_NUM, 3);
		/* open all links for knob 2 */
		E2K_RT_LCFG_vp(rt_lcfg) = 1;
		E2K_RT_LCFG_vb(rt_lcfg) = 0;
		E2K_RT_LCFG_vio(rt_lcfg) = 0;
		/* setting knob cluster to 0 */
		E2K_RT_LCFG_cln(rt_lcfg) = 0;
		NATIVE_SET_SICREG(rt_lcfg0, E2K_RT_LCFG_reg(rt_lcfg),
				E2K_MAX_CL_NUM, 3);

/* setup LCFGj for knob 3 */
		
	/* change parameters for BSP (due to new params for knob 3: cln = 0| pln = 3) */
	E2K_RT_LCFG_reg(rt_lcfg) = NATIVE_GET_SICREG(rt_lcfg0, E2K_MAX_CL_NUM, 0);
	E2K_RT_LCFG_cln(rt_lcfg) = 0;
	NATIVE_SET_SICREG(rt_lcfg0, E2K_RT_LCFG_reg(rt_lcfg), E2K_MAX_CL_NUM, 0);
	/* change parameters for link CPU 0 -> CPU 3 (due to new params for knob 3: pln = 3) */
	E2K_RT_LCFG_reg(rt_lcfg) = NATIVE_GET_SICREG(rt_lcfg3, 0, 0);
	E2K_RT_LCFG_pln(rt_lcfg) = 3;
	NATIVE_SET_SICREG(rt_lcfg3, E2K_RT_LCFG_reg(rt_lcfg), 0, 0);
		/****************************/
		/**** setup LCFG1 params ****/
		E2K_RT_LCFG_reg(rt_lcfg) = NATIVE_GET_SICREG(rt_lcfg1, 0, 3);
		/* open all links for knob 3 */
		E2K_RT_LCFG_vp(rt_lcfg) = 1;
		E2K_RT_LCFG_vb(rt_lcfg) = 1;
		E2K_RT_LCFG_vio(rt_lcfg) = 1;
		/* setting link CPU 3 -> CPU 0 */
		E2K_RT_LCFG_pln(rt_lcfg) = 0;
		NATIVE_SET_SICREG(rt_lcfg1, E2K_RT_LCFG_reg(rt_lcfg), 0, 3);
		/*#####################################################*/
		/* configure link CPU 3 to mlo space through CPU 0 */
		AS_WORD(rt_mlo) = NATIVE_GET_SICREG(rt_mlo0, 0, 0);
		NATIVE_SET_SICREG(rt_mlo1, AS_WORD(rt_mlo), 0, 3);
		/* May be the same for mhi ????????? */
		/*#####################################################*/
	if (st_p.E2K_ST_P_pl_val & 0x1){ // 001 - Node 1 is present
		/**** setup LCFG2 params ****/
		E2K_RT_LCFG_reg(rt_lcfg) = NATIVE_GET_SICREG(rt_lcfg2, 0, 3);
		/* open all links for knob 3 */
		E2K_RT_LCFG_vp(rt_lcfg) = 1;
		E2K_RT_LCFG_vb(rt_lcfg) = 0;
		E2K_RT_LCFG_vio(rt_lcfg) = 0;
		/* setiing link CPU 3 -> CPU 1 */
		E2K_RT_LCFG_pln(rt_lcfg) = 1;
		NATIVE_SET_SICREG(rt_lcfg2, E2K_RT_LCFG_reg(rt_lcfg), 0, 3);
	}else{
		/* close link CPU 3 -> CPU 1 */
		E2K_RT_LCFG_reg(rt_lcfg) = NATIVE_GET_SICREG(rt_lcfg2, 0, 3);
		E2K_RT_LCFG_vp(rt_lcfg) = 0;
		NATIVE_SET_SICREG(rt_lcfg2, E2K_RT_LCFG_reg(rt_lcfg), 0, 3);
	}
	if (st_p.E2K_ST_P_pl_val & 0x2){ // 010 - Node 2 is present	
		/**** setup LCFG3 params ****/
		E2K_RT_LCFG_reg(rt_lcfg) = NATIVE_GET_SICREG(rt_lcfg3, 0, 3);
		/* open all links for knob 3 */
		E2K_RT_LCFG_vp(rt_lcfg) = 1;
		E2K_RT_LCFG_vb(rt_lcfg) = 0;
		E2K_RT_LCFG_vio(rt_lcfg) = 0;
		/* setiing link CPU 3 -> CPU 2 */
		E2K_RT_LCFG_pln(rt_lcfg) = 2;
		NATIVE_SET_SICREG(rt_lcfg3, E2K_RT_LCFG_reg(rt_lcfg), 0, 3);
		/*****************************/		
	}else{
		/* close link CPU 3 -> CPU 2 */
		E2K_RT_LCFG_reg(rt_lcfg) = NATIVE_GET_SICREG(rt_lcfg3, 0, 3);
		E2K_RT_LCFG_vp(rt_lcfg) = 0;
		NATIVE_SET_SICREG(rt_lcfg3, E2K_RT_LCFG_reg(rt_lcfg), 0, 3);
	}
/*******************************************************************************/
}
if (!(st_p.E2K_ST_P_pl_val & 0x4)){ // 100 - Node 3 is not present
	/* change parameters for BSP (cln = 0| pln = 0) */
	E2K_RT_LCFG_reg(rt_lcfg) = NATIVE_GET_SICREG(rt_lcfg0, E2K_MAX_CL_NUM, 0);
	E2K_RT_LCFG_cln(rt_lcfg) = 0;
	NATIVE_SET_SICREG(rt_lcfg0, E2K_RT_LCFG_reg(rt_lcfg), E2K_MAX_CL_NUM, 0);
}

	/* Open all links (cfg1 and cfg3) BSP */
if (st_p.E2K_ST_P_pl_val & 0x1){ // 001 - Node 1 is present
	/* Open link CPU 0 -> CPU 1 */
	E2K_RT_LCFG_reg(rt_lcfg) = NATIVE_GET_SICREG(rt_lcfg1, 0, 0);
	E2K_RT_LCFG_vp(rt_lcfg) = 1;
	E2K_RT_LCFG_vb(rt_lcfg) = 0;
	E2K_RT_LCFG_vio(rt_lcfg) = 0;
	NATIVE_SET_SICREG(rt_lcfg1, E2K_RT_LCFG_reg(rt_lcfg), 0, 0);
}
if (st_p.E2K_ST_P_pl_val & 0x2){ // 010 - Node 2 is present
	/* Open link CPU 0 -> CPU 2 */
	E2K_RT_LCFG_reg(rt_lcfg) = NATIVE_GET_SICREG(rt_lcfg2, 0, 0);
	E2K_RT_LCFG_vp(rt_lcfg) = 1;
	E2K_RT_LCFG_vb(rt_lcfg) = 0;
	E2K_RT_LCFG_vio(rt_lcfg) = 0;
	NATIVE_SET_SICREG(rt_lcfg2, E2K_RT_LCFG_reg(rt_lcfg), 0, 0);
}
/*****************************************************************************/
	rom_printk("KNOB 0:		rt_lcfg0	rt_lcfg1	rt_lcfg2	rt_lcfg3\n"
		   "		0x%x		0x%x		0x%x		0x%x\n"
		   "		st_p	0x%x\n",			
				NATIVE_GET_SICREG(rt_lcfg0, 0, 0), NATIVE_GET_SICREG(rt_lcfg1, 0, 0),
				NATIVE_GET_SICREG(rt_lcfg2, 0, 0),	NATIVE_GET_SICREG(rt_lcfg3, 0, 0),
				NATIVE_GET_SICREG(st_p, 0, 0));
if (st_p.E2K_ST_P_pl_val & 0x1){ // 001 - Node 1 is present
	rom_printk("KNOB 1:		rt_lcfg0	rt_lcfg1	rt_lcfg2	rt_lcfg3\n"
		   "		0x%x		0x%x		0x%x		0x%x\n"
		   "		st_p	0x%x\n",
				NATIVE_GET_SICREG(rt_lcfg0, 0, 1), NATIVE_GET_SICREG(rt_lcfg1, 0, 1),
				NATIVE_GET_SICREG(rt_lcfg2, 0, 1),	NATIVE_GET_SICREG(rt_lcfg3, 0, 1),
				NATIVE_GET_SICREG(st_p, 0, 1));
}
if (st_p.E2K_ST_P_pl_val & 0x2){ // 020 - Node 2 is present
	rom_printk("KNOB 2:		rt_lcfg0	rt_lcfg1	rt_lcfg2	rt_lcfg3\n"
		   "		0x%x		0x%x		0x%x		0x%x\n"
		   "		st_p	0x%x\n",	
				NATIVE_GET_SICREG(rt_lcfg0, 0, 2), NATIVE_GET_SICREG(rt_lcfg1, 0, 2),
				NATIVE_GET_SICREG(rt_lcfg2, 0, 2),	NATIVE_GET_SICREG(rt_lcfg3, 0, 2),
				NATIVE_GET_SICREG(st_p, 0, 2));
}
if (st_p.E2K_ST_P_pl_val & 0x4){ // 100 - Node 3 is present
	rom_printk("KNOB 3:		rt_lcfg0	rt_lcfg1	rt_lcfg2	rt_lcfg3\n"
		   "		0x%x		0x%x		0x%x		0x%x\n"
		   "		st_p	0x%x\n",	
				NATIVE_GET_SICREG(rt_lcfg0, 0, 3), NATIVE_GET_SICREG(rt_lcfg1, 0, 3),
				NATIVE_GET_SICREG(rt_lcfg2, 0, 3),	NATIVE_GET_SICREG(rt_lcfg3, 0, 3),
				NATIVE_GET_SICREG(st_p, 0, 3));
}
}
void set_memory_filters(boot_info_t *boot_info)
{
	u64 size_lo = size_real;
	u64 memory_start = 0;	/* memory starts from 0 and can be on BSP */
	e2k_rt_mlo_struct_t	rt_mlo;
	u64 hole_size_lo, lo_memory_start;
#ifdef	CONFIG_SMP
	u64 size_to_probe;
#endif	/* CONFIG_SMP */
#ifdef	CONFIG_ENABLE_EXTMEM
	u64 size_hi = 0;
#ifdef	CONFIG_SMP
	u64 lo_high_memory_start;
	u64 lo_high_memory_size;
	u64 hi_high_memory_start;
	u64 hi_high_memory_size;
#endif	/* CONFIG_SMP */
	e2k_rt_mhi_struct_t	rt_mhi;
#endif	/* CONFIG_ENABLE_EXTMEM */

	/* Configure MLO & MHI for BSP. */
	AS_WORD(rt_mlo) = NATIVE_GET_SICREG(rt_mlo0, 0, 0);
	DebugMRT("get_memory_filters: BSP rt_mlo0 = 0x%x\n",
		AS_WORD(rt_mlo));

	size_lo = get_lo_memory_size(0);
	if (size_lo > size_real)
		size_lo = size_real;
	lo_memory_start = get_lo_memory_start(0);
	lo_memory_start = ALIGN_UP(lo_memory_start, E2K_SIC_MIN_MEMORY_BANK);

	AS_STRUCT(rt_mlo).bgn = (u32)(lo_memory_start / E2K_SIC_SIZE_RT_MLO);
	AS_STRUCT(rt_mlo).end = (u32)((lo_memory_start + size_lo - 1) /
							E2K_SIC_SIZE_RT_MLO);
	NATIVE_SET_SICREG(rt_mlo0, AS_WORD(rt_mlo), 0, 0);
	rom_printk("BSP NODE #0 low memory router set from 0x%X to "
		"0x%X\n",
		lo_memory_start, lo_memory_start + size_lo - 1);
	DebugMRT("set_memory_filters: BSP set rt_mlo0 to 0x%x\n",
		AS_WORD(rt_mlo));
	add_memory_region(boot_info, 0, lo_memory_start, size_lo);
#ifdef	CONFIG_SMP
	if (phys_node_pres_map & 0x2) {    /* NODE #1 is online */
		/*
		 * Setup memory routers of NODE #1 to access memory NODE #0
		 * NODE #0 is located on link #3 of NODE #1
		 */
		NATIVE_SET_SICREG(rt_mlo3, AS_WORD(rt_mlo), 0, 1);
		DebugMRT("set_memory_filters: NODE #1 set rt_mlo3 to 0x%x "
			"to access to memory of NODE #0\n",
			AS_WORD(rt_mlo));
	}
	if (phys_node_pres_map & 0x4) {   /* NODE #2 is online */
		/*
		 * Setup memory routers of NODE #2 to access memory NODE #0
		 * NODE #0 is located on link #2 of NODE #2
		 */
		NATIVE_SET_SICREG(rt_mlo2, AS_WORD(rt_mlo), 0, 2);
		DebugMRT("set_memory_filters: NODE #2 set rt_mlo2 to 0x%x "
			"to access to memory of NODE #0\n",
			AS_WORD(rt_mlo));
	}
	if (phys_node_pres_map & 0x8) {    /* NODE #3 is online */
		/*
		 * Setup memory routers of NODE #3 to access memory NODE #0
		 * NODE #0 is located on link #1 of NODE #3
		 */
		NATIVE_SET_SICREG(rt_mlo1, AS_WORD(rt_mlo), 0, 3);
		DebugMRT("set_memory_filters: NODE #3 set rt_mlo1 to 0x%x "
			"to access to memory of NODE #0\n",
			AS_WORD(rt_mlo));
	}
#endif	/* CONFIG_SMP */
	memory_start += size_lo;
	memory_start = ALIGN_UP(memory_start, E2K_SIC_MIN_MEMORY_BANK);
#ifdef	CONFIG_ENABLE_EXTMEM
	hole_size_lo = ALIGN_UP(size_lo, E2K_SIC_SIZE_RT_MLO);
	if (hole_size_lo < size_real) {
		/* Setup high memory filter of BSP */
		size_hi = size_real - hole_size_lo;
		AS_WORD(rt_mhi) = NATIVE_GET_SICREG(rt_mhi0, 0, 0);
		DebugMRT("get_memory_filters: BSP rt_mhi0 = 0x%x\n",
			AS_WORD(rt_mhi));
		hi_memory_start = get_hi_memory_start(0);
		AS_STRUCT(rt_mhi).bgn = (hi_memory_start /
							E2K_SIC_SIZE_RT_MHI);
		AS_STRUCT(rt_mhi).end = ((hi_memory_start + hole_size_lo +
					size_hi - 1) / E2K_SIC_SIZE_RT_MHI);
		NATIVE_SET_SICREG(rt_mhi0, AS_WORD(rt_mhi), 0, 0);
		rom_printk("BSP NODE #0 high memory router set from 0x%X "
			"to 0x%X\n",
			hi_memory_start,
			hi_memory_start + hole_size_lo + size_hi - 1);
		DebugMRT("set_memory_filters: BSP set rt_mhi0 to 0x%x\n",
			AS_WORD(rt_mhi));
		add_memory_region(boot_info, 0, hi_memory_start + hole_size_lo,
					size_hi);
#ifdef	CONFIG_SMP
		if (phys_node_pres_map & 0x2) {	/* NODE #1 is online */
			/*
			 * Setup memory routers of NODE #1 to access to hi 
			 * memory NODE #0,
			 * NODE #0 is located on link #3 of NODE #1
			 */
			NATIVE_SET_SICREG(rt_mhi3, AS_WORD(rt_mhi), 0, 1);
			DebugMRT("set_memory_filters: NODE #1 set rt_mhi3 to "
				"0x%x to access to memory of NODE #0\n",
				AS_WORD(rt_mhi));
		}
		if (phys_node_pres_map & 0x4) {	/* NODE #2 is online */
			/*
			 * Setup memory routers of NODE #2 to access to hi 
			 * memory NODE #0,
			 * NODE #0 is located on link #2 of NODE #2
			 */
			NATIVE_SET_SICREG(rt_mhi2, AS_WORD(rt_mhi), 0, 2);
			DebugMRT("set_memory_filters: NODE #2 set rt_mhi2 to "
				"0x%x to access to memory of NODE #0\n",
				AS_WORD(rt_mhi));
		}
		if (phys_node_pres_map & 0x8) {	/* NODE #3 is online */
			/*
			 * Setup memory routers of NODE #3 to access to hi 
			 * memory NODE #0,
			 * NODE #0 is located on link #1 of NODE #3
			 */
			NATIVE_SET_SICREG(rt_mhi1, AS_WORD(rt_mhi), 0, 3);
			DebugMRT("set_memory_filters: NODE #3 set rt_mhi1 to "
				"0x%x to access to memory of NODE #0\n",
				AS_WORD(rt_mhi));
		}
#endif	/* CONFIG_SMP */
		hi_memory_start += (size_lo + size_hi);
		hi_memory_start = ALIGN_UP(hi_memory_start,
						E2K_SIC_MIN_MEMORY_BANK);
	}
#endif	/* CONFIG_ENABLE_EXTMEM */
	add_memory_region(boot_info, 0, 0, 0);

#ifndef	CONFIG_SMP
	return;	/* none other CPUS */
#else	/* CONFIG_SMP */
	if (phys_cpu_num <= 1)
		return;	/* none other CPUs */
	if (only_BSP_has_memory) {
		/*
		 * The only BSP has access to memory, and other cpus
		 * through BSP, so we leave rt_mlo 1,2,3 of BSP and
		 * rt_mlo0 of other CPUs closed by default
		 */
		return;
	}
	size_to_probe = PROBE_MEM_LIMIT;
#ifdef	CONFIG_ENABLE_EXTMEM
	size_to_probe = ALIGN_UP(size_to_probe, E2K_SIC_SIZE_RT_MLO);
	size_to_probe += PROBE_EXT_MEM_LIMIT;
	if (!is_power_of_2(size_to_probe)) {
		/* all memory banks size can be only 2^n */
		size_to_probe = __roundup_pow_of_two(size_to_probe);
	}
#endif	/* CONFIG_ENABLE_EXTMEM */

	if ((phys_node_pres_map & 0x2) && (memory_pres_map & 0x2)) {
		/* NODE #1 is online */
		/*
		 * Setup memory routers of NODE #1 to access to own memory
		 */
		/* Configure MLO of NODE #1 */
		AS_WORD(rt_mlo) = NATIVE_GET_SICREG(rt_mlo0, 0, 1);
		DebugMRT("get_memory_filters: NODE #1 rt_mlo0 = 0x%x\n",
			AS_WORD(rt_mlo));
		/*
		 * Setup memory routers of NODE #0 to probe memory
		 * of NODE #1 located on link #1 of NODE #0
		 */
		size_real = probe_memory(boot_info, 1, 0, 1);
		if (size_real > 0) {
			size_lo = get_lo_memory_size(1);
			if (size_lo > size_real)
				size_lo = size_real;
		} else {
			size_lo = 0;
		}

		lo_memory_start = get_lo_memory_start(1);
		lo_memory_start = ALIGN_UP(lo_memory_start,
						E2K_SIC_MIN_MEMORY_BANK);
		AS_WORD(rt_mlo) = NATIVE_GET_SICREG(rt_mlo0, 0, 1);
		AS_STRUCT(rt_mlo).bgn = lo_memory_start / E2K_SIC_SIZE_RT_MLO;
		AS_STRUCT(rt_mlo).end = (lo_memory_start + size_lo - 1) /
							E2K_SIC_SIZE_RT_MLO;
		NATIVE_SET_SICREG(rt_mlo0, AS_WORD(rt_mlo), 0, 1);

		rom_printk("NODE #1 low memory router set from 0x%X to "
			"0x%X\n",
			lo_memory_start, lo_memory_start + size_lo - 1);
		DebugMRT("set_memory_filters: NODE #1 set rt_mlo0 to 0x%x\n",
			AS_WORD(rt_mlo));
		if (size_lo > 0) {
			add_memory_region(boot_info, 1, lo_memory_start,
						size_lo);
		} else {
			rom_printk("NODE #1 has not own memory\n");
		}
		if (phys_node_pres_map & 0x1) {	/* NODE #0 is online */
			/*
			 * Setup memory routers of NODE #0 to access to memory
			 * of NODE #1 located on link #1 of NODE #0
			 */
			NATIVE_SET_SICREG(rt_mlo1, AS_WORD(rt_mlo), 0, 0);
			DebugMRT("set_memory_filters: NODE #0 set rt_mlo1 to "
				"0x%x to access to memory of NODE #1\n",
				AS_WORD(rt_mlo));
		}
		if (phys_node_pres_map & 0x4) {	/* NODE #2 is online */
			/*
			 * Setup memory routers of NODE #2 to access to memory
			 * of NODE #1 located on link #3 of NODE #2
			 */
			NATIVE_SET_SICREG(rt_mlo3, AS_WORD(rt_mlo), 0, 2);
			DebugMRT("set_memory_filters: NODE #2 set rt_mlo3 to "
				"0x%x to access to memory of NODE #1\n",
				AS_WORD(rt_mlo));
		}
		if (phys_node_pres_map & 0x8) {	/* NODE #3 is online */
			/*
			 * Setup memory routers of NODE #3 to access to memory
			 * of NODE #1 is located on link #2 of NODE #3
			 */
			NATIVE_SET_SICREG(rt_mlo2, AS_WORD(rt_mlo), 0, 3);
			DebugMRT("set_memory_filters: NODE #3 set rt_mlo2 to "
				"0x%x to access to memory of NODE #1\n",
				AS_WORD(rt_mlo));
		}
		memory_start += size_lo;
		memory_start = ALIGN_UP(memory_start, E2K_SIC_MIN_MEMORY_BANK);
#ifdef	CONFIG_ENABLE_EXTMEM
		hole_size_lo = ALIGN_UP(size_lo, E2K_SIC_SIZE_RT_MLO);
		if (hole_size_lo < size_real) {
			size_hi = size_real - hole_size_lo;
		} else {
			size_hi = 0;
		}
		/* Setup high memory filter of BSP */
		if (size_hi != 0) {
			/* Setup high memory filter of NODE #1 */
			AS_WORD(rt_mhi) = NATIVE_GET_SICREG(rt_mhi0, 0, 1);
			DebugMRT("get_memory_filters: NODE #1 rt_mhi0 = "
				"0x%x\n", AS_WORD(rt_mhi));
			hi_memory_start = get_hi_memory_start(1);
			hi_memory_start = ALIGN_UP(hi_memory_start,
							E2K_SIC_SIZE_RT_MHI);
			AS_STRUCT(rt_mhi).bgn = (u32)(hi_memory_start /
							E2K_SIC_SIZE_RT_MHI);
			AS_STRUCT(rt_mhi).end = (u32)((hi_memory_start +
						hole_size_lo + size_hi - 1) /
							E2K_SIC_SIZE_RT_MHI);
			NATIVE_SET_SICREG(rt_mhi0, AS_WORD(rt_mhi), 0, 1);
			rom_printk("NODE #1 high memory router set from "
				"0x%X to 0x%X\n",
				hi_memory_start,
				hi_memory_start + hole_size_lo + size_hi - 1);
			DebugMRT("set_memory_filters: NODE #1 set rt_mhi0 to "
				"0x%x\n",
				AS_WORD(rt_mhi));
			lo_high_memory_start = hi_memory_start;
			lo_high_memory_size = lo_memory_start;
			if (lo_high_memory_size < size_hi) {
				hi_high_memory_size =
					size_hi - lo_high_memory_size;
				hi_high_memory_start = hi_memory_start +
					lo_memory_start + hole_size_lo;
			} else {
				lo_high_memory_size = size_hi;
				hi_high_memory_size = 0;
			}
			if (lo_high_memory_size != 0) {
				add_memory_region(boot_info, 1,
						lo_high_memory_start,
						lo_high_memory_size);
				rom_printk("NODE #1 high memory lo region set "
					"from 0x%X to 0x%X\n",
					lo_high_memory_start,
					lo_high_memory_start +
						lo_high_memory_size);
			}
			if (hi_high_memory_size != 0) {
				add_memory_region(boot_info, 1,
						hi_high_memory_start,
						hi_high_memory_size);
				rom_printk("NODE #1 high memory hi region set "
					"from 0x%X to 0x%X\n",
					hi_high_memory_start,
					hi_high_memory_start +
						hi_high_memory_size);
			}
			if (phys_node_pres_map & 0x1) {	/* NODE #0 is online */
				/*
				 * Setup memory routers of NODE #0 to access"
				 * to hi memory of NODE #1,
				 * NODE #1 is located on link #1 of NODE #0
				 */
				NATIVE_SET_SICREG(rt_mhi1, AS_WORD(rt_mhi), 0, 0);
				DebugMRT("set_memory_filters: NODE #0 set "
					"rt_mhi1 to 0x%x to access to "
					"memory of NODE #1\n",
					AS_WORD(rt_mhi));
			}
			if (phys_node_pres_map & 0x4) {	/* NODE #2 is online */
				/*
				 * Setup memory routers of NODE #2 to access
				 * to hi memory of NODE #1,
				 * NODE #1 is located on link #3 of NODE #2
				 */
				NATIVE_SET_SICREG(rt_mhi3, AS_WORD(rt_mhi), 0, 2);
				DebugMRT("set_memory_filters: NODE #2 set "
					"rt_mhi3 to 0x%x to access to "
					"memory of NODE #1\n",
					AS_WORD(rt_mhi));
			}
			if (phys_node_pres_map & 0x8) {	/* NODE #3 is online */
				/*
				 * Setup memory routers of NODE #3 to access
				 * to hi memory of NODE #1,
				 * NODE #1 is located on link #2 of NODE #3
				 */
				NATIVE_SET_SICREG(rt_mhi2, AS_WORD(rt_mhi), 0, 3);
				DebugMRT("set_memory_filters: NODE #3 set "
					"rt_mhi2 to 0x%x to access to "
					"memory of NODE #1\n",
					AS_WORD(rt_mhi));
			}
			hi_memory_start += (hole_size_lo + size_hi);
			hi_memory_start = ALIGN_UP(hi_memory_start,
						E2K_SIC_MIN_MEMORY_BANK);
		}
#endif	/* CONFIG_ENABLE_EXTMEM */
	}
	add_memory_region(boot_info, 1, 0, 0);

	if ((phys_node_pres_map & 0x4) && (memory_pres_map & 0x4)) {	/* NODE #2 is online */
		/*
		 * Setup memory routers of NODE #2 to access to own memory
		 */
		/* Configure MLO of NODE #2 */
		AS_WORD(rt_mlo) = NATIVE_GET_SICREG(rt_mlo0, 0, 2);
		DebugMRT("get_memory_filters: NODE #2 rt_mlo0 = 0x%x\n",
			AS_WORD(rt_mlo));

		/*
		 * Setup memory routers of NODE #0 to probe memory
		 * of NODE #2 located on link #2 of NODE #0
		 */
		size_real = probe_memory(boot_info, 2, 0, 2);
		if (size_real > 0) {
			size_lo = get_lo_memory_size(2);
			if (size_lo > size_real)
				size_lo = size_real;
		} else {
			size_lo = 0;
		}

		lo_memory_start = get_lo_memory_start(2);
		lo_memory_start = ALIGN_UP(lo_memory_start,
						E2K_SIC_MIN_MEMORY_BANK);

		AS_WORD(rt_mlo) = NATIVE_GET_SICREG(rt_mlo0, 0, 2);
		AS_STRUCT(rt_mlo).bgn = lo_memory_start / E2K_SIC_SIZE_RT_MLO;
		AS_STRUCT(rt_mlo).end = (lo_memory_start + size_lo - 1) /
							E2K_SIC_SIZE_RT_MLO;
		NATIVE_SET_SICREG(rt_mlo0, AS_WORD(rt_mlo), 0, 2);

		rom_printk("NODE #2 low memory router set from 0x%X to "
			"0x%X\n",
			lo_memory_start, lo_memory_start + size_lo - 1);
		DebugMRT("set_memory_filters: NODE #2 set rt_mlo0 to 0x%x\n",
			AS_WORD(rt_mlo));
		if (size_lo > 0) {
			add_memory_region(boot_info, 2, lo_memory_start,
								size_lo);
		} else {
			rom_printk("NODE #2 has not own memory\n");
		}
		if (phys_node_pres_map & 0x1) {	/* NODE #0 is online */
			/*
			 * Setup memory routers of NODE #0 to access to memory
			 * of NODE #2 located on link #2 of NODE #0
			 */
			NATIVE_SET_SICREG(rt_mlo2, AS_WORD(rt_mlo), 0, 0);
			DebugMRT("set_memory_filters: NODE #0 set rt_mlo2 to "
				"0x%x to access to memory of NODE #2\n",
				AS_WORD(rt_mlo));
		}
		if (phys_node_pres_map & 0x2) {	/* NODE #1 is online */
			/*
			 * Setup memory routers of NODE #1 to access to memory
			 * of NODE #2 located on link #1 of NODE #1
			 */
			NATIVE_SET_SICREG(rt_mlo1, AS_WORD(rt_mlo), 0, 1);
			DebugMRT("set_memory_filters: NODE #1 set rt_mlo1 to "
				"0x%x to access to memory of NODE #2\n",
				AS_WORD(rt_mlo));
		}
		if (phys_node_pres_map & 0x8) {	/* NODE #3 is online */
			/*
			 * Setup memory routers of NODE #3 to access to memory
			 * of NODE #2 is located on link #3 of NODE #3
			 */
			NATIVE_SET_SICREG(rt_mlo3, AS_WORD(rt_mlo), 0, 3);
			DebugMRT("set_memory_filters: NODE #3 set rt_mlo3 to "
				"0x%x to access to memory of NODE #2\n",
				AS_WORD(rt_mlo));
		}
		memory_start += size_lo;
		memory_start = ALIGN_UP(memory_start, E2K_SIC_MIN_MEMORY_BANK);
#ifdef	CONFIG_ENABLE_EXTMEM
		hole_size_lo = ALIGN_UP(size_lo, E2K_SIC_SIZE_RT_MLO);
		if (hole_size_lo < size_real) {
			size_hi = size_real - hole_size_lo;
		} else {
			size_hi = 0;
		}
		if (size_hi != 0) {
			/* Setup high memory filter of NODE #2 */
			AS_WORD(rt_mhi) = NATIVE_GET_SICREG(rt_mhi0, 0, 2);
			DebugMRT("get_memory_filters: NODE #2 rt_mhi0 = "
				"0x%x\n", AS_WORD(rt_mhi));
			hi_memory_start = get_hi_memory_start(2);
			hi_memory_start = ALIGN_UP(hi_memory_start,
							E2K_SIC_SIZE_RT_MHI);
			AS_STRUCT(rt_mhi).bgn = hi_memory_start /
							E2K_SIC_SIZE_RT_MHI;
			AS_STRUCT(rt_mhi).end = (hi_memory_start +
						hole_size_lo + size_hi - 1) /
							E2K_SIC_SIZE_RT_MHI;
			NATIVE_SET_SICREG(rt_mhi0, AS_WORD(rt_mhi), 0, 2);
			rom_printk("NODE #2 high memory router set from "
				"0x%X to 0x%X\n",
				hi_memory_start,
				hi_memory_start + hole_size_lo + size_hi - 1);
			DebugMRT("set_memory_filters: NODE #2 set rt_mhi0 to "
				"0x%x\n",
				AS_WORD(rt_mhi));
			lo_high_memory_start = hi_memory_start;
			lo_high_memory_size = lo_memory_start;
			if (lo_high_memory_size < size_hi) {
				hi_high_memory_size =
					size_hi - lo_high_memory_size;
				hi_high_memory_start = hi_memory_start +
					lo_memory_start + hole_size_lo;
			} else {
				lo_high_memory_size = size_hi;
				hi_high_memory_size = 0;
			}
			if (lo_high_memory_size != 0) {
				add_memory_region(boot_info, 2,
						lo_high_memory_start,
						lo_high_memory_size);
				rom_printk("NODE #2 high memory lo region set "
					"from 0x%X to 0x%X\n",
					lo_high_memory_start,
					lo_high_memory_start +
						lo_high_memory_size);
			}
			if (hi_high_memory_size != 0) {
				add_memory_region(boot_info, 2,
						hi_high_memory_start,
						hi_high_memory_size);
				rom_printk("NODE #2 high memory hi region set "
					"from 0x%X to 0x%X\n",
					hi_high_memory_start,
					hi_high_memory_start +
						hi_high_memory_size);
			}
			if (phys_node_pres_map & 0x1) {	/* NODE #0 is online */
				/*
				 * Setup memory routers of NODE #0 to access"
				 * to hi memory of NODE #2,
				 * NODE #2 is located on link #2 of NODE #0
				 */
				NATIVE_SET_SICREG(rt_mhi2, AS_WORD(rt_mhi), 0, 0);
				DebugMRT("set_memory_filters: NODE #0 set "
					"rt_mhi2 to 0x%x to access to "
					"memory of NODE #2\n",
					AS_WORD(rt_mhi));
			}
			if (phys_node_pres_map & 0x2) {	/* NODE #1 is online */
				/*
				 * Setup memory routers of NODE #1 to access
				 * to hi memory of NODE #2,
				 * NODE #2 is located on link #1 of NODE #1
				 */
				NATIVE_SET_SICREG(rt_mhi1, AS_WORD(rt_mhi), 0, 1);
				DebugMRT("set_memory_filters: NODE #1 set "
					"rt_mhi1 to 0x%x to access to "
					"memory of NODE #2\n",
					AS_WORD(rt_mhi));
			}
			if (phys_node_pres_map & 0x8) {	/* NODE #3 is online */
				/*
				 * Setup memory routers of NODE #3 to access
				 * to hi memory of NODE #2,
				 * NODE #2 is located on link #3 of NODE #3
				 */
				NATIVE_SET_SICREG(rt_mhi3, AS_WORD(rt_mhi), 0, 3);
				DebugMRT("set_memory_filters: NODE #3 set "
					"rt_mhi3 to 0x%x to access to "
					"memory of NODE #2\n",
					AS_WORD(rt_mhi));
			}
			hi_memory_start += (hole_size_lo + size_hi);
			hi_memory_start = ALIGN_UP(hi_memory_start,
							E2K_SIC_MIN_MEMORY_BANK);
		}
#endif	/* CONFIG_ENABLE_EXTMEM */
	}
	add_memory_region(boot_info, 2, 0, 0);

	if ((phys_node_pres_map & 0x8) && (memory_pres_map & 0x8)) {	/* NODE #3 is online */
		/*
		 * Setup memory routers of NODE #3 to access to own memory
		 */
		/* Configure MLO of NODE #3 */
		AS_WORD(rt_mlo) = NATIVE_GET_SICREG(rt_mlo0, 0, 3);
		DebugMRT("set_memory_filters: NODE #3 rt_mlo0 = 0x%x\n",
			AS_WORD(rt_mlo));

		/*
		 * Setup memory routers of NODE #0 to probe memory
		 * of NODE #3 located on link #3 of NODE #0
		 */
		size_real = probe_memory(boot_info, 3, 0, 3);
		if (size_real > 0) {
			size_lo = get_lo_memory_size(3);
			if (size_lo > size_real)
				size_lo = size_real;
		} else {
			size_lo = 0;
		}

		lo_memory_start = get_lo_memory_start(3);
		lo_memory_start = ALIGN_UP(lo_memory_start,
						E2K_SIC_MIN_MEMORY_BANK);

		AS_WORD(rt_mlo) = NATIVE_GET_SICREG(rt_mlo0, 0, 3);
		AS_STRUCT(rt_mlo).bgn = lo_memory_start / E2K_SIC_SIZE_RT_MLO;
		AS_STRUCT(rt_mlo).end = (lo_memory_start + size_lo - 1) /
							E2K_SIC_SIZE_RT_MLO;
		NATIVE_SET_SICREG(rt_mlo0, AS_WORD(rt_mlo), 0, 3);

		rom_printk("NODE #3 low memory router set from 0x%X to "
			"0x%X\n",
			lo_memory_start, lo_memory_start + size_lo - 1);
		DebugMRT("set_memory_filters: NODE #3 set rt_mlo0 to 0x%x\n",
			AS_WORD(rt_mlo));
		if (size_lo > 0) {
			add_memory_region(boot_info, 3, lo_memory_start,
						size_lo);
		} else {
			rom_printk("NODE #3 has not own memory\n");
		}
		if (phys_node_pres_map & 0x1) {	/* NODE #0 is online */
			/*
			 * Setup memory routers of NODE #0 to access to memory
			 * of NODE #3 located on link #3 of NODE #0
			 */
			NATIVE_SET_SICREG(rt_mlo3, AS_WORD(rt_mlo), 0, 0);
			DebugMRT("set_memory_filters: NODE #0 set rt_mlo3 to "
				"0x%x to access to memory of NODE #3\n",
				AS_WORD(rt_mlo));
		}
		if (phys_node_pres_map & 0x2) {	/* NODE #1 is online */
			/*
			 * Setup memory routers of NODE #1 to access to memory
			 * of NODE #3 located on link #2 of NODE #1
			 */
			NATIVE_SET_SICREG(rt_mlo2, AS_WORD(rt_mlo), 0, 1);
			DebugMRT("set_memory_filters: NODE #1 set rt_mlo2 to "
				"0x%x to access to memory of NODE #3\n",
				AS_WORD(rt_mlo));
		}
		if (phys_node_pres_map & 0x4) {	/* NODE #2 is online */
			/*
			 * Setup memory routers of NODE #2 to access to memory
			 * of NODE #3 is located on link #1 of NODE #2
			 */
			NATIVE_SET_SICREG(rt_mlo1, AS_WORD(rt_mlo), 0, 2);
			DebugMRT("set_memory_filters: NODE #2 set rt_mlo1 to "
				"0x%x to access to memory of NODE #3\n",
				AS_WORD(rt_mlo));
		}
		memory_start += size_lo;
		memory_start = ALIGN_UP(memory_start, E2K_SIC_MIN_MEMORY_BANK);
#ifdef	CONFIG_ENABLE_EXTMEM
		hole_size_lo = ALIGN_UP(size_lo, E2K_SIC_SIZE_RT_MLO);
		if (hole_size_lo < size_real) {
			size_hi = size_real - hole_size_lo;
		} else {
			size_hi = 0;
		}
		if (size_hi != 0) {
			/* Setup high memory filter of NODE #3 */
			AS_WORD(rt_mhi) = NATIVE_GET_SICREG(rt_mhi0, 0, 3);
			DebugMRT("set_memory_filters: NODE #3 rt_mhi0 = "
				"0x%x\n", AS_WORD(rt_mhi));
			hi_memory_start = get_hi_memory_start(3);
			hi_memory_start = ALIGN_UP(hi_memory_start,
							E2K_SIC_SIZE_RT_MHI);
			AS_STRUCT(rt_mhi).bgn = hi_memory_start /
							E2K_SIC_SIZE_RT_MHI;
			AS_STRUCT(rt_mhi).end = (hi_memory_start +
						hole_size_lo + size_hi - 1) /
							E2K_SIC_SIZE_RT_MHI;
			NATIVE_SET_SICREG(rt_mhi0, AS_WORD(rt_mhi), 0, 3);
			rom_printk("NODE #3 high memory router set from "
				"0x%X to 0x%X\n",
				hi_memory_start,
				hi_memory_start + hole_size_lo + size_hi - 1);
			DebugMRT("set_memory_filters: NODE #3 set rt_mhi0 to "
				"0x%x\n",
				AS_WORD(rt_mhi));
			lo_high_memory_start = hi_memory_start;
			lo_high_memory_size = lo_memory_start;
			if (lo_high_memory_size < size_hi) {
				hi_high_memory_size =
					size_hi - lo_high_memory_size;
				hi_high_memory_start = hi_memory_start +
					lo_memory_start + hole_size_lo;
			} else {
				lo_high_memory_size = size_hi;
				hi_high_memory_size = 0;
			}
			if (lo_high_memory_size != 0) {
				add_memory_region(boot_info, 3,
						lo_high_memory_start,
						lo_high_memory_size);
				rom_printk("NODE #3 high memory lo region set "
					"from 0x%X to 0x%X\n",
					lo_high_memory_start,
					lo_high_memory_start +
						lo_high_memory_size);
			}
			if (hi_high_memory_size != 0) {
				add_memory_region(boot_info, 3,
						hi_high_memory_start,
						hi_high_memory_size);
				rom_printk("NODE #3 high memory hi region set "
					"from 0x%X to 0x%X\n",
					hi_high_memory_start,
					hi_high_memory_start +
						hi_high_memory_size);
			}
			if (phys_node_pres_map & 0x1) {	/* NODE #0 is online */
				/*
				 * Setup memory routers of NODE #0 to access"
				 * to hi memory of NODE #3,
				 * NODE #3 is located on link #3 of NODE #0
				 */
				NATIVE_SET_SICREG(rt_mhi3, AS_WORD(rt_mhi), 0, 0);
				DebugMRT("set_memory_filters: NODE #0 set "
					"rt_mhi3 to 0x%x to access to "
					"memory of NODE #3\n",
					AS_WORD(rt_mhi));
			}
			if (phys_node_pres_map & 0x2) {	/* NODE #1 is online */
				/*
				 * Setup memory routers of NODE #1 to access
				 * to hi memory of NODE #3,
				 * NODE #3 is located on link #2 of NODE #1
				 */
				NATIVE_SET_SICREG(rt_mhi2, AS_WORD(rt_mhi), 0, 1);
				DebugMRT("set_memory_filters: NODE #1 set "
					"rt_mhi2 to 0x%x to access to "
					"memory of NODE #3\n",
					AS_WORD(rt_mhi));
			}
			if (phys_node_pres_map & 0x4) {	/* NODE #2 is online */
				/*
				 * Setup memory routers of NODE #2 to access
				 * to hi memory of NODE #3,
				 * NODE #3 is located on link #1 of NODE #2
				 */
				NATIVE_SET_SICREG(rt_mhi1, AS_WORD(rt_mhi), 0, 2);
				DebugMRT("set_memory_filters: NODE #2 set "
					"rt_mhi1 to 0x%x to access to "
					"memory of NODE #3\n",
					AS_WORD(rt_mhi));
			}
			hi_memory_start += (hole_size_lo + size_hi);
			hi_memory_start = ALIGN_UP(hi_memory_start,
							E2K_SIC_MIN_MEMORY_BANK);
		}
#endif	/* CONFIG_ENABLE_EXTMEM */
	}
	add_memory_region(boot_info, 3, 0, 0);

#endif	/* ! CONFIG_SMP */
}
#elif defined(CONFIG_E2K_LEGACY_SIC)
static void configure_routing_regs(void)
{
	unsigned short vid, vvid;
	unsigned short did, vdid;
	unsigned short pci_cmd;
	unsigned int hb_cfg;

	vid = __boot_readw_hb_reg(PCI_VENDOR_ID);
	did = __boot_readw_hb_reg(PCI_DEVICE_ID);
	DebugRT("configure_routing_regs: host bridge vendor ID = 0x%04x "
		"device ID = 0x%04x\n", vid, did);
	if (vid != PCI_VENDOR_ID_MCST_TMP) {
		rom_printk("Invalid Host Bridge vendor ID 0x%04x instead of "
			"0x%04x\n", vid, PCI_VENDOR_ID_MCST_TMP);
	}
	if (did != PCI_DEVICE_ID_MCST_HB) {
		rom_printk("Invalid Host Bridge device ID 0x%04x instead of "
			"0x%04x\n", did, PCI_DEVICE_ID_MCST_HB);
	}
	vvid = __boot_readw_eg_reg(PCI_VENDOR_ID);
	vdid = __boot_readw_eg_reg(PCI_DEVICE_ID);
	DebugRT("configure_routing_regs: embeded graphic controller vendor "
		"ID = 0x%04x device ID = 0x%04x\n", vvid, vdid);
	if (vvid != PCI_VENDOR_ID_MCST_TMP) {
		rom_printk("Invalid Embeded Graphic controller vendor "
			"ID 0x%04x instead of 0x%04x\n",
			vvid, PCI_VENDOR_ID_MCST_TMP);
	}
	if (vdid != PCI_DEVICE_ID_MCST_MGA2) {
		rom_printk("Invalid Embeded Graphic controller device "
			"ID 0x%04x instead of 0x%04x\n",
			vdid, PCI_DEVICE_ID_MCST_MGA2);
	}

	/* Setup initial state of Host Bridge CFG */
	hb_cfg = __boot_readl_hb_reg(HB_PCI_CFG);
	DebugRT("configure_routing_regs: host bridge CFG 0x%08x\n",
		hb_cfg);
#ifdef	CONFIG_VRAM_DISABLE
	hb_cfg &= ~HB_CFG_IntegratedGraphicsEnable;
	__boot_writel_hb_reg(hb_cfg, HB_PCI_CFG);
	rom_printk("host bridge CFG: disable embeded graphic 0x%X\n", hb_cfg);
#endif	/* CONFIG_VRAM_DISABLE */

	phys_node_num = 1;
	phys_node_pres_map = 0x1;

	pci_cmd = __boot_readw_hb_reg(PCI_COMMAND);
	DebugRT("configure_routing_regs: host bridge PCICMD 0x%04x\n",
		pci_cmd);
	pci_cmd |= PCI_COMMAND_MEMORY;
	__boot_writew_hb_reg(pci_cmd, PCI_COMMAND);
	rom_printk("Host Bridge PCICMD set to 0x%04x\n", pci_cmd);
}
void set_memory_filters(boot_info_t *boot_info)
{
	long size_lo = size_real;
	u64 memory_start = 0;	/* memory starts from 0 and can be on BSP */
	u64 lo_mem_end;
	u32 tom_lo;
	int vram_size = EG_VRAM_MBYTES_SIZE;
#ifndef	CONFIG_VRAM_DISABLE
	u32 eg_cfg;
#endif	/* ! CONFIG_VRAM_DISABLE */
#ifdef	CONFIG_ENABLE_EXTMEM
	long size_hi = 0;
	u64 hi_mem_end;
	u64 tom_hi;
	u64 remapbase;
#endif	/* CONFIG_ENABLE_EXTMEM */

	/* Configure TOM & TOM2 & REMAPBASE */
	tom_lo = __boot_readl_hb_reg(HB_PCI_TOM);
	DebugMRT("set_memory_filters: TOM (low memory top) = 0x%x\n", tom_lo);

	size_lo -= vram_size;
	if (size_lo > PROBE_MEM_LIMIT) {
		size_lo = PROBE_MEM_LIMIT;
	}
	size_lo &= HB_PCI_TOM_LOW_MASK;
	if (size_lo <= 0) {
		rom_printk("memory size 0x%X is too small to enable low memory "
			"and VRAM,\n"
			"\tincrease CONFIG_MEMLIMIT (now 0x%X)\n"
			"\tor change VRAM size (now 0x%X) at config\n",
			size_real, PROBE_MEM_LIMIT, vram_size);
		E2K_LMS_HALT_OK;
	}
	lo_mem_end = memory_start + size_lo;
	lo_mem_end &= HB_PCI_TOM_LOW_MASK;
	if (lo_mem_end == 0) {
		rom_printk("low memory size 0x%X is too small, use default "
			"size 0x%X\n",
			size_lo, tom_lo);
	} else {
		tom_lo = (tom_lo & ~HB_PCI_TOM_LOW_MASK) | lo_mem_end;
		__boot_writel_hb_reg(tom_lo, HB_PCI_TOM);
#ifndef	CONFIG_VRAM_DISABLE
		/* VRAM is part of common low memory */
		eg_cfg = __boot_readl_eg_reg(EG_PCI_CFG);
		DebugMRT("set_memory_filters: EG CFG = 0x%x\n", eg_cfg);
		eg_cfg &= ~EG_CFG_VRAM_SIZE_MASK;
		eg_cfg |= EG_VRAM_SIZE_FLAGS;
		__boot_writel_eg_reg(eg_cfg, EG_PCI_CFG);
		rom_printk("set VRAM size to 0x%X at CFG 0x%x\n",
			vram_size, __boot_readl_eg_reg(EG_PCI_CFG));
#endif	/* ! CONFIG_VRAM_DISABLE */
	}
	rom_printk("low memory TOM set to 0x%X\n", tom_lo);
	add_memory_region(boot_info, 0, memory_start, size_lo);
#ifdef	CONFIG_ENABLE_EXTMEM
	if (size_lo + vram_size < size_real) {
		/* Setup high memory filter */
		hi_memory_start = HB_PCI_HI_ADDR_BASE;
		size_hi = size_real - size_lo - vram_size;
		tom_hi = __boot_readll_hb_reg(HB_PCI_TOM2);
		DebugMRT("set_memory_filters: TOM2 (high memory top) = 0x%x\n",
			tom_hi);
		size_hi &= HB_PCI_TOM2_HI_MASK;
		hi_mem_end = (hi_memory_start + size_hi);
		hi_mem_end &= HB_PCI_TOM2_HI_MASK;
		if (hi_mem_end == hi_memory_start) {
			rom_printk("high memory size 0x%X is too small, "
				"ignore high memory\n",
				size_hi);
		} else {
			tom_hi = (tom_hi & ~HB_PCI_TOM2_HI_MASK) | hi_mem_end;
			__boot_writell_hb_reg(tom_hi, HB_PCI_TOM2);
			rom_printk("high memory TOM2 set to 0x%X\n", tom_hi);
			remapbase = HB_PCI_HI_ADDR_BASE;
			if (size_lo + vram_size + size_hi > HB_PCI_HI_ADDR_BASE)
				remapbase = size_lo + vram_size + size_hi;
			__boot_writell_hb_reg(remapbase, HB_PCI_REMAPBASE);
			rom_printk("low memory REMAPBASE set to 0x%X\n",
				remapbase);
			add_memory_region(boot_info, 0, hi_memory_start,
						size_hi);
		}
	}
#endif	/* CONFIG_ENABLE_EXTMEM */

}
#endif	/* CONFIG_E2K_FULL_SIC */
#endif	/* CONFIG_E2K_SIC */

#ifdef	CONFIG_SMP
#ifdef	CONFIG_E2K_SIC
#ifdef	CONFIG_E2K_FULL_SIC
int inline e2k_startup_core(e2k_rt_lcfg_struct_t rt_lcfg, int core)
{
	e2k_st_core_t st_core = {{ 0 }};
	int cln = E2K_RT_LCFG_cln(rt_lcfg);
	int pln = E2K_RT_LCFG_pln(rt_lcfg);

	if (core == 0) {
		E2K_ST_CORE_reg(st_core) =
			NATIVE_GET_SICREG(st_core0, cln, pln);
	} else if (core == 1) {
		E2K_ST_CORE_reg(st_core) =
			NATIVE_GET_SICREG(st_core1, cln, pln);
	} else if (core == 2) {
		E2K_ST_CORE_reg(st_core) =
			NATIVE_GET_SICREG(st_core2, cln, pln);
	} else if (core == 3) {
		E2K_ST_CORE_reg(st_core) =
			NATIVE_GET_SICREG(st_core3, cln, pln);
	} else if (core == 4) {
		E2K_ST_CORE_reg(st_core) =
			NATIVE_GET_SICREG(st_core4, cln, pln);
	} else if (core == 5) {
		E2K_ST_CORE_reg(st_core) =
			NATIVE_GET_SICREG(st_core5, cln, pln);
	} else if (core == 6) {
		E2K_ST_CORE_reg(st_core) =
			NATIVE_GET_SICREG(st_core6, cln, pln);
	} else if (core == 7) {
		E2K_ST_CORE_reg(st_core) =
			NATIVE_GET_SICREG(st_core7, cln, pln);
	} else if (core == 8) {
		E2K_ST_CORE_reg(st_core) =
			NATIVE_GET_SICREG(st_core8, cln, pln);
	} else if (core == 9) {
		E2K_ST_CORE_reg(st_core) =
			NATIVE_GET_SICREG(st_core9, cln, pln);
	} else if (core == 10) {
		E2K_ST_CORE_reg(st_core) =
			NATIVE_GET_SICREG(st_core10, cln, pln);
	} else if (core == 11) {
		E2K_ST_CORE_reg(st_core) =
			NATIVE_GET_SICREG(st_core11, cln, pln);
	} else if (core == 12) {
		E2K_ST_CORE_reg(st_core) =
			NATIVE_GET_SICREG(st_core12, cln, pln);
	} else if (core == 13) {
		E2K_ST_CORE_reg(st_core) =
			NATIVE_GET_SICREG(st_core13, cln, pln);
	} else if (core == 14) {
		E2K_ST_CORE_reg(st_core) =
			NATIVE_GET_SICREG(st_core14, cln, pln);
	} else if (core == 15) {
		E2K_ST_CORE_reg(st_core) =
			NATIVE_GET_SICREG(st_core15, cln, pln);
	} else {
		rom_printk("Invalid core # %d to detect\n", core);
		return 0;
	}

	if (!E2K_ST_CORE_val(st_core))
		return 0;
	rom_printk("Start up detected core #%d in cluster %d node %d\n",
		core, cln, pln);
	E2K_ST_CORE_wait_init(st_core) = 0;
	if (core == 0) {
		NATIVE_SET_SICREG(st_core0, E2K_ST_CORE_reg(st_core), cln, pln);
	} else if (core == 1) {
		NATIVE_SET_SICREG(st_core1, E2K_ST_CORE_reg(st_core), cln, pln);
	} else if (core == 2) {
		NATIVE_SET_SICREG(st_core2, E2K_ST_CORE_reg(st_core), cln, pln);
	} else if (core == 3) {
		NATIVE_SET_SICREG(st_core3, E2K_ST_CORE_reg(st_core), cln, pln);
	} else if (core == 4) {
		NATIVE_SET_SICREG(st_core4, E2K_ST_CORE_reg(st_core), cln, pln);
	} else if (core == 5) {
		NATIVE_SET_SICREG(st_core5, E2K_ST_CORE_reg(st_core), cln, pln);
	} else if (core == 6) {
		NATIVE_SET_SICREG(st_core6, E2K_ST_CORE_reg(st_core), cln, pln);
	} else if (core == 7) {
		NATIVE_SET_SICREG(st_core7, E2K_ST_CORE_reg(st_core), cln, pln);
	} else if (core == 8) {
		NATIVE_SET_SICREG(st_core8, E2K_ST_CORE_reg(st_core), cln, pln);
	} else if (core == 9) {
		NATIVE_SET_SICREG(st_core9, E2K_ST_CORE_reg(st_core), cln, pln);
	} else if (core == 10) {
		NATIVE_SET_SICREG(st_core10,
			E2K_ST_CORE_reg(st_core), cln, pln);
	} else if (core == 11) {
		NATIVE_SET_SICREG(st_core11,
			E2K_ST_CORE_reg(st_core), cln, pln);
	} else if (core == 12) {
		NATIVE_SET_SICREG(st_core12,
			E2K_ST_CORE_reg(st_core), cln, pln);
	} else if (core == 13) {
		NATIVE_SET_SICREG(st_core13,
			E2K_ST_CORE_reg(st_core), cln, pln);
	} else if (core == 14) {
		NATIVE_SET_SICREG(st_core14,
			E2K_ST_CORE_reg(st_core), cln, pln);
	} else if (core == 15) {
		NATIVE_SET_SICREG(st_core15,
			E2K_ST_CORE_reg(st_core), cln, pln);
	} else {
		rom_printk("Invalid core # %d to start up\n", core);
		return 0;
	}
	rom_printk("Started up core #%d in cluster %d node %d\n",
		core, cln, pln);
	return 1;
}
#elif	defined(CONFIG_E2K_LEGACY_SIC)
inline int e2k_startup_core(e2k_rt_lcfg_struct_t rt_lcfg, int core)
{
	return 1;
}
#endif	/* CONFIG_E2K_FULL_SIC */
#endif	/* CONFIG_E2K_SIC */
#endif	/* CONFIG_SMP */

#ifdef	CONFIG_E2K_SIC
#if	defined(CONFIG_E2K_FULL_SIC)
static void configure_node_io_routing(int node, int link)
{
       e2k_rt_ioapic_struct_t  rt_ioapic;
       e2k_rt_pcim_struct_t    rt_pcim;
       e2k_rt_pciio_struct_t   rt_pciio;
       unsigned long           pcim_bgn;
       unsigned long           pcim_end;
       int rt_ioapic0_reg;
       int rt_ioapic1_reg;
       int rt_ioapic2_reg;
       int rt_ioapic3_reg;
       int rt_pcim0_reg;
       int rt_pcim1_reg;
       int rt_pcim2_reg;
       int rt_pcim3_reg;
       int rt_pciio0_reg;
       int rt_pciio1_reg;
       int rt_pciio2_reg;
       int rt_pciio3_reg;
       int domain;

       rt_ioapic.E2K_RT_IOAPIC_reg = 0;
       rt_pcim.E2K_RT_PCIM_reg = 0;
       rt_pciio.E2K_RT_PCIIO_reg = 0;

       if (node == 0) {
               rt_ioapic0_reg = SIC_rt_ioapic0;
               rt_ioapic1_reg = SIC_rt_ioapic1;
               rt_ioapic2_reg = SIC_rt_ioapic2;
               rt_ioapic3_reg = SIC_rt_ioapic3;
               rt_pcim0_reg = SIC_rt_pcim0;
               rt_pcim1_reg = SIC_rt_pcim1;
               rt_pcim2_reg = SIC_rt_pcim2;
               rt_pcim3_reg = SIC_rt_pcim3;
               rt_pciio0_reg = SIC_rt_pciio0;
               rt_pciio1_reg = SIC_rt_pciio1;
               rt_pciio2_reg = SIC_rt_pciio2;
               rt_pciio3_reg = SIC_rt_pciio3;
       } else if (node == 1) {
               rt_ioapic0_reg = SIC_rt_ioapic3;
               rt_ioapic1_reg = SIC_rt_ioapic0;
               rt_ioapic2_reg = SIC_rt_ioapic1;
               rt_ioapic3_reg = SIC_rt_ioapic2;
               rt_pcim0_reg = SIC_rt_pcim3;
               rt_pcim1_reg = SIC_rt_pcim0;
               rt_pcim2_reg = SIC_rt_pcim1;
               rt_pcim3_reg = SIC_rt_pcim2;
               rt_pciio0_reg = SIC_rt_pciio3;
               rt_pciio1_reg = SIC_rt_pciio0;
               rt_pciio2_reg = SIC_rt_pciio1;
               rt_pciio3_reg = SIC_rt_pciio2;
       } else if (node == 2) {
               rt_ioapic0_reg = SIC_rt_ioapic2;
               rt_ioapic1_reg = SIC_rt_ioapic3;
               rt_ioapic2_reg = SIC_rt_ioapic0;
               rt_ioapic3_reg = SIC_rt_ioapic1;
               rt_pcim0_reg = SIC_rt_pcim2;
               rt_pcim1_reg = SIC_rt_pcim3;
               rt_pcim2_reg = SIC_rt_pcim0;
               rt_pcim3_reg = SIC_rt_pcim1;
               rt_pciio0_reg = SIC_rt_pciio2;
               rt_pciio1_reg = SIC_rt_pciio3;
               rt_pciio2_reg = SIC_rt_pciio0;
               rt_pciio3_reg = SIC_rt_pciio1;
       } else if (node == 3) {
               rt_ioapic0_reg = SIC_rt_ioapic1;
               rt_ioapic1_reg = SIC_rt_ioapic2;
               rt_ioapic2_reg = SIC_rt_ioapic3;
               rt_ioapic3_reg = SIC_rt_ioapic0;
               rt_pcim0_reg = SIC_rt_pcim1;
               rt_pcim1_reg = SIC_rt_pcim2;
               rt_pcim2_reg = SIC_rt_pcim3;
               rt_pcim3_reg = SIC_rt_pcim0;
               rt_pciio0_reg = SIC_rt_pciio1;
               rt_pciio1_reg = SIC_rt_pciio2;
               rt_pciio2_reg = SIC_rt_pciio3;
               rt_pciio3_reg = SIC_rt_pciio0;
       } else {
               rom_printk("configure_node_io_routing() invalid node #%d\n",
                       node);
               return;
       }
       domain = node_iohub_to_domain(node, link);

       /* configure own link of the NODE to access to own ioapic space */
       rt_ioapic.E2K_RT_IOAPIC_bgn = domain;
       early_sic_write_node_iolink_nbsr_reg(node, link, SIC_rt_ioapic0,
                                               rt_ioapic.E2K_RT_IOAPIC_reg);
	DebugIORT("NODE #%d IO link #%d: IO-APIC router set from 0x%X\n",
		node, link, domain);
       pcim_bgn = PCI_MEM_DOMAIN_START(domain);
       pcim_end = PCI_MEM_DOMAIN_END(domain);
       rt_pcim.E2K_RT_PCIM_bgn = (pcim_bgn) >> E2K_SIC_ALIGN_RT_PCIM;
       rt_pcim.E2K_RT_PCIM_end = (pcim_end - 1) >> E2K_SIC_ALIGN_RT_PCIM;
       early_sic_write_node_iolink_nbsr_reg(node, link, SIC_rt_pcim0,
                                               rt_pcim.E2K_RT_PCIM_reg);
	DebugIORT("NODE #%d IO link #%d: PCI-MM router set from 0x%X "
		"to 0x%X\n",
		node, link, pcim_bgn, pcim_end);
       pcim_bgn = PCI_IO_DOMAIN_START(domain);
       pcim_end = PCI_IO_DOMAIN_END(domain);
       rt_pciio.E2K_RT_PCIIO_bgn = (pcim_bgn) >> E2K_SIC_ALIGN_RT_PCIIO;
       rt_pciio.E2K_RT_PCIIO_end = (pcim_end - 1) >> E2K_SIC_ALIGN_RT_PCIIO;
       early_sic_write_node_iolink_nbsr_reg(node, link, SIC_rt_pciio0,
                                               rt_pciio.E2K_RT_PCIIO_reg);
	DebugIORT("NODE #%d IO link #%d: PCI-IO router set from 0x%X "
		"to 0x%X\n",
		node, link, pcim_bgn, pcim_end);

       if (node != 0 && (phys_node_pres_map & 0x1)) {  // node #0 is present
               /* configure link the NODE to access to ioapic space NODE 0 */
               domain = node_iohub_to_domain(0, link);
               rt_ioapic.E2K_RT_IOAPIC_bgn = domain;
               early_sic_write_node_iolink_nbsr_reg(node, link, rt_ioapic0_reg,
                                               rt_ioapic.E2K_RT_IOAPIC_reg);
		DebugIORT("NODE #%d IO link #%d: router to IO-APIC node #0 set "
			"from 0x%X\n",
			node, link, domain);
               pcim_bgn = PCI_MEM_DOMAIN_START(domain);
               pcim_end = PCI_MEM_DOMAIN_END(domain);
               rt_pcim.E2K_RT_PCIM_bgn = (pcim_bgn) >> E2K_SIC_ALIGN_RT_PCIM;
               rt_pcim.E2K_RT_PCIM_end =
                       (pcim_end - 1) >> E2K_SIC_ALIGN_RT_PCIM;
               early_sic_write_node_iolink_nbsr_reg(node, link, rt_pcim0_reg,
                                               rt_pcim.E2K_RT_PCIM_reg);
		DebugIORT("NODE #%d IO link #%d: router to PCI-MM node #0 set "
			"from 0x%X\n",
			node, link, pcim_bgn, pcim_end);
               pcim_bgn = PCI_IO_DOMAIN_START(domain);
               pcim_end = PCI_IO_DOMAIN_END(domain);
               rt_pciio.E2K_RT_PCIIO_bgn =
                       (pcim_bgn) >> E2K_SIC_ALIGN_RT_PCIIO;
               rt_pciio.E2K_RT_PCIIO_end =
                       (pcim_end - 1) >> E2K_SIC_ALIGN_RT_PCIIO;
               early_sic_write_node_iolink_nbsr_reg(node, link, rt_pciio0_reg,
                                               rt_pciio.E2K_RT_PCIIO_reg);
		DebugIORT("NODE #%d IO link #%d: router to PCI-IO node #0 set "
			"from 0x%X\n",
			node, link, pcim_bgn, pcim_end);
       }
       if (node != 1 && (phys_node_pres_map & 0x2)) {  // node #1 is present
               /* configure link the NODE to access to ioapic space NODE 1 */
               domain = node_iohub_to_domain(1, link);
               rt_ioapic.E2K_RT_IOAPIC_bgn = domain;
               early_sic_write_node_iolink_nbsr_reg(node, link, rt_ioapic1_reg,
                                               rt_ioapic.E2K_RT_IOAPIC_reg);
		DebugIORT("NODE #%d IO link #%d: router to IO-APIC node #1 set "
			"from 0x%X\n",
			node, link, domain);
               pcim_bgn = PCI_MEM_DOMAIN_START(domain);
               pcim_end = PCI_MEM_DOMAIN_END(domain);
               rt_pcim.E2K_RT_PCIM_bgn = (pcim_bgn) >> E2K_SIC_ALIGN_RT_PCIM;
               rt_pcim.E2K_RT_PCIM_end =
                       (pcim_end - 1) >> E2K_SIC_ALIGN_RT_PCIM;
               early_sic_write_node_iolink_nbsr_reg(node, link, rt_pcim1_reg,
                                               rt_pcim.E2K_RT_PCIM_reg);
		DebugIORT("NODE #%d IO link #%d: router to PCI-MM node #1 set "
			"from 0x%X\n",
			node, link, pcim_bgn, pcim_end);
               pcim_bgn = PCI_IO_DOMAIN_START(domain);
               pcim_end = PCI_IO_DOMAIN_END(domain);
               rt_pciio.E2K_RT_PCIIO_bgn =
                       (pcim_bgn) >> E2K_SIC_ALIGN_RT_PCIIO;
               rt_pciio.E2K_RT_PCIIO_end =
                       (pcim_end - 1) >> E2K_SIC_ALIGN_RT_PCIIO;
               early_sic_write_node_iolink_nbsr_reg(node, link, rt_pciio1_reg,
                                               rt_pciio.E2K_RT_PCIIO_reg);
		DebugIORT("NODE #%d IO link #%d: router to PCI-IO node #1 set "
			"from 0x%X\n",
			node, link, pcim_bgn, pcim_end);
       }
       if (node != 2 && (phys_node_pres_map & 0x4)) {  // node #2 is present
               /* configure link the NODE to access to ioapic space NODE 2 */
               domain = node_iohub_to_domain(2, link);
               rt_ioapic.E2K_RT_IOAPIC_bgn = domain;
               early_sic_write_node_iolink_nbsr_reg(node, link, rt_ioapic2_reg,
                                               rt_ioapic.E2K_RT_IOAPIC_reg);
		DebugIORT("NODE #%d IO link #%d: router to IO-APIC node #2 set "
			"from 0x%X\n",
			node, link, domain);
               pcim_bgn = PCI_MEM_DOMAIN_START(domain);
               pcim_end = PCI_MEM_DOMAIN_END(domain);
               rt_pcim.E2K_RT_PCIM_bgn = (pcim_bgn) >> E2K_SIC_ALIGN_RT_PCIM;
               rt_pcim.E2K_RT_PCIM_end =
                       (pcim_end - 1) >> E2K_SIC_ALIGN_RT_PCIM;
               early_sic_write_node_iolink_nbsr_reg(node, link, rt_pcim2_reg,
                                               rt_pcim.E2K_RT_PCIM_reg);
		DebugIORT("NODE #%d IO link #%d: router to PCI-MM node #2 set "
			"from 0x%X\n",
			node, link, pcim_bgn, pcim_end);
               pcim_bgn = PCI_IO_DOMAIN_START(domain);
               pcim_end = PCI_IO_DOMAIN_END(domain);
               rt_pciio.E2K_RT_PCIIO_bgn =
                       (pcim_bgn) >> E2K_SIC_ALIGN_RT_PCIIO;
               rt_pciio.E2K_RT_PCIIO_end =
                       (pcim_end - 1) >> E2K_SIC_ALIGN_RT_PCIIO;
               early_sic_write_node_iolink_nbsr_reg(node, link, rt_pciio2_reg,
                                               rt_pciio.E2K_RT_PCIIO_reg);
		DebugIORT("NODE #%d IO link #%d: router to PCI-IO node #2 set "
			"from 0x%X\n",
			node, link, pcim_bgn, pcim_end);
       }
       if (node != 3 && (phys_node_pres_map & 0x8)) {  // node #3 is present
               /* configure link the NODE to access to ioapic space NODE 3 */
               domain = node_iohub_to_domain(3, link);
               rt_ioapic.E2K_RT_IOAPIC_bgn = domain;
               early_sic_write_node_iolink_nbsr_reg(node, link, rt_ioapic3_reg,
                                               rt_ioapic.E2K_RT_IOAPIC_reg);
		DebugIORT("NODE #%d IO link #%d: router to IO-APIC node #3 set "
			"from 0x%X\n",
			node, link, domain);
               pcim_bgn = PCI_MEM_DOMAIN_START(domain);
               pcim_end = PCI_MEM_DOMAIN_END(domain);
               rt_pcim.E2K_RT_PCIM_bgn = (pcim_bgn) >> E2K_SIC_ALIGN_RT_PCIM;
               rt_pcim.E2K_RT_PCIM_end =
                       (pcim_end - 1) >> E2K_SIC_ALIGN_RT_PCIM;
               early_sic_write_node_iolink_nbsr_reg(node, link, rt_pcim3_reg,
                                               rt_pcim.E2K_RT_PCIM_reg);
		DebugIORT("NODE #%d IO link #%d: router to PCI-MM node #3 set "
			"from 0x%X\n",
			node, link, pcim_bgn, pcim_end);
               pcim_bgn = PCI_IO_DOMAIN_START(domain);
               pcim_end = PCI_IO_DOMAIN_END(domain);
               rt_pciio.E2K_RT_PCIIO_bgn =
                       (pcim_bgn) >> E2K_SIC_ALIGN_RT_PCIIO;
               rt_pciio.E2K_RT_PCIIO_end =
                       (pcim_end - 1) >> E2K_SIC_ALIGN_RT_PCIIO;
               early_sic_write_node_iolink_nbsr_reg(node, link, rt_pciio3_reg,
                                               rt_pciio.E2K_RT_PCIIO_reg);
		DebugIORT("NODE #%d IO link #%d: router to PCI-IO node #3 set "
			"from 0x%X\n",
			node, link, pcim_bgn, pcim_end);
       }
}

static void configure_io_routing(void)
{
       int node;
       int link;

       for (node = 0; node < MAX_NUMNODES; node ++) {
               if (!(phys_node_pres_map & (1 << node)))
                       continue;
               for_each_iolink_of_node(link) {
                       configure_node_io_routing(node, link);
               }
       }
}
#elif	defined(CONFIG_E2K_LEGACY_SIC)
#define	configure_io_routing()
#endif	/* CONFIG_E2K_FULL_SIC */
#endif /* CONFIG_E2K_SIC */

#ifdef	CONFIG_E2K_SIC
#ifdef	CONFIG_E2K_FULL_SIC
#ifdef	CONFIG_SMP
static int startup_all_cores(e2k_rt_lcfg_struct_t rt_lcfg, int max_cores_num,
				bool bsp)
{
	int i = 0, core;

	for (core = 0; core < max_cores_num; core++) {
		if (core == 0 && bsp)
			/* if core # 0 is BSP then already started */
			continue;
		i += e2k_startup_core(rt_lcfg, core);
	}
	return i;
}
#endif	/* CONFIG_SMP */

static void configure_node_io_link(int node)
{
       e2k_rt_lcfg_struct_t    rt_lcfg;
       int rt_lcfg0_reg;
       int rt_lcfg1_reg;
       int rt_lcfg2_reg;
       int rt_lcfg3_reg;
       int iolink_on;
       int link;
       int domain;

       if (node == 0) {
               rt_lcfg0_reg = SIC_rt_lcfg0;
               rt_lcfg1_reg = SIC_rt_lcfg1;
               rt_lcfg2_reg = SIC_rt_lcfg2;
               rt_lcfg3_reg = SIC_rt_lcfg3;
       } else if (node == 1) {
               rt_lcfg0_reg = SIC_rt_lcfg3;
               rt_lcfg1_reg = SIC_rt_lcfg0;
               rt_lcfg2_reg = SIC_rt_lcfg1;
               rt_lcfg3_reg = SIC_rt_lcfg2;
       } else if (node == 2) {
               rt_lcfg0_reg = SIC_rt_lcfg2;
               rt_lcfg1_reg = SIC_rt_lcfg3;
               rt_lcfg2_reg = SIC_rt_lcfg0;
               rt_lcfg3_reg = SIC_rt_lcfg1;
       } else if (node == 3) {
               rt_lcfg0_reg = SIC_rt_lcfg1;
               rt_lcfg1_reg = SIC_rt_lcfg2;
               rt_lcfg2_reg = SIC_rt_lcfg3;
               rt_lcfg3_reg = SIC_rt_lcfg0;
       } else {
               rom_printk("configure_node_io_link() invalid node #%d\n",
                       node);
               return;
       }

       /* configure own link cfg of the NODE to access to own io link */
	E2K_RT_LCFG_reg(rt_lcfg) = early_sic_read_node_nbsr_reg(node,
								SIC_rt_lcfg0);
	iolink_on = 0;
	for_each_iolink_of_node(link) {
	domain = node_iohub_to_domain(node, link);
	if ((online_iohubs_map & (1 << domain)) ||
		(online_rdmas_map & (1 << domain)))
		iolink_on |= 1;
	}
	E2K_RT_LCFG_vio(rt_lcfg) = iolink_on;
	early_sic_write_node_nbsr_reg(node, SIC_rt_lcfg0,
						E2K_RT_LCFG_reg(rt_lcfg));

       if (node != 0 && (phys_node_pres_map & 0x1)) {  // node #0 is present
               /* configure link cfg the NODE to access to io link of NODE 0 */
		E2K_RT_LCFG_reg(rt_lcfg) = early_sic_read_node_nbsr_reg(node,
						rt_lcfg0_reg);
               iolink_on = 0;
               for_each_iolink_of_node(link) {
                       domain = node_iohub_to_domain(0, link);
                       if ((online_iohubs_map & (1 << domain)) ||
                                       (online_rdmas_map & (1 << domain)))
                               iolink_on |= 1;
               }
		E2K_RT_LCFG_vio(rt_lcfg) = iolink_on;
		early_sic_write_node_nbsr_reg(node, rt_lcfg0_reg,
						E2K_RT_LCFG_reg(rt_lcfg));
       }
       if (node != 1 && (phys_node_pres_map & 0x2)) {  // node #1 is present
               /* configure link cfg the NODE to access to io link of NODE 1 */
		E2K_RT_LCFG_reg(rt_lcfg) = early_sic_read_node_nbsr_reg(node,
								rt_lcfg1_reg);
               iolink_on = 0;
               for_each_iolink_of_node(link) {
                       domain = node_iohub_to_domain(1, link);
                       if ((online_iohubs_map & (1 << domain)) ||
                                       (online_rdmas_map & (1 << domain)))
                               iolink_on |= 1;
               }
		E2K_RT_LCFG_vio(rt_lcfg) = iolink_on;
		early_sic_write_node_nbsr_reg(node, rt_lcfg1_reg,
						E2K_RT_LCFG_reg(rt_lcfg));
       }
       if (node != 2 && (phys_node_pres_map & 0x4)) {  // node #2 is present
               /* configure link cfg the NODE to access to io link of NODE 2 */
		E2K_RT_LCFG_reg(rt_lcfg) = early_sic_read_node_nbsr_reg(node,
								rt_lcfg2_reg);
               iolink_on = 0;
               for_each_iolink_of_node(link) {
                       domain = node_iohub_to_domain(2, link);
                       if ((online_iohubs_map & (1 << domain)) ||
                                       (online_rdmas_map & (1 << domain)))
                               iolink_on |= 1;
               }
		E2K_RT_LCFG_vio(rt_lcfg) = iolink_on;
		early_sic_write_node_nbsr_reg(node, rt_lcfg2_reg,
						E2K_RT_LCFG_reg(rt_lcfg));
       }
       if (node != 3 && (phys_node_pres_map & 0x8)) {  // node #3 is present
               /* configure link cfg the NODE to access to io link of NODE 3 */
		E2K_RT_LCFG_reg(rt_lcfg) = early_sic_read_node_nbsr_reg(node,
								rt_lcfg3_reg);
               iolink_on = 0;
               for_each_iolink_of_node(link) {
                       domain = node_iohub_to_domain(3, link);
                       if ((online_iohubs_map & (1 << domain)) ||
                                       (online_rdmas_map & (1 << domain)))
                               iolink_on |= 1;
               }
		E2K_RT_LCFG_vio(rt_lcfg) = iolink_on;
		early_sic_write_node_nbsr_reg(node, rt_lcfg3_reg,
						E2K_RT_LCFG_reg(rt_lcfg));
       }
}

static void configure_io_links(void)
{
       int node;

       for (node = 0; node < MAX_NUMNODES; node ++) {
               if (!(phys_node_pres_map & (1 << node)))
                       continue;
               configure_node_io_link(node);
       }
}

#ifdef	CONFIG_EIOH
static void scan_iolink_config(int node, int link)
{
	rom_printk("%s() is not implemented for EIOHub\n", __func__);
}
#else	/* ! CONFIG_EIOH */
static void scan_iolink_config(int node, int link)
{
       e2k_iol_csr_struct_t    io_link;
       e2k_io_csr_struct_t     io_hub;
       e2k_rdma_cs_struct_t    rdma;
       int src_mode, dst_mode;
       int ab_type;
       int link_on;

       link_on = 0;

       io_link.E2K_IOL_CSR_reg =
               early_sic_read_node_iolink_nbsr_reg(node, link, SIC_iol_csr);
       src_mode = io_link.E2K_IOL_CSR_mode;
       rom_printk("Node #%d IO LINK #%d is", node, link);
       if (io_link.E2K_IOL_CSR_mode == IOHUB_IOL_MODE) {
               io_hub.E2K_IO_CSR_reg =
                       early_sic_read_node_iolink_nbsr_reg(node, link,
                                                               SIC_io_csr);
               if (io_hub.E2K_IO_CSR_ch_on)
                       link_on = 1;
       } else {
               rdma.E2K_RDMA_CS_reg =
                       early_sic_read_node_iolink_nbsr_reg(node, link,
                                                               SIC_rdma_cs);
               if (rdma.E2K_RDMA_CS_ch_on)
                       link_on = 1;
       }
       if (!link_on) {
               if (src_mode == IOHUB_IOL_MODE) {
                       possible_iohubs_map |=
                               (1 << node_iohub_to_domain(node, link));
                       possible_iohubs_num ++;
                       rom_printk(" IOHUB controller");
               } else {
                       possible_rdmas_map |=
                               (1 << node_iohub_to_domain(node, link));
                       possible_rdmas_num ++;
                       rom_printk(" RDMA controller");
               }
               rom_printk(" OFF\n");
               return;
       }

       ab_type = io_link.E2K_IOL_CSR_abtype;
       switch (ab_type) {
       case IOHUB_ONLY_IOL_ABTYPE:
               rom_printk(" IO HUB controller ON connected to IOHUB");
               dst_mode = IOHUB_IOL_MODE;
               break;
       case RDMA_ONLY_IOL_ABTYPE:
               rom_printk(" RDMA controller ON connected to RDMA");
               dst_mode = RDMA_IOL_MODE;
               break;
       case RDMA_IOHUB_IOL_ABTYPE:
               rom_printk(" RDMA controller ON connected to IOHUB/RDMA");
               dst_mode = RDMA_IOL_MODE;
               break;
       default:
               rom_printk(" %s controller ON connected to unknown controller",
                       (src_mode == IOHUB_IOL_MODE) ? "IO HUB" : "RDMA");
               dst_mode = src_mode;
               break;
       }

       if (src_mode != dst_mode) {
               io_link.E2K_IOL_CSR_mode = dst_mode;
               early_sic_write_node_iolink_nbsr_reg(node, link, SIC_iol_csr,
                                               io_link.E2K_IOL_CSR_reg);
       }
       if (dst_mode == IOHUB_IOL_MODE) {
               online_iohubs_map |= (1 << node_iohub_to_domain(node, link));
               online_iohubs_num ++;
       } else {
               online_rdmas_map |= (1 << node_iohub_to_domain(node, link));
               online_rdmas_num ++;
       }
       rom_printk("\n");
}
#endif	/* CONFIG_EIOH */

#ifdef	CONFIG_EIOH
static void set_embeded_iohub(int node, int link)
{
	possible_iohubs_map |= (1 << node_iohub_to_domain(node, link));
	possible_iohubs_num++;

	online_iohubs_map |= (1 << node_iohub_to_domain(node, link));
	online_iohubs_num++;

	rom_printk("Node #%d embeded EIOHub controller #%d is ON\n",
		node, link);
}
#else	/* ! CONFIG_EIOH */
static void set_embeded_iohub(int node, int link)
{
	/* cannot be embeded IOHub */
}
#endif	/* CONFIG_EIOH */

static void scan_iohubs(void)
{
	int node;
	int link;

	for (node = 0; node < MAX_NUMNODES; node++) {
		if (!(phys_node_pres_map & (1 << node)))
			continue;
		set_embeded_iohub(node, 0);
		for_each_iolink_of_node(link) {
			scan_iolink_config(node, link);
		}
	}
}
#elif	defined(CONFIG_E2K_LEGACY_SIC)
static void scan_iohubs(void)
{
	/* only one IOHUB on root bus #0 */

	online_iohubs_map = 0x1;
	online_iohubs_num = 1;
}
#define configure_io_links()
#endif	/* CONFIG_E2K_FULL_SIC */
#endif /* CONFIG_E2K_SIC */

#ifdef CONFIG_E2C3
static void enable_embedded_devices(void)
{
	int node;
	unsigned int reg = 0xfc000000; /* Enable bits [31:26] */

	for (node = 0; node < MAX_NUMNODES; node++) {
		if (!(phys_node_pres_map & (1 << node)))
			continue;
		early_sic_write_node_nbsr_reg(node, SIC_rt_pcicfged, reg);
	}
}
#endif
#ifdef CONFIG_EIOH
static void setup_rt_msi(void)
{
	unsigned long rt_msi = PCI_MEM_END + 1; /* 0xf8000000 */
	unsigned long rt_msi_lo = rt_msi & 0xffffffff;
	unsigned long rt_msi_hi = rt_msi >> 32;
	int node;

	for (node = 0; node < MAX_NUMNODES; node++) {
		if (!(phys_node_pres_map & (1 << node)))
			continue;
		early_sic_write_node_nbsr_reg(node, SIC_rt_msi, rt_msi_lo);
		early_sic_write_node_nbsr_reg(node, SIC_rt_msi_h, rt_msi_hi);
	}
}
#endif

void jump(void)
{

	bool bootmode = (bool)(unsigned long)&boot_mode;
	e2k_addr_t areabase;
	e2k_size_t areasize;

	e2k_psp_hi_t psp_hi;
	e2k_psp_lo_t psp_lo;
	e2k_pcsp_hi_t pcsp_hi;
	e2k_pcsp_lo_t pcsp_lo;
	e2k_usbr_t usbr;

	int cmd_size;
	e2k_addr_t busy_mem_start;
	e2k_addr_t busy_mem_end;
	bank_info_t *bank_info;
#ifdef	CONFIG_E2K_SIC
#if	defined(CONFIG_E2K_FULL_SIC)
#ifdef	CONFIG_SMP
	int max_cpus_num;
#endif	/* CONFIG_SMP */
	e2k_rt_pciio_struct_t	rt_pciio;
	e2k_rt_pcim_struct_t	rt_pcim;
	e2k_rt_ioapic_struct_t	rt_ioapic;
	/* Configure PCIIO for BSP. The only BSP has access to PCIIO, and other cpus through BSP */
	/* so we leave rt_pciio 1,2,3 closed by default */
	AS_WORD(rt_pciio) = NATIVE_GET_SICREG(rt_pciio0, E2K_MAX_CL_NUM, 0);
	AS_STRUCT(rt_pciio).bgn = 0x0; 
	AS_STRUCT(rt_pciio).end = 0xf; /* All the memory for bsp 
					* 0x01_0100_0 000 - 0x01_0100_F FFF
					* Align = 4Kb (0x1000) */
	NATIVE_SET_SICREG(rt_pciio0, AS_WORD(rt_pciio), E2K_MAX_CL_NUM, 0);
#ifdef CONFIG_BIOS
	bios_first();
#endif

	/* Configure IOAPIC for BSP. The only BSP has access to IOAPIC, and other cpus through BSP */
	/* so we leave rt_ioapic 1,2,3 closed by default */
	AS_WORD(rt_ioapic) = NATIVE_GET_SICREG(rt_ioapic0, E2K_MAX_CL_NUM, 0);
	DebugRT("jump: rt_ioapic0 = 0x%x\n", AS_WORD(rt_ioapic));
	AS_STRUCT(rt_ioapic).bgn = 0x0; /* 0x00_fec0_0000-0x00_fec0_0fff Align = 4k
					 * end[20:12] = bgn[20:12]
					 * end[11:0] = 0xfff  */
	NATIVE_SET_SICREG(rt_ioapic0, AS_WORD(rt_ioapic), E2K_MAX_CL_NUM, 0);
	
	/* Configure IOAPIC link for NODE 1 FIXME: may be used in future */
	AS_WORD(rt_ioapic) = NATIVE_GET_SICREG(rt_ioapic1, E2K_MAX_CL_NUM, 0);
	DebugRT("jump: rt_ioapic1 = 0x%x\n", AS_WORD(rt_ioapic));
	AS_STRUCT(rt_ioapic).bgn = 0x1; /* 0x00_fec0_1000-0x00_fec0_1fff Align = 4k
					 * end[20:12] = bgn[20:12]
					 * end[11:0] = 0xfff  */
	NATIVE_SET_SICREG(rt_ioapic1, AS_WORD(rt_ioapic), E2K_MAX_CL_NUM, 0);
	
	/* Configure IOAPIC link for NODE 2 FIXME: may be used in future */
	AS_WORD(rt_ioapic) = NATIVE_GET_SICREG(rt_ioapic2, E2K_MAX_CL_NUM, 0);
	DebugRT("jump: rt_ioapic2 = 0x%x\n", AS_WORD(rt_ioapic));
	AS_STRUCT(rt_ioapic).bgn = 0x2; /* 0x00_fec0_2000-0x00_fec0_2fff Align = 4k
					 * end[20:12] = bgn[20:12]
					 * end[11:0] = 0xfff  */
	NATIVE_SET_SICREG(rt_ioapic2, AS_WORD(rt_ioapic), E2K_MAX_CL_NUM, 0);

	/* Configure IOAPIC link for NODE 3 FIXME: may be used in future */
	AS_WORD(rt_ioapic) = NATIVE_GET_SICREG(rt_ioapic3, E2K_MAX_CL_NUM, 0);
	DebugRT("jump: rt_ioapic3 = 0x%x\n", AS_WORD(rt_ioapic));
	AS_STRUCT(rt_ioapic).bgn = 0x3; /* 0x00_fec0_3000-0x00_fec0_3fff Align = 4k
					 * end[20:12] = bgn[20:12]
					 * end[11:0] = 0xfff  */
	NATIVE_SET_SICREG(rt_ioapic3, AS_WORD(rt_ioapic), E2K_MAX_CL_NUM, 0);

	/* Configure PCIM for BSP. The only BSP has access to PCIM, and other cpus through BSP */
	/* so we leave rt_pcim 1,2,3 closed by default */
	AS_WORD(rt_pcim) = NATIVE_GET_SICREG(rt_pcim0, E2K_MAX_CL_NUM, 0);
	DebugRT("jump: rt_pcim0 = 0x%x\n", AS_WORD(rt_pcim));
	AS_STRUCT(rt_pcim).bgn = 0x10; 	/* 2 Gb start of PCI memory */ 
	AS_STRUCT(rt_pcim).end = 0x1e; /* All other memory fo bsp 
					* 0x00_10 00_0000 - 0x00_f7 ff_ffff (0xf0 00_0000 + 0x7 ff_ffff); 
					* Align = 128Mb (0x8000000) 
					* BUG: 0x1f= 0x00_ff ff_ffff intersects with LAPIC area but
					* available. Due to specification the end can be 0x00_FEBF_FFFF but
					* it's ipmossible to reach  */ 
	NATIVE_SET_SICREG(rt_pcim0, AS_WORD(rt_pcim), E2K_MAX_CL_NUM, 0);
#elif	defined(CONFIG_E2K_LEGACY_SIC)
#ifdef CONFIG_BIOS
	bios_first();
#endif
#endif	/* CONFIG_E2K_FULL_SIC */
#endif	/* CONFIG_E2K_SIC */

#ifdef	CONFIG_E2K_SIC
	configure_routing_regs();
	configure_io_routing();
#endif	/* CONFIG_E2K_SIC */

#ifdef	CONFIG_SMP
	all_pic_ids[0] = NATIVE_READ_PIC_ID();
#ifdef	CONFIG_E2K_SIC
#if	defined(CONFIG_E2K_LEGACY_SIC)
#ifdef	CONFIG_E1CP
	atomic_set(&cpu_count, 1);	/*only BSP CPU is enable */
#endif	/* CONFIG_E1CP */
#elif	defined(CONFIG_E2K_FULL_SIC)
/* Determine the total number of CPUs */
	atomic_set(&cpu_count, 0);	/* start application CPUs to determine
					   own # and total CPU number */
#if	defined(CONFIG_E1CP)
	max_cpus_num = E1CP_NR_NODE_CPUS;
#elif	defined(CONFIG_E2C3)
	max_cpus_num = E2C3_NR_NODE_CPUS;
#elif	defined(CONFIG_E2S)
	max_cpus_num = E2S_NR_NODE_CPUS;
#elif	defined(CONFIG_E8C) || defined(CONFIG_E8C2)
	max_cpus_num = E8C_NR_NODE_CPUS;
#elif	defined(CONFIG_E12C)
	max_cpus_num = E12C_NR_NODE_CPUS;
#elif	defined(CONFIG_E16C)
	max_cpus_num = E16C_NR_NODE_CPUS;
#elif	defined(CONFIG_E48C)
	max_cpus_num = E48C_NR_NODE_CPUS;
#elif	defined(CONFIG_E8V7)
	max_cpus_num = E8V7_NR_NODE_CPUS;
#else
 #error	"Unknown MicroProcessor type"
#endif
	for (;;)
	{
		e2k_rt_lcfg_struct_t	rt_lcfg;
		int i = 0;

		if (max_cpus_num > 1) {
			E2K_RT_LCFG_reg(rt_lcfg) =	/* Read on BSP */
				NATIVE_GET_SICREG(rt_lcfg0, 0, 0);
			i += startup_all_cores(rt_lcfg, max_cpus_num,
						true	/* BSP */);
		}

		E2K_RT_LCFG_reg(rt_lcfg) =
			NATIVE_GET_SICREG(rt_lcfg1, 0, 0); /* Read on BSP */
		if (E2K_RT_LCFG_vp(rt_lcfg) == 1) {
			i += startup_all_cores(rt_lcfg, max_cpus_num,
						false	/* BSP ? */);
		}
		
		E2K_RT_LCFG_reg(rt_lcfg) =
			NATIVE_GET_SICREG(rt_lcfg2, 0, 0); /* Read on BSP */
		if (E2K_RT_LCFG_vp(rt_lcfg) == 1) {
			i += startup_all_cores(rt_lcfg, max_cpus_num,
						false	/* BSP ? */);
		}
		E2K_RT_LCFG_reg(rt_lcfg) =
			NATIVE_GET_SICREG(rt_lcfg3, 0, 0); /* Read on BSP */
		if (E2K_RT_LCFG_vp(rt_lcfg) == 1) {
			i += startup_all_cores(rt_lcfg, max_cpus_num,
						false	/* BSP ? */);
		}
		if (max_cpus_num > 1)
			atomic_inc(&cpu_count);	/* acoount BSP core */
		i = atomic_read(&cpu_count);
		rom_printk("Detected %d CPUS\n", i);
		break;
	}
#endif	/* CONFIG_E2K_LEGACY_SIC */
#endif	/* CONFIG_E2K_SIC */
#endif	/* CONFIG_SMP */

	/* Boot info goes under loader's C-stack and below kernel code. */
	bootblock = (bootblock_struct_t *)
			_PAGE_ALIGN_DOWN((e2k_addr_t)free_memory_p,
			 			E2K_BOOTINFO_PAGE_SIZE);
	free_memory_p = (char *)((e2k_addr_t)bootblock +
					sizeof(bootblock_struct_t));
	boot_info = &bootblock->info;
	rom_printk("Boot info structure at 0x%X\n", boot_info);
	bios_info = &boot_info->bios;
	rom_printk("BIOS info structure at 0x%X\n", bios_info);

#ifdef	CONFIG_RECOVERY
	if (boot_info->signature == BOOTBLOCK_ROMLOADER_SIGNATURE) {
		recovery_flag = bootblock->boot_flags & RECOVERY_BB_FLAG;
		not_read_image = bootblock->boot_flags & NO_READ_IMAGE_BB_FLAG;

		if (recovery_flag) {
			rom_puts("ROM loader restarted to recover "
				"kernel\n");
		} else {
			rom_puts("ROM loader restarted to boot kernel.\n");
		}
	} else {
#endif	/* CONFIG_RECOVERY */

		rom_printk("Kernel ROM loader's initialization started.\n");
#ifdef	CONFIG_RECOVERY
	}
#endif	/* CONFIG_RECOVERY */


#ifdef	CONFIG_RECOVERY
	if (!recovery_flag) {
#endif	/* CONFIG_RECOVERY */
		rom_printk("DATA at: 0x%X,",(u64)_data);
		rom_printk(" size: 0x%X.\n", ((u64)_edata - (u64)_data));

		rom_printk("BSS at: 0x%X,",(u64)__bss_start);
		rom_printk(" size: 0x%X.\n", ((u64)__bss_stop -
						(u64)__bss_start));

		psp_hi = NATIVE_NV_READ_PSP_HI_REG();
		psp_lo = NATIVE_NV_READ_PSP_LO_REG();

		rom_printk("Proc. Stack (PSP) at: 0x%X,",
			AS_STRUCT(psp_lo).base);
		rom_printk(" size: 0x%X,", AS_STRUCT(psp_hi).size);
		rom_printk(" direction: %s.\n", "upward");

		pcsp_hi = NATIVE_NV_READ_PCSP_HI_REG();
		pcsp_lo = NATIVE_NV_READ_PCSP_LO_REG();

		rom_printk("Proc. Chain Stack (PCSP) at: 0x%X,", 
			AS_STRUCT(pcsp_lo).base);
		rom_printk(" size: 0x%X,", AS_STRUCT(pcsp_hi).size);
		rom_printk(" direction: %s.\n", "upward");
		usbr.USBR_reg = NATIVE_NV_READ_USBR_REG_VALUE();
		rom_printk("GNU C Stack at: 0x%X,", usbr.USBR_base);
		rom_printk(" size: 0x%X, ", E2K_BOOT_KERNEL_US_SIZE);
		rom_printk(" direction: %s.\n", "downward");
		rom_printk("BOOTINFO structure is starting at: 0x%X, size 0x%X\n",
			(u64) bootblock, sizeof(bootblock_struct_t));
#ifdef	CONFIG_RECOVERY
	}
#endif	/* CONFIG_RECOVERY */

#ifdef	CONFIG_RECOVERY
	if (!recovery_flag) {
#endif	/* CONFIG_RECOVERY */


#ifdef CONFIG_CMDLINE_PROMPT
		kernel_command_prompt(cmd_line, cmd_preset);
#else
		cmd_size = bios_strlen(cmd_preset);
		if (cmd_size > sizeof(cmd_buf)) {
			rom_printk("Kernel command line size is too big "
				"size %d > %d (buffer size)\n",
				cmd_size, sizeof(cmd_buf));
			E2K_LMS_HALT_OK;
		}
		memcpy(cmd_line, cmd_preset, bios_strlen(cmd_preset));
#endif /* CONFIG_CMDLINE_PROMPT */


#ifdef	CONFIG_RECOVERY
	}
#endif	/* CONFIG_RECOVERY */

#ifdef	CONFIG_SMP
	smp_start_cpus();
#else
	
#ifdef CONFIG_L_LOCAL_APIC
	setup_local_pic(0);
#endif /* CONFIG_L_LOCAL_APIC */
	
#endif	/* CONFIG_SMP */


#ifdef	CONFIG_RECOVERY
	if (!recovery_flag) {
#endif	/* CONFIG_RECOVERY */
		memset(boot_info, 0, sizeof(*boot_info));
		memset(bios_info, 0, sizeof(*bios_info));

		/* Creation of boot info records. */
		boot_info->signature = BOOTBLOCK_ROMLOADER_SIGNATURE;	/* ROMLoader marker */
		boot_info->vga_mode = 0;
		
		/* our loader used only on simulator */
		boot_info->mach_flags = SIMULATOR_MACH_FLAG;

		probe_memory(boot_info, 0, 0, 0);
#ifdef	CONFIG_E2K_SIC
		set_memory_filters(boot_info);
#endif	/* CONFIG_E2K_SIC */

		/*
		 * The kernel command line.
		 * read Linux documentation for cmdline syntax.
		 */
		cmd_size = bios_strlen(cmd_line) + 1;
		if (cmd_size <= KSTRMAX_SIZE) {
			memcpy(boot_info->kernel_args_string, cmd_line,
					cmd_size);
		} else if (cmd_size <= KSTRMAX_SIZE_EX) {
			memcpy(boot_info->bios.kernel_args_string_ex, cmd_line,
					cmd_size);
			memcpy(boot_info->kernel_args_string,
					KERNEL_ARGS_STRING_EX_SIGNATURE,
					KERNEL_ARGS_STRING_EX_SIGN_SIZE);
		} else {
			/* command line too big */
			rom_printk("Kernel command line too big, "
				"size %d > %d\n",
				cmd_size, KSTRMAX_SIZE_EX);
			E2K_LMS_HALT_OK;
		}
		rom_printk("Kernel command line: %s\n",
			boot_info->kernel_args_string);

		/* Creation of bios info records. */
		memcpy(bios_info->signature, BIOS_INFO_SIGNATURE,
			(int)bios_strlen(BIOS_INFO_SIGNATURE) + 1);
		memcpy(bios_info->boot_ver, BOOT_VER_STR,
			(int)bios_strlen(BOOT_VER_STR) + 1);
		bios_info->chipset_type = CHIPSET_TYPE_IOHUB;
		if (NATIVE_IS_MACHINE_E2S)
			bios_info->cpu_type = CPU_TYPE_E2S;
		else if (NATIVE_IS_MACHINE_E8C)
			bios_info->cpu_type = CPU_TYPE_E8C;
		else if (NATIVE_IS_MACHINE_E8C2)
			bios_info->cpu_type = CPU_TYPE_E8C2;
		else if (NATIVE_IS_MACHINE_E1CP)
			bios_info->cpu_type = CPU_TYPE_E1CP;
		else if (NATIVE_IS_MACHINE_E12C)
			bios_info->cpu_type = CPU_TYPE_E12C;
		else if (NATIVE_IS_MACHINE_E16C)
			bios_info->cpu_type = CPU_TYPE_E16C;
		else if (NATIVE_IS_MACHINE_E2C3)
			bios_info->cpu_type = CPU_TYPE_E2C3;
		else if (NATIVE_IS_MACHINE_E48C)
			bios_info->cpu_type = CPU_TYPE_E48C;
		else if (NATIVE_IS_MACHINE_E8V7)
			bios_info->cpu_type = CPU_TYPE_E8V7;
		rom_printk("CPU & MicroProcessor: %s\n",
			GET_CPU_TYPE_NAME(bios_info->cpu_type));

#ifdef	CONFIG_RECOVERY
	}
#endif	/* CONFIG_RECOVERY */
	
	boot_info->num_of_busy = 0;

	/*
	 * Memory assumptions: node #0 & bank #0 exist and starts from 0
	 * If memory banks > 1 we use bank #1 on the node #0
	 */
	busy_mem_end = PAGE_ALIGN_DOWN((e2k_addr_t)free_memory_p);
	add_busy_memory_area(boot_info, (e2k_addr_t)_data, busy_mem_end);
	
	bank_info = &boot_info->nodes_mem[0].banks[1];
	if (bank_info->size == 0)
		/* only one bank of memory detected on the node #0 */
		bank_info = &boot_info->nodes_mem[0].banks[0];
	if (busy_mem_end >= bank_info->address &&
		busy_mem_end < (bank_info->address + bank_info->size)) {
		areabase = busy_mem_end;
		areasize = bank_info->size - 
				(busy_mem_end - bank_info->address);
	} else {
		/* should panic indeed */ ;
		areabase = bank_info->address;
		areasize = bank_info->size;
	}
	busy_mem_start = areabase;

	bios_mem_init(areabase, areasize);

	scan_iohubs();
	configure_io_links();

#ifdef CONFIG_E2C3
	enable_embedded_devices();
#endif
#ifdef CONFIG_EIOH
	setup_rt_msi();
#endif

#ifdef CONFIG_BIOS
#ifdef CONFIG_ENABLE_ELBRUS_PCIBIOS
        pci_bios();
#endif
#endif

#ifdef CONFIG_BIOS
	bios_rest();
#endif

#ifdef CONFIG_BIOS
#if defined(CONFIG_E2K_LEGACY_SIC)
        video_bios();
#endif	/* CONFIG_E2K_LEGACY_SIC */
#endif

#ifdef CONFIG_BLK_DEV_INITRD

	/*
	 * INITRD - initial ramdisk
	 */

	areasize = (e2k_addr_t)&initrd_data_end - (e2k_addr_t)&initrd_data;
	areabase = (long) malloc_aligned(areasize, E2K_INITRD_PAGE_SIZE);

#ifdef	CONFIG_RECOVERY
	if (!recovery_flag) {
#endif	/* CONFIG_RECOVERY */
		rom_puts("Copying initial ramdisk from ROM to RAM ... ");

		memcpy((void *)areabase, (void *)&initrd_data, (int)areasize);

		rom_puts("done.\n");

		boot_info->ramdisk_base = areabase;
		boot_info->ramdisk_size = areasize;

		rom_printk("Initial ramdisk relocated at: 0x%X, "
			   "size: 0x%X.\n", areabase, areasize);
#ifdef	CONFIG_RECOVERY
	}
#endif	/* CONFIG_RECOVERY */
#else	/* ! CONFIG_BLK_DEV_INITRD */
#ifdef	CONFIG_RECOVERY
	if (!recovery_flag) {
#endif	/* CONFIG_RECOVERY */
		boot_info->ramdisk_base = 0;
		boot_info->ramdisk_size = 0;
#ifdef	CONFIG_RECOVERY
	}
#endif	/* CONFIG_RECOVERY */

#endif /* CONFIG_BLK_DEV_INITRD */

#ifdef	CONFIG_RECOVERY
	if (!recovery_flag) {
#endif	/* CONFIG_RECOVERY */
		create_smp_config(boot_info);
#ifdef	CONFIG_RECOVERY
	} else {
		recover_smp_config(boot_info);
	}
#endif	/* CONFIG_RECOVERY */

	busy_mem_end = PAGE_ALIGN_DOWN(get_busy_memory_end());
	add_busy_memory_area(boot_info, busy_mem_start, busy_mem_end);

	if (bootmode) {
		areasize = (e2k_addr_t)&input_data_noncomp_size;
		rom_printk("Kernel will be loaded from 'romimage' file "
			"by simulator, size %d\n", areasize);
	} else {
		areasize = (e2k_addr_t)&input_data_end -
						(e2k_addr_t)&input_data;
		rom_printk("Kernel was loaded from ROM\n");
	}

	if (bootmode || areasize == (e2k_addr_t)&input_data_noncomp_size) {

		if (!bootmode)
			rom_printk("Non-compressed kernel found. Size: %d\n",
				areasize);

#ifdef	CONFIG_RECOVERY
	    if (!recovery_flag) {
#endif	/* CONFIG_RECOVERY */
		rom_puts("Allocating space for kernel copy... ");
		areabase = (long) malloc_aligned(areasize,
				E2K_MAX_PAGE_SIZE);
		rom_puts("done.\n");
		if (bootmode) {
			bios_outll(areabase, LMS_RAM_ADDR_PORT);
		}
#ifdef	CONFIG_RECOVERY
	   } else {
		areabase = boot_info->kernel_base;
		rom_printk("Kernel was loaded to 0x%X, size of "
			"0x%X\n", areabase, areasize);
	    }
#endif	/* CONFIG_RECOVERY */

#ifdef	CONFIG_RECOVERY
	    if (!recovery_flag) {
#endif	/* CONFIG_RECOVERY */

		if (bootmode) {
			rom_puts("Loading the kernel from 'romimage file "
				"to RAM ... ");
			bios_outb(LMS_LOAD_IMAGE_TO_RAM, LMS_TRACE_CNTL_PORT);
			rom_puts(" done.\n");
		} else {
			rom_puts("Copying the kernel from ROM to RAM ... ");
			memcpy((void *)areabase, (void *) &input_data,
				(int) areasize);
			rom_puts(" done.\n");
		}

#ifdef	CONFIG_RECOVERY
	    }
#endif	/* CONFIG_RECOVERY */
	} else {

		rom_printk("Compressed kernel found. Size: %d\n", areasize);

#ifdef	CONFIG_RECOVERY
	if (!recovery_flag) {
#endif /* CONFIG_RECOVERY */
		rom_printk("Allocating %d bytes for kernel decompression... ",
				&input_data_noncomp_size);
		areabase = (long) malloc_aligned(
					(e2k_addr_t)&input_data_noncomp_size,
					E2K_MAX_PAGE_SIZE);
		rom_puts("done.\n");
#ifdef CONFIG_RECOVERY
	   } else {
		areabase = boot_info->kernel_base;
		rom_printk("Kernel was decompressed to 0x%X, size of "
			"0x%X\n", areabase, areasize);
		areasize = boot_info->kernel_size;
	    }
#endif	/* CONFIG_RECOVERY */

#ifdef	CONFIG_RECOVERY
	    if (!recovery_flag) {
#endif	/* CONFIG_RECOVERY */
		rom_printk("Uncompressing Linux at 0x%X, size 0x%X...",
			areabase, (e2k_addr_t)&input_data_noncomp_size);
		areasize = decompress_kernel(areabase);
		rom_puts(" done.\n");
#ifdef	CONFIG_RECOVERY
	    } else {
		rom_printk("Uncompressed Linux at 0x%X, size 0x%X\n",
			areabase, areasize);
	    }
#endif	/* CONFIG_RECOVERY */
	}

	kernel_areabase = areabase;
	kernel_areasize = areasize;

#ifdef	CONFIG_RECOVERY
	if (!recovery_flag) {
#endif	/* CONFIG_RECOVERY */
		boot_info->kernel_base = kernel_areabase;
		boot_info->kernel_size = kernel_areasize;

		rom_printk("Kernel relocated at: 0x%X,", kernel_areabase);
		rom_printk(" size: 0x%X.\n", kernel_areasize);
#ifdef	CONFIG_RECOVERY
	} else {
		if (boot_info->kernel_base != kernel_areabase) {
			rom_puts("ERROR: Invalid kernel base address to "
				"recover the system.\n");
			rom_printk("Kernel base address from 'recovery_info' "
				"0x%X != 0x%X (current kernel allocation)\n",
				boot_info->kernel_base, kernel_areabase);
		}
		if (boot_info->kernel_size != kernel_areasize) {
			rom_puts("ERROR: Invalid kernel size to recover "
				"the system.\n");
			rom_printk("Kernel size from 'recovery_info' "
				"0x%X != 0x%X (current kernel size)\n",
				boot_info->kernel_size, kernel_areasize);
		}
#ifdef	CONFIG_STATE_SAVE
		rom_printk("Loading memory from disk...\n");
		load_machine_state_new(boot_info);
#endif	/* CONFIG_STATE_SAVE */
	}
#endif	/* CONFIG_RECOVERY */

	set_kernel_image_pointers();

#ifdef	CONFIG_RECOVERY
	if (!recovery_flag) {
#endif	/* CONFIG_RECOVERY */
		rom_puts("Jump into the vmlinux startup code using SCALL #12 "
			"...\n\n");
#ifdef	CONFIG_RECOVERY
	} else {
		bootblock->boot_flags &= ~RECOVERY_BB_FLAG;
		rom_printk("Jump into the vmlinux startup code using SCALL #12 "
			"to start kernel recovery\n\n");
	}
#endif	/* CONFIG_RECOVERY */

#ifdef	CONFIG_SMP
	do_smp_commence();
#endif	/* CONFIG_SMP */	

	scall2(bootblock);

	E2K_LMS_HALT_OK;
}

void
set_kernel_image_pointers(void)
{
	e2k_rwap_lo_struct_t	reg_lo;
	e2k_rwap_hi_struct_t	reg_hi;

	/*
	 * Set Kernel 'text/data/bss' segment registers to kernel image
	 * physical addresses
	 */

	reg_lo.CUD_lo_base = kernel_areabase;
	reg_lo.CUD_lo_c = E2K_CUD_CHECKED_FLAG;
	reg_lo._CUD_lo_rw = E2K_CUD_RW_PROTECTIONS;
	reg_hi.CUD_hi_size = kernel_areasize;
	reg_hi._CUD_hi_curptr = 0;
	NATIVE_WRITE_CUD_HI_REG_VALUE(reg_hi.CUD_hi_half);
	NATIVE_WRITE_CUD_LO_REG_VALUE(reg_lo.CUD_lo_half);
	NATIVE_WRITE_OSCUD_HI_REG_VALUE(reg_hi.OSCUD_hi_half);
	NATIVE_WRITE_OSCUD_LO_REG_VALUE(reg_lo.OSCUD_lo_half);

	reg_lo.GD_lo_base = kernel_areabase;
	reg_lo._GD_lo_rw = E2K_GD_RW_PROTECTIONS;
	reg_hi.GD_hi_size = kernel_areasize;
	reg_hi._GD_hi_curptr = 0;
	NATIVE_WRITE_GD_HI_REG_VALUE(reg_hi.GD_hi_half);
	NATIVE_WRITE_GD_LO_REG_VALUE(reg_lo.GD_lo_half);
	NATIVE_WRITE_OSGD_HI_REG_VALUE(reg_hi.OSGD_hi_half);
	NATIVE_WRITE_OSGD_LO_REG_VALUE(reg_lo.OSGD_lo_half);

}

