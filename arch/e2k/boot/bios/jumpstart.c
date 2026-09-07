/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/types.h>
#include <linux/mmzone.h>
#include <linux/log2.h>

#include "console/printk.h"

#include <asm/cpu_regs_types.h>
#include <asm/bootinfo.h>
#include <asm/machdep.h>
#include <asm/head.h>
#include <asm/sections.h>
#ifdef	CONFIG_SMP
#include <asm/atomic.h>
#endif	/* CONFIG_SMP */

#include "pic/pic.h"

#include <asm/e2k_api.h>
#include <asm/mpspec.h>
#include <asm/sic_regs.h>
#include <asm/sic_regs_access.h>
#include <asm/hb_regs.h>
#include "e2k_sic.h"

#include "topology.h"
#include "cpu_features.h"
#include "boot.h"
#include "pci.h"

#undef	DEBUG_RT_MODE
#undef	DebugRT
#define DEBUG_RT_MODE		1	/* routing registers */
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

//#define HAS_IOAPIC_LINKS	(CONFIG_CPU_ISET_MIN < 7)
#define HAS_IOAPIC_LINKS	1

extern long input_data_noncomp_size;

#ifdef CONFIG_BLK_DEV_INITRD
extern long initrd_data, initrd_data_end;
#endif /* CONFIG_BLK_DEV_INITRD */

#ifdef CONFIG_CMDLINE
#define CMDLINE CONFIG_CMDLINE
#else
#define CMDLINE "";
#endif

static char cmd_preset[] = CMDLINE;
static char cmd_buf[COMMAND_LINE_SIZE];

char *free_memory_p;

#ifdef	CONFIG_SMP
extern atomic_t cpu_count;
extern int phys_cpu_num;
extern void do_smp_commence(void);
extern volatile unsigned long	phys_cpu_pres_map;
#endif	/* CONFIG_SMP */

static DECLARE_BITMAP(phys_node_pres_map, MAX_NUMNODES) = { 0 };
static inline int phys_node_num(void)
{
	return bitmap_weight(phys_node_pres_map, MAX_NUMNODES);
}

volatile unsigned long	online_iohubs_map = 0;
volatile unsigned long	possible_iohubs_map = 0;
volatile unsigned long	online_rdmas_map = 0;
int			online_rdmas_num = 0;
volatile unsigned long	possible_rdmas_map = 0;
int			possible_rdmas_num = 0;

static	e2k_addr_t	kernel_areabase;
static	e2k_size_t	kernel_areasize;
bootblock_struct_t	*bootblock;
boot_info_t		*boot_info;
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


#if CONFIG_CPU_ISET_MIN >= 4
#define E2K_RT_LCFG_cln(x)	x.e8c.cln
#else
#define	E2K_RT_LCFG_cln(x)	x.e2s.cln
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

#define PCICFG_START			0x00200000000ULL

#if	defined(CONFIG_E8V7) || defined(CONFIG_V7)
# define PCICFG_NODE_SIZE		0x00100000000ULL
#else
# define PCICFG_NODE_SIZE		0x00010000000ULL
#endif

#define LO_MEMORY_START			0x00000000000ULL
#define HI_MEMORY_START	(ALIGN_BYTES_UP(PCICFG_START + \
		PCICFG_NODE_SIZE * phys_node_num(), _1GB * 4))
#define HI_MEMORY_NODE_MAX_SIZE		0x04000000000ULL

#if	defined(CONFIG_E8V7) || defined(CONFIG_V7)
# define CONFIG_RT_PCIIO_V7
# define CONFIG_IPCC4
#endif	/* CONFIG_E8V7 || CONFIG_V7 */

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
#define BOOT_MEMORY_PROBE_MAGIC 0x0123456789abcdefULL

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
	return round_up(HI_MEMORY_START + (HI_MEMORY_NODE_MAX_SIZE * node_id),
			E2K_SIC_SIZE_RT_MHI);
}
static inline u64 get_lo_memory_size(int node_id)
{
	return (PCI_MEM_START - LO_MEMORY_START) / phys_node_num();
}
static inline u64 get_lo_memory_start(int node)
{
	return round_up(LO_MEMORY_START + get_lo_memory_size(node) * node,
			E2K_SIC_MIN_MEMORY_BANK);
}

static inline e2k_rt_mhi_t get_rt_mhi(int mhi_no, int node_on, int node_for)
{
	e2k_rt_mhi_t rt_mhi;

	AW(rt_mhi) = 0x000000ff;
	if (mhi_no != 0 && mhi_no != node_for) {
		rom_printk("BUG: memory router setting is implemented on "
			"node #0 for all other nodes\n");
		return rt_mhi;
	}
	switch (mhi_no) {
	case 0:
		AW(rt_mhi) = NATIVE_GET_SICREG(rt_mhi0, 0, node_on);
		return rt_mhi;
	case 1:
		AW(rt_mhi) = NATIVE_GET_SICREG(rt_mhi1, 0, node_on);
		return rt_mhi;
	case 2:
		AW(rt_mhi) = NATIVE_GET_SICREG(rt_mhi2, 0, node_on);
		return rt_mhi;
	case 3:
		AW(rt_mhi) = NATIVE_GET_SICREG(rt_mhi3, 0, node_on);
		return rt_mhi;
	default:
		rom_printk("BUG : get_rt_mhi() : invalid RT_MHI #%d >= "
			"%d (max node numbers), ignored\n",
			mhi_no, MAX_NUMNODES);
		return rt_mhi;
	}
}

static inline void set_rt_mhi(e2k_rt_mhi_t rt_mhi, int mhi_no, int node_on, int node_for)
{
	if (mhi_no != 0 && mhi_no != node_for) {
		rom_printk("BUG: memory router setting is only implemented on "
			"node #0 for all other nodes\n");
		return;
	}
	switch (mhi_no) {
	case 0:
		NATIVE_SET_SICREG(rt_mhi0, AW(rt_mhi), 0, node_on);
		return;
	case 1:
		NATIVE_SET_SICREG(rt_mhi1, AW(rt_mhi), 0, node_on);
		return;
	case 2:
		NATIVE_SET_SICREG(rt_mhi2, AW(rt_mhi), 0, node_on);
		return;
	case 3:
		NATIVE_SET_SICREG(rt_mhi3, AW(rt_mhi), 0, node_on);
		return;
	default:
		rom_printk("BUG : set_rt_mhi() : invalid RT_MHI #%d >= "
			"%d (max node numbers), ignored\n",
			mhi_no, MAX_NUMNODES);
		return;
	}
}

static inline void set_rt_mhio_mc(e2k_rt_mhio_mc_t rt_mhio_mc, int node)
{
	NATIVE_SET_SICREG(rt_mhio_mc, AW(rt_mhio_mc), 0, node);
}

static void add_memory_region(boot_info_t *boot_info, int node, u64 start_addr, size_t size)
{
	u64 end_addr = start_addr + size;
	bank_info_t *node_banks = boot_info->nodes_mem[node].banks;
	int bank;

#ifdef	CONFIG_DISCONTIGMEM
	if (node >= MAX_NUMNODES) {
		rom_printk("BUG : add_memory_region() : invalid node #%d >= "
			"%d (max node numbers), ignored\n",
			node, MAX_NUMNODES);
		return;
	} else
#endif	/* CONFIG_DISCONTIGMEM */
	if (node >= L_MAX_MEM_NUMNODES) {
		rom_printk("BUG : add_memory_region() : node #%d >= %d (max nodes in nodes_mem table), ignored\n",
			node, L_MAX_MEM_NUMNODES);
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
			node);
		bank = -1;
		if (banks_ex_num >= L_MAX_PHYS_BANKS_EX) {
			rom_printk("BUG : add_memory_region() : banks of "
				"memory extended area is full, ignored\n");
			return;
		}
		node_banks = boot_info->banks_ex + banks_ex_num++;
	}
	node_banks->address = start_addr;
	node_banks->size = size;
	if (bank != -1)
		rom_printk("Node #%d : physical memory bank #%d:  base from "
			"0x%X to 0x%X (%d Mgb)\n",
			node, bank, start_addr, end_addr,
			(int)(size / _1MB));
	else
		rom_printk("Node #%d : extended physical memory bank #%d: "
			"base from 0x%X to 0x%X (%d Mgb)\n",
			node, banks_ex_num - 1, start_addr, end_addr,
			(int)(size / _1MB));
	boot_info->num_of_banks ++;
}

static noinline u64 probe_memory_region(boot_info_t *boot_info,
		e2k_addr_t start_addr, e2k_size_t size, u64 hi_memory_start)
{
	u64 addr;
	u64 end_addr = start_addr + size;

#ifdef	CONFIG_E2K_LEGACY_SIC
	/* Set memory range probing at TOP register of host bridge */
	if (end_addr >= APIC_DEFAULT_PHYS_BASE) {
		end_addr = APIC_DEFAULT_PHYS_BASE;
	}
	__boot_writel_hb_reg(end_addr, HB_PCI_TOM);

#endif	/* CONFIG_E2K_LEGACY_SIC */
	NATIVE_WRITE_MAS_D(start_addr, 0, MAS_BYPASS_ALL_CACHES);

	for (addr = start_addr + _1MB; addr < end_addr; addr += _1MB) {
		NATIVE_WRITE_MAS_D(addr, BOOT_MEMORY_PROBE_MAGIC,
			MAS_BYPASS_ALL_CACHES);
		if (NATIVE_READ_MAS_D(start_addr, MAS_BYPASS_ALL_CACHES) ==
			BOOT_MEMORY_PROBE_MAGIC)
			break;
	}

	return addr - start_addr;
}

static u64 probe_memory(boot_info_t *boot_info, int mhi_no, int node_on, int node_for,
			u64 hi_memory_start)
{
	u64 address;
	u64 size;
	u64 hi_start, hi_end;
	e2k_rt_mhi_t rt_mhi;

	if (mhi_no == 0) {
		rom_printk("Physical memory probing\n");
		boot_info->num_of_banks = 0;
	}
	address = get_hi_memory_start(node_for);
	size = HI_MEMORY_NODE_MAX_SIZE;

	/* all memory banks size can be only 2^n */
	size = __rounddown_pow_of_two(size);
	rom_printk("	init addr = 0x%X, init size = 0x%X\n", address, size);

	rt_mhi = get_rt_mhi(mhi_no, node_on, node_for);
	DebugMRT("get_memory_filters: on node #%d rt_mhi %x = 0x%x\n",
		node_on, mhi_no, AW(rt_mhi));
	hi_start = round_down(address, E2K_SIC_SIZE_RT_MHI);
	hi_end = round_up(address + size, E2K_SIC_SIZE_RT_MHI);
	rt_mhi.bgn = hi_start >> E2K_SIC_ALIGN_RT_MHI;
	rt_mhi.end = (hi_end - 1) >> E2K_SIC_ALIGN_RT_MHI;
	DebugMRT("set_memory_filters: on node #%d set rt_mhi %x to 0x%x\n",
		node_on, mhi_no,
		AW(get_rt_mhi(mhi_no, node_on, node_for)));
	set_rt_mhi(rt_mhi, mhi_no, node_on, node_for);

	if (mhi_no != 0) {
		/* setup rt_mhi0 on node 'for' */
		DebugMRT("set_memory_filters: on node #%d set rt_mhi %x "
			"to 0x%x\n",
			node_for, 0,
			AW(get_rt_mhi(0, node_for, node_for)));
		set_rt_mhi(rt_mhi, 0, node_for, node_for);
	}
	rom_printk("NODE #%d high memory router set from 0x%X to 0x%X\n",
		node_on, hi_start, hi_end);

	return probe_memory_region(boot_info, address, size, hi_memory_start);
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
	boot_info->num_of_nodes = phys_node_num();
	bitmap_to_arr64(&boot_info->nodes_map, phys_node_pres_map, 64);
#endif	/* CONFIG_SMP */

	boot_info->mp_table_base = allocate_mpf_structure();

#ifndef CONFIG_ENABLE_BIOS_MPTABLE
	set_mpt_config((struct intel_mp_floating *)boot_info->mp_table_base);
#else
	write_smp_table((struct intel_mp_floating *)boot_info->mp_table_base,
				boot_info->num_of_cpus);
#endif /* CONFIG_BIOS */
	rom_printk("MP-table is starting at: 0x%X size 0x%x\n",
		boot_info->mp_table_base, PAGE_SIZE);
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

#ifdef CONFIG_E2K_FULL_SIC
#ifdef	CONFIG_IPCC4
static unsigned find_active_ipi_links(void)
{
	e2k_st_ipl_t st_ipl;
	unsigned ip_links = 0;

	AW(st_ipl) = NATIVE_GET_SICREG(st_ipl, E2K_MAX_CL_NUM, 0);
	DebugRT("ST_XMU register 0x%x, links: A %x B %x C %x D %x\n",
		st_ipl.word,
		st_ipl.en_A, st_ipl.en_B, st_ipl.en_C, st_ipl.en_D);

	if (st_ipl.en_A)
		ip_links |= 0x1;	/* node 1 is present */
	if (st_ipl.en_B)
		ip_links |= 0x2;	/* node 2 is present */
	if (st_ipl.en_C)
		ip_links |= 0x4;	/* node 3 is present */

	return ip_links;
}
#else	/* !CONFIG_IPCC4 */
static unsigned find_active_ipi_links(void)
{
	e2k_st_p_t st_p;

	AW(st_p) = NATIVE_GET_SICREG(st_p, E2K_MAX_CL_NUM, 0);
	DebugRT("find_active_ipi_links: st_p = 0x%x\n", AW(st_p));

	return st_p.pl_val;
}
#endif	/* CONFIG_IPCC4 */

#ifdef	CONFIG_IPCC4
# define ipcc_v7	true
#else	/* !CONFIG_IPCC4 */
# define ipcc_v7	false
#endif	/* CONFIG_IPCC4 */
static void configure_routing_regs(void)
{
	e2k_rt_lcfg_t	rt_lcfg;
	e2k_rt_mlo_t	rt_mlo;
	unsigned	ip_links;
	int		rt_lcfg_no;
	int		rt_mlo_no;

	AW(rt_lcfg) = NATIVE_GET_SICREG(rt_lcfg0, E2K_MAX_CL_NUM, 0);
	DebugRT("configure_routing_regs: before setting up: rt_lcfg = 0x%x\n", AW(rt_lcfg));
	DebugRT("configure_routing_regs: configure RT_LCFGj\n");

	__set_bit(0, phys_node_pres_map);

	ip_links = find_active_ipi_links();
if (ip_links & 0x1){ // 001 - node 1 is present
/***********************  CONFIGURE NODE 1  ***********************************/
	__set_bit(1, phys_node_pres_map);
	/* Open link CPU 0 -> CPU 1 */
	AW(rt_lcfg) = NATIVE_GET_SICREG(rt_lcfg1, E2K_MAX_CL_NUM, 0);
	rt_lcfg.vp = 1;
	rt_lcfg.vb = 0;
	rt_lcfg.vio = 0;
	NATIVE_SET_SICREG(rt_lcfg1, AW(rt_lcfg), E2K_MAX_CL_NUM, 0);

		/* setup LCFG0 for node 1; initially node 1 = node 3 */
		AW(rt_lcfg) = NATIVE_GET_SICREG(rt_lcfg0, E2K_MAX_CL_NUM, 3);
		/* open all links for node 3 */
		rt_lcfg.vp = 1;
		rt_lcfg.vb = 0;
		rt_lcfg.vio = 0;
		/* setting node cluster to 0 */
		E2K_RT_LCFG_cln(rt_lcfg) = 0;
		/* setting node number 3 to 1 */
		rt_lcfg.pln = 1;
		NATIVE_SET_SICREG(rt_lcfg0, AW(rt_lcfg), E2K_MAX_CL_NUM, 3);

/* setup LCFGj for node 1;*/

	/* change parameters for BSP (due to new params for node 1: cln = 0| pln = 1) */
	AW(rt_lcfg) = NATIVE_GET_SICREG(rt_lcfg0, E2K_MAX_CL_NUM, 0);
	E2K_RT_LCFG_cln(rt_lcfg) = 0;
	NATIVE_SET_SICREG(rt_lcfg0, AW(rt_lcfg), E2K_MAX_CL_NUM, 0);
	/* change parameters for link CPU 0 -> CPU 1 (due to new params for node 1: pln = 1) */
	AW(rt_lcfg) = NATIVE_GET_SICREG(rt_lcfg1, 0, 0);
	rt_lcfg.pln = 1;
	NATIVE_SET_SICREG(rt_lcfg1, AW(rt_lcfg), 0, 0);
		/****************************/
	/*	cpu 1 -> cpu 2	*/
	rt_lcfg_no = (ipcc_v7) ? SIC_rt_lcfg2 : SIC_rt_lcfg1;
	if (ip_links & 0x2){ // 010 - Node 2 is present
		/**** setup LCFG CPU 1 -> CPU 2 params ****/
		AW(rt_lcfg) = native_get_sicreg(rt_lcfg_no, 0, 1);
		/* open all links for node 1 */
		rt_lcfg.vp = 1;
		rt_lcfg.vb = 0;
		rt_lcfg.vio = 0;
		/* setting link CPU 1 -> CPU 2 */
		rt_lcfg.pln = 2;
		native_set_sicreg(rt_lcfg_no, AW(rt_lcfg), 0, 1);
	} else {
		/* close link CPU 1 -> CPU 2 */
		AW(rt_lcfg) = native_get_sicreg(rt_lcfg_no, 0, 1);
		rt_lcfg.vp = 0;
		native_set_sicreg(rt_lcfg_no, AW(rt_lcfg), 0, 1);
	}

	/*	cpu 1 -> cpu 3	*/
	rt_lcfg_no = (ipcc_v7) ? SIC_rt_lcfg3 : SIC_rt_lcfg2;
	if (ip_links & 0x4){ // 100 - Node 3 is present
		/**** setup LCFG CPU 1 -> CPU 3 params ****/
		AW(rt_lcfg) = native_get_sicreg(rt_lcfg_no, 0, 1);
		/* open all links for node 1 */
		rt_lcfg.vp = 1;
		rt_lcfg.vb = 0;
		rt_lcfg.vio = 0;
		/* setiing link CPU 1 -> CPU 3 */
		rt_lcfg.pln = 3;
		native_set_sicreg(rt_lcfg_no, AW(rt_lcfg), 0, 1);
	} else {
		/* close link CPU 1 -> CPU 3 */
		AW(rt_lcfg) = native_get_sicreg(rt_lcfg_no, 0, 1);
		rt_lcfg.vp = 0;
		native_set_sicreg(rt_lcfg_no, AW(rt_lcfg), 0, 1);
	}

	/**** setup LCFG CPU 1 -> CPU 0 params ****/
	/*	cpu 1 -> cpu 0	*/
	rt_lcfg_no = (ipcc_v7) ? SIC_rt_lcfg1 : SIC_rt_lcfg3;
	AW(rt_lcfg) = native_get_sicreg(rt_lcfg_no, 0, 1);
	/* open all links for node 1 */
	rt_lcfg.vp = 1;
	rt_lcfg.vb = 1;
	rt_lcfg.vio = 1;
	/* setiing link CPU 1 -> CPU 0 */
	rt_lcfg.pln = 0;
	native_set_sicreg(rt_lcfg_no, AW(rt_lcfg), 0, 1);

	/*****************************/
	/*#####################################################*/
	/* configure own link CPU 1 to own ioapic space */
	/* configure link CPU 1 to pcim space through CPU 0 */
	/* configure link CPU 1 to mlo space through CPU 0 */
	rt_mlo_no = (ipcc_v7) ? SIC_rt_mlo1 : SIC_rt_mlo3;
	AW(rt_mlo) = NATIVE_GET_SICREG(rt_mlo0, 0, 0);
	native_set_sicreg(rt_mlo_no, AW(rt_mlo), 0, 1);
	/* May be the same for mhi ????????? */
	/*#####################################################*/

	/* Restore previous values for BSP */
	AW(rt_lcfg) = NATIVE_GET_SICREG(rt_lcfg0, 0, 0);
	E2K_RT_LCFG_cln(rt_lcfg) = E2K_MAX_CL_NUM;
	NATIVE_SET_SICREG(rt_lcfg0, AW(rt_lcfg), 0, 0);
	/* Close link CPU 0 -> CPU 1 */
	AW(rt_lcfg) = NATIVE_GET_SICREG(rt_lcfg1, E2K_MAX_CL_NUM, 0);
	rt_lcfg.vp = 0;
	rt_lcfg.vb = 0;
	rt_lcfg.vio = 0;
	NATIVE_SET_SICREG(rt_lcfg1, AW(rt_lcfg), E2K_MAX_CL_NUM, 0);
/*****************************************************************************/
}
if (ip_links & 0x2){ // 010 - Node 2 is present
/***********************  CONFIGURE NODE 2  ***********************************/
	__set_bit(2, phys_node_pres_map);

	/* Open link CPU 0 -> CPU 2 */
	AW(rt_lcfg) = NATIVE_GET_SICREG(rt_lcfg2, E2K_MAX_CL_NUM, 0);
	rt_lcfg.vp = 1;
	rt_lcfg.vb = 0;
	rt_lcfg.vio = 0;
	NATIVE_SET_SICREG(rt_lcfg2, AW(rt_lcfg), E2K_MAX_CL_NUM, 0);

		/* setup LCFG0 for node 2; initially node 2 = node 3 */
		AW(rt_lcfg) = NATIVE_GET_SICREG(rt_lcfg0, E2K_MAX_CL_NUM, 3);
		/* open all links for node 2 */
		rt_lcfg.vp = 1;
		rt_lcfg.vb = 0;
		rt_lcfg.vio = 0;
		/* setting node cluster to 0 */
		E2K_RT_LCFG_cln(rt_lcfg) = 0;
		/* setting node number 3 to 2 */
		rt_lcfg.pln = 2;
		NATIVE_SET_SICREG(rt_lcfg0, AW(rt_lcfg),
				E2K_MAX_CL_NUM, 3);

/* setup LCFGj for node 2 */

	/* change parameters for BSP (due to new params for node 2: cln = 0| pln = 2) */
	AW(rt_lcfg) = NATIVE_GET_SICREG(rt_lcfg0, E2K_MAX_CL_NUM, 0);
	E2K_RT_LCFG_cln(rt_lcfg) = 0;
	NATIVE_SET_SICREG(rt_lcfg0, AW(rt_lcfg), E2K_MAX_CL_NUM, 0);
	/* change parameters for link CPU 0 -> CPU 2 (due to new params for node 2: pln = 2) */
	AW(rt_lcfg) = NATIVE_GET_SICREG(rt_lcfg2, 0, 0);
	rt_lcfg.pln = 2;
	NATIVE_SET_SICREG(rt_lcfg2, AW(rt_lcfg), 0, 0);
		/****************************/

	/*	cpu 2 -> cpu 3	*/
	rt_lcfg_no = (ipcc_v7) ? SIC_rt_lcfg3 : SIC_rt_lcfg1;
	if (ip_links & 0x4){ // 100 - Node 3 is present
		/**** setup LCFG1 params ****/
		AW(rt_lcfg) = native_get_sicreg(rt_lcfg_no, 0, 2);
		/* open all links for node 2 */
		rt_lcfg.vp = 1;
		rt_lcfg.vb = 0;
		rt_lcfg.vio = 0;
		/* setting link CPU 2 -> CPU 3 */
		rt_lcfg.pln = 3;
		native_set_sicreg(rt_lcfg_no, AW(rt_lcfg), 0, 2);
	} else {
		/* close link CPU 2 -> CPU 3 */
		AW(rt_lcfg) = native_get_sicreg(rt_lcfg_no, 0, 2);
		rt_lcfg.vp = 0;
		native_set_sicreg(rt_lcfg_no, AW(rt_lcfg), 0, 2);
	}

	/**** setup LCFG2 params ****/
	/*	cpu 2 -> cpu 0	*/
	rt_lcfg_no = (ipcc_v7) ? SIC_rt_lcfg1 : SIC_rt_lcfg2;
	AW(rt_lcfg) = native_get_sicreg(rt_lcfg_no, 0, 2);
	/* open all links for node 1 */
	rt_lcfg.vp = 1;
	rt_lcfg.vb = 1;
	rt_lcfg.vio = 1;
	/* setiing link CPU 2 -> CPU 0 */
	rt_lcfg.pln = 0;
	native_set_sicreg(rt_lcfg_no, AW(rt_lcfg), 0, 2);
	/*#####################################################*/
	/* configure link CPU 2 to mlo space through CPU 0 */
	rt_mlo_no = (ipcc_v7) ? SIC_rt_mlo1 : SIC_rt_mlo2;
	AW(rt_mlo) = NATIVE_GET_SICREG(rt_mlo0, 0, 0);
	native_set_sicreg(rt_mlo_no, AW(rt_mlo), 0, 2);
	/* May be the same for mhi ????????? */
	/*#####################################################*/

	/*	cpu 2 -> cpu 1	*/
	rt_lcfg_no = (ipcc_v7) ? SIC_rt_lcfg2 : SIC_rt_lcfg3;
	if (ip_links & 0x1){ // 001 - Node 1 is present
		/**** setup LCFG3 params ****/
		AW(rt_lcfg) = native_get_sicreg(rt_lcfg_no, 0, 2);
		/* open all links for node 1 */
		rt_lcfg.vp = 1;
		rt_lcfg.vb = 0;
		rt_lcfg.vio = 0;
		/* setiing link CPU 2 -> CPU 1 */
		rt_lcfg.pln = 1;
		native_set_sicreg(rt_lcfg_no, AW(rt_lcfg), 0, 2);
		/*****************************/
	} else {
		/* close link CPU 2 -> CPU 1 */
		AW(rt_lcfg) = native_get_sicreg(rt_lcfg_no, 0, 2);
		rt_lcfg.vp = 0;
		native_set_sicreg(rt_lcfg_no, AW(rt_lcfg), 0, 2);
	}
	/* Restore previous values for BSP */
	AW(rt_lcfg) = NATIVE_GET_SICREG(rt_lcfg0, 0, 0);
	E2K_RT_LCFG_cln(rt_lcfg) = E2K_MAX_CL_NUM;
	NATIVE_SET_SICREG(rt_lcfg0, AW(rt_lcfg), 0, 0);
	/* Close link CPU 0 -> CPU 2 */
	AW(rt_lcfg) = NATIVE_GET_SICREG(rt_lcfg2, E2K_MAX_CL_NUM, 0);
	rt_lcfg.vp = 0;
	rt_lcfg.vb = 0;
	rt_lcfg.vio = 0;
	NATIVE_SET_SICREG(rt_lcfg2, AW(rt_lcfg), E2K_MAX_CL_NUM, 0);
/*****************************************************************************/
}
if (ip_links & 0x4){ // 100 - Node 3 is present
/***********************  CONFIGURE NODE 3  ***********************************/
	__set_bit(3, phys_node_pres_map);

	/* Open link CPU 0 -> CPU 3 */
	AW(rt_lcfg) = NATIVE_GET_SICREG(rt_lcfg3, E2K_MAX_CL_NUM, 0);
	rt_lcfg.vp = 1;
	rt_lcfg.vb = 0;
	rt_lcfg.vio = 0;
	NATIVE_SET_SICREG(rt_lcfg3, AW(rt_lcfg), E2K_MAX_CL_NUM, 0);

		/* setup LCFG0 for node 3 */
		AW(rt_lcfg) =
			NATIVE_GET_SICREG(rt_lcfg0, E2K_MAX_CL_NUM, 3);
		/* open all links for node 2 */
		rt_lcfg.vp = 1;
		rt_lcfg.vb = 0;
		rt_lcfg.vio = 0;
		/* setting node cluster to 0 */
		E2K_RT_LCFG_cln(rt_lcfg) = 0;
		NATIVE_SET_SICREG(rt_lcfg0, AW(rt_lcfg),
				E2K_MAX_CL_NUM, 3);

/* setup LCFGj for node 3 */

	/* change parameters for BSP (due to new params for node 3: cln = 0| pln = 3) */
	AW(rt_lcfg) = NATIVE_GET_SICREG(rt_lcfg0, E2K_MAX_CL_NUM, 0);
	E2K_RT_LCFG_cln(rt_lcfg) = 0;
	NATIVE_SET_SICREG(rt_lcfg0, AW(rt_lcfg), E2K_MAX_CL_NUM, 0);
	/* change parameters for link CPU 0 -> CPU 3 (due to new params for node 3: pln = 3) */
	AW(rt_lcfg) = NATIVE_GET_SICREG(rt_lcfg3, 0, 0);
	rt_lcfg.pln = 3;
	NATIVE_SET_SICREG(rt_lcfg3, AW(rt_lcfg), 0, 0);
		/****************************/

	/**** setup LCFG1 params ****/
	/*	cpu 3 -> cpu 0	*/
	rt_lcfg_no = (ipcc_v7) ? SIC_rt_lcfg1 : SIC_rt_lcfg1;
	AW(rt_lcfg) = native_get_sicreg(rt_lcfg_no, 0, 3);
	/* open all links for node 3 */
	rt_lcfg.vp = 1;
	rt_lcfg.vb = 1;
	rt_lcfg.vio = 1;
	/* setting link CPU 3 -> CPU 0 */
	rt_lcfg.pln = 0;
	native_set_sicreg(rt_lcfg_no, AW(rt_lcfg), 0, 3);
	/*#####################################################*/
	/* configure link CPU 3 to mlo space through CPU 0 */
	rt_mlo_no = (ipcc_v7) ? SIC_rt_mlo1 : SIC_rt_mlo1;
	AW(rt_mlo) = NATIVE_GET_SICREG(rt_mlo0, 0, 0);
	native_set_sicreg(rt_mlo_no, AW(rt_mlo), 0, 3);
	/* May be the same for mhi ????????? */
	/*#####################################################*/

	/*	cpu 3 -> cpu 1	*/
	rt_lcfg_no = (ipcc_v7) ? SIC_rt_lcfg2 : SIC_rt_lcfg2;
	if (ip_links & 0x1){ // 001 - Node 1 is present
		/**** setup LCFG2 params ****/
		AW(rt_lcfg) = native_get_sicreg(rt_lcfg_no, 0, 3);
		/* open all links for node 3 */
		rt_lcfg.vp = 1;
		rt_lcfg.vb = 0;
		rt_lcfg.vio = 0;
		/* setiing link CPU 3 -> CPU 1 */
		rt_lcfg.pln = 1;
		native_set_sicreg(rt_lcfg_no, AW(rt_lcfg), 0, 3);
	} else {
		/* close link CPU 3 -> CPU 1 */
		AW(rt_lcfg) = native_get_sicreg(rt_lcfg_no, 0, 3);
		rt_lcfg.vp = 0;
		native_set_sicreg(rt_lcfg_no, AW(rt_lcfg), 0, 3);
	}

	/*	cpu 3 -> cpu 2	*/
	rt_lcfg_no = (ipcc_v7) ? SIC_rt_lcfg3 : SIC_rt_lcfg3;
	if (ip_links & 0x2){ // 010 - Node 2 is present
		/**** setup LCFG3 params ****/
		AW(rt_lcfg) = native_get_sicreg(rt_lcfg_no, 0, 3);
		/* open all links for node 3 */
		rt_lcfg.vp = 1;
		rt_lcfg.vb = 0;
		rt_lcfg.vio = 0;
		/* setiing link CPU 3 -> CPU 2 */
		rt_lcfg.pln = 2;
		native_set_sicreg(rt_lcfg_no, AW(rt_lcfg), 0, 3);
		/*****************************/
	} else {
		/* close link CPU 3 -> CPU 2 */
		AW(rt_lcfg) = native_get_sicreg(rt_lcfg_no, 0, 3);
		rt_lcfg.vp = 0;
		native_set_sicreg(rt_lcfg_no, AW(rt_lcfg), 0, 3);
	}
/*******************************************************************************/
}
if (!(ip_links & 0x4)){ // 100 - Node 3 is not present
	/* change parameters for BSP (cln = 0| pln = 0) */
	AW(rt_lcfg) = NATIVE_GET_SICREG(rt_lcfg0, E2K_MAX_CL_NUM, 0);
	E2K_RT_LCFG_cln(rt_lcfg) = 0;
	NATIVE_SET_SICREG(rt_lcfg0, AW(rt_lcfg), E2K_MAX_CL_NUM, 0);
}

	/* Open all links (cfg1 and cfg3) BSP */
if (ip_links & 0x1){ // 001 - Node 1 is present
	/* Open link CPU 0 -> CPU 1 */
	AW(rt_lcfg) = NATIVE_GET_SICREG(rt_lcfg1, 0, 0);
	rt_lcfg.vp = 1;
	rt_lcfg.vb = 0;
	rt_lcfg.vio = 0;
	NATIVE_SET_SICREG(rt_lcfg1, AW(rt_lcfg), 0, 0);
}
if (ip_links & 0x2){ // 010 - Node 2 is present
	/* Open link CPU 0 -> CPU 2 */
	AW(rt_lcfg) = NATIVE_GET_SICREG(rt_lcfg2, 0, 0);
	rt_lcfg.vp = 1;
	rt_lcfg.vb = 0;
	rt_lcfg.vio = 0;
	NATIVE_SET_SICREG(rt_lcfg2, AW(rt_lcfg), 0, 0);
}
/*****************************************************************************/
	rom_printk("NODE 0:		rt_lcfg0	rt_lcfg1	rt_lcfg2	rt_lcfg3\n"
		   "		0x%x		0x%x		0x%x		0x%x\n"
		   "		st_p	0x%x\n",
				NATIVE_GET_SICREG(rt_lcfg0, 0, 0), NATIVE_GET_SICREG(rt_lcfg1, 0, 0),
				NATIVE_GET_SICREG(rt_lcfg2, 0, 0),	NATIVE_GET_SICREG(rt_lcfg3, 0, 0),
				NATIVE_GET_SICREG(st_p, 0, 0));
if (ip_links & 0x1){ // 001 - Node 1 is present
	rom_printk("NODE 1:		rt_lcfg0	rt_lcfg1	rt_lcfg2	rt_lcfg3\n"
		   "		0x%x		0x%x		0x%x		0x%x\n"
		   "		st_p	0x%x\n",
				NATIVE_GET_SICREG(rt_lcfg0, 0, 1), NATIVE_GET_SICREG(rt_lcfg1, 0, 1),
				NATIVE_GET_SICREG(rt_lcfg2, 0, 1),	NATIVE_GET_SICREG(rt_lcfg3, 0, 1),
				NATIVE_GET_SICREG(st_p, 0, 1));
}
if (ip_links & 0x2){ // 020 - Node 2 is present
	rom_printk("NODE 2:		rt_lcfg0	rt_lcfg1	rt_lcfg2	rt_lcfg3\n"
		   "		0x%x		0x%x		0x%x		0x%x\n"
		   "		st_p	0x%x\n",
				NATIVE_GET_SICREG(rt_lcfg0, 0, 2), NATIVE_GET_SICREG(rt_lcfg1, 0, 2),
				NATIVE_GET_SICREG(rt_lcfg2, 0, 2),	NATIVE_GET_SICREG(rt_lcfg3, 0, 2),
				NATIVE_GET_SICREG(st_p, 0, 2));
}
if (ip_links & 0x4){ // 100 - Node 3 is present
	rom_printk("NODE 3:		rt_lcfg0	rt_lcfg1	rt_lcfg2	rt_lcfg3\n"
		   "		0x%x		0x%x		0x%x		0x%x\n"
		   "		st_p	0x%x\n",
				NATIVE_GET_SICREG(rt_lcfg0, 0, 3), NATIVE_GET_SICREG(rt_lcfg1, 0, 3),
				NATIVE_GET_SICREG(rt_lcfg2, 0, 3),	NATIVE_GET_SICREG(rt_lcfg3, 0, 3),
				NATIVE_GET_SICREG(st_p, 0, 3));
}
}

/* link_nr[from_node][to_node] -> link number for SIC_rt_m{lo/hi}_#link */
static const int link_nr_v6[4][4] = {
	{ 0, 1, 2, 3 },
	{ 3, 0, 1, 2 },
	{ 2, 3, 0, 1 },
	{ 1, 2, 3, 0 },
};
static const int link_nr_v7[4][4] = {
	{ 0, 1, 2, 3 },
	{ 1, 0, 2, 3 },
	{ 1, 2, 0, 3 },
	{ 1, 2, 3, 0 },
};

static inline int get_link_nr(int from_node, int to_node)
{
	return (ipcc_v7) ? link_nr_v7[from_node][to_node]
			 : link_nr_v6[from_node][to_node];
}

static void set_memory_filters_node(int node, u64 *memory_start, u64 *hi_memory_start)
{
	if (!_test_bit(node, phys_node_pres_map))
		return;

	/*
	 * Setup memory routers of `node` to access own memory
	 */

	/*
	 * Setup memory routers of NODE #0 to probe memory of `node`
	 */
	int link_nr = get_link_nr(0, node);
	u64 size_real = probe_memory(boot_info, link_nr, 0, node, *hi_memory_start);

	/* Configure MLO of `node` */
	u64 lo_memory_start = get_lo_memory_start(node);
	u64 size_lo = (size_real > 0) ? min(get_lo_memory_size(node), size_real) : 0;
	e2k_rt_mlo_t rt_mlo = {
		.bgn = lo_memory_start / E2K_SIC_SIZE_RT_MLO,
		.end = (lo_memory_start + size_lo - 1) / E2K_SIC_SIZE_RT_MLO,
	};
	native_set_sicreg(SIC_rt_mlo0, AW(rt_mlo), 0, node);
	rom_printk("NODE %d low memory router set rt_mlo0 = 0x%x\n", node, AW(rt_mlo));

	if (size_lo > 0) {
		add_memory_region(boot_info, node, lo_memory_start, size_lo);
	} else {
		rom_printk("NODE %d has not own memory\n", node);
	}

#ifdef CONFIG_SMP
	/*
	 * Setup memory routers of other nodes to access memory of `node`
	 */
	for (int other_node = 0; other_node < MAX_NUMNODES; other_node++) {
		if (!_test_bit(other_node, phys_node_pres_map) || node == other_node)
			continue;

		int link_nr = get_link_nr(other_node, node);
		native_set_sicreg(SIC_rt_mlo_nr(link_nr), AW(rt_mlo), 0, other_node);
		DebugMRT("set_memory_filters: NODE %d set rt_mlo_%d to 0x%x to access memory of NODE %d\n",
			other_node, link_nr, AW(rt_mlo), node);
	}
#endif /* CONFIG_SMP */

	*memory_start = round_up(*memory_start + size_lo, E2K_SIC_MIN_MEMORY_BANK);

	u64 hole_size_lo = round_up(size_lo, E2K_SIC_SIZE_RT_MLO);

	if (size_real > hole_size_lo) {
		u64 size_hi = size_real - hole_size_lo;
		u64 hi_high_memory_size, hi_high_memory_start;

		/* Setup high memory filter */
		*hi_memory_start = get_hi_memory_start(node);
		e2k_rt_mhi_t rt_mhi = {
			.bgn = *hi_memory_start / E2K_SIC_SIZE_RT_MHI,
			.end = (*hi_memory_start + hole_size_lo + size_hi - 1) /
					E2K_SIC_SIZE_RT_MHI,
		};
		native_set_sicreg(SIC_rt_mhi0, AW(rt_mhi), 0, node);
		rom_printk("NODE %d high memory router set from 0x%X to 0x%X\n",
			node, *hi_memory_start, *hi_memory_start + hole_size_lo + size_hi - 1);

		u64 lo_high_memory_start = *hi_memory_start;
		u64 lo_high_memory_size = lo_memory_start;
		if (lo_high_memory_size < size_hi) {
			hi_high_memory_size = size_hi - lo_high_memory_size;
			hi_high_memory_start = *hi_memory_start +
					lo_memory_start + hole_size_lo;

			add_memory_region(boot_info, node,
					hi_high_memory_start, hi_high_memory_size);
			rom_printk("NODE %d high memory hi region set from 0x%X to 0x%X\n",
				node, hi_high_memory_start,
				hi_high_memory_start + hi_high_memory_size);
		} else {
			lo_high_memory_size = size_hi;
			hi_high_memory_size = 0;
		}

		if (lo_high_memory_size != 0) {
			add_memory_region(boot_info, node,
					lo_high_memory_start, lo_high_memory_size);
			rom_printk("NODE %d high memory lo region set from 0x%X to 0x%X\n",
				node, lo_high_memory_start,
				lo_high_memory_start + lo_high_memory_size);
		}

#ifdef CONFIG_SMP
		/*
		 * Setup memory routers of other nodes to access _hi_ memory of `node`
		 */
		for (int other_node = 0; other_node < MAX_NUMNODES; other_node++) {
			if (!_test_bit(other_node, phys_node_pres_map) || node == other_node)
				continue;

			int link_nr = get_link_nr(other_node, node);
			native_set_sicreg(SIC_rt_mhi_nr(link_nr), AW(rt_mhi), 0, other_node);
			DebugMRT("set_memory_filters: NODE %d set rt_mhi_%d to 0x%x to access memory of NODE %d\n",
				other_node, link_nr, AW(rt_mhi), node);
		}
#endif /* CONFIG_SMP */

		*hi_memory_start = round_up(*hi_memory_start + hole_size_lo + size_hi,
					    E2K_SIC_MIN_MEMORY_BANK);
	}

	add_memory_region(boot_info, node, 0, 0);
}

void set_memory_filters(boot_info_t *boot_info)
{
	u64 memory_start = 0;
	u64 hi_memory_start = HI_MEMORY_START;

	for (int node = 0; node < 4; node++)
		set_memory_filters_node(node, &memory_start, &hi_memory_start);
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

	__set_bit(0, phys_node_pres_map);

	pci_cmd = __boot_readw_hb_reg(PCI_COMMAND);
	DebugRT("configure_routing_regs: host bridge PCICMD 0x%04x\n",
		pci_cmd);
	pci_cmd |= PCI_COMMAND_MEMORY;
	__boot_writew_hb_reg(pci_cmd, PCI_COMMAND);
	rom_printk("Host Bridge PCICMD set to 0x%04x\n", pci_cmd);
}
void set_memory_filters(boot_info_t *boot_info)
{
	u64 hi_memory_start = HI_MEMORY_START;
	u64 memory_start = 0;	/* memory starts from 0 and can be on BSP */
	u64 lo_mem_end;
	u32 tom_lo;
	int vram_size = EG_VRAM_MBYTES_SIZE;
#ifndef	CONFIG_VRAM_DISABLE
	u32 eg_cfg;
#endif	/* ! CONFIG_VRAM_DISABLE */
	long size_hi = 0;
	u64 hi_mem_end;
	u64 tom_hi;
	u64 remapbase;

	u64 size_real = probe_memory(boot_info, 0, 0, 0, hi_memory_start);

	/* Configure TOM & TOM2 & REMAPBASE */
	tom_lo = __boot_readl_hb_reg(HB_PCI_TOM);
	DebugMRT("set_memory_filters: TOM (low memory top) = 0x%x\n", tom_lo);

	long size_lo = size_real - vram_size;
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
}
#endif	/* CONFIG_E2K_FULL_SIC */

#ifdef	CONFIG_SMP
#ifdef	CONFIG_E2K_FULL_SIC
int inline e2k_startup_core(e2k_rt_lcfg_t rt_lcfg, int core)
{
	e2k_st_core_t st_core = {{ 0 }};
	int cln = E2K_RT_LCFG_cln(rt_lcfg);
	int pln = rt_lcfg.pln;

	AW(st_core) = NATIVE_GET_SICREG(st_core(core), cln, pln);
	if (!st_core.val)
		return 0;

	rom_printk("Start up detected core #%d in cluster %d node %d\n",
		core, cln, pln);
	st_core.wait_init = 0;
	NATIVE_SET_SICREG(st_core(core), AW(st_core), cln, pln);
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
#endif	/* CONFIG_SMP */

#if	defined(CONFIG_E2K_FULL_SIC)
#ifdef	CONFIG_RT_PCIIO_V7
static void set_rt_pciio_router(int node, int link, int to_node, int rt_pciio_reg,
				unsigned long start, unsigned long end)
{
	e2k_rt_pciio_v7_t rt_pciio;

	rt_pciio.word = 0;
	rt_pciio.bgn = (start) >> E2K_SIC_ALIGN_RT_PCIIO;
	rt_pciio.end = (end - 1) >> E2K_SIC_ALIGN_RT_PCIIO;
	switch (rt_pciio_reg) {
	case SIC_rt_pciio0:
	case SIC_rt_pciio1:
	case SIC_rt_pciio2:
	case SIC_rt_pciio3:
		early_sic_write_node_iolink_nbsr_reg(node, link, rt_pciio_reg,
						     AW(rt_pciio));
		break;
	default:
		rom_printk("set_rt_pciio_router() invalid pciio router reg 0x%X\n",
			   rt_pciio_reg);
		return;
	}
	if (node == to_node) {
		DebugIORT("NODE #%d IO link #%d: PCI-IO-%d router set from 0x%X to 0x%X\n",
			node, link, 0, start, end);
	} else {
		DebugIORT("NODE #%d IO link #%d: router to PCI-IO set from 0x%X to 0x%X\n",
			node, link, start, end);
	}
}
static void set_rt_pciio_xmu_router(int node, int link, int to_node, int rt_pciio_xmu_reg,
				    unsigned long start, unsigned long end)
{
	e2k_rt_pciio_v7_t rt_pciio;
	char rt_pciio_k;

	rt_pciio.word = 0;
	rt_pciio.bgn = (start) >> E2K_SIC_ALIGN_RT_PCIIO;
	rt_pciio.end = (end - 1) >> E2K_SIC_ALIGN_RT_PCIIO;
	switch (rt_pciio_xmu_reg) {
	case SIC_rt_pciio0_xmu_l:
		early_sic_write_node_iolink_nbsr_reg(node, link, SIC_rt_pciio0_xmu_l,
						     AW(rt_pciio));
		rt_pciio_k = 'l';
		break;
	case SIC_rt_pciio0_xmu_a:
		early_sic_write_node_iolink_nbsr_reg(node, link, SIC_rt_pciio0_xmu_a,
						     AW(rt_pciio));
		rt_pciio_k = 'a';
		break;
	case SIC_rt_pciio0_xmu_b:
		early_sic_write_node_iolink_nbsr_reg(node, link, SIC_rt_pciio0_xmu_b,
						     AW(rt_pciio));
		rt_pciio_k = 'b';
		break;
	case SIC_rt_pciio0_xmu_c:
		early_sic_write_node_iolink_nbsr_reg(node, link, SIC_rt_pciio0_xmu_c,
						     AW(rt_pciio));
		rt_pciio_k = 'c';
		break;
	case SIC_rt_pciio0_xmu_d:
		early_sic_write_node_iolink_nbsr_reg(node, link, SIC_rt_pciio0_xmu_d,
						     AW(rt_pciio));
		rt_pciio_k = 'd';
		break;
	default:
		rom_printk("%s():() invalid pciio_xmu_k router reg 0x%X\n",
			   __func__, rt_pciio_xmu_reg);
		return;
	}
	if (node == to_node) {
		DebugIORT("NODE #%d IO link #%d: PCI-IO_XMU_%c router set from 0x%X to 0x%X\n",
			node, link, rt_pciio_k, start, end);
	} else {
		DebugIORT("NODE #%d IO link #%d: router to PCI-IO_XMU_%c set from 0x%X to 0x%X\n",
			node, link, rt_pciio_k, start, end);
	}
}
#else	/* !CONFIG_RT_PCIIO_V7 */
static void set_rt_pciio_router(int node, int link, int to_node, int rt_pciio_reg,
				unsigned long start, unsigned long end)
{
	e2k_rt_pciio_t rt_pciio;
	int rt_pciio_no;

	rt_pciio.word = 0;
	rt_pciio.bgn = (start) >> E2K_SIC_ALIGN_RT_PCIIO;
	rt_pciio.end = (end - 1) >> E2K_SIC_ALIGN_RT_PCIIO;
	switch (rt_pciio_reg) {
	case SIC_rt_pciio0:
		early_sic_write_node_iolink_nbsr_reg(node, link, SIC_rt_pciio0,
						     AW(rt_pciio));
		rt_pciio_no = 0;
		break;
	case SIC_rt_pciio1:
		early_sic_write_node_iolink_nbsr_reg(node, link, SIC_rt_pciio1,
						     AW(rt_pciio));
		rt_pciio_no = 1;
		break;
	case SIC_rt_pciio2:
		early_sic_write_node_iolink_nbsr_reg(node, link, SIC_rt_pciio2,
						     AW(rt_pciio));
		rt_pciio_no = 2;
		break;
	case SIC_rt_pciio3:
		early_sic_write_node_iolink_nbsr_reg(node, link, SIC_rt_pciio3,
						     AW(rt_pciio));
		rt_pciio_no = 3;
		break;
	default:
		rom_printk("set_rt_pciio_router() invalid pciio router reg 0x%X\n",
			   rt_pciio_reg);
		return;
	}
	if (node == to_node) {
		DebugIORT("NODE #%d IO link #%d: PCI-IO-%d router set "
			"from 0x%X to 0x%X\n",
			node, link, 0, start, end);
	} else {
		DebugIORT("NODE #%d IO link #%d: router to PCI-IO-%d set "
			"from 0x%X to 0x%X\n",
			node, link, rt_pciio_no, start, end);
	}
}
#endif	/* CONFIG_RT_PCIIO_V7 */

static void configure_node_io_routing(int node, int link)
{
#if HAS_IOAPIC_LINKS
       e2k_rt_ioapic_t  rt_ioapic = { 0 };
       int rt_ioapic0_reg;
       int rt_ioapic1_reg;
       int rt_ioapic2_reg;
       int rt_ioapic3_reg;
#endif
       e2k_rt_pcim_t    rt_pcim;
       unsigned long pcim_bgn;
       unsigned long pcim_end;
       int rt_pcim0_reg;
       int rt_pcim1_reg;
       int rt_pcim2_reg;
       int rt_pcim3_reg;
       int rt_pciio0_reg;
       int rt_pciio1_reg;
       int rt_pciio2_reg;
       int rt_pciio3_reg;
       int domain;
#ifdef	CONFIG_E2K_SIC_V7
	int reg_xmu;
#endif	/* CONFIG_E2K_SIC_V7 */

	AW(rt_pcim) = 0;

	if (node == 0) {
#if HAS_IOAPIC_LINKS
		rt_ioapic0_reg = SIC_rt_ioapic0;
		rt_ioapic1_reg = SIC_rt_ioapic1;
		rt_ioapic2_reg = SIC_rt_ioapic2;
		rt_ioapic3_reg = SIC_rt_ioapic3;
#endif
		rt_pcim0_reg = SIC_rt_pcim0;
		rt_pcim1_reg = SIC_rt_pcim1;
		rt_pcim2_reg = SIC_rt_pcim2;
		rt_pcim3_reg = SIC_rt_pcim3;
		rt_pciio0_reg = SIC_rt_pciio0;
		rt_pciio1_reg = SIC_rt_pciio1;
		rt_pciio2_reg = SIC_rt_pciio2;
		rt_pciio3_reg = SIC_rt_pciio3;
	} else if (node == 1) {
#if HAS_IOAPIC_LINKS
# ifdef	CONFIG_IPCC4
		rt_ioapic0_reg = SIC_rt_ioapic1;
		rt_ioapic1_reg = SIC_rt_ioapic0;
		rt_ioapic2_reg = SIC_rt_ioapic2;
		rt_ioapic3_reg = SIC_rt_ioapic3;
# else	/* !CONFIG_IPCC4 */
		rt_ioapic0_reg = SIC_rt_ioapic3;
		rt_ioapic1_reg = SIC_rt_ioapic0;
		rt_ioapic2_reg = SIC_rt_ioapic1;
		rt_ioapic3_reg = SIC_rt_ioapic2;
# endif	/* CONFIG_IPCC4 */
#endif	/* HAS_IOAPIC_LINKS */

#ifdef	CONFIG_IPCC4
		rt_pcim0_reg = SIC_rt_pcim1;
		rt_pcim1_reg = SIC_rt_pcim0;
		rt_pcim2_reg = SIC_rt_pcim2;
		rt_pcim3_reg = SIC_rt_pcim3;
		rt_pciio0_reg = SIC_rt_pciio1;
		rt_pciio1_reg = SIC_rt_pciio0;
		rt_pciio2_reg = SIC_rt_pciio2;
		rt_pciio3_reg = SIC_rt_pciio3;
#else	/* !CONFIG_IPCC4 */
		rt_pcim0_reg = SIC_rt_pcim3;
		rt_pcim1_reg = SIC_rt_pcim0;
		rt_pcim2_reg = SIC_rt_pcim1;
		rt_pcim3_reg = SIC_rt_pcim2;
		rt_pciio0_reg = SIC_rt_pciio3;
		rt_pciio1_reg = SIC_rt_pciio0;
		rt_pciio2_reg = SIC_rt_pciio1;
		rt_pciio3_reg = SIC_rt_pciio2;
#endif	/* CONFIG_IPCC4 */
	} else if (node == 2) {
#if HAS_IOAPIC_LINKS
# ifdef	CONFIG_IPCC4
		rt_ioapic0_reg = SIC_rt_ioapic1;
		rt_ioapic1_reg = SIC_rt_ioapic2;
		rt_ioapic2_reg = SIC_rt_ioapic0;
		rt_ioapic3_reg = SIC_rt_ioapic3;
# else	/* !CONFIG_IPCC4 */
		rt_ioapic0_reg = SIC_rt_ioapic2;
		rt_ioapic1_reg = SIC_rt_ioapic3;
		rt_ioapic2_reg = SIC_rt_ioapic0;
		rt_ioapic3_reg = SIC_rt_ioapic1;
# endif	/* CONFIG_IPCC4 */
#endif	/* HAS_IOAPIC_LINKS */
#ifdef	CONFIG_IPCC4
		rt_pcim0_reg = SIC_rt_pcim1;
		rt_pcim1_reg = SIC_rt_pcim2;
		rt_pcim2_reg = SIC_rt_pcim0;
		rt_pcim3_reg = SIC_rt_pcim3;
		rt_pciio0_reg = SIC_rt_pciio1;
		rt_pciio1_reg = SIC_rt_pciio2;
		rt_pciio2_reg = SIC_rt_pciio0;
		rt_pciio3_reg = SIC_rt_pciio3;
#else	/* !CONFIG_IPCC4 */
		rt_pcim0_reg = SIC_rt_pcim2;
		rt_pcim1_reg = SIC_rt_pcim3;
		rt_pcim2_reg = SIC_rt_pcim0;
		rt_pcim3_reg = SIC_rt_pcim1;
		rt_pciio0_reg = SIC_rt_pciio2;
		rt_pciio1_reg = SIC_rt_pciio3;
		rt_pciio2_reg = SIC_rt_pciio0;
		rt_pciio3_reg = SIC_rt_pciio1;
#endif	/* CONFIG_IPCC4 */
	} else if (node == 3) {
#if HAS_IOAPIC_LINKS
# ifdef	CONFIG_IPCC4
		rt_ioapic0_reg = SIC_rt_ioapic1;
		rt_ioapic1_reg = SIC_rt_ioapic2;
		rt_ioapic2_reg = SIC_rt_ioapic3;
		rt_ioapic3_reg = SIC_rt_ioapic0;
# else	/* !CONFIG_IPCC4 */
		rt_ioapic0_reg = SIC_rt_ioapic1;
		rt_ioapic1_reg = SIC_rt_ioapic2;
		rt_ioapic2_reg = SIC_rt_ioapic3;
		rt_ioapic3_reg = SIC_rt_ioapic0;
# endif	/* CONFIG_IPCC4 */
#endif	/* HAS_IOAPIC_LINKS */
#ifdef	CONFIG_IPCC4
		rt_pcim0_reg = SIC_rt_pcim1;
		rt_pcim1_reg = SIC_rt_pcim2;
		rt_pcim2_reg = SIC_rt_pcim3;
		rt_pcim3_reg = SIC_rt_pcim0;
		rt_pciio0_reg = SIC_rt_pciio1;
		rt_pciio1_reg = SIC_rt_pciio2;
		rt_pciio2_reg = SIC_rt_pciio3;
		rt_pciio3_reg = SIC_rt_pciio0;
#else	/* !CONFIG_IPCC4 */
		rt_pcim0_reg = SIC_rt_pcim1;
		rt_pcim1_reg = SIC_rt_pcim2;
		rt_pcim2_reg = SIC_rt_pcim3;
		rt_pcim3_reg = SIC_rt_pcim0;
		rt_pciio0_reg = SIC_rt_pciio1;
		rt_pciio1_reg = SIC_rt_pciio2;
		rt_pciio2_reg = SIC_rt_pciio3;
		rt_pciio3_reg = SIC_rt_pciio0;
#endif	/* CONFIG_IPCC4 */
	} else {
		rom_printk("configure_node_io_routing() invalid node #%d\n",
			node);
		return;
	}
	domain = node_iohub_to_domain(node, link);

	/* configure own link of the NODE to access to own ioapic space */
#if HAS_IOAPIC_LINKS
	rt_ioapic.bgn = domain;
	early_sic_write_node_iolink_nbsr_reg(node, link, SIC_rt_ioapic0, AW(rt_ioapic));
	DebugIORT("NODE #%d IO link #%d: IO-APIC router configured as domain #%d\n",
		node, link, domain);
#endif
	pcim_bgn = PCI_MEM_DOMAIN_START(domain);
	pcim_end = PCI_MEM_DOMAIN_END(domain);
	rt_pcim.bgn = (pcim_bgn) >> E2K_SIC_ALIGN_RT_PCIM;
	rt_pcim.end = (pcim_end - 1) >> E2K_SIC_ALIGN_RT_PCIM;
	early_sic_write_node_iolink_nbsr_reg(node, link, SIC_rt_pcim0, AW(rt_pcim));
	DebugIORT("NODE #%d IO link #%d: PCI-MM router set from 0x%X "
		"to 0x%X\n",
		node, link, pcim_bgn, pcim_end);
#ifdef	CONFIG_E2K_SIC_V7
	reg_xmu = SIC_rt_pcim0_xmu_l + 4 * domain;
	early_sic_write_node_iolink_nbsr_reg(node, link, reg_xmu, AW(rt_pcim));
	DebugIORT("NODE #%d IO link #%d: PCI-MM-XMU_k router set from 0x%X to 0x%X\n",
		node, link, pcim_bgn, pcim_end);
#endif	/* CONFIG_E2K_SIC_V7 */
	pcim_bgn = PCI_IO_DOMAIN_START(domain);
	pcim_end = PCI_IO_DOMAIN_END(domain);
	set_rt_pciio_router(node, link, node, rt_pciio0_reg, pcim_bgn, pcim_end);
#ifdef	CONFIG_E2K_SIC_V7
	reg_xmu = SIC_rt_pciio0_xmu_l + 4 * domain;
	set_rt_pciio_xmu_router(node, link, node, reg_xmu, pcim_bgn, pcim_end);
#endif	/* CONFIG_E2K_SIC_V7 */

	if (node != 0 && _test_bit(0, phys_node_pres_map)) { /* node #0 is present */
		/* configure link the NODE to access to ioapic space NODE 0 */
		domain = node_iohub_to_domain(0, link);
#if HAS_IOAPIC_LINKS
		rt_ioapic.bgn = domain;
		early_sic_write_node_iolink_nbsr_reg(node, link, rt_ioapic0_reg, AW(rt_ioapic));
		DebugIORT("NODE #%d IO link #%d: router to IO-APIC node #0 set "
			"as domain #%d\n",
			node, link, domain);
#endif
		pcim_bgn = PCI_MEM_DOMAIN_START(domain);
		pcim_end = PCI_MEM_DOMAIN_END(domain);
		rt_pcim.bgn = (pcim_bgn) >> E2K_SIC_ALIGN_RT_PCIM;
		rt_pcim.end = (pcim_end - 1) >> E2K_SIC_ALIGN_RT_PCIM;
		early_sic_write_node_iolink_nbsr_reg(node, link, rt_pcim0_reg, AW(rt_pcim));
		DebugIORT("NODE #%d IO link #%d: router to PCI-MM node #0 set "
			"from 0x%X to 0x%X\n",
			node, link, pcim_bgn, pcim_end);
#ifdef	CONFIG_E2K_SIC_V7
		reg_xmu = SIC_rt_pcim0_xmu_l + 4 * domain;
		early_sic_write_node_iolink_nbsr_reg(node, link, reg_xmu, AW(rt_pcim));
		DebugIORT("NODE #%d IO link #%d: PCI-MM-XMU_k router set from 0x%X to 0x%X\n",
			node, link, pcim_bgn, pcim_end);
#endif	/* CONFIG_E2K_SIC_V7 */

		pcim_bgn = PCI_IO_DOMAIN_START(domain);
		pcim_end = PCI_IO_DOMAIN_END(domain);
		set_rt_pciio_router(node, link, 0, rt_pciio0_reg, pcim_bgn, pcim_end);
#ifdef	CONFIG_E2K_SIC_V7
		reg_xmu = SIC_rt_pciio0_xmu_l + 4 * domain;
		set_rt_pciio_xmu_router(node, link, node, reg_xmu, pcim_bgn, pcim_end);
#endif	/* CONFIG_E2K_SIC_V7 */
	}
	if (node != 1 && _test_bit(1, phys_node_pres_map)) { /* node #1 is present */
		/* configure link the NODE to access to ioapic space NODE 1 */
		domain = node_iohub_to_domain(1, link);
#if HAS_IOAPIC_LINKS
		rt_ioapic.bgn = domain;
		early_sic_write_node_iolink_nbsr_reg(node, link, rt_ioapic1_reg, AW(rt_ioapic));
		DebugIORT("NODE #%d IO link #%d: router to IO-APIC node #1 set "
			"as domain #%d\n",
			node, link, domain);
#endif
		pcim_bgn = PCI_MEM_DOMAIN_START(domain);
		pcim_end = PCI_MEM_DOMAIN_END(domain);
		rt_pcim.bgn = (pcim_bgn) >> E2K_SIC_ALIGN_RT_PCIM;
		rt_pcim.end = (pcim_end - 1) >> E2K_SIC_ALIGN_RT_PCIM;
		early_sic_write_node_iolink_nbsr_reg(node, link, rt_pcim1_reg, AW(rt_pcim));
		DebugIORT("NODE #%d IO link #%d: router to PCI-MM node #1 set "
			"from 0x%X to 0x%X\n",
			node, link, pcim_bgn, pcim_end);
#ifdef	CONFIG_E2K_SIC_V7
		reg_xmu = SIC_rt_pcim0_xmu_l + 4 * domain;
		early_sic_write_node_iolink_nbsr_reg(node, link, reg_xmu, AW(rt_pcim));
		DebugIORT("NODE #%d IO link #%d: PCI-MM-XMU_k router set from 0x%X to 0x%X\n",
			node, link, pcim_bgn, pcim_end);
#endif	/* CONFIG_E2K_SIC_V7 */

		pcim_bgn = PCI_IO_DOMAIN_START(domain);
		pcim_end = PCI_IO_DOMAIN_END(domain);
		set_rt_pciio_router(node, link, 1, rt_pciio1_reg, pcim_bgn, pcim_end);
#ifdef	CONFIG_E2K_SIC_V7
		reg_xmu = SIC_rt_pciio0_xmu_l + 4 * domain;
		set_rt_pciio_xmu_router(node, link, node, reg_xmu, pcim_bgn, pcim_end);
#endif	/* CONFIG_E2K_SIC_V7 */
	}
	if (node != 2 && _test_bit(2, phys_node_pres_map)) { /* node #2 is present */
		/* configure link the NODE to access to ioapic space NODE 2 */
		domain = node_iohub_to_domain(2, link);
#if HAS_IOAPIC_LINKS
		rt_ioapic.bgn = domain;
		early_sic_write_node_iolink_nbsr_reg(node, link, rt_ioapic2_reg, AW(rt_ioapic));
		DebugIORT("NODE #%d IO link #%d: router to IO-APIC node #2 set "
			"as domain #%d\n",
			node, link, domain);
#endif
		pcim_bgn = PCI_MEM_DOMAIN_START(domain);
		pcim_end = PCI_MEM_DOMAIN_END(domain);
		rt_pcim.bgn = (pcim_bgn) >> E2K_SIC_ALIGN_RT_PCIM;
		rt_pcim.end = (pcim_end - 1) >> E2K_SIC_ALIGN_RT_PCIM;
		early_sic_write_node_iolink_nbsr_reg(node, link, rt_pcim2_reg, AW(rt_pcim));
		DebugIORT("NODE #%d IO link #%d: router to PCI-MM node #2 set "
			"from 0x%X to 0x%X\n",
			node, link, pcim_bgn, pcim_end);
#ifdef	CONFIG_E2K_SIC_V7
		reg_xmu = SIC_rt_pcim0_xmu_l + 4 * domain;
		early_sic_write_node_iolink_nbsr_reg(node, link, reg_xmu, AW(rt_pcim));
		DebugIORT("NODE #%d IO link #%d: PCI-MM-XMU_k router set from 0x%X to 0x%X\n",
			node, link, pcim_bgn, pcim_end);
#endif	/* CONFIG_E2K_SIC_V7 */

		pcim_bgn = PCI_IO_DOMAIN_START(domain);
		pcim_end = PCI_IO_DOMAIN_END(domain);
		set_rt_pciio_router(node, link, 2, rt_pciio2_reg, pcim_bgn, pcim_end);
#ifdef	CONFIG_E2K_SIC_V7
		reg_xmu = SIC_rt_pciio0_xmu_l + 4 * domain;
		set_rt_pciio_xmu_router(node, link, node, reg_xmu, pcim_bgn, pcim_end);
#endif	/* CONFIG_E2K_SIC_V7 */
	}
	if (node != 3 && _test_bit(3, phys_node_pres_map)) { /* node #3 is present */
		/* configure link the NODE to access to ioapic space NODE 3 */
		domain = node_iohub_to_domain(3, link);
#if HAS_IOAPIC_LINKS
		rt_ioapic.bgn = domain;
		early_sic_write_node_iolink_nbsr_reg(node, link, rt_ioapic3_reg, AW(rt_ioapic));
		DebugIORT("NODE #%d IO link #%d: router to IO-APIC node #3 set "
			"as domain #%d\n",
			node, link, domain);
#endif
		pcim_bgn = PCI_MEM_DOMAIN_START(domain);
		pcim_end = PCI_MEM_DOMAIN_END(domain);
		rt_pcim.bgn = (pcim_bgn) >> E2K_SIC_ALIGN_RT_PCIM;
		rt_pcim.end = (pcim_end - 1) >> E2K_SIC_ALIGN_RT_PCIM;
		early_sic_write_node_iolink_nbsr_reg(node, link, rt_pcim3_reg, AW(rt_pcim));
		DebugIORT("NODE #%d IO link #%d: router to PCI-MM node #3 set "
			"from 0x%X to 0x%X\n",
			node, link, pcim_bgn, pcim_end);
#ifdef	CONFIG_E2K_SIC_V7
		reg_xmu = SIC_rt_pcim0_xmu_l + 4 * domain;
		early_sic_write_node_iolink_nbsr_reg(node, link, reg_xmu, AW(rt_pcim));
		DebugIORT("NODE #%d IO link #%d: PCI-MM-XMU_k router set from 0x%X to 0x%X\n",
			node, link, pcim_bgn, pcim_end);
#endif	/* CONFIG_E2K_SIC_V7 */

		pcim_bgn = PCI_IO_DOMAIN_START(domain);
		pcim_end = PCI_IO_DOMAIN_END(domain);
		set_rt_pciio_router(node, link, 3, rt_pciio3_reg, pcim_bgn, pcim_end);
#ifdef	CONFIG_E2K_SIC_V7
		reg_xmu = SIC_rt_pciio0_xmu_l + 4 * domain;
		set_rt_pciio_xmu_router(node, link, node, reg_xmu, pcim_bgn, pcim_end);
#endif	/* CONFIG_E2K_SIC_V7 */
	}
}

static void configure_io_routing(void)
{
	int node;
	int link;

	for (node = 0; node < MAX_NUMNODES; node++) {
		if (!_test_bit(node, phys_node_pres_map))
			continue;
		for_each_iolink_of_node(link) {
			configure_node_io_routing(node, link);
		}
	}
}
#elif	defined(CONFIG_E2K_LEGACY_SIC)
#define	configure_io_routing()
#endif	/* CONFIG_E2K_FULL_SIC */

#ifdef	CONFIG_E2K_FULL_SIC
#ifdef	CONFIG_SMP
static int startup_all_cores(e2k_rt_lcfg_t rt_lcfg, int max_cores_num,
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
	e2k_rt_lcfg_t rt_lcfg;
	int rt_lcfg0_reg;
	int rt_lcfg1_reg;
	int rt_lcfg2_reg;
	int rt_lcfg3_reg;
	int iolink_on;
	int link;
	int domain;

	if (node == 0) {
#ifdef	CONFIG_IPCC4
		rt_lcfg0_reg = SIC_rt_lcfg0;
		rt_lcfg1_reg = SIC_rt_lcfg1;
		rt_lcfg2_reg = SIC_rt_lcfg2;
		rt_lcfg3_reg = SIC_rt_lcfg3;
#else	/* !CONFIG_IPCC4 */
		rt_lcfg0_reg = SIC_rt_lcfg0;
		rt_lcfg1_reg = SIC_rt_lcfg1;
		rt_lcfg2_reg = SIC_rt_lcfg2;
		rt_lcfg3_reg = SIC_rt_lcfg3;
#endif	/* CONFIG_IPCC4 */
	} else if (node == 1) {
#ifdef	CONFIG_IPCC4
		rt_lcfg0_reg = SIC_rt_lcfg1;
		rt_lcfg1_reg = SIC_rt_lcfg0;
		rt_lcfg2_reg = SIC_rt_lcfg2;
		rt_lcfg3_reg = SIC_rt_lcfg3;
#else	/* !CONFIG_IPCC4 */
		rt_lcfg0_reg = SIC_rt_lcfg3;
		rt_lcfg1_reg = SIC_rt_lcfg0;
		rt_lcfg2_reg = SIC_rt_lcfg1;
		rt_lcfg3_reg = SIC_rt_lcfg2;
#endif	/* CONFIG_IPCC4 */
	} else if (node == 2) {
#ifdef	CONFIG_IPCC4
		rt_lcfg0_reg = SIC_rt_lcfg1;
		rt_lcfg1_reg = SIC_rt_lcfg2;
		rt_lcfg2_reg = SIC_rt_lcfg0;
		rt_lcfg3_reg = SIC_rt_lcfg3;
#else	/* !CONFIG_IPCC4 */
		rt_lcfg0_reg = SIC_rt_lcfg2;
		rt_lcfg1_reg = SIC_rt_lcfg3;
		rt_lcfg2_reg = SIC_rt_lcfg0;
		rt_lcfg3_reg = SIC_rt_lcfg1;
#endif	/* CONFIG_IPCC4 */
	} else if (node == 3) {
#ifdef	CONFIG_IPCC4
		rt_lcfg0_reg = SIC_rt_lcfg1;
		rt_lcfg1_reg = SIC_rt_lcfg2;
		rt_lcfg2_reg = SIC_rt_lcfg3;
		rt_lcfg3_reg = SIC_rt_lcfg0;
#else	/* !CONFIG_IPCC4 */
		rt_lcfg0_reg = SIC_rt_lcfg1;
		rt_lcfg1_reg = SIC_rt_lcfg2;
		rt_lcfg2_reg = SIC_rt_lcfg3;
		rt_lcfg3_reg = SIC_rt_lcfg0;
#endif	/* CONFIG_IPCC4 */
	} else {
		rom_printk("configure_node_io_link() invalid node #%d\n",
			node);
		return;
	}

       /* configure own link cfg of the NODE to access to own io link */
	AW(rt_lcfg) = early_sic_read_node_nbsr_reg(node,
								SIC_rt_lcfg0);
	iolink_on = 0;
	for_each_iolink_of_node(link) {
	domain = node_iohub_to_domain(node, link);
	if ((online_iohubs_map & (1 << domain)) ||
		(online_rdmas_map & (1 << domain)))
		iolink_on |= 1;
	}
	rt_lcfg.vio = iolink_on;
	early_sic_write_node_nbsr_reg(node, SIC_rt_lcfg0,
						AW(rt_lcfg));

	if (node != 0 && _test_bit(0, phys_node_pres_map)) { /* node #0 is present */
		/* configure link cfg the NODE to access to io link of NODE 0 */
		AW(rt_lcfg) = early_sic_read_node_nbsr_reg(node,
						rt_lcfg0_reg);
		iolink_on = 0;
		for_each_iolink_of_node(link) {
			domain = node_iohub_to_domain(0, link);
			if ((online_iohubs_map & (1 << domain)) ||
					(online_rdmas_map & (1 << domain)))
				iolink_on |= 1;
		}
		rt_lcfg.vio = iolink_on;
		early_sic_write_node_nbsr_reg(node, rt_lcfg0_reg,
						AW(rt_lcfg));
	}
	if (node != 1 && _test_bit(1, phys_node_pres_map)) { /* node #1 is present */
		/* configure link cfg the NODE to access to io link of NODE 1 */
		AW(rt_lcfg) = early_sic_read_node_nbsr_reg(node,
								rt_lcfg1_reg);
		iolink_on = 0;
		for_each_iolink_of_node(link) {
			domain = node_iohub_to_domain(1, link);
			if ((online_iohubs_map & (1 << domain)) ||
					(online_rdmas_map & (1 << domain)))
				iolink_on |= 1;
		}
		rt_lcfg.vio = iolink_on;
		early_sic_write_node_nbsr_reg(node, rt_lcfg1_reg,
						AW(rt_lcfg));
	}
	if (node != 2 && _test_bit(2, phys_node_pres_map)) { /* node #2 is present */
		/* configure link cfg the NODE to access to io link of NODE 2 */
		AW(rt_lcfg) = early_sic_read_node_nbsr_reg(node,
								rt_lcfg2_reg);
		iolink_on = 0;
		for_each_iolink_of_node(link) {
			domain = node_iohub_to_domain(2, link);
			if ((online_iohubs_map & (1 << domain)) ||
					(online_rdmas_map & (1 << domain)))
				iolink_on |= 1;
		}
		rt_lcfg.vio = iolink_on;
		early_sic_write_node_nbsr_reg(node, rt_lcfg2_reg,
						AW(rt_lcfg));
	}
	if (node != 3 && _test_bit(3, phys_node_pres_map)) { /* node #3 is present */
		/* configure link cfg the NODE to access to io link of NODE 3 */
		AW(rt_lcfg) = early_sic_read_node_nbsr_reg(node,
								rt_lcfg3_reg);
		iolink_on = 0;
		for_each_iolink_of_node(link) {
			domain = node_iohub_to_domain(3, link);
			if ((online_iohubs_map & (1 << domain)) ||
					(online_rdmas_map & (1 << domain)))
				iolink_on |= 1;
		}
		rt_lcfg.vio = iolink_on;
		early_sic_write_node_nbsr_reg(node, rt_lcfg3_reg,
						AW(rt_lcfg));
	}
}

static void configure_io_links(void)
{
	int node;

	for (node = 0; node < MAX_NUMNODES; node++) {
		if (!_test_bit(node, phys_node_pres_map))
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
       e2k_iol_csr_t    io_link;
       e2k_io_csr_t     io_hub;
       e2k_rdma_cs_t    rdma;
       int src_mode, dst_mode;
       int ab_type;
       int link_on;

       link_on = 0;

       AW(io_link) = early_sic_read_node_iolink_nbsr_reg(node, link, SIC_iol_csr);
       src_mode = io_link.mode;
       rom_printk("Node #%d IO LINK #%d is", node, link);
       if (io_link.mode == IOHUB_IOL_MODE) {
	       AW(io_hub) = early_sic_read_node_iolink_nbsr_reg(node, link, SIC_io_csr);
	       if (io_hub.ch_on)
		       link_on = 1;
       } else {
	       AW(rdma) = early_sic_read_node_iolink_nbsr_reg(node, link, SIC_rdma_cs);
	       if (rdma.ch_on)
		       link_on = 1;
       }
       if (!link_on) {
	       if (src_mode == IOHUB_IOL_MODE) {
		       possible_iohubs_map |= (1 << node_iohub_to_domain(node, link));
		       rom_printk(" IOHUB controller");
	       } else {
		       possible_rdmas_map |= (1 << node_iohub_to_domain(node, link));
		       possible_rdmas_num ++;
		       rom_printk(" RDMA controller");
	       }
	       rom_printk(" OFF\n");
	       return;
       }

       ab_type = io_link.abtype;
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
	       io_link.mode = dst_mode;
	       early_sic_write_node_iolink_nbsr_reg(node, link, SIC_iol_csr, AW(io_link));
       }
       if (dst_mode == IOHUB_IOL_MODE) {
	       online_iohubs_map |= (1 << node_iohub_to_domain(node, link));
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

	online_iohubs_map |= (1 << node_iohub_to_domain(node, link));

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
		if (!_test_bit(node, phys_node_pres_map))
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
}
#define configure_io_links()
#endif	/* CONFIG_E2K_FULL_SIC */

#ifdef CONFIG_E2C3
static void enable_embedded_devices(void)
{
	int node;
	unsigned int reg = 0xfc000000; /* Enable bits [31:26] */

	for (node = 0; node < MAX_NUMNODES; node++) {
		if (!_test_bit(node, phys_node_pres_map))
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
		if (!_test_bit(node, phys_node_pres_map))
			continue;
		early_sic_write_node_nbsr_reg(node, SIC_rt_msi, rt_msi_lo);
		early_sic_write_node_nbsr_reg(node, SIC_rt_msi_h, rt_msi_hi);
	}
}
#endif

void jump(void)
{
	e2k_addr_t areabase;
	e2k_size_t areasize;

	e2k_psp_t psp;
	e2k_pcsp_t pcsp;
	e2k_usbr_t usbr;

	e2k_addr_t busy_mem_start;
	e2k_addr_t busy_mem_end;
	bank_info_t *bank_info;

#if	defined(CONFIG_E2K_FULL_SIC)
#ifdef	CONFIG_SMP
	int max_cpus_num;
#endif	/* CONFIG_SMP */
#ifdef	CONFIG_E2K_SIC_V7
	e2k_rt_pciio_v7_t rt_pciio;
#else	/* < CONFIG_E2K_SIC_V7 */
	e2k_rt_pciio_t rt_pciio;
#endif	/* CONFIG_E2K_SIC_V7 */
	e2k_rt_pcim_t	rt_pcim;
#if HAS_IOAPIC_LINKS
	e2k_rt_ioapic_t	rt_ioapic;
#endif

	setup_cpu_features();

	/* Configure PCIIO for BSP. The only BSP has access to PCIIO, and other cpus through BSP */
	/* so we leave rt_pciio 1,2,3 closed by default */
	AW(rt_pciio) = NATIVE_GET_SICREG(rt_pciio0, E2K_MAX_CL_NUM, 0);
	rt_pciio.bgn = 0x0;
	rt_pciio.end = 0xf; /* All the memory for bsp
					* 0x01_0100_0 000 - 0x01_0100_F FFF
					* Align = 4Kb (0x1000) */
	NATIVE_SET_SICREG(rt_pciio0, AW(rt_pciio), E2K_MAX_CL_NUM, 0);
#ifdef CONFIG_BIOS
	bios_first();
#endif

	/* Configure IOAPIC for BSP. The only BSP has access to IOAPIC, and other cpus through BSP */
	/* so we leave rt_ioapic 1,2,3 closed by default */
#if HAS_IOAPIC_LINKS
	AW(rt_ioapic) = NATIVE_GET_SICREG(rt_ioapic0, E2K_MAX_CL_NUM, 0);
	DebugRT("jump: rt_ioapic0 = 0x%x\n", AW(rt_ioapic));
	rt_ioapic.bgn = 0x0; /* 0x00_fec0_0000-0x00_fec0_0fff Align = 4k
					 * end[20:12] = bgn[20:12]
					 * end[11:0] = 0xfff  */
	NATIVE_SET_SICREG(rt_ioapic0, AW(rt_ioapic), E2K_MAX_CL_NUM, 0);

	/* Configure IOAPIC link for NODE 1 FIXME: may be used in future */
	AW(rt_ioapic) = NATIVE_GET_SICREG(rt_ioapic1, E2K_MAX_CL_NUM, 0);
	DebugRT("jump: rt_ioapic1 = 0x%x\n", AW(rt_ioapic));
	rt_ioapic.bgn = 0x1; /* 0x00_fec0_1000-0x00_fec0_1fff Align = 4k
					 * end[20:12] = bgn[20:12]
					 * end[11:0] = 0xfff  */
	NATIVE_SET_SICREG(rt_ioapic1, AW(rt_ioapic), E2K_MAX_CL_NUM, 0);

	/* Configure IOAPIC link for NODE 2 FIXME: may be used in future */
	AW(rt_ioapic) = NATIVE_GET_SICREG(rt_ioapic2, E2K_MAX_CL_NUM, 0);
	DebugRT("jump: rt_ioapic2 = 0x%x\n", AW(rt_ioapic));
	rt_ioapic.bgn = 0x2; /* 0x00_fec0_2000-0x00_fec0_2fff Align = 4k
					 * end[20:12] = bgn[20:12]
					 * end[11:0] = 0xfff  */
	NATIVE_SET_SICREG(rt_ioapic2, AW(rt_ioapic), E2K_MAX_CL_NUM, 0);

	/* Configure IOAPIC link for NODE 3 FIXME: may be used in future */
	AW(rt_ioapic) = NATIVE_GET_SICREG(rt_ioapic3, E2K_MAX_CL_NUM, 0);
	DebugRT("jump: rt_ioapic3 = 0x%x\n", AW(rt_ioapic));
	rt_ioapic.bgn = 0x3; /* 0x00_fec0_3000-0x00_fec0_3fff Align = 4k
					 * end[20:12] = bgn[20:12]
					 * end[11:0] = 0xfff  */
	NATIVE_SET_SICREG(rt_ioapic3, AW(rt_ioapic), E2K_MAX_CL_NUM, 0);
#endif

	/* Configure PCIM for BSP. The only BSP has access to PCIM, and other cpus through BSP */
	/* so we leave rt_pcim 1,2,3 closed by default */
	AW(rt_pcim) = NATIVE_GET_SICREG(rt_pcim0, E2K_MAX_CL_NUM, 0);
	DebugRT("jump: rt_pcim0 = 0x%x\n", AW(rt_pcim));
	rt_pcim.bgn = 0x10; 	/* 2 Gb start of PCI memory */
	rt_pcim.end = 0x1e; /* All other memory fo bsp
					* 0x00_10 00_0000 - 0x00_f7 ff_ffff (0xf0 00_0000 + 0x7 ff_ffff);
					* Align = 128Mb (0x8000000)
					* BUG: 0x1f= 0x00_ff ff_ffff intersects with LAPIC area but
					* available. Due to specification the end can be 0x00_FEBF_FFFF but
					* it's ipmossible to reach  */
	NATIVE_SET_SICREG(rt_pcim0, AW(rt_pcim), E2K_MAX_CL_NUM, 0);
#elif	defined(CONFIG_E2K_LEGACY_SIC)
#ifdef CONFIG_BIOS
	bios_first();
#endif
#endif	/* CONFIG_E2K_FULL_SIC */

	configure_routing_regs();
	configure_io_routing();

#ifdef	CONFIG_SMP
	all_pic_ids[0] = NATIVE_READ_PIC_ID();
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
#elif	defined(CONFIG_E8V7)
	max_cpus_num = E8V7_NR_NODE_CPUS;
#else
 #error	"Unknown MicroProcessor type"
#endif
	for (;;)
	{
		e2k_rt_lcfg_t	rt_lcfg;
		int i = 0;

		if (max_cpus_num > 1) {
			AW(rt_lcfg) = NATIVE_GET_SICREG(rt_lcfg0, 0, 0);
			i += startup_all_cores(rt_lcfg, max_cpus_num, true	/* BSP */);
		}

		AW(rt_lcfg) = NATIVE_GET_SICREG(rt_lcfg1, 0, 0); /* Read on BSP */
		if (rt_lcfg.vp == 1) {
			i += startup_all_cores(rt_lcfg, max_cpus_num, false	/* BSP ? */);
		}

		AW(rt_lcfg) = NATIVE_GET_SICREG(rt_lcfg2, 0, 0); /* Read on BSP */
		if (rt_lcfg.vp == 1) {
			i += startup_all_cores(rt_lcfg, max_cpus_num, false	/* BSP ? */);
		}
		AW(rt_lcfg) = NATIVE_GET_SICREG(rt_lcfg3, 0, 0); /* Read on BSP */
		if (rt_lcfg.vp == 1) {
			i += startup_all_cores(rt_lcfg, max_cpus_num, false	/* BSP ? */);
		}
		if (max_cpus_num > 1)
			atomic_inc(&cpu_count);	/* acoount BSP core */
		i = atomic_read(&cpu_count);
		rom_printk("Detected %d CPUS\n", i);
		break;
	}
#endif	/* CONFIG_E2K_LEGACY_SIC */
#endif	/* CONFIG_SMP */

	/* Boot info goes under loader's C-stack and below kernel code. */
	bootblock = (bootblock_struct_t *)ALIGN((e2k_addr_t)free_memory_p, E2K_BOOTINFO_PAGE_SIZE);
	free_memory_p = (char *)((e2k_addr_t)bootblock +
					sizeof(bootblock_struct_t));
	boot_info = &bootblock->info;
	rom_printk("Boot info structure at 0x%X\n", boot_info);

#ifdef	CONFIG_RECOVERY
	if (boot_info->signature == BOOTBLOCK_ROMLOADER_SIGNATURE) {
		recovery_flag = bootblock->boot_flags & RECOVERY_BB_FLAG;
		not_read_image = bootblock->boot_flags & NO_READ_IMAGE_BB_FLAG;

		if (recovery_flag) {
			rom_puts("ROM loader restarted to recover kernel\n");
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
		rom_printk(" size: 0x%X.\n", ((u64)__bss_stop - (u64)__bss_start));

		psp = native_read_PSP_reg();

		rom_printk("Proc. Stack (PSP) at: 0x%X,", psp.Base);
		rom_printk(" size: 0x%X,", psp.Size);
		rom_printk(" direction: %s.\n", "upward");

		pcsp = native_read_PCSP_reg();

		rom_printk("Proc. Chain Stack (PCSP) at: 0x%X,", pcsp.Base);
		rom_printk(" size: 0x%X,", pcsp.Size);
		rom_printk(" direction: %s.\n", "upward");
		usbr = native_read_USBR_reg();
		rom_printk("GNU C Stack at: 0x%X,", usbr.base);
		rom_printk(" size: 0x%X, ", E2K_BOOT_KERNEL_US_SIZE);
		rom_printk(" direction: %s.\n", "downward");
		rom_printk("BOOTINFO structure is starting at: 0x%X, size 0x%X\n",
			(u64) bootblock, sizeof(bootblock_struct_t));
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
	if (!recovery_flag)
#endif	/* CONFIG_RECOVERY */
	{
		memset(boot_info, 0, sizeof(*boot_info));

		/* Creation of boot info records. */
		boot_info->signature = BOOTBLOCK_ROMLOADER_SIGNATURE;	/* ROMLoader marker */
		boot_info->vga_mode = 0;

		/* our loader used only on simulator */
		boot_info->mach_flags = SIMULATOR_MACH_FLAG;

		set_memory_filters(boot_info);

		memcpy(boot_info->boot_ver, BOOT_VER_STR,
			(int)bios_strlen(BOOT_VER_STR) + 1);

		if (NATIVE_IS_MACHINE_E2S)
			boot_info->cpu_type = CPU_TYPE_E2S;
		else if (NATIVE_IS_MACHINE_E8C)
			boot_info->cpu_type = CPU_TYPE_E8C;
		else if (NATIVE_IS_MACHINE_E8C2)
			boot_info->cpu_type = CPU_TYPE_E8C2;
		else if (NATIVE_IS_MACHINE_E1CP)
			boot_info->cpu_type = CPU_TYPE_E1CP;
		else if (NATIVE_IS_MACHINE_E12C)
			boot_info->cpu_type = CPU_TYPE_E12C;
		else if (NATIVE_IS_MACHINE_E16C)
			boot_info->cpu_type = CPU_TYPE_E16C;
		else if (NATIVE_IS_MACHINE_E2C3)
			boot_info->cpu_type = CPU_TYPE_E2C3;
		else if (NATIVE_IS_MACHINE_E8V7)
			boot_info->cpu_type = CPU_TYPE_E8V7;
		rom_printk("CPU & MicroProcessor: %s\n",
			GET_CPU_TYPE_NAME(boot_info->cpu_type));
	}

	boot_info->num_of_busy = 0;

	/*
	 * Memory assumptions: node #0 & bank #0 exist and starts from 0
	 * If memory banks > 1 we use bank #1 on the node #0
	 */
	busy_mem_end = PAGE_ALIGN((e2k_addr_t)free_memory_p);
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

	/* This will initialize COM port */
#ifdef CONFIG_BIOS
	bios_rest();
#endif

	/* Command line */
#ifdef	CONFIG_RECOVERY
	if (!recovery_flag)
#endif	/* CONFIG_RECOVERY */
	{
		int cmd_len = bios_strlen(cmd_preset);

#ifdef CONFIG_CMDLINE_PROMPT
		kernel_command_prompt(cmd_buf, cmd_preset);
#else
		if (cmd_len >= sizeof(cmd_buf)) {
			rom_printk("Kernel command line size is too big size %d > %d (buffer size)\n",
					cmd_len, sizeof(cmd_buf));
			E2K_LMS_HALT_OK;
		}
		memcpy(cmd_buf, cmd_preset, cmd_len);
#endif /* CONFIG_CMDLINE_PROMPT */

		if (cmd_len < KSTRMAX_SIZE) {
			memcpy(boot_info->kernel_args_string, cmd_buf, cmd_len + 1);
		} else if (cmd_len < KSTRMAX_SIZE_EX) {
			memcpy(boot_info->kernel_args_string_ex, cmd_buf, cmd_len + 1);
			memcpy(boot_info->kernel_args_string,
					KERNEL_ARGS_STRING_EX_SIGNATURE,
					KERNEL_ARGS_STRING_EX_SIGN_SIZE);
		} else {
			boot_info->kernel_args_string_pnt = (u64)cmd_buf;
		}
		rom_printk("Kernel command line: %s\n", cmd_buf);
	}

#ifdef CONFIG_BIOS
#if defined(CONFIG_E2K_LEGACY_SIC)
	video_bios();
#endif	/* CONFIG_E2K_LEGACY_SIC */
#endif

#ifdef CONFIG_INITRD_INSIDE

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
#else	/* ! CONFIG_INITRD_INSIDE */
#ifdef	CONFIG_RECOVERY
	if (!recovery_flag) {
#endif	/* CONFIG_RECOVERY */
		boot_info->ramdisk_base = 0;
		boot_info->ramdisk_size = 0;
#ifdef	CONFIG_RECOVERY
	}
#endif	/* CONFIG_RECOVERY */

#endif /* CONFIG_INITRD_INSIDE */

#ifdef	CONFIG_RECOVERY
	if (!recovery_flag) {
#endif	/* CONFIG_RECOVERY */
		create_smp_config(boot_info);
#ifdef	CONFIG_RECOVERY
	} else {
		recover_smp_config(boot_info);
	}
#endif	/* CONFIG_RECOVERY */

	busy_mem_end = PAGE_ALIGN(get_busy_memory_end());
	add_busy_memory_area(boot_info, busy_mem_start, busy_mem_end);

	areasize = (e2k_addr_t)&input_data_noncomp_size;
	rom_printk("Kernel will be loaded from 'romimage' file by simulator, size %d\n",
		areasize);


#ifdef	CONFIG_RECOVERY
	if (!recovery_flag) {
#endif	/* CONFIG_RECOVERY */
		rom_puts("Allocating space for kernel copy... ");
		areabase = (long) malloc_aligned(areasize,
				E2K_MAX_PAGE_SIZE);
		rom_puts("done.\n");
		bios_outll(areabase, LMS_RAM_ADDR_PORT);
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
		rom_puts("Loading the kernel from 'romimage file to RAM ... ");
		bios_outb(LMS_LOAD_IMAGE_TO_RAM, LMS_TRACE_CNTL_PORT);
		rom_puts(" done.\n");

#ifdef	CONFIG_RECOVERY
	}
#endif	/* CONFIG_RECOVERY */

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
	e2k_cud_t		cud;
	e2k_gd_t		gd;

	/*
	 * Set Kernel 'text/data/bss' segment registers to kernel image
	 * physical addresses
	 */

#if defined(CONFIG_E2S) || defined(CONFIG_E8C) || defined(CONFIG_E1CP) || defined(CONFIG_E8C2) || \
		defined(CONFIG_E12C) || defined(CONFIG_E16C) || defined(CONFIG_E2C3)
	/* <= v6 */
	cud      = new_cud_v6(kernel_areabase, kernel_areasize, 1, cud_m64);
	gd       = new_gd_v6(kernel_areabase, kernel_areasize);
#else
	/* >= v7 */
	cud      = new_cud_v7(kernel_areabase, kernel_areasize, 1, cud_m64);
	gd       = new_gd_v7(kernel_areabase, kernel_areasize);
#endif

	native_write_CUD_reg(cud);
	native_write_OSCUD_reg(cud);

	native_write_GD_reg(gd);
	native_write_OSGD_reg(gd);

}

