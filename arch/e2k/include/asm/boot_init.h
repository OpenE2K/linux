/* $Id: boot_init.h,v 1.18 2009/06/29 11:53:32 atic Exp $
 *
 * Boot-time initialization of Virtual memory support and switch
 * from boot execution on physical memory to boot continuation
 * on virtual memory
 */
#ifndef _E2K_BOOT_INIT_H
#define _E2K_BOOT_INIT_H

#include <linux/init.h>
#include <linux/topology.h>
#include <asm/cpu_regs_access.h>

#include <asm/bootinfo.h>
#include <asm/numnodes.h>

#ifndef __ASSEMBLY__

/*
 * The next structures desribe list of the memory areas used by boot-time
 * initialization. The item 'phys' points to physical base address of
 * area, when the item 'virt' points to virtual base address of same area.
 * All the used memory areas enumerate below. If a some new area will be used,
 * then it should be added to the list of already known ones.
 */

typedef	struct mem_area_desc {		/* an area descriptor */
	e2k_addr_t	phys;		/* physical base address area */
	e2k_addr_t	virt;		/* virtual base address of same area */
	e2k_size_t	size;		/* bytes size of the area */
	e2k_size_t	phys_offset;	/* physical offset of the area */
	e2k_size_t	virt_offset;	/* virtual offset of the area */
} mem_area_desc_t;
#if defined(CONFIG_DISCONTIGMEM) || defined(CONFIG_NUMA)
typedef	struct node_mem_area_desc {	/* node an area descriptor */
	mem_area_desc_t nodes[L_MAX_MEM_NUMNODES];
} node_mem_area_desc_t;
#endif	/* CONFIG_DISCONTIGMEM || CONFIG_NUMA */

typedef	struct bootmem_areas {		/* list of all areas */
#ifndef	CONFIG_NUMA
	mem_area_desc_t	text;		/* segment 'text' of kernel */
#ifdef	CONFIG_KERNEL_CODE_CONTEXT
	mem_area_desc_t	prot_text;	/* segment 'protected text' of kernel */
#endif	/* CONFIG_KERNEL_CODE_CONTEXT */
	mem_area_desc_t	data;		/* segment 'data' of kernel */
#else	/* CONFIG_NUMA */
	node_mem_area_desc_t text;	/* nodes segment 'text' of kernel */
#ifdef	CONFIG_KERNEL_CODE_CONTEXT
	node_mem_area_desc_t prot_text;	/* nodes segment 'protected text' */
					/* of kernel */
#endif	/* CONFIG_KERNEL_CODE_CONTEXT */
	node_mem_area_desc_t dup_data;	/* nodes duplicated 'data' segment */
	node_mem_area_desc_t data;	/* node segment 'data' of kernel */
#endif	/* ! CONFIG_NUMA */
#ifndef	CONFIG_SMP
	/*
	 * Boot-time stacks to switch from physical memory to virtual memory
	 */
	mem_area_desc_t	boot_ps;	/* procedure stack of kernel */
	mem_area_desc_t	boot_pcs;	/* procedure chain stack of kernel */
	mem_area_desc_t	boot_stack;	/* kernel procedure local data stack */

	/*
	 * Init-time stacks for kernel initialization
	 * (stacks of cpu_idle() process)
	 */
	mem_area_desc_t	init_ps;	/* procedure stack of kernel */
	mem_area_desc_t	init_pcs;	/* procedure chain stack of kernel */
	mem_area_desc_t	init_dstack;	/* kernel procedure local data stack */
#else
	/*
	 * Boot-time stacks to switch from physical memory to virtual memory
	 */
	mem_area_desc_t	boot_ps[NR_CPUS];
	mem_area_desc_t	boot_pcs[NR_CPUS];
	mem_area_desc_t	boot_stack[NR_CPUS];

	/*
	 * Init-time stacks for kernel initialization
	 * (stacks of cpu_idle() processes)
	 */
	mem_area_desc_t	init_ps[NR_CPUS];
	mem_area_desc_t	init_pcs[NR_CPUS];
	mem_area_desc_t	init_dstack[NR_CPUS];
#endif	/* CONFIG_SMP */
	mem_area_desc_t	bootinfo;	/* boot-time information from loader */
#ifdef CONFIG_BLK_DEV_INITRD
	mem_area_desc_t	initrd;		/* initial disk info */
#endif	/* CONFIG_BLK_DEV_INITRD */

#ifdef	CONFIG_L_IO_APIC
	mem_area_desc_t	mpf;		/* MP floating table */
	mem_area_desc_t	mpc;		/* MP configuration table */
#endif	/* CONFIG_L_IO_APIC */
	mem_area_desc_t	symtab;		/* kernel symbols table */
	mem_area_desc_t	strtab;		/* kernel strings table */
	mem_area_desc_t	x86_hw;		/* PA 640K - 1M are reserved for PC's */
					/* integrated hardware: BIOS, VGA,... */
#ifndef CONFIG_DISCONTIGMEM
	mem_area_desc_t	bootmap;	/* memory to support bootmap of */
					/* 'linux/mm/bootmem.c' */
#else	/* CONFIG_DISCONTIGMEM */
	node_mem_area_desc_t	bootmap;
					/* memory to support bootmap of */
					/* 'linux/mm/bootmem.c' on each node */
#endif	/* ! CONFIG_DISCONTIGMEM */

} bootmem_areas_t;

extern	long			phys_memory_mgb_size;
#define	boot_phys_memory_mgb_size	boot_get_vo_value(phys_memory_mgb_size)

extern	bootmem_areas_t		kernel_bootmem;

#define	boot_kernel_bootmem	boot_vp_to_pp(&kernel_bootmem)

#ifndef	CONFIG_NUMA
#define boot_text_phys_base	boot_get_vo_value(kernel_bootmem.text.phys)
#define boot_text_virt_base	boot_get_vo_value(kernel_bootmem.text.virt)
#define boot_text_size		boot_get_vo_value(kernel_bootmem.text.size)

#ifdef	CONFIG_KERNEL_CODE_CONTEXT
#define boot_prot_text_phys_base \
			boot_get_vo_value(kernel_bootmem.prot_text.phys)
#define boot_prot_text_virt_base \
			boot_get_vo_value(kernel_bootmem.prot_text.virt)
#define boot_prot_text_size	 \
			boot_get_vo_value(kernel_bootmem.prot_text.size)
#endif	/* CONFIG_KERNEL_CODE_CONTEXT */

#define boot_data_phys_base	boot_get_vo_value(kernel_bootmem.data.phys)
#define boot_data_virt_base	boot_get_vo_value(kernel_bootmem.data.virt)
#define boot_data_size		boot_get_vo_value(kernel_bootmem.data.size)
#else	/* CONFIG_NUMA */
#define boot_node_text_phys_base(nid)		\
		boot_get_vo_value(kernel_bootmem.text.nodes[(nid)].phys)
#define boot_node_text_virt_base(nid)		\
		boot_get_vo_value(kernel_bootmem.text.nodes[(nid)].virt)
#define boot_node_text_size(nid)		\
		boot_get_vo_value(kernel_bootmem.text.nodes[(nid)].size)

#ifdef	CONFIG_KERNEL_CODE_CONTEXT
#define boot_node_prot_text_phys_base(nid)	\
		boot_get_vo_value(kernel_bootmem.prot_text.nodes[(nid)].phys)
#define boot_node_prot_text_virt_base(nid)	\
		boot_get_vo_value(kernel_bootmem.prot_text.nodes[(nid)].virt)
#define boot_node_prot_text_size(nid)		 \
		boot_get_vo_value(kernel_bootmem.prot_text.nodes[(nid)].size)
#endif	/* CONFIG_KERNEL_CODE_CONTEXT */

#define boot_node_dup_data_phys_base(nid)	\
		boot_get_vo_value(kernel_bootmem.dup_data.nodes[(nid)].phys)
#define boot_node_dup_data_virt_base(nid)	\
		boot_get_vo_value(kernel_bootmem.dup_data.nodes[(nid)].virt)
#define boot_node_dup_data_size(nid)		\
		boot_get_vo_value(kernel_bootmem.dup_data.nodes[(nid)].size)
#define boot_node_data_phys_base(nid)		\
		boot_get_vo_value(kernel_bootmem.data.nodes[(nid)].phys)
#define boot_node_data_virt_base(nid)		\
		boot_get_vo_value(kernel_bootmem.data.nodes[(nid)].virt)
#define boot_node_data_size(nid)		\
		boot_get_vo_value(kernel_bootmem.data.nodes[(nid)].size)

#define boot_text_phys_base	boot_node_text_phys_base(boot_numa_node_id())
#define boot_text_virt_base	boot_node_text_virt_base(boot_numa_node_id())
#define boot_text_size		boot_node_text_size(boot_numa_node_id())

#ifdef	CONFIG_KERNEL_CODE_CONTEXT
#define boot_prot_text_phys_base	\
		boot_node_prot_text_phys_base(boot_numa_node_id())
#define boot_prot_text_virt_base	\
		boot_node_prot_text_virt_base(boot_numa_node_id())
#define boot_prot_text_size		\
		boot_node_prot_text_size(boot_numa_node_id())
#endif	/* CONFIG_KERNEL_CODE_CONTEXT */

#define boot_dup_data_phys_base		\
		boot_node_dup_data_phys_base(boot_numa_node_id())
#define boot_dup_data_virt_base		\
		boot_node_dup_data_virt_base(boot_numa_node_id())
#define boot_dup_data_size		\
		boot_node_dup_data_size(boot_numa_node_id())
#define boot_data_phys_base	boot_node_data_phys_base(boot_numa_node_id())
#define boot_data_virt_base	boot_node_data_virt_base(boot_numa_node_id())
#define boot_data_size		boot_node_data_size(boot_numa_node_id())
#endif	/* ! CONFIG_NUMA */

#ifndef	CONFIG_SMP
#define boot_boot_ps_phys_base	boot_get_vo_value(kernel_bootmem.boot_ps.phys)
#define boot_boot_ps_virt_base	boot_get_vo_value(kernel_bootmem.boot_ps.virt)
#define boot_boot_ps_size	boot_get_vo_value(kernel_bootmem.boot_ps.size)
#define	kernel_boot_ps_phys_base(cpuid)	kernel_bootmem.boot_ps.phys
#define	kernel_boot_ps_virt_base(cpuid)	kernel_bootmem.boot_ps.virt
#define	kernel_boot_ps_size(cpuid)	kernel_bootmem.boot_ps.size
#define boot_init_ps_phys_base	boot_get_vo_value(kernel_bootmem.init_ps.phys)
#define boot_init_ps_virt_base	boot_get_vo_value(kernel_bootmem.init_ps.virt)
#define boot_init_ps_size	boot_get_vo_value(kernel_bootmem.init_ps.size)
#define	kernel_init_ps_phys_base(cpuid)	kernel_bootmem.init_ps.phys
#define	kernel_init_ps_virt_base(cpuid)	kernel_bootmem.init_ps.virt
#define	kernel_init_ps_size(cpuid)	kernel_bootmem.init_ps.size
#else
#define boot_boot_ps_phys_base	\
	boot_get_vo_value(kernel_bootmem.boot_ps[boot_smp_processor_id()].phys)
#define boot_boot_ps_virt_base	\
	boot_get_vo_value(kernel_bootmem.boot_ps[boot_smp_processor_id()].virt)
#define boot_boot_ps_size		\
	boot_get_vo_value(kernel_bootmem.boot_ps[boot_smp_processor_id()].size)
#define	kernel_boot_ps_phys_base(cpuid)	kernel_bootmem.boot_ps[cpuid].phys
#define	kernel_boot_ps_virt_base(cpuid)	kernel_bootmem.boot_ps[cpuid].virt
#define	kernel_boot_ps_size(cpuid)	kernel_bootmem.boot_ps[cpuid].size
#define boot_init_ps_phys_base	\
	boot_get_vo_value(kernel_bootmem.init_ps[boot_smp_processor_id()].phys)
#define boot_init_ps_virt_base	\
	boot_get_vo_value(kernel_bootmem.init_ps[boot_smp_processor_id()].virt)
#define boot_init_ps_size		\
	boot_get_vo_value(kernel_bootmem.init_ps[boot_smp_processor_id()].size)
#define	kernel_init_ps_phys_base(cpuid)	kernel_bootmem.init_ps[cpuid].phys
#define	kernel_init_ps_virt_base(cpuid)	kernel_bootmem.init_ps[cpuid].virt
#define	kernel_init_ps_size(cpuid)	kernel_bootmem.init_ps[cpuid].size
#endif	/* CONFIG_SMP */

#ifndef	CONFIG_SMP
#define boot_boot_pcs_phys_base	boot_get_vo_value(kernel_bootmem.boot_pcs.phys)
#define boot_boot_pcs_virt_base	boot_get_vo_value(kernel_bootmem.boot_pcs.virt)
#define boot_boot_pcs_size	boot_get_vo_value(kernel_bootmem.boot_pcs.size)
#define	kernel_boot_pcs_phys_base(cpuid)	kernel_bootmem.boot_pcs.phys
#define	kernel_boot_pcs_virt_base(cpuid)	kernel_bootmem.boot_pcs.virt
#define	kernel_boot_pcs_size(cpuid)		kernel_bootmem.boot_pcs.size
#define boot_init_pcs_phys_base	boot_get_vo_value(kernel_bootmem.init_pcs.phys)
#define boot_init_pcs_virt_base	boot_get_vo_value(kernel_bootmem.init_pcs.virt)
#define boot_init_pcs_size	boot_get_vo_value(kernel_bootmem.init_pcs.size)
#define	kernel_init_pcs_phys_base(cpuid)	kernel_bootmem.init_pcs.phys
#define	kernel_init_pcs_virt_base(cpuid)	kernel_bootmem.init_pcs.virt
#define	kernel_init_pcs_size(cpuid)		kernel_bootmem.init_pcs.size
#else
#define boot_boot_pcs_phys_base	\
	boot_get_vo_value(kernel_bootmem.boot_pcs[boot_smp_processor_id()].phys)
#define boot_boot_pcs_virt_base	\
	boot_get_vo_value(kernel_bootmem.boot_pcs[boot_smp_processor_id()].virt)
#define boot_boot_pcs_size		\
	boot_get_vo_value(kernel_bootmem.boot_pcs[boot_smp_processor_id()].size)
#define	kernel_boot_pcs_phys_base(cpuid) \
		kernel_bootmem.boot_pcs[cpuid].phys
#define	kernel_boot_pcs_virt_base(cpuid) \
		kernel_bootmem.boot_pcs[cpuid].virt
#define	kernel_boot_pcs_size(cpuid) \
		kernel_bootmem.boot_pcs[cpuid].size
#define boot_init_pcs_phys_base	\
	boot_get_vo_value(kernel_bootmem.init_pcs[boot_smp_processor_id()].phys)
#define boot_init_pcs_virt_base	\
	boot_get_vo_value(kernel_bootmem.init_pcs[boot_smp_processor_id()].virt)
#define boot_init_pcs_size		\
	boot_get_vo_value(kernel_bootmem.init_pcs[boot_smp_processor_id()].size)
#define	kernel_init_pcs_phys_base(cpuid) \
		kernel_bootmem.init_pcs[cpuid].phys
#define	kernel_init_pcs_virt_base(cpuid) \
		kernel_bootmem.init_pcs[cpuid].virt
#define	kernel_init_pcs_size(cpuid) \
		kernel_bootmem.init_pcs[cpuid].size
#endif	/* CONFIG_SMP */

#ifndef	CONFIG_SMP
#define boot_boot_stack_phys_base \
		boot_get_vo_value(kernel_bootmem.boot_stack.phys)
#define boot_boot_stack_virt_base \
		boot_get_vo_value(kernel_bootmem.boot_stack.virt)
#define boot_boot_stack_size \
		boot_get_vo_value(kernel_bootmem.boot_stack.size)
#define boot_boot_stack_phys_offset	\
		boot_get_vo_value(kernel_bootmem.boot_stack.phys_offset)
#define boot_boot_stack_virt_offset	\
		boot_get_vo_value(kernel_bootmem.boot_stack.virt_offset)

#define	kernel_boot_stack_phys_base(cpuid)	kernel_bootmem.boot_stack.phys
#define	kernel_boot_stack_virt_base(cpuid)	kernel_bootmem.boot_stack.virt
#define	kernel_boot_stack_virt_offset(cpuid) \
		kernel_bootmem.boot_stack.virt_offset
#define	kernel_boot_stack_size(cpuid)		kernel_bootmem.boot_stack.size
#define boot_init_stack_phys_base \
		boot_get_vo_value(kernel_bootmem.init_dstack.phys)
#define boot_init_stack_virt_base \
		boot_get_vo_value(kernel_bootmem.init_dstack.virt)
#define boot_init_stack_size \
		boot_get_vo_value(kernel_bootmem.init_dstack.size)
#define boot_init_stack_phys_offset	\
		boot_get_vo_value(kernel_bootmem.init_dstack.phys_offset)
#define boot_init_stack_virt_offset	\
		boot_get_vo_value(kernel_bootmem.init_dstack.virt_offset)

#define	kernel_init_stack_phys_base(cpuid)	kernel_bootmem.init_dstack.phys
#define	kernel_init_stack_virt_base(cpuid)	kernel_bootmem.init_dstack.virt
#define	kernel_init_stack_virt_offset(cpuid) \
		kernel_bootmem.init_dstack.virt_offset
#define	kernel_init_stack_size(cpuid) \
		kernel_bootmem.init_dstack.size
#else
#define boot_boot_stack_phys_base	\
	boot_get_vo_value(kernel_bootmem.boot_stack[boot_smp_processor_id()]. \
								phys)
#define boot_boot_stack_virt_base	\
	boot_get_vo_value(kernel_bootmem.boot_stack[boot_smp_processor_id()]. \
								virt)
#define boot_boot_stack_size		\
	boot_get_vo_value(kernel_bootmem.boot_stack[boot_smp_processor_id()]. \
								size)
#define boot_boot_stack_phys_offset	\
	boot_get_vo_value(kernel_bootmem.boot_stack[boot_smp_processor_id()]. \
								phys_offset)
#define boot_boot_stack_virt_offset	\
	boot_get_vo_value(kernel_bootmem.boot_stack[boot_smp_processor_id()]. \
								virt_offset)
#define	kernel_boot_stack_phys_base(cpuid) \
		kernel_bootmem.boot_stack[cpuid].phys
#define	kernel_boot_stack_virt_base(cpuid) \
		kernel_bootmem.boot_stack[cpuid].virt
#define	kernel_boot_stack_virt_offset(cpuid) \
		kernel_bootmem.boot_stack[cpuid].virt_offset
#define	kernel_boot_stack_size(cpuid) \
		kernel_bootmem.boot_stack[cpuid].size
#define boot_init_stack_phys_base	\
	boot_get_vo_value(kernel_bootmem.init_dstack[boot_smp_processor_id()]. \
								phys)
#define boot_init_stack_virt_base	\
	boot_get_vo_value(kernel_bootmem.init_dstack[boot_smp_processor_id()]. \
								virt)
#define boot_init_stack_size		\
	boot_get_vo_value(kernel_bootmem.init_dstack[boot_smp_processor_id()]. \
								size)
#define boot_init_stack_phys_offset	\
	boot_get_vo_value(kernel_bootmem.init_dstack[boot_smp_processor_id()]. \
								phys_offset)
#define boot_init_stack_virt_offset	\
	boot_get_vo_value(kernel_bootmem.init_dstack[boot_smp_processor_id()]. \
								virt_offset)
#define	kernel_init_stack_phys_base(cpuid) \
		kernel_bootmem.init_dstack[cpuid].phys
#define	kernel_init_stack_virt_base(cpuid) \
		kernel_bootmem.init_dstack[cpuid].virt
#define	kernel_init_stack_virt_offset(cpuid) \
		kernel_bootmem.init_dstack[cpuid].virt_offset
#define	kernel_init_stack_size(cpuid) \
		kernel_bootmem.init_dstack[cpuid].size
#endif	/* CONFIG_SMP */

#ifndef CONFIG_DISCONTIGMEM
#define boot_bootmap_phys_base	boot_get_vo_value(kernel_bootmem.bootmap.phys)
#define boot_bootmap_size	boot_get_vo_value(kernel_bootmem.bootmap.size)

#define init_bootmap_phys_base	kernel_bootmem.bootmap.phys
#define init_bootmap_size	kernel_bootmem.bootmap.size
#else	/* CONFIG_DISCONTIGMEM */
#define boot_node_bootmap_phys_base(nid)	\
		boot_get_vo_value(kernel_bootmem.bootmap.nodes[nid].phys)
#define boot_node_bootmap_size(nid)	\
		boot_get_vo_value(kernel_bootmem.bootmap.nodes[nid].size)
#define init_node_bootmap_phys_base(nid)	\
		kernel_bootmem.bootmap.nodes[nid].phys
#define init_node_bootmap_size(nid)	\
		kernel_bootmem.bootmap.nodes[nid].size
#define boot_bootmap_phys_base	boot_node_bootmap_phys_base(boot_numa_node_id())
#define boot_bootmap_size	boot_node_bootmap_size(boot_numa_node_id())
#define init_bootmap_phys_base	init_node_bootmap_phys_base(boot_numa_node_id())
#define init_bootmap_size	init_node_bootmap_size(boot_numa_node_id())
#endif	/* ! CONFIG_DISCONTIGMEM */

#define boot_bootinfo_phys_base	boot_get_vo_value(kernel_bootmem.bootinfo.phys)
#define boot_bootinfo_virt_base	boot_get_vo_value(kernel_bootmem.bootinfo.virt)
#define boot_bootinfo_size	boot_get_vo_value(kernel_bootmem.bootinfo.size)

#define init_bootinfo_phys_base	kernel_bootmem.bootinfo.phys
#define init_bootinfo_virt_base	kernel_bootmem.bootinfo.virt
#define init_bootinfo_size	kernel_bootmem.bootinfo.size

#ifdef CONFIG_BLK_DEV_INITRD
#define boot_initrd_phys_base	boot_get_vo_value(kernel_bootmem.initrd.phys)
#define boot_initrd_virt_base	boot_get_vo_value(kernel_bootmem.initrd.virt)
#define boot_initrd_size	boot_get_vo_value(kernel_bootmem.initrd.size)

#define init_initrd_phys_base	kernel_bootmem.initrd.phys
#define init_initrd_virt_base	kernel_bootmem.initrd.virt
#define init_initrd_size	kernel_bootmem.initrd.size
#endif	/* CONFIG_BLK_DEV_INITRD */

#ifdef	CONFIG_L_IO_APIC
#define boot_mpf_phys_base	boot_get_vo_value(kernel_bootmem.mpf.phys)
#define boot_mpf_virt_base	boot_get_vo_value(kernel_bootmem.mpf.virt)
#define boot_mpf_size		boot_get_vo_value(kernel_bootmem.mpf.size)

#define init_mpf_phys_base	kernel_bootmem.mpf.phys
#define init_mpf_virt_base	kernel_bootmem.mpf.virt
#define init_mpf_size		kernel_bootmem.mpf.size

#define boot_mpc_phys_base	boot_get_vo_value(kernel_bootmem.mpc.phys)
#define boot_mpc_virt_base	boot_get_vo_value(kernel_bootmem.mpc.virt)
#define boot_mpc_size		boot_get_vo_value(kernel_bootmem.mpc.size)

#define init_mpc_phys_base	kernel_bootmem.mpc.phys
#define init_mpc_virt_base	kernel_bootmem.mpc.virt
#define init_mpc_size		kernel_bootmem.mpc.size
#endif	/* CONFIG_L_IO_APIC */

#define boot_symtab_phys_base	boot_get_vo_value(kernel_bootmem.symtab.phys)
#define boot_symtab_virt_base	boot_get_vo_value(kernel_bootmem.symtab.virt)
#define boot_symtab_size	boot_get_vo_value(kernel_bootmem.symtab.size)

#define init_symtab_phys_base	kernel_bootmem.symtab.phys
#define init_symtab_virt_base	kernel_bootmem.symtab.virt
#define init_symtab_size	kernel_bootmem.symtab.size

#define boot_strtab_phys_base	boot_get_vo_value(kernel_bootmem.strtab.phys)
#define boot_strtab_virt_base	boot_get_vo_value(kernel_bootmem.strtab.virt)
#define boot_strtab_size	boot_get_vo_value(kernel_bootmem.strtab.size)

#define init_strtab_phys_base	kernel_bootmem.strtab.phys
#define init_strtab_virt_base	kernel_bootmem.strtab.virt
#define init_strtab_size	kernel_bootmem.strtab.size

#define boot_x86_hw_phys_base	boot_get_vo_value(kernel_bootmem.x86_hw.phys)
#define boot_x86_hw_size	boot_get_vo_value(kernel_bootmem.x86_hw.size)

#define init_x86_hw_phys_base	kernel_bootmem.x86_hw.phys
#define init_x86_hw_size	kernel_bootmem.x86_hw.size

extern unsigned long disable_caches;
extern unsigned long disable_secondary_caches;
extern unsigned long disable_IP;

/*
 * Forwards of functions of Virtual memory support initialization
 */

extern void __init	boot_mem_init(void (*boot_init_sequel_func)(void));
extern void __init	boot_probe_memory(void);
extern void __init 	init_mem_term(int cpuid);
extern void __init_recv	boot_map_needful_to_equal_virt_area(
						e2k_addr_t stack_top_addr);
extern void __init_recv	boot_switch_to_virt(void (
						*boot_init_sequel_func)(void));
extern void __init_recv	switch_to_phys(void (*restart_sequel_func)(int));
extern void __init_recv	switch_to_phys_end(void);

#endif	/* !(__ASSEMBLY__) */

#endif /* _E2K_BOOT_INIT_H */
