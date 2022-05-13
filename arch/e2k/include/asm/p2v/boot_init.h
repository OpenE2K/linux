/* $Id: boot_init.h,v 1.18 2009/06/29 11:53:32 atic Exp $
 *
 * Boot-time initialization of Virtual memory support and switch
 * from boot execution on physical memory to boot continuation
 * on virtual memory
 */

#ifndef _E2K_P2V_BOOT_INIT_H
#define _E2K_P2V_BOOT_INIT_H

#include <linux/init.h>
#include <linux/topology.h>

#include <asm/cpu_regs_access.h>
#include <asm/bootinfo.h>
#include <asm/numnodes.h>

#ifndef __ASSEMBLY__

/*
 * The next structures describe list of the memory areas used by boot-time
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

typedef	struct node_mem_area_desc {	/* node an area descriptor */
	mem_area_desc_t nodes[L_MAX_MEM_NUMNODES];
} node_mem_area_desc_t;

typedef	struct bootmem_areas {		/* list of all areas */
#ifndef	CONFIG_NUMA
	mem_area_desc_t	text;		/* segment 'text' of kernel */
	mem_area_desc_t	data;		/* segment 'data' of kernel */
#else	/* CONFIG_NUMA */
	node_mem_area_desc_t text;	/* nodes segment 'text' of kernel */
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
#else
	/*
	 * Boot-time stacks to switch from physical memory to virtual memory
	 */
	mem_area_desc_t	boot_ps[NR_CPUS];
	mem_area_desc_t	boot_pcs[NR_CPUS];
	mem_area_desc_t	boot_stack[NR_CPUS];
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
} bootmem_areas_t;

extern unsigned long			totalram_real_pages;
#define	boot_totalram_real_pages	boot_get_vo_value(totalram_real_pages)

extern	bootmem_areas_t		kernel_bootmem;
#define	boot_kernel_bootmem	boot_vp_to_pp(&kernel_bootmem)

#ifndef	CONFIG_NUMA
#define boot_text_phys_base	boot_get_vo_value(kernel_bootmem.text.phys)
#define boot_text_virt_base	boot_get_vo_value(kernel_bootmem.text.virt)
#define boot_text_size		boot_get_vo_value(kernel_bootmem.text.size)

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
#endif	/* CONFIG_SMP */

#ifndef	CONFIG_SMP
#define boot_boot_pcs_phys_base	boot_get_vo_value(kernel_bootmem.boot_pcs.phys)
#define boot_boot_pcs_virt_base	boot_get_vo_value(kernel_bootmem.boot_pcs.virt)
#define boot_boot_pcs_size	boot_get_vo_value(kernel_bootmem.boot_pcs.size)
#define	kernel_boot_pcs_phys_base(cpuid)	kernel_bootmem.boot_pcs.phys
#define	kernel_boot_pcs_virt_base(cpuid)	kernel_bootmem.boot_pcs.virt
#define	kernel_boot_pcs_size(cpuid)		kernel_bootmem.boot_pcs.size
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
#endif	/* CONFIG_SMP */

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
extern bool disable_secondary_caches;
extern bool disable_IP;

#ifdef	CONFIG_NUMA
extern boot_spinlock_t __initdata boot_node_map_lock[MAX_NUMNODES];
extern int __initdata node_mem_mapped[MAX_NUMNODES];
#define	boot_node_mem_mapped					\
		boot_get_vo_value(node_mem_mapped[boot_numa_node_id()])
#else	/* ! CONFIG_NUMA */
#define	boot_node_map_lock	SPIN_LOCK_UNLOCKED;
#define	boot_node_mem_mapped	0
#endif	/* CONFIG_NUMA */

/*
 * Forwards of functions of Virtual memory support initialization
 */

extern void boot_mem_init(bool bsp, int cpuid, boot_info_t *boot_info,
		void (*boot_init_sequel_func)(bool bsp, int cpuid, int cpus));
extern int boot_native_loader_probe_memory(
				node_phys_mem_t *nodes_phys_mem,
				boot_info_t *bootblock);
extern int boot_biosx86_probe_memory(
				node_phys_mem_t *nodes_phys_mem,
				boot_info_t *bootblock);
extern e2k_size_t boot_native_get_bootblock_size(boot_info_t *bblock);
extern void boot_native_reserve_all_bootmem(bool bsp, boot_info_t *boot_info);
extern void boot_reserve_stacks(boot_info_t *boot_info);
extern void boot_reserve_kernel_image(bool bsp, boot_info_t *boot_info);
extern void boot_reserve_bootblock(bool bsp, boot_info_t *boot_info);
extern void boot_native_map_all_bootmem(bool bsp, boot_info_t *boot_info);
extern void boot_map_kernel_image(bool populate_on_host);
extern void boot_map_kernel_boot_stacks(void);
extern void boot_map_all_phys_memory(void);
extern void boot_map_all_bootinfo_areas(boot_info_t *boot_info);
extern void init_mem_term(int cpuid);
extern void boot_native_map_needful_to_equal_virt_area(
						e2k_addr_t stack_top_addr);
extern void boot_native_switch_to_virt(bool bsp, int cpuid,
		void (*boot_init_sequel_func)(bool bsp, int cpuid, int cpus));
extern void __init_recv	switch_to_phys(void (*restart_sequel_func)(int));
extern void __init_recv	switch_to_phys_end(void);

#if	defined(CONFIG_PARAVIRT_GUEST)
/* it is paravirtualized host and guest kernel */
#include <asm/paravirt/boot.h>
#elif	defined(CONFIG_KVM_GUEST_KERNEL)
/* it is pure guest kernel (not paravirtualized based on pv_ops */
#include <asm/kvm/guest/boot.h>
#else	/* native kernel */
/* it is native kernel without any virtualization */
/* or it is native host kernel with virtualization support */
static inline  int __init
boot_loader_probe_memory(node_phys_mem_t *nodes_phys_mem,
					boot_info_t *bootblock)
{
	return boot_native_loader_probe_memory(nodes_phys_mem, bootblock);
}

static inline e2k_size_t __init
boot_get_bootblock_size(boot_info_t *bootblock)
{
	return boot_native_get_bootblock_size(bootblock);
}

static inline void __init
boot_reserve_all_bootmem(bool bsp, boot_info_t *boot_info)
{
	boot_native_reserve_all_bootmem(bsp, boot_info);
}

static inline void __init
boot_map_all_bootmem(bool bsp, boot_info_t *boot_info)
{
	boot_native_map_all_bootmem(bsp, boot_info);
}

static inline void __init_recv
boot_map_needful_to_equal_virt_area(e2k_addr_t stack_top_addr)
{
	boot_native_map_needful_to_equal_virt_area(stack_top_addr);
}

static inline void __init_recv
boot_kernel_switch_to_virt(bool bsp, int cpuid,
	void (*boot_init_sequel_func)(bool bsp, int cpuid, int cpus_to_sync))
{
	boot_native_switch_to_virt(bsp, cpuid, boot_init_sequel_func);
}

/* pv_ops does not used in native host/guest mode */
static inline void native_pv_ops_to_boot_ops(void)
{
}
static inline void native_boot_pv_ops_to_ops(void)
{
}
#endif	/* CONFIG_PARAVIRT_GUEST */

#endif	/* !(__ASSEMBLY__) */
#endif /* _E2K_P2V_BOOT_INIT_H */
