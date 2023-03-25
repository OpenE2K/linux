/*
 * E2K boot-time initializtion virtualization for KVM guest
 *
 * Copyright 2011 Salavat S. Guiliazov (atic@mcst.ru)
 */

#ifndef	_E2K_KVM_GUEST_BOOT_H_
#define	_E2K_KVM_GUEST_BOOT_H_

#ifndef __ASSEMBLY__
#include <linux/types.h>

#include <asm/e2k_api.h>
#include <asm/bootinfo.h>
#include <asm/page.h>

extern void boot_kvm_setup_machine_id(bootblock_struct_t *bootblock);
extern int __init boot_kvm_probe_memory(node_phys_mem_t *nodes_phys_mem,
						boot_info_t *bootblock);
extern e2k_size_t __init boot_kvm_get_bootblock_size(boot_info_t *bblock);

extern void boot_kvm_panic(const char *fmt_v, ...);
extern void __init_recv boot_kvm_cpu_relax(void);

#ifdef	CONFIG_SMP
/*
 * redefine for guest: number of loops in each iteration of waiting for
 * synchronization completion
 */
#define	BOOT_WAITING_FOR_SYNC_LOOPS	(NR_CPUS * 160)

extern int __init_recv boot_kvm_smp_cpu_config(boot_info_t *bootblock);
extern void __init_recv boot_kvm_smp_node_config(boot_info_t *bootblock);
#endif	/* CONFIG_SMP */

extern void __init boot_kvm_reserve_all_bootmem(bool bsp,
					boot_info_t *boot_info);
extern void __init boot_kvm_map_all_bootmem(bool bsp, boot_info_t *boot_info);
extern void __init_recv boot_kvm_map_needful_to_equal_virt_area(
						e2k_addr_t stack_top_addr);
extern void __init_recv boot_kvm_switch_to_virt(bool bsp, int cpuid,
			void (*boot_init_sequel_func)(bool bsp,
							int cpuid, int cpus));
extern void __init init_kvm_terminate_boot_init(bool bsp, int cpuid);
extern void __init boot_kvm_parse_param(bootblock_struct_t *bootblock);
extern void __init boot_kvm_clear_bss(void);
extern void __init boot_kvm_check_bootblock(bool bsp,
				bootblock_struct_t *bootblock);

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is pure guest kernel (not paravirtualized based on pv_ops */
static inline void
boot_setup_machine_id(bootblock_struct_t *bootblock)
{
	boot_kvm_setup_machine_id(bootblock);
}
static inline int __init
boot_loader_probe_memory(node_phys_mem_t *nodes_phys_mem,
					boot_info_t *bootblock)
{
	return boot_kvm_probe_memory(nodes_phys_mem, bootblock);
}

static inline e2k_size_t __init
boot_get_bootblock_size(boot_info_t *bootblock)
{
	return boot_kvm_get_bootblock_size(bootblock);
}

#define	boot_panic(fmt, args...)	boot_kvm_panic(fmt, ##args)

static inline void
boot_cpu_relax(void)
{
	boot_kvm_cpu_relax();
}

#ifdef	CONFIG_SMP
static inline e2k_size_t __init
boot_smp_cpu_config(boot_info_t *bootblock)
{
	return boot_kvm_smp_cpu_config(bootblock);
}

static inline void __init
boot_smp_node_config(boot_info_t *bootblock)
{
	boot_kvm_smp_node_config(bootblock);
}
#endif	/* CONFIG_SMP */

static inline void __init
boot_reserve_all_bootmem(bool bsp, boot_info_t *boot_info)
{
	boot_kvm_reserve_all_bootmem(bsp, boot_info);
}

static inline void __init
boot_map_all_bootmem(bool bsp, boot_info_t *boot_info)
{
	boot_kvm_map_all_bootmem(bsp, boot_info);
}

static inline void __init_recv
boot_map_needful_to_equal_virt_area(e2k_addr_t stack_top_addr)
{
	boot_kvm_map_needful_to_equal_virt_area(stack_top_addr);
}

static inline void __init_recv
boot_kernel_switch_to_virt(bool bsp, int cpuid,
	void (*boot_init_sequel_func)(bool bsp, int cpuid, int cpus_to_sync))
{
	boot_kvm_switch_to_virt(bsp, cpuid, boot_init_sequel_func);
}

static inline void __init
init_terminate_boot_init(bool bsp, int cpuid)
{
	init_kvm_terminate_boot_init(bsp, cpuid);
}

static inline void __init
boot_parse_param(bootblock_struct_t *bootblock)
{
	boot_kvm_parse_param(bootblock);
}

static inline void __init
boot_clear_bss(void)
{
	boot_kvm_clear_bss();
}
static inline void __init
boot_check_bootblock(bool bsp, bootblock_struct_t *bootblock)
{
	boot_kvm_check_bootblock(bsp, bootblock);
}

/* pv_ops does not used in native host/guest mode */
static inline void native_pv_ops_to_boot_ops(void)
{
}
static inline void native_boot_pv_ops_to_ops(void)
{
}

#endif	/* CONFIG_GUEST_KERNEL */

#endif /* ! __ASSEMBLY__ */

#endif	/* _E2K_KVM_GUEST_BOOT_H_ */
