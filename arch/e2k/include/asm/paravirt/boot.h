/*
 * E2K boot-time initializtion virtualization for paravirtualized kernel
 *
 * Copyright 2016 Salavat S. Guiliazov (atic@mcst.ru)
 */

#ifndef	_E2K_ASM_PARAVIRT_BOOT_H_
#define	_E2K_ASM_PARAVIRT_BOOT_H_

#ifndef __ASSEMBLY__

#include <linux/types.h>
#include <asm/paravirt/pv_ops.h>
#include <asm/kvm/guest/boot.h>

static inline void
boot_pv_setup_machine_id(bootblock_struct_t *bootblock)
{
	BOOT_PARAVIRT_GET_BOOT_FUNC(boot_setup_machine_id)(bootblock);
}
static inline int
boot_pv_loader_probe_memory(struct node_phys_mem *nodes_phys_mem,
				boot_info_t *bootblock)
{
	return BOOT_PARAVIRT_GET_BOOT_FUNC(boot_loader_probe_memory)
						(nodes_phys_mem, bootblock);
}

static inline e2k_size_t
boot_pv_get_bootblock_size(boot_info_t *bootblock)
{
	return BOOT_PARAVIRT_GET_BOOT_FUNC(boot_get_bootblock_size)
								(bootblock);
}

static inline void
boot_pv_reserve_all_bootmem(bool bsp, boot_info_t *boot_info)
{
	BOOT_PARAVIRT_GET_BOOT_FUNC(boot_reserve_all_bootmem)(bsp, boot_info);
}

static inline void
boot_pv_map_all_bootmem(bool bsp, boot_info_t *boot_info)
{
	BOOT_PARAVIRT_GET_BOOT_FUNC(boot_map_all_bootmem)(bsp, boot_info);
}
static inline void
boot_pv_map_needful_to_equal_virt_area(e2k_addr_t stack_top_addr)
{
	BOOT_PARAVIRT_GET_BOOT_FUNC(boot_map_needful_to_equal_virt_area)
							(stack_top_addr);
}
static inline void
boot_pv_kernel_switch_to_virt(bool bsp, int cpuid,
	void (*boot_init_sequel_func)(bool bsp, int cpuid, int cpus_to_sync))
{
	BOOT_PARAVIRT_GET_BOOT_FUNC(boot_kernel_switch_to_virt)
					(bsp, cpuid, boot_init_sequel_func);
}
static inline void
boot_pv_cpu_relax(void)
{
	BOOT_PARAVIRT_GET_BOOT_FUNC(boot_cpu_relax)();
}

#ifdef	CONFIG_SMP
static inline int
boot_pv_smp_cpu_config(boot_info_t *bootblock)
{
	return BOOT_PARAVIRT_GET_BOOT_FUNC(boot_smp_cpu_config)(bootblock);
}
static inline void
boot_pv_smp_node_config(boot_info_t *bootblock)
{
	BOOT_PARAVIRT_GET_BOOT_FUNC(boot_smp_node_config)(bootblock);
}
#endif	/* CONFIG_SMP */

static inline void
boot_pv_clear_bss(void)
{
	BOOT_PARAVIRT_GET_BOOT_FUNC(boot_clear_bss)();
}
static inline void __init
boot_pv_check_bootblock(bool bsp, bootblock_struct_t *bootblock)
{
	BOOT_PARAVIRT_GET_BOOT_FUNC(boot_check_bootblock)(bsp, bootblock);
}
static inline void
pv_init_terminate_boot_init(bool bsp, int cpuid)
{
	pv_boot_ops.init_terminate_boot_init(bsp, cpuid);
}

static inline void
boot_pv_parse_param(bootblock_struct_t *bootblock)
{
	BOOT_PARAVIRT_GET_BOOT_FUNC(boot_parse_param)(bootblock);
}

#define boot_pv_panic(fmt, args...)	\
		BOOT_PARAVIRT_GET_BOOT_FUNC(do_boot_panic)(fmt, ##args);

extern void native_pv_ops_to_boot_ops(void);
extern void native_boot_pv_ops_to_ops(void);

#ifdef	CONFIG_PARAVIRT_GUEST
/* it is paravirtualized host and guest kernel */
static inline void
boot_setup_machine_id(bootblock_struct_t *bootblock)
{
	boot_pv_setup_machine_id(bootblock);
}
static inline int __init
boot_loader_probe_memory(node_phys_mem_t *nodes_phys_mem,
					boot_info_t *bootblock)
{
	return boot_pv_loader_probe_memory(nodes_phys_mem, bootblock);
}

static inline e2k_size_t __init
boot_get_bootblock_size(boot_info_t *bootblock)
{
	return boot_pv_get_bootblock_size(bootblock);
}

#define	boot_panic(fmt, args...)	boot_pv_panic(fmt, ##args)

static inline void
boot_cpu_relax(void)
{
	boot_pv_cpu_relax();
}

#ifdef	CONFIG_SMP
static inline e2k_size_t __init
boot_smp_cpu_config(boot_info_t *bootblock)
{
	return boot_pv_smp_cpu_config(bootblock);
}

static inline void __init
boot_smp_node_config(boot_info_t *bootblock)
{
	boot_pv_smp_node_config(bootblock);
}
#endif	/* CONFIG_SMP */

static inline void __init
boot_reserve_all_bootmem(bool bsp, boot_info_t *boot_info)
{
	boot_pv_reserve_all_bootmem(bsp, boot_info);
}

static inline void __init
boot_map_all_bootmem(bool bsp, boot_info_t *boot_info)
{
	boot_pv_map_all_bootmem(bsp, boot_info);
}

static inline void __init_recv
boot_map_needful_to_equal_virt_area(e2k_addr_t stack_top_addr)
{
	boot_pv_map_needful_to_equal_virt_area(stack_top_addr);
}

static inline void __init_recv
boot_kernel_switch_to_virt(bool bsp, int cpuid,
	void (*boot_init_sequel_func)(bool bsp, int cpuid, int cpus_to_sync))
{
	boot_pv_kernel_switch_to_virt(bsp, cpuid, boot_init_sequel_func);
}

static inline void __init
init_terminate_boot_init(bool bsp, int cpuid)
{
	pv_init_terminate_boot_init(bsp, cpuid);
}

static inline void __init
boot_parse_param(bootblock_struct_t *bootblock)
{
	boot_pv_parse_param(bootblock);
}

static inline void __init
boot_clear_bss(void)
{
	boot_pv_clear_bss();
}
static inline void __init
boot_check_bootblock(bool bsp, bootblock_struct_t *bootblock)
{
	boot_pv_check_bootblock(bsp, bootblock);
}

#endif	/* CONFIG_PARAVIRT_GUEST */

#endif /* ! __ASSEMBLY__ */

#endif	/* _E2K_ASM_PARAVIRT_BOOT_H_ */
