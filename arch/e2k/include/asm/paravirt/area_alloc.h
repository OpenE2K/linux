#ifndef __ASM_PARAVIRT_AREA_ALLOC_H
#define __ASM_PARAVIRT_AREA_ALLOC_H

#ifdef __KERNEL__

#include <linux/types.h>
#include <asm/paravirt/pv_ops.h>

static inline int
pv_register_kernel_hw_stack(e2k_addr_t stack_base, e2k_size_t stack_size)
{
	if (pv_cpu_ops.register_kernel_hw_stack == NULL)
		return 0;
	return pv_cpu_ops.register_kernel_hw_stack(stack_base, stack_size);
}

static inline int
boot_pv_register_kernel_hw_stack(e2k_addr_t stack_base, e2k_size_t stack_size)
{
	if (BOOT_PARAVIRT_GET_CPU_FUNC(register_kernel_hw_stack) == NULL)
		return 0;
	return BOOT_PARAVIRT_GET_CPU_FUNC(
			register_kernel_hw_stack)(stack_base, stack_size);
}

static inline int
pv_register_kernel_data_stack(e2k_addr_t stack_base, e2k_size_t stack_size)
{
	if (pv_cpu_ops.register_kernel_data_stack == NULL)
		return 0;
	return pv_cpu_ops.register_kernel_data_stack(stack_base, stack_size);
}

static inline int
boot_pv_register_kernel_data_stack(e2k_addr_t stack_base, e2k_size_t stack_size)
{
	if (BOOT_PARAVIRT_GET_CPU_FUNC(register_kernel_data_stack) == NULL)
		return 0;
	return BOOT_PARAVIRT_GET_CPU_FUNC(
			register_kernel_data_stack)(stack_base, stack_size);
}

static inline void
pv_unregister_kernel_hw_stack(e2k_addr_t stack_base, e2k_size_t stack_size)
{
	if (pv_cpu_ops.unregister_kernel_hw_stack == NULL)
		return;
	pv_cpu_ops.unregister_kernel_hw_stack(stack_base, stack_size);
}

static inline void
boot_pv_unregister_kernel_hw_stack(e2k_addr_t stack_base, e2k_size_t stack_size)
{
	if (BOOT_PARAVIRT_GET_CPU_FUNC(unregister_kernel_hw_stack) == NULL)
		return;
	BOOT_PARAVIRT_GET_CPU_FUNC(
			unregister_kernel_hw_stack)(stack_base, stack_size);
}

static inline void
pv_unregister_kernel_data_stack(e2k_addr_t stack_base, e2k_size_t stack_size)
{
	if (pv_cpu_ops.unregister_kernel_hw_stack == NULL)
		return;
	pv_cpu_ops.unregister_kernel_hw_stack(stack_base, stack_size);
}

static inline void
boot_pv_unregister_kernel_data_stack(e2k_addr_t stack_base,
					e2k_size_t stack_size)
{
	if (BOOT_PARAVIRT_GET_CPU_FUNC(unregister_kernel_data_stack) == NULL)
		return;
	BOOT_PARAVIRT_GET_CPU_FUNC(
			unregister_kernel_data_stack)(stack_base, stack_size);
}

static inline int
pv_kmem_area_host_chunk(e2k_addr_t stack_base, e2k_size_t stack_size,
				int hw_stack)
{
	if (pv_cpu_ops.kmem_area_host_chunk == NULL)
		return 0;
	return pv_cpu_ops.kmem_area_host_chunk(stack_base, stack_size,
							hw_stack);
}

static inline void
pv_kmem_area_unhost_chunk(e2k_addr_t stack_base, e2k_size_t stack_size)
{
	if (pv_cpu_ops.kmem_area_unhost_chunk == NULL)
		return;
	pv_cpu_ops.kmem_area_unhost_chunk(stack_base, stack_size);
}

#ifdef	CONFIG_PARAVIRT_GUEST
static inline int register_kernel_hw_stack(e2k_addr_t stack_base,
						e2k_size_t stack_size)
{
	return pv_register_kernel_hw_stack(stack_base, stack_size);
}
static inline int register_kernel_data_stack(e2k_addr_t stack_base,
						e2k_size_t stack_size)
{
	return pv_register_kernel_data_stack(stack_base, stack_size);
}
static inline int boot_register_kernel_hw_stack(e2k_addr_t stack_base,
						e2k_size_t stack_size)
{
	return boot_pv_register_kernel_hw_stack(stack_base, stack_size);
}
static inline int boot_register_kernel_data_stack(e2k_addr_t stack_base,
						e2k_size_t stack_size)
{
	return boot_pv_register_kernel_data_stack(stack_base, stack_size);
}
static inline void unregister_kernel_hw_stack(e2k_addr_t stack_base,
						e2k_size_t stack_size)
{
	pv_unregister_kernel_hw_stack(stack_base, stack_size);
}
static inline void unregister_kernel_data_stack(e2k_addr_t stack_base,
						e2k_size_t stack_size)
{
	pv_unregister_kernel_data_stack(stack_base, stack_size);
}
static inline void boot_unregister_kernel_hw_stack(e2k_addr_t stack_base,
						e2k_size_t stack_size)
{
	boot_pv_unregister_kernel_hw_stack(stack_base, stack_size);
}
static inline void boot_unregister_kernel_data_stack(e2k_addr_t stack_base,
						e2k_size_t stack_size)
{
	boot_pv_unregister_kernel_data_stack(stack_base, stack_size);
}
static inline int
kmem_area_host_chunk(e2k_addr_t stack_base,
				e2k_size_t stack_size, int hw_flag)
{
	return pv_kmem_area_host_chunk(stack_base, stack_size, hw_flag);
}
static inline void
kmem_area_unhost_chunk(e2k_addr_t stack_base, e2k_size_t stack_size)
{
	pv_kmem_area_unhost_chunk(stack_base, stack_size);
}
#endif	/* CONFIG_PARAVIRT_GUEST */

#endif	/* __KERNEL__ */

#endif	/* __ASM_PARAVIRT_AREA_ALLOC_H */
