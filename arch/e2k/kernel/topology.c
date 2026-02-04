/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/cpu.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/node.h>
#include <linux/init.h>
#include <linux/memblock.h>
#include <linux/nodemask.h>
#include <linux/slab.h>
#include <linux/topology.h>
#include <asm/cpu.h>
#include <asm/mmu_context.h>
#include <linux/crash_dump.h>

static struct cpu *sysfs_cpus;


int __ref arch_register_cpu(int num)
{
#ifdef CONFIG_HOTPLUG_CPU
	sysfs_cpus[num].hotpluggable = 1;
#endif

	return register_cpu(&sysfs_cpus[num], num);
}

#ifdef CONFIG_HOTPLUG_CPU
EXPORT_SYMBOL(arch_register_cpu);

void arch_unregister_cpu(int num)
{
	return unregister_cpu(&sysfs_cpus[num]);
}
EXPORT_SYMBOL(arch_unregister_cpu);
#endif

/* maps the cpu to the sched domain representing multi-core */
const struct cpumask *cpu_coregroup_mask(int cpu)
{
	return cpumask_of_node(cpu_to_node(cpu));
}

static int __init topology_init(void)
{
	int i, err;

	sysfs_cpus = kmalloc(sizeof(sysfs_cpus[0]) * NR_CPUS, GFP_KERNEL);
	if (!sysfs_cpus)
		return -ENOMEM;
	memset(sysfs_cpus, 0, sizeof(sysfs_cpus[0]) * NR_CPUS);

	for_each_possible_cpu(i) {
		if ((err = arch_register_cpu(i)))
			return err;
	}

	return 0;
}
subsys_initcall(topology_init);

int cpuid_to_cpu(int cpuid)
{
	int cpu = 0;

	for (; cpu < NR_CPUS; cpu++)
		if (cpu_to_cpuid(cpu) == cpuid)
			return cpu;

	BUG();
}

#ifdef CONFIG_NUMA

s16 __apicid_to_node[NR_CPUS] = {
	[0 ... NR_CPUS-1] = NUMA_NO_NODE
};

/*
 * This version of cpu_to_node() will work earlier but is much slower
 */
int __init early_cpu_to_node(int cpu)
{
	int apicid = cpu_to_cpuid(cpu);

	BUG_ON(apicid >= ARRAY_SIZE(__apicid_to_node));
	BUG_ON(__apicid_to_node[apicid] == NUMA_NO_NODE);

	return __apicid_to_node[apicid];
}

static void zero_page_duplicate(void)
{
	int node;

	/* Duplicate zero page */
	kernel_image_duplicate_page_range(empty_zero_page,
			sizeof(empty_zero_page), false);

	/* Initialize pointers to zero page */
	for_each_node_state(node, N_MEMORY) {
		phys_addr_t pa;

		pa = node_kernel_address_to_phys(node,
				(unsigned long) empty_zero_page);
		BUG_ON(IS_ERR_VALUE(pa));

		zero_page_nid_to_pfn[node] = PHYS_PFN(pa);
		zero_page_nid_to_page[node] = phys_to_page(pa);
	}

	/* Nodes without memory will use zero pages from other nodes */
	for_each_node(node) {
		if (node_state(node, N_MEMORY))
			continue;

		zero_page_nid_to_pfn[node] =
				zero_page_nid_to_pfn[first_memory_node];
		zero_page_nid_to_page[node] =
				zero_page_nid_to_page[first_memory_node];
	}
}

static int __init duplicate_kernel_image(void)
{
	unsigned long start_pfn, end_pfn;
	int i;

	/* Check this is not panic kernel, where only one node available */
	if (is_kdump_kernel())
		return 0;

	/* These are the same areas as in boot_map_kernel_image() */
	kernel_image_duplicate_page_range(_stext,
			_etext - _stext, false);
	kernel_image_duplicate_page_range(__start_rodata_notes,
			__end_rodata_notes - __start_rodata_notes, false);
	kernel_image_duplicate_page_range(__special_data_begin,
			__special_data_end - __special_data_begin, true);
	kernel_image_duplicate_page_range(__node_data_start,
			__node_data_end - __node_data_start, false);
	kernel_image_duplicate_page_range(__common_data_begin,
			__common_data_end - __common_data_begin, true);
	kernel_image_duplicate_page_range(__init_text_begin,
			__init_text_end - __init_text_begin, false);
	kernel_image_duplicate_page_range(__init_data_begin,
			__init_data_end - __init_data_begin, true);

	for_each_mem_pfn_range(i, MAX_NUMNODES, &start_pfn, &end_pfn, NULL) {
		unsigned long start, end;

		/* Duplicate PAGE_OFFSET mapping */
		start = (unsigned long) pfn_to_virt(start_pfn);
		end = (unsigned long) pfn_to_virt(end_pfn);
		kernel_image_duplicate_page_range((void *) start, end - start, true);

		/* Duplicate sparse vmemmap mapping */
		start = (unsigned long) pfn_to_page(start_pfn);
		end = (unsigned long) pfn_to_page(end_pfn);
		start = round_down(start, PAGE_SIZE);
		end = round_up(end, PAGE_SIZE);
		kernel_image_duplicate_page_range((void *) start, end - start, true);
	}

	zero_page_duplicate();

	return 0;
}
arch_initcall(duplicate_kernel_image);

# ifdef CONFIG_E2K_MODULES_DUPLICATION
static int __init duplicate_pgds(void)
{
	/* Check this is not panic kernel, where only one node available */
	if (is_kdump_kernel())
		return 0;

	/*
	 * We duplicate PGD pages now to initialize init_mm.context.pgds_nodemask
	 * as early as possible. All following memory allocations in modules area
	 * (including the ones in duplicate_preallocated_pgds_for_modules_area()
	 * and an allocation from ptp_classifier_init()) rely on initialized
	 * pgds_nodemask.
	 */
	WARN_ON(duplicate_pgds_for_modules_area());

	/*
	 * PUD pages in page table for modules area were allocated in
	 * preallocate_dynamic_pgds(). Here we duplicate them.
	 *
	 * Current implementation of NUMA duplication for modules area
	 * implies that this area should always be fully duplicated on the
	 * nodes from init_mm.context.pgds_nodemask. It requires that nothing
	 * was mapped to modules area between preallocate_dynamic_pgds() and
	 * current function. Otherwise, we either should duplicate everything
	 * mapped right now or we will once find not-none entries in
	 * PUD pages while duplicating. The first way is a bit challenging
	 * (it requires separate page table traversal), so we just hope that
	 * nothing is yet mapped to modules area and call a special function
	 * to duplicate preallocated PUD pages. It will print a warning if it
	 * failed to duplicate the pages or if it found any mapping to modules
	 * area.
	 */
	return WARN_ON(duplicate_preallocated_pgds_for_modules_area());
}
/*
 * Duplicate PGD pages and preallocated PUD pages as early as possible,
 * because BPF programs can be mapped to modules area from core_initcall().
 */
early_initcall(duplicate_pgds);
# endif /* CONFIG_E2K_MODULES_DUPLICATION */


# ifdef CONFIG_E2K_MODULES_DUPLICATION
static inline int is_duplicated_modules_addr(unsigned long addr)
{
	return addr >= MODULES_VADDR && addr < MODULES_END;
}
# else /* !CONFIG_E2K_MODULES_DUPLICATION */
static inline int is_duplicated_modules_addr(unsigned long addr)
{
	return false;
}
# endif /* CONFIG_E2K_MODULES_DUPLICATION */

int is_duplicated_address(unsigned long addr)
{
	/* Code is not yet duplicated this early in the boot process */
	if (system_state == SYSTEM_BOOTING)
		return 0;

	return addr >= (unsigned long) _stext &&
				addr < (unsigned long) _etext ||
			addr >= (unsigned long) __start_rodata_notes &&
				addr < (unsigned long) __end_rodata_notes ||
			addr >= (unsigned long) __special_data_begin &&
				addr < (unsigned long) __special_data_end ||
			addr >= (unsigned long) __node_data_start &&
				addr < (unsigned long) __node_data_end ||
			addr >= (unsigned long) __common_data_begin &&
				addr < (unsigned long) __common_data_end ||
			addr >= (unsigned long) __init_text_begin &&
				addr < (unsigned long) __init_text_end ||
			addr >= (unsigned long) __init_data_begin &&
				addr < (unsigned long) __init_data_end ||
			addr >= PAGE_OFFSET && addr < PAGE_OFFSET + MAX_PM_SIZE ||
			addr >= VMEMMAP_START && addr < VMEMMAP_END ||
			is_duplicated_modules_addr(addr);
}

# ifdef CONFIG_E2K_MODULES_DUPLICATION
static inline int is_duplicated_modules_code(unsigned long ip)
{
	/* Guess caller knows that 'ip' is code */
	return is_duplicated_modules_addr(ip);
}
# else /* !CONFIG_E2K_MODULES_DUPLICATION */
static inline int is_duplicated_modules_code(unsigned long ip)
{
	return false;
}
# endif /* CONFIG_E2K_MODULES_DUPLICATION */

int is_duplicated_code(unsigned long ip)
{
	/* Code is not yet duplicated this early in the boot process */
	if (system_state == SYSTEM_BOOTING)
		return 0;

	return ip >= (unsigned long) _stext && ip < (unsigned long) _etext ||
		is_duplicated_modules_code(ip);
}
#endif /* CONFIG_NUMA */

#ifdef CONFIG_E2K_MODULES_DUPLICATION

/* hack from kernel/module/internal.h */
# ifndef CONFIG_ARCH_WANTS_MODULES_DATA_IN_VMALLOC
#  define data_layout core_layout
# endif

static void duplicate_module_section_pages(void *start, unsigned int size, struct module *mod)
{
	duplicate_module_pages(start, size, &mod->arch.duplicated_pages);
}

static void duplicate_module_memory(struct module *mod)
{
	const struct module_layout *cl = &mod->core_layout, *dl = &mod->data_layout;

	/* Duplicate text section pages */
	duplicate_module_section_pages(cl->base, cl->text_size, mod);

	/* Duplicate rodata section pages */
	duplicate_module_section_pages(dl->base + dl->text_size, dl->ro_size - dl->text_size, mod);

	/*
	 * Section ro-after-init is duplicated later, when the module comes to
	 * MODULE_STATE_LIVE state.
	 */

	/*
	 * No need to duplicate data section: this section is not read-only, so its
	 * last level pages should not be duplicated. Page table of this section was
	 * duplicated during module memory mapping.
	 */
}

static void duplicate_module_ro_after_init_memory(struct module *mod)
{
	const struct module_layout *dl = &mod->data_layout;

	/* Duplicate ro-after-init section pages */
	duplicate_module_section_pages(dl->base + dl->ro_size,
			dl->ro_after_init_size - dl->ro_size, mod);
}

static void deduplicate_module_section_pages(void *start, unsigned int size, struct module *mod)
{
	deduplicate_module_pages(start, size, &mod->arch.duplicated_pages);
}

static void deduplicate_module_memory(struct module *mod)
{
	const struct module_layout *cl = &mod->core_layout, *dl = &mod->data_layout;

	/* Deduplicate text section pages */
	deduplicate_module_section_pages(cl->base, cl->text_size, mod);

	/* Deduplicate rodata section pages */
	deduplicate_module_section_pages(dl->base + dl->text_size,
			dl->ro_size - dl->text_size, mod);

	/* Deduplicate ro-after-init section pages */
	deduplicate_module_section_pages(dl->base + dl->ro_size,
			dl->ro_after_init_size - dl->ro_size, mod);

	/*
	 * No need to deduplicate data section: last level pages are not duplicated,
	 * and duplicated page table is handled during unmapping.
	 */

	/* Check that all module's duplicated pages were freed */
	WARN(!list_empty(&mod->arch.duplicated_pages),
	     "List with duplicated pages for module '%s' is not empty; it is a memory leak",
	     mod->name);
}

static int numa_duplication_module_callback(struct notifier_block *nb, unsigned long action,
					    void *data)
{
	struct module *mod = data;

	/* Check this is not panic kernel, where only one node available */
	if (is_kdump_kernel())
		return 0;

	switch (action) {
	case MODULE_STATE_COMING:
		duplicate_module_memory(mod);
		return NOTIFY_OK;
	case MODULE_STATE_LIVE:
		duplicate_module_ro_after_init_memory(mod);
		return NOTIFY_OK;
	case MODULE_STATE_GOING:
		deduplicate_module_memory(mod);
		return NOTIFY_OK;
	default:
		return NOTIFY_DONE;
	}
}

static struct notifier_block numa_duplication_module_nb = {
	.notifier_call = numa_duplication_module_callback
};

static __init int numa_duplication_init_module(void)
{
	return register_module_notifier(&numa_duplication_module_nb);
}
arch_initcall(numa_duplication_init_module);
#endif /* CONFIG_E2K_MODULES_DUPLICATION */
