/*
 * Mapping/unmapping of kernel virtual area on the NUMA node.
 * Each node can have own page table to access to own copy of
 * kernel duplicated text and data
 */

#include <linux/vmalloc.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <asm/io.h>
#include <asm/pgtable.h>
#include <asm/pgalloc.h>
#include <asm/cacheflush.h>
#include <asm/tlbflush.h>

#undef	DebugNM
#undef	DEBUG_NODE_MAP_MODE
#define	DEBUG_NODE_MAP_MODE	0	/* Map kernel virtual memory on node */
#define DebugNM(...)		DebugPrint(DEBUG_NODE_MAP_MODE ,##__VA_ARGS__)

#undef	DebugNUMA
#undef	DEBUG_NUMA_MODE
#define	DEBUG_NUMA_MODE		0	/* NUMA */
#define DebugNUMA(...)		DebugPrint(DEBUG_NUMA_MODE ,##__VA_ARGS__)

#undef	DebugNUMAM
#undef	DEBUG_NUMA_MAP_MODE
#define	DEBUG_NUMA_MAP_MODE	0	/* NUMA mapping */
#define DebugNUMAM(...)		DebugPrint(DEBUG_NUMA_MAP_MODE ,##__VA_ARGS__)

static inline pte_t *node_pte_alloc_k(int nid, pmd_t *pmd,
						unsigned long address)
{
	if (pmd_none(*pmd)) {
		if (mem_init_done)
			return node_pte_alloc_kernel(nid, pmd, address);
		else
			return node_early_pte_alloc(nid, pmd, address);
	}
	return pte_offset_kernel(pmd, address);
}

static inline pmd_t *node_pmd_alloc_k(int nid, pud_t *pud,
						unsigned long address)
{
	if (pud_none(*pud)) {
		if (mem_init_done)
			return node_pmd_alloc_kernel(nid, pud, address);
		else
			return node_early_pmd_alloc(nid, pud, address);
	}
	return pmd_offset_kernel(pud, address);
}

static inline pud_t *node_pud_alloc_k(int nid, pgd_t *pgd,
						unsigned long address)
{
	if (pgd_none(*pgd)) {
		if (mem_init_done)
			return node_pud_alloc_kernel(nid, pgd, address);
		else
			return node_early_pud_alloc(nid, pgd, address);
	}
	return pud_offset_kernel(pgd, address);
}

static inline int node_map_vm_area_pte(int nid_to,
			pmd_t *pmd_from, pmd_t *pmd_to,
			unsigned long address, unsigned long end)
{
	pte_t *pte_from, *pte_to;

	DebugNM("started for pmd from 0x%p == 0x%lx, "
		"pmd to 0x%p = 0x%lx, addr 0x%lx, end 0x%lx\n",
		pmd_from, pmd_val(*pmd_from), pmd_to, pmd_val(*pmd_to),
		address, end);
	pte_from = pte_offset_kernel(pmd_from, address);
	if (pte_none(*pte_from)) {
		printk("CPU #%d node_map_vm_area_pte() pte from is none "
			"0x%p = 0x%lx\n",
			smp_processor_id(), pte_from, pte_val(*pte_from));
		BUG();
	}
	pte_to = node_pte_alloc_k(nid_to, pmd_to, address);
	if (!pte_to)
		return -ENOMEM;
	if (address >= end)
		BUG();
	do {
		DebugNM("addr 0x%lx, pte from 0x%p = "
			"0x%lx, pte to 0x%p = 0x%lx\n",
			address, pte_from, pte_val(*pte_from),
			pte_to, pte_val(*pte_to));
		if (!pte_none(*pte_to)) {
			printk("node_map_vm_area_pte(): page already exists, "
				"addr 0x%lx pte 0x%p == 0x%lx\n",
				address, pte_to, pte_val(*pte_to));
			BUG();
		}
		set_pte(pte_to, *pte_from);
	} while (pte_from ++, pte_to ++, address += PAGE_SIZE, address != end);
	return 0;
}

static inline int node_map_vm_area_pmd(int nid_to,
			pud_t * pud_from, pud_t *pud_to,
			unsigned long address, unsigned long end)
{
	pmd_t *pmd_from, *pmd_to;
	unsigned long next;

	DebugNM("started for pud from 0x%p == 0x%lx, pud to 0x%p = 0x%lx, addr 0x%lx, end 0x%lx\n",
		pud_from, pud_val(*pud_from), pud_to, pud_val(*pud_to),
		address, end);
	pmd_from = pmd_offset_kernel(pud_from, address);
	if (pmd_none(*pmd_from))
		BUG();
	pmd_to = node_pmd_alloc_k(nid_to, pud_to, address);
	if (!pmd_to)
		return -ENOMEM;
	if (address >= end)
		BUG();
	do {
		DebugNM("addr 0x%lx, pmd from 0x%p = 0x%lx, pmd to 0x%p = 0x%lx\n",
			address, pmd_from, pmd_val(*pmd_from),
			pmd_to, pmd_val(*pmd_to));
		next = pmd_addr_end(address, end);
		if (pmd_large(*pmd_from)) {
			pte_t *pte = (pte_t *)pmd_offset_kernel(pud_from,
					(address & LARGE_PAGE_MASK));
			DebugNM("detected large page pte 0x%p = 0x%lx for address 0x%lx\n",
				pte, pte_val(*pte), address);
			set_pte((pte_t *)pmd_to, *pte);
			continue;
		}
		if (node_map_vm_area_pte(nid_to, pmd_from, pmd_to,
							address, next))
			return -ENOMEM;
	} while (pmd_from ++, pmd_to ++, address = next, address != end);
	return 0;
}

static inline int node_map_vm_area_pud(int nid_to,
			pgd_t *dir_from, pgd_t *dir_to,
			unsigned long address, unsigned long end)
{
	pud_t *pud_from, *pud_to;
	unsigned long next;

	DebugNM("started for pgd from 0x%p = 0x%lx, "
		"pgd to 0x%p = 0x%lx, addr 0x%lx, end 0x%lx\n",
		dir_from, pgd_val(*dir_from), dir_to, pgd_val(*dir_to),
		address, end);
	pud_from = pud_offset_kernel(dir_from, address);
	if (pud_none(*pud_from))
		BUG();
	pud_to = node_pud_alloc_k(nid_to, dir_to, address);
	if (!pud_to)
		return -ENOMEM;
	if (address >= end)
		BUG();
	do {
		DebugNM("addr 0x%lx, pud from 0x%p = "
			"0x%lx, pud to 0x%p = 0x%lx\n",
			address, pud_from, pud_val(*pud_from),
			pud_to, pud_val(*pud_to));
		next = pud_addr_end(address, end);
		if (node_map_vm_area_pmd(nid_to, pud_from, pud_to,
							address, next))
			return -ENOMEM;
	} while (pud_from ++, pud_to ++, address = next, address != end);
	return 0;
}

static int __ref node_do_map_vm_area(int nid_from, int nid_to,
				unsigned long address, unsigned long size)
{
	pgd_t *dir_from, *dir_to;
	unsigned long end = address + size;
	unsigned long next;
	int ret = 0;

	DebugNUMA("started on node #%d, node from #%d "
		"node to #%d, addr 0x%lx, size 0x%lx\n",
		numa_node_id(), nid_from, nid_to, address, size);
	if (address >= end)
		BUG();
	if (nid_from == nid_to)
		BUG();
	dir_from = node_pgd_offset_kernel(nid_from, address);
	if (pgd_none(*dir_from))
		BUG();
	dir_to = node_pgd_offset_kernel(nid_to, address);
	do {
		DebugNM("addr 0x%lx, pgd from 0x%p = "
			"0x%lx, pgd to 0x%p = 0x%lx\n",
			address, dir_from, pgd_val(*dir_from),
			dir_to, pgd_val(*dir_to));
		next = pgd_addr_end(address, end);
		if (node_map_vm_area_pud(nid_to, dir_from, dir_to,
				address, next)) {
			ret = -ENOMEM;
			break;
		}
	} while (dir_from ++, dir_to ++, address = next, address != end);
	return ret;
}

int node_map_vm_area(int nid_from, nodemask_t nodes_to,
			unsigned long address, unsigned long size)
{
	int dup_nid_from;
	int nid_to;
	int ret = 0;

	DebugNUMAM("started on node #%d to map from #%d "
		"to 0x%lx addr 0x%lx, size 0x%lx\n",
		numa_node_id(), nid_from, nodes_addr(nodes_to)[0],
		address, size);
	dup_nid_from = node_dup_kernel_nid(nid_from);
	if (dup_nid_from != nid_from) {
		DebugNUMAM("node #%d has not own copy and "
			"use copy of node #%d\n",
			nid_from, dup_nid_from);
	}
	for_each_node_mask(nid_to, nodes_to) {
		if (!node_has_dup_kernel(nid_to))
			continue;
		if (nid_to == dup_nid_from)
			continue;
		ret = node_do_map_vm_area(dup_nid_from, nid_to, address, size);
		if (ret)
			break;
	}
	return ret;
}

static void node_unmap_vm_area_pte(int nid, pmd_t *pmd,
			unsigned long addr, unsigned long end)
{
	pte_t *pte;

	pte = pte_offset_kernel(pmd, addr);
	do {
		pte_t ptent = ptep_get_and_clear((&init_mm), addr, pte);
		WARN_ON(!pte_none(ptent) && !pte_present(ptent));
	} while (pte++, addr += PAGE_SIZE, addr != end);
}

static inline void node_unmap_vm_area_pmd(int nid, pud_t *pud,
				unsigned long addr, unsigned long end)
{
	pmd_t *pmd;
	unsigned long next;

	pmd = pmd_offset_kernel(pud, addr);
	do {
		next = pmd_addr_end(addr, end);
		if (pmd_none_or_clear_bad_kernel(pmd))
			continue;
		if (pmd_large(*pmd)) {
			pte_t *pte = (pte_t *) pmd_offset_kernel(pud,
					(addr & LARGE_PAGE_MASK));
			DebugNM("detected large page pte 0x%p = 0x%lx for address 0x%lx\n",
				pte, pte_val(*pte), addr);
			ptep_get_and_clear((&init_mm), addr, pte);
			continue;
		}
		node_unmap_vm_area_pte(nid, pmd, addr, next);
	} while (pmd++, addr = next, addr != end);
}

static inline void node_unmap_vm_area_pud(int nid, pgd_t *pgd,
				unsigned long addr, unsigned long end)
{
	pud_t *pud;
	unsigned long next;

	pud = pud_offset_kernel(pgd, addr);
	do {
		next = pud_addr_end(addr, end);
		if (pud_none_or_clear_bad_kernel(pud))
			continue;
		node_unmap_vm_area_pmd(nid, pud, addr, next);
	} while (pud++, addr = next, addr != end);
}

static void
node_do_unmap_vm_area(int nid, unsigned long address, unsigned long size)
{
	pgd_t *pgd;
	unsigned long next;
	unsigned long addr = address;
	unsigned long end = address + size;

	DebugNUMA("started on node #%d for "
		"node #%d, addr 0x%lx, size 0x%lx\n",
		numa_node_id(), nid, address, size);
	pgd = node_pgd_offset_kernel(nid, addr);
	do {
		next = pgd_addr_end(addr, end);
		if (pgd_none_or_clear_bad_kernel(pgd))
			continue;
		node_unmap_vm_area_pud(nid, pgd, addr, next);
	} while (pgd++, addr = next, addr != end);
}

nodemask_t inline get_node_dup_kernel_map(nodemask_t nodes)
{
	nodemask_t dup_nodes = nodes;
	int nid;
	int dup_nid;

	for_each_node_mask(nid, nodes) {
		if (node_has_dup_kernel(nid))
			continue;
		dup_nid = node_dup_kernel_nid(nid);
		if (dup_nid != nid) {
			node_clear(nid, dup_nodes);
			node_set(dup_nid, dup_nodes);
		}
	}
	return dup_nodes;
}

void
node_unmap_kernel_vm_area_noflush(nodemask_t nodes, unsigned long start,
				unsigned long end)
{
	unsigned long size = end - start;
	int nid;

	BUG_ON(start >= end);
	/*
	 * If the function will be used for arbitrary nodes map (not only
	 * whole node_has_dup_kernel_map or without current node
	 * then need uncomment following function call
	 */
	/* nodes = get_node_dup_kernel_map(nodes); */
	for_each_node_mask(nid, nodes) {
		if (!node_has_dup_kernel(nid))
			continue;
		node_do_unmap_vm_area(nid, start, size);
	}
}

void node_unmap_vm_area_noflush(nodemask_t nodes, struct vm_struct *area)
{
	unsigned long address = (unsigned long) area->addr;
	unsigned long end = address + area->size;

	node_unmap_kernel_vm_area_noflush(nodes, address, end);
}

void node_unmap_kmem_area(nodemask_t nodes,
				unsigned long address, unsigned long size)
{
	unsigned long end = address + size;
	int nid;

	BUG_ON(address >= end);
	for_each_node_mask(nid, nodes) {
		if (!node_has_dup_kernel(nid))
			continue;
		node_do_unmap_vm_area(nid, address, size);
	}
}
