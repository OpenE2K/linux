/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_SWIOTLB_H
#define __LINUX_SWIOTLB_H

#include <linux/dma-direction.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/limits.h>

struct device;
struct page;
struct scatterlist;

enum swiotlb_force {
	SWIOTLB_NORMAL,		/* Default - depending on HW DMA mask etc. */
	SWIOTLB_FORCE,		/* swiotlb=force */
	SWIOTLB_NO_FORCE,	/* swiotlb=noforce */
};

/*
 * Maximum allowable number of contiguous slabs to map,
 * must be a power of 2.  What is the appropriate value ?
 * The complexity of {map,unmap}_single is linearly dependent on this value.
 */
#define IO_TLB_SEGSIZE	128

/*
 * log of the size of each IO TLB slab.  The number of slabs is command line
 * controllable.
 */
#define IO_TLB_SHIFT 11
#define IO_TLB_SIZE (1 << IO_TLB_SHIFT)

#if defined(CONFIG_E2K) && defined(CONFIG_NUMA)
# define SWIOTLB_NODE_CYCLE_BEGIN	\
	for_each_online_node(node) {	\
		if (!NODE_DATA(node))	\
			continue;

# define SWIOTLB_NODE_CYCLE_END	\
	}

static inline int swiotlb_node(struct device *dev)
{
	int node = dev->numa_node;

	if (node < 0 || node >= MAX_NUMNODES || !node_online(node))
		node = first_online_node;

	return node;
}
#endif

#if defined(CONFIG_E2K) && defined(CONFIG_NUMA)
extern void swiotlb_init(int verbose, int node);
int swiotlb_init_with_tbl(char *tlb, unsigned long nslabs, int verbose, int node);
extern unsigned long swiotlb_nr_tbl(int node);
unsigned long swiotlb_size_or_default(int node);
extern int swiotlb_late_init_with_tbl(char *tlb, unsigned long nslabs, int node);
extern int swiotlb_late_init_with_default_size(size_t default_size, int node);
extern void __init swiotlb_update_mem_attributes(int node);
#else
extern void swiotlb_init(int verbose);
int swiotlb_init_with_tbl(char *tlb, unsigned long nslabs, int verbose);
extern unsigned long swiotlb_nr_tbl(void);
unsigned long swiotlb_size_or_default(void);
extern int swiotlb_late_init_with_tbl(char *tlb, unsigned long nslabs);
extern int swiotlb_late_init_with_default_size(size_t default_size);
extern void __init swiotlb_update_mem_attributes(void);
#endif

/*
 * Enumeration for sync targets
 */
enum dma_sync_target {
	SYNC_FOR_CPU = 0,
	SYNC_FOR_DEVICE = 1,
};

phys_addr_t swiotlb_tbl_map_single(struct device *hwdev, phys_addr_t phys,
		size_t mapping_size, size_t alloc_size,
		enum dma_data_direction dir, unsigned long attrs);

extern void swiotlb_tbl_unmap_single(struct device *hwdev,
				     phys_addr_t tlb_addr,
				     size_t mapping_size,
				     size_t alloc_size,
				     enum dma_data_direction dir,
				     unsigned long attrs);

extern void swiotlb_tbl_sync_single(struct device *hwdev,
				    phys_addr_t tlb_addr,
				    size_t size, enum dma_data_direction dir,
				    enum dma_sync_target target);

dma_addr_t swiotlb_map(struct device *dev, phys_addr_t phys,
		size_t size, enum dma_data_direction dir, unsigned long attrs);

#ifdef CONFIG_SWIOTLB
extern enum swiotlb_force swiotlb_force;
# if defined(CONFIG_E2K) && defined(CONFIG_NUMA)
extern phys_addr_t __io_tlb_start[MAX_NUMNODES], __io_tlb_end[MAX_NUMNODES];
# else
extern phys_addr_t io_tlb_start, io_tlb_end;
# endif

static inline bool is_swiotlb_buffer(phys_addr_t paddr)
{
# if defined(CONFIG_E2K) && defined(CONFIG_NUMA)
	int node;
	SWIOTLB_NODE_CYCLE_BEGIN
		if (paddr >= __io_tlb_start[node] && paddr < __io_tlb_end[node])
			return true;
	SWIOTLB_NODE_CYCLE_END
	return false;
# else
	return paddr >= io_tlb_start && paddr < io_tlb_end;
#endif
}

# if defined(CONFIG_E2K) && defined(CONFIG_NUMA)
void __init swiotlb_exit(int node);
unsigned int swiotlb_max_segment(int node);
# else
void __init swiotlb_exit(void);
unsigned int swiotlb_max_segment(void);
# endif
size_t swiotlb_max_mapping_size(struct device *dev);
# if defined(CONFIG_E2K) && defined(CONFIG_NUMA)
bool is_swiotlb_active(int node);
# else
bool is_swiotlb_active(void);
# endif
#else
#define swiotlb_force SWIOTLB_NO_FORCE
static inline bool is_swiotlb_buffer(phys_addr_t paddr)
{
	return false;
}
# if defined(CONFIG_E2K) && defined(CONFIG_NUMA)
static inline void swiotlb_exit(int node)
# else
static inline void swiotlb_exit(void)
# endif
{
}
# if defined(CONFIG_E2K) && defined(CONFIG_NUMA)
static inline unsigned int swiotlb_max_segment(int node)
# else
static inline unsigned int swiotlb_max_segment(void)
# endif
{
	return 0;
}
static inline size_t swiotlb_max_mapping_size(struct device *dev)
{
	return SIZE_MAX;
}

# if defined(CONFIG_E2K) && defined(CONFIG_NUMA)
static inline bool is_swiotlb_active(void)
# else
static inline bool is_swiotlb_active(void)
# endif
{
	return false;
}
#endif /* CONFIG_SWIOTLB */

#if defined(CONFIG_E2K) && defined(CONFIG_NUMA)
extern void swiotlb_print_info(int);
extern void swiotlb_set_max_segment(unsigned int, int);
#else
extern void swiotlb_print_info(void);
extern void swiotlb_set_max_segment(unsigned int);
#endif

#endif /* __LINUX_SWIOTLB_H */
