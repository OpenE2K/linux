/*
 * pgd.h: the functions and defines necessary to manage
 * root level of page tables - pgd
 *
 * Copyright 2013 Salavat S. Guiliazov (atic@mcst.ru)
 */
#ifndef _E2K_PGD_H
#define _E2K_PGD_H

#include <linux/types.h>

#include <asm/mmu_regs_types.h>
#include <asm/pgtable_def.h>

#undef	DEBUG_PA_MODE
#undef	DebugPA
#define	DEBUG_PA_MODE		0	/* page table allocation */
#define	DebugPA(fmt, args...)						\
({									\
	if (DEBUG_PA_MODE)						\
		pr_info(fmt, ##args);					\
})

/*
 * The pointer of kernel root-level page table directory
 * The Page table directory is allocated and created at boot-time
 */

#ifndef	CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT
extern	pgd_t			swapper_pg_dir[PTRS_PER_PGD];
#else	/* CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT */
typedef struct pg_dir {
	pgd_t pg_dir[PTRS_PER_PGD];
} pg_dir_t;
extern	pg_dir_t		all_cpus_swapper_pg_dir[NR_CPUS];
#define	swapper_pg_dir		(all_cpus_swapper_pg_dir[0].pg_dir)
#endif	/* ! CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT */

#ifndef	CONFIG_NUMA
#define	kernel_root_pt		((pgd_t *)swapper_pg_dir)
#define	boot_root_pt		boot_vp_to_pp(kernel_root_pt)
#define	node_pg_dir(nid)	((nid), &swapper_pg_dir)
#define	cpu_pg_dir(cpu)		kernel_root_pt
#define	the_cpu_pg_dir		cpu_pg_dir
#define	cpu_kernel_root_pt	cpu_pg_dir(dummy)
#else	/* CONFIG_NUMA */
#ifndef	CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT
extern	pgd_t	__nodedata	*all_nodes_pg_dir[MAX_NUMNODES];
#else	/* CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT */
extern	pg_dir_t __nodedata	*all_nodes_pg_dir[MAX_NUMNODES];
#endif	/* ! ONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT */

#define	node_pg_dir(nid)	(all_nodes_pg_dir[nid])

#ifdef	CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT
#define	my_cpu_pg_dir							\
({									\
	pgd_t *pgdp;							\
	int my_cpu = hard_smp_processor_id();				\
									\
	if (!MMU_IS_SEPARATE_PT() && THERE_IS_DUP_KERNEL) {		\
		pgdp = all_cpus_swapper_pg_dir[my_cpu].pg_dir;		\
	} else {							\
		pgdp = swapper_pg_dir;					\
	}								\
	pgdp;								\
})
#define	the_node_pg_dir(nid)						\
({									\
	pg_dir_t *node_pgds;						\
	pg_dir_t *pg_dir;						\
									\
	node_pgds = node_pg_dir(nid);					\
	pg_dir = &node_pgds[0];						\
	pg_dir;								\
})
#define	the_node_kernel_root_pt(nid)					\
({									\
	pg_dir_t *pg_dir;						\
	pgd_t *pgdp;							\
									\
	pg_dir = the_node_pg_dir(nid);					\
	pgdp = pg_dir->pg_dir;						\
	pgdp;								\
})
#define	the_cpu_pg_dir(cpu)						\
({									\
	int the_cpu = (cpu);						\
	int nid = cpu_to_node(the_cpu);					\
	pg_dir_t *pg_dir;						\
	pgd_t *pgdp;							\
									\
	pg_dir = the_node_pg_dir(nid);					\
	if (!MMU_IS_SEPARATE_PT() && THERE_IS_DUP_KERNEL) {		\
		pgdp = pg_dir[cpu_to_cpuid(the_cpu)].pg_dir;		\
	} else {							\
		pgdp = pg_dir->pg_dir;					\
	}								\
	pgdp;								\
})
#define	boot_the_node_root_pg_dir(nid)					\
({									\
	pg_dir_t *pg_dir;						\
									\
	pg_dir = boot_the_node_vp_to_pp(nid, all_cpus_swapper_pg_dir);	\
	pg_dir;								\
})
#define	boot_the_node_root_pt(nid)					\
({									\
	pg_dir_t *pg_dir;						\
	pgd_t *pgdp;							\
									\
	pg_dir = boot_the_node_root_pg_dir(nid);			\
	pgdp = pg_dir->pg_dir;						\
	pgdp;								\
})
#define	boot_node_cpu_pg_dir(nid, cpuid)				\
({									\
	pg_dir_t *pg_dir;						\
	pgd_t *pgdp;							\
									\
	pg_dir = boot_the_node_root_pg_dir(nid);			\
	if (!MMU_IS_SEPARATE_PT() && BOOT_NODE_THERE_IS_DUP_KERNEL()) {	\
		pgdp = pg_dir[cpuid].pg_dir;				\
	} else {							\
		pgdp = pg_dir->pg_dir;					\
	}								\
	pgdp;								\
})
#define	boot_cpu_pg_dir(cpuid)						\
		boot_node_cpu_pg_dir(boot_numa_node_id(), cpuid)
#define	cpu_kernel_root_pt	my_cpu_pg_dir
#define	boot_cpu_kernel_root_pt	boot_cpu_pg_dir(boot_smp_processor_id())
#define	boot_node_root_pt	boot_the_node_root_pt(boot_numa_node_id())
#define	boot_root_pt		boot_cpu_kernel_root_pt
#define	kernel_root_pt		cpu_kernel_root_pt
#else	/* ! CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT */
#define	boot_the_node_root_pt(nid)	\
		boot_the_node_vp_to_pp(nid, swapper_pg_dir)
#define	boot_node_root_pt		boot_node_vp_to_pp(swapper_pg_dir)
#define	boot_root_pt			boot_node_root_pt
#define	kernel_root_pt			node_pg_dir(numa_node_id())
#define	cpu_pg_dir(cpu)			kernel_root_pt
#define	cpu_kernel_root_pt		cpu_pg_dir(dummy)
#endif	/* CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT */
#endif	/* ! CONFIG_NUMA */

static inline void
clear_pgd_range(pgd_t *dst_pgd, int start_index, int end_index)
{
	int index;

	BUG_ON(start_index > PTRS_PER_PGD);
	BUG_ON(end_index > PTRS_PER_PGD);
	BUG_ON(start_index >= end_index);
	BUG_ON(MMU_IS_SEPARATE_PT() && end_index > USER_PTRS_PER_PGD);
	for (index = start_index; index < end_index; index++) {
		DebugPA("clear_pgd_range() clear pgd #%d 0x%px = 0x%lx\n",
			index,
			&dst_pgd[index], pgd_val(dst_pgd[index]));
		dst_pgd[index] = __pgd(0);
	}
}

static inline void
copy_pgd_range(pgd_t *dst_pgd, pgd_t *src_pgd, int start_index, int end_index)
{
	int index;

	BUG_ON(start_index > PTRS_PER_PGD);
	BUG_ON(end_index > PTRS_PER_PGD);
	BUG_ON(start_index >= end_index);
	BUG_ON(MMU_IS_SEPARATE_PT() && end_index > USER_PTRS_PER_PGD);
	for (index = start_index; index < end_index; index++) {
		dst_pgd[index] = src_pgd[index];
		DebugPA("copy_pgd_range() copy pgd #%d 0x%px = 0x%lx to "
			"pgd 0x%px\n",
			index,
			&src_pgd[index], pgd_val(src_pgd[index]),
			&dst_pgd[index]);
	}
}

static inline void
copy_kernel_pgd_range(pgd_t *dst_pgd, pgd_t *src_pgd)
{
	copy_pgd_range(dst_pgd, src_pgd, USER_PTRS_PER_PGD, PTRS_PER_PGD);
}

static inline void
set_pgd_range(pgd_t *dst_pgd, pgd_t pgd_to_set, int start_index, int end_index)
{
	int index;

	BUG_ON(start_index > PTRS_PER_PGD);
	BUG_ON(end_index > PTRS_PER_PGD);
	BUG_ON(start_index >= end_index);
	BUG_ON(MMU_IS_SEPARATE_PT() && end_index > USER_PTRS_PER_PGD);
	for (index = start_index; index < end_index; index++) {
		dst_pgd[index] = pgd_to_set;
		DebugPA("set_pgd_range() set pgd #%d 0x%px to 0x%lx\n",
			index,
			&dst_pgd[index], pgd_val(pgd_to_set));
	}
}

static inline void
set_kernel_pgd_range(pgd_t *dst_pgd, pgd_t pgd_to_set)
{
	set_pgd_range(dst_pgd, pgd_to_set, USER_PTRS_PER_PGD, PTRS_PER_PGD);
}

#ifdef	CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT
static inline void
copy_one_user_pgd_to_kernel_pgd(pgd_t *kernel_pgd, pgd_t *user_pgd, int index)
{
	BUG_ON(index >= USER_PTRS_PER_PGD);
	BUG_ON(MMU_IS_SEPARATE_PT());
	kernel_pgd[index] = user_pgd[index];
	DebugPA("copy_one_user_pgd_to_kernel_pgd() CPU #%d copy one user pgd "
		"#%d 0x%px = 0x%lx to kernel root pt 0x%px\n",
		raw_smp_processor_id(), index,
		&user_pgd[index], pgd_val(user_pgd[index]),
		&kernel_pgd[index]);
}
static inline void
copy_user_pgd_to_kernel_pgd_addr(pgd_t *kernel_pgd, pgd_t *user_pgd,
							e2k_addr_t addr)
{
	copy_one_user_pgd_to_kernel_pgd(kernel_pgd, user_pgd,
						pgd_index(addr));
}
static inline void
copy_user_pgd_to_kernel_root_pt_addr(pgd_t *user_pgd, e2k_addr_t addr)
{
	copy_user_pgd_to_kernel_pgd_addr(cpu_kernel_root_pt, user_pgd,
						addr);
}

static inline void
copy_user_pgd_to_kernel_pgd_range(pgd_t *kernel_pgd, pgd_t *user_pgd,
		int start_index, int end_index)
{
#if DEBUG_PA_MODE
	int index;
#endif
	BUG_ON(start_index >= USER_PTRS_PER_PGD);
	BUG_ON(end_index > USER_PTRS_PER_PGD);
	BUG_ON(start_index >= end_index);
	BUG_ON(MMU_IS_SEPARATE_PT());
#if DEBUG_PA_MODE
	for (index = start_index; index < end_index; index++)
		DebugPA("copy_user_pgd_to_kernel_pgd_range() CPU #%d copy "
			"user pgd #%d 0x%px = 0x%lx to kernel root pt 0x%px\n",
			raw_smp_processor_id(), index,
			&user_pgd[index], pgd_val(user_pgd[index]),
			&kernel_pgd[index]);
#endif
	memcpy(&kernel_pgd[start_index], &user_pgd[start_index],
			sizeof(pgd_t) * (end_index - start_index));
}

static inline void
copy_user_pgd_to_kernel_pgd_addr_range(pgd_t *kernel_pgd, pgd_t *user_pgd,
		e2k_addr_t start_addr, e2k_addr_t end_addr)
{
	copy_user_pgd_to_kernel_pgd_range(kernel_pgd, user_pgd,
			pgd_index(start_addr),
			pgd_index(_PAGE_ALIGN_DOWN(end_addr, PGDIR_SIZE)));
}
static inline void
copy_user_pgd_to_kernel_root_pt_addr_range(pgd_t *user_pgd,
		e2k_addr_t start_addr, e2k_addr_t end_addr)
{
	copy_user_pgd_to_kernel_pgd_addr_range(cpu_kernel_root_pt, user_pgd,
						start_addr, end_addr);
}

static inline void
copy_user_pgd_to_kernel_pgd(pgd_t *kernel_pgd, pgd_t *user_pgd)
{
	copy_user_pgd_to_kernel_pgd_range(kernel_pgd, user_pgd,
						0, USER_PTRS_PER_PGD);
}

static inline void
copy_user_pgd_to_kernel_root_pt(pgd_t *user_pgd)
{
	copy_user_pgd_to_kernel_pgd(cpu_kernel_root_pt, user_pgd);
}
#else	/* !CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT */
static inline void
copy_user_pgd_to_kernel_root_pt(pgd_t *user_pgd)
{
	BUG_ON(true);
}
#endif	/* CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT */

#endif /* _E2K_PGD_H */
