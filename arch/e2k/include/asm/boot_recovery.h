/* $Id: boot_recovery.h,v 1.12 2009/06/29 11:52:31 atic Exp $
 *
 * boot-time recovery of kernel from control point.
 */
#ifndef _E2K_BOOT_RECOVERY_H
#define _E2K_BOOT_RECOVERY_H

#include <asm/types.h>
#include <asm/console.h>

#ifdef CONFIG_SMP
extern struct task_struct	*tasks_to_recover[NR_CPUS];
extern struct task_struct	*tasks_to_restart[NR_CPUS];
#define idle_task(cpu)		(init_tasks[cpu])
#define	interrupted_task(cpu)	(tasks_to_recover[cpu])
#define restart_task(cpu)	(tasks_to_restart[cpu])
#define boot_restart_task(cpu)	boot_get_vo_value(tasks_to_restart[cpu])
#else
extern struct task_struct	*task_to_recover;
extern struct task_struct	*task_to_restart;
#define idle_task(cpu)		(&init_task)
#define	interrupted_task(cpu)	(task_to_recover)
#define	restart_task(cpu)	(task_to_restart)
#define boot_restart_task(cpu)	boot_get_vo_value(task_to_restart)
#endif	/* CONFIG_SMP */

typedef enum rest_type {
	CREATE_CNTP_REST_TYPE,		/* create new control point */
	RECREATE_CNTP_REST_TYPE,	/* recreate current control point */
	RECOVERY_REST_TYPE,		/* debug mode: create point only */
					/* in the memory and restart */
					/* from this point to create next */
					/* point and restart from next */
					/* check safety of recovery from */
					/* control points while a lot of */
					/* system restarts */
	CORE_DUMP_REST_TYPE,		/* core dump mode to save all */
					/* memory and stacks */
	INVALID_REST_TYPE,
} rest_type_t;

typedef enum rest_goal {
	CREATE_REST_GOAL,		/* create new control point */
					/* and restart system */
	RECOVER_REST_GOAL,		/* recovery from created control */
					/* point */
} rest_goal_t;

struct extd_info {
	void		*info;
	rest_type_t	restart_type;
};

extern rest_goal_t restart_goal;

/*
 * Forwards of boot-time functions to recover system state
 */

extern void	boot_recovery(bootblock_struct_t *bootblock);
extern void	boot_recovery_cnt_points(bootblock_struct_t *bootblock);
extern void	boot_add_mapped_area(e2k_addr_t area_base, e2k_size_t area_size);
extern void	boot_add_nosave_area(e2k_addr_t area_base, e2k_size_t area_size);
extern void	add_nosave_area(e2k_addr_t area_base, e2k_size_t area_size);
extern int	restart_system(rest_type_t restart_type, int async_mode);
extern void	do_restart_system(rest_type_t restart_type);
extern void	switch_to_restart_process(void *einfo);
extern void	trap_recovery(void);
extern void	__init boot_scan_full_physmem(void);
extern void	device_recovery(void);
extern int	emergency_restart_system(void);
extern void	e2k_reset_machine(void);
extern void	init_dump_analyze_mode(void);

#ifdef	CONFIG_RECOVERY
/*
 * Structure 'full_phys_mem' holds all available physical memory on the
 * system. Structure 'e2k_phys_banks' holds physical memory available to use
 * only by current control point instance.
 */
extern node_phys_mem_t full_phys_mem[L_MAX_MEM_NUMNODES];
#define	boot_full_phys_mem	boot_vp_to_pp(full_phys_mem)
#else	/* !CONFIG_RECOVERY */
#define	full_phys_mem		nodes_phys_mem
#define	boot_full_phys_banks	boot_vp_to_pp(nodes_phys_mem)
#endif	/* CONFIG_RECOVERY */

/*
 * Full physical memory descriptors.
 * In this case start_of_phys_memory, end_of_phys_memory, pages_of_phys_memory
 * describe only current control point memory boundaries
 */
#ifdef	CONFIG_RECOVERY
extern e2k_addr_t start_of_full_memory;	/* real start address of full */
					/* physical memory */
extern e2k_addr_t end_of_full_memory;	/* real end address + 1 of full */
					/* physical memory */
extern e2k_size_t pages_of_full_memory;	/* real number of pages of full */
					/* physical memory */
#else	/* !CONFIG_RECOVERY */
#define	start_of_full_memory		start_of_phys_memory
#define	end_of_full_memory		end_of_phys_memory
#define	pages_of_full_memory		pages_of_phys_memory
#endif	/* CONFIG_RECOVERY */
#define	boot_start_of_full_memory	boot_get_vo_value(start_of_full_memory)
#define	boot_end_of_full_memory		boot_get_vo_value(end_of_full_memory)
#define	boot_pages_of_full_memory	boot_get_vo_value(pages_of_full_memory)

/*
 * Table of just mapped areas into other control point memory
 */
#define	E2K_MAX_MAPPED_AREAS	(8 * NR_CPUS)

extern bank_info_t		just_mapped_areas[E2K_MAX_MAPPED_AREAS];
extern int			mapped_areas_num;

#define	boot_just_mapped_areas	boot_vp_to_pp(just_mapped_areas)
#define	boot_mapped_areas_num	boot_get_vo_value(mapped_areas_num)

/*
 * Table of memory areas to do not save on a disk
 */
#define	E2K_MAX_NOSAVE_AREAS	(8 * NR_CPUS)

extern bank_info_t		nosave_areas[E2K_MAX_NOSAVE_AREAS];
extern int			nosave_areas_num;

#define	boot_nosave_areas	boot_vp_to_pp(nosave_areas)
#define	boot_nosave_areas_num	boot_get_vo_value(nosave_areas_num)

#define	START_KERNEL_SYSCALL	12

extern inline void
scall2(register volatile bootblock_struct_t *bootblock)
{
	(void) E2K_SYSCALL(START_KERNEL_SYSCALL,	/* Trap number */
			   0,				/* empty sysnum */
			   1,				/* single argument */
			   (long) bootblock);		/* the argument */
}

#endif /* _E2K_BOOT_RECOVERY_H */
