/*
 * arch/e2k/kernel/monitors.h
 *
 * This file contains declarations of interface functions for working with 
 * monitors.
 *
 * Copyright (C) 2009-2013 Pavel V. Panteleev (panteleev_p@mcst.ru)
 */

#ifndef	_MONITORS_H_
#define	_MONITORS_H_

#ifdef CONFIG_MONITORS

#define	MONITORS_COUNT			4

#define SICMONITORS_COUNT_PER_NODE	2
#define	SICMONITORS_COUNT		\
		(MAX_NUMNODES * SICMONITORS_COUNT_PER_NODE)

#define	IPCCMONITORS_COUNT		1
#define	IOCCMONITORS_COUNT		1

typedef struct {
	unsigned char cpu_num;
	unsigned long dim0;
	unsigned long dim1;
	unsigned long ddm0;
	unsigned long ddm1;
} monitor_registers_delta_t;

extern const struct file_operations	proc_pid_monitors_events_operations;
extern int				monitors_used;

void process_monitors(struct task_struct *task);
void init_monitors(struct task_struct *task);
void store_monitors_delta(struct task_struct *task);
void add_dead_proc_events(struct task_struct *task);
unsigned char get_monitors_mask(char *title);

#define MONITORING_IS_ACTIVE unlikely(monitors_used)

#else	/* !CONFIG_MONITORS*/
#define MONITORING_IS_ACTIVE false
static inline void init_monitors(struct task_struct *task) { };
#endif	/* CONFIG_MONITORS */

#endif	/* _MONITORS_H_ */

