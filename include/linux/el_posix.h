/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _EL_POSIX__H_
#define _EL_POSIX__H_

#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/ktime.h>
#include <linux/hrtimer.h>

struct task_struct;

struct el_wait_queue_head {
	ktime_t wuc_time; /* Moment of call of wake up function */
	struct task_struct *task;
	struct list_head task_list;
};

struct el_timerfd_ctx {
	raw_spinlock_t lock;
	int locked;		/* To combine raw_spinlock with irqsafe flag.
				 * It protects all excluding queue and ticks;
				 * for manipulating with them lock is enough */
	struct el_wait_queue_head wqh;	/* Protected by "->lock" */
	ktime_t tintv;
	struct hrtimer tmr;
	u64 ticks, handled_ticks; /* all and handled by user */
	ktime_t cb_timeout;       /* Callback timeout */
	ktime_t run_time;	  /* Moment of __run_hrtimer call */
	ktime_t expiried;         /* When the timer has expiried */
};

#ifndef STANDALONE
#ifdef CONFIG_MCST
#ifdef CONFIG_E90
#define do_postpone_tick(a)	do {} while (0)
#else
extern void do_postpone_tick(int to_netxt_inrt_ns);
#endif
#endif
#endif
extern void tick_setup_sched_timer(void);
extern void tick_cancel_sched_timer(int cpu);

#endif /* _EL_POSIX__H_ */

