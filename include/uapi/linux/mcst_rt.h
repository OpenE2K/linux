#ifndef  _UAPI_LINUX_MCST_RT_H
#define  _UAPI_LINUX_MCST_RT_H


#define RT_BIT_HZ_RT		2  /* no tickless (tick_nohz_enabled=off) */
#define RT_BIT_NO_CPU_BLNC	4  /* scheduler no migration, no balancing */
#define RT_BIT_NO_RD_AHEAD	7  /* turn off on read ahead or warn if any */
#define RT_BIT_NO_IO_SCHED	8  /* turn off on IO schediling (elevator) */
#define RT_BIT_MLOCK_DONE       14 /* prohibit new mmap() & PF occurence */
#define RT_BIT_NO_FORK		16 /* warning if forking */
#define RT_BIT_PGFLT_RTWRN	17 /* warn if page fault in rt task */
#define RT_BIT_PGFLT_WRN	18 /* warn if page fault in any task */
#define RT_BIT_NO_SETTIME	19 /* settimeofday() return EPRERM for root */

#define RT_BIT_DEBUG		31 /* for tmp debugging
					   in timer interrupt */

#define RTS_NO_CPU_BLNC		(1 << RT_BIT_NO_CPU_BLNC)
#define RTS_NO_RD_AHEAD		(1 << RT_BIT_NO_RD_AHEAD)
#define RTS_NO_IO_SCHED		(1 << RT_BIT_NO_IO_SCHED)
#define RTS_HZ_RT		(1 << RT_BIT_HZ_RT)
#define VM_MLOCK_DONE		(1 << RT_BIT_MLOCK_DONE)
#define RTS_NO_FORK		(1 << RT_BIT_NO_FORK)
#define RTS_PGFLT_RTWRN		(1 << RT_BIT_PGFLT_RTWRN)
#define RTS_PGFLT_WRN		(1 << RT_BIT_PGFLT_WRN)
#define RTS_NO_SETTIME		(1 << RT_BIT_NO_SETTIME)
#define RTS_DEBUG		(1 << RT_BIT_DEBUG)

/* MCST_RT soft flags: */
#define RTS_SOFT__RT	(RTS_NO_CPU_BLNC | RTS_NO_RD_AHEAD |\
			RTS_NO_IO_SCHED | RTS_HZ_RT)

/* MCST_RT hard flags: */
#define RTS_HARD__RT	RTS_SOFT__RT | RTS_FLUSH_ALL | RTS_PGFLT_WRN | RTS_PGFLT_WRN
#define RTS__SOFT_RT RTS_SOFT__RT

#define EL_GET_CPUS_NUM		100
#define EL_MY_CPU_ID		101
#define EL_CPU_BIND_DEPRICATED	102
#define EL_TICK_TIME		105
#define EL_RTS_MODE		106
#define EL_SET_RTS_ACTIVE	107
#define EL_GET_RTS_ACTIVE	108
#define EL_GET_CPUS_MASK	115
#define SPARC_GET_USEC		116
#define EL_SET_IRQ_MASK		120
#define EL_SET_NET_RT           126
#define EL_UNSET_NET_RT         127
#define EL_GET_CPU_FREQ		135
#define EL_ATOMIC_ADD		141
#define EL_SET_MLOCK_CONTROL    153
#define EL_UNSET_MLOCK_CONTROL  154
#define EL_OPEN_TIMERFD		161
#define EL_TIMERFD_SETTIME	162
#define EL_SYNC_CYCLS		163
#define EL_GET_TIMES		165
#define EL_USER_TICK            166
#define EL_RT_CPU		167
#define EL_SCLKR_READ		168

#define EL_MISC_TO_DEBUG	500

/* offsets of times in long long array for EL_GET_TIMES */
#define EL_GET_TIMES_WAKEUP		0
#define EL_GET_TIMES_SCHED_ENTER	1
#define EL_GET_TIMES_SCHED_LOCK		2
#define EL_GET_TIMES_WOKEN		3
#define EL_GET_TIMES_LAST_PRMT_ENAB	4
#define EL_GET_TIMES_INTR_W		5
#define EL_GET_TIMES_INTR_S		6
#define EL_GET_TIMES_CNTXB		7
#define EL_GET_TIMES_CNTXE		8
#define EL_GET_TIMES_INTR_SC		9

/* this is start number for el_posix support sys_calls */
#define PTHREAD_INTRF_START	500

#endif	/* _UAPI_LINUX_MCST_RT_H */

