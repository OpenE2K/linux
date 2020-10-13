#ifndef  _UAPI_LINUX_MCST_RT_H
#define  _UAPI_LINUX_MCST_RT_H


#define RT_BIT_POSTP_TICK	1  /* postpone timer if periodic rt-irq */
#define RT_BIT_HZ_RT		2  /* no tickless (tick_nohz_enabled=off) */
#define RT_BIT_NO_CPU_BLNC	4  /* scheduler no migration, no balancing */
#define RT_BIT_NO_RD_AHEAD	7  /* turn off on read ahead or warn if any */
#define RT_BIT_NO_IO_SCHED	8  /* turn off on IO schediling (elevator) */
#define RT_BIT_FAST_TIMER	9  /* not do some jobs immidiatly */
#define RT_BIT_MLOCK_DONE       14 /* prohibit new mmap() & PF occurence */
#define RT_BIT_NO_FORK		16 /* warning if forking */
#define RT_BIT_PGFLT_RTWRN	17 /* warn if page fault in rt task */
#define RT_BIT_PGFLT_WRN	18 /* warn if page fault in any task */

#define RT_BIT_DEBUG		31 /* for tmp debugging
					   in timer interrupt */

#define RTS_NO_CPU_BLNC		(1 << RT_BIT_NO_CPU_BLNC)
#define RTS_NO_RD_AHEAD		(1 << RT_BIT_NO_RD_AHEAD)
#define RTS_NO_IO_SCHED		(1 << RT_BIT_NO_IO_SCHED)
#define RTS_FAST_TIMER		(1 << RT_BIT_FAST_TIMER)
#define RTS_POSTP_TICK		(1 << RT_BIT_POSTP_TICK)
#define RTS_HZ_RT		(1 << RT_BIT_HZ_RT)
#define VM_MLOCK_DONE		(1 << RT_BIT_MLOCK_DONE)
#define RTS_NO_FORK		(1 << RT_BIT_NO_FORK)
#define RTS_PGFLT_RTWRN		(1 << RT_BIT_PGFLT_RTWRN)
#define RTS_PGFLT_WRN		(1 << RT_BIT_PGFLT_WRN)
#define RTS_DEBUG		(1 << RT_BIT_DEBUG)

/* MCST_RT soft flags: */
#define RTS_SOFT__RT	(RTS_NO_CPU_BLNC | RTS_NO_RD_AHEAD |\
			RTS_NO_IO_SCHED | RTS_POSTP_TICK |\
			RTS_FAST_TIMER | RTS_HZ_RT)

/* MCST_RT hard flags: */
#define RTS_HARD__RT	RTS_SOFT__RT | RTS_FLUSH_ALL | RTS_PGFLT_WRN | RTS_PGFLT_WRN
#define RTS__SOFT_RT RTS_SOFT__RT

/* Possible modes rt_cpu_data. see above*/
#define RTCPUM_NO_PG_FAULT      0x0001
#define RTCPUM_NO_UNBOUND       0x0002


#define EL_GET_CPUS_NUM		100
#define EL_MY_CPU_ID		101
#define EL_CPU_BIND_DEPRICATED	102
/*#define EL_IRQS_BIND		104*/
#define EL_TICK_TIME		105
#define EL_RTS_MODE		106
#define EL_SET_RTS_ACTIVE	107
#define EL_GET_RTS_ACTIVE	108
#define EL_SET_USER_IRQ_THR	109
#define EL_UNSET_USER_IRQ_THR	110
#define EL_GET_CPU_KHZ		111
#define EL_UNSET_APIC_TIMER	112
#define EL_SET_APIC_TIMER	113
/*#define EL_HANDLE_IRQ_MASK	114*/
#define EL_GET_CPUS_MASK	115
#define SPARC_GET_USEC		116
#define EL_SET_RTCPU_MODE	117
#define EL_UNSET_RTCPU_MODE	118
#define EL_GET_RTCPU_MODE	119
#define EL_SET_IRQ_MASK		120
#define EL_GET_IRQ_MASK		121
#define EL_TICK_THR_START	122
/*#define EL_TICK_THR_START_NSEC  159*/
#define EL_TICK_THR_CONT        123
#define EL_TICK_THR_STOP        124
#define EL_GET_HZ               125
#define EL_SET_NET_RT           126
#define EL_UNSET_NET_RT         127
#define EL_DO_CNTR_PNT          128
//#define EL_PRECISE_GETTIMEOFDAY		129
//#define EL_PRECISE_GETTIMEOFDAY_SET0	130
//#define EL_PRECISE_GETTIMEOFDAY_SET1	131
//#define EL_GET_PRECISE_TIME_MPV		132
//#define EL_GET_PRECISE_TIME_MPV_SET0	133
//#define EL_GET_PRECISE_TIME_MPV_SET1	134
#define EL_GET_CPU_FREQ		135

#define EL_SET_TRACE_POINT	136
#define EL_SET_SWITCH_CHECK     137
#define EL_ATOMIC_ADD		141

#define EL_SHOW_STATE           150

#define EL_START_TASK_TIMER     151
#define EL_STOP_TASK_TIMER      152
#define EL_SET_MLOCK_CONTROL    153
#define EL_UNSET_MLOCK_CONTROL  154
#define EL_SET_CPU_FREQ		155
#define EL_WAKEUP_TIME		156
#define EL_WAKEUP_WKR_TIME	157
#define EL_WAKEN_TIME		158
#define EL_TICK_THR_START_NSEC  159
#define EL_GET_CPUS_INTCOUNT	160
#define EL_OPEN_TIMERFD		161
#define EL_TIMERFD_SETTIME	162
#define EL_SYNC_CYCLS		163
#define EL_WAKEUP_LAT		164
#define EL_GET_TIMES		165
#define EL_USER_TICK            166
#define EL_RT_CPU		167

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

