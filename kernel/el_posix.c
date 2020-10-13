/*
 * Here is implementation of Posix Support
 * Two variants are implemented:
 *
 * 1. There is pobjs pointer in thread_t structure which points
 * to el_pobjs.
 *
 * 2. There are two variants to work with mutex (see el_posix.h):
 *
 * #define WAKEUP_MUTEX_ONE  1  // to wakeup only one thread
 * #define WAKEUP_MUTEX_ONE  0  // to wakeup all
 *
 * Short description of work.
 *
 * el_pobjs has two head queues for posix threads which are waiting
 * mutexes or conditions. User's address of needed mutex or condition
 * are located in item of queue.
 * Internel function pthread_run() will wakeup needed pthreads only.
 *
 * Implementation in kernel.
 * 	Aditional system call el_posix() was implemented for el_pthread lib:
 *
 *	sys_el_posix() (see kernel/el_posix.c)
 *	sys_clone2()	(see arch/e2k/process.c)
 *
 * 	To define syscall el_posix() was done:
 *
 *	unistd.h:
 *		#define	__NR_el_posix		255
 *	e2k_syswork.h :
 *		static inline _syscall5(int, el_posix, int, req,
 *				void *, a1, void *, a2, void *, a3, void *, a4);
 *
 *	systable.c :
 *		SYSTEM_CALL_DEFINE(sys_el_posix);
 *		SYSTEM_CALL_TBL_ENTRY(sys_el_posix),
 *
 * Note that to port our posix for sparc and i386 only sys_el_posix()
 * 	is needed as syscall el_posix().
 * 	sys_el_posix() can be port without changing as additional system call
 * 	(as for E2K)
 * 	or can be done as psevdo driver.
 *	Instead sys_clone2() should  be used nativ clone() (system call
 *	(see el_pthread.c)
 *
 *
 * Implementation of posix lib.
 * 	See el_pthread.c where lib posix is inplemented using el_posix()
 *
 * Posix implementation includes
 * 1. new linux/el_posix.h
 * 2. new kernel/el_posix.c
 * additional element is needed in struct thread_t:
 *	void		*pobjs;
 *
 * == SVS ==
 */

#define	DEBUG_POSIX	0	/* DEBUG_POSIX */
#if DEBUG_POSIX
# define DEBUG
# define DbgPos(fmt, ...) \
		pr_debug("%d " fmt, current->pid ,##__VA_ARGS__)
#else
# define DbgPos(...)
#endif

#include <linux/el_posix.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/syscalls.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/timer.h>
#include <linux/interrupt.h>
#include <linux/compat.h>
#include <linux/spinlock.h>
#include <linux/proc_fs.h>
#ifdef CONFIG_MCST_RT
#include <linux/hrtimer.h>
#include <linux/anon_inodes.h>
#include <linux/file.h>
#endif

#include <linux/sched/rt.h>

#ifdef CONFIG_E90S
#include <asm/e90s.h>
#endif
#include <asm/delay.h>
#include <asm/processor.h>
#include <asm/uaccess.h>
#include <asm/el_posix.h>
#include <linux/clocksource.h>

#define PMUTEX_UNLOCKED 1
#define PMUTEX_LOCKED_ONCE 0
//#define PMUTEX_HAS_QUEUE 2

#define PTHREAD_WAIT (PMUTEX_WAIT | PCOND_WAIT | WAKEUP_PID_WAIT | SWITCH_WAIT)

/*
 * wakeup_mode
 */
#define WAKEUP_ALL	0x100
#define WAKEUP_ONE	0x101
#define MOVE_TO_MUTEX	0x102
#define WAKEUP_PID	0x103

//typedef struct kmem_cache struct kmem_cache;

long redir_to_waiter = 1;
static long to_do_move_to_mutex = 1;
static long wakeup_mutex_one = 1;
static long PImutex = 0;
static DECLARE_RWSEM(posix_sem);
static struct kmem_cache *posix_objects = NULL;

#ifdef CONFIG_MCST_RT
static DEFINE_RAW_SPINLOCK(rts_lock);
long rts_mode = 0;	// hard realtime mode 0-unactive, 1-active
EXPORT_SYMBOL(rts_mode);
// mcst realtime mode mask
long rts_act_mask = 0;
EXPORT_SYMBOL(rts_act_mask);
/* For changing rts_lock must be held */
volatile unsigned int mcst_rt_state = MCST_RT_STATE_NORMAL;
#endif	// CONFIG_MCST_RT

/* cpu_freq_hz is used to convert clocks into ns in user space */
u32 cpu_freq_hz = UNSET_CPU_FREQ; /* CPU freq (Hz) */
EXPORT_SYMBOL(cpu_freq_hz);
int __init cpufreq_setup(char *str)
{
	cpu_freq_hz = simple_strtoul(str, &str, 0);
	return 1;
}
__setup("cpufreq=", cpufreq_setup);

#if defined(__e2k__)
extern long irq_bind_to_cpu(int irq_msk, int cpu);
extern long el_set_apic_timer(void);
extern long el_unset_apic_timer(void);
#endif

/*
 * pthread structs are as in glibc
 * We use fields as follow:
 *	__spinlock for atomic operation
 *	__m_count for count of sleepers
 *	__m_owner to save pid of owner
 */
/*=============================================*/

struct _pthread_fastlock
{
	long int 	__status;
	int 		__spinlock;
};

typedef struct
{
	int 	__m_owner_org_prio;    // int __m_reserved; in bits/pthreadtypes.h/
	int 	__m_count;
	void 	*__m_owner;
	int 	__m_kind;
	struct _pthread_fastlock __m_lock;
} pthread_mutex_t;

typedef struct
{
	struct _pthread_fastlock	 __c_lock;
	void 				*__c_waiting;
} pthread_cond_t;

/*=============================================*/

#define BITMAP_SIZE ((((MAX_PRIO+1+7)/8)+sizeof(long)-1)/sizeof(long))

typedef struct {
	unsigned long bitmap[BITMAP_SIZE];
	struct list_head	prio_list[MAX_PRIO];
} p_array_t;

typedef struct el_pobjs {
	int			pjobs_flag;
	int			adaptive_count;
	raw_spinlock_t		pobj_lock;
	atomic_t		users_number;
	p_array_t		pmutx_task_list;
	p_array_t		pcond_task_list;
} el_pobjs_t;

#define PJOBS_FLG_KERNEL_IMPL		0x00001

typedef struct pwait_q {
	void			*my_pobj;
	struct task_struct 	*task;
	struct list_head 	task_list;
	pthread_mutex_t 	*mutex; // for cond wait
	int			cond_wakeuped;
	int			moved_to_mutex;
} pwait_q_t;

inline void pwaitq_init(pwait_q_t *wait, struct task_struct *tsk,
			void *object)
{
	wait->my_pobj 		= object;
	wait->task 		= tsk;
	wait->task_list.prev 	= NULL;
	wait->task_list.next 	= NULL;
	wait->mutex		= NULL;
	wait->cond_wakeuped     = 0;
	wait->moved_to_mutex     = 0;
}

static inline void add_to_p_array(struct list_head *new, p_array_t *a, int prio)
{
	list_add(new, a->prio_list + prio);
	__set_bit(prio, a->bitmap);
}

static int
pmutex_trylock(pthread_mutex_t *mutex, struct task_struct *p)
{
	int			rval;
	int 			*mutex_spin = &mutex->__m_lock.__spinlock;

	DbgPos("trylock: start mutex=%p\n", mutex);
	mutex->__m_count++;
	rval = xchg(mutex_spin, -(mutex->__m_count));
	WARN_ON(rval > PMUTEX_UNLOCKED);
	if (rval == PMUTEX_UNLOCKED) {
		DbgPos("trylock: rval == PMUTEX_UNLOCKED\n");
		mutex->__m_count--;
		mutex->__m_owner = (void *)(long)p->pid; /* target task is an owner */
		mutex->__m_owner_org_prio = p->prio;
		return 0;
	}
	return -EBUSY;
}

static inline void move_to_mutex(pwait_q_t *curr)
{
	el_pobjs_t 		*pobjs;
	pthread_cond_t 		*cond;
	pthread_mutex_t 	*mutex;

	pobjs = current->pobjs;
	cond = (pthread_cond_t *)curr->my_pobj;
	mutex = curr->mutex;
	if(!pmutex_trylock(mutex, curr->task)) {
		curr->moved_to_mutex = 1;
		wake_up_process(curr->task);
		return;
	}
	list_del(&curr->task_list);
	curr->my_pobj = mutex;
	add_to_p_array(&curr->task_list, &pobjs->pmutx_task_list, curr->task->prio);
	DbgPos("lock_continue: start %p __m_count=%d spn=%d\n",
			mutex, mutex->__m_count, mutex->__m_lock.__spinlock);
	xchg(&mutex->__m_lock.__spinlock, -(mutex->__m_count));
}

static int pthread_run_prio(struct list_head *head, void *obj, int up_mode, int pid)
{
	struct list_head 	*tmp;
	int wokenup = 0;

	DbgPos("pthread_run: up_mode %x\n", up_mode);
	if (!head->next || !head->prev)
		panic("pthread_run: !head->next || !head->prev\n");
	tmp = head->next;
	while (tmp != head) {
		pwait_q_t *curr = list_entry(tmp, pwait_q_t, task_list);
		tmp = tmp->next;
		DbgPos("pthread_run: obj=%p cur=%p pid=%d\n", obj, curr->my_pobj, curr->task->pid);
		if (obj == curr->my_pobj) {
			if (up_mode == WAKEUP_ALL) {
				curr->cond_wakeuped = 1;
				wake_up_process(curr->task);
				wokenup++;
				continue;
			}
			if (up_mode == WAKEUP_ONE) {
				curr->cond_wakeuped = 1;
				wake_up_process(curr->task);
				wokenup++;
				break;
			}
			if (up_mode == MOVE_TO_MUTEX) {
				curr->cond_wakeuped = 1;
				move_to_mutex(curr);
				wokenup++;
				continue;
			}
			if (up_mode == WAKEUP_PID) {
				if (curr->task->pid == pid) {
					curr->cond_wakeuped = 1;
					wake_up_process(curr->task);
					wokenup++;
					break;
				}
				continue;
			}
			printk(KERN_INFO "pthread_run: bad up_mode =%d \n",
					up_mode);
			dump_stack();
		}
	}
	DbgPos("pthread_run end\n");
	return wokenup;
}

static int pthread_run(p_array_t *head, void *obj, int up_mode, int pid)
{
	int i = 0;
	int num = 0;

	i = sched_find_first_bit(head->bitmap);
	while (i < MAX_PRIO) {
		num += pthread_run_prio(head->prio_list + i, obj, up_mode, pid);
		if (list_empty(head->prio_list + i)) {
			__clear_bit(i, head->bitmap);
		}
		if (num && ((up_mode == WAKEUP_ONE) ||
					(up_mode == WAKEUP_PID))) {
			break;
		}
		i = find_next_bit(head->bitmap, MAX_PRIO, i + 1);
	}
	return num;
}



static void
pmutex_unlock_continue(pthread_mutex_t *mutex)
{
	el_pobjs_t 	*pobjs = current->pobjs;

	mutex->__m_owner = (void *)0;
	if (PImutex)
		current->prio = mutex->__m_owner_org_prio;
	DbgPos("unlock_continue: start %p __m_count=%d spn=%d\n",
			mutex, mutex->__m_count, mutex->__m_lock.__spinlock);
	if (wakeup_mutex_one) {
		pthread_run(&pobjs->pmutx_task_list, mutex, WAKEUP_ONE, 0);
	} else {
		pthread_run(&pobjs->pmutx_task_list, mutex, WAKEUP_ALL, 0);
	}
}
	/*
	 * Main synchro algorithm beetwin lock - unlock is based on
	 * atomic operation:
	 * 	xchg(mutex_spin, PMUTEX_UNLOCKED); and
	 *	xchg(mutex_spin, -mutex->__m_count); or
	 *
	 * In our schema  mutex_spin (mutex->__m_lock.__spinlock) can be:
	 *
	 * 	== 1 (PMUTEX_UNLOCKED)
	 *	== 0 (PMUTEX_LOCKED_ONCE)
	 *      == -__m_count (sleepers) (LOCKED too)
	 *
	 * When user do
	 *	xchg(mutex_spin, -mutex->__m_count);
	 * user go in kernel if mutex_spin <= PMUTEX_LOCKED_ONCE
	 * When user do
	 *	xchg(mutex_spin, PMUTEX_UNLOCKED);
	 * user go in kernel if mutex_spin < 0 (no sleepers).
	 *
	 * Bellow we try to substantiate that all is OK for our schema
	 * (time growes down: t1, t2, ...).
	 *
	 * Consider next sitations:
	 *
	 * 1. There are 2 threads thread_0 & thread_1 which work so:
	 *
	 * t1: thread_0	xchg(mutex_spin, PMUTEX_LOCKED_ONCE);
	 * t2: thread_1	xchg(mutex_spin, PMUTEX_LOCKED_ONCE);
	 * t3: thread_0	xchg(mutex_spin, PMUTEX_UNLOCKED);
	 *
	 * In this time (t3) thread_1 works or will work in kernel and will do
	 *
	 *	xchg(mutex_spin, -mutex->__m_count);
	 *
	 * in any case before or after thread_0 (owner) will do
	 *
	 *   	xchg(mutex_spin, PMUTEX_UNLOCKED);
	 *
	 * 1.1. thread_0 before thread_1:
	 *
	 * t1: thread_0 xchg(mutex_spin, PMUTEX_LOCKED_ONCE);
	 * t2: thread_0 xchg(mutex_spin, PMUTEX_UNLOCKED);
	 * t3: thread_1 xchg(mutex_spin, -mutex->__m_count);
	 *
	 * In this case thread_1 will be owner,
	 * because mutex_spin == PMUTEX_UNLOCKED
	 *
	 * 1.2. thread_1 before thread_0
	 *
	 * t1: thread_0 xchg(mutex_spin, PMUTEX_LOCKED_ONCE);
	 * t2: thread_1 xchg(mutex_spin, -mutex->__m_count);
	 * t3: thread_0 xchg(mutex_spin, PMUTEX_UNLOCKED);
	 *
	 * When thread_0 do
	 * 	xchg(mutex_spin, PMUTEX_UNLOCKED);
	 * __m_count == 1; and mutex_spin == -1;
	 * so thread_0 go to kernel because mutex_spin < PMUTEX_LOCKED_ONCE (-1)
	 * to do wakeup()
	 * So for two threads every thing is OK in any case.
	 *
	 * 2. There are 3 threads thread_0, thread_1, thread_2.
	 * 2.1
	 * For any threads i (i > 0) we can say the same as
	 * in 1 (instead of thread_1 can be any thread_i).
	 * Different is only that value of __m_count can be > 1
	 * and value of mutex_spin < -1
	 *
	 * Uh !!!
	 */

static int
pmutex_unlock(pthread_mutex_t *mutex)
{
	int		rval;
	int 		*mutex_spin = &mutex->__m_lock.__spinlock;

	DbgPos("unlock: start %p __m_count=%d spn=%d\n",
			mutex, mutex->__m_count, *mutex_spin);
	rval = xchg(mutex_spin, PMUTEX_UNLOCKED);
	if (rval == PMUTEX_LOCKED_ONCE) {
		return 0;
	}
	if (rval >= PMUTEX_UNLOCKED) {
		WARN_ON_ONCE(rval > PMUTEX_UNLOCKED);
		printk(KERN_INFO "%d pmutex_unlock: mutex %p ISN'T locked "
				"rval=%d\n", current->pid, mutex, rval);
		WARN_ON_ONCE(1);
		return -EINVAL;
	}
	pmutex_unlock_continue(mutex);
	DbgPos("unlock: end\n");
	return 0;
}

static struct task_struct *__find_task_by_pid_check(pid_t pid);

static int
pmutex_lock_continue(pthread_mutex_t *mutex)
{
	int			rval;
	el_pobjs_t 		*pobjs;
	struct task_struct 	*tsk = current;
	struct task_struct 	*owner_tsk;
	int 			*mutex_spin = &mutex->__m_lock.__spinlock;
	pwait_q_t		wait;

	pwaitq_init(&wait, tsk, mutex);
	pobjs = current->pobjs;
	add_to_p_array(&wait.task_list, &pobjs->pmutx_task_list,tsk->prio);
	mutex->__m_count++;
	DbgPos("lock_continue: start %p __m_count=%d spn=%d\n",
			mutex, mutex->__m_count, mutex->__m_lock.__spinlock);
	for (;;) {
		rval = xchg(mutex_spin, -(mutex->__m_count));
		if (rval == PMUTEX_UNLOCKED) {
			DbgPos("lock_continue: I am owner __m_count=%d\n",
					mutex->__m_count);
			//WARN_ON(mutex->__m_count != 1);
			break;
		}
		if ( PImutex &&     // debuging
		    (long)(mutex->__m_owner) &&
		    tsk->prio < mutex->__m_owner_org_prio) { // this test is for optimization
			read_lock(&tasklist_lock);
			owner_tsk = __find_task_by_pid_check((long)(mutex->__m_owner));
			if (owner_tsk) {
				get_task_struct(owner_tsk);
				read_unlock(&tasklist_lock);
				if (tsk->prio < owner_tsk->prio) {
					rt_mutex_setprio(owner_tsk, tsk->prio);
				}
				put_task_struct(owner_tsk);
			} else {
				read_unlock(&tasklist_lock);
				printk(KERN_INFO "PImutex owner_tsk empty "
						"mutex->__m_owner=%ld\n",
						(long)(mutex->__m_owner));
			}
		}
		tsk->state = TASK_INTERRUPTIBLE;
		raw_spin_unlock_irq_no_resched(&pobjs->pobj_lock);
		schedule();
		raw_spin_lock_irq(&pobjs->pobj_lock);
		if (signal_pending(current)) {
			mutex->__m_count--;
			WARN_ON(mutex->__m_count < 0);
			DbgPos("lock_continue: sig __m_count=%d spn=%d atomic_dec=%d\n",
					mutex->__m_count, mutex->__m_lock.__spinlock, rval);
			WARN_ON(wait.task_list.next == LIST_POISON1);
			WARN_ON(wait.task_list.prev == LIST_POISON2);
			list_del(&wait.task_list);
			tsk->state = TASK_RUNNING;
			return -EINTR;
		}

	}
	WARN_ON(tsk->state != TASK_RUNNING);
	DbgPos("lock_continue: end __m_count=%d spn=%d atomic_dec=%d\n",
			mutex->__m_count, mutex->__m_lock.__spinlock, rval);
	mutex->__m_count--;
	WARN_ON(mutex->__m_count < 0);
	WARN_ON(wait.task_list.next == LIST_POISON1);
	WARN_ON(wait.task_list.prev == LIST_POISON2);
	list_del(&wait.task_list);
	mutex->__m_owner = (void *)(long)current->pid;
	mutex->__m_owner_org_prio = current->prio;
	return 0;
}
static int
pmutex_lock(pthread_mutex_t *mutex, el_pobjs_t *pobjs)
{
	int			rval;
	int 			*mutex_spin = &mutex->__m_lock.__spinlock;
	unsigned long 		flags;
//	unsigned long t1, t2;
	int i;

	DbgPos("lock: start mutex=%p __m_count=%d __spinlock=%d\n",
			mutex, mutex->__m_count, *mutex_spin);
	/*
	 *  __m_count should be >=0 in any time
	 * We do it without any synchro and check it on the off chance
	 */
	WARN_ON(mutex->__m_count < 0);
#if 0
#ifdef __e2k__
	for (i = 1; i < 36 * my_cpu_data.proc_freq / (100 * 1000 * 1000); i++) {
#else
	for (i = 1; i < 2000; i++) {
#endif
#endif
	for (i = 0; i < pobjs->adaptive_count; i++) {
		rval = xchg(mutex_spin, -(mutex->__m_count));
		WARN_ON(rval > PMUTEX_UNLOCKED);
		if (rval == PMUTEX_UNLOCKED) {
			DbgPos("lock: rval == PMUTEX_UNLOCKED\n");
			mutex->__m_owner = (void *)(long)current->pid; /* I am owner */
// PI		mutex->__m_owner_org_prio = current->prio;
			return 0;
		}
		udelay(1);
	}
	raw_spin_lock_irqsave(&pobjs->pobj_lock, flags);
	rval = pmutex_lock_continue(mutex); // returns 0 or EINTR
	raw_spin_unlock_irqrestore(&pobjs->pobj_lock, flags);
	return rval;
}
int test_tsk[3];
static int
pcond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex)
{
	el_pobjs_t 		*pobjs;
	int			rval;
	int			rval1;
	struct task_struct 	*tsk = current;
	pwait_q_t		wait;
	unsigned long 		flags;

	DbgPos("pcond_wait: start cond=%p mutex=%p\n", cond, mutex);
	pobjs = current->pobjs;
	raw_spin_lock_irqsave(&pobjs->pobj_lock, flags);
	rval = pmutex_unlock(mutex);
	if (rval) {
		raw_spin_unlock_irqrestore(&pobjs->pobj_lock, flags);
		return rval;
	}
	pwaitq_init(&wait, tsk, (void *)cond);
	wait.mutex = mutex;
	add_to_p_array(&wait.task_list, &pobjs->pcond_task_list, tsk->prio);
	while (!wait.cond_wakeuped && !signal_pending(current)) {
		tsk->state = TASK_INTERRUPTIBLE;
		raw_spin_unlock_irq_no_resched(&pobjs->pobj_lock);
		schedule();
		raw_spin_lock_irq(&pobjs->pobj_lock);
	};
	WARN_ON(tsk->state != TASK_RUNNING);
	DbgPos("pcond_wait: after schedule() %p\n", cond);

	WARN_ON(wait.task_list.next == LIST_POISON1);
	WARN_ON(wait.task_list.prev == LIST_POISON2);
	list_del(&wait.task_list);
	raw_spin_unlock_irqrestore(&pobjs->pobj_lock, flags);
	if (wait.moved_to_mutex)
		return 0;
	do {
		if (signal_pending(current) &&
			!(sigismember(&current->pending.signal, SIGKILL))) {
			if (test_and_clear_tsk_thread_flag(current,
					TIF_SIGPENDING))
				rval = -EINTR;
		}
		rval1 = pmutex_lock(mutex, pobjs); // returns 0 or EINTR
	} while (rval1 == -EINTR && !(sigismember(&current->pending.signal, SIGKILL)));
	if (rval == -EINTR)
		set_tsk_thread_flag(current, TIF_SIGPENDING);
	DbgPos("pcond_wait: rval=%d\n", rval);
	return rval;
}

static int
pcond_timedwait(pthread_cond_t *cond, pthread_mutex_t *mutex,
					struct timespec *rqtp)
{
	el_pobjs_t 		*pobjs;
	unsigned long 		expire;
	int			rval = 0;
	struct task_struct 	*tsk = current;
	pwait_q_t		wait;
	unsigned long 		flags;

	DbgPos("pcond_timedwait: start\n");
	pobjs = current->pobjs;
	raw_spin_lock_irqsave(&pobjs->pobj_lock, flags);
	rval = pmutex_unlock(mutex);
	if (rval) {
		raw_spin_unlock_irqrestore(&pobjs->pobj_lock, flags);
		return rval;
	}
	pwaitq_init(&wait, tsk, (void *)cond);
	wait.mutex = mutex;
	add_to_p_array(&wait.task_list, &pobjs->pcond_task_list, tsk->prio);
	expire = timespec_to_jiffies(rqtp) + (rqtp->tv_sec || rqtp->tv_nsec);
	while (!wait.cond_wakeuped && !expire &&
			!signal_pending(current)) {
		tsk->state = TASK_INTERRUPTIBLE;
		raw_spin_unlock_irq_no_resched(&pobjs->pobj_lock);
		expire = schedule_timeout(expire);
		raw_spin_lock_irq(&pobjs->pobj_lock);
	};
	WARN_ON(tsk->state != TASK_RUNNING);
	WARN_ON(wait.task_list.next == LIST_POISON1);
	WARN_ON(wait.task_list.prev == LIST_POISON2);
	list_del(&wait.task_list);
	if (expire == 0) {
		raw_spin_unlock_irqrestore(&pobjs->pobj_lock, flags);
		return  -ETIMEDOUT;
	}
	if (signal_pending(current)) {
		raw_spin_unlock_irqrestore(&pobjs->pobj_lock, flags);
		return -EINTR;
	}
	raw_spin_unlock_irqrestore(&pobjs->pobj_lock, flags);
	do {
		rval = pmutex_lock(mutex, pobjs);	// returns 0 or EINTR
	} while (rval == -EINTR && !(sigismember(&current->pending.signal, SIGKILL)));
	return rval;
}

static int
pcond_broadcast(pthread_cond_t *cond)
{
	el_pobjs_t 	*pobjs;
	unsigned long	flags;

	DbgPos("pcond_broadcast: cond=%p start\n", cond);
	pobjs = current->pobjs;
	raw_spin_lock_irqsave(&pobjs->pobj_lock, flags);
	if (to_do_move_to_mutex)
		pthread_run(&pobjs->pcond_task_list, (void *)cond, MOVE_TO_MUTEX, 0);
	else
		pthread_run(&pobjs->pcond_task_list, (void *)cond, WAKEUP_ALL, 0);
	raw_spin_unlock_irqrestore(&pobjs->pobj_lock, flags);
	DbgPos("pcond_broadcast: finish\n");
	return 0;
}
static int
pcond_signal(pthread_cond_t *cond)
{
	el_pobjs_t 	*pobjs;
	unsigned long	flags;

	DbgPos("pcond_broadcast: start\n");
	pobjs = current->pobjs;
	raw_spin_lock_irqsave(&pobjs->pobj_lock, flags);
	pthread_run(&pobjs->pcond_task_list, (void *)cond, WAKEUP_ONE, 0);
	DbgPos("pcond_broadcast: finish\n");
	raw_spin_unlock_irqrestore(&pobjs->pobj_lock, flags);
	return 0;
}
static int
pcond_unlock_wait(pthread_cond_t *cond, pthread_mutex_t *mutex)
{
	el_pobjs_t 		*pobjs;
	int			rval;
	unsigned long 		flags;
	struct task_struct 	*tsk = current;
	pwait_q_t		wait;

	DbgPos("pcond_unlock_wait: start\n");
	pobjs = current->pobjs;
	raw_spin_lock_irqsave(&pobjs->pobj_lock, flags);
	rval = pmutex_unlock(mutex);
	if (rval) {
		raw_spin_unlock_irqrestore(&pobjs->pobj_lock, flags);
		return rval;
	}
	pwaitq_init(&wait, tsk, (void *)cond);
	wait.mutex = mutex;
	add_to_p_array(&wait.task_list, &pobjs->pcond_task_list, tsk->prio);
	while (!wait.cond_wakeuped && !signal_pending(current)) {
		tsk->state = TASK_INTERRUPTIBLE;
		raw_spin_unlock_irq_no_resched(&pobjs->pobj_lock);
		schedule();
		raw_spin_lock_irq(&pobjs->pobj_lock);
	};
	WARN_ON(tsk->state != TASK_RUNNING);
	WARN_ON(wait.task_list.next == LIST_POISON1);
	WARN_ON(wait.task_list.prev == LIST_POISON2);
	list_del(&wait.task_list);
	raw_spin_unlock_irqrestore(&pobjs->pobj_lock, flags);
	DbgPos("pcond_unlock_wait: finish wakeuped=%d sig_pend=%d\n",
			wait.cond_wakeuped, signal_pending(current));
	if (signal_pending(current))
		return -EINTR;
	WARN_ON(!wait.cond_wakeuped);
	return 0;
}

static int
el_pthread_wait(pthread_cond_t *cond)
{
	el_pobjs_t 		*pobjs;
	unsigned long 		flags;
	struct task_struct 	*tsk = current;
	pwait_q_t		wait;

	DbgPos("el_pthread_wait: start\n");
	pwaitq_init(&wait, tsk, (void *)cond);

	pobjs = current->pobjs;
	raw_spin_lock_irqsave(&pobjs->pobj_lock, flags);
	add_to_p_array(&wait.task_list, &pobjs->pcond_task_list, tsk->prio);
	while (!wait.cond_wakeuped && !signal_pending(current)) {
		tsk->state = TASK_INTERRUPTIBLE;
		raw_spin_unlock_irq_no_resched(&pobjs->pobj_lock);
		schedule();
		raw_spin_lock_irq(&pobjs->pobj_lock);
	};
	WARN_ON(tsk->state != TASK_RUNNING);
	WARN_ON(wait.task_list.next == LIST_POISON1);
	WARN_ON(wait.task_list.prev == LIST_POISON2);
	list_del(&wait.task_list);
	raw_spin_unlock_irqrestore(&pobjs->pobj_lock, flags);
	DbgPos("el_pthread_wait: finish\n");
	if (wait.cond_wakeuped)
		return 0;
	if (signal_pending(current))
		return -EINTR;
	WARN_ON(1);
	return 0;
}
static int
el_wakeup_pthread(pthread_cond_t *cond,  int pid)
{
	el_pobjs_t 		*pobjs;
	unsigned long 		flags;

	DbgPos("el_wakeup_pthread: start for %d\n", pid);
	pobjs = current->pobjs;
	raw_spin_lock_irqsave(&pobjs->pobj_lock, flags);
	pthread_run(&pobjs->pcond_task_list, (void *)cond, WAKEUP_PID, pid);
	raw_spin_unlock_irqrestore(&pobjs->pobj_lock, flags);
	DbgPos("el_wakeup_pthread: finish el_wakeup_pthread\n");
	return 0;
}

/*
 * Set rts_mode. enable mlock, param priority, setaffinity, cpu_bind,
 * irq_bind & mlock for all users.
 */
#ifdef CONFIG_MCST_RT
static long
change_rts_mode_mask(long mode, long mask)
{
	unsigned long flags;
	long ret = rts_mode;

	if (mode != -1 && mask != -1) {
		printk("change_rts_mode_mask wrong mode = %ld, mask = %ld\n", mode, mask);
		return -EINVAL;
	}
	raw_spin_lock_irqsave(&rts_lock, flags);

	if (mode != -1) {
		if (!capable(CAP_SYS_ADMIN)) {
			ret = -EPERM;
			goto unlock;
		}
	
		mode = !!mode;
		if (mode == rts_mode) {
			goto unlock;
		}
		rts_mode = mode;
		if (mode) {
			mask = RTS_SOFT__RT;
		} else {
			mask = 0;
		}
	}
	ret = rts_act_mask;
	rts_act_mask = mask;

unlock:
	raw_spin_unlock_irq(&rts_lock);
	return ret;
}

#include <linux/sysctl.h>

static DEFINE_MUTEX(sysctl_lock);
static int sysctl_rts_mode;
static int sysctl_rts_mask;


static int
rts_mode_sysctl(struct ctl_table *table, int write,
                     void __user *buffer, size_t *lenp,
                     loff_t *ppos)
{
        int ret;

        mutex_lock(&sysctl_lock); 
	sysctl_rts_mode = !!rts_mode; 
        ret  = proc_dointvec(table, write, buffer, lenp, ppos);

        if (ret || !write )
                goto out;
	       
	ret = (int)change_rts_mode_mask((long)sysctl_rts_mode, -1);

 out:
        mutex_unlock(&sysctl_lock);
        return ret;
}



static int
rts_mask_sysctl(struct ctl_table *table, int write,
                     void __user *buffer, size_t *lenp,
                     loff_t *ppos)
{
        int ret;

        mutex_lock(&sysctl_lock); 
	sysctl_rts_mask = (int)rts_act_mask; 
        ret  = proc_dointvec(table, write, buffer, lenp, ppos);

        if (ret || !write )
                goto out;
	       
	ret = (int)change_rts_mode_mask(-1, (long)sysctl_rts_mask);

 out:
        mutex_unlock(&sysctl_lock);
        return ret;
}

struct ctl_table rt_table[] = {
       {
                .procname       = "rts_mode",
                .data           = &sysctl_rts_mode,
                .maxlen         = sizeof(unsigned int),
                .mode           = 0644,
                .proc_handler   = rts_mode_sysctl,
       },
       {
                .procname       = "rts_act_mask",
                .data           = &sysctl_rts_mask,
                .maxlen         = sizeof(unsigned int),
                .mode           = 0644,
                .proc_handler   = rts_mask_sysctl,
        },
	{}
};

#endif


#include <asm/processor.h>
extern unsigned long loops_per_jiffy;
int
pthread_main_init(void)
{
	el_pobjs_t 	*pobjs;
	int i;

	down_write(&posix_sem);
	if (posix_objects == NULL) {
		/* it is first action in the system */
		posix_objects =
			(struct kmem_cache *)kmem_cache_create("el_pobjs_t",
			sizeof(el_pobjs_t), 0,
			SLAB_HWCACHE_ALIGN, NULL);
		if (!posix_objects) {
			printk(KERN_INFO "Cannot create posix_objects "
					"SLAB cache\n");
			up_write(&posix_sem);
			return -ENOMEM;
		}
	}
	up_write(&posix_sem);
	pobjs = (el_pobjs_t *)kmem_cache_alloc(posix_objects, GFP_KERNEL);
	if (!pobjs) {
		printk(KERN_INFO "Cannot alloc el_pobjs_t in SLAB cache\n");
		return -ENOMEM;
	}
	current->pobjs = (void *)pobjs;
	raw_spin_lock_init(&pobjs->pobj_lock);
	atomic_set(&pobjs->users_number, 0);
	pobjs->adaptive_count = 5;
	for (i = 0; i < MAX_PRIO; i++) {
		INIT_LIST_HEAD(pobjs->pmutx_task_list.prio_list + i);
		INIT_LIST_HEAD(pobjs->pcond_task_list.prio_list + i);
	}
	__set_bit(MAX_PRIO, pobjs->pmutx_task_list.bitmap);
	__set_bit(MAX_PRIO, pobjs->pcond_task_list.bitmap);
	return 0;
}

void pthread_exit(void)
{
	struct task_struct 	*tsk = current;
	el_pobjs_t 	*pobjs = current->pobjs;
	DbgPos("pthread_exit: kmem_cache_free for posix_objects\n");
	if (atomic_dec_and_test(&pobjs->users_number))
		kmem_cache_free(posix_objects, tsk->pobjs);
	tsk->pobjs = NULL;
}

int pmutex_init(pthread_mutex_t *mutex)
{
	DbgPos("pmutex_init: start for %p\n", mutex);
	mutex->__m_lock.__spinlock = PMUTEX_UNLOCKED;
	mutex->__m_count = 0;
	DbgPos("pmutex_init: finish\n");
	return 0;

}

int pcond_init(pthread_cond_t *cond)
{
	cond->__c_lock.__spinlock = PMUTEX_UNLOCKED;
	cond->__c_waiting = NULL;
	return 0;
}

#ifdef CONFIG_MCST_RT
DEFINE_PER_CPU(rt_cpu_data_t, rt_cpu_data);

extern int set_user_irq_thr(int irq);
extern int unset_user_irq_thr(void);
#endif

#define BAD_USER_REGION(addr, type) \
	(unlikely(!access_ok(VERIFY_WRITE, addr, sizeof(type)) \
		|| (((unsigned long) addr) % __alignof__(type)) != 0 ))

/*
 * If user call any func with bad addres in user area then he get SIGSEGV
 * from kernel's do_page_fault()
 */


/* To simplify 32-bit support user-space library always uses
 * 64-bit values for tv_sec and tv_nsec in struct timespec. */
struct timespec_64 {
	long long tv_sec;
	long long tv_nsec;
};


static int do_main_init(unsigned int *cs_cost, unsigned int *kernel_flags);
static int do_object_init_fini(unsigned long type,
		void *op,
		void *obj,
		int arg);
static int do_sem_post(struct posix_sem_s *__restrict const sem,
		const int __s_desc);
#if defined ARCH_HAS_ATOMIC_CMPXCHG
static int do_sem_timedwait(struct posix_sem_s *__restrict const sem,
		struct timespec_64 *__restrict const abstime,
		const int __s_desc);
#else
static int do_sem_timedwait(struct posix_sem_s *__restrict const sem,
		struct timespec_64 *__restrict const abstime,
		const int __s_desc,
		const int try);
#endif
static int do_mutex_timedlock(
		struct pthread_mutex_s *__restrict const mutex,
		const struct timespec_64 *__restrict const abstime,
		const int __m_kind,
		const int __m_desc);
static int do_mutex_unlock(
		struct pthread_mutex_s *__restrict const mutex,
		const int __m_kind,
		const int __m_desc);
static int do_cond_timedwait(
		struct pthread_cond_s *const cond,
		struct pthread_mutex_s *const mutex,
		const struct timespec_64 *const abstime,
		const int ptr_64);
static int do_cond_wake(
		struct pthread_cond_s *const cond,
		const int __c_desc,
		const int up_mode);
static int do_barrier_wait(
		struct pthread_barrier_s *const barr,
		const unsigned int required,
		const int restarted,
		const int __b_desc);
static int do_cancel(pid_t tgid, pid_t *p, int signal);
#if !defined ARCH_HAS_ATOMIC_CMPXCHG
static int do_sem_getvalue(struct posix_sem_s *__restrict const sem,
		const int __s_desc);
#endif
static int do_mutex_set_ceiling(
		struct pthread_mutex_s *const mutex,
		const int __m_desc,
		const int __m_kind_new,
		const int ptr_64);
static int do_mutex_consistent(
		struct pthread_mutex_s *const mutex,
		const int __m_kind,
		const int __m_desc);
static int do_set_unsafe_shared(pid_t pid, int *old_unsafe, int unsafe);
static int do_get_prio_protect(void);

static DEFINE_RAW_SPINLOCK(atomic_add_lock);

#ifdef CONFIG_RT_TICK_THREAD
static int tick_thread_start(s32 sec, s32 nsec);
static int tick_thread_continue(u32 *skipped, u32 *tick_wkup);
int        tick_thread_stop(void);
#endif

#ifdef CONFIG_MCST_RT
static int el_open_timerfd(void);
static int el_timerfd_settime(int ufd, struct itimerspec __user *tmr);
#ifdef CONFIG_COMPAT
static int compat_el_timerfd_settime(int ufd, struct compat_itimerspec __user *tmr);
#endif
#endif

int show_woken_time = 0;
EXPORT_SYMBOL(show_woken_time);

int __init woken_setup(char *str)
{
	show_woken_time = simple_strtoul(str, &str, 0);
	return 1;
}
__setup("wokent=", woken_setup);

static ssize_t woken_write(struct file *file, const char __user *ubuf,
				size_t count, loff_t *ppos)
{
	char str[64];

	if (count == 0)
		return 0;
	if (copy_from_user(str, ubuf, sizeof(str)))
		return -EFAULT;
	show_woken_time = simple_strtoul(str, NULL, 0);
	return count;
}

int show_woken(struct seq_file *p, void *v)
{
	seq_printf(p, "wokent= %d\n", show_woken_time);
	return 0;
}

static int woken_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, show_woken, PDE_DATA(inode));
}

static const struct file_operations proc_woken_operations = {
	.open           = woken_open,
	.read           = seq_read,
	.write		= woken_write,
	.llseek         = seq_lseek,
	.release        = seq_release,
};

static int __init proc_woken_init(void)
{
	proc_create("woken-time", 0, NULL, &proc_woken_operations);
	return 0;
}
module_init(proc_woken_init);

int  cpus_intcount[NR_CPUS];

#include <linux/cpuset.h>
static int pr_err_done = 0;
SYSCALL_DEFINE5(el_posix, int, req, void __user *, a1, void __user *, a2,
		void __user *, a3, int, a4)
{
	long 		rval = 0;
	int		cpu = 0;
	el_pobjs_t 	*pobjs;
	unsigned long	flags;

	/* This way compiler will use a jump table here. */
	switch (req - POSIX_MAIN_INIT) {
	case POSIX_MAIN_INIT - POSIX_MAIN_INIT:
		if (BAD_USER_REGION(a1, unsigned int)) {
			rval = -EINVAL;
			break;
		}
		if (BAD_USER_REGION(a2, unsigned int)) {
			rval = -EINVAL;
			break;
		}
		rval = do_main_init((unsigned int *) a1, (unsigned int *) a2);
		break;
	case POSIX_OBJECT_INIT_FINI - POSIX_MAIN_INIT:
		rval = do_object_init_fini((unsigned long) a1, a2, a3, a4);
		break;
	case POSIX_SEM_POST - POSIX_MAIN_INIT:
		if (BAD_USER_REGION(a1, struct posix_sem_s)) {
			rval = -EINVAL;
			break;
		}
		rval = do_sem_post((struct posix_sem_s *) a1,
				(int) (unsigned long) a2);
		break;
	case POSIX_SEM_TIMEDWAIT - POSIX_MAIN_INIT:
		if (BAD_USER_REGION(a1, struct posix_sem_s)) {
			rval = -EINVAL;
			break;
		}
#if defined ARCH_HAS_ATOMIC_CMPXCHG
		rval = do_sem_timedwait((struct posix_sem_s *) a1,
				(struct timespec_64 *) a2,
				(int) (unsigned long) a3);
#else
		rval = do_sem_timedwait((struct posix_sem_s *) a1,
				(struct timespec_64 *) a2,
				(int) (unsigned long) a3, a4);
#endif
		break;
	case POSIX_MUTEX_TIMEDLOCK - POSIX_MAIN_INIT:
		if (BAD_USER_REGION(a1, struct pthread_mutex_s)) {
			rval = -EINVAL;
			break;
		}
		rval = do_mutex_timedlock((struct pthread_mutex_s *) a1,
				(struct timespec_64 *) a2,
				(int) (unsigned long) a3, a4);
		break;
	case POSIX_MUTEX_UNLOCK - POSIX_MAIN_INIT:
		if (BAD_USER_REGION(a1, struct pthread_mutex_s)) {
			rval = -EINVAL;
			break;
		}
		rval = do_mutex_unlock((struct pthread_mutex_s *) a1,
				(int) (unsigned long) a2,
				(int) (unsigned long) a3);
		break;
	case POSIX_COND_TIMEDWAIT - POSIX_MAIN_INIT:
		if (BAD_USER_REGION(a1, struct pthread_cond_s)) {
			rval = -EINVAL;
			break;
		}
		if (BAD_USER_REGION(a2, struct pthread_mutex_s)) {
			rval = -EINVAL;
			break;
		}
		rval = do_cond_timedwait((struct pthread_cond_s *) a1,
				(struct pthread_mutex_s *) a2,
				(struct timespec_64 *) a3, a4);
		break;
	case POSIX_COND_WAKE - POSIX_MAIN_INIT:
		if (BAD_USER_REGION(a1, struct pthread_cond_s)) {
			rval = -EINVAL;
			break;
		}
		rval = do_cond_wake((struct pthread_cond_s *) a1,
				(int) (unsigned long) a2,
				(int) (unsigned long) a3);
		break;
	case POSIX_BARRIER_WAIT - POSIX_MAIN_INIT:
		if (BAD_USER_REGION(a1, struct pthread_barrier_s)) {
			rval = -EINVAL;
			break;
		}
		rval = do_barrier_wait((struct pthread_barrier_s *) a1,
				(unsigned int) (unsigned long) a2,
				(int) (unsigned long) a3, a4);
		break;
	case POSIX_CANCEL - POSIX_MAIN_INIT:
		rval = do_cancel((pid_t) (unsigned long) a1, (pid_t *) a2,
				(int) (unsigned long) a3);
		break;
	case POSIX_COLLECT_SHARED - POSIX_MAIN_INIT:
		rval = -ENOSYS;
		break;
	case POSIX_SEM_GET_VALUE - POSIX_MAIN_INIT:
#ifdef ARCH_HAS_ATOMIC_CMPXCHG
		rval = -ENOSYS;
#else
		if (BAD_USER_REGION(a1, struct posix_sem_s)) {
			rval = -EINVAL;
			break;
		}
		rval = do_sem_getvalue((struct posix_sem_s *) a1,
				(int) (unsigned long) a2);
#endif
		break;
	case POSIX_MUTEX_SET_CEILING - POSIX_MAIN_INIT:
		if (BAD_USER_REGION(a1, struct pthread_mutex_s)) {
			rval = -EINVAL;
			break;
		}
		rval = do_mutex_set_ceiling((struct pthread_mutex_s *) a1,
				(int) (unsigned long) a2,
				(int) (unsigned long) a3, a4);
		break;
	case POSIX_MUTEX_CONSISTENT - POSIX_MAIN_INIT:
		if (BAD_USER_REGION(a1, struct pthread_mutex_s)) {
			rval = -EINVAL;
			break;
		}
		rval = do_mutex_consistent((struct pthread_mutex_s *) a1,
				(int) (unsigned long) a2,
				(int) (unsigned long) a3);
		break;
	case POSIX_SET_PARAMETER - POSIX_MAIN_INIT:
		switch ((unsigned long) a1) {
		case POSIX_UNSAFE_SHARED:
			rval = do_set_unsafe_shared((pid_t) (unsigned long) a2,
					(int *) a3, a4);
			break;
		default:
			rval = -EINVAL;
			break;
		}
		break;
	case POSIX_GET_PRIO_PROTECT - POSIX_MAIN_INIT:
		rval = security_task_getscheduler(current);
		if (!rval)
			rval = do_get_prio_protect();
		break;
	}
	if (req >= POSIX_MAIN_INIT)
		goto out;

	pobjs = current->pobjs;
	if (pobjs == NULL && req > PTHREAD_MAIN_INIT)
		 goto BAD;

	switch (req) {
	case PTHREAD_MAIN_INIT:
		rval = pthread_main_init();
		break;
	case PTHREAD_SET_KERNEL_IMPL:
		if (current->pobjs == NULL) {
			return -EINVAL;
		}
		((el_pobjs_t *)current->pobjs)->pjobs_flag |= PJOBS_FLG_KERNEL_IMPL;
		break;
	case PTHREAD_MUTEX_INIT:
		if (BAD_USER_REGION(a1, sizeof(pthread_mutex_t)))
			return -EFAULT;
		rval = pmutex_init((pthread_mutex_t *)a1);
		break;
	case PTHREAD_COND_INIT:
		if (BAD_USER_REGION(a1, sizeof(pthread_cond_t))) {
			rval = -EFAULT;
			break;
		}
		rval = pcond_init((pthread_cond_t *)a1);
		break;
	case PTHREAD_MUTEX_LOCK:
		if (BAD_USER_REGION(a1, sizeof(pthread_mutex_t)))
			return -EFAULT;
	     //   DELAY_PRINT(("MutexLock Enter 0x%lx\n", a1));
		raw_spin_lock_irqsave(&pobjs->pobj_lock, flags);
		rval = pmutex_lock_continue((pthread_mutex_t *)a1); //rval=0 or EINTR
		raw_spin_unlock_irqrestore(&pobjs->pobj_lock, flags);
	      //  DELAY_PRINT(("MutexLock Exit 0x%lx\n", a1));
		break;
	case PTHREAD_MUTEX_UNLOCK:
		if (BAD_USER_REGION(a1, sizeof(pthread_mutex_t)))
			return -EFAULT;
		raw_spin_lock_irqsave(&pobjs->pobj_lock, flags);
		if (((el_pobjs_t *)current->pobjs)->pjobs_flag & PJOBS_FLG_KERNEL_IMPL) {
	       		 pmutex_unlock((pthread_mutex_t *)a1);
		} else {
			pmutex_unlock_continue((pthread_mutex_t *)a1);
		}
		raw_spin_unlock_irqrestore(&pobjs->pobj_lock, flags);
		rval = 0;
		break;
	case PTHREAD_COND_WAIT:
		if (BAD_USER_REGION(a1, sizeof(pthread_cond_t)))
			return -EFAULT;
		if (BAD_USER_REGION(a2, sizeof(pthread_mutex_t)))
			return -EFAULT;
		rval = pcond_wait((pthread_cond_t *)a1, (pthread_mutex_t *)a2);
		break;
	case PTHREAD_COND_TIMEDWAIT:
		if (BAD_USER_REGION(a1, sizeof(pthread_cond_t)))
			return -EFAULT;
		if (BAD_USER_REGION(a2, sizeof(pthread_mutex_t)))
			return -EFAULT;
		if (BAD_USER_REGION(a3, sizeof(struct timespec_64)))
			return -EFAULT;
		rval = pcond_timedwait((pthread_cond_t *)a1,
			(pthread_mutex_t *)a2, (struct timespec *)a3);
		break;
	case PTHREAD_COND_BROADCAST:
		if (BAD_USER_REGION(a1, sizeof(pthread_cond_t)))
			return -EFAULT;
		rval = pcond_broadcast((pthread_cond_t *)a1);
		break;
	case PTHREAD_COND_SIGNAL:
		if (BAD_USER_REGION(a1, sizeof(pthread_cond_t)))
			return -EFAULT;
	     //   DELAY_PRINT(("CondSignal Enter 0x%lx\n", a1));
		rval = pcond_signal((pthread_cond_t *)a1);
	     //   DELAY_PRINT(("CondSignal Exit 0x%lx\n", a1));
		break;
/* It isn't POSIX standart bellow */
	case EL_PCOND_UNLOCK_WAIT:
		if (BAD_USER_REGION(a1, sizeof(pthread_cond_t)))
			return -EFAULT;
		if (BAD_USER_REGION(a2, sizeof(pthread_mutex_t)))
			return -EFAULT;
		rval = pcond_unlock_wait((pthread_cond_t *)a1,
						(pthread_mutex_t *)a2);
		break;

	case EL_PTHREAD_WAIT:
		if (BAD_USER_REGION(a1, sizeof(pthread_cond_t)))
			return -EFAULT;
		rval = el_pthread_wait((pthread_cond_t *)a1);
		break;
	case EL_WAKEUP_PTHREAD_COND:
		if (BAD_USER_REGION(a1, sizeof(pthread_cond_t)))
			return -EFAULT;
		rval = el_wakeup_pthread((pthread_cond_t *)a1,
						(long)a2 & ~(int)0);
		break;
	case EL_ATOMIC_ADD: {
		int *target = (int *)a1;
		int delta   = (long)a2;
		int *dst    = (int *)a3;
		int val;

		raw_spin_lock_irq(&atomic_add_lock);
		rval = get_user(val, target);
		rval |= put_user(val, dst);
		rval |= put_user((val + delta), target);
		raw_spin_unlock_irq(&atomic_add_lock);
		break;
	}
	case EL_SET_TRACE_POINT:
	//	DELAY_PRINT(("User Mark: 0x%lx 0x%lx 0x%lx\n", a1, a2, a3));
		break;
#ifdef CONFIG_MCST_RT
	case EL_SET_SWITCH_CHECK:
		if (a1) {
			my_rt_cpu_data->flags |= RTCPU_FLG_CHECK_SWITCH;
		} else {
			if (my_rt_cpu_data->flags & RTCPU_FLG_CHECK_SWITCH) {
				my_rt_cpu_data->flags &= ~RTCPU_FLG_CHECK_SWITCH;
			} else {
				rval = 1;
			}
		}
		break;
#endif
	/* For mcst_rt lib: */
	case EL_GET_CPUS_NUM:
		rval = 0;
		for_each_online_cpu(cpu) rval++;
		return rval;
	case EL_GET_CPUS_MASK:
		rval = 0;
		for_each_online_cpu(cpu) {
			rval |= (1 << cpu);
		}
		return rval;
	case EL_MY_CPU_ID:
		rval = raw_smp_processor_id();
		return rval;
#ifdef CONFIG_SMP
	case EL_SET_IRQ_MASK:
		{
			unsigned long __maybe_unused cpu_mask = (long)a2;
#if defined(__e2k__) || defined(CONFIG_E90S) || \
		(defined(__i386__) && defined(CONFIG_GENERIC_PENDING_IRQ))
			unsigned long irq_mask = (long)a1;
			cpumask_var_t cpu_mask_bitmap;
			int i;
			if (!alloc_cpumask_var(&cpu_mask_bitmap, GFP_KERNEL))
				return -ENOMEM;
			cpumask_clear(cpu_mask_bitmap);
			for_each_online_cpu(i) {
				if (cpu_mask & (1 << i)) {
					if (cpu_online(i)) {
						cpumask_set_cpu(i, cpu_mask_bitmap);
					} else {
						return -EINVAL;
					}
				}
			}
			for (i = 0; i < NR_IRQS; i++) {
			    if ((irq_mask >= (1<<24)) || (irq_mask & 1 << i))
				if (irq_to_desc(i) && irq_can_set_affinity(i))
					irq_set_affinity(i, cpu_mask_bitmap);
			}
			free_cpumask_var(cpu_mask_bitmap);
#elif defined(CONFIG_E90)
			extern int smp4m_irq_set_mask(int cpu_mask, int on);
			extern int smp4m_irq_get_mask(void);
			unsigned long all_cpu_mask = 0;
			smp4m_irq_set_mask(cpu_mask, 1);
			for_each_online_cpu(cpu) {
				all_cpu_mask |= (1 << cpu);
	       		}
			rval = smp4m_irq_set_mask(all_cpu_mask & ~cpu_mask, 0);
			return smp4m_irq_get_mask();
#endif
		}
		break;
	case EL_GET_IRQ_MASK:
		/* sets 1 in cpu_mask if some irq may be send to the cpu# */
#if 0
//TODO 3.10
#if defined(__e2k__) || (defined(__i386__) && defined(CONFIG_GENERIC_PENDING_IRQ))
		{
			unsigned long irq_mask = (long)a1;
			unsigned long cpu_mask = 0;
			cpumask_t cpu_mask_bitmap = CPU_MASK_NONE;
			int i;
			for (i = 0; i < NR_IRQS; i++)
				if (irq_to_desc(i))
				if ((irq_mask >= (1<<24)) || !irq_mask || irq_mask & 1 << i)
					cpus_or(cpu_mask_bitmap, cpu_mask_bitmap,
						*(irq_to_desc(i)->affinity));
			for_each_online_cpu(i)
				if (cpu_isset(i, cpu_mask_bitmap))
					cpu_mask |= 1 << i;
			return cpu_mask;
		}
#elif defined(CONFIG_E90)
		{
			extern int smp4m_irq_get_mask(void);
			rval = smp4m_irq_get_mask();
			return rval;
		}
#endif
#endif
		break;
#endif	/* SMP */
#ifdef CONFIG_MCST
	case EL_GET_CPU_KHZ:
		if (cpu_freq_hz == UNSET_CPU_FREQ)
			return -EINVAL;
		return cpu_freq_hz / 1000;
#endif
#if defined(CONFIG_E90S)
	case SPARC_GET_USEC:
		rval = put_user(get_cycles() * 1000000 / cpu_freq_hz,
					(long long *)a1);
		return rval;
#endif
#ifdef CONFIG_MCST_RT
	case EL_RTS_MODE:
		rval = change_rts_mode_mask((long) a1, -1);
		return rval;
	case EL_SET_RTS_ACTIVE:
		rval = change_rts_mode_mask(-1, (long) a1);
		return rval;
	case EL_GET_RTS_ACTIVE:
		return rts_act_mask;
	case EL_SET_USER_IRQ_THR:
		rval = set_user_irq_thr((long) a1);
		return rval;
	case EL_UNSET_USER_IRQ_THR:
		rval = unset_user_irq_thr();
		return rval;
#if 0
	case EL_START_TASK_TIMER: {
		long timeout = (long)a1;
		long sleep   = (long)a2;
		if (timeout < 0) {
			return -EINVAL;
		}
		timeout = (timeout * HZ) / 1000;
		if (timeout == 0) {
			return 0;
		}
		if (sleep) {
			current->state = TASK_INTERRUPTIBLE;
			start_task_timer(timeout);
			schedule();
		} else {
			start_task_timer(timeout);
		}
		return 0;
	}
	case EL_STOP_TASK_TIMER:
		stop_task_timer();
		return 0;
#endif
#if defined(__e2k__)
	case EL_SET_APIC_TIMER:
	case EL_UNSET_APIC_TIMER:
		rval = -ENOSYS;
		break;
#endif
	case EL_SET_RTCPU_MODE:
	case EL_UNSET_RTCPU_MODE:
	case EL_GET_RTCPU_MODE: {
		int cpu;
		int msk = (int)(long)a2;
		if ((long)a1 == -1)
			cpu = raw_smp_processor_id();
		else
			cpu = (int)(long)a1;
		if (!cpu_possible(cpu)) {
			rval = -1;
			break;
		}
		if (req == EL_SET_RTCPU_MODE) {
			rt_cpu_data(cpu)->modes |= msk;
		} else if (req == EL_UNSET_RTCPU_MODE) {
			rt_cpu_data(cpu)->modes &= ~msk;
		}
		return rt_cpu_data(cpu)->modes;
	}
	case EL_GET_CPU_FREQ: {
#ifdef CONFIG_E90S
		int mb_type = bootblock_virt->info.bios.mb_type;
		if (cpu_freq_hz == UNSET_CPU_FREQ)
			return -EINVAL;
		if (mb_type == MB_TYPE_E90S_BUTTERFLY
				|| mb_type == MB_TYPE_E90S_SIVUCH2) {
			int i;
			for_each_online_cpu(i)
				if (cpu_freq_hz != cpu_data(i).clock_tick) {
					pr_warning("Error EL_GET_CPU_FREQ: freq_common"
						"(%u) != freq_cpu%02d (%lu)\n",
						cpu_freq_hz, i,
						cpu_data(i).clock_tick);
					cpu_freq_hz = UNSET_CPU_FREQ;
					return -EINVAL;
				}
		}
#elif defined(__e2k__)
		int i;
		u8 mb_type = bootblock_virt->info.bios.mb_type;

		/* Sivuch has multiple motherboards without clock
		 * synchronization. */
		if (mb_type == MB_TYPE_ES2_RTC_CY14B101P_MULTICLOCK)
			return -EINVAL;
		if (cpu_freq_hz == UNSET_CPU_FREQ)
			return -EINVAL;
		for_each_online_cpu(i)
			if (cpu_freq_hz != cpu_data[i].proc_freq) {
				pr_warning("Error EL_GET_CPU_FREQ: freq_common"
					"(%u) != freq_cpu%02u (%llu)\n",
					cpu_freq_hz, i,
					cpu_data[i].proc_freq);
				cpu_freq_hz = UNSET_CPU_FREQ;
				return -EINVAL;
			}
#endif
		if (cpu_freq_hz == UNSET_CPU_FREQ)
			return -EINVAL;
		return cpu_freq_hz;
	}
	case EL_SET_CPU_FREQ: {
		u32 new_freq = (u32) (unsigned long) a1;
		int i;
		if (new_freq != 0) {
			for_each_online_cpu(i)
#ifdef CONFIG_E90S
				cpu_data(i).clock_tick = new_freq;
#elif defined(__e2k__)
				cpu_data[i].proc_freq = new_freq;
#endif
			cpu_freq_hz = new_freq;
			return 0;
		} else {
			return -EINVAL;
		}
	}
#endif
	case EL_GET_HZ:
		rval = HZ;
		break;
#ifdef CONFIG_RT_TICK_THREAD
	case EL_TICK_THR_START:
#define MY_TICK_NSEC	(NSEC_PER_SEC / HZ)
		rval = tick_thread_start(((s32)(unsigned long)a1 * MY_TICK_NSEC)
						/ NSEC_PER_SEC,
				((s32)(unsigned long)a1 * MY_TICK_NSEC)
						% NSEC_PER_SEC);
#undef MY_TICK_NSEC
		break; 
        case EL_TICK_THR_START_NSEC:
                rval = tick_thread_start((s32) (unsigned long) a1,
				(s32) (unsigned long) a2);
                break;
	case EL_TICK_THR_CONT: {
		u32 s, t;
		rval = tick_thread_continue(&s, &t);
		if (rval == 0 && a1) {
			rval |= put_user(s, (u32 *)a1);
		}
		if (rval == 0 && a2) {
			rval |= put_user(t, (u32 *)a2);
		}
		break;
	}	
	case EL_TICK_THR_STOP:
		rval = tick_thread_stop();
		break;
#endif
#if 0
	case EL_SET_NET_RT:
		local_irq_disable();
		raw_spin_lock(&current->pi_lock);
		current->rt_flags |= RT_TASK_IS_NET_RT;
		raw_spin_unlock(&current->pi_lock);
		local_irq_enable();
		break;
	case EL_UNSET_NET_RT:
		local_irq_disable();
		raw_spin_lock(&current->pi_lock);
		current->rt_flags &= ~RT_TASK_IS_NET_RT;
		raw_spin_unlock(&current->pi_lock);
		local_irq_enable();
		break;
#endif
        case EL_SET_MLOCK_CONTROL :
                current->extra_flags |= RT_MLOCK_CONTROL;
                break;
        case EL_UNSET_MLOCK_CONTROL :
		current->extra_flags &= ~RT_MLOCK_CONTROL;
                break;
	case EL_SHOW_STATE:
		if (!capable(CAP_SYS_ADMIN)) {
			rval = -EPERM;
			break;
		}
		show_state();
		printk(KERN_INFO "\n");
		rval = 0;
		break;
#ifdef CONFIG_MCST
	case EL_GET_TIMES:
	{
		size_t sz = ((size_t)a2) / sizeof(long long);
		unsigned long long ip;
		unsigned long long *m = (unsigned long long *)a1;
		if (show_woken_time < 2) {
			if (pr_err_done)
				return -EINVAL;
			pr_err_done = 1;
			return -EINVAL;
		}

		if (sz > EL_GET_TIMES_WAKEUP) {
			rval = put_user(current->wakeup_tm,
				(m + EL_GET_TIMES_WAKEUP));
		}
		if (rval) {
			break;
		}
		if (sz > EL_GET_TIMES_SCHED_ENTER) {
			rval = put_user(current->sched_enter_tm,
				(m + EL_GET_TIMES_SCHED_ENTER));
		}
		if (rval) {
			break;
		}
		if (sz > EL_GET_TIMES_SCHED_LOCK) {
			rval = put_user(current->sched_lock_tm,
				(m + EL_GET_TIMES_SCHED_LOCK));
		}
		if (rval) {
			break;
		}
		if (sz > EL_GET_TIMES_WOKEN) {
			rval = put_user(current->waken_tm,
			(m + EL_GET_TIMES_WOKEN));
		}
		if (rval) {
			break;
		}
		if (sz > EL_GET_TIMES_LAST_PRMT_ENAB) {
			ip = (unsigned long long)current->last_ipi_prmt_enable;
			rval = put_user(ip, (m + EL_GET_TIMES_LAST_PRMT_ENAB));
		}
		if (rval) {
			break;
		}
		if (sz > EL_GET_TIMES_INTR_W) {
			rval = put_user(current->intr_w,
				(m + EL_GET_TIMES_INTR_W));
		}
		if (rval) {
			break;
		}
		if (sz > EL_GET_TIMES_INTR_S) {
			rval = put_user(current->intr_s,
				(m + EL_GET_TIMES_INTR_S));
		}
		if (rval) {
			break;
		}
		if (sz > EL_GET_TIMES_CNTXB) {
			rval = put_user(current->cntx_swb_tm,
				(m + EL_GET_TIMES_CNTXB));
		}
		if (rval) {
			break;
		}
		if (sz > EL_GET_TIMES_CNTXE) {
			rval = put_user(current->cntx_swe_tm,
				(m + EL_GET_TIMES_CNTXE));
		}
		if (rval) {
			break;
		}
		if (sz > EL_GET_TIMES_INTR_SC) {
			rval = put_user(current->intr_sc,
				(m + EL_GET_TIMES_INTR_SC));
		}
		if (rval) {
			break;
		}
		break;
	}
	case EL_WAKEUP_TIME:
		if (!show_woken_time) {
			if (pr_err_done)
				return -EINVAL;
			pr_err_done = 1;
			pr_err("%s(EL_WAKEUP_TIME): /proc/wokent is not set\n",
				__func__);
			return -EINVAL;
		}
		rval = put_user(current->wakeup_tm, (long long *)a1);
		break;
	case EL_WAKEN_TIME:
		if (!show_woken_time) {
			if (pr_err_done)
				return -EINVAL;
			pr_err_done = 1;
			pr_err("%s(EL_WAKEN_TIME): /proc/wokent is not set\n",
				__func__);
			return -EINVAL;
		}
		rval = put_user(current->waken_tm, (long long *)a1);
		break;
	case EL_WAKEUP_LAT:
		if (!show_woken_time) {
			if (pr_err_done)
				return -EINVAL;
			pr_err_done = 1;
			pr_err("%s(EL_WAKEUP_LAT): /proc/wokent is not set\n",
				__func__);
			return -EINVAL;
		}
		rval = put_user(current->waken_tm - current->wakeup_tm,
			(long long *)a1);
		break;
#endif
#ifdef CONFIG_MCST_RT
	case EL_USER_TICK: {
			int interval_us = (int)(long long)a1;
			do_postpone_tick(interval_us * 1000);
			break;
		}
	case EL_OPEN_TIMERFD :
		rval = el_open_timerfd();
		break;
	case EL_TIMERFD_SETTIME :
		rval = el_timerfd_settime((int) (unsigned long) a1, a2);
		break;
#endif
	case EL_GET_CPUS_INTCOUNT: {
		unsigned long len = (int) (unsigned long) a1;
		if (len > NR_CPUS) {
			rval = -EINVAL;
			break;
		}
		rval = copy_to_user((void *)a2, (void *)cpus_intcount,
			len * sizeof (int));
		if (rval) {
			rval = -EINVAL;
		}
		break;	
	}
#ifdef CONFIG_E90S
	case EL_SYNC_CYCLS: {
		int	i, this_cpu;
		do_sync_cpu_clocks = (unsigned long) a1;
		preempt_disable();
		this_cpu = smp_processor_id();
		for_each_online_cpu(i) {
			if (i != this_cpu)
				smp_synchronize_one_tick(i);
			else
				delta_ticks[i] = 0;
		}
		preempt_enable();
		return copy_to_user((void *)a2, (void *)delta_ticks,
				num_possible_cpus() * sizeof(long));
	}
#endif
#ifdef CONFIG_MCST_RT
	case EL_RT_CPU: {
		int set = (int)(long long)a1;
		struct task_struct *p, *t;
		unsigned long cpu = smp_processor_id();
		cpumask_var_t new_mask;
		int retval;
		int restore_flag = 0;

		if (set) {
			if (cpumask_test_cpu(cpu, rt_cpu_mask))
				return 0;
			if (!zalloc_cpumask_var(&new_mask, GFP_NOWAIT)) {
				return -ENOMEM;
			}
			cpumask_set_cpu(cpu, rt_cpu_mask);
#if 0
			pr_warning("RT_CPUset %lu rm=%5lx\n",
				cpu, cpumask_bits(rt_cpu_mask)[0]);
			trace_printk("RCPs rm=%5lx\n",
				cpumask_bits(rt_cpu_mask)[0]);
#endif
			read_lock(&tasklist_lock);
			do_each_thread(t, p) {
#if 0
				pr_warning("RT_CPUseB %lu %20s/%6d m=0x%5lx"
					" tcpu=%d md=%x na=%d\n",
					cpu, p->comm, p->pid,
					cpumask_bits(&p->cpus_allowed)[0],
					task_cpu(p), p->migrate_disable,
					p->nr_cpus_allowed);
#endif
				if (cpumask_weight(&p->cpus_allowed) == 1)
					continue;
				get_task_struct(p);
				if (p->state > TASK_UNINTERRUPTIBLE) {
					put_task_struct(p);
					continue;
				}
				cpumask_copy(new_mask, tsk_cpus_allowed(p));
				cpumask_clear_cpu(cpu, new_mask);
				restore_flag = p->flags & PF_NO_SETAFFINITY;
				p->flags &= ~PF_NO_SETAFFINITY;
				retval = sched_setaffinity(p->pid, new_mask);
				p->flags |= restore_flag;
				if (retval)
					pr_err("Could not set affinity "
						"%20s/%6d m=0x%5lx ER=%d\n",
						p->comm, p->pid,
						cpumask_bits(new_mask)[0],
						retval);
#if 0
				cpuset_cpus_allowed(p, new_mask);
				pr_warning("RT_CPUset %lu %20s/%6d m=0x%4lx "
					"sm=0x%4lx tcpu=%d md=%x na=%d ret=%d\n",
					cpu, p->comm, p->pid,
					cpumask_bits(&p->cpus_allowed)[0],
					cpumask_bits(new_mask)[0],
					task_cpu(p), p->migrate_disable,
					p->nr_cpus_allowed, retval);
#endif
				put_task_struct(p);
			} while_each_thread(t, p);
			read_unlock(&tasklist_lock);
			free_cpumask_var(new_mask);
#if 0
			cpu_callback(NULL, CPU_DEAD, cpu);
#endif
		} else {
			if (!cpumask_test_cpu(cpu, rt_cpu_mask))
				return 0;
			cpumask_clear_cpu(cpu, rt_cpu_mask);
			if (!zalloc_cpumask_var(&new_mask, GFP_NOWAIT)) {
				return -ENOMEM;
			}
			read_lock(&tasklist_lock);
			do_each_thread(t, p) {
				if (cpumask_weight(&p->cpus_allowed) == 1)
					continue;
				get_task_struct(p);
				if (p->state > TASK_UNINTERRUPTIBLE) {
					put_task_struct(p);
					continue;
				}
				cpumask_copy(new_mask, tsk_cpus_allowed(p));
				cpumask_set_cpu(cpu, new_mask);
				p->flags &= ~PF_NO_SETAFFINITY;
				retval = sched_setaffinity(p->pid, new_mask);
				p->flags |= restore_flag;
				if (retval)
					pr_err("Could not set affinity to cpu "
						"%20s/%6d m=0x%5lx ER=%d\n",
						p->comm, p->pid,
						cpumask_bits(new_mask)[0],
						retval);
#if 0
				pr_warning("RT_CPUunset %lu %20s/%6d m=0x%5lx"
					"curcpu=%d md=%d na=%d ret=%d\n",
					cpu, p->comm, p->pid,
					cpumask_bits(&p->cpus_allowed)[0],
					task_cpu(p), p->migrate_disable,
					p->nr_cpus_allowed, retval);
#endif
				put_task_struct(p);
			} while_each_thread(t, p);
			read_unlock(&tasklist_lock);
			free_cpumask_var(new_mask);
#if 0
			cpu_callback(NULL, CPU_UP_PREPARE, cpu);
			cpu_callback(NULL, CPU_ONLINE, cpu);
#endif
		}
		return 0;
	}
#endif
	case EL_MISC_TO_DEBUG:
		switch ((long) a1) {
		case 1: printk(KERN_INFO "el_posix: DEBUG to_do_move_to_mutex "
					"old=%ld new=%ld\n",
					to_do_move_to_mutex, (long) a2);
			to_do_move_to_mutex = (long) a2;
			break;
		case 2:
			//printk(KERN_INFO "el_posix: DEBUG wakeup_mutex_one "
			//		"old=%ld new=%ld\n",
			//		wakeup_mutex_one, (long) a2);
			wakeup_mutex_one = (long) a2;
			break;
		case 3: printk(KERN_INFO "el_posix: DEBUG redir_to_waiter "
					"old=%ld new=%ld\n",
					redir_to_waiter, (long) a2);
			redir_to_waiter = (long) a2;
			break;
		case 4: printk(KERN_INFO "el_posix: DEBUG PImutex old=%ld "
					"new=%ld\n", PImutex, (long) a2);
			PImutex = (long) a2;
			break;
		case 5: test_tsk[(long)a2] = (long)a3;
			printk(KERN_INFO "el_posix: DEBUG test pid=%d %d %d\n",
					test_tsk[0], test_tsk[1], test_tsk[2]);
			break;
		}
		DbgPos("sys_el_posix: EL_MISC_TO_DEBUG\n");
		break;
	default:
//		printk(KERN_INFO "sys_el_posix: UNRNOWN REQ %ld\n", req);
		rval = -EINVAL;
	}

out:
	if (rval < 0)
		DbgPos("posix ret error %ld for req %ld\n", rval, req);

	return rval;

BAD:
	return -EINVAL;
}

#ifdef CONFIG_COMPAT
asmlinkage long compat_sys_el_posix(int req, void __user *a1, void __user *a2,
				    void __user *a3, int a4)
{
	long rval;

	switch (req) {
#ifdef CONFIG_MCST_RT
		case EL_TIMERFD_SETTIME:
			rval = compat_el_timerfd_settime((int) (unsigned long) a1, a2);
			break;
#endif
		/* TODO: all el_posix users must use this interface */
		default:
			rval = sys_el_posix(req, a1, a2, a3, a4);
			break;
	}
	return rval;
}
#endif /* CONFIG_COMPAT */

/* POSIX compliant implementation.
 *
 * Highlights:
 * 1. Descriptors for mutexes and conditions are not allocated and freed
 * dynamically, thus it is necessary to call destructors.
 * 2. To support static initializers, functions mutex_once(), cond_once()
 * and so on check whether the descriptor has already been allocated.
 * 3. Broadcasting a condition with private mutex associated wakes only
 * one thread, but it is necessary to check for one special case: if a
 * thread locks a recursive mutex more than one time and calls
 * pthread_cond_wait(), then it remains an owner of the mutex.
 * 4. Use of mlock() will not protect from minor page faults. For
 * example, move_pages() still can move data around.
 */

/* Mutex types. */
enum {
	PTHREAD_MUTEX_TIMED_NP,
	PTHREAD_MUTEX_RECURSIVE_NP,
	PTHREAD_MUTEX_ERRORCHECK_NP,
	PTHREAD_MUTEX_ADAPTIVE_NP
};

/* Mutex protocols.  */
enum {
	PTHREAD_PRIO_NONE,
	PTHREAD_PRIO_INHERIT,
	PTHREAD_PRIO_PROTECT
};

/*
 * wake up modes
 */
enum wake_modes {
	MOVE_TO_MUTEX_ALL = 0,
	MOVE_TO_MUTEX_ONE = 1
};

/*
 * enum waiting_states - possible values of el_waiter.state field
 * @NOT_WAITING: process is not queued anywhere.
 * @WAITING_ON_CONDITION: process is queued on a condition.
 * @WAITING_ON_MUTEX: process is queued on a mutex.
 * @WAITING_ON_BARRIER: process is queued on a barrier.
 * @WAITING_ON_SEMAPHORE: process is queued on a semaphore.
 */
enum waiting_states {
	NOT_WAITING = 0,
	WAITING_ON_CONDITION,
	WAITING_ON_MUTEX,
	WAITING_ON_BARRIER,
	WAITING_ON_SEMAPHORE
};

/**
 * enum robust_state - robust mutex states.
 * @NOT_ROBUST: mutex was initialized without robust attribute set.
 * @ROBUST: mutex was initialized with robust attribute set and
 * 	is in consistent state.
 * @OWNER_DEAD: mutex is in inconsistent state and has an owner that must
 * 	mark it either as consistent with pthread_mutex_consistent() or
 * 	as permanently unusable by unlocking immediately.
 * @NOT_RECOVERABLE:
 * 	mutex is permanently unusable, all waiting threads are woken.
 *
 *
 * ARCH_HAS_ATOMIC_CMPXCHG is set:
 *
 * There are two ways for a mutex to arrive at OWNER_DEAD state - when owner
 * dies with fast-locked mutex (mutex->__m_lock field holds owner's pid) and
 * when owner dies with slow-locked mutex (mutex->__m_lock field holds -1).
 *
 * If the first case (the mutex was fast-locked) the next thread trying to
 * lock it will discover that the owner is dead and change mutex's state to
 * OWNER_DEAD. In this case mutex will have an owner.
 *
 * In the second case (the mutex was slow-locked) when the owner dies he will
 * either unlock it and move to OWNER_DEAD state (if mutex has waiters) or
 * will put an invalid pid (PID_MAX_LIMIT) into mutex->__m_lock field so that
 * the next thread to lock it will put the mutex in the OWNER_DEAD state.
 *
 * Thus mutex in OWNER_DEAD state always has an owner.
 *
 * If the mutex has no owner (!m_desc->owner && !m_desc->pending_owner) then
 * mutex->__m_lock field contains owner's pid and the task which called
 * mutex_lock() will try to set m_desc->owner field by calling
 * task_fast_locked_pi_mutex_proxy() or task_locked_pp_mutex_proxy(). If
 * the call succeeds the task will just block or return -EBUSY, and if it
 * does not the task will return the corresponding error code (-EOWNERDEAD).
 *
 * If m_desc->robust is set to NOT_RECOVERABLE, the mutex is in not
 * recoverable state and mutex->__m_lock is left with value '-1' to
 * make fast locking impossible. Mutex can enter this state only from
 * pthread_mutex_unlock(), so if we find out in do_mutex_unlock() that the
 * mutex is in OWNER_DEAD state, we change it to NOT_RECOVERABLE and wake
 * all waiters. Since mutex being in NOT_RECOVERABLE state is a new condition
 * indicating that the thread should wake up, the additional check
 * (m_desc->robust != NOT_RECOVERABLE) is done right before schedule() in
 * __do_mutex_timedlock() and do_cond_timedwait().
 *
 *
 * ARCH_HAS_ATOMIC_CMPXCHG is not set:
 *
 * This case is different: we cannot use mutex->__m_lock field to store
 * additional information about robust state the mutex is in. So in this
 * case OWNER_DEAD state does _not_ indicate that mutex has an owner -
 * only that its owner died.
 */
enum robust_state {
	NOT_ROBUST = 0,
	ROBUST,
	OWNER_DEAD,
	NOT_RECOVERABLE
};


/*
 * Descriptors.
 */

/**
 * struct mutex_desc - descriptor of a userspace POSIX mutex.
 * @lock: the internal lock.
 * @next_free: if this descriptor is free, then next_free points to the next
 * 	free descriptor, thus forming a single-linked list of free descriptors.
 * 	Otherwise stores '-1'.
 * @private: is the mutex private?
 * @desc_type: descriptor's type (MUTEX).
 * @wait_list: list of all tasks waiting for the release of this mutex.
 * @pending_owner: points to owner if ownership is pending.
 * @owner: points to owner if ownership is not pending.
 * @protocol: priority protection protocol used.
 * @type: the mutex's type (errorcheck, recursive, normal).
 * @robust: the mutex's robust state (see 'enum robust_state').
 * @prioceiling: prioceiling for PTHREAD_PRIO_PROTECT mutexes (in kernel
 * 	units, i.e. 0 is the highest priority).
 * @mutex_list_entry: list entry for the list of all priority protected
 * 	mutexes this thread owns (i.e. all PTHREAD_PRIO_INHERIT and
 * 	PTHREAD_PRIO_PROTECT mutexes).
 *
 * Pending owner is an owner that was given the mutex but has not been able
 * to enter its critical section yet because of contention for CPU, so if
 * some other (with higher priority) task tries to lock the mutex now it can
 * get it without corrupting anything.
 *
 * Using direct pointers to owners' task_struct's is OK since the kernel
 * maintains the list of all objects the process holds, and when the owner
 * dies it parses the list and unlocks all encountered mutexes leaving no
 * hanging pointers behind.
 */
struct mutex_desc {
	struct raw_spinlock lock;
	s16 next_free;
	char private;
	char desc_type;
	struct plist_head wait_list;
	struct task_struct *pending_owner;
	/* For priority inheritance and priority protection mutexes */
	struct task_struct *owner;
	char protocol;
	char type;
	char robust;
	/* Prioceiling (converted to kernel values). */
#if MAX_RT_PRIO > 256
# error char is not enough
#endif
	unsigned char prioceiling;
	union {
		struct list_head pi;
		struct plist_node pp;
	} mutex_list_entry;
};

/**
 * struct cond_desc - descriptor of a userspace POSIX condition variable.
 * @lock: the internal lock.
 * @next_free: if this descriptor is free, then next_free points to the next
 * 	free descriptor, thus forming a single-linked list of free descriptors.
 * 	Otherwise stores '-1'.
 * @private: is the condition variable private?
 * @desc_type: descriptor's type (CONDITION).
 * @wait_list: list of all tasks waiting for this condition.
 * @m_desc: the descriptor of the associated mutex (NULL if there aren't any).
 */
struct cond_desc {
	struct raw_spinlock lock;
	s16 next_free;
	char private;
	char desc_type;
	struct plist_head wait_list;
	struct mutex_desc *m_desc;
};

/**
 * struct barr_desc - descriptor of a userspace POSIX barrier.
 * @lock: the internal lock.
 * @next_free: if this descriptor is free, then next_free points to the next
 * 	free descriptor, thus forming a single-linked list of free descriptors.
 * 	Otherwise stores '-1'.
 * @private: is the barrier private?
 * @desc_type: descriptor's type (BARRIER).
 * @wait_list: list of all tasks waiting on this barrier.
 * @present: number of threads that have already arrived at this barrier.
 */
struct barr_desc {
	struct raw_spinlock lock;
	s16 next_free;
	char private;
	char desc_type;
	struct plist_head wait_list;
	unsigned int present;
};

/**
 * struct sem_desc - descriptor of a userspace POSIX semaphore.
 * @lock: the internal lock.
 * @next_free: if this descriptor is free, then next_free points to the next
 * 	free descriptor, thus forming a single-linked list of free descriptors.
 * 	Otherwise stores '-1'.
 * @private: is the semaphore private?
 * @desc_type: descriptor's type (SEMAPHORE).
 * @wait_list: list of all tasks waiting on this semaphore.
 * @waiters_nr: total number of waiters (for semaphores located partly in
 * 	kernel space and partly in user space).
 * @value: semaphore's value (for semaphores located entirely in kernel space).
 */
struct sem_desc {
	struct raw_spinlock lock;
	s16 next_free;
	char private;
	char desc_type;
	struct plist_head wait_list;
#if defined ARCH_HAS_ATOMIC_CMPXCHG
	int waiters_nr;
#else
	int value;
#endif
};

/**
 * struct el_waiter - used for waiting on mutexes and condition variables.
 * @state: state of the waiting thread (see enum waiting_states).
 * @list_entry: the list entry which is queued into descriptor's wait_list.
 * @task: points to the task_struct of the blocked task.
 * @desc: points to the descriptor if the task is waiting on a mutex.
 * @timedout: is set to 1 when the waiting task times out.
 * @pi_list_entry: used to implement PTHREAD_PRIO_INHERIT and
 * 	PTHREAD_PRIO_PROTECT protocols.
 *
 * struct el_waiter is allocated in the stack.
 *
 * The first four fields must be the same as in 'struct el_barrier_waiter'
 * (which is basically the same but only for barriers). */
struct el_waiter {
	int state;
	struct plist_node list_entry;
	struct task_struct *task;
	void *pi_desc;
	int timedout;
	struct plist_node pi_list_entry;
};


/*
 * Defines used when allocating descriptors.
 */

#define DESCS_NUMBER_BITS 6
#define DESCS_NUMBER (1 << DESCS_NUMBER_BITS)

#define BLOCKS_NUMBER_BITS 8
#define BLOCKS_NUMBER (1 << BLOCKS_NUMBER_BITS)

#define DESC_ALIGN 32

/* DESCS_NUMBER cannot be 16 because one bit
 * is used to mark process shared descs. */
#if BLOCKS_NUMBER_BITS > 16 || DESCS_NUMBER_BITS > 15
# error Bad configuration
#endif

#define DESC_INDEX_SHIFT BLOCKS_NUMBER_BITS
#define DESC_PSHARED_FLAG ((1 << BLOCKS_NUMBER_BITS) << DESCS_NUMBER_BITS)

#define BLOCK_INDEX_MASK ((1 << BLOCKS_NUMBER_BITS) - 1)
#define DESC_INDEX_MASK (((1 << DESCS_NUMBER_BITS) - 1) << BLOCKS_NUMBER_BITS)

#define GET_PRIVATE(desc) (!(desc & DESC_PSHARED_FLAG))
#define GET_BLOCK_INDEX(desc) (desc & BLOCK_INDEX_MASK)
#define GET_DESC_INDEX(desc) ((desc & DESC_INDEX_MASK) >> DESC_INDEX_SHIFT)
#define SET_DESC(private, block_index, desc_index) \
	((private ? 0 : DESC_PSHARED_FLAG) \
	| (desc_index << DESC_INDEX_SHIFT) | block_index)

/* Zero descriptor index is not allowed (it is used
 * for static initialization, and first descriptor
 * is used as descriptors' list head). */
#define GOOD_DESC(desc) (desc >= (1 << DESC_INDEX_SHIFT))

/**
 * struct common_desc - kind of a 'parent class' of all descriptor types
 * 	(struct mutex_desc, struct cond_desc, etc), contains all shared
 * 	fields.
 * @lock: the internal lock.
 * @next_free: if this descriptor is free, then next_free points to the next
 * 	free descriptor, thus forming a single-linked list of free descriptors.
 * 	Otherwise stores '-1'.
 * @private: is the corresponding object private?
 * @desc_type: descriptor's type (see 'enum types').
 * @wait_list: list of all tasks waiting for this object.
 *
 * This structure is used by (de)allocation routines which are the same
 * for all descriptor types.
 */
struct common_desc {
	struct raw_spinlock lock;
	s16 next_free;
	char private;
	char desc_type;
	struct plist_head wait_list;
};


/**
 * struct zero_cell - first cell in a block of descriptors stores
 * 	head of the free descriptors' list.
 * @free_desc: index of the first free descriptor in the block.
 * @used_descs: how many descriptors in the block have been initialized
 * at least once.
 */
struct zero_cell {
	s16 free_desc;
	s16 used_descs;
};

struct common_cell_private {
	struct common_desc desc;
};

struct mutex_cell_private {
	union {
		struct common_desc common_desc;
		struct mutex_desc m_desc;
	} desc;
	void *mutex;
} __attribute__((__aligned__(DESC_ALIGN)));

struct other_cell_private {
	union desc {
		struct common_desc common_desc;
		struct cond_desc c_desc;
		struct barr_desc b_desc;
		struct sem_desc s_desc;
	} desc;
	void *object;
} __attribute__((__aligned__(DESC_ALIGN)));

struct mutex_block_private {
	struct mutex_cell_private descs[DESCS_NUMBER];
};

struct other_block_private {
	struct other_cell_private descs[DESCS_NUMBER];
};

struct allocated_descs_common {
	int free_block;
	int used_blocks;
	/* .blocks is an array of BLOCKS_NUMBER pointers to arrays
	 * consisting of DESCS_NUMBER cells. */
	void *blocks[BLOCKS_NUMBER];
	u16 next_free[BLOCKS_NUMBER];
};

/* There is one instance of this structure per process. */
struct allocated_private_mutex_descs {
	int free_block;
	int used_blocks;
	/* .blocks is an array of BLOCKS_NUMBER pointers to arrays
	 * consisting of DESCS_NUMBER 'mutex_cell_private' structures. */
	struct mutex_block_private *blocks[BLOCKS_NUMBER];
	u16 next_free[BLOCKS_NUMBER];
	struct mutex_block_private first_block;
};

/* There is one instance of this structure per process. */
struct allocated_private_other_descs {
	int free_block;
	int used_blocks;
	/* .blocks is an array of BLOCKS_NUMBER pointers to arrays
	 * consisting of DESCS_NUMBER 'other_cell_private' structures. */
	struct other_block_private *blocks[BLOCKS_NUMBER];
	u16 next_free[BLOCKS_NUMBER];
	struct other_block_private first_block;
};


/*
 * Structures used to store descriptors for shared objects
 */

/* This union is the same as 'union futex_key' used in futex code. */
union key_shared {
	struct {
		unsigned long pgoff;
		struct inode *inode;
		int offset;
	} shared;
	struct {
		unsigned long address;
		struct mm_struct *mm;
		int offset;
	} private;
	struct {
		unsigned long word;
		void *ptr;
		int offset;
	} both;
};

static __always_inline int key_cmp(union key_shared *k1, union key_shared *k2)
{
	return unlikely(k1->both.word != k2->both.word
			|| k1->both.ptr != k2->both.ptr
			|| k1->both.offset != k2->both.offset);
}

struct common_cell_shared {
	struct list_head shared_descs_list_entry;
	struct common_desc desc;
};

struct mutex_cell_shared {
	struct list_head shared_descs_list_entry;
	struct mutex_desc desc;
	union key_shared key;
	int __desc;
	struct user_struct *user;
} __attribute__((__aligned__(DESC_ALIGN)));

struct other_cell_shared {
	struct list_head shared_descs_list_entry;
	union {
		struct cond_desc c_desc;
		struct barr_desc b_desc;
		struct sem_desc s_desc;
	} desc;
	union key_shared key;
	int __desc;
	struct user_struct *user;
} __attribute__((__aligned__(DESC_ALIGN)));

struct mutex_block_shared {
	struct mutex_cell_shared descs[DESCS_NUMBER];
};

struct other_block_shared {
	struct other_cell_shared descs[DESCS_NUMBER];
};

struct allocated_shared_mutex_descs {
	int free_block;
	int used_blocks;
	/* .blocks is an array of BLOCKS_NUMBER pointers to arrays
	 * consisting of DESCS_NUMBER 'mutex_cell_shared' structures. */
	struct mutex_block_shared *blocks[BLOCKS_NUMBER];
	u16 next_free[BLOCKS_NUMBER];
	struct mutex_block_shared first_block;
};

struct allocated_shared_other_descs {
	int free_block;
	int used_blocks;
	/* .blocks is an array of BLOCKS_NUMBER pointers to arrays
	 * consisting of DESCS_NUMBER 'other_cell_shared' structures. */
	struct other_block_shared *blocks[BLOCKS_NUMBER];
	u16 next_free[BLOCKS_NUMBER];
	struct other_block_shared first_block;
};


/*
 * Statically allocate shared objects.
 */
static struct {
	struct rw_semaphore lock;
	struct allocated_shared_mutex_descs *mutexes;
	struct allocated_shared_other_descs *others;
} shared;

static struct allocated_shared_mutex_descs shared_mutexes_struct = {
	.free_block = 1,
	.used_blocks = 1,
	.blocks = {
		[1] = &shared_mutexes_struct.first_block
	}
};

static struct allocated_shared_other_descs shared_others_struct = {
	.free_block = 1,
	.used_blocks = 1,
	.blocks = {
		[1] = &shared_others_struct.first_block
	}
};


static inline void *cell_to_desc(void *cell, int private)
{
	if (private)
		return &((struct common_cell_private *) cell)->desc;
	else
		return &((struct common_cell_shared *) cell)->desc;
}

static void block_init(s8 *block, int sz, int private)
{
	int i;

	/* Block must be cleared already */
	for (i = 1; i < DESCS_NUMBER; i++) {
		struct common_desc *common_desc =
				cell_to_desc(block + i * sz, private);

		/* This place may confuse lockdep since all locks
		 * will look as they are of the same type to it. */
		raw_spin_lock_init(&common_desc->lock);
		plist_head_init(&common_desc->wait_list);
	}
}

static __always_inline union key_shared *desc_to_key(void *desc,
		const enum types type)
{
	switch (type) {
	case MUTEX:
		return &container_of(desc, struct mutex_cell_shared, desc)->key;
	case CONDITION:
	case BARRIER:
	case SEMAPHORE:
		return &container_of(desc, struct other_cell_shared, desc)->key;
	default:
		return NULL;
	}
}

static __always_inline struct user_struct **desc_to_user(void *desc,
		const enum types type)
{
	switch (type) {
	case MUTEX:
		return &container_of(desc, struct mutex_cell_shared,
				desc)->user;
	case CONDITION:
	case BARRIER:
	case SEMAPHORE:
		return &container_of(desc, struct other_cell_shared,
				desc)->user;
	default:
		return NULL;
	}
}

static __always_inline int **desc_to_object(void *desc, const enum types type)
{
	switch (type) {
	case MUTEX:
		return (int **) &container_of(desc, struct mutex_cell_private,
				desc)->mutex;
	case CONDITION:
	case BARRIER:
	case SEMAPHORE:
		return (int **) &container_of(desc, struct other_cell_private,
				desc)->object;
	default:
		return NULL;
	}
}

static __always_inline void *desc_get_object(void *desc, const enum types type)
{
	int **object_ptr = desc_to_object(desc, type);

	return (void *) *object_ptr;
}

static __always_inline int get_sz(const int private, const enum types type)
{
	int sz;

	switch (type) {
	case MUTEX:
		sz = private ? sizeof(struct mutex_cell_private)
				: sizeof(struct mutex_cell_shared);
		break;
	case CONDITION:
	case BARRIER:
	case SEMAPHORE:
	case OTHER:
		sz = private ? sizeof(struct other_cell_private)
				: sizeof(struct other_cell_shared);
		break;
	default:
		sz = 0;
		break;
	}

	return sz;
}

static __always_inline struct allocated_descs_common *get_all_blocks(
		struct task_struct *const task,
		const int private, const enum types type)
{
	struct allocated_descs_common *all_blocks;

	switch (type) {
	case MUTEX:
		if (private)
			all_blocks = (struct allocated_descs_common *)
					task->mm->el_posix.mutexes;
		else
			all_blocks = (struct allocated_descs_common *)
					shared.mutexes;
		break;
	case CONDITION:
	case BARRIER:
	case SEMAPHORE:
		if (private)
			all_blocks = (struct allocated_descs_common *)
					task->mm->el_posix.others;
		else
			all_blocks = (struct allocated_descs_common *)
					shared.others;
		break;
	default:
		all_blocks = NULL;
		break;
	}

	return all_blocks;
}

/* For shared objects key is (page->index,
 * vma->vm_file->f_path.dentry->d_inode, offset_within_page).
 * The key words are stored in *key on success.
 * Returns 0 on success. */
static int get_shared_key(unsigned long uaddr, union key_shared *key,
		const int get_reference)
{
	struct page *page;
	int err;

	key->both.offset = uaddr % PAGE_SIZE;
	WARN_ON(key->both.offset & 1);

again:
	err = get_user_pages_fast(uaddr - key->both.offset, 1, 1, &page);
	if (err < 0)
		goto out;

	page = compound_head(page);
	lock_page(page);
	if (!page->mapping) {
		unlock_page(page);
		put_page(page);
		goto again;
	}

	if (PageAnon(page)) {
		/* Mapping is actually private. */
		key->private.address = uaddr;
		key->private.mm = current->mm;
		key->private.offset |= 1;
		/* Do not increase mm reference counter: if mm is destroyed
		 * before the descriptor, then descriptor will be moved to
		 * the global freed_shared_descs list. */
	} else {
		key->shared.pgoff = page->index;
		key->shared.inode = page->mapping->host;
		if (unlikely(get_reference))
			atomic_inc(&key->shared.inode->i_count);
	}

	unlock_page(page);
	put_page(page);

	err = 0;
out:

	DbgPos("get_shared_key: err=%d, word=%ld, ptr=%p, offset=%d\n",
			err, key->both.word, key->both.ptr, key->both.offset);

	return err;
}

#ifndef __HAVE_ARCH_CMPXCHG
# error Should have at least emulated cmpxchg to count objects
#endif
static void sub_descriptors_count(const int private, int how_many,
		struct user_struct *const user)
{
	int current_num;
	int *counter;

	if (private)
		counter = &user->el_posix.private_objects;
	else
		counter = &user->el_posix.shared_objects;

again:
	current_num = ACCESS_ONCE(*counter);

	if (how_many > current_num) {
		WARN(1, "%s objects underflow in %d: was %d, trying to subtract %d (user %p)\n",
				private ? "private" : "shared",
				current->pid, current_num, how_many, user);
		return;
	}

	if (unlikely(cmpxchg(counter, current_num, current_num - how_many) !=
			current_num)) {
		cpu_relax();
		goto again;
	}

	DbgPos("sub_descriptors_count: user %lx, private=%d, decreasing by %d, was %d\n",
			user, private, how_many, current_num);
}

static int add_descriptors_count(const int private, int how_many,
		struct user_struct *const user)
{
	int current_num, new_num, descs_limit;
	int *counter;

	if (private) {
		counter = &user->el_posix.private_objects;
		descs_limit = INT_MAX;
	} else {
		counter = &user->el_posix.shared_objects;
		/* 1/2 of all allocated shared descriptors */
		descs_limit = (DESCS_NUMBER - 1) * (BLOCKS_NUMBER - 1) / 2;
	}

again:
	current_num = ACCESS_ONCE(*counter);

	new_num = current_num + how_many;

	if (unlikely(new_num < 0)) {
		WARN_ONCE(1, "%s objects overflow in %d: was %d, trying to add %d (user %p)\n",
				private ? "private" : "shared", current->pid,
				current_num, how_many, user);
		return -EAGAIN;
	}

	if (unlikely(new_num > descs_limit && !capable(CAP_SYS_RESOURCE)))
		return -EAGAIN;

	if (unlikely(cmpxchg(counter, current_num, new_num) != current_num)) {
		cpu_relax();
		goto again;
	}

	DbgPos("add_descriptors_count: user %lx, private=%d, increasing by %d, was %d\n",
			user, private, how_many, current_num);

	return 0;
}

void el_posix_switch_user(struct user_struct *old_user,
		struct user_struct *new_user)
{
	struct mm_struct *mm = current->mm;
	int descs_number;

	if (!mm)
		return;

	down_write(&mm->el_posix.lock);

	if (!mm->el_posix.user || mm->el_posix.user != old_user)
		goto out_unlock;

	descs_number = 0;
	if (mm->el_posix.mutexes)
		descs_number += mm->el_posix.mutexes->used_blocks
				* DESCS_NUMBER;
	if (mm->el_posix.others)
		descs_number += mm->el_posix.others->used_blocks * DESCS_NUMBER;

	if (descs_number) {
		DbgPos("el_posix_switch_user: moving %d private objects from user %lx to user %lx\n",
				descs_number, old_user, new_user);
		if (add_descriptors_count(1, descs_number, new_user))
			goto out_unlock;

		sub_descriptors_count(1, descs_number, old_user);

		mm->el_posix.user = new_user;

		free_uid(old_user);

		get_uid(new_user);
	}

out_unlock:
	up_write(&mm->el_posix.lock);
}


static DEFINE_RAW_SPINLOCK(freed_shared_descs_lock);
static LIST_HEAD(freed_shared_descs);

/* Called from destroy_inode(). */
void el_posix_inode_free(struct inode *inode)
{
	unsigned long flags;

	if (list_empty(&inode->el_posix_objects))
		return;

	raw_spin_lock_irqsave(&freed_shared_descs_lock, flags);
	list_splice_init(&inode->el_posix_objects, &freed_shared_descs);
	raw_spin_unlock_irqrestore(&freed_shared_descs_lock, flags);
}

static int desc_free(int, const enum types, void *, const int);

/* Must be called with shared.lock held to avoid race conditions
 * with other tasks that are calling desc_free/desc_alloc. */
static void free_unused_shared_descs(void)
{
	while (!list_empty(&freed_shared_descs)) {
		struct list_head *list_entry;
		struct common_cell_shared *cell;
		int __desc;

		raw_spin_lock_irq(&freed_shared_descs_lock);
		if (!list_empty(&freed_shared_descs)) {
			list_entry = freed_shared_descs.next;
			list_del_init(list_entry);
		} else {
			list_entry = NULL;
		}
		raw_spin_unlock_irq(&freed_shared_descs_lock);
		if (!list_entry)
			return;

		cell = container_of(list_entry, struct common_cell_shared,
				shared_descs_list_entry);
		switch (cell->desc.desc_type) {
		case MUTEX:
			__desc = ((struct mutex_cell_shared *) cell)->__desc;
			break;
		case CONDITION:
		case BARRIER:
		case SEMAPHORE:
			__desc = ((struct other_cell_shared *) cell)->__desc;
			break;
		default:
			WARN_ON(1);
			continue;
		}

		DbgPos("free_unused_shared_descs: found unused descriptor at "
				"%p.\n", &cell->desc);
		desc_free(__desc, cell->desc.desc_type, NULL, 0);
	}
}

static void add_desc_to_inode(void *desc, struct inode *inode,
		const enum types type)
{
	struct common_cell_shared *cell;

	cell = container_of(desc, struct common_cell_shared, desc);

	raw_spin_lock_irq(&freed_shared_descs_lock);
	list_add(&cell->shared_descs_list_entry, &inode->el_posix_objects);
	raw_spin_unlock_irq(&freed_shared_descs_lock);
}

static void add_desc_to_mm(void *desc, struct mm_struct *mm,
		const enum types type)
{
	struct common_cell_shared *cell;

	cell = container_of(desc, struct common_cell_shared, desc);

	raw_spin_lock_irq(&freed_shared_descs_lock);
	list_add(&cell->shared_descs_list_entry, &mm->el_posix.shared_objects);
	raw_spin_unlock_irq(&freed_shared_descs_lock);
}

static void remove_desc_from_inode_or_mm(void *desc, const enum types type)
{
	struct common_cell_shared *cell;

	cell = container_of(desc, struct common_cell_shared, desc);

	raw_spin_lock_irq(&freed_shared_descs_lock);
	list_del_init(&cell->shared_descs_list_entry);
	raw_spin_unlock_irq(&freed_shared_descs_lock);
}


struct mutex_init_args {
	char protocol;
	char type;
	char robust;
	unsigned char prioceiling;
};

/**
 * desc_init() - initializes the newly allocated descriptor.
 * @desc: the pointer to the descriptor in question.
 * @private: is the descriptor private?
 * @type: the type of the descriptor (mutex, barrier, etc).
 * @init_args: the pointer to additional initialization arguments
 * 	which are dependent on descriptor's type.
 *
 * We assume that the spinlock and the waitqueue of the descriptor
 * have already been initialized.
 */
static void desc_init(void *desc, const int private,
		const enum types type, void *init_args)
{
	struct mutex_desc *m_desc;
	struct cond_desc *c_desc;
	struct barr_desc *b_desc;
	struct sem_desc *s_desc;
	struct mutex_init_args *m_args;

	switch (type) {
	case MUTEX:
		m_desc = (struct mutex_desc *) desc;
		m_args = (struct mutex_init_args *) init_args;
		m_desc->private = private;
		m_desc->pending_owner = NULL;
		m_desc->owner = NULL;
		m_desc->protocol = m_args->protocol;
		m_desc->type = m_args->type;
		m_desc->robust = m_args->robust;
		m_desc->prioceiling = m_args->prioceiling;
		if (m_desc->type == PTHREAD_PRIO_INHERIT)
			INIT_LIST_HEAD(&m_desc->mutex_list_entry.pi);
		m_desc->desc_type = MUTEX;
		break;
	case CONDITION:
		c_desc = (struct cond_desc *) desc;
		c_desc->m_desc = NULL;
		c_desc->private = private;
		c_desc->desc_type = CONDITION;
		break;
	case BARRIER:
		b_desc = (struct barr_desc *) desc;
		b_desc->present = 0;
		b_desc->private = private;
		b_desc->desc_type = BARRIER;
		break;
	case SEMAPHORE:
		s_desc = (struct sem_desc *) desc;
#if defined ARCH_HAS_ATOMIC_CMPXCHG
		s_desc->waiters_nr = 0;
#else
		s_desc->value = *((int *) init_args);
#endif
		s_desc->private = private;
		s_desc->desc_type = SEMAPHORE;
		break;
	case OTHER:
		break;
	}
}

/**
 * creation_lock() - lock a global lock protecting all descriptor allocations.
 * @private: type of a descriptor being (de)allocated.
 */
static void creation_lock(int private)
{
	if (private)
		down_write(&current->mm->el_posix.lock);
	else
		down_write(&shared.lock);
}

/**
 * creation_unlock() - unlock a global lock protecting all descriptor
 * 	allocations.
 * @private: type of a descriptor being (de)allocated.
 */
static void creation_unlock(int private)
{
	if (private)
		up_write(&current->mm->el_posix.lock);
	else
		up_write(&shared.lock);
}


/**
 * desc_alloc() - creates a new descriptor, allocates memory for it
 * 	if necessary and initializes it.
 * @private: is the new descriptor private?
 * @desc: points to pointer to the descriptor.
 * @__desc: points to index of the new descriptor.
 * @type: type of the descriptor to be allocated.
 * @addr: address of the corresponding object in userspace.
 * @init_args: the pointer to additional initialization arguments
 * 	which are dependent on descriptor's type.
 *
 * If desc_alloc() return 0, then the pointer to the new descriptor and its
 * index are saved to *desc and *__desc.
 */
static int desc_alloc(const int private, void *desc, int *__desc,
		const enum types type, unsigned long addr, void *init_args)
{
	struct allocated_descs_common *all_blocks;
	s8 *block;
	struct user_struct *user = NULL;
	struct zero_cell *zero_cell;
	int block_index, desc_index, sz, rval;
	union key_shared key;
	struct common_desc *common_desc;

	sz = get_sz(private, type);
	all_blocks = get_all_blocks(current, private, type);

	DbgPos("desc_alloc: start, type=%d, all_blocks=%p, sz=%d\n",
			type, all_blocks, sz);

	if (unlikely(!all_blocks)) {
		if (private) {
			struct allocated_private_mutex_descs *mutexes;
			struct allocated_private_other_descs *others;

			/* First thing check permissions. */
			if (!current->mm->el_posix.user)
				current->mm->el_posix.user = get_current_user();
			rval = add_descriptors_count(1, DESCS_NUMBER,
					current->mm->el_posix.user);
			if (rval)
				return rval;

			switch (type) {
			case MUTEX:
				mutexes = kzalloc(sizeof(*mutexes), GFP_USER);
				if (!mutexes) {
					sub_descriptors_count(1, DESCS_NUMBER,
						current->mm->el_posix.user);
					return -ENOMEM;
				}
				mutexes->free_block = 1;
				mutexes->used_blocks = 1;
				mutexes->blocks[1] = &mutexes->first_block;
				block_init((s8 *) &mutexes->first_block, sz, 1);
				current->mm->el_posix.mutexes = mutexes;
				break;
			case CONDITION:
			case BARRIER:
			case SEMAPHORE:
				others = kzalloc(sizeof(*others), GFP_USER);
				if (!others) {
					sub_descriptors_count(1, DESCS_NUMBER,
						current->mm->el_posix.user);
					return -ENOMEM;
				}
				others->free_block = 1;
				others->used_blocks = 1;
				others->blocks[1] = &others->first_block;
				block_init((s8 *) &others->first_block, sz, 1);
				current->mm->el_posix.others = others;
				break;
			case OTHER:
				break;
			}
		} else {
			switch (type) {
			case MUTEX:
				block_init((s8 *)
					&shared_mutexes_struct.first_block,
					sz, 0);
				/* A pair to smp_read_barrier_depends()
				 * in get_desc(). */
				smp_wmb();
				shared.mutexes = &shared_mutexes_struct;
				break;
			case CONDITION:
			case BARRIER:
			case SEMAPHORE:
				block_init((s8 *)
					&shared_others_struct.first_block,
					sz, 0);
				/* A pair to smp_read_barrier_depends()
				 * in get_desc(). */
				smp_wmb();
				shared.others = &shared_others_struct;
				break;
			case OTHER:
				break;
			}
		}

		all_blocks = get_all_blocks(current, private, type);
	}

	/* Check if some descriptors are unused but was not freed by user. */
	if (!private)
		free_unused_shared_descs();

	/* Test permissions. */
	if (!private) {
		rval = get_shared_key(addr, &key, 1);
		if (unlikely(rval))
			return rval;

		if (!(key.both.offset & 1)) {
			user = alloc_uid(key.shared.inode->i_uid);
			if (unlikely(!user)) {
				DbgPos("desc_alloc: alloc_uid failed\n");
				iput(key.shared.inode);
				return -ENOMEM;
			}
		} else {
			user = current_user();
		}

		rval = add_descriptors_count(0, 1, user);
		if (unlikely(rval))
			goto out_put_key;
	} else {
		if (!current->mm->el_posix.user)
			current->mm->el_posix.user = get_current_user();
		user = current->mm->el_posix.user;
	}

	/* Find block with unused descriptor */
	if (unlikely(!all_blocks->free_block)) {
		if (all_blocks->used_blocks < (BLOCKS_NUMBER - 1)) {
			if (private) {
				rval = add_descriptors_count(1, DESCS_NUMBER,
						user);
				if (unlikely(rval))
					return rval;
			}
			block = kzalloc(sz * DESCS_NUMBER, GFP_USER);
			if (!block) {
				if (private) {
					sub_descriptors_count(1, DESCS_NUMBER,
							user);
					return -ENOMEM;
				} else {
					rval = -ENOMEM;
					goto out_sub_count;
				}
			}
			block_init(block, sz, private);
			/* A pair to smp_read_barrier_depends()
			 * in get_desc(). */
			smp_wmb();
			block_index = ++all_blocks->used_blocks;
			all_blocks->blocks[block_index] = block;
			all_blocks->free_block = block_index;
		} else {
			static int printed;
			if (!printed) {
				printk(KERN_WARNING "%d el_posix object "
					"initialization: all available %s "
					"descriptors used!\n", current->pid,
					private ? "private" : "shared");
				printed = 1;
			}

			DbgPos("el_posix object initialization: all "
					"available descriptors used!\n");
			rval = -EAGAIN;
			goto out_sub_count;
		}
	} else {
		block_index = all_blocks->free_block;
	}

	block = (s8 *) all_blocks->blocks[block_index];

	zero_cell = (struct zero_cell *) block;

	/* Find an unused descriptor within the block */
	if (!zero_cell->free_desc) {
		if (zero_cell->used_descs < (DESCS_NUMBER - 1)) {
			desc_index = ++zero_cell->used_descs;
		} else {
			WARN_ON(1);
			rval = -EINVAL;
			goto out_sub_count;
		}
	} else {
		desc_index = (int) zero_cell->free_desc;
		/* Read 'next_free' field of the [zero_cell->free_desc] cell. */
		zero_cell->free_desc = ((struct common_desc *)
			cell_to_desc(block + ((int) zero_cell->free_desc) * sz,
			private))->next_free;
	}

	/* Point of no return */

	/* Check whether the block is full now */
	if (!zero_cell->free_desc && unlikely(
			zero_cell->used_descs == (DESCS_NUMBER - 1)))
		all_blocks->free_block = all_blocks->next_free[block_index];

	/* Found descriptor to use */
	common_desc = cell_to_desc(block + desc_index * sz, private);
	*(struct common_desc **) desc = common_desc;
	*__desc = SET_DESC(private, block_index, desc_index);

	if (private) {
		int **object = desc_to_object(common_desc, type);

		*object = (int *) addr;
	} else {
		union key_shared *desc_key = desc_to_key(common_desc, type);
		struct user_struct **desc_user = desc_to_user(common_desc,
				type);

		*desc_key = key;
		*desc_user = user;
		DbgPos("desc_alloc: key stored at %p: offset=%d, ptr=%p, "
				"word=%ld\n", desc_key, key.both.offset,
				key.both.ptr, key.both.word);

		if (!(key.both.offset & 1)) {
			/* inode based mapping. Enable automatic freeing
			 * of this descriptor. */
			switch (type) {
			case MUTEX:
				((struct mutex_cell_shared *) (block +
					desc_index * sz))->__desc = *__desc;
				break;
			case CONDITION:
			case BARRIER:
			case SEMAPHORE:
				((struct other_cell_shared *) (block +
					desc_index * sz))->__desc = *__desc;
				break;
			case OTHER:
				break;
			}
			add_desc_to_inode(common_desc, key.shared.inode,
					type);
			iput(key.shared.inode);
		} else {
			add_desc_to_mm(common_desc, key.private.mm, type);
		}
	}

	raw_spin_lock_irq(&common_desc->lock);
	desc_init(common_desc, private, type, init_args);
	/* Now that the descriptor is allocated and initialized we set
	 * the 'next_free' field to -1, indicating that it is in use
	 * (we will use this for runtime checks, see desc_in_use()). */
	common_desc->next_free = -1;
	raw_spin_unlock_irq(&common_desc->lock);

	DbgPos("desc_alloc: success __desc=%d, block=%d, desc=%d, private=%d\n",
			*__desc, block_index, desc_index, private);
	return 0;

out_sub_count:
	if (!private)
		sub_descriptors_count(0, 1, user);
out_put_key:
	if (!private) {
		if (unlikely(!key.both.ptr))
			WARN_ON_ONCE(1);

		if (!(key.both.offset & 1)) {
			/* inode based mapping. */
			iput(key.shared.inode);
			free_uid(user);
		}
	}

	return rval;
}

/**
 * desc_in_use() - returns 1 if the descriptor is used and 0 otherwise.
 * @desc: the descriptor in question.
 */
static __always_inline int desc_in_use(void *desc)
{
	int rval = likely(((struct common_desc *) desc)->next_free == -1);

#if DEBUG_POSIX
	if (!rval)
		DbgPos("desc_in_use: bad descriptor at %p!!!\n", desc);
#endif

	return rval;
}

/**
 * desc_private() - returns 1 if the descriptor is private and 0 otherwise.
 * @desc: the descriptor in question.
 */
static __always_inline int desc_private(void *desc)
{
	return likely(((struct common_desc *) desc)->private);
}

/**
 * desc_check_type() - returns 0 if the descriptor type matches
 * 	and 1 otherwisee.
 * @desc: the descriptor in question.
 * @type: expected type to check against.
 */
static __always_inline int desc_check_type(void *desc, enum types type)
{
	int rval;

	switch (type) {
	case MUTEX:
		rval = 0;
		break;
	case CONDITION:
	case BARRIER:
	case SEMAPHORE:
		rval = unlikely(((char) type) !=
				((struct common_desc *) desc)->desc_type);
		break;
	default:
		rval = 1;
		break;
	}

#if DEBUG_POSIX
	if (rval)
		DbgPos("desc_check_type: bad descriptor at %p (%d != %d)!!!\n",
				desc, type,
				(int) ((struct common_desc *) desc)->desc_type);
#endif

	return rval;
}

/**
 * desc_check_type() - returns 0 if the descriptor is good and 1 otherwise.
 * @desc: the descriptor in question.
 * @type: expected type to check against.
 * @object: address of the corresponding userspace object (for private
 * 	descriptors only).
 */
static __always_inline int check_desc(void *desc, enum types type, void *object)
{
	return unlikely(desc_in_use(desc) == 0
			|| (desc_get_object(desc, type) != object &&
					desc_private(desc))
			|| desc_check_type(desc, type));
}

/**
 * desc_is_busy() - returns 1 if the descriptor's userspace object is in use
 * 	and 0 otherwise.
 * @desc: the descriptor in question.
 * @type: the descriptor's type.
 * @free_arg: meaning depends on type, used to perform additional checks.
 */
static int desc_is_busy(void *desc, const enum types type, const int free_arg)
{
	struct mutex_desc *m_desc;
	struct barr_desc *b_desc;

	switch (type) {
	case MUTEX:
		m_desc = (struct mutex_desc *) desc;
		if (unlikely((free_arg && m_desc->robust <= OWNER_DEAD)
				|| m_desc->owner || m_desc->pending_owner)) {
			DbgPos("mutex_destroy: locked mutex, lock=%d\n",
					free_arg);
			return 1;
		}
		break;
	case BARRIER:
		b_desc = (struct barr_desc *) desc;
		if (unlikely(b_desc->present))
			return 1;
		break;
	default:
		break;
	}

	return 0;
}

/**
 * desc_free() - frees the descriptor.
 * @__desc: index of the descriptor in question.
 * @type: the descriptor's type.
 * @object: address of the corresponding userspace object (for private
 * 	descriptors only).
 * @free_arg: meaning depends on type, used to perform additional checks.
 */
static int desc_free(int __desc, const enum types type, void *object,
		const int free_arg)
{
	struct allocated_descs_common *all_blocks;
	s8 *block;
	struct common_desc *desc;
	struct zero_cell *zero_cell;
	int private, block_index, desc_index, sz;

	private = GET_PRIVATE(__desc);
	block_index = GET_BLOCK_INDEX(__desc);
	desc_index = GET_DESC_INDEX(__desc);

	sz = get_sz(private, type);
	all_blocks = get_all_blocks(current, private, type);

	if (unlikely(!all_blocks || block_index > all_blocks->used_blocks))
		return -EINVAL;

	block = all_blocks->blocks[block_index];
	if (!block)
		return -EINVAL;

	zero_cell = (struct zero_cell *) block;
	if (desc_index > zero_cell->used_descs)
		return -EINVAL;

	desc = cell_to_desc(block + desc_index * sz, private);

	/* Before we actually do anything, we must make sure that
	 * no one is waiting on this descriptor. Return -EBUSY
	 * if there is someone. */
	raw_spin_lock_irq(&desc->lock);
	if (check_desc(desc, type, object)) {
		raw_spin_unlock_irq(&desc->lock);
		return -EINVAL;
	}

	if (desc_is_busy(desc, type, free_arg)) {
		raw_spin_unlock_irq(&desc->lock);
		return -EBUSY;
	}

	/* There is no need to check here whether mutex_list_entry is empty,
	 * because if it was not then desc_is_busy() would return true
	 * after checking 'owner' field. */
	if (plist_head_empty(&desc->wait_list))
		desc->next_free = 0;
	raw_spin_unlock_irq(&desc->lock);
	if (desc->next_free != 0)
		return -EBUSY;

	/* All checks passed, proceed to actual freeing. */

	/* Permissions and accounting stuff */
	if (!private) {
		union key_shared *desc_key = desc_to_key(desc, type);
		struct user_struct **desc_user = desc_to_user(desc, type);

		/* This must be done before calling free_uid(). */
		sub_descriptors_count(0, 1, *desc_user);

		/* Clear the key of the freed descriptor. */
		if (unlikely(!desc_key->both.ptr)) {
			WARN_ON_ONCE(1);
		} else {
			/* Disable automatic freeing of this descriptor. */
			remove_desc_from_inode_or_mm(desc, type);

			if (!(desc_key->both.offset & 1))
				/* inode based mapping. */
				free_uid(*desc_user);
			desc_key->both.ptr = NULL;
		}
		desc_key->both.word = 0;
		desc_key->both.offset = 0;
	} else {
		int **object = desc_to_object(desc, type);

		*object = NULL;
	}

	desc->desc_type = 0;

	if (unlikely(!zero_cell->free_desc
			&& zero_cell->used_descs == (DESCS_NUMBER - 1))) {
		/* This block was full, but now it has an unused descriptor */
		all_blocks->next_free[block_index] = all_blocks->free_block;
		all_blocks->free_block = block_index;
	}

	/* Set 'next_free' field of the [desc_index] cell. */
	desc->next_free = zero_cell->free_desc;
	zero_cell->free_desc = (s16) desc_index;

	DbgPos("desc_free: success_desc=%d, block=%d, desc=%d, private=%d\n",
			__desc, block_index, desc_index, private);
	return 0;
}

/**
 * get_desc() - returns the descriptor's address.
 * @task: the pointer to current task_struct.
 * @__desc: index of the descriptor in question.
 * @type: the descriptor's type.
 * @addr: address of the corresponding userspace object.
 * @force_check: if set to 0 then the validity of the shared
 * 	objects' descriptors will be checked if and only if
 * 	task->mm->el_posix.unsafe_shared_objects variable is set.
 *
 * Descriptor's index __desc must be checked with GOOD_DESC() macro
 * before calling this function.
 */
static __always_inline void *get_desc(struct task_struct *const task,
		const int __desc, const enum types type, void *addr,
		const int force_check)
{
	struct allocated_descs_common *all_blocks;
	s8 *block, *desc;
	int block_index, desc_index, sz;
	const int private = GET_PRIVATE(__desc);

	all_blocks = get_all_blocks(task, private, type);
	block_index = GET_BLOCK_INDEX(__desc);
	if (unlikely(!all_blocks)) {
		DbgPos("get_desc: all_blocks is zero!\n");
		return ERR_PTR(-EINVAL);
	}
	block = all_blocks->blocks[block_index];
	desc_index = GET_DESC_INDEX(__desc);
	sz = get_sz(private, type);
	if (unlikely(!block)) {
		DbgPos("get_desc: the block is zero!\n");
		return ERR_PTR(-EINVAL);
	}
	smp_read_barrier_depends();
	desc = cell_to_desc(block + sz * desc_index, private);
	/* Check descriptor's type. */
	if (desc_check_type(desc, type))
		return ERR_PTR(-EINVAL);
	if (unlikely(!private && (force_check
			|| !task->mm->el_posix.unsafe_shared_objects))) {
		int rval;
		union key_shared user_key;
		union key_shared *desc_key;

		rval = get_shared_key((unsigned long) addr, &user_key, 0);
		if (unlikely(rval))
			return ERR_PTR(rval);
		desc_key = desc_to_key(desc, type);
		if (key_cmp(desc_key, &user_key)) {
			DbgPos("bad key at %p: %ld, %ld, %p, %p, %d, %d\n",
				desc_key, desc_key->both.word,
				user_key.both.word, desc_key->both.ptr,
				user_key.both.ptr, desc_key->both.offset,
				user_key.both.offset);
			return ERR_PTR(-EINVAL);
		}
	}
	return (void *) desc;
}


/* Initialize @mutex. */
static int do_mutex_init(struct pthread_mutex_s *mutex, const int __m_kind)
{
	int rval = 0, __m_desc, private;
	struct mutex_desc *m_desc;
	struct mutex_init_args m_args;
	char protocol, m_kind;

	private = !(__m_kind & PTHREAD_MUTEXATTR_FLAG_PSHARED);

	creation_lock(private);
	if (__get_user(__m_desc, &mutex->__m_desc)) {
		rval = -EFAULT;
		goto out_unlock;
	}

	if (unlikely(GOOD_DESC(__m_desc))) {
		/* Attempted to initialize an initialized mutex. */
		rval = -EBUSY;
		goto out_unlock;
	}

	protocol = (char) ((__m_kind & PTHREAD_MUTEXATTR_PROTOCOL_MASK)
				>> PTHREAD_MUTEXATTR_PROTOCOL_SHIFT);
	m_kind = (char) (__m_kind & ~PTHREAD_MUTEXATTR_FLAG_BITS);
	if (unlikely((unsigned char) protocol > PTHREAD_PRIO_PROTECT
		      || (unsigned char) m_kind > PTHREAD_MUTEX_ADAPTIVE_NP)) {
		rval = -EINVAL;
		goto out_unlock;
	}
	m_args.protocol = protocol;
	m_args.type = m_kind;

	if (__m_kind & PTHREAD_MUTEXATTR_FLAG_ROBUST) {
		if (unlikely(m_args.protocol == PTHREAD_PRIO_NONE)) {
			rval = -ENOSYS;
			goto out_unlock;
		}
		m_args.robust = ROBUST;
	} else {
		m_args.robust = NOT_ROBUST;
	}

	if (unlikely(protocol == PTHREAD_PRIO_PROTECT)) {
		int prioceiling = (__m_kind
				& PTHREAD_MUTEXATTR_PRIO_CEILING_MASK)
				>> PTHREAD_MUTEXATTR_PRIO_CEILING_SHIFT;

		if (prioceiling < 1 || prioceiling > MAX_USER_RT_PRIO-1) {
			rval = -EINVAL;
			goto out_unlock;
		}

		if (!capable(CAP_SYS_NICE)) {
			unsigned long flags, rlim_rtprio;

			if (!lock_task_sighand(current, &flags)) {
				rval = -EPERM;
				goto out_unlock;
			}
			rlim_rtprio =
				current->signal->rlim[RLIMIT_RTPRIO].rlim_cur;
			unlock_task_sighand(current, &flags);

			if ((current->policy != SCHED_FIFO && !rlim_rtprio)
					|| (prioceiling > current->rt_priority
					&& prioceiling > rlim_rtprio)) {
				rval = -EPERM;
				goto out_unlock;
			}
		}

		if (current->policy == SCHED_IDLE) {
			rval = -EPERM;
			goto out_unlock;
		}

#ifdef CONFIG_RT_GROUP_SCHED
		if (!sched_task_has_rt_runtime(current)) {
			rval = -EPERM;
			goto out_unlock;
		}
#endif

		rval = security_task_setscheduler(current);
		if (rval)
			goto out_unlock;

		m_args.prioceiling = (unsigned char)
				(MAX_RT_PRIO-1 - prioceiling);
	}

	/* Allocate a new descriptor */
	rval = desc_alloc(private, &m_desc, &__m_desc, MUTEX,
			(unsigned long) mutex, &m_args);
	if (unlikely(rval))
		goto out_unlock;

	if (__put_user(__m_desc, &mutex->__m_desc)) {
		desc_free(__m_desc, MUTEX, mutex, 0);
		rval = -EFAULT;
		goto out_unlock;
	}
out_unlock:
	creation_unlock(private);
	DbgPos("pmutex_init: allocated descr %p for mutex %p, rval = %d\n",
			m_desc, mutex, rval);

	return rval;
}

/* Destroy @mutex. */
static int do_mutex_destroy(struct pthread_mutex_s *mutex, const int __m_desc)
{
	int __m_lock, private, rval;
	struct mutex_desc *m_desc;

	if (__get_user(__m_lock, &mutex->__m_lock))
		return -EFAULT;
	if (unlikely(!__m_desc)) {
		/* Looks like statically initialized mutex */
		__put_user(1, &mutex->__m_desc);
		return 0;
	}

	if (unlikely(!GOOD_DESC(__m_desc)))
		return -EINVAL;

	m_desc = get_desc(current, __m_desc, MUTEX, mutex, 1);
	if (unlikely(IS_ERR(m_desc)))
		return PTR_ERR(m_desc);

	/* Deallocate the descriptor */
	private = GET_PRIVATE(__m_desc);
	creation_lock(private);
	rval = desc_free(__m_desc, MUTEX, mutex, __m_lock);
	creation_unlock(private);
	if (!rval)
		__put_user(1, &mutex->__m_desc);
	return rval;
}

/* mutex_once() function is needed to dynamically allocate a descriptor
 * if a mutex was initialized via static initializer. */
static struct mutex_desc *mutex_once(struct task_struct *const task,
		struct pthread_mutex_s *const mutex, int __m_desc, int __m_kind)
{
	if (unlikely(!GOOD_DESC(__m_desc))) {
		int rval;

		if (unlikely(__m_desc)) {
			DbgPos("mutex_once: bad desc %x, rval = %d\n",
					__m_desc, -EINVAL);
			return ERR_PTR(-EINVAL);
		}
		/* Statically initialized mutex. do_mutex_init() will
		 * return -EBUSY when several threads simultaneously
		 * initialize the mutex. */
		rval = do_mutex_init(mutex, __m_kind);
		if (rval && rval != -EBUSY)
			return ERR_PTR(rval);
		if (unlikely(__get_user(__m_desc, &mutex->__m_desc)))
			return ERR_PTR(-EFAULT);
	}

	return (struct mutex_desc *) get_desc(task, __m_desc, MUTEX, mutex, 0);
}

/* Initialize @cond. */
static int do_cond_init(struct pthread_cond_s *cond)
{
	int rval = 0, private, __c_desc, __c_value;
	struct cond_desc *c_desc;

	if (__get_user(__c_value, &cond->__c_value))
		return -EFAULT;

	private = !(__c_value & PTHREAD_CONDATTR_FLAG_PSHARED);

	creation_lock(private);
	if (__get_user(__c_desc, &cond->__c_desc)) {
		rval = -EFAULT;
		goto out_unlock;
	}

	if (unlikely(GOOD_DESC(__c_desc))) {
		/* Attempted to initialize an initialized condition. */
		rval = -EBUSY;
		goto out_unlock;
	}

	/* Allocate a new descriptor */
	rval = desc_alloc(private, &c_desc, &__c_desc, CONDITION,
			(unsigned long) cond, NULL);
	if (unlikely(rval))
		goto out_unlock;

	if (__put_user(__c_desc, &cond->__c_desc)) {
		desc_free(__c_desc, CONDITION, cond, 0);
		rval = -EFAULT;
		goto out_unlock;
	}
out_unlock:
	creation_unlock(private);
	DbgPos("pcond_init: allocated descr %p for cond %p, rval = %d\n",
			c_desc, cond, rval);

	return rval;
}

/* Destroy @cond. */
static int do_cond_destroy(struct pthread_cond_s *cond, int __c_desc)
{
	int private, rval;
	struct cond_desc *c_desc;

	if (unlikely(!__c_desc)) {
		/* Looks like statically initialized condition */
		__put_user(1, &cond->__c_desc);
		return 0;
	}

	if (unlikely(!GOOD_DESC(__c_desc)))
		return -EINVAL;

	c_desc = get_desc(current, __c_desc, CONDITION, cond, 1);
	if (unlikely(IS_ERR(c_desc)))
		return PTR_ERR(c_desc);

	/* Deallocate the descriptor */
	private = GET_PRIVATE(__c_desc);
	creation_lock(private);
	rval = desc_free(__c_desc, CONDITION, cond, 0);
	creation_unlock(private);
	if (!rval)
		__put_user(1, &cond->__c_desc);
	return rval;
}

/* cond_once() function is needed to dynamically allocate a descriptor
 * if a condition was initialized via static initializer. */
static struct cond_desc *cond_once(struct task_struct *const task,
		struct pthread_cond_s *const cond, int __c_desc)
{
	if (unlikely(!GOOD_DESC(__c_desc))) {
		int rval;

		if (unlikely(__c_desc)) {
			DbgPos("cond_once: bad desc %x, rval = %d\n",
					__c_desc, -EINVAL);
			return ERR_PTR(-EINVAL);
		}
		/* Statically initialized condition variable.
		 * do_cond_init() will return -EBUSY when several
		 * threads simultaneously initialize the variable. */
		rval = do_cond_init(cond);
		if (rval && rval != -EBUSY)
			return ERR_PTR(rval);
		if (unlikely(__get_user(__c_desc, &cond->__c_desc)))
			return ERR_PTR(-EFAULT);
	}

	return (struct cond_desc *) get_desc(task, __c_desc,
			CONDITION, cond, 0);
}

/* Initialize @barr. */
static int do_barrier_init(struct pthread_barrier_s *__restrict barr,
		const int pshared)
{
	int rval = 0, __b_desc;
	struct barr_desc *b_desc;

	creation_lock(!pshared);
	if (__get_user(__b_desc, &barr->__b_desc)) {
		rval = -EFAULT;
		goto out_unlock;
	}

	if (unlikely(GOOD_DESC(__b_desc))) {
		/* Attempted to initialize an initialized barrier. */
		rval = -EBUSY;
		goto out_unlock;
	}

	/* Allocate a new descriptor */
	rval = desc_alloc(!pshared, &b_desc, &__b_desc, BARRIER,
			(unsigned long) barr, NULL);
	if (unlikely(rval))
		goto out_unlock;

	if (__put_user(__b_desc, &barr->__b_desc)) {
		desc_free(__b_desc, BARRIER, barr, 0);
		rval = -EFAULT;
		goto out_unlock;
	}
out_unlock:
	creation_unlock(!pshared);
	DbgPos("pbarrier_init: allocated descr %p for barrier %p, rval %d\n",
			b_desc, barr, rval);

	return rval;
}

/* Destroy @barr. */
static int do_barrier_destroy(struct pthread_barrier_s *barr, int __b_desc)
{
	int private, rval;
	struct barr_desc *b_desc;

	if (unlikely(!__b_desc)) {
		/* Looks like statically initialized barrier */
		__put_user(1, &barr->__b_desc);
		return 0;
	}

	if (unlikely(!GOOD_DESC(__b_desc)))
		return -EINVAL;

	b_desc = get_desc(current, __b_desc, BARRIER, barr, 1);
	if (unlikely(IS_ERR(b_desc)))
		return PTR_ERR(b_desc);

	/* Deallocate the descriptor */
	private = GET_PRIVATE(__b_desc);
	creation_lock(private);
	rval = desc_free(__b_desc, BARRIER, barr, 0);
	creation_unlock(private);
	if (!rval)
		__put_user(1, &barr->__b_desc);
	return rval;
}

static struct barr_desc *barr_once(struct task_struct *const task,
		struct pthread_barrier_s *barr, int __b_desc)
{
	if (unlikely(!GOOD_DESC(__b_desc))) {
		int rval;

		if (unlikely(__b_desc))
			return ERR_PTR(-EINVAL);
		/* Statically initialized barrier.
		 * do_barrier_init() will return -EBUSY when several
		 * threads simultaneously initialize the barrier. */
		rval = do_barrier_init(barr, 0);
		if (rval && rval != -EBUSY)
			return ERR_PTR(rval);
		if (unlikely(__get_user(__b_desc, &barr->__b_desc)))
			return ERR_PTR(-EFAULT);
	}

	return (struct barr_desc *) get_desc(task, __b_desc, BARRIER, barr, 0);
}

/* Initialize @sem. */
static int do_sem_init(struct posix_sem_s *sem, const int pshared)
{
	int rval = 0, __s_desc;
	struct sem_desc *s_desc;
#if !defined ARCH_HAS_ATOMIC_CMPXCHG
	int value;

	if (unlikely(__get_user(value, &sem->__s_value)))
		return -EFAULT;
#endif

	creation_lock(!pshared);
	if (__get_user(__s_desc, &sem->__s_desc)) {
		rval = -EFAULT;
		goto out_unlock;
	}

	if (unlikely(GOOD_DESC(__s_desc))) {
		/* Attempted to initialize an initialized semaphore. */
		rval = -EBUSY;
		goto out_unlock;
	}

	/* Allocate a new descriptor */
#if !defined ARCH_HAS_ATOMIC_CMPXCHG
	rval = desc_alloc(!pshared, &s_desc, &__s_desc, SEMAPHORE,
			(unsigned long) sem, &value);
#else
	rval = desc_alloc(!pshared, &s_desc, &__s_desc, SEMAPHORE,
			(unsigned long) sem, NULL);
#endif
	if (unlikely(rval))
		goto out_unlock;

	if (__put_user(__s_desc, &sem->__s_desc)) {
		desc_free(__s_desc, SEMAPHORE, sem, 0);
		rval = -EFAULT;
		goto out_unlock;
	}
out_unlock:
	creation_unlock(!pshared);
	DbgPos("sem_init: allocated descr %p for sem %p, rval = %d\n",
			s_desc, sem, rval);

	return rval;
}

/* Destroy @sem. */
static int do_sem_destroy(struct posix_sem_s *sem, int __s_desc)
{
	int private, rval;
	struct sem_desc *s_desc;

	if (unlikely(!__s_desc)) {
		/* Looks like statically initialized semaphore */
		__put_user(1, &sem->__s_desc);
		return 0;
	}

	if (unlikely(!GOOD_DESC(__s_desc)))
		return -EINVAL;

	s_desc = get_desc(current, __s_desc, SEMAPHORE, sem, 1);
	if (unlikely(IS_ERR(s_desc)))
		return PTR_ERR(s_desc);

	/* Deallocate the descriptor */
	private = GET_PRIVATE(__s_desc);
	creation_lock(private);
	rval = desc_free(__s_desc, SEMAPHORE, sem, 0);
	creation_unlock(private);
	if (!rval)
		__put_user(1, &sem->__s_desc);
	return rval;
}

/* sem_once() function is needed to dynamically allocate a descriptor
 * if a semaphore was initialized via static initializer. */
static struct sem_desc *sem_once(struct task_struct *const task,
		struct posix_sem_s *const sem, int __s_desc)
{
	if (unlikely(!GOOD_DESC(__s_desc))) {
		int rval;

		if (unlikely(__s_desc))
			return ERR_PTR(-EINVAL);
		/* Statically initialized semaphore.
		 * do_sem_init() will return -EBUSY when several
		 * threads simultaneously initialize the semaphore. */
		rval = do_sem_init(sem, 0);
		if (rval && rval != -EBUSY)
			return ERR_PTR(rval);
		if (unlikely(__get_user(__s_desc, &sem->__s_desc)))
			return ERR_PTR(-EFAULT);
	}

	return (struct sem_desc *) get_desc(task, __s_desc,
			SEMAPHORE, sem, 0);
}

/**
 * do_object_init_fini() - calls corresponding *_init() or *_destroy() function.
 * @type: type of the object in question.
 * @op: initialize the object if 0 and destroy otherwise.
 * @obj: the pointer to the object
 * @arg: initialization argument which is dependent on the object's type.
 */
static int do_object_init_fini(unsigned long type, void *op, void *obj, int arg)
{
	int rval;

	switch (type) {
	case MUTEX:
		if (BAD_USER_REGION(obj, struct pthread_mutex_s)) {
			rval = -EINVAL;
			break;
		}
		if (!op)
			rval = do_mutex_init((struct pthread_mutex_s *) obj,
					arg);
		else
			rval = do_mutex_destroy((struct pthread_mutex_s *) obj,
					arg);
		break;
	case CONDITION:
		if (BAD_USER_REGION(obj, struct pthread_cond_s)) {
			rval = -EINVAL;
			break;
		}
		if (!op)
			rval = do_cond_init((struct pthread_cond_s *) obj);
		else
			rval = do_cond_destroy((struct pthread_cond_s *) obj,
					arg);
		break;
	case BARRIER:
		if (BAD_USER_REGION(obj, struct pthread_barrier_s)) {
			rval = -EINVAL;
			break;
		}
		if (!op)
			rval = do_barrier_init((struct pthread_barrier_s *) obj,
					arg);
		else
			rval = do_barrier_destroy(
					(struct pthread_barrier_s *) obj, arg);
		break;
	case SEMAPHORE:
		if (BAD_USER_REGION(obj, struct posix_sem_s)) {
			rval = -EINVAL;
			break;
		}
		if (!op)
			rval = do_sem_init((struct posix_sem_s *) obj, arg);
		else
			rval = do_sem_destroy((struct posix_sem_s *) obj, arg);
		break;
	default:
		rval = -EINVAL;
		break;
	}

	return rval;
}


/*
 * Functions used for priority boosting.
 */

/**
 * task_has_pi_waiters() - returns 1 if the task's priority
 * 	was temporarily boosted.
 * @p: the task in question.
 */
static __always_inline int task_has_pi_waiters(struct task_struct *p)
{
	return !plist_head_empty(&p->el_posix.pi_waiters);
}

/**
 * __mutex_adjust_prio() - compares task's expected priority with
 * 	actual priority and calls rt_mutex_setprio() on a mismatch.
 * @task: the task in question.
 * @has_pi_waiters: is task's priority boosted?
 */
static __always_inline void __mutex_adjust_prio(struct task_struct *task,
		const int has_pi_waiters)
{
	int prio;

	/* Take waiters from rt mutexes into account. */
	prio = el_posix_getprio(task, has_pi_waiters);

	/* Do not allow transition from one non-RT priority to another. */
	if (!rt_prio(prio) && !rt_prio(task->prio))
		return;

	DbgPos("__mutex_adjust_prio: boosting task %d from %d to %d\n",
			task->pid, task->prio, prio);
	if (task->prio != prio) {
		rt_mutex_setprio(task, prio);
		WARN_ON(task->prio != prio);
	}
}

/**
 * mutex_top_waiter() - get mutex's waiter with the highest priority.
 * @m_desc: the descriptor of the mutex in question.
 */
static __always_inline struct el_waiter *mutex_top_waiter(
		struct mutex_desc *m_desc)
{
	return plist_first_entry(&m_desc->wait_list, struct el_waiter,
			list_entry);
}

/**
 * mutex_has_waiters() - does mutex have any waiters?
 * @m_desc: the descriptor of the mutex in question.
 */
static __always_inline int mutex_has_waiters(struct mutex_desc *m_desc)
{
	return !plist_head_empty(&m_desc->wait_list);
}


/*
 * Functions used for priority inheritance.
 */

/* Max number of times we'll walk the boosting chain: */
static int l_max_lock_depth = 1024;

/**
 * mutex_adjust_prio_chain() - adjusts priorities in a priority inheritance
 * 	chain of tasks.
 * @task: the task in the chain that had its priority changed.
 * @orig_m_desc: descriptor of the very first mutex in the chain
 * @top_task: the just blocked task from  which the PI cahin starts (used
 * 	to catch some cases with loops in PI chain).
 */
static void mutex_adjust_prio_chain(struct task_struct *task,
		struct mutex_desc *const orig_m_desc,
		struct task_struct *const top_task)
{
	unsigned long flags;
	struct mutex_desc *m_desc;
	struct el_waiter *waiter, *top_waiter;
	int depth = 0;

	DbgPos("mutex_adjust_prio_chain started (task=%d, orig_m_desc=%p, "
			"top_task=%d\n", task->pid, orig_m_desc, top_task->pid);
again:
	if (unlikely(++depth > l_max_lock_depth)) {
		static int prev_max;
		/* Print this only once. If the admin changes the limit,
		 * print a new message when reaching the limit again */
		if (prev_max != l_max_lock_depth) {
			prev_max = l_max_lock_depth;
			printk(KERN_WARNING "Maximum lock depth %d reached task"
					": %s\n", l_max_lock_depth, task->comm);
		}
		goto out_put_task;
	}

retry:
	/* Task can not go away as we did a get_task_struct() before */
	raw_spin_lock_irqsave(&task->pi_lock, flags);

	/* Check whether the end of the boosting chain has been reached or
	 * the state of the chain has changed while we dropped the locks.
	 * 'pi_blocked_on' field can be unset only while holding pi_lock,
	 * thus it can be safely checked here */
	waiter = task->el_posix.pi_blocked_on;
	DbgPos("mutex_adjust_prio_chain task=%d waiter=%p\n",
			task->pid, waiter);
	if (!waiter)
		goto out_unlock_pi;
	smp_read_barrier_depends();

	m_desc = waiter->pi_desc;
	DbgPos("mutex_adjust_prio_chain m_desc=%p\n", m_desc);

	if (unlikely(!raw_spin_trylock(&m_desc->lock))) {
		raw_spin_unlock_irqrestore(&task->pi_lock, flags);
		cpu_relax();
		goto retry;
	}

	/* Check if further priority adjustment is necessary. */
	if (waiter->list_entry.prio == task->prio || (!rt_prio(task->prio) &&
			!rt_prio(waiter->list_entry.prio))) {
		raw_spin_unlock(&m_desc->lock);
		goto out_unlock_pi;
	}

	/* Deadlock detection */
	if (unlikely(m_desc == orig_m_desc)) {
		raw_spin_unlock(&m_desc->lock);
		goto out_unlock_pi;
	}

	/* Since el_posix.pi_blocked_on field was not empty,
	 * the mutex has at least one waiter (i.e. task itself).
	 * Remember old top waiter. */
	DbgPos("mutex_adjust_prio_chain finding top waiter\n");
	top_waiter = mutex_top_waiter(m_desc);

	/* Requeue the waiter */
	plist_del(&waiter->list_entry, &m_desc->wait_list);
	waiter->list_entry.prio = min(task->prio, MAX_RT_PRIO);
	plist_add(&waiter->list_entry, &m_desc->wait_list);

	/* Release the task */
	raw_spin_unlock(&task->pi_lock);

	if (unlikely(m_desc->pending_owner)) {
		struct el_waiter *new_top_waiter = mutex_top_waiter(m_desc);
		DbgPos("mutex_adjust_prio_chain pending_owner\n");

		/* The pending owner does not have to be the first in the wait
		 * queue. Such a situation can arise when a low priority task
		 * blocks on mutex, but its priority gets boosted before the
		 * task checks for stealing. Then the check will fail and the
		 * task will be queued with high priority.
		 * We have just dropped task->pi_lock, so task->prio may not
		 * equal waiter->list_entry.prio. That's why we try to give
		 * the mutex to the top waiter: since m_desc->lock is still
		 * held that information is reliable. */
		if (waiter == new_top_waiter) {
			/* Check if we can steal the mutex. */
			if (task->prio < m_desc->pending_owner->prio) {
				/* Since task's priority is higher than pending
				 * owner's priority, the task is not the pending
				 * owner and it can steal the mutex.
				 * Note: it is still possible that @task is the
				 * pending owner, and in that very unlikely case
				 * task will just receive a second wakeup which
				 * is OK. */
				m_desc->pending_owner = task;
				wake_up_state(task, TASK_INTERRUPTIBLE);
			}
		} else if (top_waiter == waiter) {
			if (new_top_waiter->task->prio <
					m_desc->pending_owner->prio) {
				/* The task is not on top of wait list anymore,
				 * so give the mutex to the more appropriate
				 * waiter. (It is still possible that the new
				 * top waiter is the pending owner already).*/
				m_desc->pending_owner = new_top_waiter->task;
				wake_up_state(new_top_waiter->task,
						TASK_INTERRUPTIBLE);
			}
		}

		/* We finished walking pi chain. */
		raw_spin_unlock_irqrestore(&m_desc->lock, flags);
		goto out_put_task;
	}

	/* Grab the next task */
	if (unlikely(!m_desc->owner)) {
		/* This should not happen - mutex must have either owner
		 * or a pending owner. */
		WARN_ON(m_desc->robust == ROBUST);
		raw_spin_unlock_irqrestore(&m_desc->lock, flags);
		DbgPos("el_posix error: owner of mutex is dead.\n");
		goto out_put_task;
	}
	put_task_struct(task);
	task = m_desc->owner;
	get_task_struct(task);

	raw_spin_lock(&task->pi_lock);
	DbgPos("mutex_adjust_prio_chain (de)boosting\n");
	if (waiter == mutex_top_waiter(m_desc)) {
		/* (De)boost the owner */
		plist_del(&top_waiter->pi_list_entry,
				&task->el_posix.pi_waiters);
		plist_node_init(&waiter->pi_list_entry,
				waiter->list_entry.prio);
		plist_add(&waiter->pi_list_entry, &task->el_posix.pi_waiters);
		__mutex_adjust_prio(task, 1);
	} else if (top_waiter == waiter) {
		/* Deboost the owner */
		plist_del(&waiter->pi_list_entry, &task->el_posix.pi_waiters);
		waiter = mutex_top_waiter(m_desc);
		plist_node_init(&waiter->pi_list_entry,
				waiter->list_entry.prio);
		plist_add(&waiter->pi_list_entry, &task->el_posix.pi_waiters);
		__mutex_adjust_prio(task, 1);
	}
	raw_spin_unlock(&task->pi_lock);

	DbgPos("mutex_adjust_prio_chain iteration ended\n");
	top_waiter = mutex_top_waiter(m_desc);
	raw_spin_unlock_irqrestore(&m_desc->lock, flags);

	/* Return if priority of the mutex owner was not changed. */
	if (waiter != top_waiter)
		goto out_put_task;

	/* Deadlock detection */
	if (unlikely(task == top_task))
		goto out_put_task;

	goto again;

out_unlock_pi:
	raw_spin_unlock_irqrestore(&task->pi_lock, flags);
out_put_task:
	put_task_struct(task);

	return;
}

/**
 * task_fast_locked_pi_mutex() - called when task locked PI mutex without
 * 	blocking on it (i.e. without queuing).
 * @task: points to the current task_struct.
 * @m_desc: the descriptor of the mutex in question.
 */
static void task_fast_locked_pi_mutex(struct task_struct *task,
		struct mutex_desc *const m_desc)
{
	if (unlikely(m_desc->owner))
		return;

	/* Set the task as the new owner */
	m_desc->owner = task;

	raw_spin_lock(&task->pi_lock);

	list_add(&m_desc->mutex_list_entry.pi, &task->el_posix.pi_mutex_list);

#if defined ARCH_HAS_ATOMIC_CMPXCHG
	if (likely(mutex_has_waiters(m_desc))) {
#else
	if (unlikely(mutex_has_waiters(m_desc))) {
#endif
		struct el_waiter *top_waiter;

		top_waiter = mutex_top_waiter(m_desc);
		plist_node_init(&top_waiter->pi_list_entry,
				top_waiter->list_entry.prio);
		plist_add(&top_waiter->pi_list_entry,
				&task->el_posix.pi_waiters);
		__mutex_adjust_prio(task, 1);
	}
	raw_spin_unlock(&task->pi_lock);
}

/**
 * __find_task_by_pid_check() - wrapper around find_task_by_vpid()
 * 	with additional checks.
 * @pid: the task's pid.
 */
static struct task_struct *__find_task_by_pid_check(pid_t pid)
{
	struct task_struct *task;
	const struct cred *cred, *task_cred;

	task = find_task_by_vpid(pid);
	if (unlikely(!task))
		return NULL;

	cred = current_cred();
	task_cred = __task_cred(task);
	if (unlikely(!uid_eq(cred->euid, task_cred->euid) &&
		     !uid_eq(cred->euid, task_cred->uid)))
		return NULL;

	return task;
}

#if defined ARCH_HAS_ATOMIC_CMPXCHG
/**
 * task_fast_locked_pi_mutex_proxy() - same as task_fast_locked_pi_mutex()
 * 	but owner is not current, thus checks for dead owner are required.
 * @pid: owner's pid.
 * @m_desc: the descriptor of the mutex in question.
 */
static struct task_struct *task_fast_locked_pi_mutex_proxy(const int pid,
		struct mutex_desc *const m_desc)
{
	struct task_struct *task;
	int chain_walk = 0;

	if (unlikely(pid == -1)) {
		if (m_desc->owner || m_desc->pending_owner)
			return NULL;
		else
			return ERR_PTR(-EOWNERDEAD);
	}

	/* Set the task as the new owner */
	rcu_read_lock();
	task = __find_task_by_pid_check(pid);
	if (unlikely(!task)) {
		int rval;
owner_dead:
		rcu_read_unlock();
		DbgPos("el_posix: owner of mutex is dead (pid %d).\n", pid);
		/* Now mutex has -1 in '__m_lock' field but has no owner,
		 * so it can be acquired. */
		switch (m_desc->robust) {
		case ROBUST:
			m_desc->robust = OWNER_DEAD;
			rval = -EOWNERDEAD;
			break;
		case OWNER_DEAD:
			WARN_ON_ONCE(1);
			rval = -EOWNERDEAD;
			break;
		case NOT_RECOVERABLE:
			WARN_ON_ONCE(1);
			rval = -ENOTRECOVERABLE;
			break;
		default:
			rval = 0;
			break;
		}
		return ERR_PTR(rval);
	}

	prefetch(&task->flags);

	raw_spin_lock(&task->pi_lock);
	if (unlikely(task->flags & PF_EXITING)) {
		/* This is the only function that deals with PI stuff on behalf
		 * of another task, so there is no need to check PF_EXITING
		 * flag anywhere else: we cannot race with ourselves. */
		raw_spin_unlock(&task->pi_lock);
		goto owner_dead;
	}

	m_desc->owner = task;

	list_add(&m_desc->mutex_list_entry.pi, &task->el_posix.pi_mutex_list);

	if (mutex_has_waiters(m_desc)) {
		struct el_waiter *top_waiter;

		top_waiter = mutex_top_waiter(m_desc);
		plist_node_init(&top_waiter->pi_list_entry,
				top_waiter->list_entry.prio);
		plist_add(&top_waiter->pi_list_entry,
				&task->el_posix.pi_waiters);
		__mutex_adjust_prio(task, 1);
		if (task->el_posix.pi_blocked_on)
			chain_walk = 1;
	}

	raw_spin_unlock(&task->pi_lock);
	if (unlikely(chain_walk))
		get_task_struct(task);

	rcu_read_unlock();

	if (likely(!chain_walk))
		return NULL;
	else
		return task;
}
#endif

/**
 * task_slow_locked_pi_mutex() - task locked PI mutex after being blocked on it.
 * @task: the current task_struct.
 * @m_desc: the descriptor of the mutex in question.
 * @fast_unlock: (only for architectures with ARCH_HAS_ATOMIC_CMPXCHG set)
 * 	if not zero then this function will not do any PI stuff in
 * 	the kernel to avoid fast unlocking entirely in userspace (which is
 * 	done by cmpxchg(pid, 0, &mutex->__m_lock) operation).
 */
#if defined ARCH_HAS_ATOMIC_CMPXCHG
static __always_inline void task_slow_locked_pi_mutex(
		struct task_struct *const task,
		struct mutex_desc *const m_desc, const int fast_unlock)
{
	if (unlikely(m_desc->owner))
		return;

	raw_spin_lock(&task->pi_lock);
	task->el_posix.pi_blocked_on = NULL;
	if (!fast_unlock && mutex_has_waiters(m_desc)) {
		struct el_waiter *top_waiter = mutex_top_waiter(m_desc);

		plist_node_init(&top_waiter->pi_list_entry,
				top_waiter->list_entry.prio);
		plist_add(&top_waiter->pi_list_entry,
				&task->el_posix.pi_waiters);
		__mutex_adjust_prio(task, 1);
	}

	/* Set the task as the new owner */
	if (!fast_unlock)
		list_add(&m_desc->mutex_list_entry.pi,
				&task->el_posix.pi_mutex_list);

	raw_spin_unlock(&task->pi_lock);

	/* Set the task as the new owner */
	if (!fast_unlock)
		m_desc->owner = task;
}
#else
static void task_slow_locked_pi_mutex(
		struct task_struct *const task,
		struct mutex_desc *const m_desc)
{
	if (unlikely(m_desc->owner))
		return;

	raw_spin_lock(&task->pi_lock);

	list_add(&m_desc->mutex_list_entry.pi, &task->el_posix.pi_mutex_list);

	task->el_posix.pi_blocked_on = NULL;
	if (mutex_has_waiters(m_desc)) {
		struct el_waiter *top_waiter = mutex_top_waiter(m_desc);

		plist_node_init(&top_waiter->pi_list_entry,
				top_waiter->list_entry.prio);
		plist_add(&top_waiter->pi_list_entry,
				&task->el_posix.pi_waiters);
		__mutex_adjust_prio(task, 1);
	}
	raw_spin_unlock(&task->pi_lock);

	/* Set the task as the new owner */
	m_desc->owner = task;
}
#endif

/**
 * pi_mutex_waiters_changed() - is called from pthread_cond_broadcast() after
 * 	a number of waiters were requeued from a condition variable to a mutex,
 * 	checks whether a PI chain parsing is needed.
 * @m_desc: the descriptor of the mutex in question.
 * @old_top_waiter: points to the waiter which had the highest priority before
 * 	requeue.
 * @new_top_waiter: points to the waiter which has the highest priority after
 * 	requeue.
 * @owner_pid: (only for architectures with ARCH_HAS_ATOMIC_CMPXCHG set)
 * 	contains owner's pid if the mutex was fast locked.
 *
 * The check for stealing of PTHREAD_PRIO_INHERIT mutexes must be done
 * after the setting of @task->el_posix.pi_blocked_on to avoid races
 * when another thread changes our priority in between setting of
 * pi_blocked_on and checking for stealing.
 *
 * Returns the pointer to the first task is PI chain if parsing is needed.
 */
#if defined ARCH_HAS_ATOMIC_CMPXCHG
static struct task_struct *pi_mutex_waiters_changed(
		struct mutex_desc *const m_desc,
		struct el_waiter *const old_top_waiter,
		struct el_waiter *const new_top_waiter,
		const int owner_pid)
{
	struct task_struct *const owner = m_desc->owner;
	int chain_walk = 0;

	/* We cannot trust owner_pid because it is read from user space,
	 * so check m_desc->owner instead. */
	if (!owner) {
		/* Mutex has no owner (it may still have a pending owner).
		 * This means that either we set m_desc->owner based on
		 * owner_pid or there is no need to do PI stuff. */
		if (unlikely(m_desc->pending_owner))
			/* If the new top waiter has higher priority than the
			 * old one, it will steal the mutex. */
			return NULL;

		if (owner_pid == 0)
			return NULL;
		else
			return task_fast_locked_pi_mutex_proxy(
					owner_pid, m_desc);
	}

	if (old_top_waiter != new_top_waiter) {
		raw_spin_lock(&owner->pi_lock);
		if (old_top_waiter)
			plist_del(&old_top_waiter->pi_list_entry,
					&owner->el_posix.pi_waiters);
		plist_node_init(&new_top_waiter->pi_list_entry,
				new_top_waiter->list_entry.prio);
		plist_add(&new_top_waiter->pi_list_entry,
				&owner->el_posix.pi_waiters);
		if (!old_top_waiter || old_top_waiter->pi_list_entry.prio
				!= new_top_waiter->pi_list_entry.prio) {
			__mutex_adjust_prio(owner, 1);
			if (owner->el_posix.pi_blocked_on)
				chain_walk = 1;
		}
		raw_spin_unlock(&owner->pi_lock);
	}

	if (!chain_walk) {
		return NULL;
	} else {
		get_task_struct(owner);
		return owner;
	}
}
#else
static struct task_struct *pi_mutex_waiters_changed(
		struct mutex_desc *const m_desc,
		struct el_waiter *const old_top_waiter,
		struct el_waiter *const new_top_waiter)
{
	struct task_struct *const owner = m_desc->owner;
	int chain_walk = 0;

	if (!owner)
		return NULL;

	if (old_top_waiter != new_top_waiter) {
		raw_spin_lock(&owner->pi_lock);
		if (old_top_waiter)
			plist_del(&old_top_waiter->pi_list_entry,
					&owner->el_posix.pi_waiters);
		plist_node_init(&new_top_waiter->pi_list_entry,
				new_top_waiter->list_entry.prio);
		plist_add(&new_top_waiter->pi_list_entry,
				&owner->el_posix.pi_waiters);
		if (!old_top_waiter || old_top_waiter->pi_list_entry.prio
				!= new_top_waiter->pi_list_entry.prio) {
			__mutex_adjust_prio(owner, 1);
			if (owner->el_posix.pi_blocked_on)
				chain_walk = 1;
		}
		raw_spin_unlock(&owner->pi_lock);
	}

	if (!chain_walk) {
		return NULL;
	} else {
		get_task_struct(owner);
		return owner;
	}
}
#endif

/**
 * task_blocks_on_pi_mutex() - is called when current task blocks on
 * 	a PTHREAD_PRIO_INHERIT mutex, checks whether a PI chain parsing
 * 	is needed.
 * @task: current task's task_struct.
 * @waiter: the pointer to the allocated and initialized el_waiter structure.
 * @m_desc: the descriptor of the mutex in question.
 * @owner_pid: (only for architectures with ARCH_HAS_ATOMIC_CMPXCHG set)
 * 	contains owner's pid if the mutex was fast locked.
 *
 * Returns the pointer to the first task is PI chain if parsing is needed.
 */
#ifdef ARCH_HAS_ATOMIC_CMPXCHG
static struct task_struct *task_blocks_on_pi_mutex(
		struct task_struct *const task,
		struct el_waiter *const waiter,
		struct mutex_desc *const m_desc,
		const int owner_pid)
{
	struct task_struct *owner;
	struct el_waiter *top_waiter;
	int prio, chain_walk = 0;

	DbgPos("task_blocks_on_pi_mutex started\n");

init_list_entry:
	prio = task->prio;
	plist_node_init(&waiter->list_entry, min(prio, MAX_RT_PRIO));
	/* The task is blocked on this mutex now. Corresponding
	 * smp_read_barrier_depends() is called from mutex_adjust_prio_chain()
	 * and el_posix_adjust_pi(). */
	smp_wmb();
	/* Now that waiter is initialized, we can set 'pi_blocked_on' field. */
	task->el_posix.pi_blocked_on = waiter;
	/* There was a small window between reading task->prio and writing
	 * task->el_posix.pi_blocked_on in which task's priority may have
	 * changed, so re-read it. This is faster than locking task->pi_lock.
	 * We may have old priority stored in waiter for some time, but it is
	 * OK since the m_desc->lock is locked now. */
	smp_mb();
	if (unlikely(task->prio != prio))
		goto init_list_entry;

	/* We cannot trust owner_pid because it is read from user space,
	 * so check m_desc->owner instead. */
	if (!m_desc->owner) {
		/* Mutex has no owner (it may still have a pending owner).
		 * This means that either we set m_desc->owner based on
		 * owner_pid or there is no need to do PI stuff. */
		plist_add(&waiter->list_entry, &m_desc->wait_list);

		if (unlikely(m_desc->pending_owner))
			/* If the new waiter has higher priority than the
			 * mutex top waiter, it will steal the mutex. */
			return NULL;

		if (owner_pid == 0)
			return NULL;
		else
			return task_fast_locked_pi_mutex_proxy(
					owner_pid, m_desc);
	}

	/* So, m_desc->owner is set, and that means that PI waiters are
	 * queued. Check if the new waiter has the biggest priority. */

	/* Remember the top waiter on the lock */
	if (mutex_has_waiters(m_desc))
		top_waiter = mutex_top_waiter(m_desc);
	else
		top_waiter = waiter;

	/* Add this task to the mutex waitqueue */
	plist_add(&waiter->list_entry, &m_desc->wait_list);

	/* Check if the top waiter changed and PI adjustments must be made */
	if (waiter == mutex_top_waiter(m_desc)) {
		/* Mutex top waiter changed, so we must
		 * change owner's pi_waiters */
		owner = m_desc->owner;

		raw_spin_lock(&owner->pi_lock);
		/* plist_node_init must be called before plist_del, because
		 * sometimes top_waiter == waiter and pi_list_entry would be
		 * uninitialized! */
		plist_node_init(&waiter->pi_list_entry,
				waiter->list_entry.prio);
		plist_del(&top_waiter->pi_list_entry,
				&owner->el_posix.pi_waiters);
		plist_add(&waiter->pi_list_entry, &owner->el_posix.pi_waiters);
		__mutex_adjust_prio(owner, 1);
		if (owner->el_posix.pi_blocked_on)
			chain_walk = 1;
		raw_spin_unlock(&owner->pi_lock);
	} else {
		/* Prevent compiler warning about uninitialized owner. */
		owner = NULL;
	}

	if (!chain_walk) {
		return NULL;
	} else {
		get_task_struct(owner);
		return owner;
	}
}
#else
static struct task_struct *task_blocks_on_pi_mutex(
		struct task_struct *const task,
		struct el_waiter *const waiter,
		struct mutex_desc *const m_desc)
{
	struct task_struct *owner;
	struct el_waiter *top_waiter;
	int prio, chain_walk = 0;

	DbgPos("task_blocks_on_pi_mutex started\n");

init_list_entry:
	prio = task->prio;
	plist_node_init(&waiter->list_entry, min(prio, MAX_RT_PRIO));
	/* The task is blocked on this mutex now. Corresponding
	 * smp_read_barrier_depends() is called from mutex_adjust_prio_chain()
	 * and el_posix_adjust_pi(). */
	smp_wmb();
	/* Now that waiter is initialized, we can set 'pi_blocked_on' field. */
	task->el_posix.pi_blocked_on = waiter;
	/* There was a small window between reading task->prio and writing
	 * task->el_posix.pi_blocked_on in which task's priority may have
	 * changed, so re-read it. This is faster than locking task->pi_lock.
	 * We may have old priority stored in waiter for some time, but it is
	 * OK since the m_desc->lock is locked now. */
	smp_mb();
	if (unlikely(task->prio != prio))
		goto init_list_entry;

	/* Remember the top waiter on the lock */
	if (mutex_has_waiters(m_desc))
		top_waiter = mutex_top_waiter(m_desc);
	else
		top_waiter = waiter;

	/* Add this task to the mutex waitqueue */
	plist_add(&waiter->list_entry, &m_desc->wait_list);

	/* Check if the top waiter changed and PI adjustments must be made */
	if (waiter == mutex_top_waiter(m_desc)) {
		/* Mutex top waiter changed, so we must
		 * change owner's pi_waiters */
		owner = m_desc->owner;
		if (unlikely(owner == NULL))
			/* Owner unlocked the mutex or is dead. */
			return NULL;

		raw_spin_lock(&owner->pi_lock);
		/* plist_node_init must be called before plist_del, because
		 * sometimes top_waiter == waiter and pi_list_entry would be
		 * uninitialized! */
		plist_node_init(&waiter->pi_list_entry,
				waiter->list_entry.prio);
		plist_del(&top_waiter->pi_list_entry,
				&owner->el_posix.pi_waiters);
		plist_add(&waiter->pi_list_entry, &owner->el_posix.pi_waiters);
		__mutex_adjust_prio(owner, 1);
		if (owner->el_posix.pi_blocked_on)
			chain_walk = 1;
		raw_spin_unlock(&owner->pi_lock);
	}

	if (!chain_walk) {
		return NULL;
	} else {
		get_task_struct(owner);
		return owner;
	}
}
#endif

/**
 * give_up_on_pi_mutex() - unqueues the task and undoes PI boosting.
 * @task: current's task_struct.
 * @waiter: the pointer to the queued el_waiter structure.
 * @m_desc: the descriptor of the mutex in question.
 */
static struct task_struct *give_up_on_pi_mutex(struct task_struct *const task,
		struct el_waiter *const waiter,
		struct mutex_desc *const m_desc)
{
	int chain_walk = 0;
	struct task_struct *const owner = m_desc->owner;
	struct el_waiter *old_top_waiter, *new_top_waiter;

	raw_spin_lock(&task->pi_lock);
	task->el_posix.pi_blocked_on = NULL;
	raw_spin_unlock(&task->pi_lock);

	waiter->state = NOT_WAITING;
	if (!owner) {
		plist_del(&waiter->list_entry, &m_desc->wait_list);
		return 0;
	}

	old_top_waiter = mutex_top_waiter(m_desc);
	plist_del(&waiter->list_entry, &m_desc->wait_list);
	if (mutex_has_waiters(m_desc))
		new_top_waiter = mutex_top_waiter(m_desc);
	else
		new_top_waiter = NULL;
	if (new_top_waiter != old_top_waiter) {
		int has_pi_waiters;

		raw_spin_lock(&owner->pi_lock);
		plist_del(&old_top_waiter->pi_list_entry,
				&owner->el_posix.pi_waiters);
		if (new_top_waiter) {
			plist_node_init(&new_top_waiter->pi_list_entry,
					new_top_waiter->list_entry.prio);
			plist_add(&new_top_waiter->pi_list_entry,
					&owner->el_posix.pi_waiters);
			has_pi_waiters = 1;
		} else {
			has_pi_waiters = task_has_pi_waiters(owner);
		}
		__mutex_adjust_prio(owner, has_pi_waiters);
		if (owner->el_posix.pi_blocked_on)
			chain_walk = 1;
		raw_spin_unlock(&owner->pi_lock);
	}

	if (!chain_walk) {
		return 0;
	} else {
		get_task_struct(owner);
		return owner;
	}
}

/**
 * __task_unlocked_pi_mutex() - is called from pthread_mutex_unlock() and
 * 	when task dies, undoes PI boosting on the current task.
 * @task: current's task_struct.
 * @m_desc: the descriptor of the mutex in question.
 *
 * The difference between this function and task_unlocked_pi_mutex() is that
 * pi_lock is already held here and m_desc->owner is not zeroed.
 */
static void __task_unlocked_pi_mutex(
		struct task_struct *const task,
		struct mutex_desc *const m_desc)
{
	DbgPos("task_unlocked_pi_mutex: contended=%d\n",
			mutex_has_waiters(m_desc));

	list_del(&m_desc->mutex_list_entry.pi);
	if (mutex_has_waiters(m_desc)) {
		/* Remove pi_list_entry */
		struct el_waiter *top_waiter;

		top_waiter = mutex_top_waiter(m_desc);
		plist_del(&top_waiter->pi_list_entry,
				&task->el_posix.pi_waiters);
		__mutex_adjust_prio(task, task_has_pi_waiters(task));
	}
}

/**
 * task_unlocked_pi_mutex() - is called from pthread_mutex_unlock(),
 * 	undoes PI boosting on the current task.
 * @task: current's task_struct.
 * @m_desc: the descriptor of the mutex in question.
 */
static void task_unlocked_pi_mutex(
		struct task_struct *const task,
		struct mutex_desc *const m_desc)
{
	raw_spin_lock(&task->pi_lock);
	__task_unlocked_pi_mutex(task, m_desc);
	raw_spin_unlock(&task->pi_lock);

	m_desc->owner = NULL;
}

/**
 * el_posix_adjust_pi() - called fron sched_setscheduler(), this function
 * 	updates PI chain state and (de)boost tasks' priorities if needed.
 * @task: the task that had its priority changed.
 */
void el_posix_adjust_pi(struct task_struct *task)
{
	struct el_waiter *waiter;
	unsigned long flags;

	raw_spin_lock_irqsave(&task->pi_lock, flags);
	waiter = task->el_posix.pi_blocked_on;
	if (!waiter)
		goto out_unlock;
	smp_read_barrier_depends();
	if (waiter->list_entry.prio == task->prio || (!rt_prio(task->prio) &&
			!rt_prio(waiter->list_entry.prio)))
		goto out_unlock;
	raw_spin_unlock_irqrestore(&task->pi_lock, flags);

	get_task_struct(task);
	mutex_adjust_prio_chain(task, NULL, task);

	return;

out_unlock:
	raw_spin_unlock_irqrestore(&task->pi_lock, flags);
}

/**
 * boost_priority() - boosts current task's priority by queueing it as
 * 	a PI waiter to itself.
 * @prio: new effective priority.
 * @pi_list_entry: initialized plist node to enqueue in pi_waiters list.
 *
 * Should be called with disabled irqs.
 */
static void boost_priority(const int prio,
		struct plist_node *const pi_list_entry)
{
	struct task_struct *const task = current;

	raw_spin_lock(&task->pi_lock);
	if (unlikely(!plist_node_empty(pi_list_entry)))
		plist_del(pi_list_entry, &task->el_posix.pi_waiters);
	pi_list_entry->prio = prio;
	plist_add(pi_list_entry, &task->el_posix.pi_waiters);
	__mutex_adjust_prio(task, 1);
	raw_spin_unlock(&task->pi_lock);
}

/**
 * restore_priority() - restore priority back to the original value
 * 	after boost_priority().
 * @pi_list_entry: list entry that was passed to boost_priority().
 */
static void restore_priority(struct plist_node *const pi_list_entry)
{
	struct task_struct *const task = current;

	/* Remove this task from list */
	raw_spin_lock_irq(&task->pi_lock);
	if (likely(!plist_node_empty(pi_list_entry))) {
		plist_del(pi_list_entry, &task->el_posix.pi_waiters);
		/* Undo priority boost */
		__mutex_adjust_prio(task, task_has_pi_waiters(task));
	}
	raw_spin_unlock_irq(&task->pi_lock);
}


/*
 * Functions used for priority protection.
 */

/**
 * __task_locked_pp_mutex() - called when task locks a PP mutex.
 * @task: the new owner's task_struct.
 * @m_desc: the descriptor of the mutex in question.
 *
 * task->pi_lock and m_desc->lock must be held.
 */
static void __task_locked_pp_mutex(struct task_struct *const task,
		struct mutex_desc *const m_desc)
{
	const int prioceiling = (int) m_desc->prioceiling;
	struct plist_node *old_top_entry, *new_top_entry;

	if (plist_head_empty(&task->el_posix.pp_mutex_list))
		old_top_entry = NULL;
	else
		old_top_entry = plist_first(&task->el_posix.pp_mutex_list);
	plist_node_init(&m_desc->mutex_list_entry.pp, prioceiling);
	plist_add(&m_desc->mutex_list_entry.pp, &task->el_posix.pp_mutex_list);
	new_top_entry = plist_first(&task->el_posix.pp_mutex_list);
	if (old_top_entry != new_top_entry) {
		/* Boosting priority has changed. */
		if (old_top_entry)
			plist_del(&task->el_posix.pi_list_entry,
					&task->el_posix.pi_waiters);
		task->el_posix.pi_list_entry.prio = prioceiling;
		plist_add(&task->el_posix.pi_list_entry,
				&task->el_posix.pi_waiters);
		/* Change priority */
		__mutex_adjust_prio(task, 1);
	}
}

#if defined ARCH_HAS_ATOMIC_CMPXCHG
/**
 * task_locked_pp_mutex_proxy() - called when a PP mutex was fast locked
 * 	by another task and we need to do all the priority protection stuff
 * 	(i.e. to boost owner's priority to the priority ceiling).
 * @pid: owner's pid.
 * @m_desc: the descriptor of the mutex in question.
 */
static int task_locked_pp_mutex_proxy(const int pid,
		struct mutex_desc *const m_desc)
{
	struct task_struct *task;

	if (unlikely(pid == -1)) {
		if (printk_ratelimit())
			pr_info("elpthread: possible memory corruption detected"
					"in thread %d\n", pid);
		return 0;
	}

	/* Set the task as the new owner */
	rcu_read_lock();
	task = __find_task_by_pid_check(pid);
	if (unlikely(!task)) {
		int rval;
owner_dead:
		rcu_read_unlock();
		DbgPos("el_posix: owner of mutex is dead (pid %d).\n", pid);
		/* Now mutex has -1 in '__m_lock' field but has no owner,
		 * so it can be acquired. */
		switch (m_desc->robust) {
		case ROBUST:
			m_desc->robust = OWNER_DEAD;
			rval = -EOWNERDEAD;
			break;
		case OWNER_DEAD:
			WARN_ON_ONCE(1);
			rval = -EOWNERDEAD;
			break;
		case NOT_RECOVERABLE:
			WARN_ON_ONCE(1);
			rval = -ENOTRECOVERABLE;
			break;
		default:
			rval = 0;
			break;
		}

		return rval;
	}

	prefetch(&task->flags);

	raw_spin_lock(&task->pi_lock);
	if (unlikely(task->flags & PF_EXITING)) {
		/* This is the only function that deals with PP stuff on behalf
		 * of another task, so there is no need to check PF_EXITING
		 * flag anywhere else: we cannot race with ourselves. */
		raw_spin_unlock(&task->pi_lock);
		goto owner_dead;
	}
	rcu_read_unlock();
	__task_locked_pp_mutex(task, m_desc);
	raw_spin_unlock(&task->pi_lock);

	m_desc->owner = task;

	return 0;
}
#endif

/**
 * task_locked_pp_mutex() - called when current locks a PP mutex.
 * @task: the current task_struct.
 * @m_desc: the descriptor of the mutex in question.
 */
static void task_locked_pp_mutex(struct task_struct *const task,
		struct mutex_desc *const m_desc)
{
	raw_spin_lock(&task->pi_lock);
	__task_locked_pp_mutex(task, m_desc);
	raw_spin_unlock(&task->pi_lock);

	m_desc->owner = task;
}

/**
 * __task_unlocked_pp_mutex() - is called from pthread_mutex_unlock() and
 * 	when task dies, undoes PP boosting on the current task.
 * @task: current's task_struct.
 * @m_desc: the descriptor of the mutex in question.
 *
 * The difference between this function and task_unlocked_pp_mutex() is that
 * pi_lock is already held and m_desc->owner is not zeroed.
 */
static void __task_unlocked_pp_mutex(struct task_struct *task,
		struct mutex_desc *m_desc)
{
	struct plist_node *old_top_entry, *new_top_entry;

	old_top_entry = plist_first(&current->el_posix.pp_mutex_list);
	plist_del(&m_desc->mutex_list_entry.pp,
			&current->el_posix.pp_mutex_list);
	if (plist_head_empty(&current->el_posix.pp_mutex_list))
		new_top_entry = NULL;
	else
		new_top_entry = plist_first(&current->el_posix.pp_mutex_list);
	if (!new_top_entry || new_top_entry->prio != old_top_entry->prio) {
		/* Boosting priority has changed. */
		plist_del(&current->el_posix.pi_list_entry,
				&current->el_posix.pi_waiters);
		if (new_top_entry) {
			current->el_posix.pi_list_entry.prio =
					new_top_entry->prio;
			plist_add(&current->el_posix.pi_list_entry,
					&current->el_posix.pi_waiters);
		}
		/* Change priority */
		__mutex_adjust_prio(current, task_has_pi_waiters(current));
	}
}

/**
 * task_unlocked_pp_mutex() - is called from pthread_mutex_unlock(),
 * 	undoes PP boosting on the current task.
 * @task: current's task_struct.
 * @m_desc: the descriptor of the mutex in question.
 */
static void task_unlocked_pp_mutex(struct task_struct *const task,
		struct mutex_desc *m_desc)
{
	raw_spin_lock(&task->pi_lock);
	__task_unlocked_pp_mutex(task, m_desc);
	raw_spin_unlock(&task->pi_lock);

	m_desc->owner = NULL;
}

/**
 * do_get_prio_protect() - returns the priority boosted by PTHREAD_PRIO_PROTECT
 * 	mutexes.
 *
 * This function is not required by POSIX and is used for testing
 * PTHREAD_PRIO_PROTECT mutexes.
 */
static int do_get_prio_protect()
{
	struct task_struct *const task = current;
	int prio;

	prio = task->rt_priority;
	if (!plist_head_empty(&task->el_posix.pp_mutex_list)) {
		struct plist_node *top_entry;

		top_entry = plist_first(&task->el_posix.pp_mutex_list);
		prio = max(prio, MAX_RT_PRIO-1 - top_entry->prio);
	}

	return prio;
}


/**
 * handle_fault() - handles a page fault on a given (aligned) address.
 * @address: the faulted address.
 */
static int handle_fault(unsigned long address)
{
	struct mm_struct *mm = current->mm;
	int ret = 0;

	down_read(&mm->mmap_sem);
	ret = fixup_user_fault(current, mm, (unsigned long) address,
			       FAULT_FLAG_WRITE);
	up_read(&mm->mmap_sem);

	DbgPos("handle_fault in el_posix returned %d\n", ret);

	return ret;
}


/* Iterating backwards has superior performance when moving plists. */
#ifndef plist_for_each_entry_safe_reverse
#define plist_for_each_entry_safe_reverse(pos, n, head, m)	\
	list_for_each_entry_safe_reverse(pos, n, &(head)->node_list, \
			m.node_list)
#endif


/**
 * requeue_waiters() - moves maximum @count first entries from the plist @from
 * 	at a condition variable to the plist @to at a mutex.
 * @from: the list to move.
 * @to: where to move.
 * @count: how many entries to move.
 * @m_desc: the descriptor containing the 'to' plist.
 * @protocol: the mutex's protocol (the same as m_desc->protocol).
 */
static void requeue_waiters(struct plist_head *from,
		struct plist_head *to, const int count,
		struct mutex_desc *m_desc, const char protocol)
{
	int moved, prio;
	struct el_waiter *this, *tmp;

	WARN_ON(plist_head_empty(from));

	moved = 0;
	plist_for_each_entry_safe_reverse(this, tmp, from, list_entry) {
		/* Add this task to the mutex waitqueue */
		this->state = WAITING_ON_MUTEX;
		plist_del(&this->list_entry, from);
init_list_entry:
		prio = this->task->prio;
		this->list_entry.prio = min(prio, MAX_RT_PRIO);
		if (protocol == PTHREAD_PRIO_INHERIT) {
			this->pi_desc = m_desc;
			/* The task is blocked on this mutex now.
			 * Corresponding smp_read_barrier_depends()
			 * is called from mutex_adjust_prio_chain()
			 * and el_posix_adjust_pi(). */
			smp_wmb();
			this->task->el_posix.pi_blocked_on = this;
			/* There was a small window between reading
			 * task->prio and writing el_posix.pi_blocked_on
			 * in which task's priority may have changed,
			 * so re-read it. This is faster than locking
			 * task->pi_lock. We may have old priority
			 * stored in waiter for some time, but it is
			 * OK since the m_desc->lock is locked now. */
			smp_mb();
			if (unlikely(this->task->prio != prio))
				goto init_list_entry;
		}
		plist_add(&this->list_entry, to);
		if (unlikely(++moved >= count))
			break;
	}

	return;
}

/**
 * task_can_steal_mutex() - check if the mutex can be stealed, i.e. whether
 * 	it has a pending owner with a lesser priority.
 * @m_desc: the descriptor of the mutex in question.
 * @task: the task that tries to lock the mutex.
 */
static __always_inline int task_can_steal_mutex(struct mutex_desc *m_desc,
		struct task_struct *task)
{
	if (unlikely(m_desc->pending_owner)
			&& task->prio < m_desc->pending_owner->prio)
		return 1;
	else
		return 0;
}

/**
 * try_to_lock_mutex_proxy() - check mutex->__m_lock field to see whether
 * 	the first waiter in mutex's waitqueue should be woken up.
 * @mutex: the mutex in question.
 * @m_desc: descriptor of the mutex.
 * @protocol: priority protection protocol of the mutex (the same as
 * 	m_desc->protocol).
 *
 * try_to_lock_mutex_proxy() should be called after requeue_waiters() -
 * i.e. we first move waiters and then check whether to wake up the first one.
 *
 * Returns zero on success (if the mutex is available).
 *
 * Must be called with m_desc->lock held.
 */
static __always_inline int try_to_lock_mutex_proxy(
		struct pthread_mutex_s *const mutex,
		struct mutex_desc *const m_desc,
		const char protocol)
{
	int rval, oldval;

	switch (protocol) {
	case PTHREAD_PRIO_NONE:
		/* Try to acquire the mutex for the thread-to-be-woken */
		if (unlikely(__get_user(rval, &mutex->__m_lock)))
			return -EFAULT;

		if (likely(rval != -1)) {
			rval = el_atomic_xchg_acq(oldval, &mutex->__m_lock, -1);
			if (likely(!rval))
				rval = !!oldval;
		}
		break;
#if !defined ARCH_HAS_ATOMIC_CMPXCHG
	case PTHREAD_PRIO_INHERIT:
	case PTHREAD_PRIO_PROTECT:
		rval = m_desc->owner || m_desc->pending_owner;
		break;
#endif
	default:
		BUG();
	}

	return rval;
}

/* How many threads to move at once before re-enabling interrupts
 * (smaller values improve irqs-off latency and decrease throughput of
 * pthread_cond_broadcast() and pthread_barrier_wait()). Must be
 * greater than 1. */
#define MOVE_AT_MOST	8
/* How many threads to wake at once */
#define WAKE_AT_MOST	2

/**
 * do_cond_wake() - implements pthread_cond_signal() and
 * 	pthread_cond_broadcast() functionality.
 * @cond: the condition variable in question.
 * @__c_desc: the key for finding condition variable's descriptor
 * 	(the same as cond->__c_desc).
 * @up_mode:
 * 	1 == MOVE_TO_MUTEX_ONE - move and wake one,
 * 	0 == MOVE_TO_MUTEX_ALL - move all, wake one.
 *
 * do_cond_wake() moves one or all threads waiting on the condition
 * to the corresponding mutex and wakes up the first one of them if
 * the mutex can be locked.
 */
static int do_cond_wake(
		struct pthread_cond_s *const cond,
		const int __c_desc,
		const int up_mode)
{
	struct pthread_mutex_s *mutex;
	struct task_struct *first_in_pi_chain = NULL;
	struct task_struct *const task = current;
	struct cond_desc *const c_desc  = cond_once(task, cond, __c_desc);
	struct mutex_desc *m_desc;
	struct el_waiter *waiter = NULL, *old_top_waiter, *temp_waiter;
	struct plist_head detached_list;
	struct plist_node pi_list_entry = PLIST_NODE_INIT(pi_list_entry,
			MAX_PRIO-1);
	int i, rval, do_wake_up = 0, waiting_owner;
#if defined ARCH_HAS_ATOMIC_CMPXCHG
	int oldval;
#endif

restart:
	DbgPos("do_cond_wake: up_mode %d, cond %p, c_desc %p\n",
			up_mode, cond, c_desc);

	if (unlikely(IS_ERR(c_desc)))
		return PTR_ERR(c_desc);

	raw_spin_lock_irq(&c_desc->lock);

	if (unlikely(__get_user(mutex, &cond->__c_mutex)))
		goto handle_fault_in_condition;

	/* There is no need to check with desc_in_use() here because we
	 * test whether the c_desc->wait_list is empty, and that check
	 * is enough (if it is not empty then desc_in_use() == 1, and
	 * if it is we do not care). */
	if (desc_check_type(c_desc, CONDITION)
			|| (desc_get_object(c_desc, CONDITION) != cond &&
			desc_private(c_desc))) {
		rval = -EINVAL;
		goto out_error_unlock_cond;
	}

	if (unlikely(!mutex))
		goto out_success_unlock_cond;

	/* This check also ensures that c_desc->m_desc is not NULL. */
	if (unlikely(plist_head_empty(&c_desc->wait_list))) {
		/* Although the wait queue is empty, it is still possible that
		 * __c_mutex is not NULL (if fork() happened while there were
		 * waiters). Since we are at this instruction and we tested
		 * __c_mutex before, it actually happened. Make sure
		 * cond->__c_mutex has the up-to-date information. */
		if (unlikely(__put_user(NULL, &cond->__c_mutex)))
			goto handle_fault_in_condition;
		goto out_success_unlock_cond;
	}

	m_desc = (void *) ((unsigned long) c_desc->m_desc & ~1UL);
	waiting_owner = (int) ((unsigned long) c_desc->m_desc & 1UL);

	/* For shared mutexes there is no fast way to retrieve pointer
	 * to the mutex for the current process (it might even be
	 * impossible). That's why for shared mutexes we do not try
	 * to take the mutex by ourselves and just wake the waiter. */
	if (desc_private(m_desc)) {
		/* Private mutex. */
		if (BAD_USER_REGION(mutex, struct pthread_mutex_s)) {
			DbgPos("do_cond_wake: bad private mutex address %p "
					"(c_desc->m_desc=%p)\n",
					mutex, c_desc->m_desc);
			rval = -EINVAL;
			goto out_error_unlock_cond;
		}
	}

	switch (up_mode) {
	case MOVE_TO_MUTEX_ONE:
		waiter = plist_first_entry(&c_desc->wait_list,
				struct el_waiter, list_entry);

		if (c_desc->wait_list.node_list.next->next
				== &c_desc->wait_list.node_list) {
			/* Since there are no more threads waiting on
			 * condition, disassociate the mutex from it */
			if (unlikely(__put_user(NULL, &cond->__c_mutex)))
				goto handle_fault_in_condition;
			c_desc->m_desc = NULL;
		}

		if ((!desc_private(m_desc) &&
#ifndef ARCH_HAS_ATOMIC_CMPXCHG
				m_desc->protocol == PTHREAD_PRIO_NONE &&
#endif
				!mutex_has_waiters(m_desc))
				|| unlikely(waiting_owner)) {
			/* Special case with locked recursive mutex. We should
			 * not move the waiter because he already has the mutex.
			 * No need for priority inheritance stuff here.
			 *
			 * We also cannot move the waiter if the mutex
			 * is shared (this does not apply to mutexes
			 * located entirely in kernel space and mutexes
			 * with waiters which do not require access to
			 * mutex->__m_lock). */
			c_desc->m_desc = (void *) ((unsigned long)
					c_desc->m_desc & ~1UL);
just_wake_waiter:
			plist_del(&waiter->list_entry, &c_desc->wait_list);
			waiter->state = NOT_WAITING;
			wake_up_state(waiter->task, TASK_INTERRUPTIBLE);
			raw_spin_unlock_irq(&c_desc->lock);
			break;
		}

		/* We detach waiter from the descriptor so that if
		 * atomic operation on mutex fails, waiter will be
		 * able to wake itself. */
		plist_del(&waiter->list_entry, &c_desc->wait_list);

		INIT_LIST_HEAD(&waiter->list_entry.prio_list);
		waiter->list_entry.node_list.next = &detached_list.node_list;
		waiter->list_entry.node_list.prev = &detached_list.node_list;

		detached_list.node_list.next = &waiter->list_entry.node_list;
		detached_list.node_list.prev = &waiter->list_entry.node_list;

continue_signal:
		raw_spin_lock(&m_desc->lock);
		if (check_desc(m_desc, MUTEX, mutex)
				|| unlikely(m_desc->robust == NOT_RECOVERABLE)
#if defined ARCH_HAS_ATOMIC_CMPXCHG
				|| (unlikely(!desc_private(m_desc))
#else
				|| (unlikely(!desc_private(m_desc) &&
					m_desc->protocol == PTHREAD_PRIO_NONE)
#endif
				&& !mutex_has_waiters(m_desc))) {
			/* Oops. check_desc() should not fail in good user
			 * programs. Wake the waiter and let him sort it out.
			 * It does not matter that the waiter was moved:
			 * we still hold the condition variable's spinlock.
			 *
			 * If the mutex is in OWNER_DEAD state then it has
			 * an owner that will take care of everything, so
			 * there is no need to check for this case.
			 *
			 * Also check for shared mutex again since the previous
			 * check was done without holding the spinlock. */
			raw_spin_unlock(&m_desc->lock);
			goto just_wake_waiter;
		}

		switch (m_desc->protocol) {
		case PTHREAD_PRIO_NONE:
			/* We do not check here whether the mutex is shared or
			 * whether its owner died because we already know that
			 * if it is shared (or its owner died) then it has
			 * waiters (or a new owner), and the code below does
			 * exactly what we want to do in this case. */
			if (mutex_has_waiters(m_desc)) {
				/* The mutex has waiters so there is no point
				 * in trying to fast lock it.
				 * do_wake_up = 0; */
			} else {
				do_wake_up = try_to_lock_mutex_proxy(mutex,
						m_desc, PTHREAD_PRIO_NONE);
				if (unlikely(do_wake_up == -EFAULT))
					goto handle_fault_in_mutex;
				do_wake_up = !do_wake_up;
			}

			plist_node_init(&waiter->list_entry,
					waiter->list_entry.prio);
			plist_add(&waiter->list_entry, &m_desc->wait_list);
			/* State is changing under both spinlocks */
			waiter->state = WAITING_ON_MUTEX;
			raw_spin_unlock(&c_desc->lock);

			if (do_wake_up || task_can_steal_mutex(m_desc,
					waiter->task)) {
				/* Mutex is free or can be stealed */
				m_desc->pending_owner = waiter->task;
				wake_up_state(waiter->task, TASK_INTERRUPTIBLE);
			}
			raw_spin_unlock_irq(&m_desc->lock);
			break;
		case PTHREAD_PRIO_INHERIT:
#if defined ARCH_HAS_ATOMIC_CMPXCHG
			/* We do not check here whether the mutex is shared or
			 * whether its owner died because we already know that
			 * if it is shared (or its owner died) then it has
			 * waiters (or a new owner), and the code below does
			 * exactly what we want to do in this case. */
			if (mutex_has_waiters(m_desc)) {
				/* The mutex has waiters so we know already
				 * that mutex->__m_lock == -1. */
				oldval = -1;
			} else {
				rval = el_atomic_xchg_acq(oldval,
						&mutex->__m_lock, -1);
				if (unlikely(rval))
					goto handle_fault_in_mutex;
			}
#endif
			plist_node_init(&waiter->list_entry,
					waiter->list_entry.prio);
			waiter->state = WAITING_ON_MUTEX;
			raw_spin_unlock(&c_desc->lock);

#if defined ARCH_HAS_ATOMIC_CMPXCHG
			waiter->pi_desc = m_desc;
			first_in_pi_chain = task_blocks_on_pi_mutex(
					waiter->task, waiter, m_desc, oldval);

			if (unlikely(IS_ERR(first_in_pi_chain))) {
				/* PTR_ERR(first_in_pi_chain) == -EOWNERDEAD */
				first_in_pi_chain = NULL;
				do_wake_up = 1;
			} else if (unlikely(first_in_pi_chain)) {
				/* Mutex has an owner, thus it cannot
				 * be stealed. */
				boost_priority(waiter->list_entry.prio,
						&pi_list_entry);
				do_wake_up = 0;
			} else {
				do_wake_up = !oldval || task_can_steal_mutex(
						m_desc, waiter->task);
			}
#else
			waiter->pi_desc = m_desc;
			first_in_pi_chain = task_blocks_on_pi_mutex(
					waiter->task, waiter, m_desc);

			if (unlikely(first_in_pi_chain)) {
				boost_priority(waiter->list_entry.prio,
						&pi_list_entry);
				do_wake_up = 0;
			} else {
				do_wake_up = !m_desc->owner
						&& (!m_desc->pending_owner
						|| m_desc->pending_owner->prio
							> waiter->task->prio);
			}
#endif
			if (do_wake_up) {
				/* Mutex is free or can be stealed */
				m_desc->pending_owner = waiter->task;
				wake_up_state(waiter->task, TASK_INTERRUPTIBLE);
			}
			raw_spin_unlock_irq(&m_desc->lock);

			if (unlikely(first_in_pi_chain)) {
				WARN_ON(do_wake_up);
				mutex_adjust_prio_chain(first_in_pi_chain,
						m_desc, waiter->task);
				restore_priority(&pi_list_entry);
			}
			break;
		case PTHREAD_PRIO_PROTECT:
#if defined ARCH_HAS_ATOMIC_CMPXCHG
			/* We do not check here whether the mutex is shared or
			 * whether its owner died because we already know that
			 * if it is shared (or its owner died) then it has
			 * waiters (or a new owner), and the code below does
			 * exactly what we want to do in this case. */
			if (mutex_has_waiters(m_desc)) {
				/* The mutex has waiters so we know already
				 * that mutex->__m_lock == -1. */
				oldval = -1;
			} else {
				rval = el_atomic_xchg_acq(oldval,
						&mutex->__m_lock, -1);
				if (unlikely(rval))
					goto handle_fault_in_mutex;
			}
#endif
			plist_node_init(&waiter->list_entry,
					waiter->list_entry.prio);
			plist_add(&waiter->list_entry, &m_desc->wait_list);
			waiter->state = WAITING_ON_MUTEX;
			raw_spin_unlock(&c_desc->lock);

#if defined ARCH_HAS_ATOMIC_CMPXCHG
			if (unlikely(oldval > 0)) {
				rval = task_locked_pp_mutex_proxy(oldval,
						m_desc);
				if (unlikely(rval)) {
					/* rval == -EOWNERDEAD */
					do_wake_up = 1;
				} else {
					do_wake_up = task_can_steal_mutex(
							m_desc,	waiter->task);
				}
			} else {
				do_wake_up = !oldval ||	task_can_steal_mutex(
						m_desc,	waiter->task);
			}
#else
			do_wake_up = !m_desc->owner && (!m_desc->pending_owner
					|| task_can_steal_mutex(m_desc,
							waiter->task));
#endif
			if (do_wake_up) {
				/* Mutex is free or it can be stealed */
				m_desc->pending_owner = waiter->task;
				wake_up_state(waiter->task, TASK_INTERRUPTIBLE);
			}
			raw_spin_unlock_irq(&m_desc->lock);
			break;
		}
		break;

	case MOVE_TO_MUTEX_ALL:
		/* Wake up one thread and move others from the
		 * waitqueue in condition to the waitqueue in mutex */

		if (unlikely(__put_user(NULL, &cond->__c_mutex)))
			goto handle_fault_in_condition;

		/* Detach the list of waiting threads from
		 * the condition variable so that we can
		 * later drop the spinlock */
		detached_list = c_desc->wait_list;
		detached_list.node_list.next->prev = &detached_list.node_list;
		detached_list.node_list.prev->next = &detached_list.node_list;

		c_desc->m_desc = NULL;
		plist_head_init(&c_desc->wait_list);

continue_broadcast:
		raw_spin_lock(&m_desc->lock);

		if (check_desc(m_desc, MUTEX, mutex)
				|| unlikely(m_desc->robust == NOT_RECOVERABLE)
#if defined ARCH_HAS_ATOMIC_CMPXCHG
				|| (unlikely(!desc_private(m_desc))
#else
				|| (unlikely(!desc_private(m_desc) &&
					m_desc->protocol == PTHREAD_PRIO_NONE)
#endif
				&& !mutex_has_waiters(m_desc))) {
			/* check_desc() should not fail in good user programs,
			 * we wake all waiters in this case and let them sort
			 * it out.
			 *
			 * If the mutex is shared and has no waiters then we
			 * do not have access to mutex->__m_lock field and
			 * the only solution is to wake all waiters.
			 *
			 * If the mutex is in OWNER_DEAD state then it has
			 * an owner that will take care of everything, so
			 * there is no need to check for this case.
			 *
			 * If the mutex is in a not recoverable state none of
			 * the waiters should be blocked. */
			struct el_waiter *this, *tmp;
			int i = 0;

			/* m_desc is not needed, so we release the lock. */
			raw_spin_unlock(&m_desc->lock);

			/* Wake all waiters. */
			plist_for_each_entry_safe(this, tmp, &detached_list,
					list_entry) {
				plist_del(&this->list_entry, &detached_list);
				this->state = NOT_WAITING;
				wake_up_state(this->task, TASK_INTERRUPTIBLE);
				if (unlikely(++i >= WAKE_AT_MOST))
					break;
			}
			raw_spin_unlock_irq(&c_desc->lock);
			goto broadcast_iteration_end;
		}

		if (unlikely(waiting_owner)) {
			/* This is a special case, because when thread calls
			 * pthread_cond_wait() while holding mutex, it may not
			 * release the mutex, so we wake the owner. We know
			 * that the owner is the first in the list because
			 * he was queued with priority -1. */
			DbgPos("do_cond_wake: owner is waiting\n");

			waiter = plist_first_entry(&detached_list,
					struct el_waiter, list_entry);
			waiting_owner = 0;
			plist_del(&waiter->list_entry, &detached_list);
			waiter->state = NOT_WAITING;
			wake_up_state(waiter->task, TASK_INTERRUPTIBLE);
		}

		/* Actually move tasks from the condition to the mutex */
		switch (m_desc->protocol) {
		case PTHREAD_PRIO_NONE:
			/* We do not check here whether the mutex is shared or
			 * whether its owner died because we already know that
			 * if it is shared (or its owner died) then it has
			 * waiters (or a new owner), and the code below does
			 * exactly what we want to do in this case. */
			if (mutex_has_waiters(m_desc)) {
				/* The mutex has waiters so there is no point
				 * in trying to fast lock it.
				 * do_wake_up = 0; */
			} else {
				do_wake_up = try_to_lock_mutex_proxy(mutex,
						m_desc, PTHREAD_PRIO_NONE);
				if (unlikely(do_wake_up == -EFAULT))
					goto handle_fault_in_mutex;
				do_wake_up = !do_wake_up;
			}

			waiter = plist_first_entry(&detached_list,
				struct el_waiter, list_entry);
			requeue_waiters(&detached_list, &m_desc->wait_list,
				MOVE_AT_MOST, m_desc, PTHREAD_PRIO_NONE);
			raw_spin_unlock(&c_desc->lock);
			break;
		case PTHREAD_PRIO_INHERIT:
#if defined ARCH_HAS_ATOMIC_CMPXCHG
			/* We do not check here whether the mutex is shared or
			 * whether its owner died because we already know that
			 * if it is shared (or its owner died) then it has
			 * waiters (or a new owner), and the code below does
			 * exactly what we want to do in this case. */
			if (mutex_has_waiters(m_desc)) {
				old_top_waiter = mutex_top_waiter(m_desc);
				oldval = -1;
			} else {
				if (unlikely(__get_user(oldval,
						&mutex->__m_lock)))
					goto handle_fault_in_mutex;
				if (likely(oldval != -1)) {
					rval = el_atomic_xchg_acq(oldval,
							&mutex->__m_lock, -1);
					if (unlikely(rval))
						goto handle_fault_in_mutex;
				}
				old_top_waiter = NULL;
			}

			requeue_waiters(&detached_list, &m_desc->wait_list,
				MOVE_AT_MOST, m_desc, PTHREAD_PRIO_INHERIT);
#else
			if (mutex_has_waiters(m_desc))
				old_top_waiter = mutex_top_waiter(m_desc);
			else
				old_top_waiter = NULL;

			requeue_waiters(&detached_list, &m_desc->wait_list,
				MOVE_AT_MOST, m_desc, PTHREAD_PRIO_INHERIT);
#endif
			raw_spin_unlock(&c_desc->lock);

			waiter = mutex_top_waiter(m_desc);

#if defined ARCH_HAS_ATOMIC_CMPXCHG
			first_in_pi_chain = pi_mutex_waiters_changed(
					m_desc, old_top_waiter, waiter, oldval);

			if (unlikely(IS_ERR(first_in_pi_chain))) {
				WARN_ON(PTR_ERR(first_in_pi_chain)
						== -ENOTRECOVERABLE);
				/* PTR_ERR(first_in_pi_chain) == -EOWNERDEAD */
				first_in_pi_chain = NULL;
				do_wake_up = 1;
			} else if (unlikely(first_in_pi_chain)) {
				boost_priority(waiter->list_entry.prio,
						&pi_list_entry);
				do_wake_up = 0;
			} else {
				do_wake_up = !oldval;
			}
#else
			first_in_pi_chain = pi_mutex_waiters_changed(
					m_desc, old_top_waiter, waiter);

			if (unlikely(first_in_pi_chain))
				boost_priority(waiter->list_entry.prio,
						&pi_list_entry);

			/* 'mutex' parameter is not used here. */
			do_wake_up = !try_to_lock_mutex_proxy(NULL,
					m_desc, PTHREAD_PRIO_INHERIT);
#endif
			break;
		case PTHREAD_PRIO_PROTECT:
#if defined ARCH_HAS_ATOMIC_CMPXCHG
			/* We do not check here whether the mutex is shared or
			 * whether its owner died because we already know that
			 * if it is shared (or its owner died) then it has
			 * waiters (or a new owner), and the code below does
			 * exactly what we want to do in this case. */
			if (mutex_has_waiters(m_desc)) {
				/* The mutex has waiters so we know already
				 * that mutex->__m_lock == -1. */
				oldval = -1;
			} else {
				if (unlikely(__get_user(oldval,
						&mutex->__m_lock)))
					goto handle_fault_in_mutex;
				if (likely(oldval != -1)) {
					rval = el_atomic_xchg_acq(oldval,
							&mutex->__m_lock, -1);
					if (unlikely(rval))
						goto handle_fault_in_mutex;
				}
			}
#endif
			/* Move threads waiting on the condition
			 * to the mutex waitqueue */
			waiter = plist_first_entry(&detached_list,
					struct el_waiter, list_entry);
			requeue_waiters(&detached_list, &m_desc->wait_list,
					MOVE_AT_MOST, m_desc,
					PTHREAD_PRIO_PROTECT);
			raw_spin_unlock(&c_desc->lock);

#if defined ARCH_HAS_ATOMIC_CMPXCHG
			if (unlikely(oldval > 0)) {
				rval = task_locked_pp_mutex_proxy(oldval,
						m_desc);
				if (unlikely(rval)) {
					/* rval == -EOWNERDEAD */
					do_wake_up = 1;
				}
			} else {
				do_wake_up = !oldval;
			}
#else
			/* 'mutex' parameter is not used here. */
			do_wake_up = !try_to_lock_mutex_proxy(NULL,
					m_desc, PTHREAD_PRIO_PROTECT);
#endif
			break;
		}

		if (do_wake_up || task_can_steal_mutex(m_desc, waiter->task)) {
			/* Mutex is free or can be stealed */
			DbgPos("do_cond_wake: waking %d thread\n",
					waiter->task->pid);
			m_desc->pending_owner = waiter->task;
			wake_up_state(waiter->task, TASK_INTERRUPTIBLE);
		}
		raw_spin_unlock_irq(&m_desc->lock);

		if (m_desc->protocol == PTHREAD_PRIO_INHERIT
				&& unlikely(first_in_pi_chain)) {
			mutex_adjust_prio_chain(first_in_pi_chain,
					m_desc, waiter->task);
			restore_priority(&pi_list_entry);
		}

broadcast_iteration_end:
		if (unlikely(!plist_head_empty(&detached_list))) {
			cpu_relax();
			raw_spin_lock_irq(&c_desc->lock);
			if (!plist_head_empty(&detached_list))
				goto continue_broadcast;
			raw_spin_unlock_irq(&c_desc->lock);
		}
		break;
	}
	goto out_success;

out_success_unlock_cond:
	raw_spin_unlock_irq(&c_desc->lock);
out_success:
	DbgPos("do_cond_wake end\n");
	return 0;

out_error_unlock_cond:
	raw_spin_unlock_irq(&c_desc->lock);
out_error:
	DbgPos("do_cond_wake end, error=%d\n", rval);
	return rval;

handle_fault_in_condition:
	raw_spin_unlock_irq(&c_desc->lock);
	rval = handle_fault((unsigned long) &cond->__c_mutex);
	if (!rval)
		goto restart;
	else
		goto out_error;

handle_fault_in_mutex:
	raw_spin_unlock(&m_desc->lock);
	raw_spin_unlock_irq(&c_desc->lock);
	rval = handle_fault((unsigned long) &mutex->__m_lock);
	raw_spin_lock_irq(&c_desc->lock);
	if (rval)
		goto wake_all_in_detached_list;
	if (!plist_head_empty(&detached_list)) {
		switch (up_mode) {
		case MOVE_TO_MUTEX_ONE:
			goto continue_signal;
		case MOVE_TO_MUTEX_ALL:
			goto continue_broadcast;
		}
	} else {
		DbgPos("do_cond_wake end after fault\n");
		return 0;
	}

wake_all_in_detached_list:
	i = 0;
	plist_for_each_entry_safe_reverse(waiter, temp_waiter, &detached_list,
			list_entry) {
		plist_del(&waiter->list_entry, &detached_list);
		waiter->state = NOT_WAITING;
		wake_up_state(waiter->task, TASK_INTERRUPTIBLE);
		if (++i >= WAKE_AT_MOST)
			break;
	}
	if (!plist_head_empty(&detached_list)) {
		raw_spin_unlock_irq(&c_desc->lock);
		cpu_relax();
		raw_spin_lock_irq(&c_desc->lock);
		goto wake_all_in_detached_list;
	}
	rval = -EFAULT;
	goto out_error_unlock_cond;
}

/**
 * schedule_with_timeout() - sleep with an absolute timeout.
 * @task: the current task_struct.
 * @clock_id: the clock to use for an alarm.
 * @abstime: absolute timeout.
 */
static int schedule_with_timeout(struct task_struct *task,
		clockid_t clock_id,
		struct timespec_64 *abstime)
{
	struct hrtimer_sleeper hrtimer;
	ktime_t k_abstime = ktime_set(abstime->tv_sec, abstime->tv_nsec);
	int timedout = 0;

	hrtimer_init_on_stack(&hrtimer.timer, clock_id, HRTIMER_MODE_ABS);
	hrtimer_init_sleeper(&hrtimer, task);
	hrtimer_set_expires_range_ns(&hrtimer.timer, k_abstime,
			current->timer_slack_ns);
	DbgPos("hrtimer set with slack of %ld\n", current->timer_slack_ns);
	hrtimer_start_expires(&hrtimer.timer, HRTIMER_MODE_ABS);
	if (!hrtimer_active(&hrtimer.timer))
		hrtimer.task = NULL;
	if (hrtimer.task)
		schedule();
	hrtimer_cancel(&hrtimer.timer);
	if (hrtimer.task == NULL)
		timedout = 1;
	destroy_hrtimer_on_stack(&hrtimer.timer);

	return timedout;
}

/**
 * give_up_on_mutex() - stop waiting on mutex.
 * @mutex: the mutex in question.
 * @m_desc: the mutex's descriptor.
 * @waiter: the pointer to the used el_waiter structure.
 *
 * Must be called with m_desc->lock held.
 */
static int give_up_on_mutex(struct pthread_mutex_s *mutex,
		struct mutex_desc *m_desc, struct el_waiter *waiter)
{
	struct task_struct *first_in_pi_chain = NULL;
	int rval = 0;

	if (unlikely(m_desc->robust > ROBUST))
		goto skip_fixing_user_space;

restart:
	/* Change synchronization variable as needed */
	switch (m_desc->protocol) {
#if defined ARCH_HAS_ATOMIC_CMPXCHG
	case PTHREAD_PRIO_INHERIT:
	case PTHREAD_PRIO_PROTECT:
#endif
	case PTHREAD_PRIO_NONE:
		if (m_desc->wait_list.node_list.next->next ==
				&m_desc->wait_list.node_list) {
			/* There are no other waiters. */
			if (unlikely(m_desc->pending_owner == current)) {
				/* If only we were in the waitqueue and we were
				 * the pending owner, mutex will be free. */
				if (unlikely(__put_user(0, &mutex->__m_lock)))
					goto handle_fault;
			}
#if defined ARCH_HAS_ATOMIC_CMPXCHG
			/* When ARCH_HAS_ATOMIC_CMPXCHG is not defined
			 * we race here with zeroing __m_lock in
			 * pthread_mutex_unlock() in userspace library
			 * (it is still possible to use an atomic
			 * instruction here though). */
			else if (m_desc->protocol == PTHREAD_PRIO_NONE) {
				/* So mutex has an owner and the last waiter
				 * is leaving. Set __m_lock to 1 so that the
				 * owner will be able to fast unlock it. */
				if (unlikely(__put_user(1, &mutex->__m_lock)))
					goto handle_fault;
			}
#endif
		}
		break;
	}

skip_fixing_user_space:
	/* Unqueue this task from mutex */
	if (m_desc->protocol != PTHREAD_PRIO_INHERIT) {
		plist_del(&waiter->list_entry, &m_desc->wait_list);
		waiter->state = NOT_WAITING;
	} else {
		first_in_pi_chain = give_up_on_pi_mutex(waiter->task,
				waiter, m_desc);
	}

	if (unlikely(m_desc->pending_owner == current)) {
		/* This task was set as the pending owner,
		 * give the mutex to the next waiter */
		if (mutex_has_waiters(m_desc)) {
			struct task_struct *to_wake =
					plist_first_entry(&m_desc->wait_list,
					struct el_waiter, list_entry)->task;
			m_desc->pending_owner = to_wake;
			wake_up_state(to_wake, TASK_INTERRUPTIBLE);
		} else {
			m_desc->pending_owner = NULL;
		}
	}

	DbgPos("give_up_on_mutex: mutex %p unqueued\n", mutex);
	raw_spin_unlock_irq(&m_desc->lock);
	if (first_in_pi_chain)
		mutex_adjust_prio_chain(first_in_pi_chain, m_desc,
				waiter->task);
	return rval;

handle_fault:
	raw_spin_unlock_irq(&m_desc->lock);
	rval = handle_fault((unsigned long) &mutex->__m_lock);
	raw_spin_lock_irq(&m_desc->lock);
	if (!rval)
		goto restart;
	else
		goto skip_fixing_user_space;
}

/**
 * normal_prio() - calculate the expected normal priority, i.e. priority
 * 	without taking priority inheritance and priority protection into
 * 	account. Returned priority is "kernel priority", i.e. 0 is the
 * 	highest possible priority.
 * @p: the task in question.
 */
static __always_inline int normal_prio(struct task_struct *p)
{
	int prio;

	if (likely(p->policy == SCHED_FIFO || p->policy == SCHED_RR))
		prio = MAX_RT_PRIO-1 - p->rt_priority;
	else
		prio = p->static_prio;

	return prio;
}

/* Be careful: if this function fails, it does not enable interrupts
 * and check for preemption. Must be called with the spinlock held. */
static int try_to_take_mutex(struct task_struct *const task,
		struct pthread_mutex_s *const mutex,
		struct mutex_desc *const m_desc,
		struct el_waiter *const waiter)
{
#if DEBUG_POSIX
	if (m_desc->pending_owner)
		DbgPos("try_to_take_mutex: pending_owner %d (prio %d)\n",
				m_desc->pending_owner->pid,
				m_desc->pending_owner->prio);
	else
		DbgPos("try_to_take_mutex: no pending_owner\n");
#endif
	if (likely(m_desc->pending_owner == task) ||
			unlikely(m_desc->pending_owner &&
			m_desc->pending_owner->prio > task->prio)) {
		/* Mutex is ours */
		m_desc->pending_owner = NULL;
		plist_del(&waiter->list_entry, &m_desc->wait_list);
		waiter->state = NOT_WAITING;
		switch (m_desc->protocol) {
		case PTHREAD_PRIO_INHERIT:
			/* Check if there are other waiters */
#if defined ARCH_HAS_ATOMIC_CMPXCHG
			if (plist_head_empty(&m_desc->wait_list)
					&& likely(m_desc->robust <= ROBUST)
					&& likely(!__put_user(task->pid,
							&mutex->__m_lock))) {
				task_slow_locked_pi_mutex(task, m_desc, 1);
			} else {
				task_slow_locked_pi_mutex(task, m_desc, 0);
			}
#else
			task_slow_locked_pi_mutex(task, m_desc);
#endif
			break;
		case PTHREAD_PRIO_PROTECT:
#if defined ARCH_HAS_ATOMIC_CMPXCHG
			if (plist_head_empty(&m_desc->wait_list)
					&& likely(m_desc->robust <= ROBUST)
					&& likely(!__put_user(task->pid,
							&mutex->__m_lock))) {
				/* Now the mutex has pid in mutex->__m_lock
				 * field and it has no waiters, so there is no
				 * need to boost current's priority: if some
				 * task blocks on the mutex then it will raise
				 * current's priority, otherwise boosting will
				 * just waste CPU time. */
			} else
#endif
				task_locked_pp_mutex(task, m_desc);
			break;
		case PTHREAD_PRIO_NONE:
			/* Check if there are other waiters */
			if (plist_head_empty(&m_desc->wait_list))
				/* If this fails, fast unlocking
				 * will not be possible */
				__put_user(1, &mutex->__m_lock);
			break;
		}
		return 0;
	} else {
		/* Either we caught a signal or the mutex was stealed. */
		return 1;
	}
}

/**
 * __do_mutex_timedlock() - implements pthread_mutex_(timed)lock().
 * @mutex: the mutex to be locked.
 * @abstime: absolute timeout for CLOCK_REALTIME.
 * @task: points to current task_struct.
 * @m_desc: the mutex's descriptor.
 *
 * mutex->__m_lock field is used to synchronize threads. It is
 * interpreted differently depending on whether the architecture
 * has atomic compare-and-swap instruction and on the type of the
 * mutex in question.
 *
 *
 * 1) PTHREAD_PRIO_NONE mutex:
 *
 * 1.1) ARCH_HAS_ATOMIC_CMPXCHG is set.
 * 	__m_lock == 0 - the mutex is free and there are no waiters.
 * 			It can be acquired promptly from userspace with
 * 			cmpxchg(&__m_lock,0,1).
 * 	__m_lock == 1 - the mutex is locked but has no waiters.
 * 			It can be freed promptly from userspace with
 * 			cmpxchg(&__m_lock,1,0).
 * 	__m_lock == -1 - the mutex is locked and may have waiters. It cannot
 * 			be freed without checking the waitqueue
 * 			(i.e. without a system call).
 * Transition 0->1 and 1->0 are the only ones allowed to happen in
 * userspace. All other transitions happen in kernel under the mutex's
 * spinlock. That's why when we see that __m_lock == -1 and the waitqueue is
 * empty while holding spinlock, we can just write '1' into __m_lock to
 * permit fast unlocking.
 * This is done, for example, when contention for a lock is low
 * and only 1 thread is waiting for it: when owner gives the mutex to this
 * waiter, waiter before unlocking the spinlock writes '1' (see
 * try_to_take_mutex()). This optimization is also used in
 * cond_signal/broadcast (see do_cond_wake() and try_to_lock_mutex_proxy()).
 *
 * 1.2) ARCH_HAS_ATOMIC_CMPXCHG is not set.
 * 	__m_lock == 0 - the mutex is free and can be acquired promptly with
 * 			xchg(&__m_lock,1). NOTE: In contrast to 1.1 (see above)
 * 			the mutex may have waiters! And if it has, at least one
 * 			of them is running and trying to acquire the mutex.
 * 	__m_lock == 1 - the mutex is locked and can be freed promptly from
 * 			userspace with xchg(&__m_lock,0). NOTE: Like with
 * 			__m_lock == 0 it may have waiters!
 * 	__m_lock == -1 - the mutex is locked and may have waiters.
 * 			It cannot be freed without checking the waitqueue
 * 			(i.e. without a system call).
 * All transitions are allowed to happen in userspace (*->-1 only happens in
 * mutex_trylock, *->1 happens in mutex_lock and *->0 happens in mutex_unlock),
 * so the same technique as in 1.1 above can be used in try_to_take_mutex()
 * and cond_signal/broadcast.
 * When a thread adds itself to the waitqueue, it (like in 1.1 above) changes
 * mutex state to -1. When owner unlocks the mutex with xchg(&__m_lock,0) and
 * sees that __m_lock was set to -1, it enters the kernel and tries to lock
 * the mutex for the thread-to-be-woken  (see __do_mutex_unlock()).
 * If the mutex had been locked while the owner was entering the kernel (i.e.
 * xchg returned non-zero value), then it is left in '-1' state. If mutex is
 * free at the moment of xchg (i.e. xchg returns 0), the owner (the one that
 * wrote 0) will wake the first waiter.
 * One thing to pay attention to: some other thread may try to lock the mutex
 * with xchg(&__m_lock,1) when it is in the '-1' state. Owner in this case will
 * not do a system call when unlocking the mutex, and an obligation to clean
 * up this (i.e. to set __m_lock to -1) lies on that thread that saw '-1'
 * in __m_lock.
 *
 *
 * 2) PTHREAD_PRIO_INHERIT or PTHREAD_PRIO_PROTECT mutex and
 * ARCH_HAS_ATOMIC_CMPXCHG is set:
 * 	__m_lock == 0 - the mutex is free and there are no waiters.
 * 			It can be acquired promptly from userspace with
 * 			cmpxchg(&__m_lock,0,tid).
 * 	__m_lock == owner's tid (pid in kernel terminology) -
 * 			the mutex is locked but has no waiters.
 * 			It can be freed promptly from userspace with
 * 			cmpxchg(&__m_lock,tid,0).
 * 	__m_lock == -1 - the mutex is locked and may have waiters. It cannot
 * 			be freed without checking the corresponding waitqueue
 * 			(i.e. without a system call).
 * Priority inheritance and priority protection protocols require some
 * additional fields to be set when locking/unlocking the mutex. For example,
 * 'owner' field in mutex descriptor points to owner' task_struct. If a thread
 * acquired the mutex in userspace without doing a system call, it cannot set
 * those fields. So, '-1' has an additional meaning in this case: it means that
 * all necessary priority inheritance stuff (like setting 'owner' field) has
 * been done and will have to be undone when unlocking the mutex.
 *
 *
 * 3) All other cases (PTHREAD_PRIO_PROTECT and PTHREAD_PRIO_INHERIT:
 * without ARCH_HAS_ATOMIC_CMPXCHG set):
 * Since in these cases a system call is always done and the locking/unlocking
 * thread can work directly with the mutex's waitqueue, there is no need in
 * __m_lock field and it is always 0.
 */
static int __do_mutex_timedlock(
		struct pthread_mutex_s *__restrict const mutex,
		const struct timespec_64 *__restrict const abstime,
		struct task_struct *const task,
		struct mutex_desc *const m_desc)
{
	int rval, oldval, protocol;
	struct el_waiter waiter;
	struct timespec_64 iabstime;
#if DEBUG_POSIX
	int __m_lock, __m_owner;

	__get_user(__m_lock, &mutex->__m_lock);
	__get_user(__m_owner, &mutex->__m_owner);
#endif
	DbgPos("mutex_lock mutex=%p: start, lock=%d, owner=%d\n",
			mutex, __m_lock, __m_owner);

	if (unlikely(abstime))
		if (unlikely(copy_from_user(&iabstime, abstime,
				sizeof(iabstime))))
			return -EFAULT;

restart:
	raw_spin_lock_irq(&m_desc->lock);
	if (check_desc(m_desc, MUTEX, mutex)) {
		rval = -EINVAL;
		goto out_unlock;
	}

	protocol = (int) m_desc->protocol;
	switch (protocol) {
	case PTHREAD_PRIO_PROTECT:
		DbgPos("Testing prioceiling=%d, prio=%d\n",
				(int) m_desc->prioceiling, normal_prio(task));
		if (unlikely(((int) m_desc->prioceiling) > normal_prio(task))) {
			rval = -EINVAL;
			goto out_unlock;
		}
	/* FALLTHROUGH */
	case PTHREAD_PRIO_INHERIT:
		DbgPos("mutex_lock mutex=%p: protocol=%d, pending_owner=%d, "
				"owner=%d\n", mutex, protocol,
				(m_desc->pending_owner)
					? (int) m_desc->pending_owner->pid : 0,
				(m_desc->owner) ? m_desc->owner->pid : 0);

		/* If mutex is in NOT_RECOVERABLE state return an error and
		 * if it is in OWNER_DEAD state then we'll have to block. */
		if (unlikely(m_desc->robust == NOT_RECOVERABLE)) {
			rval = -ENOTRECOVERABLE;
			goto out_unlock;
		}

#if defined ARCH_HAS_ATOMIC_CMPXCHG
		/* Read mutex->__m_lock beforehead. */
		if (unlikely(__get_user(oldval, &mutex->__m_lock))) {
			rval = -EFAULT;
			goto out_unlock;
		}

		if (unlikely(m_desc->type == PTHREAD_MUTEX_ERRORCHECK_NP) &&
			      (m_desc->owner == task || oldval == task->pid)) {
			rval = -EDEADLK;
			goto out_unlock;
		}

		if (likely(oldval != -1)) {
			rval = el_atomic_xchg_acq(oldval, &mutex->__m_lock, -1);
			if (unlikely(rval))
				goto out_unlock;

			if (unlikely(oldval == 0)) {
				/* Mutex was unlocked while we were
				 * entering the kernel. */
				if (unlikely(__put_user(task->pid,
						&mutex->__m_lock)))
					/* Priority stuff must be done
					 * when __m_lock == -1. */
					goto lock_protected_mutex;
				goto success_unlock;
			} else if (protocol == PTHREAD_PRIO_PROTECT) {
				/* Mutex's owner priority was not
				 * boosted so do it now. */
				rval = task_locked_pp_mutex_proxy(oldval,
						m_desc);
				if (rval)
					/* Owner died and there are
					 * no waiters */
					goto lock_protected_mutex;
			}
		} else if (task_can_steal_mutex(m_desc, task)) {
			/* We can steal the mutex. Note that this check alone
			 * is not enough for PTHREAD_PRIO_INHERIT mutexes
			 * (see comment before task_blocks_on_pi_mutex()). */
			m_desc->pending_owner = NULL;
lock_protected_mutex:
			if (protocol == PTHREAD_PRIO_INHERIT)
				task_fast_locked_pi_mutex(task, m_desc);
			else
				task_locked_pp_mutex(task, m_desc);
			goto success_unlock;
		}
#else
		if (unlikely(m_desc->type == PTHREAD_MUTEX_ERRORCHECK_NP
				&& m_desc->owner == task)) {
			rval = -EDEADLK;
			goto out_unlock;
		}

		if (!m_desc->owner && (!m_desc->pending_owner ||
				m_desc->pending_owner->prio > task->prio)) {
			/* Note that this check alone is not enough for
			 * PTHREAD_PRIO_INHERIT mutexes (see comment
			 * before task_blocks_on_pi_mutex()). */
			if (m_desc->pending_owner)
				/* Steal the mutex */
				m_desc->pending_owner = NULL;

			if (protocol == PTHREAD_PRIO_INHERIT)
				task_fast_locked_pi_mutex(task, m_desc);
			else
				task_locked_pp_mutex(task, m_desc);
			goto success_unlock;
		}
#endif
		break;
	case PTHREAD_PRIO_NONE:
		/* Check if owner unlocked mutex while we were entering
		 * kernel. Also it may be possible to steal the mutex
		 * (since no priority protection protocol is used, we will
		 * steal mutex regardless pending owner's priority). */

		/* Read mutex->__m_lock beforehead. */
		if (unlikely(__get_user(oldval, &mutex->__m_lock))) {
			rval = -EFAULT;
			goto out_unlock;
		}

		if (likely(oldval != -1)) {
			if (unlikely(el_atomic_xchg_acq(oldval,
					&mutex->__m_lock, -1))) {
				rval = -EFAULT;
				goto out_unlock;
			}
		}

		if (unlikely(oldval == 0)) {
#if !defined ARCH_HAS_ATOMIC_CMPXCHG
			if (plist_head_empty(&m_desc->wait_list))
#endif
				/* Mutex has no waiters, so
				 * we try to make fast unlock possible. */
				__put_user(1, &mutex->__m_lock);
			goto success_unlock;
		}
		if (unlikely(m_desc->pending_owner) &&
				m_desc->pending_owner->prio > task->prio) {
			/* Success */
			m_desc->pending_owner = NULL;
			goto success_unlock;
		}
		break;
	default:
		rval = -EINVAL;
		goto out_unlock;
	}

	/* Check timeout validity before blocking ourselves */
	if (unlikely(abstime && (iabstime.tv_nsec < 0 ||
			iabstime.tv_nsec >= 1000000000))) {
		rval = -EINVAL;
		goto out_unlock;
	}

	waiter.task = task;
	waiter.timedout = 0;
	waiter.state = WAITING_ON_MUTEX;

	/* Queue ourselves. */
	if (protocol == PTHREAD_PRIO_INHERIT) {
		struct task_struct *first_in_pi_chain;

		waiter.pi_desc = m_desc;
#if defined ARCH_HAS_ATOMIC_CMPXCHG
		first_in_pi_chain = task_blocks_on_pi_mutex(task,
				&waiter, m_desc, oldval);

		if (unlikely(IS_ERR(first_in_pi_chain))) {
			WARN_ON(PTR_ERR(first_in_pi_chain) == -ENOTRECOVERABLE);
			(void) give_up_on_pi_mutex(task, &waiter, m_desc);
			task_fast_locked_pi_mutex(task, m_desc);
			rval = -EOWNERDEAD;
			goto out_unlock;
		}
#else
		first_in_pi_chain = task_blocks_on_pi_mutex(task,
				&waiter, m_desc);
#endif

		/* Check for stealing _after_ enqueuing ourselves.
		 * This protects us from race with another task
		 * boosting our priority. */
		if (task_can_steal_mutex(m_desc, task))
			m_desc->pending_owner = task;

		/* Since we are going to call schedule() right away,
		 * there is no need to check preemption. */
		raw_spin_unlock_irq_no_resched(&m_desc->lock);

		/* Adjust priorities if necessary */
		if (first_in_pi_chain)
			mutex_adjust_prio_chain(first_in_pi_chain, m_desc,
						task);
	} else {
		int prio;

		/* This thread is added to wait queue either with
		 * its own priority if it is a real-time thread or
		 * with MAX_RT_PRIO if it is non-RT thread. This
		 * way RT threads get woken up in priority order
		 * and non-RT threads get woken up in FIFO order. */
		prio = min(task->prio, MAX_RT_PRIO);
		plist_node_init(&waiter.list_entry, prio);
		plist_add(&waiter.list_entry, &m_desc->wait_list);
		/* Since we are going to call schedule() right away,
		 * there is no need to check preemption. */
		raw_spin_unlock_irq_no_resched(&m_desc->lock);
	}

sleep:
	set_task_state(task, TASK_INTERRUPTIBLE);
	DbgPos("mutex_lock: before schedule(), mutex=%p\n", mutex);
	if (likely(m_desc->pending_owner != task
			&& m_desc->robust != NOT_RECOVERABLE)) {
		/* Sleep only when necessary */
		if (likely(!abstime))
			schedule();
		else
			waiter.timedout = schedule_with_timeout(task,
						CLOCK_REALTIME, &iabstime);
	} else {
		preempt_check_resched();
	}
	__set_task_state(task, TASK_RUNNING);

#if DEBUG_POSIX
	__get_user(__m_lock, &mutex->__m_lock);
#endif
	DbgPos("mutex_lock: after schedule(), lock=%d\n", __m_lock);

	raw_spin_lock_irq(&m_desc->lock);
	if (unlikely(waiter.timedout) ||
			try_to_take_mutex(task, mutex, m_desc, &waiter) != 0) {
		/* Timed out, signaled or the mutex was stealed */
		if (likely(!waiter.timedout) && !signal_pending(task)
				&& likely(m_desc->robust != NOT_RECOVERABLE)) {
			raw_spin_unlock_irq_no_resched(&m_desc->lock);
			goto sleep;
		}

		rval = give_up_on_mutex(mutex, m_desc, &waiter);
		if (unlikely(m_desc->robust == NOT_RECOVERABLE)) {
			rval = -ENOTRECOVERABLE;
		} else if (likely(!rval)) {
			if (waiter.timedout)
				rval = -ETIMEDOUT;
			else
				rval = -EINTR;
		}
		goto out;
	}

success_unlock:
	raw_spin_unlock_irq(&m_desc->lock);
	if (unlikely(m_desc->robust > ROBUST)) {
		/* Since we were able to lock the mutex, it
		 * should not be in NOT_RECOVERABLE state. */
		WARN_ON_ONCE(m_desc->robust == NOT_RECOVERABLE);
		rval = -EOWNERDEAD;
	} else {
		rval = 0;
	}
#if DEBUG_POSIX
	__get_user(__m_lock, &mutex->__m_lock);
#endif
	DbgPos("mutex_lock success! mutex=%p: lock=%d, rval=%d\n",
			mutex, __m_lock, rval);
	return rval;

out_unlock:
	raw_spin_unlock_irq(&m_desc->lock);
	if (unlikely(rval == -EFAULT)) {
		if (!handle_fault((unsigned long) &mutex->__m_lock))
			goto restart;
	}
out:
#if DEBUG_POSIX
	__get_user(__m_lock, &mutex->__m_lock);
#endif
	DbgPos("mutex_lock mutex=%p: lock=%d, rval=%d\n",
			mutex, __m_lock, rval);
	WARN_ON(rval == 0);
	return rval;
}

/**
 * __do_mutex_trylock - kernel part of pthread_mutex_trylock() implementation
 * @mutex: the mutex in question.
 * @task: pointer to current task_struct.
 * @m_desc: descriptor of the mutex.
 */
static int __do_mutex_trylock(
		struct pthread_mutex_s *__restrict const mutex,
		struct task_struct *const task,
		struct mutex_desc *const m_desc)
{
#if defined ARCH_HAS_ATOMIC_CMPXCHG
	struct task_struct *first_in_pi_chain;
	int oldval;
#endif
	const int protocol = (int) m_desc->protocol;
	int rval;

restart:
	raw_spin_lock_irq(&m_desc->lock);
	if (check_desc(m_desc, MUTEX, mutex)) {
		rval = -EINVAL;
		goto out_unlock;
	}
	DbgPos("mutex_trylock mutex=%p: start, pending_owner=%d\n",
			mutex, (m_desc->pending_owner) ?
				m_desc->pending_owner->pid : 0);

#if defined ARCH_HAS_ATOMIC_CMPXCHG
	if (unlikely(protocol == PTHREAD_PRIO_NONE
			|| m_desc->robust == NOT_ROBUST)) {
#else
	if (unlikely(protocol == PTHREAD_PRIO_NONE)) {
#endif
		rval = -EINVAL;
		goto out_unlock;
	}

	/* So now we know that protocol is either
	 * PTHREAD_PRIO_INHERIT or PTHREAD_PRIO_PROTECT. */

	if (unlikely(m_desc->robust == NOT_RECOVERABLE)) {
		rval = -ENOTRECOVERABLE;
		goto out_unlock;
	}

	if (protocol == PTHREAD_PRIO_PROTECT) {
		DbgPos("Testing prioceiling=%d, prio=%d\n",
				(int) m_desc->prioceiling, normal_prio(task));
		if (unlikely(((int) m_desc->prioceiling) > normal_prio(task))) {
			rval = -EINVAL;
			goto out_unlock;
		}
	}

#if defined ARCH_HAS_ATOMIC_CMPXCHG
	/* This is a robust mutex, so check
	 * everything with extra care. */
	if (unlikely(__get_user(oldval, &mutex->__m_lock))) {
		rval = -EFAULT;
		goto out_unlock;
	}

	if (likely(oldval != -1)) {
		rval = el_atomic_xchg_acq(oldval, &mutex->__m_lock, -1);
		if (unlikely(rval))
			goto out_unlock;

		if (unlikely(oldval == 0)) {
			/* Mutex was unlocked while we were
			 * entering the kernel. */
			if (unlikely(__put_user(task->pid, &mutex->__m_lock)))
				/* Priority stuff must be done
				 * when __m_lock == -1. */
				goto lock_protected_mutex;
			goto out_unlock;
		}
	} else if (task_can_steal_mutex(m_desc, task)) {
		/* We can steal the mutex. */
		m_desc->pending_owner = NULL;
		rval = 0;
lock_protected_mutex:
		if (protocol == PTHREAD_PRIO_INHERIT)
			task_fast_locked_pi_mutex(task, m_desc);
		else
			task_locked_pp_mutex(task, m_desc);
		goto out_unlock;
	}

	if (m_desc->owner || m_desc->pending_owner) {
		/* The mutex is busy and has a valid owner. */
		rval = -EBUSY;
		goto out_unlock;
	}

	/* Since mutex has no new waiters there should be
	 * no need to walk priority chain. */
	if (protocol == PTHREAD_PRIO_INHERIT) {
		first_in_pi_chain = task_fast_locked_pi_mutex_proxy(
				oldval, m_desc);
		if (IS_ERR(first_in_pi_chain)) {
			task_fast_locked_pi_mutex(task, m_desc);
			rval = PTR_ERR(first_in_pi_chain);
		} else {
			WARN_ON(first_in_pi_chain);
			rval = -EBUSY;
		}
	} else {
		rval = task_locked_pp_mutex_proxy(oldval, m_desc);
		if (rval) {
			/* Owner died and there are no waiters */
			task_locked_pp_mutex(task, m_desc);
		} else {
			rval = -EBUSY;
		}
	}
	goto out_unlock;
#else
	if (!m_desc->owner && (!m_desc->pending_owner ||
			m_desc->pending_owner->prio > task->prio)) {
		if (m_desc->pending_owner)
			/* Steal the mutex */
			m_desc->pending_owner = NULL;

		if (protocol == PTHREAD_PRIO_INHERIT)
			task_fast_locked_pi_mutex(task, m_desc);
		else
			task_locked_pp_mutex(task, m_desc);

		rval = 0;
	} else {
		rval = -EBUSY;
	}
#endif

out_unlock:
	raw_spin_unlock_irq(&m_desc->lock);

	if (unlikely(rval == -EFAULT)) {
		if (!handle_fault((unsigned long) &mutex->__m_lock))
			goto restart;
	}

	if (rval == 0) {
		if (unlikely(m_desc->robust > ROBUST)) {
			/* Since we were able to lock the mutex, it
			 * should not be in NOT_RECOVERABLE state. */
			WARN_ON_ONCE(m_desc->robust == NOT_RECOVERABLE);
			rval = -EOWNERDEAD;
		}
	}

	DbgPos("mutex_trylock mutex=%p: rval=%d\n", mutex, rval);
	return rval;
}

static int do_mutex_timedlock(
		struct pthread_mutex_s *__restrict const mutex,
		const struct timespec_64 *__restrict const abstime,
		const int __m_kind, const int __m_desc)
{
	struct task_struct *const task = current;
	struct mutex_desc *const m_desc = mutex_once(task, mutex, __m_desc,
			__m_kind);

	if (unlikely(IS_ERR(m_desc)))
		return PTR_ERR(m_desc);

	if (likely(abstime != (void *) -1
#ifdef CONFIG_64BIT
			/* On 64-bit kernels running 32-bit applications
			 * we have to test for 32 bits 'long' variables. */
			&& ((int) (unsigned long) abstime) != -1
#endif
			))
		return __do_mutex_timedlock(mutex, abstime, task, m_desc);
	else
		return __do_mutex_trylock(mutex, task, m_desc);
}

/**
 * __do_mutex_unlock() - implements pthread_mutex_unlock().
 * @mutex: the mutex to be unlocked.
 * @task: pointer to current task_struct.
 * @m_desc: the mutex's descriptor.
 *
 * If __do_mutex_unlock() returns -ENOTRECOVERABLE, then the caller must
 * call robust_mutex_wake_all() to wake all waiters on this mutex.
 *
 * Must be called with m_desc->lock held.
 */
static int __do_mutex_unlock(struct pthread_mutex_s *__restrict const mutex,
		struct task_struct *const task,
		struct mutex_desc *const m_desc)
{
	int rval;
	const int protocol = (int) m_desc->protocol;
	struct el_waiter *waiter;

	DbgPos("mutex_unlock mutex=%p: start\n", mutex);

	switch (__builtin_expect(protocol, PTHREAD_PRIO_INHERIT)) {
	case PTHREAD_PRIO_NONE:
		if (likely(mutex_has_waiters(m_desc))) {
#if !defined ARCH_HAS_ATOMIC_CMPXCHG
			int oldval;
			rval = el_atomic_xchg_acq(oldval, &mutex->__m_lock, -1);
			if (unlikely(rval || oldval))
				/* If el_atomic_xchg_acq failed with -EFAULT or
				 * the mutex already has owner (i.e. oldval is
				 * 1 or -1) we do notihng. */
				break;
#endif
			waiter = plist_first_entry(&m_desc->wait_list,
					struct el_waiter, list_entry);
			m_desc->pending_owner = waiter->task;
			wake_up_state(waiter->task, TASK_INTERRUPTIBLE);
			rval = 0;
		} else {
#if defined ARCH_HAS_ATOMIC_CMPXCHG
			/* We do not know if there are waiters, so just exit
			 * (maybe somebody has not added himself to the
			 * waitqueue yet). */
			rval = __put_user(0, &mutex->__m_lock);
#else
			rval = 0;
#endif
		}
		break;
	case PTHREAD_PRIO_INHERIT:
	case PTHREAD_PRIO_PROTECT:
		if (unlikely(task != m_desc->owner)) {
			rval = -EPERM;
			break;
		}

		if (protocol == PTHREAD_PRIO_INHERIT)
			task_unlocked_pi_mutex(task, m_desc);
		else
			task_unlocked_pp_mutex(task, m_desc);

		if (unlikely(m_desc->robust == OWNER_DEAD)) {
			m_desc->robust = NOT_RECOVERABLE;
			rval = -ENOTRECOVERABLE;
			break;
		}

		if (likely(mutex_has_waiters(m_desc))) {
			waiter = plist_first_entry(&m_desc->wait_list,
					struct el_waiter, list_entry);
			m_desc->pending_owner = waiter->task;
			wake_up_state(waiter->task, TASK_INTERRUPTIBLE);
		} else {
#ifdef ARCH_HAS_ATOMIC_CMPXCHG
			if (unlikely(__put_user(0, &mutex->__m_lock))) {
				rval = -EFAULT;
				break;
			}
#endif
		}
		rval = 0;
		break;
	default:
		rval = -EINVAL;
		break;
	}

	DbgPos("mutex_unlock mutex=%p: end, rval=%d\n", mutex, rval);
	return rval;
}

static void robust_mutex_wake_all(
		struct pthread_mutex_s *__restrict const mutex,
		struct mutex_desc *m_desc)
{
	struct el_waiter *waiter;
	int i;

	if (!mutex_has_waiters(m_desc))
		return;

	raw_spin_lock_irq(&m_desc->lock);
	waiter = plist_first_entry(&m_desc->wait_list,
			struct el_waiter, list_entry);

continue_wake:
	if (check_desc(m_desc, MUTEX, mutex)
			|| m_desc->robust != NOT_RECOVERABLE) {
		raw_spin_unlock_irq(&m_desc->lock);
		return;
	}

	i = 0;
	list_for_each_entry_from(waiter, &m_desc->wait_list.node_list,
			list_entry.node_list) {
		wake_up_state(waiter->task, TASK_INTERRUPTIBLE);
		if (++i >= WAKE_AT_MOST)
			break;
	}
	raw_spin_unlock_irq(&m_desc->lock);

	if (mutex_has_waiters(m_desc)) {
		cpu_relax();
		raw_spin_lock_irq(&m_desc->lock);
		goto continue_wake;
	}
}

static int do_mutex_unlock(struct pthread_mutex_s *__restrict const mutex,
		const int __m_kind, const int __m_desc)
{
	int rval;
	struct task_struct *const task = current;
	struct mutex_desc *const m_desc = mutex_once(task, mutex, __m_desc,
			__m_kind);

	if (unlikely(IS_ERR(m_desc)))
		return PTR_ERR(m_desc);

restart:
	raw_spin_lock_irq(&m_desc->lock);
	if (!check_desc(m_desc, MUTEX, mutex))
		rval = __do_mutex_unlock(mutex, task, m_desc);
	else
		rval = -EINVAL;
	raw_spin_unlock_irq(&m_desc->lock);

	if (unlikely(rval == -EFAULT)) {
		if (!handle_fault((unsigned long) &mutex->__m_lock))
			goto restart;
	} else if (unlikely(rval == -ENOTRECOVERABLE)) {
		robust_mutex_wake_all(mutex, m_desc);
		rval = 0;
	}

	return rval;
}

int do_cancel(pid_t tgid, pid_t *p, int signal)
{
	pid_t pid;

	if (unlikely(get_user(pid, p) || pid <= 0))
		return -ESRCH;
	DbgPos("do_cancel: cancelling thread %d\n", pid);
	if (unlikely(sys_tgkill(tgid, pid, signal)))
		return -ESRCH;
	return 0;
}

/*
 * do_cond_lock() and do_cond_unlock() are used by
 * do_cond_timedwait() to do the user-side of mutex locking and
 * unlocking here in kernel so that we do not need to switch to userspace
 * just to call pthread_mutex_lock() or pthread_mutex_unlock() from there
 */

//TODO 3.14 support SCHED_DEADLINE
/* Returns zero on success */
static int cond_fast_lock(struct pthread_mutex_s *const mutex,
		const char protocol, const int __m_lock)
{
	int rval, oldval;

	switch (protocol) {
	case PTHREAD_PRIO_NONE:
		if (unlikely(__m_lock)) {
			rval = 1;
		} else {
#if defined ARCH_HAS_ATOMIC_CMPXCHG
			rval = el_atomic_cmpxchg_acq(oldval,
					&mutex->__m_lock, 0, 1);
#else
			rval = el_atomic_xchg_acq(oldval,
						&mutex->__m_lock, 1);
#endif
			if (likely(!rval))
				rval = (oldval != 0);
		}
		break;
#if defined ARCH_HAS_ATOMIC_CMPXCHG
	case PTHREAD_PRIO_INHERIT:
	case PTHREAD_PRIO_PROTECT:
		if (unlikely(__m_lock)) {
			rval = 1;
		} else {
			rval = el_atomic_cmpxchg_acq(oldval,
					&mutex->__m_lock, 0, current->pid);
			if (likely(!rval))
				rval = (oldval != 0);
		}
		break;
#endif
	default:
		rval = 1;
		break;
	}

	return rval;
}

#ifdef CONFIG_SMP
/* Returns zero if @mutex is locked. */
static int mutex_is_free(struct pthread_mutex_s *const mutex,
		const char protocol)
{
	int rval, __m_lock;

	switch (protocol) {
	case PTHREAD_PRIO_NONE:
#if defined ARCH_HAS_ATOMIC_CMPXCHG
	case PTHREAD_PRIO_INHERIT:
	case PTHREAD_PRIO_PROTECT:
#endif
		if (unlikely(__get_user(__m_lock,
				(volatile int *) &mutex->__m_lock)))
			rval = 1;
		else
			rval = unlikely(__m_lock == 0);
		break;
	default:
		rval = 0;
		break;
	}
	return rval;
}
#endif

/* Context switch cost for threads in processor cycles (must account for
 * context switch time, system call time and cache invalidation). */
#ifdef CONFIG_SMP

/* Assumed thread context switch cost (in cycles). */
# define ASSUMED_SWITCH_COST 5000

static unsigned int __read_mostly context_switch_cost = ASSUMED_SWITCH_COST;

#else
static unsigned int __read_mostly context_switch_cost;
#endif

/* Maximum delay between reads when spinning in processor cycles. */
#define MAXIMUM_SPIN_DELAY 50
static int do_cond_lock(
		struct pthread_mutex_s *__restrict const mutex,
		struct mutex_desc *const m_desc, const int ptr_64)
{
	int rval, __m_lock, __m_owner;
#ifdef CONFIG_SMP
	struct task_struct *task;
	int pid, cycles, __m_spins = 0;
# ifdef ARCH_HAS_GET_CYCLES
	int contended = 0;
	cycles_t start, waited = 0;
# else
	unsigned int waited = 0;
# endif
#endif

	if (unlikely(__get_user(__m_lock, &mutex->__m_lock)))
		return -EFAULT;
	DbgPos("cond_lock: mutex=%p started lock=%d\n", mutex, __m_lock);

	switch (__builtin_expect(m_desc->type, PTHREAD_MUTEX_TIMED_NP)) {
	case PTHREAD_MUTEX_ADAPTIVE_NP:
#ifdef CONFIG_SMP
		rval = cond_fast_lock(mutex, m_desc->protocol, __m_lock);
		if (likely(!rval)) {
			return __put_user((unsigned int) get_cycles(),
						&mutex->__m_count)
					| __put_user(current->pid,
						&mutex->__m_owner);
		}

		if (unlikely(rval == -EFAULT))
			break;

		waited = 0;

		if (__m_lock == -1) {
			/* The mutex has waiters and we definitely will not
			 * get it soon. */
# ifdef ARCH_HAS_GET_CYCLES
			/* We do not want to adjust spinning time for this
			 * lock - the mutex is contended, so in any case
			 * spinning here does not make any sense (without
			 * pipelining, that is).
			 * Pipelining is when a new waiter can steal the mutex
			 * from all the waiters that are already in the queue -
			 * a complete unfairness. This library is intended for
			 * real-time applications, so pipelining is avoided at
			 * all costs (only on architectures without cmpxchg it
			 * is used for PTHREAD_PRIO_NONE mutexes). */
			contended = 1;
# endif
			break;
		} else {
# ifdef ARCH_HAS_GET_CYCLES
			contended = 0;
# endif
		}

		if (unlikely(__get_user(__m_spins,
				&mutex->__m_spins - ptr_64))) {
			rval = -EFAULT;
			break;
		}

# ifdef ARCH_HAS_GET_CYCLES
		/* Note: for the '!mutex->__m_spins' check to work,
		 * context_switch_cost must not be adjusted at run-time
		 * as __m_spins is changed only by multiples of
		 * (context_switch_cost >> 4) (otherwise after a change
		 * it might never be 0 again). */
# endif
		if (unlikely(!__m_spins))
			break;

		/* __m_spins is passed from user so we cannot trust it */
		if (unlikely(__m_spins > context_switch_cost))
			__m_spins = context_switch_cost;

# ifdef ARCH_HAS_GET_CYCLES
		start = get_cycles();
# endif

		/* Check that the owner is running now. */
		if (unlikely(__get_user(pid, &mutex->__m_owner))) {
			rval = -EFAULT;
			break;
		}
		if (unlikely(!pid))
			break;

		rcu_read_lock();
		task = __find_task_by_pid_check(pid);
		if (unlikely(!task || !task_curr(task))) {
# if DEBUG_POSIX
			if (!task)
				DbgPos("el_posix: owner of adaptive mutex %p"
						" not found.\n", mutex);
# endif
			rcu_read_unlock();
			break;
		}
		get_task_struct(task);
		rcu_read_unlock();

		cycles = 12; /* Just some small value. */
# ifdef ARCH_HAS_GET_CYCLES
		/* Wait until the mutex is freed. */
		do {
			__delay(cycles);
			if (cycles < MAXIMUM_SPIN_DELAY)
				cycles *= 2;

			waited = get_cycles() - start;

			/* Try to take the mutex.
			 *
			 * We do not check for -EFAULT now because we
			 * already checked, and anyway if there is some
			 * problem then the user is seriously screwed
			 * and a little spinning won't do any harm. */
			if (mutex_is_free(mutex, m_desc->protocol)
					&& !__get_user(__m_lock,
						&mutex->__m_lock)
					&& !cond_fast_lock(mutex,
						m_desc->protocol, __m_lock)) {
				/* We successfully acquired the mutex. */
				cycles_t delta;

				put_task_struct(task);

adjust_adaptive_spin_strategy:
				delta = context_switch_cost >> 4;
				if (waited > context_switch_cost) {
					/* We were waiting for a long time,
					 * looks like blocking is better than
					 * spinning. */
					if (__m_spins >= delta) {
						__m_spins -= delta;
						__put_user(__m_spins,
							     &mutex->__m_spins -
									ptr_64);
					}
				} else {
					/* We were waiting for a short time,
					 * looks like spinning is better than
					 * blocking. */
					if (__m_spins < context_switch_cost) {
						__m_spins += delta;
						__put_user(__m_spins,
							     &mutex->__m_spins -
									ptr_64);
					}
				}

skip_adjust_adaptive_spin_strategy:
				return __put_user((unsigned int) get_cycles(),
							&mutex->__m_count)
						| __put_user(current->pid,
							&mutex->__m_owner);
			}
		} while (task_curr(task) && ((get_cycles() - start + cycles) <
				(cycles_t) __m_spins));
# else
		/* Wait until the mutex is freed for __m_spins
		 * processor cycles. */
		waited = 0;
		do {
			__delay(cycles);
			waited += cycles + 100;
			if (cycles < MAXIMUM_SPIN_DELAY)
				cycles *= 2;

			/* Try to take the mutex. */
			if (mutex_is_free(mutex, m_desc->protocol)
					&& !__get_user(__m_lock,
						&mutex->__m_lock)
					&& !cond_fast_lock(mutex,
						m_desc->protocol, __m_lock)) {
				/* We successfully acquired the mutex. */
				put_task_struct(task);
				return __put_user(current->pid,
						&mutex->__m_owner);
			}
		} while (waited + cycles < __m_spins);
# endif
		put_task_struct(task);
		break;
#endif
	case PTHREAD_MUTEX_TIMED_NP:
		rval = cond_fast_lock(mutex, m_desc->protocol, __m_lock);
		if (likely(rval == 0))
			return 0;
		break;
	case PTHREAD_MUTEX_RECURSIVE_NP:
		if (unlikely(__get_user(__m_owner, &mutex->__m_owner)))
			return -EFAULT;
		if (__m_owner == current->pid) {
			int __m_count;

			if (unlikely(__get_user(__m_count, &mutex->__m_count)))
				return -EFAULT;
			if (unlikely(__m_count + 1 == 0))
				/* Overflow of the counter */
				return -EAGAIN;
			return __put_user(__m_count + 1, &mutex->__m_count);
		}
	/* FALLTHROUGH */
	case PTHREAD_MUTEX_ERRORCHECK_NP:
		rval = cond_fast_lock(mutex, m_desc->protocol, __m_lock);
		if (likely(rval == 0))
			return __put_user(current->pid, &mutex->__m_owner);
		break;
	default:
		return -EINVAL;
	}

	if (likely(rval != -EFAULT)) {
		rval = __do_mutex_timedlock(mutex, NULL, current, m_desc);
		if (likely(rval == 0)) {
#if defined CONFIG_SMP && defined ARCH_HAS_GET_CYCLES
			if (unlikely(m_desc->type ==
					PTHREAD_MUTEX_ADAPTIVE_NP)) {
				/* We successfully acquired the mutex. */
				cycles_t crit_section_length;
				unsigned int __m_count;

# ifdef ARCH_HAS_ATOMIC_CMPXCHG
				if (unlikely(contended || __get_user(__m_count,
						&mutex->__m_count)))
# else
				if (unlikely(contended
						|| m_desc->protocol !=
							PTHREAD_PRIO_NONE
						|| __get_user(__m_count,
							&mutex->__m_count)))
# endif
					goto skip_adjust_adaptive_spin_strategy;

				crit_section_length = (cycles_t) __m_count;

				/* Estimate the time between the last 'lock'
				 * and 'unlock' operations. 'waited' stands
				 * for how much we were busy waiting, and
				 * '(crit_section_length - waited) / 2' stands
				 * for how much more we probably should have
				 * busy waited before the owner would unlock
				 * the mutex. */
				if (crit_section_length > waited)
					waited += (crit_section_length - waited) / 2;

				goto adjust_adaptive_spin_strategy;
			}
#endif
			rval = __put_user(current->pid, &mutex->__m_owner);
		}
	}

#if DEBUG_POSIX
	__get_user(__m_lock, &mutex->__m_lock);
#endif
	DbgPos("cond_lock mutex=%p: ended __m_lock=%d rval=%d\n",
			mutex, __m_lock, rval);
	return rval;
}

/* Returns zero on success, -EFAULT if the page is not available
 * and any other number on failure */
static int cond_fast_unlock(struct pthread_mutex_s *const mutex,
		const char protocol, const int __m_lock)
{
	int rval, oldval;

#if defined ARCH_HAS_ATOMIC_CMPXCHG
	int pid;

	switch (protocol) {
	case PTHREAD_PRIO_NONE:
		if (unlikely(__m_lock != 1)) {
			rval = 1;
		} else {
			rval = el_atomic_cmpxchg_rel(oldval,
					&mutex->__m_lock, 1, 0);
			if (likely(!rval))
				rval = (oldval != 1);
		}
		break;
	case PTHREAD_PRIO_INHERIT:
	case PTHREAD_PRIO_PROTECT:
		pid = current->pid;
		if (unlikely(__m_lock != pid)) {
			rval = 1;
		} else {
			rval = el_atomic_cmpxchg_rel(oldval,
					&mutex->__m_lock, pid, 0);
			if (likely(!rval))
				rval = (oldval != pid);
		}
		break;
	default:
		rval = 1;
		break;
	}
#else
	if (unlikely(protocol == PTHREAD_PRIO_NONE)) {
		rval = el_atomic_xchg_rel(oldval, &mutex->__m_lock, 0);
		if (likely(!rval))
			rval = (oldval != 1);
	} else {
		rval = 1;
	}
#endif
	return rval;
}

static int do_cond_unlock(
		struct task_struct *const task,
		struct pthread_mutex_s *__restrict const mutex,
		struct mutex_desc *const m_desc,
		unsigned long *fault_address, const int ptr_64)
{
	int rval, __m_owner, __m_lock;
#ifdef CONFIG_SMP
# ifdef ARCH_HAS_GET_CYCLES
	unsigned int __m_count;
# endif
#endif

	DbgPos("do_cond_unlock mutex=%p: start\n", mutex);

	if (unlikely(__get_user(__m_lock, &mutex->__m_lock))) {
		*fault_address = (unsigned long) &mutex->__m_lock;
		return -EFAULT;
	}

	switch (__builtin_expect(m_desc->type, PTHREAD_MUTEX_TIMED_NP)) {
	case PTHREAD_MUTEX_ADAPTIVE_NP:
#ifdef CONFIG_SMP
# ifdef ARCH_HAS_GET_CYCLES
		if (unlikely(__get_user(__m_count, &mutex->__m_count))) {
			*fault_address = (unsigned long) &mutex->__m_count;
			return -EFAULT;
		}
		__m_count = ((unsigned int) get_cycles()) - __m_count;

		if (unlikely(__put_user(__m_count, &mutex->__m_count))) {
			*fault_address = (unsigned long) &mutex->__m_count;
			return -EFAULT;
		}
# endif
		if (unlikely(__put_user(0, &mutex->__m_owner))) {
			*fault_address = (unsigned long) &mutex->__m_owner;
			return -EFAULT;
		}
#endif
	/* FALLTHROUGH */
	case PTHREAD_MUTEX_TIMED_NP:
simple:
		rval = cond_fast_unlock(mutex, m_desc->protocol, __m_lock);
		break;
	case PTHREAD_MUTEX_ERRORCHECK_NP:
		if (unlikely(__get_user(__m_owner, &mutex->__m_owner))) {
			*fault_address = (unsigned long) &mutex->__m_owner;
			return -EFAULT;
		}
		if (likely(__m_owner == current->pid)) {
			if (unlikely(__put_user(0, &mutex->__m_owner))) {
				*fault_address = (unsigned long)
						&mutex->__m_owner;
				return -EFAULT;
			}
			goto simple;
		} else {
			return -EPERM;
		}
		break;
	case PTHREAD_MUTEX_RECURSIVE_NP:
		if (unlikely(__get_user(__m_owner, &mutex->__m_owner))) {
			*fault_address = (unsigned long) &mutex->__m_owner;
			return -EFAULT;
		}
		if (likely(__m_owner == current->pid)) {
			int __m_count;

			if (unlikely(__get_user(__m_count, &mutex->__m_count))){
				*fault_address = (unsigned long)
						&mutex->__m_count;
				return -EFAULT;
			}
			if (__m_count) {
				/* Just decrease the counter */
				if (unlikely(__put_user(__m_count - 1,
						&mutex->__m_count))) {
					*fault_address = (unsigned long)
							&mutex->__m_count;
					return -EFAULT;
				}
				return 0;
			} else {
				if (unlikely(__put_user(0, &mutex->__m_owner))){
					*fault_address = (unsigned long)
							&mutex->__m_owner;
					return -EFAULT;
				}
				goto simple;
			}
		} else {
			return -EPERM;
		}
		break;
	default:
		return -EINVAL;
	}

	switch (__builtin_expect(rval, 0)) {
	case 0:
		break;
	case -EFAULT:
		*fault_address = (unsigned long) &mutex->__m_lock;
		break;
	default:
		raw_spin_lock(&m_desc->lock);
		if (!check_desc(m_desc, MUTEX, mutex))
			rval = __do_mutex_unlock(mutex, task, m_desc);
		else
			rval = -EINVAL;
		raw_spin_unlock(&m_desc->lock);
		if (unlikely(rval == -EFAULT))
			*fault_address = (unsigned long) &mutex->__m_lock;
		break;
	}

	DbgPos("do_cond_unlock mutex=%p: rval=%d\n", mutex, rval);
	return rval;
}

static __always_inline int queue_on_condition(
		struct task_struct *const task,
		struct el_waiter *const waiter,
		struct cond_desc *const c_desc,
		struct pthread_cond_s *const cond,
		struct mutex_desc *const m_desc,
		struct pthread_mutex_s *const mutex,
		const int ptr_64)
{
	struct mutex_desc *prev_m_desc;
	struct pthread_mutex_s *prev_mutex;
	int prio, rval = 0;
	unsigned long fault_address = 0;
	char m_kind;

restart:
	raw_spin_lock_irq(&c_desc->lock);

	prev_m_desc = c_desc->m_desc;
	if (unlikely(__get_user(prev_mutex, &cond->__c_mutex))) {
		fault_address = (unsigned long) &cond->__c_mutex;
		goto out_error_unlock;
	}

	if (check_desc(c_desc, CONDITION, cond)) {
		rval = -EINVAL;
		goto out_error_unlock;
	}

	/* After fork() cond->__c_mutex may be left in bad state.
	 * That's why we use c_desc->m_desc here instead. */
	if (prev_m_desc) {
		if (unlikely((void *) ((unsigned long) prev_m_desc & ~1UL)
				!= m_desc)) {
			DbgPos("queue_on_condition: different mutex descriptors"
				" (%p != %p)\n", c_desc->m_desc, m_desc);
			rval = -EINVAL;
			goto out_error_unlock;
		}
	} else {
		/* For shared mutexes the value stored in __c_mutex cannot
		 * be used because it must be process-local, but since we
		 * have mutex type (private or process shared) stored in its
		 * descriptor, we just will not use __c_mutex field in that
		 * case. */

		if (unlikely(__put_user(mutex, &cond->__c_mutex))) {
			fault_address = (unsigned long) &cond->__c_mutex;
			goto out_error_unlock;
		}
		c_desc->m_desc = m_desc;
	}

	/* Unlock the mutex */
	m_kind = m_desc->type;
	rval = do_cond_unlock(task, mutex, m_desc, &fault_address, ptr_64);
	if (unlikely(rval) && rval != -ENOTRECOVERABLE) {
		__put_user(prev_mutex, &cond->__c_mutex);
		c_desc->m_desc = prev_m_desc;
		goto out_error_unlock;
	}

	/* Check for multiple times locked recursive mutex */
	if (unlikely(m_kind == PTHREAD_MUTEX_RECURSIVE_NP)) {
		int tmp;

		if (unlikely(__get_user(tmp, &mutex->__m_owner))) {
			fault_address = (unsigned long) &mutex->__m_owner;
			goto out_error_unlock;
		}
		if (unlikely(tmp == task->pid)) {
			/* We add the mutex owner (i.e. this thread) to
			 * the top of condition variable's waitqueue. */
			c_desc->m_desc = (void *) ((unsigned long)
					c_desc->m_desc | 1UL);
			prio = -1;
			goto prio_is_set;
		}
	}

	/*
	 * This thread is added to wait queue either with
	 * its own priority if it is a real-time thread or
	 * with MAX_RT_PRIO if it is non-RT thread. This
	 * way RT threads get woken up in priority order
	 * and non-RT threads get woken up in FIFO order.
	 */
	prio = min(task->prio, MAX_RT_PRIO);
prio_is_set:

	/* Initialize the waitqueue */
	plist_node_init(&waiter->list_entry, prio);
	plist_add(&waiter->list_entry, &c_desc->wait_list);
	waiter->task = task;
	waiter->timedout = 0;
	waiter->state = WAITING_ON_CONDITION;

	/* Since we are going to call schedule() right away,
	 * there is no need to check preemption. */
	raw_spin_unlock_irq_no_resched(&c_desc->lock);

	return rval;

out_error_unlock:
	raw_spin_unlock_irq(&c_desc->lock);
	if (unlikely(fault_address)) {
		if (!handle_fault(fault_address)) {
			fault_address = 0;
			goto restart;
		}
		rval = -EFAULT;
	}

	return rval;
}

static __always_inline int unqueue_from_condition(
		struct el_waiter *const waiter,
		struct pthread_cond_s *const cond,
		struct cond_desc *const c_desc)
{
restart:
	raw_spin_lock_irq(&c_desc->lock);
	if (unlikely(waiter->state != WAITING_ON_CONDITION)) {
		raw_spin_unlock_irq(&c_desc->lock);
		return 1;
	}
	/* This check works even if this waiter was moved to a temporary list
	 * by signal or broadcast (node_list.next points to node_list
	 * if list is empty). */
	if (c_desc->wait_list.node_list.next->next
			== &c_desc->wait_list.node_list) {
		/* Since there are no more threads waiting on this
		 * condition, disassociate the mutex from it */
		if (unlikely(__put_user(NULL, &cond->__c_mutex))) {
			raw_spin_unlock_irq(&c_desc->lock);
			if (!handle_fault((unsigned long) &cond->__c_mutex))
				goto restart;
			raw_spin_lock_irq(&c_desc->lock);
		}
		c_desc->m_desc = NULL;
	}
	plist_del(&waiter->list_entry, &c_desc->wait_list);
	waiter->state = NOT_WAITING;
	raw_spin_unlock_irq(&c_desc->lock);

	return 0;
}

static int do_cond_timedwait(
		struct pthread_cond_s *const cond,
		struct pthread_mutex_s *const mutex,
		const struct timespec_64 *const abstime, const int ptr_64)
{
	int rval, __c_value = 0;
	struct task_struct *const task = current;
	const int __m_kind = ({
		int tmp;
		if (unlikely(((unsigned int) ptr_64) > 1))
			return -EINVAL;
		if (unlikely(__get_user(tmp, &mutex->__m_kind + ptr_64)))
			return -EFAULT;
		tmp;
	});
	const int __c_desc = ({
		int tmp;
		if (unlikely(__get_user(tmp, &cond->__c_desc)))
			return -EFAULT;
		tmp;
	});
	const int __m_desc = ({
		int tmp;
		if (unlikely(__get_user(tmp, &mutex->__m_desc)))
			return -EFAULT;
		tmp;
	});
	struct cond_desc *const c_desc = cond_once(task, cond, __c_desc);
	struct mutex_desc *const m_desc = mutex_once(task, mutex, __m_desc,
			__m_kind);
	struct el_waiter waiter;
	struct timespec_64 iabstime;

	DbgPos("cond_timedwait cond=%p mutex=%p: start\n", cond, mutex);

	if (unlikely(IS_ERR(c_desc)))
		return PTR_ERR(c_desc);
	if (unlikely(IS_ERR(m_desc)))
		return PTR_ERR(m_desc);

	if (unlikely(abstime)) {
		if (unlikely(copy_from_user(&iabstime, abstime,
				sizeof(iabstime))))
			return -EFAULT;
		if (unlikely(iabstime.tv_nsec < 0
				|| iabstime.tv_nsec >= 1000000000)) {
			DbgPos("%d cond_timedwait cond=%p mutex=%p: bad nsec "
					"timeout (%lld)\n", task->pid, cond,
					mutex, iabstime.tv_nsec);
			return -EINVAL;
		}
		if (unlikely(__get_user(__c_value, &cond->__c_value)))
			return -EFAULT;
	}

	rval = queue_on_condition(task, &waiter, c_desc,
				  cond, m_desc, mutex, ptr_64);
	if (unlikely(rval)) {
		if (rval != -ENOTRECOVERABLE)
			return rval;

		robust_mutex_wake_all(mutex, m_desc);
	}

	DbgPos("cond_timedwait cond=%p mutex=%p: before schedule()\n",
			cond, mutex);
	set_task_state(task, TASK_INTERRUPTIBLE);
	if (likely(waiter.state == WAITING_ON_CONDITION)) {
		if (likely(!abstime)) {
			schedule();
		} else {
			clockid_t clock_id;

			clock_id = (__c_value & PTHREAD_CONDATTR_CLOCK_ID_MASK)
					>> PTHREAD_CONDATTR_CLOCK_ID_SHIFT;
			if (clock_id != CLOCK_REALTIME
					&& clock_id != CLOCK_MONOTONIC)
				clock_id = CLOCK_REALTIME;

			waiter.timedout = schedule_with_timeout(task,
					clock_id, &iabstime);
		}
	} else {
		preempt_check_resched();
	}
	__set_task_state(task, TASK_RUNNING);
	DbgPos("cond_timedwait cond=%p mutex=%p, state=%d: after schedule()\n",
			cond, mutex, waiter.state);

retry:
	switch (__builtin_expect(waiter.state, WAITING_ON_MUTEX)) {
	case WAITING_ON_MUTEX:
		/* We are standing in mutex's waitqueue.
		 * Try to acquire it. */
try_taking_mutex_again:
		raw_spin_lock_irq(&m_desc->lock);
		if (unlikely(m_desc->protocol == PTHREAD_PRIO_PROTECT
				&& ((int) m_desc->prioceiling)
					> normal_prio(task))) {
			DbgPos("cond_timedwait cond=%p mutex=%p: thread "
					"priority is bigger than mutex "
					"prioceiling.\n", cond, mutex);
			rval = give_up_on_mutex(mutex, m_desc, &waiter);
			if (likely(!rval))
				rval = -EINVAL;
			break;
		}
		if (try_to_take_mutex(task, mutex, m_desc, &waiter) == 0) {
			/* Success. */
			raw_spin_unlock_irq(&m_desc->lock);
			rval = __put_user(task->pid, &mutex->__m_owner);
			if (unlikely(rval))
				break;

			/* Check robust attribute. */
			if (unlikely(m_desc->robust > ROBUST)) {
				/* Since we were able to lock the mutex, it
				 * should not be in NOT_RECOVERABLE state. */
				WARN_ON(m_desc->robust == NOT_RECOVERABLE);
				rval = -EOWNERDEAD;
			} else if (unlikely(waiter.timedout) && !rval) {
				rval = -ETIMEDOUT;
			}
		} else {
			/* We were signaled or the mutex was stealed. */
			if (!signal_pending(task) && likely(
					m_desc->robust != NOT_RECOVERABLE)) {
				raw_spin_unlock_irq_no_resched(&m_desc->lock);
				set_task_state(task, TASK_INTERRUPTIBLE);
				if (likely(m_desc->pending_owner != task
						&& m_desc->robust
							!= NOT_RECOVERABLE))
					schedule();
				else
					preempt_check_resched();
				__set_task_state(task, TASK_RUNNING);
				goto try_taking_mutex_again;
			}

			DbgPos("%d cond_timedwait cond=%p mutex=%p: "
					"signal_pending() = %d, "
					"pending.signal = %lx : %lx\n",
					task->pid, cond, mutex,
					signal_pending(task),
					task->pending.signal.sig[0],
					task->pending.signal.sig[1]);
			rval = give_up_on_mutex(mutex, m_desc, &waiter);
			if (unlikely(m_desc->robust == NOT_RECOVERABLE))
				rval = -ENOTRECOVERABLE;
			else if (likely(!rval))
				rval = -EINTR;
		}
		break;
	case WAITING_ON_CONDITION:
		/* We were not woken by cond_signal or cond_broadcast,
		 * i.e. we timed out or caught a signal. */
		if (unlikely(unqueue_from_condition(&waiter, cond, c_desc)))
			/* Condition was signaled in the small window
			 * after wakeup. */
			goto retry;

		if (unlikely(!signal_pending(task)))
			/* We timed out or the signal was handled
			 * by another thread */
			goto retry;

		rval = -EINTR;
		break;
	case NOT_WAITING:
		/* We were not moved to the mutex waitqueue.
		 * Acquire the mutex by ourselves, but first wait to make
		 * sure that there will be no wake up signals sent after
		 * we leave kernel. */
		raw_spin_unlock_wait(&c_desc->lock);
		rval = do_cond_lock(mutex, m_desc, ptr_64);
		if (rval == 0 && unlikely(waiter.timedout))
				rval = -ETIMEDOUT;
		break;
	default:
		WARN_ON(1);
		rval = -EINVAL;
		break;
	}

	DbgPos("cond_timedwait cond=%p mutex=%p: end rval=%d\n",
			cond, mutex, rval);
	return rval;
}


static __always_inline void queue_on_barrier(struct task_struct *const task,
		struct el_barrier_waiter *const waiter,
		struct barr_desc *const b_desc)
{
	++b_desc->present;

	/*
	 * This thread is added to wait queue either with
	 * its own priority if it is a real-time thread or
	 * with MAX_RT_PRIO if it is non-RT thread. This
	 * way RT threads get woken up in priority order
	 * and non-RT threads get woken up in FIFO order.
	 */
	plist_node_init(&waiter->list_entry, min(task->prio, MAX_RT_PRIO));
	plist_add(&waiter->list_entry, &b_desc->wait_list);
	waiter->task = task;
	waiter->b_desc = b_desc;
	waiter->state = WAITING_ON_BARRIER;
}

/* Wake all from queue in the descriptor @b_desc. Maximum possible number
 * of waiters is @list_size while actual number can be less.
 * Must be called with the spinlock held. */
static void wake_barrier_waiters(struct task_struct *const task,
		const unsigned int list_size, struct barr_desc *const b_desc)
{
	struct el_waiter *waiter;
	struct plist_node pi_list_entry = PLIST_NODE_INIT(pi_list_entry,
			MAX_PRIO-1);

	if (list_size <= WAKE_AT_MOST) {
		DbgPos("waking waiters: list not detached, waking %d threads\n",
				list_size);
		plist_for_each_entry(waiter, &b_desc->wait_list, list_entry) {
			waiter->state = NOT_WAITING;
			wake_up_state(waiter->task, TASK_INTERRUPTIBLE);
		}
		plist_head_init(&b_desc->wait_list);
	} else {
		int i;
		struct plist_head to_move_list;
		struct el_waiter *next;

		/* Do not disable interrupts for a long periods of time.
		 * Detach the list of waiting threads from the barrier
		 * so that we can drop the spinlock from time to time.*/
		if (unlikely(plist_head_empty(&b_desc->wait_list))) {
			raw_spin_unlock_irq(&b_desc->lock);
			return;
		}
		to_move_list = b_desc->wait_list;
		to_move_list.node_list.next->prev = &to_move_list.node_list;
		to_move_list.node_list.prev->next = &to_move_list.node_list;
		plist_head_init(&b_desc->wait_list);

		i = WAKE_AT_MOST >> 1;
continue_wake:
		plist_for_each_entry_safe(waiter, next, &to_move_list,
				list_entry) {
			plist_del(&waiter->list_entry, &to_move_list);
			waiter->state = NOT_WAITING;
			wake_up_state(waiter->task, TASK_INTERRUPTIBLE);
			if (unlikely(++i >= WAKE_AT_MOST
					&& !plist_head_empty(&to_move_list))) {
				boost_priority(next->list_entry.prio,
						&pi_list_entry);
				raw_spin_unlock_irq(&b_desc->lock);
				cpu_relax();
				raw_spin_lock_irq(&b_desc->lock);
				i = 0;
				goto continue_wake;
			}
		}
	}

	raw_spin_unlock_irq(&b_desc->lock);

	/* Restore normal priority if we detached the waiters list. */
	if (list_size > WAKE_AT_MOST)
		restore_priority(&pi_list_entry);
}

static int do_barrier_wait(struct pthread_barrier_s *const barr,
		const unsigned int required, const int restarted,
		const int __b_desc)
{
	struct task_struct *const task = current;
	struct el_barrier_waiter *waiter;
	struct barr_desc *const b_desc = barr_once(task, barr, __b_desc);

	DbgPos("pbarrier_wait: started for barr %p, descr=%p\n", barr, b_desc);
	if (unlikely(IS_ERR(b_desc)))
		return PTR_ERR(b_desc);

	if (unlikely(restarted)) {
		waiter = &task->el_posix.barr_waiter;
		goto again;
	}

	raw_spin_lock_irq(&b_desc->lock);
	if (check_desc(b_desc, BARRIER, barr)) {
		raw_spin_unlock_irq(&b_desc->lock);
		return -EINVAL;
	}

	if (unlikely((b_desc->present + 1) == required)
			&& likely(!restarted)) {
		/* Wake everyone */
		b_desc->present = 0;

		DbgPos("pbarrier_wait: barr %p, I am the waker\n", barr);
		wake_barrier_waiters(task, required, b_desc);

		/* One thread must return PTHREAD_BARRIER_SERIAL_THREAD */
		return 1;
	} else {
		/* Queue ourselves */
		waiter = &task->el_posix.barr_waiter;
		queue_on_barrier(task, waiter, b_desc);
		/* Since we are going to call schedule() right away,
		 * there is no need to check preemption. */
		raw_spin_unlock_irq_no_resched(&b_desc->lock);

again:
		DbgPos("pbarrier_wait: barr %p, before schedule\n", barr);
		set_task_state(task, TASK_INTERRUPTIBLE);
		if (likely(waiter->state == WAITING_ON_BARRIER))
			schedule();
		else
			preempt_check_resched();
		__set_task_state(task, TASK_RUNNING);
		DbgPos("pbarrier_wait: barr %p, after schedule\n", barr);

		if (unlikely(waiter->state == WAITING_ON_BARRIER)) {
			/* Signal caught */
			if (unlikely(!signal_pending(task)))
				goto again;

			if (!restarted)
				return -EINTR;
			else
				return -ERESTARTNOINTR;
		}
		return 0;
	}
}


struct el_sem_waiter {
	int state;
	struct plist_node list_entry;
	struct task_struct *task;
};

#if !defined ARCH_HAS_ATOMIC_CMPXCHG

static int do_sem_getvalue(struct posix_sem_s *__restrict const sem,
		const int __s_desc)
{
	struct sem_desc *s_desc = sem_once(current, sem, __s_desc);
	int rval;

	if (unlikely(IS_ERR(s_desc)))
		return PTR_ERR(s_desc);

	raw_spin_lock_irq(&s_desc->lock);
	if (check_desc(s_desc, SEMAPHORE, sem))
		rval = -EINVAL;
	else
		rval = s_desc->value;
	raw_spin_unlock_irq(&s_desc->lock);

	return rval;
}

static int do_sem_post(struct posix_sem_s *__restrict const sem,
		const int __s_desc)
{
	struct sem_desc *s_desc = sem_once(current, sem, __s_desc);

	DbgPos("sem_post: sem %p - started\n", sem);
	if (unlikely(IS_ERR(s_desc)))
		return PTR_ERR(s_desc);

	raw_spin_lock_irq(&s_desc->lock);
	if (check_desc(s_desc, SEMAPHORE, sem)) {
		raw_spin_unlock_irq(&s_desc->lock);
		return -EINVAL;
	}

	if (unlikely(s_desc->value == INT_MAX)) {
		raw_spin_unlock_irq(&s_desc->lock);
		return -EOVERFLOW;
	}

	++s_desc->value;

	if (!plist_head_empty(&s_desc->wait_list)) {
		struct el_sem_waiter *this;
		int i;

		/* Wake the waiters. */
		i = 0;
		plist_for_each_entry(this, &s_desc->wait_list, list_entry) {
			this->state = NOT_WAITING;
			wake_up_state(this->task, TASK_INTERRUPTIBLE);

			++i;
			if (i >= WAKE_AT_MOST || i == s_desc->value)
				break;
		}
	}

	raw_spin_unlock_irq(&s_desc->lock);

	return 0;
}

static __always_inline void queue_on_semaphore(
		struct task_struct *const task,
		struct el_sem_waiter *const waiter,
		struct posix_sem_s *const sem,
		struct sem_desc *const s_desc)
{
	/*
	 * This thread is added to wait queue either with
	 * its own priority if it is a real-time thread or
	 * with MAX_RT_PRIO if it is non-RT thread. This
	 * way RT threads get woken up in priority order
	 * and non-RT threads get woken up in FIFO order.
	 */
	waiter->task = task;
	waiter->state = WAITING_ON_SEMAPHORE;
	plist_node_init(&waiter->list_entry, min(task->prio, MAX_RT_PRIO));
	plist_add(&waiter->list_entry, &s_desc->wait_list);
}

static int do_sem_timedwait(struct posix_sem_s *__restrict const sem,
		struct timespec_64 *__restrict const abstime,
		const int __s_desc, const int try)
{
	struct timespec_64 iabstime;
	struct task_struct *const task = current;
	struct sem_desc *s_desc = sem_once(task, sem, __s_desc);
	struct el_sem_waiter waiter;
	int rval, timedout;

	DbgPos("sem_wait: sem %p - started\n", sem);
	if (unlikely(IS_ERR(s_desc)))
		return PTR_ERR(s_desc);

	if (unlikely(abstime)) {
		if (unlikely(copy_from_user(&iabstime, abstime,
				sizeof(iabstime))))
			return -EFAULT;
		if (unlikely(iabstime.tv_nsec < 0
				|| iabstime.tv_nsec >= 1000000000))
			return -EINVAL;
	}

	raw_spin_lock_irq(&s_desc->lock);
	if (check_desc(s_desc, SEMAPHORE, sem)) {
		rval = -EINVAL;
		goto out_unlock;
	}

	if (s_desc->value) {
		--s_desc->value;
		goto success_unlock;
	}

	if (unlikely(try)) {
		rval = -EAGAIN;
		goto out_unlock;
	}

	queue_on_semaphore(task, &waiter, sem, s_desc);

	raw_spin_unlock_irq_no_resched(&s_desc->lock);

sleep:
	DbgPos("sem_wait sem=%p: before schedule()\n", sem);
	set_current_state(TASK_INTERRUPTIBLE);
	timedout = 0;
	if (likely(waiter.state == WAITING_ON_SEMAPHORE)) {
		if (likely(!abstime))
			schedule();
		else
			timedout = schedule_with_timeout(task,
					CLOCK_REALTIME, &iabstime);
	} else {
		preempt_check_resched();
	}
	__set_task_state(task, TASK_RUNNING);
	DbgPos("sem_wait semaphore %p: after schedule\n", sem);

	raw_spin_lock_irq(&s_desc->lock);

	if (unlikely(waiter.state == WAITING_ON_SEMAPHORE)) {
		/* Task caught signal or timed out */
		if (unlikely(!signal_pending(task) && !timedout)) {
			raw_spin_unlock_irq_no_resched(&s_desc->lock);
			goto sleep;
		}

		if (timedout)
			rval = -ETIMEDOUT;
		else
			rval = -EINTR;

		plist_del(&waiter.list_entry, &s_desc->wait_list);

		goto out_unlock;
	}

	if (unlikely(!s_desc->value)) {
		/* Someone was faster. */
		waiter.state = WAITING_ON_SEMAPHORE;
		raw_spin_unlock_irq_no_resched(&s_desc->lock);
		goto sleep;
	}

	plist_del(&waiter.list_entry, &s_desc->wait_list);

	--s_desc->value;

success_unlock:
	raw_spin_unlock_irq(&s_desc->lock);

	return 0;

out_unlock:
	raw_spin_unlock_irq(&s_desc->lock);

	return rval;
}

#else

static int do_sem_post(struct posix_sem_s *__restrict const sem,
		const int __s_desc)
{
	struct task_struct *const task = current;
	struct sem_desc *s_desc = sem_once(task, sem, __s_desc);
	int __s_value;

	DbgPos("sem_post: sem %p - started\n", sem);
	if (unlikely(IS_ERR(s_desc)))
		return PTR_ERR(s_desc);

	if (unlikely(__get_user(__s_value, &sem->__s_value)))
		return -EINVAL;

	/* We can safely read s_desc->waiters_nr here even if the descriptor
	 * is bad since the only effect would be immediate return. */
	if (unlikely(!__s_value || !s_desc->waiters_nr))
		/* Somebody else has done sem_wait() while we were
		 * entering the kernel or there are no waiters. */
		return 0;

restart:
	raw_spin_lock_irq(&s_desc->lock);
	if (check_desc(s_desc, SEMAPHORE, sem)) {
		raw_spin_unlock_irq(&s_desc->lock);
		return -EINVAL;
	}

	if (s_desc->waiters_nr) {
		struct el_sem_waiter *this;
		int i;

		/* Find how many waiters we will wake. */
		i = 0;
		plist_for_each_entry(this, &s_desc->wait_list, list_entry) {
			++i;
			if (i >= WAKE_AT_MOST)
				break;
		}
		if (i > __s_value)
			i = __s_value;

		/* Store the new waiters number in sem->__s_waiters. */
		if (unlikely(__put_user(s_desc->waiters_nr - i,
				&sem->__s_waiters))) {
			raw_spin_unlock_irq(&s_desc->lock);
			if (handle_fault((unsigned long) &sem->__s_waiters))
				return -EFAULT;
			goto restart;
		}

		/* Store the new waiters number in s_desc->waiters_nr. */
		s_desc->waiters_nr -= i;

		/* Wake the waiters. */
		for (; i > 0; i--) {
			this = plist_first_entry(&s_desc->wait_list,
					struct el_sem_waiter, list_entry);
			plist_del(&this->list_entry, &s_desc->wait_list);
			this->state = NOT_WAITING;
			wake_up_state(this->task, TASK_INTERRUPTIBLE);
		}
	}

	raw_spin_unlock_irq(&s_desc->lock);

	return 0;
}

static __always_inline int queue_on_semaphore(
		struct task_struct *const task,
		struct el_sem_waiter *const waiter,
		struct posix_sem_s *const sem,
		struct sem_desc *const s_desc)
{
restart:
	raw_spin_lock_irq(&s_desc->lock);
	if (check_desc(s_desc, SEMAPHORE, sem)) {
		raw_spin_unlock_irq(&s_desc->lock);
		return -EINVAL;
	}

	if (unlikely(__put_user(s_desc->waiters_nr + 1, &sem->__s_waiters))) {
		raw_spin_unlock_irq(&s_desc->lock);
		if (handle_fault((unsigned long) &sem->__s_waiters))
			return -EFAULT;
		goto restart;
	}

	++s_desc->waiters_nr;

	/*
	 * This thread is added to wait queue either with
	 * its own priority if it is a real-time thread or
	 * with MAX_RT_PRIO if it is non-RT thread. This
	 * way RT threads get woken up in priority order
	 * and non-RT threads get woken up in FIFO order.
	 */
	waiter->task = task;
	waiter->state = WAITING_ON_SEMAPHORE;
	plist_node_init(&waiter->list_entry, min(task->prio, MAX_RT_PRIO));
	plist_add(&waiter->list_entry, &s_desc->wait_list);

	raw_spin_unlock_irq_no_resched(&s_desc->lock);

	return 0;
}

static int unqueue_from_semaphore(
		struct el_sem_waiter *const waiter,
		struct posix_sem_s *const sem,
		struct sem_desc *const s_desc)
{
restart:
	raw_spin_lock_irq(&s_desc->lock);
	if (unlikely(waiter->state != WAITING_ON_SEMAPHORE)) {
		raw_spin_unlock_irq(&s_desc->lock);
		return 1;
	}

	if (unlikely(__put_user(s_desc->waiters_nr - 1, &sem->__s_waiters))) {
		raw_spin_unlock_irq(&s_desc->lock);
		if (handle_fault((unsigned long) &sem->__s_waiters))
			return -EFAULT;
		goto restart;
	}

	--s_desc->waiters_nr;

	plist_del(&waiter->list_entry, &s_desc->wait_list);
	waiter->state = NOT_WAITING;
	raw_spin_unlock_irq(&s_desc->lock);

	return 0;
}

static int do_sem_timedwait(struct posix_sem_s *__restrict const sem,
		struct timespec_64 *__restrict const abstime,
		const int __s_desc)
{
	struct timespec_64 iabstime;
	struct task_struct *const task = current;
	struct sem_desc *s_desc = sem_once(task, sem, __s_desc);
	struct el_sem_waiter waiter;
	int rval, __s_value, timedout;

	DbgPos("sem_post: sem %p - started\n", sem);
	if (unlikely(IS_ERR(s_desc)))
		return PTR_ERR(s_desc);

	if (unlikely(abstime)) {
		if (unlikely(copy_from_user(&iabstime, abstime,
				sizeof(iabstime))))
			return -EFAULT;
		if (unlikely(iabstime.tv_nsec < 0
				|| iabstime.tv_nsec >= 1000000000))
			return -EINVAL;
	}

	rval = queue_on_semaphore(task, &waiter, sem, s_desc);
	if (unlikely(rval))
		return rval;

	/* Order is important here: first we set __s_waiters field in
	 * queue_on_semaphore(), and only after that we read __s_value field. */
	smp_mb();
	if (unlikely(__get_user(__s_value, &sem->__s_value))) {
		if (unlikely(__get_user(__s_value, &sem->__s_value)))
			return -EFAULT;
	}

sleep:
	DbgPos("sem_wait sem=%p: before schedule()\n", sem);
	set_current_state(TASK_INTERRUPTIBLE);
	timedout = 0;
	if (likely(!__s_value && waiter.state == WAITING_ON_SEMAPHORE)) {
		if (likely(!abstime))
			schedule();
		else
			timedout = schedule_with_timeout(task,
					CLOCK_REALTIME, &iabstime);
	} else {
		preempt_check_resched();
	}
	__set_task_state(task, TASK_RUNNING);
	DbgPos("sem_wait semaphore %p: after schedule\n", sem);

	if (unlikely(waiter.state == WAITING_ON_SEMAPHORE)) {
		/* __s_value was not 0, task caught signal or timed out */
		if (unlikely(!__s_value && !signal_pending(task)
				&& !timedout)) {
			if (likely(!__get_user(__s_value, &sem->__s_value)))
				goto sleep;

			if (unqueue_from_semaphore(&waiter, sem, s_desc) == 1)
				goto success;

			rval = -EFAULT;
		} else {
			rval = unqueue_from_semaphore(&waiter, sem, s_desc);

			if (unlikely(__s_value > 0 || rval == 1))
				goto success;

			if (likely(!rval)) {
				if (timedout)
					rval = -ETIMEDOUT;
				else
					rval = -EINTR;
			}
		}

		return rval;
	}

success:
	return 0;
}

#endif


#ifdef CONFIG_SMP
struct thread_data {
	struct completion done;
	unsigned long long start_time;
	unsigned long long end_time;
	long khz;
	unsigned int iterations;
};

/* Placing semaphore on stack defeats lockdep mechanism so make it global. */
struct semaphore cs_sem __initdata = __SEMAPHORE_INITIALIZER(cs_sem, 0);

static int __init cs_thread(void *data)
{
	struct thread_data *td = (struct thread_data *) data;
	int i;

	down(&cs_sem);
	td->start_time = sched_clock();
	up(&cs_sem);

	for (i = 0; (kthread_should_stop() == 0)
			&& ((i < (td->khz >> 7)) || i < 10); i++)
		yield();

	td->end_time = sched_clock();
	td->iterations = i;
	complete(&td->done);

	/* Wait for termination */
	set_current_state(TASK_INTERRUPTIBLE);
	while (kthread_should_stop() == 0) {
		schedule();
		set_current_state(TASK_INTERRUPTIBLE);
	}
	__set_current_state(TASK_RUNNING);

	return 0;
}

static int __init
elpthread_init(void)
{
	struct sched_param param;
	struct task_struct *th1, *th2;
	struct thread_data thread1_data, thread2_data;
	unsigned long long start_time, end_time;
	unsigned int switch_cost, iterations;
	long khz;
	int rval;

	init_rwsem(&shared.lock);

	khz = sys_el_posix(EL_GET_CPU_KHZ, 0, 0, 0, 0);
	if (khz <= 0)
		return 0;

	thread1_data.iterations = 0;
	thread1_data.khz = khz;
	thread1_data.done = COMPLETION_INITIALIZER_ONSTACK(thread1_data.done);
	thread2_data.iterations = 0;
	thread2_data.khz = khz;
	thread2_data.done = COMPLETION_INITIALIZER_ONSTACK(thread2_data.done);

	th1 = kthread_create(&cs_thread, &thread1_data, "cs_thread1");
	if (IS_ERR(th1))
		goto failed;

	th2 = kthread_create(&cs_thread, &thread2_data, "cs_thread2");
	if (IS_ERR(th2))
		goto failed_cleanup_thread;

	kthread_bind(th1, 0);
	kthread_bind(th2, 0);

	param.sched_priority = MAX_RT_PRIO - 1;
	if ((rval = sched_setscheduler_nocheck(th1, SCHED_FIFO, &param))
			|| (rval = sched_setscheduler_nocheck(th2, SCHED_FIFO,
					&param)))
		goto failed_cleanup_threads;

	printk(KERN_INFO "Measuring thread context switch cost...\n");

	wake_up_process(th1);
	wake_up_process(th2);

	up(&cs_sem);

	wait_for_completion(&thread1_data.done);
	kthread_stop(th1);
	wait_for_completion(&thread2_data.done);
	kthread_stop(th2);

	iterations = thread1_data.iterations + thread2_data.iterations;
	if (iterations == 0)
		goto failed;

	start_time = (thread1_data.start_time > thread2_data.start_time)
			? thread1_data.start_time : thread2_data.start_time;
	end_time = (thread1_data.end_time < thread2_data.end_time)
			? thread1_data.end_time : thread2_data.end_time;

	/* Use 3x multiplier to account for cache invalidation,
	 * system call cost and time spent in the library. */
	switch_cost = 3 * (((unsigned int) (end_time - start_time)) /
			iterations);

	printk(KERN_INFO "%d iterations in %lld nanoseconds\n",
			iterations, end_time - start_time);

	/* Convert to processor cycles. */
	switch_cost = (switch_cost * ((unsigned int) (khz >> 10))) >> 10;

	if (switch_cost > (4 * ASSUMED_SWITCH_COST))
		/* Looks like there was some other high-priority thread
		 * interfering with this computation. */
		goto failed;

	printk(KERN_INFO "Thread context switch cost is %d cycles "
			"(CPU at %ld kHz).\n", switch_cost, khz);

	context_switch_cost = switch_cost;

	return 0;

failed_cleanup_threads:
	kthread_stop(th2);
	up(&cs_sem);
	wait_for_completion(&thread2_data.done);
failed_cleanup_thread:
	kthread_stop(th1);
	up(&cs_sem);
	wait_for_completion(&thread1_data.done);
failed:
	printk(KERN_INFO "Measuring thread context switch cost failed\n");
	return 0;
}
late_initcall(elpthread_init);
#endif


/**
 * do_main_init() - the first and only initialization function
 * 	a process must call before anything else.
 * @cs_cost: context switch cost measured by kernel is written at this
 * 	address and isused to implement adaptive spinning.
 * @kernel_flags: a set of flags indicating some ABI peculiarities of
 * 	the kernel el_posix implementation is passed to the library here.
 */
static int do_main_init(unsigned int *cs_cost, unsigned int *kernel_flags)
{
	int new_flags;

	DbgPos("pthread_main_init\n");

	if (cs_cost && __put_user(context_switch_cost, cs_cost))
		return -EFAULT;

	if (!kernel_flags) {
		if (printk_ratelimit())
			pr_info("elpthread library is too old, "
					"please update\n");
		return -ENOSYS;
	}

	/*
	 * Bits in 'kernel_flags':
	 * 0x1 - 'kernel_flags' parameter is supported (always set to 1)
	 * 0x2 - kernel uses atomic cmpxchg instruction
	 * 0x4 - updated PTHREAD_PRIO_PROTECT implementation which supports
	 * 	fast unlocking.
	 * 0x8 - use -1 instead of 2 in mutex->__m_lock for PTHREAD_PRIO_NONE
	 * 	mutexes to mark fast unlocking impossible (only has meaning for
	 * 	!ARCH_HAS_ATOMIC_CMPXCHG architectures because only in them
	 * 	library actually uses this value).
	 */
	new_flags = 0x1 | 0x4;
#if defined ARCH_HAS_ATOMIC_CMPXCHG
	new_flags |= 0x2;
#else
	new_flags |= 0x8;
#endif
	if (__put_user(new_flags, kernel_flags))
		return -EFAULT;

	return 0;
}

void el_posix_lock(unsigned long clone_flags)
{
	if (!(clone_flags & (CLONE_VM | CLONE_VFORK))
			&& current->mm
			&& current->mm->el_posix.others)
		/* This task uses el_posix and is forking. */
		down_read(&current->mm->el_posix.lock);
}

void el_posix_unlock(unsigned long clone_flags)
{
	if (!(clone_flags & (CLONE_VM | CLONE_VFORK))
			&& current->mm
			&& current->mm->el_posix.others)
		/* This task uses el_posix and is forking. */
		up_read(&current->mm->el_posix.lock);
}

void el_posix_init(struct task_struct *task)
{
	INIT_LIST_HEAD(&task->el_posix.pi_mutex_list);
	plist_head_init(&task->el_posix.pp_mutex_list);
	plist_node_init(&task->el_posix.pi_list_entry, MAX_PRIO-1);
	plist_head_init(&task->el_posix.pi_waiters);
	task->el_posix.barr_waiter.state = NOT_WAITING;
	task->el_posix.pi_blocked_on = NULL;
}

static void copy_block(s8 *from, s8 *to, int sz, enum types type)
{
	int i;

	*((struct zero_cell *) to) = *((struct zero_cell *) from);
	for (i = 1; i < DESCS_NUMBER; i++) {
		struct common_desc *from_desc =
				(struct common_desc *) (from + i * sz);
		struct common_desc *to_desc =
				(struct common_desc *) (to + i * sz);

		to_desc->next_free = from_desc->next_free;
		if (type != MUTEX) {
			to_desc->desc_type = from_desc->desc_type;
		} else {
			((struct mutex_desc *) to_desc)->protocol =
				((struct mutex_desc *) from_desc)->protocol;
			((struct mutex_desc *) to_desc)->type =
				((struct mutex_desc *) from_desc)->type;
		}
		raw_spin_lock_init(&to_desc->lock);
		plist_head_init(&to_desc->wait_list);
	}
}

/* Copies private descriptors when forking */
static int copy_blocks(struct allocated_descs_common *old,
		struct allocated_descs_common **to, const enum types type)
{
	int i, j, sz;
	struct allocated_descs_common *new;

	if (!old)
		return 0;

	switch (type) {
	case MUTEX:
		new = kzalloc(sizeof(struct allocated_private_mutex_descs),
				GFP_USER);
		if (!new)
			goto bad;
		new->blocks[1] = &((struct allocated_private_mutex_descs *)
				new)->first_block;
		break;
	case OTHER:
		new = kzalloc(sizeof(struct allocated_private_other_descs),
				GFP_USER);
		if (!new)
			goto bad;
		new->blocks[1] = &((struct allocated_private_other_descs *)
				new)->first_block;
		break;
	default:
		goto bad;
	}

	new = kzalloc(sizeof(struct allocated_private_other_descs), GFP_USER);
	if (!new)
		goto bad;
	new->blocks[1] = &((struct allocated_private_other_descs *)
			new)->first_block;

	sz = get_sz(1, type);

	new->free_block = old->free_block;
	new->used_blocks = old->used_blocks;
	copy_block(old->blocks[1], new->blocks[1], sz, type);
	for (i = 2; i < BLOCKS_NUMBER && old->blocks[i]; i++) {
		new->blocks[i] = kzalloc(DESCS_NUMBER * sz, GFP_USER);
		if (!new->blocks[i])
			goto bad_cleanup;
		copy_block(old->blocks[i], new->blocks[i], sz, type);
	}
	*to = new;
	return 0;

bad_cleanup:
	for (j = 2; j < i; j++)
		kfree(new->blocks[j]);
	kfree(new);
bad:
	return -ENOMEM;
}

static void free_blocks(struct allocated_descs_common *all_blocks)
{
	int i;

	if (!all_blocks)
		return;

	for (i = 2; i < BLOCKS_NUMBER && all_blocks->blocks[i]; i++)
		kfree(all_blocks->blocks[i]);
	kfree(all_blocks);
}

/* Called when forking */
int dup_mm_el_posix(struct mm_struct *oldmm, struct mm_struct *mm,
		    unsigned long clone_flags)
{
	int rval, copied_descs_num;

	if (clone_flags & CLONE_VFORK) {
		/* The new task will not use these. */
		mm->el_posix.mutexes = NULL;
		mm->el_posix.others = NULL;
		return 0;
	}

	if (oldmm->el_posix.mutexes) {
		struct allocated_private_mutex_descs *mutexes;

		mutexes = kzalloc(sizeof(*mutexes), GFP_USER);
		if (!mutexes) {
			rval = -ENOMEM;
			goto bad;
		}
		mutexes->free_block = 1;
		mutexes->used_blocks = 1;
		mutexes->blocks[1] = &mutexes->first_block;
		block_init((s8 *) &mutexes->first_block, get_sz(1, MUTEX), 1);
		mm->el_posix.mutexes = mutexes;
	}

	rval = copy_blocks((struct allocated_descs_common *)
			oldmm->el_posix.others,
			(struct allocated_descs_common **)
			&mm->el_posix.others,
			OTHER);
	if (rval)
		goto bad_cleanup_mutexes;

	copied_descs_num = 0;
	if (mm->el_posix.mutexes)
		copied_descs_num += mm->el_posix.mutexes->used_blocks
				* DESCS_NUMBER;
	if (mm->el_posix.others)
		copied_descs_num += mm->el_posix.others->used_blocks
				* DESCS_NUMBER;

	if (oldmm->el_posix.user) {
		rval = add_descriptors_count(1, copied_descs_num,
				oldmm->el_posix.user);
		if (rval)
			goto bad_cleanup_others;
		mm->el_posix.user = get_uid(oldmm->el_posix.user);
	}

	return 0;

bad_cleanup_others:
	free_blocks((struct allocated_descs_common *) mm->el_posix.others);
	mm->el_posix.others = NULL;
bad_cleanup_mutexes:
	free_blocks((struct allocated_descs_common *) mm->el_posix.mutexes);
	mm->el_posix.mutexes = NULL;
bad:
	return rval;
}

/* Called from __mmdrop(). */
void el_posix_mm_destroy(struct mm_struct *mm)
{
	int freed_descs_number;

	if (!list_empty(&mm->el_posix.shared_objects)) {
		unsigned long flags;

		raw_spin_lock_irqsave(&freed_shared_descs_lock, flags);
		list_splice_init(&mm->el_posix.shared_objects,
				&freed_shared_descs);
		raw_spin_unlock_irqrestore(&freed_shared_descs_lock, flags);
	}

	freed_descs_number = 0;

	if (mm->el_posix.mutexes) {
		freed_descs_number += mm->el_posix.mutexes->used_blocks
				* DESCS_NUMBER;
		free_blocks((struct allocated_descs_common *)
				mm->el_posix.mutexes);
		mm->el_posix.mutexes = NULL;
	}

	if (mm->el_posix.others) {
		freed_descs_number += mm->el_posix.others->used_blocks
				* DESCS_NUMBER;
		free_blocks((struct allocated_descs_common *)
				mm->el_posix.others);
		mm->el_posix.others = NULL;
	}

	if (mm->el_posix.user) {
		sub_descriptors_count(1, freed_descs_number, mm->el_posix.user);
		free_uid(mm->el_posix.user);
		mm->el_posix.user = NULL;
	}
}


/* Called when task is dying and unlocking all the mutexes it owns. */
static void remove_mutex_desc(struct mutex_desc *const m_desc,
		struct task_struct *const task, const int protocol)
{
	unsigned long flags;
#if defined ARCH_HAS_ATOMIC_CMPXCHG
	struct pthread_mutex_s *mutex;
#endif

	/* We can do this check without any locks because
	 * we own the mutex so it cannot be freed. */

	WARN_ON((int) m_desc->protocol != protocol);

#if defined ARCH_HAS_ATOMIC_CMPXCHG
again:
#endif
	raw_spin_lock_irqsave(&m_desc->lock, flags);
	if (desc_in_use(m_desc) == 0
			|| desc_check_type((void *) m_desc, MUTEX)) {
		/* This should not happen because descriptors
		 * queued in mutex_list cannot be freed. */
		WARN_ON_ONCE(1);
		if (m_desc->protocol == PTHREAD_PRIO_INHERIT) {
			list_del(&m_desc->mutex_list_entry.pi);
		} else if (m_desc->protocol == PTHREAD_PRIO_PROTECT) {
			plist_del(&m_desc->mutex_list_entry.pp,
					&current->el_posix.pp_mutex_list);
			if (plist_head_empty(&current->el_posix.pp_mutex_list)
					&& !plist_node_empty(
					      &current->el_posix.pi_list_entry))
				plist_del(&current->el_posix.pi_list_entry,
						&current->el_posix.pi_waiters);
		}
		goto out_unlock;
	}

	DbgPos("exit_el_posix: found mutex with descriptor at %p, robust=%d\n",
			m_desc, (int) m_desc->robust);

	/*
	 * If mutex is robust and does not have any waiters then
	 * we write an invalid pid into mutex->__m_lock.
	 *
	 * If mutex is robust and does have waiters we just make
	 * one of them the next owner.
	 */
#if defined ARCH_HAS_ATOMIC_CMPXCHG
	if ((m_desc->robust == ROBUST || m_desc->robust == OWNER_DEAD)
			&& !mutex_has_waiters(m_desc)) {
		int __m_lock;

		/* We have to write invalid pid into mutex->__m_lock field.
		 * For details see the explanation before enum robust_state. */

		/* Make sure that OWNER_DEAD mutexes
		 * always have an owner. */
		if (m_desc->robust == OWNER_DEAD)
			m_desc->robust = ROBUST;

		/* Write invalid pid into mutex->__m_lock */
		if (m_desc->private) {
			/* Private mutex */
			mutex = (struct pthread_mutex_s *)
					*desc_to_object(m_desc, MUTEX);

private_mapping:
			if (__get_user(__m_lock, &mutex->__m_lock))
				goto handle_fault;

			DbgPos("exit_el_posix: replacing %d with %ld in "
					"mutex->__m_lock for mutex %p\n",
					__m_lock, PID_MAX_LIMIT, mutex);

			if (__m_lock != -1) {
				DbgPos("exit_el_posix: bad __m_lock "
						"(mutex %p)\n", mutex);
				goto skip_fixing_robust_mutex;
			}

			if (__put_user(PID_MAX_LIMIT, &mutex->__m_lock))
				goto handle_fault;

		} else {
			/* Shared mutex */
			union key_shared *key = desc_to_key(m_desc, MUTEX);
			struct page *page;
			void *kaddr;
# ifdef CONFIG_HIGHMEM
			int page_mapped = 0;
# endif

			DbgPos("exit_el_posix: robust mutex (m_desc %p), "
					"shared key %p\n", m_desc, key);
			if (key->both.offset & 1) {
				/* Private mapping */
				mutex = (struct pthread_mutex_s *)
						key->private.address;
				goto private_mapping;
			}

			/* Shared mapping */

			page = find_get_page(key->shared.inode->i_mapping,
					key->shared.pgoff);

			if (!page) {
				DbgPos("exit_el_posix: zero page!\n");
				goto skip_fixing_robust_mutex;
			}

			kaddr = page_address(page);
			if (!kaddr) {
				DbgPos("exit_el_posix: page_address() "
						"returned 0 (high = %d)\n",
						PageHighMem(page));

# ifdef CONFIG_HIGHMEM
				if (!PageHighMem(page)) {
					/* Something strange is happening... */
					page_cache_release(page);
					goto skip_fixing_robust_mutex;
				}

				/* So this is a page from high memory, map it */
				kaddr = kmap_atomic(page);
				page_mapped = 1;
# else
				/* Something strange is happening... */
				page_cache_release(page);
				goto skip_fixing_robust_mutex;
# endif
			}

			mutex = (struct pthread_mutex_s *)
				       (kaddr + key->shared.offset);
			DbgPos("exit_el_posix: replacing %d with %ld in "
					"mutex->__m_lock for mutex with "
					"desc %p\n", mutex->__m_lock,
					PID_MAX_LIMIT, m_desc);

			if (mutex->__m_lock == -1)
				mutex->__m_lock = PID_MAX_LIMIT;
			else
				DbgPos("exit_el_posix: bad __m_lock "
						"(desc %p)\n", m_desc);

# ifdef CONFIG_HIGHMEM
			if (page_mapped)
				kunmap_atomic(kaddr);
# endif
			page_cache_release(page);
		}
	} else
#endif
	if (m_desc->robust == ROBUST) {
		/* For robust mutexes with waiters
		 * we change the state to OWNER_DEAD. */
		m_desc->robust = OWNER_DEAD;
	}

#if defined ARCH_HAS_ATOMIC_CMPXCHG
skip_fixing_robust_mutex:
#endif
	raw_spin_lock(&task->pi_lock);

	m_desc->owner = NULL;

	switch (m_desc->protocol) {
	case PTHREAD_PRIO_INHERIT:
		__task_unlocked_pi_mutex(task, m_desc);
		break;
	case PTHREAD_PRIO_PROTECT:
		__task_unlocked_pp_mutex(task, m_desc);
		break;
	default:
		/* Only PP and PI mutexes can have robust attribute
		 * set and be freed when owner dies. */
		WARN_ON(1);
		break;
	}
	raw_spin_unlock(&task->pi_lock);

	if (mutex_has_waiters(m_desc)) {
		struct el_waiter *waiter = plist_first_entry(&m_desc->wait_list,
				struct el_waiter, list_entry);

		m_desc->pending_owner = waiter->task;
		wake_up_state(waiter->task, TASK_INTERRUPTIBLE);
	}

out_unlock:
	raw_spin_unlock_irqrestore(&m_desc->lock, flags);

	return;

#ifdef ARCH_HAS_ATOMIC_CMPXCHG
handle_fault:
	raw_spin_unlock_irqrestore(&m_desc->lock, flags);
	if (handle_fault((unsigned long) &mutex->__m_lock)) {
		/* Since the underlying mapping has been destroyed
		 * there is no one to inform about roubst states
		 * anyway, so just skip it. */
		DbgPos("exit_el_posix: mutex at %p is unaccessible!\n", mutex);
		raw_spin_lock_irqsave(&m_desc->lock, flags);
		goto skip_fixing_robust_mutex;
	} else {
		goto again;
	}
#endif
}

void exit_el_posix(struct task_struct *task)
{
	struct mm_struct *mm = task->mm;

	if (!mm)
		return;

	if (mm->el_posix.others) {
		struct el_barrier_waiter *waiter = &task->el_posix.barr_waiter;

		if (unlikely(waiter->state == WAITING_ON_BARRIER)) {
			struct barr_desc *const b_desc = waiter->b_desc;

			/* b_desc is a valid address, because this function is
			 * called from the beginning of mm_release() when
			 * meomry descriptor is still valid. */
			raw_spin_lock_irq(&b_desc->lock);
			if (waiter->state == WAITING_ON_BARRIER) {
				/* There is no way for us to know whether
				 * the wait_list was detached from the
				 * barrier's descriptor, so we can not
				 * do --b_desc->present, but this is okay. */
				plist_del(&waiter->list_entry,
						&b_desc->wait_list);
				waiter->state = NOT_WAITING;
			}
			raw_spin_unlock_irq(&b_desc->lock);
		}
	}

	if (mm->el_posix.mutexes) {
		struct mutex_desc *m_desc, *next;

		WARN_ON(task->el_posix.pi_blocked_on);

		/* Set all robust mutexes owned by task to the OWNER_DEAD
		 * state. PTHREAD_PRIO_PROTECT and PTHREAD_PRIO_INHERIT
		 * mutexes are queued even if robust attribute is not set,
		 * this allows to handle walking priority chain with dead
		 * tasks and does not notably affect performance. */

		list_for_each_entry_safe(m_desc, next,
				&task->el_posix.pi_mutex_list,
				mutex_list_entry.pi) {
			remove_mutex_desc(m_desc, task, PTHREAD_PRIO_INHERIT);
		}

		plist_for_each_entry_safe(m_desc, next,
				&task->el_posix.pp_mutex_list,
				mutex_list_entry.pp) {
			remove_mutex_desc(m_desc, task, PTHREAD_PRIO_PROTECT);
		}
	}

	WARN_ON(!list_empty(&task->el_posix.pi_mutex_list));
	WARN_ON(!plist_head_empty(&task->el_posix.pp_mutex_list));
	WARN_ON(!plist_node_empty(&task->el_posix.pi_list_entry));
	WARN_ON(!plist_head_empty(&task->el_posix.pi_waiters));
}

static int do_mutex_set_ceiling(struct pthread_mutex_s *const mutex,
		const int __m_desc, const int __m_kind_new, const int ptr_64)
{
	struct task_struct *const task = current;
	unsigned long fault_address = 0;
	struct sched_param param;
	struct mutex_desc *m_desc;
	int __m_kind, rval, prioceiling, rval_unlock;

	if (unlikely(((unsigned int) ptr_64) > 1))
		return -EINVAL;

	if (unlikely(__get_user(__m_kind, &mutex->__m_kind + ptr_64)))
		return -EFAULT;

	DbgPos("do_mutex_set_ceiling started: mutex %p, __m_kind %x, "
			"new __m_kind %x\n", mutex, __m_kind, __m_kind_new);
	/*
	 * Check permissions
	 */

	m_desc = mutex_once(task, mutex, __m_desc, __m_kind);

	if (unlikely(IS_ERR(m_desc)))
		return PTR_ERR(m_desc);

	if (unlikely(m_desc->protocol != PTHREAD_PRIO_PROTECT)) {
		DbgPos("do_mutex_set_ceiling: mutex %p is not protected!\n",
				mutex);
		return -EINVAL;
	}

	prioceiling = (__m_kind_new & PTHREAD_MUTEXATTR_PRIO_CEILING_MASK)
			>> PTHREAD_MUTEXATTR_PRIO_CEILING_SHIFT;

	if (prioceiling < 1 || prioceiling > MAX_USER_RT_PRIO-1) {
		DbgPos("do_mutex_set_ceiling: mutex %p, bad prioceiling %d\n",
				mutex, prioceiling);
		return -EINVAL;
	}

	/* Allow unprivileged RT tasks to decrease priority. */
	if (!capable(CAP_SYS_NICE)) {
		unsigned long flags, rlim_rtprio;

		if (!lock_task_sighand(task, &flags))
			return -EPERM;
		rlim_rtprio = task->signal->rlim[RLIMIT_RTPRIO].rlim_cur;
		unlock_task_sighand(task, &flags);

		if ((SCHED_FIFO != task->policy && !rlim_rtprio)
				|| (prioceiling > task->rt_priority
				&& prioceiling > rlim_rtprio))
			return -EPERM;
	}

	if (task->policy == SCHED_IDLE)
		return -EPERM;

#ifdef CONFIG_RT_GROUP_SCHED
	if (!sched_task_has_rt_runtime(task))
		return -EPERM;
#endif

	param.sched_priority = prioceiling;
	rval = security_task_setscheduler(task);
	if (rval)
		return rval;

	/*
	 * Lock the mutex
	 */

	rval = do_cond_lock(mutex, m_desc, ptr_64);
	if (rval)
		return rval;

	/*
	 * Change priority ceiling
	 */

	if (m_desc->protocol == PTHREAD_PRIO_PROTECT) {
		/* We can safely set prioceiling without locking the spinlock
		 * because locked mutex cannot be freed. (Actually user can
		 * free it by writing 0 to mutex->__m_lock directly and then
		 * calling mutex_ destroy(), but he will never ever do that,
		 * and if he does, nothing too bad would happen). */
		m_desc->prioceiling = (unsigned char)
				(MAX_RT_PRIO-1 - prioceiling);
		rval = __put_user(__m_kind_new, &mutex->__m_kind + ptr_64);
	} else {
		rval = -EINVAL;
	}

	/*
	 * Unlock the mutex
	 */

restart_unlock:
	rval_unlock = do_cond_unlock(task, mutex, m_desc,
			&fault_address, ptr_64);
	DbgPos("do_mutex_set_ceiling: mutex %p, rval_unlock %d, rval %d\n",
			mutex, rval_unlock, rval);
	if (unlikely(rval_unlock == -EFAULT)) {
		if (!handle_fault(fault_address))
			goto restart_unlock;
	} else if (unlikely(rval_unlock == -ENOTRECOVERABLE)) {
		robust_mutex_wake_all(mutex, m_desc);
		rval_unlock = 0;
	}

	if (rval_unlock)
		rval = rval_unlock;

	return rval;
}

static int do_mutex_consistent(struct pthread_mutex_s *const mutex,
		const int __m_kind, const int __m_desc)
{
	struct task_struct *const task = current;
	struct mutex_desc *const m_desc = mutex_once(task, mutex, __m_desc,
			__m_kind);
	int rval;

	if (unlikely(IS_ERR(m_desc)))
		return PTR_ERR(m_desc);

	raw_spin_lock_irq(&m_desc->lock);
	if (check_desc(m_desc, MUTEX, mutex)) {
		rval = -EINVAL;
		goto out_unlock;
	}

	if (m_desc->robust == OWNER_DEAD) {
		m_desc->robust = ROBUST;
		rval = 0;
	} else {
		rval = -EINVAL;
	}

out_unlock:
	raw_spin_unlock_irq(&m_desc->lock);

	return rval;
}

static int do_set_unsafe_shared(pid_t pid, int *old_unsafe, int unsafe)
{
	struct task_struct *task;
	int rval;

#ifdef CONFIG_MCST_RT
	if (!capable(CAP_SYS_RESOURCE) && !rts_mode)
#else
	if (!capable(CAP_SYS_RESOURCE))
#endif
		return -EPERM;

	if ((unsigned int) unsafe > 1)
		return -EINVAL;

	if (!pid) {
		task = current;
	} else {
		rcu_read_lock();
		task = __find_task_by_pid_check(pid);
		if (task && task->mm)
			get_task_struct(task);
		rcu_read_unlock();
		if (!task || !task->mm)
			return -ESRCH;
	}

	if (old_unsafe) {
		if (put_user((int) task->mm->el_posix.unsafe_shared_objects,
				old_unsafe)) {
			rval = -EFAULT;
			goto out_put_task;
		}
		smp_mb();
	}

	task->mm->el_posix.unsafe_shared_objects = unsafe;

	rval = 0;

out_put_task:
	if (pid)
		put_task_struct(task);

	return rval;
}


#ifdef CONFIG_RT_TICK_THREAD
		/*   Tick thread stuff for campatibility ty 2.6.14   */



struct hrtimer	tick_hrt;
static int tick_skipped;
static int tick_tm;
static struct task_struct	*tick_hrt_waiter;
static struct task_struct	*tick_hrt_owner;
static int 	tick_hrt_owned;
static s32	tick_thr_sec;
static s32      tick_thr_nsec;
static ktime_t expected_tick;
static ktime_t prev_expected_tick;
static ktime_t real_tick;
static DEFINE_RAW_SPINLOCK(tick_lock);

static enum hrtimer_restart tick_hrt_callback(struct hrtimer *hrt)
{
	struct task_struct       *tsk = tick_hrt_owner;
	if (tsk == NULL) {
		return HRTIMER_NORESTART;
	}
	tick_skipped++;
	real_tick = hrtimer_cb_get_time(&tick_hrt);
        prev_expected_tick = expected_tick;
	if (tick_hrt_waiter) {
		tick_hrt_waiter = NULL;
		// tick_hrt_owner == tick_hrt_waiter
		wake_up_process(tsk);
	}
	tick_tm += hrtimer_forward(&tick_hrt, hrtimer_cb_get_time(&tick_hrt),
				ktime_set(tick_thr_sec, tick_thr_nsec));
        expected_tick = hrtimer_get_expires(&tick_hrt);
	return HRTIMER_RESTART;
}
                                        

static int tick_thread_start(s32 sec, s32 nsec)
{
	raw_spin_lock_irq(&tick_lock);
	if (tick_hrt_owned) {
		raw_spin_unlock_irq(&tick_lock);
		return -1;
	}
	tick_hrt_owned = 1;
	tick_hrt_owner = current;
	raw_spin_unlock_irq(&tick_lock);
        hrtimer_init(&tick_hrt, CLOCK_REALTIME, HRTIMER_MODE_REL);
	tick_hrt.function = tick_hrt_callback;
	tick_hrt.irqsafe = 1;
	tick_thr_sec = sec;
	tick_thr_nsec = nsec;
	tick_skipped = 0;
	tick_tm = 0;
	tick_hrt_waiter = current;
        set_current_state(TASK_INTERRUPTIBLE);
	hrtimer_start(&tick_hrt, ktime_set(sec, nsec), HRTIMER_MODE_REL);
	expected_tick = hrtimer_get_expires(&tick_hrt);
	schedule();
	return 0;
}
	
static int tick_thread_continue(u32 *skipped, u32 *tk)
{
	if (current != tick_hrt_owner) {
		return -1;
	}
	set_current_state(TASK_INTERRUPTIBLE);
	tick_hrt_waiter = current;
	schedule();
	*skipped = tick_tm;
	*tk = (u32)(ktime_to_ns(ktime_sub(real_tick, prev_expected_tick)));
	return 0;
}


int tick_thread_stop(void)
{
        if (current != tick_hrt_owner) {
                return -1;
        }
	tick_hrt_owner = NULL;
	hrtimer_cancel(&tick_hrt);
	tick_hrt_owned = 0;
	return 0;
}
#endif // CONFIG_RT_TICK_THREAD

#ifdef CONFIG_MCST_RT

static inline int el_ctx_lock_irq(struct el_timerfd_ctx *ctx)
{
again:
	raw_spin_lock_irq(&ctx->lock);
	if (ctx->locked) {
		raw_spin_unlock_irq(&ctx->lock);
		if (signal_pending(current))
			return -ERESTARTSYS;
		goto again;
	}
	return 0;
}

static inline void el_ctx_unlock_irq(struct el_timerfd_ctx *ctx)
{
	raw_spin_unlock_irq(&ctx->lock);
}

static int el_timerfd_release(struct inode *inode, struct file *file)
{
	struct el_timerfd_ctx *ctx = file->private_data;

	hrtimer_cancel(&ctx->tmr);
	kfree(ctx);
	return 0;
}

static inline int eltfd_populate_user_buf(char __user *buf, size_t count,
				u64 ticks, s64 wu_time, ktime_t cb_timeout,
				s64 intr_timeout, ktime_t expiried)
{
	int res = 0;
	s64 nsec;

	/* Number of missed ticks */
	if (copy_to_user(buf, &ticks, sizeof(s64)))
		return -EFAULT;
	res = sizeof(s64);

	/* Wake up time */
	if (count >=  2 * sizeof(s64)) {
		buf += sizeof(s64);
		if (copy_to_user(buf, &wu_time, sizeof(s64)))
			return -EFAULT;
		res += sizeof(s64);
	}
	
	/* Callback timeout */
	if (count >=  3 * sizeof(s64)) {
		buf += sizeof(s64);
		nsec = ktime_to_ns(cb_timeout);
		if (copy_to_user(buf, &nsec, sizeof(s64)))
			return -EFAULT;
		res += sizeof(s64);
	}

	/* Latency of hrtimer_interrupt start */
	if (count >=  4 * sizeof(s64)) {
		buf += sizeof(s64);
		nsec = intr_timeout;
		if (copy_to_user(buf, &nsec, sizeof(s64)))
			return -EFAULT;
		res += sizeof(s64);
	}

	/* Time of timer expiration */
	if (count >=  5 * sizeof(s64)) {
		buf += sizeof(s64);
		nsec = ktime_to_ns(expiried);
		if (copy_to_user(buf, &nsec, sizeof(s64)))
			return -EFAULT;
		res += sizeof(s64);
	}

	return res;
}

static ssize_t el_timerfd_read(struct file *file, char __user *buf, size_t count,
				loff_t *ppos)
{
	struct el_timerfd_ctx *ctx = file->private_data;
	struct el_wait_queue_head wait = { .task = current,
					   .wuc_time.tv64 = KTIME_MAX };
	s64 wu_time, intr_timeout;
	u64 ticks;
	ktime_t remaining;
	ktime_t cb_timeout;
	ktime_t expiried;
	int res;

	if (count < sizeof(s64))
		return -EINVAL;

	if (el_ctx_lock_irq(ctx))
		return -ERESTARTSYS;

	ticks = ctx->ticks;

	/* Have we missed at least a tick? */
	if (ctx->handled_ticks != ticks) {
		ctx->handled_ticks = ticks;
		cb_timeout   = ctx->cb_timeout;
		intr_timeout = ctx->tmr.intr_timeout;
		expiried     = ctx->expiried;
		ctx->tmr.intr_timeout = 0;
		el_ctx_unlock_irq(ctx);

		wu_time = 0;
		goto copy_to_user;
	}

	/* We have to wait next tick */
	list_add(&wait.task_list, &ctx->wqh.task_list);
	set_current_state(TASK_INTERRUPTIBLE);

	el_ctx_unlock_irq(ctx);

	while (1) {
		ktime_t now;

		schedule();

		now = ktime_get();

		if (el_ctx_lock_irq(ctx)) {
			res = -ERESTARTSYS;
			goto out;
		}

		/* Got we a new tick? */
		if (ticks != ctx->ticks) {
			ticks     = ctx->ticks;
			remaining = ktime_sub(now, wait.wuc_time);
			wu_time   = ktime_to_ns(remaining);
			cb_timeout   = ctx->cb_timeout;
			intr_timeout = ctx->tmr.intr_timeout;
			expiried     = ctx->expiried;
			ctx->handled_ticks = ticks;
			ctx->tmr.intr_timeout = 0;

			WARN_ON_ONCE(wait.wuc_time.tv64 == KTIME_MAX);

			res = 0;
			break;
		}
		set_current_state(TASK_INTERRUPTIBLE);
		el_ctx_unlock_irq(ctx);
	}
	list_del(&wait.task_list);
	__set_current_state(TASK_RUNNING);
	el_ctx_unlock_irq(ctx);

	if (wu_time < 0)
		return -EAGAIN; /* It's wrong, because the timer had to be expiried */
	else if (res < 0)
		return res;
copy_to_user:
	res = eltfd_populate_user_buf(buf, count, ticks, wu_time, cb_timeout,
				      intr_timeout, expiried);
out:
	return res;
}

static const struct file_operations el_timerfd_fops = {
	.release        = el_timerfd_release,
	.read           = el_timerfd_read,
};

static int el_open_timerfd(void)
{
	struct el_timerfd_ctx *ctx;
	int ufd;
	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	hrtimer_init(&ctx->tmr, CLOCK_REALTIME, HRTIMER_MODE_ABS);

	raw_spin_lock_init(&ctx->lock);
	INIT_LIST_HEAD(&ctx->wqh.task_list);

	ctx->locked = 0;
	ctx->ticks  = 0;
	ctx->handled_ticks = 0;

	ufd = anon_inode_getfd("[el_timerfd]", &el_timerfd_fops, ctx, O_RDWR);
	if (ufd < 0)
		kfree(ctx);
	
	return ufd;
}

static struct file *el_timerfd_fget(int fd)
{
	struct file *file;

	file = fget(fd);
	if (!file)
		return ERR_PTR(-EBADF);
	if (file->f_op != &el_timerfd_fops) {
		fput(file);
		return ERR_PTR(-EINVAL);
	}
	
	return file;
}

enum hrtimer_restart el_timerfd_tmrproc(struct hrtimer *htmr)
{
	struct el_timerfd_ctx *ctx = container_of(htmr, struct el_timerfd_ctx, tmr);
	struct el_wait_queue_head *wait;
	ktime_t now = ctx->run_time;

	BUG_ON(!irqs_disabled());

	raw_spin_lock(&ctx->lock);

	ctx->ticks++;

	ctx->expiried   = hrtimer_get_expires(htmr);
	ctx->cb_timeout = ktime_sub(now, ctx->expiried);

	list_for_each_entry(wait, &ctx->wqh.task_list, task_list) {
		if (wait->wuc_time.tv64 == KTIME_MAX) {
			wait->wuc_time = ktime_get();
			wake_up_state(wait->task, TASK_NORMAL);
		}
	}

	raw_spin_unlock(&ctx->lock);

	hrtimer_forward_now(htmr, ctx->tintv);

	return HRTIMER_RESTART;
}


static int do_el_timerfd_settime(int ufd, struct itimerspec *ktmr)
{
	struct file *file;
	struct el_timerfd_ctx *ctx;

	file = el_timerfd_fget(ufd);
	if (IS_ERR(file))
		return PTR_ERR(file);
	ctx = file->private_data;

	BUG_ON(irqs_disabled());

	for (;;) {
		raw_spin_lock_irq(&ctx->lock);
		if (ctx->locked) {
			raw_spin_unlock_irq(&ctx->lock);
			continue;
		}

		/* Prevent from parallel settime and read */
		ctx->locked = 1;
		raw_spin_unlock_irq(&ctx->lock);

		if (hrtimer_try_to_cancel(&ctx->tmr) >= 0)
			break;

		raw_spin_lock_irq(&ctx->lock);
		ctx->locked = 0;
		raw_spin_unlock_irq(&ctx->lock);
		cpu_relax();
	}

	raw_spin_lock_irq(&ctx->lock);

	ctx->tmr.function = el_timerfd_tmrproc;
	ctx->tmr.irqsafe  = 1;

	ctx->tintv = timespec_to_ktime(ktmr->it_interval);

	hrtimer_set_expires(&ctx->tmr, ctx->tintv);

	/* Return the first timer expiration time */
	ktmr->it_value = ktime_to_timespec(ctx->tmr.node.expires);

	ctx->tmr.intr_timeout = 0;

	raw_spin_unlock_irq(&ctx->lock);

	if (ctx->tintv.tv64 != 0)
		hrtimer_start(&ctx->tmr, ctx->tintv, HRTIMER_MODE_REL);
	
	raw_spin_lock_irq(&ctx->lock);
	ctx->locked = 0;
	raw_spin_unlock_irq(&ctx->lock);

	fput(file);

	return 0;
}

static int el_timerfd_settime(int ufd, struct itimerspec __user *tmr)
{
	struct itimerspec ktmr;
	int ret;

	if (copy_from_user(&ktmr, tmr, sizeof(ktmr)))
		return -EFAULT;
	
	ret = do_el_timerfd_settime(ufd, &ktmr);
	if (ret < 0)
		return ret;
	
	return copy_to_user(tmr, &ktmr, sizeof(ktmr));
}

#ifdef CONFIG_COMPAT
static int compat_el_timerfd_settime(int ufd, struct compat_itimerspec __user *tmr)
{
	struct compat_itimerspec c_ktmr;
	struct itimerspec ktmr;
	int ret;

	if (copy_from_user(&c_ktmr, tmr, sizeof(c_ktmr)))
		return -EFAULT;
	
	ktmr.it_interval.tv_sec = c_ktmr.it_interval.tv_sec;
	ktmr.it_interval.tv_nsec = c_ktmr.it_interval.tv_nsec;

	ktmr.it_value.tv_sec = c_ktmr.it_value.tv_sec;
	ktmr.it_value.tv_nsec = c_ktmr.it_value.tv_nsec;

	ret =  do_el_timerfd_settime(ufd, &ktmr);
	if (ret < 0)
		return ret;
	
	c_ktmr.it_interval.tv_sec = ktmr.it_interval.tv_sec;
	c_ktmr.it_interval.tv_nsec = ktmr.it_interval.tv_nsec;

	c_ktmr.it_value.tv_sec = ktmr.it_value.tv_sec;
	c_ktmr.it_value.tv_nsec = ktmr.it_value.tv_nsec;
	
	return copy_to_user(tmr, &c_ktmr, sizeof(c_ktmr));
}
#endif /* CONFIG_COMPAT */

#endif


 // int ____ilog2_NaN(void ) {return 0;}
