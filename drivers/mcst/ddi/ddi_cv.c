/*
 *
 * ddi_cv, Supported by Alexey V. Sitnikov, alexmipt@mcst.ru MCST
 *
 */

#include <linux/sched.h>
#include <linux/sem.h>
#include <linux/mcst/ddi.h>
#include <asm/unistd.h>
#include <asm/hardirq.h>

#define DEBUG 0
#define	dbgprn if (DEBUG) printk 

/***********************************!!!!!!!! FIXME !!!!!!!!!*************************************/
/* IN SOLARIS */
/*
*	cv_wait - returns void if reached condition
*
*	cv_wait_sig - returns 0 if signaled or > 0 if reached condition
*
*	cv_timedwait - returns -1 if timeouted or > 0 if reached condition
*
*	cv_timedwait_sig - returns 0 if signaled, -1 if timeouted or > 0 if reached condition
*/

/* IN LINUX */
/*
*	cv_wait - returns -1 if signaled, 0 if reached condition
*
*	cv_timedwait - returns -1 if timeouted or signaled (signal_pending checking needed),
*		       0 if reached condition	 
*/

/*
 * cond_wait and cond_broadcast, with using mutex
 */

int
ddi_cv_wait(kcondvar_t *cvp, kmutex_t *semp)
{
        struct task_struct *tsk = current;
        int rval = 0;
	DECLARE_RAW_WAIT_QUEUE(wait);

        dbgprn("cond_wait: start\n");
        tsk->state = TASK_INTERRUPTIBLE;
	raw_add_wait_queue(cvp, &wait);
	if(!in_interrupt())
	        mutex_exit(semp);
        schedule();
	raw_remove_wait_queue(cvp, &wait);
        tsk->state = TASK_RUNNING;
        if (signal_pending(current)) {
                rval = -1;
        }
	if(!in_interrupt())
	        mutex_enter(semp);
        return rval;
        
}

int
ddi_cv_broadcast(kcondvar_t *cvp)
{
        dbgprn("cond_broadcast: start\n");
	raw_wake_up(cvp);
        return 0;
}

int
ddi_cv_timedwait(kcondvar_t *cvp, kmutex_t *semp, long tim)
{
	long	expire;
        int            	 	rval = 0;
        struct task_struct 	*tsk = current;
	DECLARE_RAW_WAIT_QUEUE(wait);
        
        dbgprn("cond_timedwait: start\n");
        expire = tim - jiffies;
	dbgprn("cond_timedwait: before schedule_timeout, expire = 0x%lx\n", expire);
        tsk->state = TASK_INTERRUPTIBLE;
	raw_add_wait_queue(cvp, &wait);
	if(!in_interrupt())
 	       mutex_exit(semp);
	if (expire > 0)
		expire = schedule_timeout(expire);
	else
		expire = 0;
	dbgprn("cond_timedwait: after schedule_timeout, expire = 0x%lx\n", expire);
	raw_remove_wait_queue(cvp, &wait);
        tsk->state = TASK_RUNNING;
	if(!in_interrupt())
  	      mutex_enter(semp);
        if (expire) {
                if (signal_pending(current)) {
                        rval = -1;
                }
        } else {
                rval = -1;
        }
        return rval;
        
}

/*
 * cond_wait and cond_broadcast, with using spinlock, analog Solaris
 */

int
ddi_cv_spin_wait(kcondvar_t *cvp, raw_spinlock_t *lock)
{
        struct task_struct *tsk = current;
        int rval = 0;
	int spin_locking_done	= 0;
	DECLARE_RAW_WAIT_QUEUE(wait);

        dbgprn("cond_wait: start\n");
        tsk->state = TASK_INTERRUPTIBLE;
        raw_add_wait_queue(cvp, &wait);
	spin_locking_done = raw_spin_is_locked(lock);
	if (spin_locking_done)
	        spin_mutex_exit(lock);
	dbgprn("cond_wait: in_interrupt = %ld\n", in_interrupt());
        schedule();
	raw_remove_wait_queue(cvp, &wait);

        tsk->state = TASK_RUNNING;
        if (signal_pending(current)) {
                rval = -1;
        }
	if (spin_locking_done)
		spin_mutex_enter(lock);
        return rval;
        
}

int
ddi_cv_spin_timedwait(kcondvar_t *cvp, raw_spinlock_t *lock, long tim)
{
        unsigned long   	expire;
        int            	 	rval = 0;
	int 			spin_locking_done	= 0;
        struct task_struct 	*tsk = current;
	DECLARE_RAW_WAIT_QUEUE(wait);
        
        dbgprn("cond_timedwait: start\n");
        expire = tim - jiffies;
	dbgprn("cond_timedwait: before schedule_timeout, expire = 0x%lx\n", expire);
        tsk->state = TASK_INTERRUPTIBLE;
	raw_add_wait_queue(cvp, &wait);
	spin_locking_done = raw_spin_is_locked(lock);
	if(spin_locking_done)
 	       spin_mutex_exit(lock);

        dbgprn("cond_timedwait: in_interrupt = %ld\n", in_interrupt());
        expire = schedule_timeout(expire);
	dbgprn("cond_timedwait: after schedule_timeout, expire = 0x%lx\n", expire);
	raw_remove_wait_queue(cvp, &wait);
        tsk->state = TASK_RUNNING;
	if(spin_locking_done)
		spin_mutex_enter(lock);
        if (expire) {
                if (signal_pending(current)) {
                        rval = -2;
                }
        } else {
                rval = -1;
        }
        return rval;
        
}
