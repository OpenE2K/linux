#include <linux/mm.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <asm/process.h>


/* Does nothing, just return */
extern void sys_backtrace_return(void);

static int is_privileged_return(u64 ip)
{
	return ip == (u64) &sys_backtrace_return;
}

noinline
static long do_get_backtrace(void *__user buf, size_t count, size_t skip,
			  unsigned long flags, int step)
{
	e2k_pcsp_lo_t pcsp_lo;
	e2k_pcsp_hi_t pcsp_hi;
	e2k_cr0_hi_t cr0_hi;
	e2k_mem_crs_t *frame, *base;
	long ret = 0, nr_read;

	if (flags)
		return -EINVAL;

	if (!access_ok(VERIFY_WRITE, buf, count * step))
		return -EFAULT;

	raw_all_irq_save(flags);
	E2K_FLUSHC;
	pcsp_hi = READ_PCSP_HI_REG();
	pcsp_lo = READ_PCSP_LO_REG();
	raw_all_irq_restore(flags);

	frame = (e2k_mem_crs_t *) (AS(pcsp_lo).base + AS(pcsp_hi).ind);
	base = GET_PCS_BASE(current_thread_info());

	/* Skip kernel frames and the caller's frame */
	frame -= 2;

	nr_read = 0;
	while (nr_read < count) {
		u64 ip;

		--frame;
		if (frame < (e2k_mem_crs_t *) base)
			/* Not an error: we will just return the size */
			break;

		if (__get_user(AW(cr0_hi), &AW(frame->cr0_hi))) {
			ret = -EFAULT;
			break;
		}

		ip = AS(cr0_hi).ip << 3;

		/* Skip kernel frames */
		if (!is_privileged_return(ip) && ip >= TASK_SIZE)
			continue;

		/* Skip the requested number of frames */
		if (skip) {
			--skip;
			continue;
		}

		if (!is_privileged_return(ip) &&
		    !access_ok(VERIFY_READ, ip, 8)) {
			ret = -EFAULT;
			break;
		}

		/* Special case of "just return" function */
		if (is_privileged_return(ip))
			ip = -1ULL;

		if ((step == 8) ? __put_user(ip, (u64 *) buf) :
				  __put_user(ip, (u32 *) buf)) {
			ret = -EFAULT;
			break;
		}

		buf += step;
		++nr_read;
	}

	if (nr_read)
		ret = nr_read;

	return ret;
}

SYSCALL_DEFINE4(get_backtrace, unsigned long *__user, buf,
		size_t, count, size_t, skip, unsigned long, flags)
{
	return do_get_backtrace(buf, count, skip, flags, 8);
}

asmlinkage long compat_sys_get_backtrace(unsigned int *__user buf,
		size_t count, size_t skip, unsigned long flags)
{
	return do_get_backtrace(buf, count, skip, flags, 4);
}

noinline
static long do_set_backtrace(void *__user buf, size_t count, size_t skip,
		unsigned long flags, int step)
{
	e2k_pcsp_lo_t pcsp_lo;
	e2k_pcsp_hi_t pcsp_hi;
	e2k_cr0_hi_t cr0_hi;
	e2k_cr1_lo_t cr1_lo;
	e2k_mem_crs_t *frame, *base;
	struct vm_area_struct *pvma = NULL, *vma = NULL;
	struct mm_struct *mm = current->mm;
	long ret = 0, nr_written;

	if (flags)
		return -EINVAL;

	if (!access_ok(VERIFY_READ, buf, count * step))
		return -EFAULT;

	raw_all_irq_save(flags);
	E2K_FLUSHC;
	pcsp_hi = READ_PCSP_HI_REG();
	pcsp_lo = READ_PCSP_LO_REG();
	raw_all_irq_restore(flags);

	frame = (e2k_mem_crs_t *) (AS(pcsp_lo).base + AS(pcsp_hi).ind);
	base = GET_PCS_BASE(current_thread_info());

	/* Skip kernel frames and the caller's frame */
	frame -= 2;

	down_read(&mm->mmap_sem);

	nr_written = 0;
	while (nr_written < count) {
		u64 prev_ip, ip;
		int fault;

		--frame;
		if (frame < (e2k_mem_crs_t *) base)
			/* Not an error: we will just return the size */
			break;

		if (((step == 8) ? __get_user(ip, (u64 *) buf) :
				   __get_user(ip, (u32 *) buf)) ||
		    __get_user(AW(cr0_hi), &AW(frame->cr0_hi)) ||
		    __get_user(AW(cr1_lo), &AW(frame->cr1_lo))) {
			ret = -EFAULT;
			break;
		}

		/* Special case of "just return" function */
		if (step == 8 && ip == -1ULL ||
		    step != 8 && ip == 0xffffffffULL)
			ip = (u64) &sys_backtrace_return;

		prev_ip = AS(cr0_hi).ip << 3;

		/* Skip kernel frames */
		if (prev_ip >= TASK_SIZE)
			continue;

		/* Skip the requested number of frames */
		if (skip) {
			--skip;
			continue;
		}

		if (!is_privileged_return(ip) &&
		    !access_ok(VERIFY_READ, ip, 8)) {
			ret = -EFAULT;
			break;
		}

		if (!is_privileged_return(prev_ip) && (!pvma ||
					     pvma->vm_start > prev_ip ||
					     pvma->vm_end <= prev_ip)) {
			pvma = find_vma(mm, prev_ip);
			if (!pvma || prev_ip < pvma->vm_start) {
				ret = -ESRCH;
				break;
			}
		}
		if (!is_privileged_return(ip) && (!vma || vma->vm_start > ip ||
					vma->vm_end <= ip)) {
			if (ip >= pvma->vm_start && ip < pvma->vm_end) {
				vma = pvma;
			} else {
				vma = find_vma(mm, ip);
				if (!vma || ip < vma->vm_start) {
					ret = -ESRCH;
					break;
				}
			}
		}

		/* Forbid changing of special return value into normal
		 * one - to avoid cases when user changes to special and
		 * back to normal function to avoid security checks. */
		if (is_privileged_return(prev_ip) &&
		    !is_privileged_return(ip)) {
			ret = -EPERM;
			break;
		}

		/* Check that the permissions are the same - i.e. if
		 * the original was not writable, the new one is not
		 * writable too. */
		if (!is_privileged_return(ip) &&
		    (pvma->vm_flags & (VM_READ|VM_WRITE|VM_EXEC)) ^
		     (vma->vm_flags & (VM_READ|VM_WRITE|VM_EXEC))) {
			ret = -EPERM;
			break;
		}

		/* Check that the exception handling code
		 * resides in the same executable. */
		if (!is_privileged_return(ip) &&
		    pvma->vm_file != vma->vm_file) {
			ret = -EPERM;
			break;
		}

		if (is_privileged_return(ip)) {
			AS(cr1_lo).pm = 1;
			AS(cr1_lo).ic = 0;
		}
		AS(cr0_hi).ip = ip >> 3;

repeat_write:
		all_irq_disable();
		pagefault_disable();
		E2K_FLUSHCPU;
		E2K_FLUSH_WAIT;

		fault = __put_user(AW(cr0_hi), &AW(frame->cr0_hi));
		if (!fault && is_privileged_return(ip))
			fault = __put_user(AW(cr1_lo), &AW(frame->cr1_lo));

		pagefault_enable();
		all_irq_enable();

		if (fault) {
			if (__put_user(AW(cr0_hi), &AW(frame->cr0_hi))) {
				ret = -EFAULT;
				break;
			}
			goto repeat_write;
		}

		buf += step;
		++nr_written;
	}

	up_read(&mm->mmap_sem);

	if (nr_written)
		ret = nr_written;

	return ret;
}


SYSCALL_DEFINE4(set_backtrace, unsigned long *__user, buf,
		size_t, count, size_t, skip, unsigned long, flags)
{
	return do_set_backtrace(buf, count, skip, flags, 8);
}

asmlinkage long compat_sys_set_backtrace(unsigned int *__user buf,
		size_t count, size_t skip, unsigned long flags)
{
	return do_set_backtrace(buf, count, skip, flags, 4);
}

