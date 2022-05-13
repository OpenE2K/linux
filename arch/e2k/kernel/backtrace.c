#include <linux/mm.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <asm/e2k_debug.h>
#include <asm/process.h>

/* Does nothing, just return */
extern void sys_backtrace_return(void);

static int is_privileged_return(u64 ip)
{
	return ip == (u64) &sys_backtrace_return;
}

struct get_backtrace_args {
	int skip;
	int nr_read;
	int count;
	int step;
	void __user *buf;
};

static int get_backtrace_fn(e2k_mem_crs_t *frame, unsigned long real_frame_addr,
		unsigned long corrected_frame_addr, int flags, void *arg)
{
	struct get_backtrace_args *args = (struct get_backtrace_args *) arg;
	void __user *buf = args->buf;
	int step = args->step;
	u64 ip;

	if (args->nr_read >= args->count)
		return 1;

	ip = AS(frame->cr0_hi).ip << 3;

	/* Skip kernel frames */
	if (!is_privileged_return(ip) && ip >= TASK_SIZE)
		return 0;

	if (args->skip) {
		--(args->skip);
		return 0;
	}

	if (!is_privileged_return(ip) && !access_ok(ip, 8))
		return -EFAULT;

	/* Special case of "just return" function */
	if (is_privileged_return(ip))
		ip = -1ULL;

	if ((step == 8) ? __put_user(ip, (u64 *) buf) :
			  __put_user(ip, (u32 *) buf))
		return -EFAULT;

	args->buf += step;
	++(args->nr_read);

	return 0;
}

static long do_get_backtrace(void __user *buf, size_t count, size_t skip,
			  unsigned long flags, int step)
{
	long ret;
	struct get_backtrace_args args;

	args.buf = buf;
	args.step = step;
	args.count = count;
	args.nr_read = 0;
	args.skip = skip + 1; /* Skip caller's frame */

	if (flags)
		return -EINVAL;

	if (!access_ok(buf, count * step))
		return -EFAULT;

	ret = parse_chain_stack(PCS_USER, NULL, get_backtrace_fn, &args);

	if (args.nr_read)
		ret = args.nr_read;

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

struct set_backtrace_args {
	int skip;
	int nr_written;
	int count;
	int step;
	void __user *buf;
	struct vm_area_struct *vma;
	struct vm_area_struct *pvma;
};

static int set_backtrace_fn(e2k_mem_crs_t *frame, unsigned long real_frame_addr,
		unsigned long corrected_frame_addr, int flags, void *arg)
{
	struct set_backtrace_args *args = (struct set_backtrace_args *) arg;
	void __user *buf = args->buf;
	int step = args->step;
	struct vm_area_struct *vma = args->vma;
	struct vm_area_struct *pvma = args->pvma;
	u64 prev_ip, ip;
	e2k_cr0_hi_t cr0_hi;
	e2k_cr1_lo_t cr1_lo;
	int ret;

	if (args->nr_written >= args->count)
		return 1;

	prev_ip = AS(frame->cr0_hi).ip << 3;

	/* Skip kernel frames */
	if (!is_privileged_return(prev_ip) && prev_ip >= TASK_SIZE)
		return 0;

	if (args->skip) {
		--(args->skip);
		return 0;
	}

	if ((step == 8) ? __get_user(ip, (u64 *) buf) :
			  __get_user(ip, (u32 *) buf))
		return -EFAULT;

	/* Special case of "just return" function */
	if (step == 8 && ip == -1ULL || step != 8 && ip == 0xffffffffULL)
		ip = (u64) &sys_backtrace_return;

	if (!is_privileged_return(prev_ip) && (!pvma ||
			pvma->vm_start > prev_ip || pvma->vm_end <= prev_ip)) {
		pvma = find_vma(current->mm, prev_ip);
		if (!pvma || prev_ip < pvma->vm_start)
			return -ESRCH;
		args->pvma = pvma;
	}

	if (!is_privileged_return(ip)) {
		if (!access_ok(ip, 8))
			return -EFAULT;

		if (!vma || vma->vm_start > ip || vma->vm_end <= ip) {
			if (ip >= pvma->vm_start && ip < pvma->vm_end) {
				vma = pvma;
			} else {
				vma = find_vma(current->mm, ip);
				if (!vma || ip < vma->vm_start)
					return -ESRCH;
			}
			args->vma = vma;
		}

		/* Forbid changing of special return value into normal
		 * one - to avoid cases when user changes to special and
		 * back to normal function to avoid security checks. */
		if (is_privileged_return(prev_ip))
			return -EPERM;

		/* Check that the permissions are the same - i.e. if
		 * the original was not writable then the new instruction
		 * is not writable too. */
		if ((pvma->vm_flags & (VM_READ|VM_WRITE|VM_EXEC)) ^
		     (vma->vm_flags & (VM_READ|VM_WRITE|VM_EXEC)))
			return -EPERM;

		/* Check that the exception handling code
		 * resides in the same executable. */
		if (pvma->vm_file != vma->vm_file)
			return -EPERM;
	}

	cr0_hi = frame->cr0_hi;
	cr1_lo = frame->cr1_lo;

	if (is_privileged_return(ip)) {
		AS(cr1_lo).pm = 1;
		if (machine.native_iset_ver < E2K_ISET_V6)
			AS(cr1_lo).ic = 0;
		else
			AS(cr1_lo).cui = KERNEL_CODES_INDEX;
	} else {
		AS(cr1_lo).pm = 0;
		if (machine.native_iset_ver < E2K_ISET_V6) {
			AS(cr1_lo).ic = 1;
		} else {
			int cui = find_cui_by_ip(ip);

			if (cui < 0)
				return cui;

			AS(cr1_lo).cui = cui;
		}
	}
	AS(cr0_hi).ip = ip >> 3;

	if (flags & PCF_FLUSH_NEEDED)
		E2K_FLUSHC;
	if (is_privileged_return(ip))
		ret = put_cr0_hi(cr0_hi, real_frame_addr, 0);
	else
		ret = put_cr1_lo(cr1_lo, real_frame_addr, 0);
	if (ret)
		return ret;

	if (flags & PCF_FLUSH_NEEDED)
		E2K_FLUSHC;
	if (is_privileged_return(ip))
		ret = put_cr1_lo(cr1_lo, real_frame_addr, 0);
	else
		ret = put_cr0_hi(cr0_hi, real_frame_addr, 0);
	if (ret) {
		/* Stack is not consistent anymore */
		force_sig(SIGBUS);
		return ret;
	}

	args->buf += step;
	++(args->nr_written);

	return 0;
}

static long do_set_backtrace(void *__user buf, size_t count, size_t skip,
		unsigned long flags, int step)
{
	struct mm_struct *mm = current->mm;
	struct set_backtrace_args args;
	long ret;

	if (flags)
		return -EINVAL;

	if (!access_ok(buf, count * step))
		return -EFAULT;

	down_read(&mm->mmap_sem);

	args.skip = skip + 1; /* Skip caller's frame */
	args.nr_written = 0;
	args.count = count;
	args.step = step;
	args.buf = buf;
	args.vma = NULL;
	args.pvma = NULL;
	ret = parse_chain_stack(PCS_USER, NULL, set_backtrace_fn, &args);

	up_read(&mm->mmap_sem);

	if (args.nr_written)
		ret = args.nr_written;

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

