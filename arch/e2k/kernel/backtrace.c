/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/compat.h>
#include <linux/mm.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>

#include <asm/e2k_debug.h>
#include <asm/process.h>
#include <asm/hw_stacks.h>


static int is_privileged_return(u64 ip)
{
	return ip == backtrace_return(current->mm);
}

struct get_backtrace_args {
	int skip;
	int nr_read;
	int count;
	int step;
	void __user *buf;
};

static int get_backtrace_fn(e2k_mem_crs_t *frame, unsigned long real_frame_addr,
		unsigned long corrected_frame_addr, chain_write_fn_t write_frame, void *arg)
{
	struct get_backtrace_args *args = (struct get_backtrace_args *) arg;
	void __user *buf = args->buf;
	int step = args->step;
	const struct mm_struct *mm = current->mm;
	u64 ip;

	if (args->nr_read >= args->count)
		return 1;

	ip = get_cr0_ip(frame->cr0);

	/* Skip service frames */
	if (!is_privileged_return(ip) && is_trampoline(mm, ip))
		return 0;

	if (args->skip) {
		--(args->skip);
		return 0;
	}

	if (!is_privileged_return(ip) && !access_ok((void __user __force *) ip, 8))
		return -EFAULT;

	/* Special case of "just return" function */
	if (is_privileged_return(ip))
		ip = -1ULL;

	if ((step == 8) ? __put_user(ip, (u64 __user *) buf) :
			  __put_user(ip, (u32 __user *) buf))
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

	ret = parse_chain_stack(true, false, NULL, get_backtrace_fn, &args);

	if (args.nr_read)
		ret = args.nr_read;

	return ret;
}

SYSCALL_DEFINE4(get_backtrace, unsigned long __user *, buf,
		size_t, count, size_t, skip, unsigned long, flags)
{
	return do_get_backtrace(buf, count, skip, flags, 8);
}

COMPAT_SYSCALL_DEFINE4(get_backtrace, unsigned int __user *, buf,
		size_t, count, size_t, skip, unsigned long, flags)
{
	return do_get_backtrace(buf, count, skip, flags, 4);
}

struct frame_to_update {
	e2k_mem_crs_t value;
	unsigned long addr;
	chain_write_fn_t write_fn;
};

struct set_backtrace_args {
	int skip;
	int nr_written;
	int count;
	int step;
	void __user *buf;

	struct vm_area_struct *cached_vma;
	struct vm_area_struct *cached_pvma;

#define BATCH_SIZE (2048 / sizeof(struct frame_to_update))
	struct frame_to_update frames[BATCH_SIZE];
	size_t frames_count;
};

/* Writing user frames can cause a page fault so it cannot be done
 * under locked mmap_sem.  This function processes a batch of updates
 * that has been checked for validity already. */
static int write_updated_frames(struct set_backtrace_args *args)
{
	struct mm_struct *mm = current->mm;
	int i;

	mmap_read_unlock(mm);

	/* Cached values are no longer valid after dropping mmap_sem */
	args->cached_vma = NULL;
	args->cached_pvma = NULL;

	for (i = 0; i < args->frames_count; i++) {
		struct frame_to_update *frame = &args->frames[i];

		int ret = frame->write_fn(frame->addr, &frame->value);
		if (ret) {
			/* Stack is not consistent anymore */
			force_sig(SIGBUS);
			mmap_read_lock(mm);
			return ret;
		}
	}
	mmap_read_lock(mm);

	args->frames_count = 0;

	return 0;
}

static int set_backtrace_fn(e2k_mem_crs_t *frame, unsigned long real_frame_addr,
		unsigned long corrected_frame_addr, chain_write_fn_t write_frame, void *arg)
{
	struct set_backtrace_args *args = (struct set_backtrace_args *) arg;
	void __user *buf = args->buf;
	int step = args->step;
	struct vm_area_struct *vma = args->cached_vma;
	struct vm_area_struct *pvma = args->cached_pvma;
	struct mm_struct *mm = current->mm;
	u64 prev_ip, ip;

	if (args->nr_written >= args->count)
		return 1;

	prev_ip = get_cr0_ip(frame->cr0);

	/* Skip service frames */
	if (!is_privileged_return(prev_ip) && is_trampoline(mm, prev_ip))
		return 0;

	if (args->skip) {
		--(args->skip);
		return 0;
	}
repeat_get_user:
	/* mm rwsem locked. we need to avoid nested rwsem lock */
	/* see rm 39419 for details */
	pagefault_disable();
	int ret = (step == 8) ? __get_user(ip, (u64 __user *) buf) :
				__get_user(ip, (u32 __user *) buf);
	pagefault_enable();
	if (ret) {
		if (fixup_user_fault(mm, (unsigned long)buf, 0, NULL))
			return -EFAULT;
		args->cached_pvma = NULL;
		args->cached_vma = NULL;
		goto repeat_get_user;
	}

	/* Special case of "just return" function */
	if (step == 8 && ip == -1ULL || step != 8 && ip == 0xffffffffULL)
		ip = backtrace_return(mm);

	if (!is_privileged_return(prev_ip) && (!pvma || pvma->vm_start > prev_ip ||
			pvma->vm_end <= prev_ip)) {
		pvma = find_vma(mm, prev_ip);
		if (!pvma || prev_ip < pvma->vm_start)
			return -ESRCH;
		args->cached_pvma = pvma;
	}

	if (!is_privileged_return(ip)) {
		if (!access_ok((void __user __force *) ip, 8))
			return -EFAULT;

		if (!vma || vma->vm_start > ip || vma->vm_end <= ip) {
			if (ip >= pvma->vm_start && ip < pvma->vm_end) {
				vma = pvma;
			} else {
				vma = find_vma(mm, ip);
				if (!vma || ip < vma->vm_start)
					return -ESRCH;
			}
			args->cached_vma = vma;
		}

		/* Forbid changing of special return value into normal
		 * one - to avoid cases when user changes to special and
		 * back to normal function to avoid security checks. */
		if (is_privileged_return(prev_ip))
			return -EPERM;

		/* Check that the permissions are the same - i.e. if
		 * the original was not writable then the new instruction
		 * is not writable too. */
		if ((pvma->vm_flags & (VM_READ | VM_WRITE | VM_EXEC)) ^
		     (vma->vm_flags & (VM_READ | VM_WRITE | VM_EXEC)))
			return -EPERM;

		/* Check that the exception handling code
		 * resides in the same executable. */
		if (pvma->vm_file != vma->vm_file)
			return -EPERM;
	}

	frame->cr1.pm = 0;

	if (is_privileged_return(ip)) {
		if (machine.native_iset_ver < E2K_ISET_V6)
			frame->cr1.ic = 0;
		else
			frame->cr1.cui = KERNEL_CODES_INDEX;
	} else {
		if (machine.native_iset_ver < E2K_ISET_V6) {
			frame->cr1.ic = 1;
		} else {
			int cui = find_cui_by_ip(ip);
			if (cui < 0)
				return cui;

			frame->cr1.cui = cui;
		}
	}
	set_cr0_ip(frame->cr0, ip);

	if (args->frames_count == BATCH_SIZE)
		write_updated_frames(args);

	args->frames[args->frames_count].value = *frame;
	args->frames[args->frames_count].addr = real_frame_addr;
	args->frames[args->frames_count].write_fn = write_frame;
	args->frames_count += 1;

	args->buf += step;
	++(args->nr_written);

	return 0;
}

static long do_set_backtrace(void __user *buf, size_t count, size_t skip,
			     unsigned long flags, int step)
{
	struct mm_struct *mm = current->mm;
	struct set_backtrace_args args;
	long ret;

	if (flags)
		return -EINVAL;

	if (!access_ok((void __user *) buf, count * step))
		return -EFAULT;
repeat:
	mmap_read_lock(mm);

	args.skip = skip + 1; /* Skip caller's frame */
	args.nr_written = 0;
	args.count = count;
	args.step = step;
	args.buf = buf;
	args.cached_vma = NULL;
	args.cached_pvma = NULL;
	args.frames_count = 0;
	ret = parse_chain_stack(true, true, NULL, set_backtrace_fn, &args);
	if (ret == -EAGAIN) {
		/* __uaccess_copy_crs_fn unlocked mm before handle page fault to avoid deadlock */
		mmap_read_unlock(mm);
		goto repeat;
	}
	if (args.frames_count)
		write_updated_frames(&args);

	mmap_read_unlock(mm);

	if (args.nr_written)
		ret = args.nr_written;

	return ret;
}


SYSCALL_DEFINE4(set_backtrace, unsigned long __user *, buf,
		size_t, count, size_t, skip, unsigned long, flags)
{
	return do_set_backtrace(buf, count, skip, flags, 8);
}

COMPAT_SYSCALL_DEFINE4(set_backtrace, unsigned int __user *, buf,
		size_t, count, size_t, skip, unsigned long, flags)
{
	return do_set_backtrace(buf, count, skip, flags, 4);
}

