/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*  
 * arch/e2k/kernel/sec_space.c
 *
 * Secondary space support for E2K binary compiler
 *
 */
#include <linux/file.h>
#include <linux/kernel.h>
#include <linux/signal.h>
#include <linux/irqflags.h>
#include <linux/sched/task.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/mman.h>

#include <asm/types.h>
#include <asm/cpu_regs.h>
#include <asm/regs_state.h>
#include <asm/secondary_space.h>
#include <asm/mmu_regs_access.h>
#include <asm/cacheflush.h>

#undef	DEBUG_SS_MODE
#undef	DebugSS
#define	DEBUG_SS_MODE		0	/* Secondary Space Debug */
#define DebugSS(...)		DebugPrint(DEBUG_SS_MODE, ##__VA_ARGS__)

#define RTC32_NAME	"/rtc32"
#define RTC64_NAME	"/rtc64"

/* Check if current->mm->exe matches bi->rtc32 or bi->rtc64 */
static bool is_current_bincomp(void)
{
	bin_comp_info_t *bi;
	struct file  *exe_file;
	bool res = false;
	struct mm_struct *mm = current->mm;

	bi = &mm->context.bincomp_info;

	exe_file = get_mm_exe_file(mm);
	if (!exe_file)
		return false;

	read_lock(&bi->lock);
	res = (bi->rtc32 == exe_file) || (bi->rtc64 == exe_file);
	read_unlock(&bi->lock);

	fput(exe_file);
	return res;
}

static bin_comp_info_t *alloc_bin_comp_info_info(unsigned long size)
{
	void *info;

	info = kzalloc(size, GFP_ATOMIC);
	return info ? info : NULL;
}

static int set_user_bin_comp_info_info(void __user *addr, unsigned long size,
				       int pid)
{
	bin_comp_info_t *bi;
	struct task_struct *p;
	struct mm_struct *mm = NULL;
	union bincomp_info_header *header;
	size_t header_min_size;
	void *info, *info_to_free = NULL;
	int ret = 0;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (current->pid == pid) {
		mm = current->mm;
	} else {
		rcu_read_lock();
		p = find_task_by_vpid(pid);
		if (p)
			mm = get_task_mm(p);
		rcu_read_unlock();

		if (!mm)
			return -EACCES;
	}

	bi = &mm->context.bincomp_info;

	read_lock(&bi->lock);
	info = bi->info;
	read_unlock(&bi->lock);

	if (info) {
		/* info can be set only once */
		ret = -EPERM;
		goto out_put_mm;
	}

	info = alloc_bin_comp_info_info(size);
	if (!info) {
		ret = -ENOMEM;
		goto out_put_mm;
	}

	info_to_free = info;

	if (copy_from_user(info, addr, size)) {
		ret = -EFAULT;
		goto out_free_info;
	}

	header = (union bincomp_info_header *)info;

	switch (header->v0.version) {
	case 0:
		header_min_size = sizeof(header->v0);
		break;
	case 1:
		header_min_size = sizeof(header->v1);
		break;
	default:
		ret = -EINVAL;
		goto out_free_info;
	}

	if (size < header_min_size + 1) {
		ret = -EINVAL;
		goto out_free_info;
	}

	write_lock(&bi->lock);

	info_to_free = bi->info ? : NULL;

	bi->info = info;
	bi->info_size = size;

	write_unlock(&bi->lock);

out_free_info:
	kfree(info_to_free);

out_put_mm:
	if (current->pid != pid)
		mmput(mm);

	return ret;
}

static int get_user_bin_comp_info_info(void __user *addr, int pid)
{
	struct task_struct *p;
	struct mm_struct *mm = NULL;
	bin_comp_info_t *bi;
	void *info;
	e2k_size_t info_size;
	int ret = 0;

	if (!is_current_bincomp())
		return -EPERM;

	if (current->pid == pid) {
		mm = current->mm;
	} else {
		rcu_read_lock();
		p = find_task_by_vpid(pid);
		if (p)
			mm = get_task_mm(p);
		rcu_read_unlock();

		if (!mm)
			return -EACCES;
	}

	bi = &mm->context.bincomp_info;
	if (!bi) {
		ret = -EACCES;
		goto out;
	}

	read_lock(&bi->lock);

	WARN_ON_ONCE(bi->info_size == 0);

	info = alloc_bin_comp_info_info(bi->info_size);
	if (!info) {
		ret = -ENOMEM;
		read_unlock(&bi->lock);
		goto out;
	}

	memcpy(info, bi->info, bi->info_size);
	info_size = bi->info_size;

	read_unlock(&bi->lock);

	if (copy_to_user(addr, info, info_size))
		ret = -EFAULT;

	kfree(info);

out:
	if (current->pid != pid)
		mmput(mm);

	return ret;
}

static struct file **alloc_bin_comp_fdt(void)
{
	return kzalloc(sizeof(struct file *) * BIN_COMP_FD_TABLE_SIZE, GFP_ATOMIC);
}

/*
 * Delete empty log file on exit (bug #143358)
 */
static void unlink_empty_bin_comp_fd(struct file *f)
{
	struct kstat stat;
	struct path *path = &f->f_path;
	struct dentry *dentry = path->dentry;
	struct inode *parent_inode = d_inode(dentry->d_parent);
	int error;

	error = vfs_getattr(path, &stat, STATX_SIZE, AT_STATX_SYNC_AS_STAT);
	if (error || stat.size || file_count(f) > 1)
		return;

	if (!S_ISREG(stat.mode))
		return;

	if (!inode_trylock(parent_inode))
		return;
	dget(dentry);
	vfs_unlink(&init_user_ns, parent_inode, dentry, NULL);
	dput(dentry);
	inode_unlock(parent_inode);
}

void free_bin_comp_info(bin_comp_info_t *bi)
{
	int i;

	if (bi->info) {
		kfree(bi->info);
		bi->info = NULL;
	}

	/**
	 * exe_file isn't managed by kernel exec subsystem, and we have to
	 * allow/deny write access ourselves. Write access is also managed in
	 * rtcfs_set_exe_file() and copy_bin_comp_info().
	 */
	if (bi->exe_file) {
		allow_write_access(bi->exe_file);
		fput(bi->exe_file);
		bi->exe_file = NULL;
	}

	/**
	 * Write access is granted by kernel when thread dies,
	 * since rtc32/64 are real executables.
	 */
	if (bi->rtc32) {
		fput(bi->rtc32);
		bi->rtc32 = NULL;
	}

	if (bi->rtc64) {
		fput(bi->rtc64);
		bi->rtc64 = NULL;
	}

	bi->startx86_pid_ns = NULL;

	if (bi->fd_table) {
		for (i = 0; i < BIN_COMP_FD_TABLE_SIZE; i++) {
			struct file *f = bi->fd_table[i];

			if (f) {
				unlink_empty_bin_comp_fd(f);
				fput(f);
			}
		}

		kfree(bi->fd_table);
		bi->fd_table = NULL;
	}
}

int copy_bin_comp_info(bin_comp_info_t *oldbi, bin_comp_info_t *bi)
{
	int i;

	read_lock(&oldbi->lock);

	if (oldbi->info) {
		bi->info = alloc_bin_comp_info_info(oldbi->info_size);
		if (!bi->info) {
			read_unlock(&oldbi->lock);
			return -ENOMEM;
		}

		memcpy(bi->info, oldbi->info, oldbi->info_size);
		bi->info_size = oldbi->info_size;
	}

	/* See comments in free_bin_comp_info() */
	if (oldbi->exe_file) {
		bi->exe_file = oldbi->exe_file;
		get_file(bi->exe_file);
		WARN_ON_ONCE(deny_write_access(bi->exe_file));
	}

	/* Denying write access permissions is done in load_rtc() */
	if (oldbi->rtc32) {
		bi->rtc32 = oldbi->rtc32;
		get_file(bi->rtc32);
	}
	if (oldbi->rtc64) {
		bi->rtc64 = oldbi->rtc64;
		get_file(bi->rtc64);
	}

	bi->startx86_pid_ns = oldbi->startx86_pid_ns;

	if (oldbi->fd_table) {
		bi->fd_table = alloc_bin_comp_fdt();
		if (!bi->fd_table) {
			read_unlock(&oldbi->lock);
			return -ENOMEM;
		}

		for (i = 0; i < BIN_COMP_FD_TABLE_SIZE; i++) {
			struct file *f = oldbi->fd_table[i];

			if (f) {
				get_file(f);
				bi->fd_table[i] = f;
			}
		}
	}

	read_unlock(&oldbi->lock);

	return 0;
}

/*
 * Process additional x86 rlimits (bug #141958)
 */
static int do_bin_comp_rlimit(pid_t pid, unsigned int resource,
				struct rlimit __user *unew,
				struct rlimit __user *uold)
{
	struct rlimit old, new;
	struct task_struct *p;
	int ret = 0;

	if (resource >= BINCOMP_RLIM_NLIMITS)
		return -EINVAL;

	if (unew) {
		if (copy_from_user(&new, unew, sizeof(*unew)))
			return -EFAULT;
		if (new.rlim_cur > new.rlim_max)
			return -EINVAL;
	}

	rcu_read_lock();

	p = pid ? find_task_by_vpid(pid) : current;
	if (!p) {
		rcu_read_unlock();
		return -ESRCH;
	}

	/* FIXME: check_prlimit_permission should be here! */

	get_task_struct(p);
	rcu_read_unlock();

	read_lock(&tasklist_lock);

	if (!p->sighand) {
		read_unlock(&tasklist_lock);
		return -ESRCH;
	}

	task_lock(p->group_leader);

	if (uold)
		old = p->signal->bin_comp_rlim[resource];
	if (unew)
		p->signal->bin_comp_rlim[resource] = new;

	task_unlock(p->group_leader);
	read_unlock(&tasklist_lock);

	if (uold)
		ret = copy_to_user(uold, &old, sizeof(*uold)) ? -EFAULT : 0;

	put_task_struct(p);

	return ret;
}

/*
 * Set additional x86 rlimit (bug #141958)
 */
static inline int set_rlim(int resource, struct rlimit __user *rlim, pid_t pid)
{
	return do_bin_comp_rlimit(pid, resource, rlim, NULL);
}

/*
 * Get additional x86 rlimit (bug #141958)
 */
static inline int get_rlim(int resource, struct rlimit __user *rlim, pid_t pid)
{
	return do_bin_comp_rlimit(pid, resource, NULL, rlim);
}

static bool bin_comp_file_lock_pos(struct file *file)
{
	if (file->f_mode & FMODE_ATOMIC_POS) {
		if (file_count(file) > 1) {
			mutex_lock(&file->f_pos_lock);
			return true;
		}
	}

	return false;
}

static struct file *get_bin_comp_file(int specfd)
{
	bin_comp_info_t *bi;
	struct file *file;

	if (specfd > BIN_COMP_FD_TABLE_SIZE - 1)
		return ERR_PTR(-ENFILE);

	bi = &current->mm->context.bincomp_info;

	read_lock(&bi->lock);

	if (!bi->fd_table) {
		read_unlock(&bi->lock);
		return ERR_PTR(-EACCES);
	}

	file = bi->fd_table[specfd];
	if (file)
		get_file(file);

	read_unlock(&bi->lock);

	return file ?: ERR_PTR(-EBADF);
}

/*
 * Write() syscall implementaion for hidden fd table
 */
static ssize_t bin_comp_fd_write(unsigned int fd, const char __user *buf, size_t count)
{
	struct file *file;
	loff_t pos, *ppos;
	bool locked;
	ssize_t ret;

	if (!is_current_bincomp())
		return -EPERM;

	file = get_bin_comp_file(fd);
	if (IS_ERR(file))
		return PTR_ERR(file);

	locked = bin_comp_file_lock_pos(file);

	ppos = (file->f_mode & FMODE_STREAM) ? NULL : &file->f_pos;
	if (ppos) {
		pos = *ppos;
		ppos = &pos;
	}

	ret = vfs_write(file, buf, count, ppos);
	if (ret >= 0 && ppos)
		file->f_pos = pos;

	if (locked)
		__f_unlock_pos(file);
	fput(file);

	return ret;
}

static int is_bin_comp_fd_set(int specfd)
{
	struct file *file;

	if (!is_current_bincomp())
		return -EPERM;

	file = get_bin_comp_file(specfd);
	if (IS_ERR(file))
		return PTR_ERR(file);
	fput(file);

	return file != NULL;
}

/* Opening binary compilers and saving current task active pid ns*/
static int set_bin_comp_info_search_path(const char __user *user_path)
{
	bin_comp_info_t *bi;
	struct file *exe32, *exe64;
	char *path;
	int ret, len;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (!user_path)
		return -EINVAL;

	bi = &current->mm->context.bincomp_info;
	read_lock(&bi->lock);

	if (bi->rtc32 || bi->rtc64) {
		read_unlock(&bi->lock);
		return -EEXIST;
	}
	read_unlock(&bi->lock);

	path = kmalloc(PATH_MAX, GFP_KERNEL);
	if (IS_ERR(path))
		return PTR_ERR(path);

	len = strncpy_from_user(path, user_path, PATH_MAX);
	if (len < 1) {
		ret = len < 0 ? len : -ENOENT;
		goto out_free;
	}
	if (path[len-1] == '/')
		path[len--] = '0';

	/* currently both RTC32/64 have the same lengths */
	if (len + strlen(RTC32_NAME) >= PATH_MAX) {
		ret = -ENAMETOOLONG;
		goto out_free;
	}

	strcpy(path + len, RTC32_NAME);
	exe32 = filp_open(path, O_LARGEFILE | O_RDONLY | __FMODE_EXEC, 0);

	if (IS_ERR(exe32)) {
		ret = PTR_ERR(exe32);
		goto out_free;
	}

	strcpy(path + len, RTC64_NAME);
	exe64 = filp_open(path, O_LARGEFILE | O_RDONLY | __FMODE_EXEC, 0);

	if (IS_ERR(exe64)) {
		fput(exe32);
		ret = PTR_ERR(exe64);
		goto out_free;
	}

	write_lock(&bi->lock);
	bi->rtc32 = exe32;
	bi->rtc64 = exe64;
	bi->startx86_pid_ns = task_active_pid_ns(current);
	write_unlock(&bi->lock);

	ret = 0;
out_free:
	if (ret)
		pr_warn("Can't open '%s', err %d\n", path, ret);
	kfree(path);
	return ret;
}

/*
 * Add entry to hidden fd table (bug #140153)
 */
static int set_bin_comp_fd(unsigned int specfd, unsigned int fd)
{
	struct fd f = fdget_raw(fd);
	bin_comp_info_t *bi;
	int ret = 0;

	/* check caps if called from startx86 */
	if (!capable(CAP_SYS_ADMIN) && !is_current_bincomp())
		return -EPERM;

	if (specfd > BIN_COMP_FD_TABLE_SIZE - 1) {
		ret = -EACCES;
		goto out_putfd;
	}

	if (!f.file) {
		ret = -EBADF;
		goto out_putfd;
	}

	bi = &current->mm->context.bincomp_info;

	write_lock(&bi->lock);

	if (!bi->fd_table) {
		bi->fd_table = alloc_bin_comp_fdt();
		if (!bi->fd_table) {
			ret = -ENOMEM;
			goto out_unlock;
		}
	}

	if (bi->fd_table[specfd]) {
		ret = -EINVAL;
		goto out_unlock;
	}

	bi->fd_table[specfd] = f.file;
	get_file(f.file);

out_unlock:
	write_unlock(&bi->lock);

out_putfd:
	fdput(f);

	return ret;
}

/*
 * Get init ns for current run. Also used to check that process is working
 * in "FledgedMode" (i.e. was started with sufficient privileges).
 */
static struct pid_namespace *bin_comp_init_ns(void)
{
	bin_comp_info_t *bi;
	struct pid_namespace *ns;

	bi = &current->mm->context.bincomp_info;

	read_lock(&bi->lock);
	ns = bi->startx86_pid_ns;
	read_unlock(&bi->lock);

	return ns;
}

/*
 * Change parent for bincomp service threads on clone() (bug #148500).
 * tasklist_lock should be taken by caller.
 */
int bc_set_outmost_parent(struct task_struct *t)
{
	struct pid_namespace *bc_init_ns;
	struct task_struct *p;

	bc_init_ns = bin_comp_init_ns();
	if (!bc_init_ns)
		return -EACCES;

	rcu_read_lock();
	p = find_task_by_pid_ns(1, bc_init_ns);
	rcu_read_unlock();

	if (!p)
		return -ESRCH;

	lockdep_assert_held_write(&tasklist_lock);
	RCU_INIT_POINTER(t->real_parent, p);
	RCU_INIT_POINTER(t->parent, p);
	t->parent_exec_id = p->self_exec_id;
	t->exit_signal = SIGCHLD;
	return 0;
}

/*
 * Move bincomp service threads to init namespace on clone() (bug #148500).
 */
int bc_set_outmost_ns(struct task_struct *t, u64 clone_flags)
{
	struct pid_namespace *bc_init_ns;
	struct task_struct *p;
	struct nsproxy *nsp;

	if (clone_flags & (CLONE_THREAD | CLONE_PARENT))
		return -EINVAL;

	bc_init_ns = bin_comp_init_ns();
	if (!bc_init_ns)
		return -EACCES;

	rcu_read_lock();
	p = find_task_by_pid_ns(1, bc_init_ns);
	if (!p) {
		rcu_read_unlock();
		return -ESRCH;
	}

	task_lock(p);
	nsp = p->nsproxy;
	if (nsp)
		get_nsproxy(nsp);
	task_unlock(p);

	rcu_read_unlock();
	if (!nsp)
		return -ESRCH;
	switch_task_namespaces(t, nsp);
	return 0;
}

/*
 * Get outer ns tid from nested ns (bug #148500)
 *
 * In FledgedMode binary compiler service threads are moved into init
 * namespace, but execution threads need to know outer namespace tid
 * to call send_signal_to_outmost_tid.
 *
 * See also: bin_comp_init_ns(), set_bin_comp_info_search_path()
 */
static pid_t get_outmost_ns_tid(pid_t tid)
{
	struct pid_namespace *bc_init_ns;
	struct pid *pid;
	struct task_struct *p;
	struct mm_struct *mm;
	pid_t nr = -ESRCH;

	if (!is_current_bincomp())
		return -EPERM;

	bc_init_ns = bin_comp_init_ns();
	if (!bc_init_ns)
		return -EACCES;

	if (tid == 0 || current->pid == tid)
		pid = get_task_pid(current, PIDTYPE_PID);
	else {
		pid = find_get_pid(tid);
		if (!pid)
			goto out;

		p = get_pid_task(pid, PIDTYPE_PID);
		if (!p)
			goto out_put_pid;

		mm = get_task_mm(p);
		put_task_struct(p);

		nr = -EACCES;
		if (!mm)
			goto out_put_pid;
		mmput(mm);

		if (current->mm != mm)
			goto out_put_pid;
	}

	nr = pid_nr_ns(pid, bc_init_ns);
out_put_pid:
	put_pid(pid);
out:
	return nr;
}

/*
 * Send signal to procces working in external ns (bug #148500)
 *
 * In FledgedMode binary compiler service threads are moved into init
 * namespace, but they still need to interact with each other.
 *
 * See also: bin_comp_init_ns(), set_bin_comp_info_search_path()
 */
static int send_signal_to_outmost_tid(pid_t tid, int sig, siginfo_t __user *uinfo)
{
	struct pid_namespace *bc_init_ns;
	kernel_siginfo_t info;
	struct task_struct *task;
	int retval;

	if (!is_current_bincomp())
		return -EPERM;

	bc_init_ns = bin_comp_init_ns();
	if (!bc_init_ns)
		return -EACCES;

	if (copy_siginfo_from_user(&info, uinfo))
		return -EFAULT;
	info.si_signo = sig;

	retval = -ESRCH;
	rcu_read_lock();
	task = find_task_by_pid_ns(tid, bc_init_ns);
	if (!task)
		goto out;

	if (task->mm != current->mm) {
		pr_err("send_signal_to_outmost: task->mm != current->mm\n");
		retval = -EINVAL;
		goto out;
	}

	retval = do_send_sig_info(sig, &info, task, PIDTYPE_PID);
out:
	rcu_read_unlock();

	return retval;
}

/*
 * Userfaultfd ioctl implementation for special file descriptors table (bug #147568)
 */
static int bin_comp_uffd_ioctl(unsigned int fd, unsigned int cmd, unsigned long arg)
{
	struct file *file;
	int error;

	if (!is_current_bincomp())
		return -EPERM;

	file = get_bin_comp_file(fd);
	if (IS_ERR(file))
		return PTR_ERR(file);

	error = security_file_ioctl(file, cmd, arg);
	if (error)
		goto out;

	error = vfs_ioctl(file, cmd, arg);

out:
	fput(file);
	return error;
}

/*
 * Closing special file descriptor
 */
static int close_bin_comp_fd(int specfd)
{
	bin_comp_info_t *bi;
	struct file *file;
	int ret = 0;

	if (!is_current_bincomp())
		return -EPERM;

	if (specfd > BIN_COMP_FD_TABLE_SIZE - 1) {
		ret = -ENFILE;
		goto out;
	}

	bi = &current->mm->context.bincomp_info;

	write_lock(&bi->lock);

	if (!bi->fd_table) {
		ret = -EACCES;
		goto out_unlock;
	}

	file = bi->fd_table[specfd];
	if (!file) {
		ret = -EBADF;
		goto out_unlock;
	}

	fput(file);
	bi->fd_table[specfd] = NULL;

out_unlock:
	write_unlock(&bi->lock);
out:
	return ret;
}

/*
 * map_bin_comp_exe - map bincomp elf (bug #152358)
 *
 * This maps binary compiler elf file into user memory area.
 *
 * Optimization for binary compiler which allows to eliminate redundant copying
 * of loccode section. Implemented as el_binary call, since executablie file
 * may be inaccessible in FledgedMode.
 */
static s64 map_bin_comp_exe(long addr, long len, long prot, long flags, long offset)
{
	struct file *file;
	s64 res;

	if (!is_current_bincomp() || (flags & MAP_SHARED))
		return -EPERM;

	file = get_task_exe_file(current);
	if (!file)
		return -ENOENT;

	res = vm_mmap(file, addr, len, prot, flags, offset);
	fput(file);
	return res;
}


/*
 * Convert vm_flags to prot flags
 */
static u64 flags_vm_to_prot(struct vm_area_struct *vma)
{
	u64 prot = 0;

	if (vma->vm_flags & VM_READ)
		prot |= PROT_READ;
	if (vma->vm_flags & VM_WRITE)
		prot |= PROT_WRITE;
	if (vma->vm_flags & VM_EXEC)
		prot |= PROT_EXEC;
	return prot;
}

/*
 * Convert vm_flags to mmap flags
 */
static u64 flags_vm_to_mmap(struct vm_area_struct *vma)
{
	u64 flags = 0;

	if (vma->vm_flags & VM_SHARED)
		flags |= MAP_SHARED;
	else
		flags |= MAP_PRIVATE;

	if (vma_is_anonymous(vma))
		flags |= MAP_ANONYMOUS;

	if (vma->vm_flags & VM_GROWSDOWN)
		flags |= MAP_GROWSDOWN;

	if (vma->vm_flags & VM_LOCKED)
		flags |= MAP_LOCKED;

	if (vma->vm_flags & VM_NORESERVE)
		flags |= MAP_NORESERVE;

	if (vma->vm_flags & VM_WRITECOMBINED)
		flags |= MAP_WRITECOMBINED;

	if (vma->vm_flags & VM_HUGETLB)
		flags |= MAP_HUGETLB;

	return flags;
}

/*
 * get_map_info - print vmas info to user
 *
 * This prints vmas info to user in case of mapping x86 elf by kernel.
 *
 * Currently binary compiler needs to have this information at start in order
 * to initialize its own vma list, but such instruments like /proc/maps
 * may be unavailable in FledgedMode.
 *
 * Additionaly MAP_FIXED flag should be added by bincomp.
 */
static int get_map_info(char __user *addr, int num, unsigned long start_addr)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	struct bincomp_vma *bc_vma;
	VMA_ITERATOR(vmi, mm, start_addr);
	int copied = 0, ret;

	struct bincomp_vma {
		u64 start;
		u64 end;
		u64 prot;
		u64 flags;
		u64 pgoff;
	};

	if (!is_current_bincomp())
		return -EPERM;

	if (num < 1)
		return -EINVAL;

	bc_vma = kmalloc(sizeof(*bc_vma) * num, GFP_KERNEL);
	if (!bc_vma)
		return -ENOMEM;

	mmap_read_lock(mm);

	while (copied < num) {
		vma = vma_next(&vmi);
		if (!vma)
			break;

		bc_vma[copied].start	= vma->vm_start;
		bc_vma[copied].end	= vma->vm_end;
		bc_vma[copied].prot	= flags_vm_to_prot(vma);
		bc_vma[copied].flags	= flags_vm_to_mmap(vma);
		bc_vma[copied].pgoff	= vma->vm_pgoff;

		++copied;
	}

	mmap_read_unlock(mm);

	ret = copied;

	if (copied)
		if (copy_to_user(addr, bc_vma, sizeof(*bc_vma) * copied))
			ret = -EFAULT;

	kfree(bc_vma);
	return ret;
}

/* Get absolute path by file descriptor */
static int get_fd_path(int fd, char __user *ubuf, int usize)
{
	struct fd f = fdget_raw(fd);
	char *buf, *pathname;
	/* Some additional characters may be added, see d_path() */
	size_t max_size = PATH_MAX * 2;
	int ret;

	if (!is_current_bincomp())
		return -EPERM;

	if (!f.file)
		return -EBADF;

	buf = kzalloc(max_size, GFP_KERNEL);
	if (!buf) {
		ret = -ENOMEM;
		goto out_putfd;
	}

	pathname = d_path(&f.file->f_path, buf, max_size);
	if (IS_ERR(pathname)) {
		ret = PTR_ERR(pathname);
		goto out;
	}

	ret = buf + max_size - 1 - pathname;
	if (ret > usize)
		ret = usize;

	if (copy_to_user(ubuf, pathname, ret))
		ret = -EFAULT;

out:
	kfree(buf);

out_putfd:
	fdput(f);

	return ret;
}

/* Open fd associated with an entry in the hidden fdt */
static int bin_comp_fd_open(int place)
{
	struct file *file;
	int fd;

	if (!is_current_bincomp())
		return -EINVAL;

	file = get_bin_comp_file(place);
	if (IS_ERR(file))
		return PTR_ERR(file);

	fd = get_unused_fd_flags(0);
	if (fd < 0) {
		fput(file);
		return fd;
	}

	fd_install(fd, file);
	return fd;
}

SYSCALL_DEFINE6(el_binary, s64, work,
		s64, arg2, s64, arg3, s64, arg4, s64, arg5, s64, arg6)
{
	s64 res = 0;
	thread_info_t *ti = current_thread_info();

	if (!TASK_IS_BINCO(current)) {
		pr_info("sys_el_binary(): Task %d is not binary compiler\n",
			current->pid);
		return -EPERM;
	}

	switch (work) {
	case GET_SECONDARY_SPACE_OFFSET:
		DebugSS("GET_SECONDARY_SPACE_OFFSET: 0x%lx\n", SS_ADDR_START);
		res = SS_ADDR_START;
		break;
	case SET_SECONDARY_REMAP_BOUND:
		DebugSS("SET_SECONDARY_REMAP_BOUND: bottom = 0x%llx\n", arg2);
		ti->ss_rmp_bottom = arg2 + SS_ADDR_START;
		break;
	case SET_SECONDARY_DESCRIPTOR:
		/* arg2 - descriptor # ( 0-CS, 1-DS, 2-ES, 3-SS, 4-FS, 5-GS )
		 * arg3 - desc.lo
		 * arg4 - desc.hi
		 */
		DebugSS("SET_SECONDARY_DESCRIPTOR: desc #%lld, desc.lo = x%llx, desc.hi = 0x%llx\n",
				arg2, arg3, arg4);
		switch (arg2) {
		case CS_SELECTOR:
			WRITE_CS_LO_REG_VALUE(arg3);
			WRITE_CS_HI_REG_VALUE(arg4);
			break;
		case DS_SELECTOR:
			WRITE_DS_LO_REG_VALUE(arg3);
			WRITE_DS_HI_REG_VALUE(arg4);
			break;
		case ES_SELECTOR:
			WRITE_ES_LO_REG_VALUE(arg3);
			WRITE_ES_HI_REG_VALUE(arg4);
			break;
		case SS_SELECTOR:
			WRITE_SS_LO_REG_VALUE(arg3);
			WRITE_SS_HI_REG_VALUE(arg4);
			break;
		case FS_SELECTOR:
			WRITE_FS_LO_REG_VALUE(arg3);
			WRITE_FS_HI_REG_VALUE(arg4);
			break;
		case GS_SELECTOR:
			WRITE_GS_LO_REG_VALUE(arg3);
			WRITE_GS_HI_REG_VALUE(arg4);
			break;
		default:
			DebugSS
			    ("SET_SECONDARY_DESCRIPTOR: Invalid descriptor #%lld\n",
			     arg2);
			res = -EINVAL;
		}
		break;
	case GET_SNXE_USAGE:
		DebugSS("GET_SNXE_USAGE\n");
		res = (machine.native_iset_ver >= E2K_ISET_V5) ? 1 : 0;
		break;
	case SIG_EXIT_GROUP:
		arg2 = arg2 & 0xff7f;
		DebugSS("SIG_EXIT_GROUP: code = 0x%llx\n", arg2);
		do_group_exit(arg2);
		BUG();
		break;
	case SET_RP_BOUNDS_AND_IP:
		DebugSS
		    ("SET_RP_BOUNDS_AND_IP: start = 0x%llx, end = 0x%llx, IP = 0x%llx\n",
		     arg2, arg3, arg4);
		ti->rp_start = arg2;
		ti->rp_end = arg3;
		ti->rp_ret_ip = arg4;
		break;
	case SET_SECONDARY_64BIT_MODE:
		if (arg2 == 1)
			current->thread.flags |= E2K_FLAG_64BIT_BINCO;
		else
			res = -EINVAL;
		break;
	case GET_PROTOCOL_VERSION:
		DebugSS("GET_PROTOCOL_VERSION: %d\n", BINCO_PROTOCOL_VERSION);
		res = BINCO_PROTOCOL_VERSION;
		break;
	case SET_IC_NEED_FLUSH_ON_SWITCH:
		DebugSS("SET_IC_NEED_FLUSH_ON_SWITCH: set = %lld\n", arg2);
		if (arg2)
			ti->last_ic_flush_cpu = smp_processor_id();
		else
			ti->last_ic_flush_cpu = -1;
		break;
	case SET_UPT_SEC_AD_SHIFT_DSBL:
		res = -EPERM;
		break;
	case GET_UPT_SEC_AD_SHIFT_DSBL:
		DebugSS("SET_UPT_AEC_AD_SHIFT_DSBL\n");
		if (machine.native_iset_ver >= E2K_ISET_V6) {
			e2k_cu_hw0_t cu_hw0 = read_CU_HW0_reg();
			res = cu_hw0.upt_sec_ad_shift_dsbl;
		} else {
			res = -EPERM;
		}
		break;
	case SET_BIN_COMP_INFO:
		DebugSS
		    ("SET_BIN_COMP_INFO: info = 0x%llx, size = 0x%llx, pid = %d\n",
		     arg2, arg3, (int)arg4);
		res = set_user_bin_comp_info_info((void __user *)arg2, arg3, arg4);
		break;
	case GET_BIN_COMP_INFO:
		DebugSS("GET_BIN_COMP_INFO: info = 0x%llx, pid = %d\n",
			arg2, (int)arg3);
		res = get_user_bin_comp_info_info((void __user *)arg2, arg3);
		break;
	case SET_RLIM:
		DebugSS("SET_RLIM: resource = 0x%x, rlim = 0x%llx, pid = %d\n",
			(unsigned int)arg2, arg3, (int)arg4);
		res = set_rlim(arg2, (struct rlimit __user *)arg3, arg4);
		break;
	case GET_RLIM:
		DebugSS("GET_RLIM: resource = 0x%x, rlim = 0x%llx, pid = %d\n",
			(unsigned int)arg2, arg3, (int)arg4);
		res = get_rlim(arg2, (struct rlimit __user *)arg3, arg4);
		break;
	case SET_BIN_COMP_FD:
		DebugSS("SET_BIN_COMP_FD: specfd = %d, fd = %d\n",
			(unsigned int)arg2, (unsigned int)arg3);
		res = set_bin_comp_fd(arg2, arg3);
		break;
	case BIN_COMP_FD_WRITE:
		DebugSS
		    ("BIN_COMP_FD_WRITE: fd = %d, buf = 0x%llx, count = 0x%llx\n",
		     (unsigned int)arg2, arg3, arg4);
		res = bin_comp_fd_write(arg2, (const char __user *)arg3, arg4);
		break;
	case IS_BIN_COMP_FD_SET:
		DebugSS("IS_BIN_COMP_SET: fd = %d\n", (unsigned int)arg2);
		res = is_bin_comp_fd_set(arg2);
		break;
	case SET_BIN_COMP_SEARCH_PATH:
		DebugSS("SET_BIN_COMP_SEARCH_PATH: path = %s\n",
			(const char *)arg2);
		res = set_bin_comp_info_search_path((const char __user *)arg2);
		break;
	case SET_CHILD_IS_SERVING_THREAD:
		DebugSS("SET_CHILD_IS_SERVING_THREAD: cur val = 0x%x, val = 0x%x\n",
			ti->bc_flags, (bool)arg2);

		if (!is_current_bincomp())
			return -EPERM;

		if ((bool)arg2) {
			if (ti->bc_flags & BC_HAS_OUTMOST_CHILD)
				res = -EPERM;
			else
				ti->bc_flags |= BC_CHILD_IS_SERVING
						| BC_HAS_OUTMOST_CHILD;
		} else {
			ti->bc_flags &= ~BC_CHILD_IS_SERVING;
		}
		break;
	case GET_OUTMOST_NS_TID:
		DebugSS("GET_OUTMOST_NS_TID: tid = %u\n", (pid_t)arg2);
		res = get_outmost_ns_tid((pid_t)arg2);
		break;
	case SEND_SIGNAL_TO_OUTMOST_TID:
		DebugSS("SEND_SIGNAL_TO_OUTMOST_TID: tid = %u, sig = %d, si = %llx\n",
			(pid_t)arg2, (int)arg3, arg4);
		res = send_signal_to_outmost_tid((pid_t)arg2, (int)arg3,
						(siginfo_t __user *)arg4);
		break;
	case BIN_COMP_UFFD_IOCTL:
		DebugSS("BIN_COMP_UFFD_IOCTL: fd = %u cmd = %u arg = %lu\n",
			(int)arg2, (unsigned int)arg3, (unsigned long)arg4);
		res = bin_comp_uffd_ioctl((int)arg2, (unsigned int)arg3,
						(unsigned long)arg4);
		break;
	case CLOSE_BIN_COMP_FD:
		DebugSS("CLOSE_BIN_COMP_FD: fd = %u\n", (int)arg2);
		res = close_bin_comp_fd((int)arg2);
		break;
	case MAP_BIN_COMP_EXE:
		DebugSS("MAP_BIN_COMP_EXE: addr = 0x%lx, len = 0x%lx, prot = 0x%lx, flags = 0x%lx, offset = 0x%lx\n",
			(unsigned long)arg2, (unsigned long)arg3,
			(unsigned long)arg4, (unsigned long)arg5,
			(unsigned long)arg6);
		res = map_bin_comp_exe(arg2, arg3, arg4, arg5, arg6);
		break;
	case GET_MAP_INFO:
		 DebugSS("GET_MAP_INFO: info = %lx num = %d start addr = %lx\n",
			  (unsigned long)arg2, (int)arg3, (unsigned long)arg4);
		 res = get_map_info((char __user *)arg2, (int)arg3, (unsigned long)arg4);
		 break;
	case GET_FD_PATH:
		DebugSS("GET_FD_PATH: fd = %d, buf = %lx, size = %u\n",
				(int)arg2, (unsigned long)arg3, (int)arg4);
		res = get_fd_path((int)arg2, (char __user *)arg3, (int)arg4);
		break;
	case BIN_COMP_FD_OPEN:
		DebugSS("BIN_COMP_FD_OPEN: place = %d\n", (int)arg2);
		res = bin_comp_fd_open((int)arg2);
		break;

	default:
		DebugSS("Invalid work: #%lld\n", work);
		res = -EINVAL;
		break;
	}

	DebugSS("res = %lld\n", res);
	return res;
}

static __init int check_ss_addr(void)
{
	WARN(SS_ADDR_END > USER_ADDR_MAX,
	     "Secondary space crosses privileged area!\n");

	return 0;
}

late_initcall(check_ss_addr);
