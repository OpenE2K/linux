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

#include <asm/types.h>
#include <asm/cpu_regs_access.h>
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

void set_upt_sec_ad_shift_dsbl(void *arg)
{
	unsigned long flags;
	e2k_cu_hw0_t cu_hw0;

	raw_all_irq_save(flags);
	cu_hw0 = READ_CU_HW0_REG();
	cu_hw0.upt_sec_ad_shift_dsbl = (arg) ? 1 : 0;
	WRITE_CU_HW0_REG(cu_hw0);
	raw_all_irq_restore(flags);
}

static bin_comp_info_t *alloc_bin_comp_info_info(unsigned long size)
{
	void *info;

	info = kzalloc(size, GFP_ATOMIC);
	return info ? info : NULL;
}

static int set_user_bin_comp_info_info(void __user *addr, unsigned long size, int pid)
{
	bin_comp_info_t *bi;
	struct task_struct *p;
	struct mm_struct *mm = NULL;
	void *info, *info_to_free = NULL;
	int ret = 0;

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

	if (size < sizeof(struct bincomp_info_header_v0) + 1) {
		ret = -EINVAL;
		goto out_free_info;
	}

	write_lock(&bi->lock);

	info_to_free = bi->info ?: NULL;

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

	inode_lock(parent_inode);
	dget(dentry);
	vfs_unlink(parent_inode, dentry, NULL);
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

static int do_bin_comp_rlimit(pid_t pid, unsigned int resource, struct rlimit __user *unew,
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

static inline int set_rlim(int resource, struct rlimit __user *rlim, pid_t pid)
{
	return do_bin_comp_rlimit(pid, resource, rlim, NULL);
}

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

static ssize_t bin_comp_fd_write(unsigned int fd, const char __user *buf, size_t count)
{
	struct file *file;
	loff_t pos, *ppos;
	bool locked;
	ssize_t ret;

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

static int set_bin_comp_fd(unsigned int specfd, unsigned int fd)
{
	struct fd f = fdget(fd);
	bin_comp_info_t *bi;
	int ret = 0;

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

struct pid_namespace *bin_comp_init_ns(void)
{
	bin_comp_info_t *bi;
	struct pid_namespace *ns;

	bi = &current->mm->context.bincomp_info;

	read_lock(&bi->lock);
	ns = bi->startx86_pid_ns;
	read_unlock(&bi->lock);

	return ns;
}

/* tasklist_lock should be taken by caller */
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

	t->real_parent = p;
	t->parent = p;
	t->parent_exec_id = p->self_exec_id;
	t->exit_signal = SIGCHLD;
	return 0;
}

/* Moving ourselves to outmost namespaces */
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

static pid_t get_outmost_ns_tid(pid_t tid)
{
	struct pid_namespace *bc_init_ns;
	struct pid *pid;
	pid_t nr;

	bc_init_ns = bin_comp_init_ns();
	if (!bc_init_ns)
		return -EACCES;

	if (tid == 0 || current->pid == tid)
		pid = get_task_pid(current, PIDTYPE_PID);
	else
		pid = find_get_pid(tid);

	nr = pid_nr_ns(pid, bc_init_ns);

	put_pid(pid);
	return nr;
}

static int send_signal_to_outmost_tid(pid_t tid, int sig, siginfo_t __user *uinfo)
{
	struct pid_namespace *bc_init_ns;
	kernel_siginfo_t info;
	struct task_struct *task;
	int retval;

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

static int close_bin_comp_fd(int specfd)
{
	bin_comp_info_t *bi;
	struct file *file;
	int ret = 0;

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
	bi->fd_table[specfd] = 0;

out_unlock:
	write_unlock(&bi->lock);
out:
	return ret;
}

SYSCALL_DEFINE4(el_binary, s64, work, s64, arg2, s64, arg3, s64, arg4)
{
	s64		res = 0;
	thread_info_t	*ti = current_thread_info();

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
		DebugSS("SET_SECONDARY_DESCRIPTOR: desc #%lld, desc.lo = "
			"0x%llx, desc.hi = 0x%llx\n",
			arg2, arg3, arg4);
		switch (arg2) {
		case CS_SELECTOR:
			WRITE_CS_LO_REG_VALUE(I32_ADDR_TO_E2K(arg3));
			WRITE_CS_HI_REG_VALUE(arg4);
			break;
		case DS_SELECTOR:
			WRITE_DS_LO_REG_VALUE(I32_ADDR_TO_E2K(arg3));
			WRITE_DS_HI_REG_VALUE(arg4);
			break;
		case ES_SELECTOR:
			WRITE_ES_LO_REG_VALUE(I32_ADDR_TO_E2K(arg3));
			WRITE_ES_HI_REG_VALUE(arg4);
			break;
		case SS_SELECTOR:
			WRITE_SS_LO_REG_VALUE(I32_ADDR_TO_E2K(arg3));
			WRITE_SS_HI_REG_VALUE(arg4);
			break;
		case FS_SELECTOR:
			WRITE_FS_LO_REG_VALUE(I32_ADDR_TO_E2K(arg3));
			WRITE_FS_HI_REG_VALUE(arg4);
			break;
		case GS_SELECTOR:
			WRITE_GS_LO_REG_VALUE(I32_ADDR_TO_E2K(arg3));
			WRITE_GS_HI_REG_VALUE(arg4);
			break;
		default:
			DebugSS("SET_SECONDARY_DESCRIPTOR: Invalid descriptor #%lld\n",
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
		DebugSS("SET_RP_BOUNDS_AND_IP: start = 0x%llx, end = 0x%llx, IP = 0x%llx\n",
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
		DebugSS("GET_PROTOCOL_VERSION: %d\n",
			BINCO_PROTOCOL_VERSION);
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
		DebugSS("SET_UPT_AEC_AD_SHIFT_DSBL: set = %lld\n", arg2);
		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;
		if (machine.native_iset_ver >= E2K_ISET_V6)
			on_each_cpu(set_upt_sec_ad_shift_dsbl, (void *)arg2, 1);
		else
			res = -EPERM;
		break;
	case GET_UPT_SEC_AD_SHIFT_DSBL:
		DebugSS("SET_UPT_AEC_AD_SHIFT_DSBL\n");
		if (machine.native_iset_ver >= E2K_ISET_V6) {
			e2k_cu_hw0_t cu_hw0 = READ_CU_HW0_REG();
			res = cu_hw0.upt_sec_ad_shift_dsbl;
		} else {
			res = -EPERM;
		}
		break;
	case SET_BIN_COMP_INFO:
		DebugSS("SET_BIN_COMP_INFO: info = 0x%llx, size = 0x%llx, pid = %d\n",
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
		DebugSS("BIN_COMP_FD_WRITE: fd = %d, buf = 0x%llx, count = 0x%llx\n",
			(unsigned int)arg2, arg3, arg4);
		res = bin_comp_fd_write(arg2, (const char __user *)arg3, arg4);
		break;
	case IS_BIN_COMP_FD_SET:
		DebugSS("IS_BIN_COMP_SET: fd = %d\n", (unsigned int)arg2);
		res = is_bin_comp_fd_set(arg2);
		break;
	case SET_BIN_COMP_SEARCH_PATH:
		DebugSS("SET_BIN_COMP_SEARCH_PATH: path = %s\n", (const char *)arg2);
		res = set_bin_comp_info_search_path((const char __user *)arg2);
		break;
	case SET_CHILD_IS_SERVING_THREAD:
		DebugSS("SET_CHILD_IS_SERVING_THREAD: cur val = 0x%x, val = 0x%x\n",
			ti->bc_flags, (bool)arg2);
		ti->bc_flags = (bool)arg2 ?
					ti->bc_flags | BC_CHILD_IS_SERVING :
					ti->bc_flags & ~BC_CHILD_IS_SERVING;
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
	case CLOSE_BIN_COMP_FD:
		DebugSS("CLOSE_BIN_COMP_FD: fd = %u\n", (int)arg2);
		res = close_bin_comp_fd((int)arg2);
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

