/*
 * arch/e2k/kernel/sec_space.c
 *
 * Secondary space support for E2K binary compiler
 *
 */
#include <linux/kernel.h>
#include <linux/signal.h>
#include <linux/irqflags.h>
#include <linux/sched/task.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/file.h>
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
#define DebugSS(...)		DebugPrint(DEBUG_SS_MODE ,##__VA_ARGS__)

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

static bin_comp_info_t *alloc_bin_comp_info(unsigned long size)
{
	void *info;

	info = kzalloc(size, GFP_KERNEL);
	return info ? info : NULL;
}

void free_bin_comp_info(bin_comp_info_t *bi)
{
	kfree(bi->info);
	bi->info = NULL;
}

int copy_bin_comp_info(bin_comp_info_t *oldbi, struct mm_struct *mm)
{
	bin_comp_info_t	*bi = &mm->context.bincomp_info;

	BUG_ON(!oldbi->info);

	bi->info = alloc_bin_comp_info(oldbi->size);
	if (!bi->info)
		return -ENOMEM;

	memcpy(bi->info, oldbi->info, oldbi->size);
	bi->size = oldbi->size;

	return 0;
}

static int set_user_bin_comp_info(void __user *addr, unsigned long size, int pid)
{
	bin_comp_info_t *bi;
	struct task_struct *p;
	struct mm_struct *mm;
	void *info, *info_to_free = NULL;
	int ret = 0;

	p = (current->pid == pid) ? current : find_task_by_vpid(pid);
	if (!p)
		return -ESRCH;

	get_task_struct(p);

	mm = get_task_mm(p);
	if (!mm) {
		ret = -EACCES;
		goto out_put_task;
	}

	bi = &mm->context.bincomp_info;

	info = alloc_bin_comp_info(size);
	if (!info) {
		ret = -ENOMEM;
		goto out_put_mm;
	}

	info_to_free = info;

	if (copy_from_user(info, addr, size)) {
		ret = -EFAULT;
		goto out_free_info;
	}

	write_lock(&bi->lock);

	info_to_free = bi->info ?: NULL;

	bi->info = info;
	bi->size = size;

	write_unlock(&bi->lock);

out_free_info:
	kfree(info_to_free);

out_put_mm:
	mmput(mm);

out_put_task:
	put_task_struct(p);
	return ret;
}

static int get_user_bin_comp_info(void __user *addr, int pid)
{
	struct task_struct *p;
	struct mm_struct *mm;
	bin_comp_info_t *bi;
	int ret = 0;

	p = (current->pid == pid) ? current : find_task_by_vpid(pid);
	if (!p)
		return -ESRCH;

	get_task_struct(p);

	mm = get_task_mm(p);
	if (!mm) {
		ret = -EACCES;
		goto out_put_task;
	}

	bi = &mm->context.bincomp_info;

	read_lock(&bi->lock);
	if (bi) {
		WARN_ON(bi->size == 0);
		if (copy_to_user(addr, bi->info, bi->size))
			ret = -EFAULT;
	} else {
		ret = -EACCES;
	}
	read_unlock(&bi->lock);

	mmput(mm);

out_put_task:
	put_task_struct(p);
	return ret;
}

static int set_rlim(unsigned int resource, struct rlimit __user *rlim, int pid)
{
	struct rlimit r;
	struct task_struct *p;

	if (resource >= BINCOMP_RLIM_NLIMITS)
		return -EINVAL;

	if (copy_from_user(&r, rlim, sizeof(*rlim)))
		return -EFAULT;

	p = (current->pid == pid) ? current : find_task_by_vpid(pid);
	if (!p)
		return -ESRCH;

	get_task_struct(p);
	read_lock(&tasklist_lock);
	task_lock(p->group_leader);

	p->signal->bin_comp_rlim[resource] = r;

	task_unlock(p->group_leader);
	read_unlock(&tasklist_lock);
	put_task_struct(p);

	return 0;
}

static int get_rlim(unsigned int resource, struct rlimit __user *rlim, int pid)
{
	struct rlimit *r;
	struct task_struct *p;
	int ret = 0;

	if (resource >= BINCOMP_RLIM_NLIMITS)
		return -EINVAL;

	p = (current->pid == pid) ? current : find_task_by_vpid(pid);
	if (!p)
		return -ESRCH;

	get_task_struct(p);
	read_lock(&tasklist_lock);
	task_lock(p->group_leader);

	r = &p->signal->bin_comp_rlim[resource];
	ret = copy_to_user(rlim, r, sizeof(*rlim)) ? -EFAULT : 0;

	task_unlock(p->group_leader);
	read_unlock(&tasklist_lock);
	put_task_struct(p);

	return ret;
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

static ssize_t bin_comp_fd_write(unsigned int fd, const char __user *buf, size_t count)
{
	mm_context_t *ctx = &current->mm->context;
	bin_comp_fdt_t *fdt;
	struct file *file;
	loff_t pos, *ppos;
	bool locked;
	ssize_t ret;

	if (fd >= BIN_COMP_FD_MAX)
		return -EINVAL;

	read_lock(&ctx->bincomp_fdt_lock);
	fdt = ctx->bincomp_fdt;
	read_unlock(&ctx->bincomp_fdt_lock);

	if (!fdt)
		return -EACCES;

	read_lock(&fdt->lock);
	file = fdt->fd[fd];
	read_unlock(&fdt->lock);

	if (!file)
		return -EINVAL;

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

	return ret;
}

static bin_comp_fdt_t *alloc_bin_comp_fdt(void)
{
	bin_comp_fdt_t *fdt;

	fdt = kzalloc(sizeof(*fdt), GFP_KERNEL);
	if (!fdt)
		return NULL;

	atomic_set(&fdt->usage, 1);
	rwlock_init(&fdt->lock);

	return fdt;
}

void free_bin_comp_fdt(bin_comp_fdt_t *fdt)
{
	int i = 0;

	if (!atomic_sub_and_test(1, &fdt->usage))
		return;

	for (; i < BIN_COMP_FD_MAX; i++) {
		if (fdt->fd[i])
			fput(fdt->fd[i]);
	}

	kfree(fdt);
}

static int set_bin_comp_fd(unsigned int fd)
{
	struct fd f = fdget(fd);
	mm_context_t *ctx = &current->mm->context;
	bin_comp_fdt_t *fdt;
	int ret = 0;

	if (!f.file) {
		ret = -EBADF;
		goto out_fd;
	}

	write_lock(&ctx->bincomp_fdt_lock);

	if (!ctx->bincomp_fdt) {
		ctx->bincomp_fdt = alloc_bin_comp_fdt();
		if (!ctx->bincomp_fdt) {
			ret =  -ENOMEM;
			write_unlock(&ctx->bincomp_fdt_lock);
			goto out_fd;
		}
	}

	write_unlock(&ctx->bincomp_fdt_lock);

	fdt = ctx->bincomp_fdt;

	write_lock(&fdt->lock);

	if (fdt->pos > BIN_COMP_FD_MAX - 1) {
		ret = -EACCES;
		goto out_fd_lock;
	}

	ret = fdt->pos;
	fdt->fd[fdt->pos++] = f.file;
	get_file(f.file);

out_fd_lock:
	write_unlock(&fdt->lock);

out_fd:
	fdput(f);
	return ret;
}

s64 sys_el_binary(s64 work, s64 arg2, s64 arg3, s64 arg4)
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
		res = set_user_bin_comp_info((void *)arg2, arg3, arg4);
		break;
	case GET_BIN_COMP_INFO:
		DebugSS("GET_BIN_COMP_INFO: info = 0x%llx, pid = %d\n",
			arg2, (int)arg3);
		res = get_user_bin_comp_info((void *)arg2, arg3);
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
		DebugSS("SET_BIN_COMP_FD: fd = 0x%d\n", (unsigned int)arg2);
		res = set_bin_comp_fd(arg2);
		break;
	case BIN_COMP_FD_WRITE:
		DebugSS("SET_BIN_COMP_FD: fd = 0x%d, buf = 0x%llx, count = 0x%llx\n",
			(unsigned int)arg2, arg3, arg4);
		res = bin_comp_fd_write(arg2, (const char *)arg3, arg4);
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

