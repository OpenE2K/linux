#include <asm/fast_syscalls.h>
#include <asm/process.h>
#include <linux/uaccess.h>
#include <asm/unistd.h>

notrace __interrupt __section(".entry.text")
int fast_sys_set_return(u64 ip, int flags)
{
	struct thread_info *const ti = READ_CURRENT_REG();
	e2k_pcsp_lo_t pcsp_lo;
	e2k_pcsp_hi_t pcsp_hi;
	e2k_cr0_hi_t cr0_hi;
	e2k_mem_crs_t *frame, *base;
	u64 prev_ip;

#ifdef	CONFIG_KVM_HOST_MODE
	/* TODO set_retrun does not have a slow counterpart, not implemented for paravirt guest */
	KVM_BUG_ON(test_ti_status_flag(ti, TS_HOST_AT_VCPU_MODE));
#endif

	E2K_FLUSHC;

	if (unlikely(flags))
		return -EINVAL;

	if (unlikely(ip >= USER_DS.seg))
		return -EFAULT;

	pcsp_hi = READ_PCSP_HI_REG(); /* We don't use %pcsp_hi.size */
	pcsp_lo = READ_PCSP_LO_REG();

	base = GET_PCS_BASE(&ti->u_hw_stack);
	frame = (e2k_mem_crs_t *) (AS(pcsp_lo).base + AS(pcsp_hi).ind);

	do {
		--frame;

		cr0_hi = frame->cr0_hi;

		prev_ip = AS(cr0_hi).ip << 3;
	} while (unlikely(prev_ip >= TASK_SIZE && frame > base));

	/* No user frames above? */
	if (unlikely(prev_ip >= TASK_SIZE))
		return -EPERM;

	/* Modify stack */
	AS(cr0_hi).ip = ip >> 3;
	frame->cr0_hi = cr0_hi;

	return 0;
}
