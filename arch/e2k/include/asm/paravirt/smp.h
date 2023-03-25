#ifndef __ASM_PARAVIRT_SMP_H
#define __ASM_PARAVIRT_SMP_H

#include <linux/types.h>
#include <asm/paravirt/pv_ops.h>

#ifdef	CONFIG_SMP
static inline void
pv_wait_for_cpu_booting(void)
{
	pv_cpu_ops.wait_for_cpu_booting();
}
static inline void
pv_wait_for_cpu_wake_up(void)
{
	pv_cpu_ops.wait_for_cpu_wake_up();
}
static inline int
pv_activate_cpu(int cpu_id)
{
	return pv_cpu_ops.activate_cpu(cpu_id);
}
static inline int
pv_activate_all_cpus(void)
{
	return pv_cpu_ops.activate_all_cpus();
}

static inline void
pv_csd_lock_wait(call_single_data_t *data)
{
	pv_cpu_ops.csd_lock_wait(data);
}
static inline void
pv_csd_lock(call_single_data_t *data)
{
	pv_cpu_ops.csd_lock(data);
}
static inline void
pv_arch_csd_lock_async(call_single_data_t *data)
{
	pv_cpu_ops.arch_csd_lock_async(data);
}
static inline void
pv_csd_unlock(call_single_data_t *data)
{
	pv_cpu_ops.csd_unlock(data);
}

static inline void
pv_setup_local_pic_virq(unsigned int cpuid)
{
	if (pv_cpu_ops.setup_local_pic_virq != NULL)
		pv_cpu_ops.setup_local_pic_virq(cpuid);
}
static inline void
pv_startup_local_pic_virq(unsigned int cpuid)
{
	if (pv_cpu_ops.startup_local_pic_virq != NULL)
		pv_cpu_ops.startup_local_pic_virq(cpuid);
}

#ifdef	CONFIG_PARAVIRT_GUEST
/* it is paravirtualized host and guest kernel */
static inline void
wait_for_cpu_booting(void)
{
	pv_wait_for_cpu_booting();
}
static inline void
wait_for_cpu_wake_up(void)
{
	pv_wait_for_cpu_wake_up();
}
static inline int
activate_cpu(int cpu_id)
{
	return pv_activate_cpu(cpu_id);
}
static inline int
activate_all_cpus(void)
{
	return pv_activate_all_cpus();
}

static inline void
csd_lock_wait(call_single_data_t *data)
{
	pv_csd_lock_wait(data);
}
static inline void
csd_lock(call_single_data_t *data)
{
	pv_csd_lock(data);
}
static inline void
arch_csd_lock_async(call_single_data_t *data)
{
	pv_arch_csd_lock_async(data);
}
static inline void
csd_unlock(call_single_data_t *data)
{
	pv_csd_unlock(data);
}

static inline void
setup_local_pic_virq(unsigned int cpuid)
{
	pv_setup_local_pic_virq(cpuid);
}

static inline void
startup_local_pic_virq(unsigned int cpuid)
{
	pv_startup_local_pic_virq(cpuid);
}
#endif	/* CONFIG_PARAVIRT_GUEST */

#endif	/* CONFIG_SMP */
#endif	/* __ASM_PARAVIRT_SMP_H */
