/*
 *  arch/e2k/kvm/process.c
 *
 * This file handles the arch-dependent parts of kvm process handling
 *
 * Copyright 2011 Salavat S. Guiliazov (atic@mcst.ru)
 */

#include <linux/types.h>
#include <linux/syscalls.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/tty.h>
#include <linux/freezer.h>
#include <linux/kvm_host.h>
#include <linux/kvm.h>
#include <linux/mman.h>

#include <asm/thread_info.h>
#include <asm/process.h>
#include <asm/traps.h>
#include <asm/syscalls.h>
#include <asm/mmu_context.h>
#include <asm/kvm/runstate.h>
#include <asm/kvm/switch.h>
#include <asm/kvm/async_pf.h>

#include "process.h"
#include "cpu.h"
#include "mman.h"
#include "mmu.h"
#include "io.h"
#include "gaccess.h"
#include "time.h"
#include "pic.h"


#undef	DEBUG_KVM_MODE
#undef	DebugKVM
#define	DEBUG_KVM_MODE	0	/* kernel virtual machine debugging */
#define	DebugKVM(fmt, args...)						\
({									\
	if (DEBUG_KVM_MODE)						\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_THREAD_MODE
#undef	DebugKVMT
#define	DEBUG_KVM_THREAD_MODE	0	/* KVM thread debugging */
#define	DebugKVMT(fmt, args...)						\
({									\
	if (DEBUG_KVM_THREAD_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_KERNEL_MODE
#undef	DebugKVMKS
#define	DEBUG_KVM_KERNEL_MODE	0	/* KVM process copy debugging */
#define	DebugKVMKS(fmt, args...)					\
({									\
	if (DEBUG_KVM_KERNEL_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_STARTUP_MODE
#undef	DebugKVMSTUP
#define	DEBUG_KVM_STARTUP_MODE	0	/* VCPU startup debugging */
#define	DebugKVMSTUP(fmt, args...)					\
({									\
	if (DEBUG_KVM_STARTUP_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_EXEC_MODE
#undef	DebugKVMEX
#define	DEBUG_KVM_EXEC_MODE	0	/* KVM execve() debugging */
#define	DebugKVMEX(fmt, args...)					\
({									\
	if (DEBUG_KVM_EXEC_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_CLONE_USER_MODE
#undef	DebugKVMCLN
#define	DEBUG_KVM_CLONE_USER_MODE	0	/* KVM thread clone debug */
#define	DebugKVMCLN(fmt, args...)					\
({									\
	if (DEBUG_KVM_CLONE_USER_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_COPY_USER_MODE
#undef	DebugKVMCPY
#define	DEBUG_KVM_COPY_USER_MODE	0	/* KVM thread clone debugging */
#define	DebugKVMCPY(fmt, args...)					\
({									\
	if (DEBUG_KVM_COPY_USER_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_SIGNAL_MODE
#undef	DebugSIG
#define	DEBUG_SIGNAL_MODE	0	/* signal handling debugging */
#define	DebugSIG(fmt, args...)						\
({									\
	if (DEBUG_SIGNAL_MODE)						\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_THREAD_INFO_MODE
#undef	DebugKVMTI
#define	DEBUG_KVM_THREAD_INFO_MODE	0	/* KVM thread info debug */
#define	DebugKVMTI(fmt, args...)					\
({									\
	if (DEBUG_KVM_THREAD_INFO_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_FREE_TASK_STRUCT_MODE
#undef	DebugFRTASK
#define	DEBUG_FREE_TASK_STRUCT_MODE	0	/* free thread info debug */
#define	DebugFRTASK(fmt, args...)					\
({									\
	if (DEBUG_FREE_TASK_STRUCT_MODE)				\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_ACTIVATION_MODE
#undef	DebugKVMACT
#define	DEBUG_KVM_ACTIVATION_MODE	0	/* KVM guest kernel data */
						/* stack activations */
						/* debugging */
#define	DebugKVMACT(fmt, args...)					\
({									\
	if (DEBUG_KVM_ACTIVATION_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_HOST_ACTIVATION_MODE
#undef	DebugHACT
#define	DEBUG_HOST_ACTIVATION_MODE	0	/* KVM host kernel data */
						/* stack activations */
						/* debugging */
#define	DebugHACT(fmt, args...)						\
({									\
	if (DEBUG_HOST_ACTIVATION_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_SWITCH_VCPU_MODE
#undef	DebugSWVCPU
#define	DEBUG_KVM_SWITCH_VCPU_MODE	false	/* guest thread switch to */
						/* other VCPU */
#define	DebugSWVCPU(fmt, args...)					\
({									\
	if (DEBUG_KVM_SWITCH_VCPU_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_GPT_REGS_MODE
#define	DEBUG_GPT_REGS_MODE	0	/* KVM host and guest kernel */
					/* stack activations print */
#define	DebugHACT(fmt, args...)						\
({									\
	if (DEBUG_HOST_ACTIVATION_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_SWITCH_HS_MODE
#undef	DebugKVMSW
#define	DEBUG_KVM_SWITCH_HS_MODE	0	/* KVM switch guest hardware */
						/* stacks */
#define	DebugKVMSW(fmt, args...)					\
({									\
	if (DEBUG_KVM_SWITCH_HS_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_SHUTDOWN_MODE
#undef	DebugKVMSH
#define	DEBUG_KVM_SHUTDOWN_MODE	0	/* KVM shutdown debugging */
#define	DebugKVMSH(fmt, args...)					\
({									\
	if (DEBUG_KVM_SHUTDOWN_MODE || kvm_debug)			\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_IRQ_MODE
#undef	DebugKVMIRQ
#define	DEBUG_KVM_IRQ_MODE	0	/* KVM shutdown debugging */
#define	DebugKVMIRQ(fmt, args...)					\
({									\
	if (DEBUG_KVM_IRQ_MODE)						\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_VIRQs_MODE
#undef	DebugVIRQs
#define	DEBUG_KVM_VIRQs_MODE	debug_guest_virqs	/* VIRQs debugging */
#define	DebugVIRQs(fmt, args...)					\
({									\
	if (DEBUG_KVM_VIRQs_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_IDLE_MODE
#undef	DebugKVMIDLE
#define	DEBUG_KVM_IDLE_MODE	0	/* KVM guest idle debugging */
#define	DebugKVMIDLE(fmt, args...)					\
({									\
	if (DEBUG_KVM_IDLE_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_SHOW_GUEST_STACKS_MODE
#undef	DebugGST
#define	DEBUG_SHOW_GUEST_STACKS_MODE	true	/* show all guest stacks */
#define	DebugGST(fmt, args...)						\
({									\
	if (DEBUG_SHOW_GUEST_STACKS_MODE)				\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_TO_VIRT_MODE
#undef	DebugTOVM
#define	DEBUG_KVM_TO_VIRT_MODE	0	/* switch guest to virtual mode */
#define	DebugTOVM(fmt, args...)						\
({									\
	if (DEBUG_KVM_TO_VIRT_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_USER_STACK_MODE
#undef	DebugGUS
#define	DEBUG_KVM_USER_STACK_MODE	0	/* guest user stacks */
#define	DebugGUS(fmt, args...)						\
({									\
	if (DEBUG_KVM_USER_STACK_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})
static bool debug_copy_guest = false;
bool debug_clone_guest = false;

#undef	DEBUG_KVM_GUEST_MM_MODE
#undef	DebugGMM
#define	DEBUG_KVM_GUEST_MM_MODE	0	/* guest MM support */
#define	DebugGMM(fmt, args...)						\
({									\
	if (DEBUG_KVM_GUEST_MM_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_SIG_HANDLER_MODE
#undef	DebugSIGH
#define	DEBUG_KVM_SIG_HANDLER_MODE	0	/* signal handler debug */
#define	DebugSIGH(fmt, args...)						\
({									\
	if (DEBUG_KVM_SIG_HANDLER_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_LONG_JUMP_MODE
#undef	DebugLJMP
#define	DEBUG_KVM_LONG_JUMP_MODE	0	/* long jump debug */
#define	DebugLJMP(fmt, args...)						\
({									\
	if (DEBUG_KVM_LONG_JUMP_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

int clone_guest_kernel = 0;

static gthread_info_t *alloc_guest_thread_info(struct kvm *kvm);
static void free_guest_thread_info(struct kvm *kvm, gthread_info_t *gti);
static void do_free_guest_thread_info(struct kvm *kvm, gthread_info_t *gti);
static int kvm_guest_failed(struct kvm_vcpu *vcpu);

#define	SET_VCPU_BREAKPOINT	false

#ifdef	CONFIG_DATA_BREAKPOINT
atomic_t hw_data_breakpoint_num = ATOMIC_INIT(-1);
#endif	/* CONFIG_DATA_BREAKPOINT */

#ifdef	CONFIG_KVM_HOST_MODE
/* It is paravirtualized host and guest kernel */
/* or native host kernel with virtualization support */
/* FIXME: kvm host and hypervisor features is not supported on guest mode */
/* and all files from arch/e2k/kvm should not be compiled for guest kernel */
/* only arch/e2k/kvm/guest/ implements guest kernel support */
/* So this ifdef should be deleted after excluding arch/e2k/kvm compilation */
noinline notrace long
as_guest_entry_start(unsigned long arg0, unsigned long arg1,
			unsigned long arg2, unsigned long arg3,
			char *entry_point, bool priv_guest)
{
	/*
	 * Do not update this function. Any new operators can change
	 * behaviour and goal of the function - simulate guest
	 * at start point was interrupted by go2user() function
	 */
	go2guest((unsigned long)entry_point, priv_guest);
	/* here we should not be never */
	return arg0;
}
#endif	/* CONFIG_KVM_HOST_MODE */

/**
 * The function return bool value - should this guest kernel thread be stopped
 * now?
 *
 * When someone calls kvm_guest_vcpu_thread_stop() on your kthread, it will be
 * woken and this will return true.
 */
bool kvm_guest_vcpu_thread_should_stop(struct kvm_vcpu *vcpu)
{
	BUG_ON(vcpu == NULL);
	BUG_ON(!vcpu->arch.is_hv && vcpu->arch.host_task != current);
	return vcpu->arch.should_stop ||
		vcpu->kvm->arch.halted ||
		vcpu->kvm->arch.reboot;
}

gthread_info_t *create_guest_start_thread_info(struct kvm_vcpu *vcpu)
{
	gthread_info_t	*gthread_info;

	DebugKVMTI("started to launch guest kernel on VCPU %d\n",
		vcpu->vcpu_id);

	gthread_info = alloc_guest_thread_info(vcpu->kvm);
	if (gthread_info == NULL) {
		DebugKVMTI("could not create guest thread info\n");
		return NULL;
	}
	set_gti_thread_flag(gthread_info, GTIF_VCPU_START_THREAD);
	set_gti_thread_flag(gthread_info, GTIF_KERNEL_THREAD);
	kvm_gmm_get(vcpu, gthread_info, pv_vcpu_get_init_gmm(vcpu));
	pv_vcpu_set_active_gmm(vcpu, pv_vcpu_get_init_gmm(vcpu));
	setup_vcpu_boot_stacks(vcpu, gthread_info);
	return gthread_info;
}

/*
 * There are two VCPU threads: host thread and guest thread.
 * Both threads are created and executed as user threads on host
 * Host VCPU thread execute QEMU (virtual machine simulation) and
 * start guest VCPU run, handle exit reasons from guest VCPU,
 * resume VCPU execution, terminate VCPU running
 * Guest VCPU thread is created by host VCPU thread and execute
 * guest kernel on this thread (as one of guest VCPUs)
 * Guest VCPU thread creates VIRQ VCPU threads to handle virtual
 * interrupts
 */
void kvm_clear_host_thread_info(thread_info_t *ti)
{
	/* each VCPU can has own root pgd */
	ti->kernel_image_pgd_p = NULL;
	pgd_val(ti->kernel_image_pgd) = 0;

	/* guest thread info does not yet created */
	ti->gthread_info = NULL;

	INIT_LIST_HEAD(&ti->tasks_to_spin);
	ti->gti_to_spin = NULL;

	/* VCPU is not yet created */
	clear_ti_thread_flag(ti, TIF_VIRTUALIZED_HOST);
	clear_ti_thread_flag(ti, TIF_VIRTUALIZED_GUEST);
	clear_ti_thread_flag(ti, TIF_PARAVIRT_GUEST);
}

static inline void resume_host_start_thread(struct kvm_vcpu *vcpu)
{
	DebugKVMSH("started on %s (%d) VCPU #%d\n",
		current->comm, current->pid, vcpu->vcpu_id);
	BUG_ON(vcpu == NULL);
	if (vcpu->arch.host_task == NULL) {
		DebugKVMSH("host VCPU #%d thread is already halted or not "
			"started\n", vcpu->vcpu_id);
	} else if (vcpu->arch.host_task != current) {
		/* it is not thread of VCPU host process */
		BUG_ON(1);
		return;
	}

	/* from here the thread will be as common thread */
	clear_thread_flag(TIF_VIRTUALIZED_HOST);
	clear_thread_flag(TIF_MULTITHREADING);

	kvm_halt_host_vcpu_thread(vcpu);
}

int kvm_resume_vm_thread(void)
{
	if (!test_thread_flag(TIF_MULTITHREADING))
		return 0;

	if (test_thread_flag(TIF_VIRTUALIZED_HOST))
		resume_host_start_thread(current_thread_info()->vcpu);
	else if (test_thread_flag(TIF_VIRTUALIZED_GUEST))
		return kvm_guest_failed(current_thread_info()->vcpu);
	clear_thread_flag(TIF_MULTITHREADING);
	return 0;
}

void kvm_spare_host_vcpu_release(struct kvm_vcpu *vcpu)
{
	DebugKVMSH("%s (%d) started for VCPU #%d\n",
		current->comm, current->pid, vcpu->vcpu_id);
	resume_host_start_thread(vcpu);
}

/*
 * same as prepare_bu_stacks_to_startup_vcpu() but only for paravirtualization
 * and boot stacks are from guest memory space
 */
static int prepare_pv_stacks_to_startup_vcpu(struct kvm_vcpu *vcpu,
			guest_hw_stack_t *stack_regs,
			u64 *args, int args_num,
			char *entry_point, e2k_psr_t psr,
			e2k_size_t usd_size, void *ps_base, void *pcs_base,
			int cui, bool kernel)
{
	e2k_mem_crs_t pcs_frames[2];
	e2k_mem_ps_t ps_frames[8 * sizeof(*args) / (EXT_4_NR_SZ / 2)];
	e2k_mem_crs_t *g_pcs_frames;
	e2k_mem_ps_t *g_ps_frames;
	e2k_size_t ps_ind, pcs_ind;
	int up_frame, ret;

	DebugKVMSTUP("started on VCPU #%d base PS %px, PCS %px\n",
		vcpu->vcpu_id, ps_base, pcs_base);

	/*max number of arguments limited by above ps_frames[] size */
	KVM_BUG_ON(args_num > 8);

	prepare_stacks_to_startup_vcpu(vcpu, ps_frames, pcs_frames,
		args, args_num, entry_point, psr,
		usd_size, &ps_ind, &pcs_ind, cui, kernel);

	g_ps_frames = (e2k_mem_ps_t *)ps_base;
	g_pcs_frames = (e2k_mem_crs_t *)pcs_base;
	ret = kvm_vcpu_copy_to_guest(vcpu, g_ps_frames, ps_frames, ps_ind);
	if (unlikely(ret < 0)) {
		pr_err("%s(): could not prepare initial content of "
			"guest boot procedure stack, error %d\n",
			__func__, ret);
		return ret;
	}
	/* very UP frame of chain stack will be loaded on registers */
	/* directly by host before return to guest */
	up_frame = pcs_ind / SZ_OF_CR - 1;
	stack_regs->crs.cr0_lo = pcs_frames[up_frame].cr0_lo;
	stack_regs->crs.cr0_hi = pcs_frames[up_frame].cr0_hi;
	stack_regs->crs.cr1_lo = pcs_frames[up_frame].cr1_lo;
	stack_regs->crs.cr1_hi = pcs_frames[up_frame].cr1_hi;

	ret = kvm_vcpu_copy_to_guest(vcpu, g_pcs_frames, pcs_frames, pcs_ind);
	if (unlikely(ret < 0)) {
		pr_err("%s(): could not prepare initial content of "
			"guest boot chain stack, error %d\n",
			__func__, ret);
		return ret;
	}

	/* correct stacks pointers indexes */
	stack_regs->stacks.psp_hi.PSP_hi_ind = ps_ind;
	stack_regs->stacks.pcsp_hi.PCSP_hi_ind = pcs_ind - SZ_OF_CR;
	DebugKVMSTUP("VCPU #%d boot PS.ind 0x%x PCS.ind 0x%x\n",
		vcpu->vcpu_id,
		stack_regs->stacks.psp_hi.PSP_hi_ind,
		stack_regs->stacks.pcsp_hi.PCSP_hi_ind);
	return 0;
}

struct tty_struct *kvm_tty = NULL;

int kvm_init_vcpu_thread(struct kvm_vcpu *vcpu)
{
	char name[80];

	sprintf(name, "kvm/%d-vcpu/%d",
		vcpu->kvm->arch.vmid.nr, vcpu->vcpu_id);
	set_task_comm(current, name);
	vcpu->arch.host_task = current;

	INIT_LIST_HEAD(&current_thread_info()->tasks_to_spin);
	current_thread_info()->gti_to_spin = NULL;

	DebugKVM("VCPU %d will be run as thread %s (%d) pgd %px\n",
		vcpu->vcpu_id, current->comm, current->pid, current->mm->pgd);

	return 0;
}

int hv_vcpu_start_thread(struct kvm_vcpu *vcpu)
{
	return kvm_init_vcpu_thread(vcpu);
}

int pv_vcpu_start_thread(struct kvm_vcpu *vcpu)
{
	gthread_info_t	*gthread_info;
	int ret;

	ret = kvm_init_vcpu_thread(vcpu);
	if (ret) {
		pr_err("%s(): could not init start thread for VCPU #%d "
			"error %d\n",
			__func__, vcpu->vcpu_id, ret);
		goto out_failed;
	}
	gthread_info = create_guest_start_thread_info(vcpu);
	if (gthread_info == NULL) {
		pr_err("%s() could not create guest start thread info "
			"structure\n",
			__func__);
		ret = -ENOMEM;
		goto out_failed;
	}
	pv_vcpu_set_gti(vcpu, gthread_info);

	return 0;

out_failed:
	return ret;
}

int kvm_prepare_pv_vcpu_start_stacks(struct kvm_vcpu *vcpu)
{
	vcpu_boot_stack_t *boot_stacks = &vcpu->arch.boot_stacks;
	e2k_stacks_t *regs = &boot_stacks->regs.stacks;
	int ret;

	DebugKVM("started to prepare boot stacks on VCPU #%d\n",
		vcpu->vcpu_id);

	prepare_vcpu_startup_args(vcpu);
	ret = prepare_pv_stacks_to_startup_vcpu(vcpu,
			&boot_stacks->regs,
			vcpu->arch.args, vcpu->arch.args_num,
			vcpu->arch.entry_point, E2K_USER_INITIAL_PSR,
			GET_VCPU_BOOT_CS_SIZE(boot_stacks),
			GET_VCPU_BOOT_PS_BASE(boot_stacks),
			GET_VCPU_BOOT_PCS_BASE(boot_stacks), 0, true);
	if (ret) {
		pr_err("%s(): failed to prepare VCPU #%d boot stacks, "
			"error %d\n",
			__func__, vcpu->vcpu_id, ret);
		return ret;
	}

	/* Make sure guest sees actual values of its own registers */
	kvm_set_guest_vcpu_PSP_lo(vcpu, regs->psp_lo);
	kvm_set_guest_vcpu_PSP_hi(vcpu, regs->psp_hi);
	kvm_set_guest_vcpu_PCSP_lo(vcpu, regs->pcsp_lo);
	kvm_set_guest_vcpu_PCSP_hi(vcpu, regs->pcsp_hi);
	kvm_set_guest_vcpu_USD_lo(vcpu, regs->usd_lo);
	kvm_set_guest_vcpu_USD_hi(vcpu, regs->usd_hi);
	kvm_set_guest_vcpu_SBR(vcpu, regs->top);

	return 0;
}

static gthread_info_t *alloc_guest_thread_info(struct kvm *kvm)
{
	gthread_info_t *gthread_info;
	gpid_t *gpid = NULL;

	DebugKVMTI("started\n");
	gthread_info = kmem_cache_alloc(kvm->arch.gti_cachep,
					GFP_KERNEL | __GFP_ZERO);
	if (!gthread_info) {
		DebugKVMTI("could not allocate guest thread info structure\n");
		goto out;
	}

	gpid = kvm_alloc_gpid(&kvm->arch.gpid_table);
	if (!gpid) {
		DebugKVMTI("could not allocate guest PID\n");
		goto out_free;
	}
	gpid->gthread_info = gthread_info;
	gthread_info->gpid = gpid;
	gthread_info->vcpu = NULL;
	gthread_info->gmm = NULL;
	gthread_info->nonp_root_hpa = E2K_INVALID_PAGE;
	init_pv_vcpu_l_gregs(gthread_info);
/*	gthread_info->upsr = E2K_USER_INITIAL_UPSR; */
	DebugKVMTI("allocated guest thread info GPID %d\n", gpid->nid.nr);

out:
	return gthread_info;

out_free:

	kmem_cache_free(kvm->arch.gti_cachep, gthread_info);
	gthread_info = NULL;
	goto out;
}

/*
 * Clear guest thread info structure from old user task,
 * while sys_execve() of new user task
 */
void kvm_pv_clear_guest_thread_info(gthread_info_t *gthread_info)
{
	gthread_info->gpid = NULL;	/* not exist */
	gthread_info->gmm = NULL;
	gthread_info->gregs_active = 0;
	gthread_info->gregs_valid = 0;
	gthread_info->gregs_for_currents_valid = 0;
	gthread_info->u_upsr_valid = false;
	gthread_info->k_upsr_valid = false;
	gthread_info->gpt_regs = NULL;
}

static void __free_guest_thread_info(struct kvm *kvm, gthread_info_t *gti,
					bool lock_done)
{
	DebugKVMTI("started for GPID %d\n", gti->gpid->nid.nr);

	if (likely(!lock_done)) {
		kvm_free_gpid(gti->gpid, &kvm->arch.gpid_table);
	} else {
		kvm_do_free_gpid(gti->gpid, &kvm->arch.gpid_table);
	}

	kmem_cache_free(kvm->arch.gti_cachep, gti);
}

static void free_guest_thread_info(struct kvm *kvm, gthread_info_t *gti)
{
	__free_guest_thread_info(kvm, gti, false);
}

static void do_free_guest_thread_info(struct kvm *kvm, gthread_info_t *gti)
{
	__free_guest_thread_info(kvm, gti, true);
}

int kvm_pv_guest_thread_info_init(struct kvm *kvm)
{
	int ret;

	DebugKVMTI("started\n");

	sprintf(kvm->arch.gti_cache_name, "gthread_info_VM%d",
						kvm->arch.vmid.nr);
	kvm->arch.gti_cachep =
		kmem_cache_create(kvm->arch.gti_cache_name,
					sizeof(gthread_info_t), 0,
					SLAB_HWCACHE_ALIGN, NULL);
	if (kvm->arch.gti_cachep == NULL) {
		DebugKVMTI("could not allocate guest kernel info cache\n");
		return -ENOMEM;
	}

	ret = kvm_gpidmap_init(kvm, &kvm->arch.gpid_table,
				kvm->arch.gpid_nidmap, GPIDMAP_ENTRIES,
				kvm->arch.gpid_hash, GPID_HASH_BITS);
	if (ret != 0) {
		kmem_cache_destroy(kvm->arch.gti_cachep);
		kvm->arch.gti_cachep = NULL;
	}

	return ret;
}

void kvm_pv_guest_thread_info_destroy(struct kvm *kvm)
{
	gpid_t *gpid;
	struct hlist_node *next;
	unsigned long flags;
	int i;

	DebugKVMTI("started\n");
	gpid_table_lock_irqsave(&kvm->arch.gpid_table, flags);
	for_each_guest_thread_info(gpid, i, next, &kvm->arch.gpid_table) {
		do_free_guest_thread_info(kvm, gpid->gthread_info);
	}
	gpid_table_unlock_irqrestore(&kvm->arch.gpid_table, flags);
	kmem_cache_destroy(kvm->arch.gti_cachep);
	kvm->arch.gti_cachep = NULL;
	kvm_gpidmap_destroy(&kvm->arch.gpid_table);
}

static int kvm_get_guest_kernel_stacks(struct kvm_vcpu *vcpu,
		kvm_task_info_t	*user_info, guest_hw_stack_t *stack_regs,
		u64 *args, int args_num, char *entry_point)
{
	thread_info_t	*ti = current_thread_info();
	gthread_info_t	*gti = pv_vcpu_get_gti(vcpu);
	e2k_usd_lo_t	usd_lo;
	e2k_usd_hi_t	usd_hi;
	e2k_addr_t	sbr;
	e2k_size_t	us_size;
	e2k_psp_lo_t	psp_lo;
	e2k_psp_hi_t	psp_hi;
	e2k_pcsp_lo_t	pcsp_lo;
	e2k_pcsp_hi_t	pcsp_hi;
	e2k_addr_t	ps_base;
	e2k_size_t	ps_size;
	e2k_addr_t	pcs_base;
	e2k_size_t	pcs_size;
	e2k_psr_t	psr;
	bool priv_guest = vcpu->arch.is_hv;
	int		ret;

	DebugKVM("started\n");

	/*
	 * New guest kernel stacks (data and hardware) were allocated by guest
	 * Create all register state for new guest stacks
	 */
	us_size = user_info->us_size;
	sbr = user_info->us_base + us_size;	/* top of stack */
	usd_hi.USD_hi_half = 0;
	usd_lo.USD_lo_half = 0;
	usd_hi.USD_hi_size = user_info->sp_offset;
	usd_lo.USD_lo_base = user_info->us_base + user_info->sp_offset;

	psp_hi.PSP_hi_half = 0;
	psp_lo.PSP_lo_half = 0;
	ps_size = user_info->ps_size;
	ps_base = user_info->ps_base;
	psp_hi.PSP_hi_size = ps_size;
	psp_lo.PSP_lo_base = ps_base;

	pcsp_hi.PCSP_hi_half = 0;
	pcsp_lo.PCSP_lo_half = 0;
	pcs_size = user_info->pcs_size;
	pcs_base = user_info->pcs_base;
	pcsp_hi.PCSP_hi_size = pcs_size;
	pcsp_lo.PCSP_lo_base = pcs_base;

	stack_regs->stacks.top = sbr;
	stack_regs->stacks.usd_hi = usd_hi;
	stack_regs->stacks.usd_lo = usd_lo;
	if (gti != NULL) {
		gti->g_usd_lo = usd_lo;
		gti->g_usd_hi = usd_hi;
		gti->g_sbr.SBR_reg = stack_regs->stacks.top;
		gti->us_size = us_size;
	}
	DebugTOVM("new local guest kernel data stack base 0x%llx size 0x%x "
		"top 0x%lx\n",
		 usd_lo.USD_lo_base, usd_hi.USD_hi_size, sbr);

	/* host kernel data stack does not changed */
	DebugTOVM("host kernel current data stack bottom 0x%lx "
		"base 0x%llx size 0x%x\n",
		current->stack, ti->k_usd_lo.USD_lo_base,
		ti->k_usd_hi.USD_hi_size);

	BUG_ON(sbr < GUEST_TASK_SIZE);
	BUG_ON(sbr >= HOST_TASK_SIZE);

	stack_regs->stacks.psp_hi = psp_hi;
	stack_regs->stacks.psp_lo = psp_lo;
	if (gti != NULL) {
		gti->g_psp_lo = psp_lo;
		gti->g_psp_hi = psp_hi;
	}

	DebugTOVM("new guest kernel procedure stack from 0x%llx size 0x%x\n",
		psp_lo.PSP_lo_base, psp_hi.PSP_hi_size);

	stack_regs->stacks.pcsp_hi = pcsp_hi;
	stack_regs->stacks.pcsp_lo = pcsp_lo;
	if (gti != NULL) {
		gti->g_pcsp_lo = pcsp_lo;
		gti->g_pcsp_hi = pcsp_hi;
	}

	DebugTOVM("new guest kernel chain stack from 0x%llx size 0x%x\n",
		pcsp_lo.PCSP_lo_base, pcsp_hi.PCSP_hi_size);

	if (entry_point == NULL)
		return 0;

	if (priv_guest) {
		psr = E2K_KERNEL_PSR_ENABLED;
		psr.PSR_sge = 1;
	} else {
		psr = E2K_USER_INITIAL_PSR;
	}
	ret = prepare_pv_stacks_to_startup_vcpu(vcpu,
			stack_regs, args, args_num, entry_point,
			psr, user_info->sp_offset,
			(void *)ps_base, (void *)pcs_base, 0, true);
	if (ret)
		goto failed;

	return 0;

failed:
	return ret;
}

static void kvm_init_guest_user_stacks(struct kvm_vcpu *vcpu,
		gthread_info_t *gti, gmm_struct_t *gmm,
		kvm_task_info_t	*user_info, guest_hw_stack_t *stack_regs,
		bool is_user_stacks)
{
	e2k_usd_lo_t	usd_lo;
	e2k_usd_hi_t	usd_hi;
	e2k_addr_t	sbr;
	e2k_size_t	us_size;
	e2k_psp_lo_t	psp_lo;
	e2k_psp_hi_t	psp_hi;
	e2k_pcsp_lo_t	pcsp_lo;
	e2k_pcsp_hi_t	pcsp_hi;
	e2k_cutd_t	cutd;

	/*
	 * New guest kernel stacks (data and hardware) were allocated by guest
	 * Create all register state for new guest stacks
	 */
	usd_hi.USD_hi_half = 0;
	usd_lo.USD_lo_half = 0;
	psp_hi.PSP_hi_half = 0;
	psp_lo.PSP_lo_half = 0;
	pcsp_hi.PCSP_hi_half = 0;
	pcsp_lo.PCSP_lo_half = 0;
	if (is_user_stacks) {
		us_size = user_info->u_us_size;
		sbr = user_info->u_us_base + us_size;	/* top of stack */
		usd_hi.USD_hi_size = user_info->u_sp_offset;
		usd_lo.USD_lo_base = user_info->u_us_base +
					user_info->u_sp_offset;

		psp_hi.PSP_hi_size = user_info->u_ps_size;
		psp_hi.PSP_hi_ind  = user_info->u_ps_ind;
		psp_lo.PSP_lo_base = user_info->u_ps_base;

		pcsp_hi.PCSP_hi_size = user_info->u_pcs_size;
		pcsp_hi.PCSP_hi_ind  = user_info->u_pcs_ind;
		pcsp_lo.PCSP_lo_base = user_info->u_pcs_base;
	} else {
		us_size = user_info->us_size;
		sbr = user_info->us_base + us_size;	/* top of stack */
		usd_hi.USD_hi_size = user_info->sp_offset;
		usd_lo.USD_lo_base = user_info->us_base + user_info->sp_offset;

		psp_hi.PSP_hi_size = user_info->ps_size;
		psp_hi.PSP_hi_ind  = user_info->ps_ind;
		psp_lo.PSP_lo_base = user_info->ps_base;

		pcsp_hi.PCSP_hi_size = user_info->pcs_size;
		pcsp_hi.PCSP_hi_ind  = user_info->pcs_ind;
		pcsp_lo.PCSP_lo_base = user_info->pcs_base;
	}

	/* keep host local data stack unchanged */
	gti->us_size = us_size;
	stack_regs->stacks.top = sbr;
	stack_regs->stacks.usd_hi = usd_hi;
	stack_regs->stacks.usd_lo = usd_lo;
	DebugGUS("new local guest start stack base 0x%llx size 0x%x "
		"top 0x%lx\n",
		 usd_lo.USD_lo_base, usd_hi.USD_hi_size, sbr);

	sbr = user_info->us_base + user_info->us_size;
	sbr = round_up(sbr, E2K_ALIGN_STACK_BASE_REG);
	usd_hi.USD_hi_half = 0;
	usd_lo.USD_lo_half = 0;
	usd_hi.USD_hi_size = user_info->us_size;
	usd_lo.USD_lo_base = sbr;
	gti->g_usd_lo = usd_lo;
	gti->g_usd_hi = usd_hi;
	gti->g_sbr.SBR_reg = 0;
	gti->g_sbr.SBR_base = sbr;

	DebugGUS("new local guest kernel data stack base 0x%llx size 0x%x "
		"top 0x%llx\n",
		gti->g_usd_lo.USD_lo_base, gti->g_usd_hi.USD_hi_size,
		gti->g_sbr.SBR_base);
	/* host kernel data stack does not changed */
	DebugGUS("host kernel current data stack bottom %px "
		"base 0x%llx size 0x%x\n",
		current->stack + KERNEL_C_STACK_OFFSET,
		current_thread_info()->k_usd_lo.USD_lo_base,
		current_thread_info()->k_usd_hi.USD_hi_size);

	BUG_ON(stack_regs->stacks.top >= HOST_TASK_SIZE);

	stack_regs->stacks.psp_hi = psp_hi;
	stack_regs->stacks.psp_lo = psp_lo;

	DebugGUS("new guest procedure stack from 0x%llx size 0x%x "
		"ind 0x%x\n",
		psp_lo.PSP_lo_base, psp_hi.PSP_hi_size, psp_hi.PSP_hi_ind);

	psp_hi.PSP_hi_half = 0;
	psp_lo.PSP_lo_half = 0;
	psp_hi.PSP_hi_size = user_info->ps_size;
	psp_lo.PSP_lo_base = user_info->ps_base;
	gti->g_psp_hi = psp_hi;
	gti->g_psp_lo = psp_lo;

	DebugGUS("new guest kernel procedure stack from 0x%llx size 0x%x "
		"ind 0x%x\n",
		gti->g_psp_lo.PSP_lo_base, gti->g_psp_hi.PSP_hi_size,
		gti->g_psp_hi.PSP_hi_ind);

	stack_regs->stacks.pcsp_hi = pcsp_hi;
	stack_regs->stacks.pcsp_lo = pcsp_lo;

	DebugGUS("new guest chain stack from 0x%llx size 0x%x "
		"ind 0x%x\n",
		pcsp_lo.PCSP_lo_base, pcsp_hi.PCSP_hi_size,
		pcsp_hi.PCSP_hi_ind);

	pcsp_hi.PCSP_hi_half = 0;
	pcsp_lo.PCSP_lo_half = 0;
	pcsp_hi.PCSP_hi_size = user_info->pcs_size;
	pcsp_lo.PCSP_lo_base = user_info->pcs_base;
	gti->g_pcsp_hi = pcsp_hi;
	gti->g_pcsp_lo = pcsp_lo;

	DebugGUS("new guest kernel chain stack from 0x%llx size 0x%x "
		"ind 0x%x\n",
		gti->g_pcsp_lo.PCSP_lo_base, gti->g_pcsp_hi.PCSP_hi_size,
		gti->g_pcsp_hi.PCSP_hi_ind);

	/* Set user local stack and Compilation Unit table context */
	cutd.CUTD_reg = 0;
	cutd.CUTD_base = user_info->cut_base;
	stack_regs->cutd = cutd;

	DebugGUS("new guest CUTD : %px\n", (void *)stack_regs->cutd.CUTD_base);
}

static int kvm_setup_guest_user_stacks(struct kvm_vcpu *vcpu,
		kvm_task_info_t	*user_info, guest_hw_stack_t *stack_regs)
{
	gthread_info_t	*gti;
	gmm_struct_t	*gmm;
	char		*entry_point;
	e2k_psr_t	psr;
	int		ret, cui;
	bool		kernel;

	gti = pv_vcpu_get_gti(vcpu);
	BUG_ON(gti == NULL);
	gmm = pv_vcpu_get_gmm(vcpu);
	BUG_ON(gmm == NULL || pv_vcpu_is_init_gmm(vcpu, gmm));

	kvm_init_guest_user_stacks(vcpu, gti, gmm, user_info, stack_regs,
					true	/* set guest user stacks */);
	set_pv_vcpu_u_stack_context(vcpu, stack_regs);

	cui = user_info->cui;
	kernel = user_info->kernel;
	atomic_set(&gmm->context.cur_cui, cui);
	DebugKVMEX("set new CUTD size 0x%lx, CUI to 0x%x\n",
		user_info->cut_size, cui);

	entry_point = (char *)user_info->entry_point;

	psr = E2K_USER_INITIAL_PSR;

	ret = prepare_pv_stacks_to_startup_vcpu(vcpu,
			stack_regs, NULL, 0, entry_point,
			psr, user_info->u_sp_offset,
			(void *)user_info->u_ps_base,
			(void *)user_info->u_pcs_base,
			cui, kernel);
	if (ret)
		goto out_failed;

	kvm_set_guest_vcpu_PSR(vcpu, psr);
	kvm_set_guest_vcpu_UPSR(vcpu, E2K_USER_INITIAL_UPSR);
	kvm_set_guest_vcpu_under_upsr(vcpu, false);

	DebugFRTASK("starting the new user task GPID #%d GMMID #%d\n",
		gti->gpid->nid.nr, gmm->nid.nr);

	return 0;

out_failed:
	return ret;
}

int kvm_switch_guest_kernel_stacks(struct kvm_vcpu *vcpu,
			kvm_task_info_t __user *task_info, char *entry_point,
			unsigned long __user *task_args, int args_num,
			guest_hw_stack_t *stack_regs)
{
	kvm_task_info_t	user_info;
	u64 args[4];
	int ret;

	DebugTOVM("started\n");

	KVM_BUG_ON(vcpu->arch.is_hv);

	if (kvm_vcpu_copy_from_guest(vcpu, &user_info, task_info,
						sizeof(*task_info))) {
		pr_err("%s(): copy guest task info from guest failed\n",
			__func__);
		ret = -EFAULT;
		goto failed;
	}

	if (args_num > sizeof(args) / sizeof(*args)) {
		pr_err("%s(): too many guest args %d, max %ld\n",
			__func__, args_num, sizeof(args) / sizeof(*args));
		ret = -EINVAL;
		goto failed;
	}
	if (kvm_vcpu_copy_from_guest(vcpu, &args, task_args,
					sizeof(*task_args) * args_num)) {
		pr_err("%s(): copy guest args from guest failed\n",
			__func__);
		ret = -EFAULT;
		goto failed;
	}

	ret = kvm_get_guest_kernel_stacks(vcpu, &user_info, stack_regs,
					  args, args_num, entry_point);
	if (ret) {
		pr_err("%s(): VCPU #%d could not switch guest kernel stacks, "
			"error %d\n",
			__func__, vcpu->vcpu_id, ret);
		goto failed;
	}

	stack_regs->cutd = vcpu->arch.hw_ctxt.sh_oscutd;

	raw_all_irq_disable();

	startup_pv_vcpu(vcpu, stack_regs, FROM_HYPERCALL_SWITCH);
	/* should not be here */
	KVM_BUG_ON(true);

	return 0;

failed:

	vcpu->arch.exit_reason = EXIT_SHUTDOWN;
	vcpu->run->exit_reason = KVM_EXIT_E2K_PANIC;

	DebugKVMSH("VCPU #%d thread exits\n", vcpu->vcpu_id);

	/* return to host VCPU to handle exit reason */
	return RETURN_TO_HOST_APP_HCRET;
}

int kvm_switch_to_virt_mode(struct kvm_vcpu *vcpu,
		kvm_task_info_t __user *task_info, guest_hw_stack_t *stack_regs,
		void (*func)(void *data, void *arg1, void *arg2),
		void *data, void *arg1, void *arg2)
{
	kvm_task_info_t	user_info;
	gthread_info_t *gti;
	u64 args[4];
	int ret;

	DebugTOVM("started on VCPU #%d to enable guest MMU virtual mode\n",
		vcpu->vcpu_id);

	if (kvm_vcpu_copy_from_guest(vcpu, &user_info, task_info,
					sizeof(*task_info))) {
		DebugKVM("copy new task info from user failed\n");
		ret = -EFAULT;
		goto failed;
	}
	args[0] = (u64)data;
	args[1] = (u64)arg1;
	args[2] = (u64)arg2;
	args[3] = 0;

	if (!is_paging(vcpu)) {
		/* it need create shadow PT based on PTs created by guest */
		/* and enable paging mode */
		KVM_BUG_ON(!is_shadow_paging(vcpu));
		ret = kvm_mmu_enable_shadow_paging(vcpu);
		if (ret) {
			pr_err("%s(): VCPU #%d could not switch to "
				"shadow PT, error %d\n",
				__func__, vcpu->vcpu_id, ret);
			goto failed;
		}
	}

	ret = kvm_get_guest_kernel_stacks(vcpu, &user_info, stack_regs,
			args, sizeof(args) / sizeof(*args), (char *)func);
	if (ret) {
		pr_err("%s(): VCPU #%d could not get guest kernel "
			"stacks, error %d\n",
			__func__, vcpu->vcpu_id, ret);
		goto failed;
	}

	KVM_BUG_ON(!is_shadow_paging(vcpu));

	if (vcpu->arch.is_hv || vcpu->arch.is_pv) {
		kvm_hw_cpu_context_t *hw_ctxt = &vcpu->arch.hw_ctxt;
		kvm_sw_cpu_context_t *sw_ctxt = &vcpu->arch.sw_ctxt;

		raw_all_irq_disable();
		if (vcpu->arch.is_hv) {
			/* set guest stacks registers to new guest kernel */
			/* stacks (hw context) */
			kvm_update_guest_stacks_registers(vcpu, stack_regs);

			/* update local data stack pointers */
			/* (software context) */
			sw_ctxt->sbr.SBR_reg = stack_regs->stacks.top;
			sw_ctxt->usd_lo = stack_regs->stacks.usd_lo;
			sw_ctxt->usd_hi = stack_regs->stacks.usd_hi;
		}

		/* set guest OS compilation units context */
		ret = vcpu_init_os_cu_hw_ctxt(vcpu, &user_info);
		if (ret != 0) {
			pr_err("%s(): init guest OS CU context\n",
				__func__);
			goto failed;
		}
		stack_regs->cutd = hw_ctxt->sh_oscutd;

		gti = pv_vcpu_get_gti(vcpu);
		if (gti != NULL) {
			gti->stack_regs = *stack_regs;
		}

		/* restore global register pointer to VCPU state */
		/* from now it should be virtual address */
		INIT_HOST_VCPU_STATE_GREG_COPY(current_thread_info(), vcpu);
		/* all addresses into VCPU state too */
		guest_pv_vcpu_state_to_paging(vcpu);

		/* setup hypervisor to handle guest kernel intercepts */
		kvm_init_kernel_intc(vcpu);

		if (!vcpu->arch.is_hv) {
			startup_pv_vcpu(vcpu, stack_regs,
					FROM_HYPERCALL_SWITCH);
			/* should not be here */
			KVM_BUG_ON(true);
		}
		raw_all_irq_enable();
		return 0;
	} else {
		KVM_BUG_ON(true);
	}

	ret = -EINVAL;

failed:

	raw_all_irq_enable();
	vcpu->arch.exit_reason = EXIT_SHUTDOWN;
	vcpu->run->exit_reason = KVM_EXIT_E2K_PANIC;

	DebugKVMSH("VCPU #%d thread exits\n", vcpu->vcpu_id);

	if (!vcpu->arch.is_hv) {
		/* return to host VCPU to handle exit reason */
		return RETURN_TO_HOST_APP_HCRET;
	}
	/* inject intercept as hypercall return to switch to */
	/* vcpu run thread and handle VM exit on guest panic */
	kvm_inject_vcpu_exit(vcpu);

	return ret;
}

extern int guest_thread_copy;	/* FIXME: only to debug */

static inline int
kvm_put_guest_new_sw_regs(struct kvm_vcpu *vcpu, gthread_info_t *new_gti,
		e2k_stacks_t *new_stacks, e2k_mem_crs_t *new_crs,
		__user unsigned long *g_gregs)
{
	struct sw_regs *sw_regs = &new_gti->sw_regs;

	sw_regs->top	 = new_stacks->top;
	sw_regs->usd_lo	 = new_stacks->usd_lo;
	sw_regs->usd_hi	 = new_stacks->usd_hi;
	sw_regs->psp_lo	 = new_stacks->psp_lo;
	sw_regs->psp_hi	 = new_stacks->psp_hi;
	sw_regs->pcsp_lo = new_stacks->pcsp_lo;
	sw_regs->pcsp_hi = new_stacks->pcsp_hi;
	sw_regs->crs.cr0_lo = new_crs->cr0_lo;
	sw_regs->crs.cr0_hi = new_crs->cr0_hi;
	sw_regs->crs.cr1_lo = new_crs->cr1_lo;
	sw_regs->crs.cr1_hi = new_crs->cr1_hi;

	init_sw_user_regs(sw_regs, false, new_gti->task_is_binco);
	if (g_gregs != NULL) {
		int ret;

		ret = kvm_copy_guest_all_glob_regs(vcpu, &sw_regs->gregs,
							g_gregs);
		if (ret != 0) {
			pr_err("%s(): could not copy guest global registers, "
				"error %d\n", __func__, ret);
			return ret;
		}
		/* set BGR register to enable floating point stack */
		sw_regs->gregs.bgr = E2K_INITIAL_BGR;
	}
	sw_regs->cutd	= new_gti->stack_regs.cutd;
	sw_regs->dimar0 = 0;
	sw_regs->dimar1 = 0;
	sw_regs->ddmar0 = 0;
	sw_regs->ddmar1 = 0;
	AW(sw_regs->dibsr) = 0;
	AW(sw_regs->dimcr) = 0;
	AW(sw_regs->ddbsr) = 0;
	AW(sw_regs->ddmcr) = 0;
	if (!test_gti_thread_flag(new_gti, GTIF_KERNEL_THREAD)) {
		DebugKVMACT("set guest data stack entry state: "
			"base 0x%llx, size 0x%x, top 0x%lx\n",
			new_stacks->usd_lo.USD_lo_base,
			new_stacks->usd_hi.USD_hi_size,
			new_stacks->top);
	}
	/* set initial state of guest kernel UPSR */
	/* guest kernel is user of host, so initial user UPSR state */
	DO_SAVE_GUEST_KERNEL_UPSR(new_gti, E2K_USER_INITIAL_UPSR);
	return 0;
}

int kvm_copy_guest_kernel_stacks(struct kvm_vcpu *vcpu,
				kvm_task_info_t __user *task_info,
				e2k_cr1_hi_t cr1_hi)
{
	thread_info_t	*cur_ti = current_thread_info();
	kvm_task_info_t	user_info;
	gthread_info_t	*gti;
	guest_hw_stack_t *stack_regs;
	e2k_stacks_t	*new_stacks;
	e2k_mem_crs_t	*new_crs;
	e2k_usd_lo_t	usd_lo;
	e2k_usd_hi_t	usd_hi;
	e2k_addr_t	sbr;
	e2k_psp_lo_t	psp_lo;
	e2k_psp_hi_t	psp_hi;
	e2k_pcsp_lo_t	pcsp_lo;
	e2k_pcsp_hi_t	pcsp_hi;
	e2k_addr_t	ps_base;
	e2k_size_t	ps_size;
	e2k_addr_t	pcs_base;
	e2k_size_t	pcs_size;
	int		ret;

	DebugKVMKS("started\n");

	if (kvm_vcpu_copy_from_guest(vcpu, &user_info, task_info,
						sizeof(*task_info))) {
		pr_err("%s(): copy new task info from user failed\n",
			__func__);
		return -EFAULT;
	}
	gti = alloc_guest_thread_info(vcpu->kvm);
	if (gti == NULL) {
		pr_err("%s(): could not create guest thread info\n",
			__func__);
		return -ENOMEM;
	}
	set_gti_thread_flag(gti, GTIF_KERNEL_THREAD);
	stack_regs = &gti->stack_regs;
	new_stacks = &stack_regs->stacks;
	new_crs = &stack_regs->crs;

	/*
	 * New guest kernel stacks (data and hardware) were allocated by guest
	 * Create all register state for new guest stacks
	 */
	sbr = user_info.us_base + user_info.us_size;	/* top of stack */
	usd_hi.USD_hi_half = 0;
	usd_lo.USD_lo_half = 0;
	usd_hi.USD_hi_size = user_info.sp_offset;
	usd_lo.USD_lo_base = user_info.us_base + user_info.sp_offset;
	new_stacks->top = sbr;
	new_stacks->usd_hi = usd_hi;
	new_stacks->usd_lo = usd_lo;
	gti->g_usd_lo = usd_lo;
	gti->g_usd_hi = usd_hi;
	gti->g_sbr.SBR_reg = 0;
	gti->g_sbr.SBR_base = sbr;
	gti->us_size = user_info.us_size;
	DebugKVMKS("new local guest kernel data stack base 0x%llx size 0x%x "
		"top 0x%lx\n",
		 usd_lo.USD_lo_base, usd_hi.USD_hi_size, sbr);

	ps_size = user_info.ps_size;
	ps_base = user_info.ps_base;

	pcs_size = user_info.pcs_size;
	pcs_base = user_info.pcs_base;

	psp_hi.PSP_hi_half = 0;
	psp_lo.PSP_lo_half = 0;
	psp_hi.PSP_hi_size = ps_size;
	psp_hi.PSP_hi_ind = user_info.ps_ind;
	psp_lo.PSP_lo_base = ps_base;
	new_stacks->psp_hi = psp_hi;
	new_stacks->psp_lo = psp_lo;
	gti->g_psp_lo = psp_lo;
	gti->g_psp_hi = psp_hi;

	DebugKVMKS("new guest kernel procedure stack from 0x%llx size 0x%x, "
		"ind 0x%x\n",
		psp_lo.PSP_lo_base, psp_hi.PSP_hi_size, psp_hi.PSP_hi_ind);

	pcsp_hi.PCSP_hi_half = 0;
	pcsp_lo.PCSP_lo_half = 0;
	pcsp_hi.PCSP_hi_size = pcs_size;
	pcsp_hi.PCSP_hi_ind = user_info.pcs_ind;
	pcsp_lo.PCSP_lo_base = pcs_base;
	new_stacks->pcsp_hi = pcsp_hi;
	new_stacks->pcsp_lo = pcsp_lo;
	gti->g_pcsp_lo = pcsp_lo;
	gti->g_pcsp_hi = pcsp_hi;

	DebugKVMKS("new guest kernel procedure chain stack from 0x%llx "
		"size 0x%x, ind 0x%x\n",
		pcsp_lo.PCSP_lo_base, pcsp_hi.PCSP_hi_size,
		pcsp_hi.PCSP_hi_ind);

	new_crs->cr0_lo.CR0_lo_half = user_info.cr0_lo;
	new_crs->cr0_hi.CR0_hi_half = user_info.cr0_hi;
	DebugKVMKS("new chain registers: IP 0x%llx, PF 0x%llx\n",
		new_crs->cr0_hi.CR0_hi_IP,
		new_crs->cr0_lo.CR0_lo_pf);

	new_crs->cr1_lo.CR1_lo_half = user_info.cr1_wd;
	new_crs->cr1_hi.CR1_hi_half = user_info.cr1_ussz;
	DebugKVMKS("new chain registers: wbs 0x%x, ussz 0x%x\n",
		new_crs->cr1_lo.CR1_lo_wbs * EXT_4_NR_SZ,
		new_crs->cr1_hi.CR1_hi_ussz << 4);

	DebugKVMKS("current user data stack: bottom "
		"0x%lx, top 0x%lx, max size 0x%lx\n",
		cur_ti->u_stack.bottom, cur_ti->u_stack.top,
		cur_ti->u_stack.size);

	kvm_gmm_get(vcpu, gti, pv_vcpu_get_init_gmm(vcpu));

	/* FIXME: here should be copy of host kernel frames and guest pt_regs */
	/* from source process to new cloned process for recursive case of */
	/* fork(), but now it is not implemented, only without recursion case */

	user_info.cr0_lo = new_crs->cr0_lo.CR0_lo_half;
	user_info.cr0_hi = new_crs->cr0_hi.CR0_hi_half;
	user_info.cr1_wd = new_crs->cr1_lo.CR1_lo_half;
	user_info.cr1_ussz = new_crs->cr1_hi.CR1_hi_half;
	if (kvm_vcpu_copy_to_guest(vcpu, task_info, &user_info,
						sizeof(*task_info))) {
		pr_err("%s(): copy updated task info to user failed, "
			"retry\n", __func__);
		ret = -EFAULT;
		goto out_free_gti;
	}
	stack_regs->cutd = vcpu->arch.hw_ctxt.sh_oscutd;

	/* save user special registers to initial state while switch */
	gti->task_is_binco = 0;
	kvm_put_guest_new_sw_regs(vcpu, gti, new_stacks, new_crs, NULL);

	DebugKVMKS("completed successfully, GPID #%d\n",
		gti->gpid->nid.nr);
	return gti->gpid->nid.nr;

out_free_gti:
	free_guest_thread_info(vcpu->kvm, gti);
	return ret;
}

int kvm_release_guest_task_struct(struct kvm_vcpu *vcpu, int gpid_nr)
{
	gthread_info_t *gti;
	gthread_info_t *cur_gti;
	gmm_struct_t *gmm;
	int gmmid_nr;
	bool kthread;

	if (gpid_nr < 0) {
		pr_alert("%s(): invalid GPID # %d: nothing to release\n",
			__func__, gpid_nr);
		return 0;
	}
	gti = kvm_get_guest_thread_info(vcpu->kvm, gpid_nr);
	if (gti == NULL) {
		pr_alert("%s(): could not find guest thread GPID #%d\n",
			__func__, gpid_nr);
		return -ENODEV;
	}

	kthread = test_gti_thread_flag(gti, GTIF_KERNEL_THREAD);

	if (!kthread)
		DebugFRTASK("started for guest thread GPID #%d\n", gpid_nr);

	/* Guest should pass gpid number only of the dead process */
	/* FIXME: it need check the passed gpid is not number of active */
	/* (queued or running) guest thread. But now it is checker */
	/* only on current active process */
	cur_gti = pv_vcpu_get_gti(vcpu);
	if (gti == cur_gti || gpid_nr == cur_gti->gpid->nid.nr) {
		pr_alert("%s(): guest kernel try release current active "
			"guest process GPID #%d\n",
			__func__, gpid_nr);
		return -EEXIST;
	}

	if (likely(!test_gti_thread_flag(gti, GTIF_KERNEL_THREAD))) {
		gmm = gti->gmm;
	} else {
		gmm = pv_vcpu_get_init_gmm(vcpu);
	}
	KVM_BUG_ON(gmm == NULL);
	gmmid_nr = gmm->nid.nr;
	if (!pv_vcpu_is_init_gmm(vcpu, gmm) &&
			!test_gti_thread_flag(gti, GTIF_USER_THREAD) &&
				(gmm == pv_vcpu_get_gmm(vcpu) ||
				gmm == pv_vcpu_get_active_gmm(vcpu))) {
		pr_err("%s(): guest tries to release current active "
			"gmm GMMID #%d\n",
			__func__, gmm->nid.nr);
		return -EBUSY;
	}

	if (kvm_gmm_put(vcpu->kvm, gti) == 0) {
		DebugFRTASK("gmm GMMID #%d was released\n", gmmid_nr);
	} else {
		if (!kthread) {
			DebugFRTASK("gmm GMMID #%d cannot be released\n",
				gmmid_nr);
		}
	}
	free_guest_thread_info(vcpu->kvm, gti);

	if (!kthread)
		DebugFRTASK("task GPID #%d released successfully\n", gpid_nr);

	return 0;
}

/*
 * End of sys_execve() for guest:
 *	switching to new user stacks;
 *	start user from entry point;
 */
int kvm_switch_to_guest_new_user(struct kvm_vcpu *vcpu,
				 kvm_task_info_t __user *task_info,
				 guest_hw_stack_t *stack_regs)
{
	gthread_info_t	*gthread_info;
	kvm_task_info_t	user_info;
	bool syscall;
	int ret;

	DebugKVMEX("started\n");

	BUG_ON(vcpu == NULL);
	BUG_ON(kvm_get_guest_vcpu_runstate(vcpu) != RUNSTATE_in_hcall);

	ret = kvm_vcpu_copy_from_guest(vcpu, &user_info, task_info,
						sizeof(*task_info));
	if (unlikely(ret < 0)) {
		pr_err("%s(): copy new task info from user failed\n",
			__func__);
		return ret;
	}

	ret = kvm_setup_guest_user_stacks(vcpu, &user_info, stack_regs);
	if (ret) {
		pr_err("%s(): VCPU #%d could not get guest user "
			"stacks, error %d\n",
			__func__, vcpu->vcpu_id, ret);
		goto failed;
	}

	gthread_info = pv_vcpu_get_gti(vcpu);
	BUG_ON(gthread_info == NULL);
	gthread_info->stack_regs = *stack_regs;
	if (user_info.flags & PROTECTED_CODE_TASK_FLAG) {
		pr_err("%sd(): could not running of protected guest codes "
			"(is not yet implemented)\n",
			__func__);
		ret = -ENOEXEC;
		goto failed;
	}

	/* Set some flags of new task */
	syscall = !test_and_clear_gti_thread_flag(gthread_info,
							GTIF_KERNEL_THREAD);
	if (user_info.flags & BIN_COMP_CODE_TASK_FLAG)
		gthread_info->task_is_binco = 1;
	else
		gthread_info->task_is_binco = 0;

	if (syscall) {
		syscall_handler_trampoline_start(vcpu, 0);
	}

	return 0;

failed:
	return ret;
}

static int prepare_pv_vcpu_last_user_crs(struct kvm_vcpu *vcpu,
			e2k_stacks_t *stacks, e2k_mem_crs_t *crs)
{
	void __user *u_frame;
	int ret;

	u_frame = (void __user *)stacks->pcsp_lo.PCSP_lo_base +
					stacks->pcsp_hi.PCSP_hi_ind;
	ret = pv_vcpu_user_crs_copy_to_kernel(vcpu, u_frame, crs);
	if (unlikely(ret)) {
		return ret;
	}
	DebugKVMCLN("copy last user frame from CRS at %px to guest "
		"kernel chain %px (base 0x%llx + ind 0x%x)\n",
		crs, u_frame, stacks->pcsp_lo.PCSP_lo_base,
		stacks->pcsp_hi.PCSP_hi_ind);

	stacks->pcsp_hi.PCSP_hi_ind += SZ_OF_CR;
	DebugKVMCLN("guest kernel chain stack index is now 0x%x\n",
		stacks->pcsp_hi.PCSP_hi_ind);

	return 0;
}

static int prepare_pv_vcpu_fork_trampoline(struct kvm_vcpu *vcpu,
			gthread_info_t *gti, e2k_stacks_t *stacks)
{
	e2k_mem_crs_t crs;
	e2k_mem_crs_t __user *u_frame;
	int ret;

	/*
	 * Prepare 'syscall_copy pr_trampoline' frame
	 */
	memset(&crs, 0, sizeof(crs));

	crs.cr0_lo.CR0_lo_pf = -1ULL;
	crs.cr0_hi.CR0_hi_IP = (u64)syscall_fork_trampoline;
	crs.cr1_lo.CR1_lo_psr = E2K_KERNEL_PSR_DISABLED.PSR_reg;
	crs.cr1_lo.CR1_lo_cui = KERNEL_CODES_INDEX;
	if (machine.native_iset_ver < E2K_ISET_V6)
		crs.cr1_lo.CR1_lo_ic = 1;
	crs.cr1_lo.CR1_lo_wpsz = 1;
	crs.cr1_lo.CR1_lo_wbs = 0;
	crs.cr1_hi.CR1_hi_ussz = gti->us_size >> 4;

	/* Copy the new frame into top of guest kernel chain stack */
	u_frame = (e2k_mem_crs_t __user *)(stacks->pcsp_lo.PCSP_lo_base +
						stacks->pcsp_hi.PCSP_hi_ind);
	ret = pv_vcpu_user_crs_copy_to_kernel(vcpu, u_frame, &crs);
	if (unlikely(ret)) {
		return ret;
	}
	DebugKVMCLN("set trampoline CRS at the top of guest kernel chain %px "
		"(base 0x%llx + ind 0x%x)\n",
		u_frame, stacks->pcsp_lo.PCSP_lo_base,
		stacks->pcsp_hi.PCSP_hi_ind);

	stacks->pcsp_hi.PCSP_hi_ind += SZ_OF_CR;
	DebugKVMCLN("guest kernel chain stack index is now 0x%x\n",
		stacks->pcsp_hi.PCSP_hi_ind);

	return 0;
}

static int prepare_pv_vcpu_ret_from_fork_frame(struct kvm_vcpu *vcpu,
		gthread_info_t *gti, e2k_stacks_t *stacks,
		e2k_mem_crs_t *crs, void *func_IP)
{
	e2k_mem_crs_t __user *u_frame;
	int ret;

	/*
	 * Prepare 'switch_to() -> return_from_fork' frame
	 */
	memset(crs, 0, sizeof(*crs));

	crs->cr0_lo.CR0_lo_pf = -1ULL;
	crs->cr0_hi.CR0_hi_IP = (u64)func_IP;
	crs->cr1_lo.CR1_lo_psr = E2K_KERNEL_PSR_DISABLED.PSR_reg;
	crs->cr1_lo.CR1_lo_pm = 0;	/* guest should be not privileged */
	crs->cr1_lo.CR1_lo_cui = KERNEL_CODES_INDEX;
	if (machine.native_iset_ver < E2K_ISET_V6)
		crs->cr1_lo.CR1_lo_ic = 1;
	crs->cr1_lo.CR1_lo_wpsz = 1;
	crs->cr1_lo.CR1_lo_wbs = 0;
	crs->cr1_hi.CR1_hi_ussz = stacks->usd_hi.USD_hi_size >> 4;

	/* Copy the new frame into top of guest kernel chain stack */
	u_frame = (e2k_mem_crs_t __user *)(stacks->pcsp_lo.PCSP_lo_base +
						stacks->pcsp_hi.PCSP_hi_ind);
	ret = pv_vcpu_user_crs_copy_to_kernel(vcpu, u_frame, crs);
	if (unlikely(ret)) {
		return ret;
	}
	DebugKVMCLN("set return from fork CRS franme at the top of guest "
		"kernel chain %px (base 0x%llx + ind 0x%x)\n",
		u_frame, stacks->pcsp_lo.PCSP_lo_base,
		stacks->pcsp_hi.PCSP_hi_ind);

	/* The frame will be setup from pt_regs structure directly to
	 * the registers CR0/CR1 to return to from 'return from fork' function,
	 * so should not be counted in memory
	stacks->pcsp_hi.PCSP_hi_ind += SZ_OF_CR;
	DebugKVMCPY("guest kernel chain stack index is now 0x%x\n",
		stacks->pcsp_hi.PCSP_hi_ind);
	 */

	return 0;
}

/*
 * End of copy_thread() for guest user process (clone_user_stack()):
 */
int kvm_copy_guest_user_stacks(struct kvm_vcpu *vcpu,
			kvm_task_info_t __user *task_info,
			vcpu_gmmu_info_t __user *gmmu_info)
{
	struct kvm	*kvm = vcpu->kvm;
	pt_regs_t	*cur_regs, *regs;
	gthread_info_t	*cur_gti;
	gthread_info_t	*gti;
	gmm_struct_t	*gmm;
	guest_hw_stack_t *stack_regs;
	e2k_stacks_t	*new_stacks;
	e2k_mem_crs_t	*new_crs;
	kvm_task_info_t	user_info;
	e2k_addr_t	sbr;
	e2k_size_t	us_size;
	vcpu_gmmu_info_t gmm_info;
	gpa_t		u_pptb;
	int		gmmid_nr;
	int		ret;

	ret = kvm_vcpu_copy_from_guest(vcpu, &user_info, task_info,
						sizeof(*task_info));
	if (unlikely(ret < 0)) {
		pr_err("%s(): copy new task info from user failed\n",
			__func__);
		return ret;
	}

	ret = kvm_vcpu_copy_from_guest(vcpu, &gmm_info, gmmu_info,
						sizeof(*gmmu_info));
	if (unlikely(ret < 0)) {
		pr_err("%s(): copy new GMMU info from user failed\n",
			__func__);
		return ret;
	}
	KVM_BUG_ON(gmm_info.opcode != CREATE_NEW_GMM_GMMU_OPC);

	gti = alloc_guest_thread_info(kvm);
	if (gti == NULL) {
		pr_err("%s(): could not create guest thread info\n",
			__func__);
		return -ENOMEM;
	}
	DebugGMM("allocated guest thread info agent #%d\n",
		gti->gpid->nid.nr);

	gmm = create_gmm(kvm);
	if (gmm == NULL) {
		pr_err("%s(): could not create new host agent of guest mm\n",
			__func__);
		ret = -ENOMEM;
		goto out_free_gti;
	}
	gmmid_nr = gmm->nid.nr;
	kvm_gmm_get(vcpu, gti, gmm);

	cur_gti = pv_vcpu_get_gti(vcpu);
	BUG_ON(cur_gti == NULL);

	cur_regs = &cur_gti->fork_regs;
	regs = &gti->fork_regs;
	KVM_BUG_ON(!is_sys_call_pt_regs(cur_regs));
	*regs = *cur_regs;

	stack_regs = &gti->stack_regs;
	new_stacks = &stack_regs->stacks;
	new_crs = &stack_regs->crs;

	if (DEBUG_KVM_COPY_USER_MODE)
		debug_copy_guest = true;
	/*
	 * New user stacks (data and hardware) were allocated by guest
	 * Create all register state for new guest stacks
	 */
	kvm_init_guest_user_stacks(vcpu, gti, gmm, &user_info, stack_regs,
					false	/* set guest kernel stacks */);

	us_size = user_info.u_us_size;
	sbr = user_info.u_us_base + us_size;	/* top of stack */
	if (unlikely(regs->stacks.top != sbr)) {
		e2k_usd_lo_t	usd_lo;
		e2k_usd_hi_t	usd_hi;

		/* guest user local data stack was changed, so setup user */
		/* local data stack registers to return to new stack */
		usd_hi.USD_hi_half = 0;
		usd_lo.USD_lo_half = 0;
		usd_hi.USD_hi_size = user_info.u_sp_offset;
		usd_lo.USD_lo_base = user_info.u_us_base +
						user_info.u_sp_offset;
		sbr = round_up(sbr, E2K_ALIGN_STACK_BASE_REG);
		regs->stacks.top = sbr;
		regs->stacks.usd_hi = usd_hi;
		regs->stacks.usd_lo = usd_lo;
		DebugKVMCPY("new local guest user data stack base 0x%llx "
			"size 0x%x top 0x%lx\n",
			usd_lo.USD_lo_base, usd_hi.USD_hi_size, sbr);
	}

	new_crs->cr0_lo.CR0_lo_half = user_info.cr0_lo;
	new_crs->cr0_hi.CR0_hi_half = user_info.cr0_hi;
	DebugKVMCPY("new chain registers: IP 0x%llx, PF 0x%llx\n",
		new_crs->cr0_hi.CR0_hi_ip << 3,
		new_crs->cr0_lo.CR0_lo_pf);

	new_crs->cr1_lo.CR1_lo_half = user_info.cr1_wd;
	new_crs->cr1_hi.CR1_hi_half = user_info.cr1_ussz;
	DebugKVMCPY("new chain registers: wbs 0x%x, ussz 0x%x\n",
		new_crs->cr1_lo.CR1_lo_wbs * EXT_4_NR_SZ,
		new_crs->cr1_hi.CR1_hi_ussz << 4);

	/* copy last guest user CRS frame to top of guest kernel stack */
	ret = prepare_pv_vcpu_last_user_crs(vcpu, new_stacks, new_crs);
	if (unlikely(ret)) {
		pr_err("%s(): user CRS frame copy failed\n", __func__);
		goto out_free_gmm;
	}

	/* inject CRS for return from system call to guest user */
	ret = prepare_pv_vcpu_fork_trampoline(vcpu, gti, new_stacks);
	if (unlikely(ret)) {
		pr_err("%s(): fork trampoline CRS frame copy failed\n",
			__func__);
		goto out_free_gmm;
	}

	/* inject CRS frame to return from fork() on the child */
	/* these CRS should be as switch to frame (see switch_to()) */
	ret = prepare_pv_vcpu_ret_from_fork_frame(vcpu, gti, new_stacks,
				new_crs, (void *)user_info.entry_point);
	if (unlikely(ret)) {
		pr_err("%s(): return from fork() CRS frame copy failed\n",
			__func__);
		goto out_free_gmm;
	}

	/* save user special registers to initial state while switch */
	gti->task_is_binco =
		((user_info.flags & BIN_COMP_CODE_TASK_FLAG) != 0);
	gti->task_is_protect =
		((user_info.flags & PROTECTED_CODE_TASK_FLAG) != 0);

	kvm_put_guest_new_sw_regs(vcpu, gti, new_stacks, new_crs,
				(unsigned long *)user_info.gregs);

	/* prepare new shadow PT to switch to */
	u_pptb = gmm_info.u_pptb;
	ret = kvm_pv_prepare_guest_mm(vcpu, gmm, u_pptb);
	if (ret) {
		pr_err("%s(): could not prepare shadow PT for new guest "
			"process, error %d\n",
			__func__, ret);
		goto out_free_gmm;
	}

	/* return ID of created gmm struct to guest */
	gmm_info.gmmid_nr = gmmid_nr;
	ret = kvm_vcpu_copy_to_guest(vcpu, gmmu_info, &gmm_info,
						sizeof(*gmmu_info));
	if (unlikely(ret < 0)) {
		pr_err("%s(): copy updated gmm info to user failed, retry\n",
			__func__);
		goto out_free_gmm;
	}

	DebugFRTASK("created task GPID #%d GMMID #%d\n",
		gti->gpid->nid.nr, gmm->nid.nr);

	if (DEBUG_KVM_COPY_USER_MODE)
		debug_copy_guest = false;

	return gti->gpid->nid.nr;

out_free_gmm:
	kvm_free_gmm(kvm, gmm);
	gti->gmm = NULL;
out_free_gti:
	free_guest_thread_info(kvm, gti);

	if (DEBUG_KVM_COPY_USER_MODE)
		debug_copy_guest = false;
	return ret;
}

/*
 * End of copy_thread() for guest user thread (clone_user_stacks()):
 */
int kvm_clone_guest_user_stacks(struct kvm_vcpu *vcpu,
			kvm_task_info_t __user *task_info)
{
	struct kvm	*kvm = vcpu->kvm;
	pt_regs_t	*cur_regs, *regs;
	gthread_info_t	*cur_gti, *gti;
	gmm_struct_t	*gmm;
	guest_hw_stack_t *stack_regs;
	e2k_stacks_t	*new_stacks;
	e2k_mem_crs_t	*new_crs;
	kvm_task_info_t	user_info;
	e2k_usd_lo_t	usd_lo;
	e2k_usd_hi_t	usd_hi;
	e2k_addr_t	sbr;
	e2k_size_t	us_size;
	e2k_psp_lo_t	psp_lo;
	e2k_psp_hi_t	psp_hi;
	e2k_pcsp_lo_t	pcsp_lo;
	e2k_pcsp_hi_t	pcsp_hi;
	int		ret;

	ret = kvm_vcpu_copy_from_guest(vcpu, &user_info, task_info,
						sizeof(*task_info));
	if (unlikely(ret < 0)) {
		pr_err("%s(): copy new task info from user failed\n",
			__func__);
		return ret;
	}
	if (DEBUG_KVM_CLONE_USER_MODE)
		debug_clone_guest = true;

	gti = alloc_guest_thread_info(kvm);
	if (gti == NULL) {
		pr_err("%s(): could not create guest thread info\n",
			__func__);
		return -ENOMEM;
	}
	DebugKVMCLN("allocated guest thread info agent GPID #%d\n",
		gti->gpid->nid.nr);

	cur_gti = pv_vcpu_get_gti(vcpu);
	BUG_ON(cur_gti == NULL);
	gmm = cur_gti->gmm;
	BUG_ON(gmm == NULL);
	kvm_gmm_get(vcpu, gti, gmm);

	/*
	 * Mark the parent & child processes as user threads
	 * on common virtual memory (gmm structure)
	 */
	set_gti_thread_flag(cur_gti, GTIF_USER_THREAD);
	set_gti_thread_flag(gti, GTIF_USER_THREAD);

	cur_regs = &cur_gti->fork_regs;
	regs = &gti->fork_regs;
	KVM_BUG_ON(!is_sys_call_pt_regs(cur_regs));
	*regs = *cur_regs;

	stack_regs = &gti->stack_regs;
	new_stacks = &stack_regs->stacks;
	new_crs = &stack_regs->crs;

	/*
	 * New user stacks (data and hardware) were allocated by guest
	 * Create all register state for new guest stacks
	 */
	kvm_init_guest_user_stacks(vcpu, gti, gmm, &user_info, stack_regs,
					false	/* set guest kernel stacks */);

	/* setup guest user register state to return to new thread */
	us_size = user_info.u_us_size;
	sbr = user_info.u_us_base + us_size;	/* top of stack */
	usd_hi.USD_hi_half = 0;
	usd_lo.USD_lo_half = 0;
	usd_hi.USD_hi_size = user_info.u_sp_offset;
	usd_lo.USD_lo_base = user_info.u_us_base + user_info.u_sp_offset;
	sbr = round_up(sbr, E2K_ALIGN_STACK_BASE_REG);
	regs->stacks.top = sbr;
	regs->stacks.usd_hi = usd_hi;
	regs->stacks.usd_lo = usd_lo;
	DebugKVMCLN("local guest user data stack base 0x%llx size 0x%x "
		"top 0x%lx\n",
		 usd_lo.USD_lo_base, usd_hi.USD_hi_size, sbr);

	psp_hi.PSP_hi_half = 0;
	psp_lo.PSP_lo_half = 0;
	psp_hi.PSP_hi_size = user_info.u_ps_size;
	psp_hi.PSP_hi_ind  = user_info.u_ps_ind;
	psp_lo.PSP_lo_base = user_info.u_ps_base;
	regs->stacks.psp_hi = psp_hi;
	regs->stacks.psp_lo = psp_lo;
	DebugKVMCLN("new guest user procedure stack from 0x%llx size 0x%x "
		"ind 0x%x\n",
		psp_lo.PSP_lo_base, psp_hi.PSP_hi_size, psp_hi.PSP_hi_ind);

	pcsp_hi.PCSP_hi_half = 0;
	pcsp_lo.PCSP_lo_half = 0;
	pcsp_hi.PCSP_hi_size = user_info.u_pcs_size;
	pcsp_hi.PCSP_hi_ind  = user_info.u_pcs_ind;
	pcsp_lo.PCSP_lo_base = user_info.u_pcs_base;
	regs->stacks.pcsp_hi = pcsp_hi;
	regs->stacks.pcsp_lo = pcsp_lo;
	DebugKVMCLN("new guest user chain stack from 0x%llx size 0x%x "
		"ind 0x%x\n",
		pcsp_lo.PCSP_lo_base, pcsp_hi.PCSP_hi_size,
		pcsp_hi.PCSP_hi_ind);

	new_crs->cr0_lo.CR0_lo_half = user_info.cr0_lo;
	new_crs->cr0_hi.CR0_hi_half = user_info.cr0_hi;
	DebugKVMCLN("new chain registers: IP 0x%llx, PF 0x%llx\n",
		new_crs->cr0_hi.CR0_hi_IP,
		new_crs->cr0_lo.CR0_lo_pf);

	new_crs->cr1_lo.CR1_lo_half = user_info.cr1_wd;
	new_crs->cr1_hi.CR1_hi_half = user_info.cr1_ussz;
	DebugKVMCLN("new chain registers: wbs 0x%x, ussz 0x%x\n",
		new_crs->cr1_lo.CR1_lo_wbs * EXT_4_NR_SZ,
		new_crs->cr1_hi.CR1_hi_ussz << 4);

	/* copy last guest user CRS frame to top of guest kernel stack */
	ret = prepare_pv_vcpu_last_user_crs(vcpu, new_stacks, new_crs);
	if (unlikely(ret)) {
		pr_err("%s(): user CRS frame copy failed\n", __func__);
		goto out_free_gmm;
	}

	/* inject CRS for return from system call to guest user */
	ret = prepare_pv_vcpu_fork_trampoline(vcpu, gti, new_stacks);
	if (unlikely(ret)) {
		pr_err("%s(): fork trampoline CRS frame copy failed\n",
			__func__);
		goto out_free_gmm;
	}

	/* inject CRS frame to return from fork() on the child */
	/* these CRS should be as switch to frame (see switch_to()) */
	ret = prepare_pv_vcpu_ret_from_fork_frame(vcpu, gti, new_stacks,
				new_crs, (void *)user_info.entry_point);
	if (unlikely(ret)) {
		pr_err("%s(): return from fork() CRS frame copy failed\n",
			__func__);
		goto out_free_gmm;
	}

	/* save user special registers to initial state while switch */
	gti->task_is_binco =
		((user_info.flags & BIN_COMP_CODE_TASK_FLAG) != 0);
	gti->task_is_protect =
		((user_info.flags & PROTECTED_CODE_TASK_FLAG) != 0);

	kvm_put_guest_new_sw_regs(vcpu, gti, new_stacks, new_crs,
				(unsigned long *)user_info.gregs);

	DebugFRTASK("created thread GPID #%d GMMID #%d\n",
		gti->gpid->nid.nr, gmm->nid.nr);

	if (DEBUG_KVM_CLONE_USER_MODE)
		debug_clone_guest = false;

	return gti->gpid->nid.nr;

out_free_gmm:
	kvm_gmm_put(kvm, gti);

	free_guest_thread_info(kvm, gti);

	if (DEBUG_KVM_CLONE_USER_MODE)
		debug_clone_guest = false;
	return ret;
}

int kvm_sig_handler_return(struct kvm_vcpu *vcpu, kvm_stacks_info_t *regs_info,
				unsigned long sigreturn_entry, long sys_rval,
				guest_hw_stack_t *stack_regs)
{
	kvm_stacks_info_t user_info;
	struct signal_stack_context __user *context;
	pv_vcpu_ctxt_t *vcpu_ctxt;
	struct kvm_sw_cpu_context *sw_ctxt = &vcpu->arch.sw_ctxt;
	unsigned long ts_flag;
	int ret;

	ret = kvm_vcpu_copy_from_guest(vcpu, &user_info, regs_info,
						sizeof(*regs_info));
	if (ret < 0) {
		pr_err("%s(): copy stack registers state info from user "
			"failed\n", __func__);
		return ret;
	}

	stack_regs->stacks.top = user_info.top;
	stack_regs->stacks.usd_lo.USD_lo_half = user_info.usd_lo;
	stack_regs->stacks.usd_hi.USD_hi_half = user_info.usd_hi;
	DebugSIGH("data stack new: top 0x%lx base 0x%llx size 0x%x\n",
		stack_regs->stacks.top, stack_regs->stacks.usd_lo.USD_lo_base,
		stack_regs->stacks.usd_hi.USD_hi_size);
	/* update user local data stack pointer */
	sw_ctxt->sbr.SBR_reg = stack_regs->stacks.top;
	sw_ctxt->usd_lo = stack_regs->stacks.usd_lo;
	sw_ctxt->usd_hi = stack_regs->stacks.usd_hi;

	stack_regs->stacks.psp_lo.PSP_lo_half = user_info.psp_lo;
	stack_regs->stacks.psp_hi.PSP_hi_half = user_info.psp_hi;
	stack_regs->stacks.pshtp.PSHTP_reg = user_info.pshtp;
	DebugSIGH("procedure stack new: base 0x%llx size 0x%x ind 0x%x "
		"PSHTP 0x%llx\n",
		stack_regs->stacks.psp_lo.PSP_lo_base,
		stack_regs->stacks.psp_hi.PSP_hi_size,
		stack_regs->stacks.psp_hi.PSP_hi_ind,
		stack_regs->stacks.pshtp.PSHTP_reg);

	stack_regs->stacks.pcsp_lo.PCSP_lo_half = user_info.pcsp_lo;
	stack_regs->stacks.pcsp_hi.PCSP_hi_half = user_info.pcsp_hi;
	stack_regs->stacks.pcshtp = user_info.pcshtp;
	DebugSIGH("chain stack new: base 0x%llx size 0x%x ind 0x%x "
		"PCSHTP 0x%x\n",
		stack_regs->stacks.pcsp_lo.PCSP_lo_base,
		stack_regs->stacks.pcsp_hi.PCSP_hi_size,
		stack_regs->stacks.pcsp_hi.PCSP_hi_ind,
		stack_regs->stacks.pcshtp);

	stack_regs->crs.cr0_lo.CR0_lo_half = user_info.cr0_lo;
	stack_regs->crs.cr0_hi.CR0_hi_half = user_info.cr0_hi;
	stack_regs->crs.cr1_lo.CR1_lo_half = user_info.cr1_lo;
	stack_regs->crs.cr1_hi.CR1_hi_half = user_info.cr1_hi;
	DebugSIGH("chain CR0-CR1 : IP 0x%llx wbs 0x%x wpsz 0x%x wfx %d\n",
		stack_regs->crs.cr0_hi.CR0_hi_IP,
		stack_regs->crs.cr1_lo.CR1_lo_wbs,
		stack_regs->crs.cr1_lo.CR1_lo_wpsz,
		stack_regs->crs.cr1_lo.CR1_lo_wfx);

	KVM_BUG_ON(stack_regs->crs.cr1_lo.CR1_lo_pm ||
			!stack_regs->crs.cr1_lo.CR1_lo_ie ||
				!stack_regs->crs.cr1_lo.CR1_lo_nmie);

	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
	context = get_signal_stack();
	vcpu_ctxt = &context->vcpu_ctxt;
	ret = __put_user(true, &vcpu_ctxt->in_sig_handler);
	ret |= __put_user(sigreturn_entry, &vcpu_ctxt->sigreturn_entry);
	ret |= __put_user(sys_rval, &vcpu_ctxt->sys_rval);
	clear_ts_flag(ts_flag);

	return ret;
}

int kvm_long_jump_return(struct kvm_vcpu *vcpu,
				kvm_long_jump_info_t *regs_info)
{
	kvm_long_jump_info_t user_info;
	struct signal_stack_context __user *context;
	e2k_stacks_t stacks;
	e2k_mem_crs_t crs;
	unsigned long ts_flag;
	int ret;

	ret = kvm_vcpu_copy_from_guest(vcpu, &user_info, regs_info,
						sizeof(*regs_info));
	if (unlikely(ret < 0)) {
		pr_err("%s(): copy stack registers state info from user "
			"failed\n", __func__);
		return ret;
	}

	context = get_signal_stack();

	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);

	ret = __copy_from_user(&stacks, &context->regs.stacks,
				sizeof(stacks));
	ret |= __copy_from_user(&crs, &context->regs.crs,
				sizeof(crs));

	clear_ts_flag(ts_flag);
	if (ret) {
		goto failed;
	}

	stacks.top = user_info.top;
	stacks.usd_lo.USD_lo_half = user_info.usd_lo;
	stacks.usd_hi.USD_hi_half = user_info.usd_hi;
	DebugLJMP("data stack new: top 0x%lx base 0x%llx size 0x%x\n",
		stacks.top, stacks.usd_lo.USD_lo_base,
		stacks.usd_hi.USD_hi_size);

	stacks.psp_lo.PSP_lo_half = user_info.psp_lo;
	stacks.psp_hi.PSP_hi_half = user_info.psp_hi;
	stacks.pshtp.PSHTP_reg = user_info.pshtp;
	DebugLJMP("procedure stack new: base 0x%llx size 0x%x ind 0x%x "
		"PSHTP 0x%llx\n",
		stacks.psp_lo.PSP_lo_base,
		stacks.psp_hi.PSP_hi_size,
		stacks.psp_hi.PSP_hi_ind,
		stacks.pshtp.PSHTP_reg);

	stacks.pcsp_lo.PCSP_lo_half = user_info.pcsp_lo;
	stacks.pcsp_hi.PCSP_hi_half = user_info.pcsp_hi;
	stacks.pcshtp = user_info.pcshtp;
	DebugLJMP("chain stack new: base 0x%llx size 0x%x ind 0x%x "
		"PCSHTP 0x%x\n",
		stacks.pcsp_lo.PCSP_lo_base,
		stacks.pcsp_hi.PCSP_hi_size,
		stacks.pcsp_hi.PCSP_hi_ind,
		stacks.pcshtp);

	crs.cr0_lo.CR0_lo_half = user_info.cr0_lo;
	crs.cr0_hi.CR0_hi_half = user_info.cr0_hi;
	crs.cr1_lo.CR1_lo_half = user_info.cr1_lo;
	crs.cr1_hi.CR1_hi_half = user_info.cr1_hi;
	DebugLJMP("chain CR0-CR1 : IP 0x%llx wbs 0x%x wpsz 0x%x wfx %d\n",
		crs.cr0_hi.CR0_hi_IP,
		crs.cr1_lo.CR1_lo_wbs,
		crs.cr1_lo.CR1_lo_wpsz,
		crs.cr1_lo.CR1_lo_wfx);

	KVM_BUG_ON(crs.cr1_lo.CR1_lo_pm ||
			!crs.cr1_lo.CR1_lo_ie ||
				!crs.cr1_lo.CR1_lo_nmie);

	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);

	ret = __copy_to_user(&context->regs.stacks, &stacks, sizeof(stacks));
	ret |= __copy_to_user(&context->regs.crs, &crs, sizeof(crs));

	clear_ts_flag(ts_flag);
	if (ret) {
		goto failed;
	}

	return 0;

failed:
	user_exit();
	do_exit(SIGKILL);
	return ret;
}

void kvm_guest_vcpu_common_idle(struct kvm_vcpu *vcpu,
				long timeout, bool interruptable)
{
	long out;

	DebugKVMIDLE("started on VCPU %d\n", vcpu->vcpu_id);

	BUG_ON(!vcpu->arch.is_hv && vcpu->arch.host_task == NULL);

	if (kvm_guest_vcpu_thread_should_stop(vcpu))
		goto need_stopped;

	BUG_ON(vcpu->arch.on_idle);
	BUG_ON(kvm_get_guest_vcpu_runstate(vcpu) != RUNSTATE_in_hcall);
	if (kvm_test_pending_virqs(vcpu)) {
		/* guest has pending VIRQs, so complete idle mode right now */
		/* to inject interrupt while hypercall return */
		return;
	}
	kvm_update_guest_vcpu_current_runstate(vcpu, RUNSTATE_blocked);
	vcpu->arch.on_idle = interruptable;

	if (timeout == 0) {
		/* schedule the CPU away without any timeout */
		timeout = MAX_SCHEDULE_TIMEOUT;
	}
	set_current_state(TASK_INTERRUPTIBLE);
	if (interruptable)
		kvm_arch_vcpu_to_wait(vcpu);
	out = schedule_timeout(timeout);
	vcpu->arch.on_idle = false;
	if (interruptable)
		kvm_arch_vcpu_to_run(vcpu);
	BUG_ON(kvm_get_guest_vcpu_runstate(vcpu) != RUNSTATE_blocked);
	kvm_update_guest_vcpu_current_runstate(vcpu, RUNSTATE_in_hcall);
	__set_current_state(TASK_RUNNING);
	if (out > 0) {
		DebugKVMIDLE("VCPU %d waked up on some event\n",
			vcpu->vcpu_id);
	} else {
		DebugKVMIDLE("VCPU %d waked up on timeout\n",
			vcpu->vcpu_id);
	}
need_stopped:
	if (kvm_guest_vcpu_thread_should_stop(vcpu)) {
		DebugKVMSH("guest VCPU #%d should be stopped\n",
			vcpu->vcpu_id);
		kvm_spare_host_vcpu_release(vcpu);
		do_exit(-EINTR);
	}
}

/*
 * Activate VCPU which is wating for activation in idle mode
 */
static int do_activate_host_vcpu(struct kvm_vcpu *vcpu)
{
	DebugKVMIDLE("started on VCPU %d to activate VCPU #%d\n",
		current_thread_info()->vcpu->vcpu_id, vcpu->vcpu_id);

	mutex_lock(&vcpu->arch.lock);
	if (vcpu->arch.host_task == NULL) {
		mutex_unlock(&vcpu->arch.lock);
		pr_err("%s(): guest thread of VCPU #%d does not exist, "
			"probably completed\n",
			__func__, vcpu->vcpu_id);
		return -ENODEV;
	}
	wake_up_process(vcpu->arch.host_task);
	mutex_unlock(&vcpu->arch.lock);
	return 0;
}
int kvm_activate_host_vcpu(struct kvm *kvm, int vcpu_id)
{
	struct kvm_vcpu *vcpu_to;	/* the VCPU to activate */
	struct kvm_vcpu *vcpu_from;	/* current VCPU */
	int ret;

	vcpu_from = current_thread_info()->vcpu;
	BUG_ON(vcpu_from == NULL);
	BUG_ON(vcpu_from->kvm != kvm);

	mutex_lock(&kvm->lock);
	vcpu_to = kvm_get_vcpu_on_id(kvm, vcpu_id);
	if (IS_ERR(vcpu_to)) {
		mutex_unlock(&kvm->lock);
		pr_err("%s(): could not find VCPU #%d to activate\n",
			__func__, vcpu_id);
		return PTR_ERR(vcpu_to);
	}
	ret = do_activate_host_vcpu(vcpu_to);
	mutex_unlock(&kvm->lock);
	return ret;
}

/* Suspend vcpu thread until it will be woken up by pv_kick */
void kvm_pv_wait(struct kvm *kvm, struct kvm_vcpu *vcpu)
{
	/*
	 * If vcpu has pending VIRQs, do not put its thread
	 * into sleep. Exit from kvm_pv_wait to inject
	 * interrupt while hypercall returns.
	 */
	if (kvm_test_pending_virqs(vcpu))
		return;

	/* Update arch-dependent state of vcpu */
	kvm_update_guest_vcpu_current_runstate(vcpu, RUNSTATE_blocked);
	/* For PV guest */
	vcpu->arch.on_idle = true;

	vcpu->arch.mp_state = KVM_MP_STATE_HALTED;

	/* Suspend vcpu thread until it will be woken up by pv_kick */
	kvm_vcpu_block(vcpu);

	/*
	 * Clear KVM_REQ_UNHALT bit in vcpu->requests.
	 * We need to do it here because kvm_vcpu_block sets this bit
	 * after vcpu thread is woken up.
	 */
	kvm_check_request(KVM_REQ_UNHALT, vcpu);

	vcpu->arch.mp_state = KVM_MP_STATE_RUNNABLE;
	vcpu->arch.unhalted = false;

	/* Restore arch-dependent state of vcpu */
	vcpu->arch.on_idle = false;
	kvm_update_guest_vcpu_current_runstate(vcpu, RUNSTATE_in_hcall);
}

/* Wake up sleeping vcpu thread */
void kvm_pv_kick(struct kvm *kvm, int hard_cpu_id)
{
	struct kvm_vcpu *vcpu_to;

	/* Get vcpu by given cpu id */
	if (kvm_is_epic(kvm))
		/* FIXME ioepic does not currently support logical cp
		 * numbering, bug 122110
		 */
		vcpu_to = kvm_get_vcpu_on_hard_cpu_id(kvm, hard_cpu_id);
	else
		vcpu_to = kvm_get_vcpu_on_id(kvm, hard_cpu_id);

	vcpu_to->arch.unhalted = true;

	/* Send wake up to target vcpu thread */
	kvm_vcpu_wake_up(vcpu_to);

	/* Yield our cpu to woken vcpu_to thread if possible */
	kvm_vcpu_yield_to(vcpu_to);
}
int kvm_activate_guest_all_vcpus(struct kvm *kvm)
{
	struct kvm_vcpu *vcpu_to;	/* follow VCPU to activate */
	struct kvm_vcpu *vcpu_from;	/* current VCPU */
	int r;
	int ret;
	int err = 0;

	vcpu_from = current_thread_info()->vcpu;
	BUG_ON(vcpu_from == NULL);
	BUG_ON(vcpu_from->kvm != kvm);

	mutex_lock(&kvm->lock);
	kvm_for_each_vcpu(r, vcpu_to, kvm) {
		if (vcpu_to != NULL && vcpu_to->vcpu_id != vcpu_from->vcpu_id) {
			ret = do_activate_host_vcpu(vcpu_to);
			if (ret && !err)
				err = ret;
		}
	}
	mutex_unlock(&kvm->lock);
	return err;
}

long kvm_guest_shutdown(struct kvm_vcpu *vcpu, void __user *msg,
							unsigned long reason)
{
	char buffer[512];
	int count = sizeof(buffer);
	char *todo;
	char *buf;
	e2k_addr_t hva_msg;
	int exit_reason;
	int ret;
	kvm_arch_exception_t exception;

	DebugKVMSH("started for msg %px, reason %ld\n",
		msg, reason);
	if (msg != NULL) {
		hva_msg = kvm_vcpu_gva_to_hva(vcpu, (gva_t)msg,
					false, &exception);
		if (kvm_is_error_hva(hva_msg)) {
			DebugKVM("failed to find GPA for dst %lx GVA, "
				"inject page fault to guest\n", msg);
			kvm_vcpu_inject_page_fault(vcpu, (void *)msg,
						&exception);
			return -EAGAIN;
		}
	} else {
		hva_msg = 0;
	}
	if (hva_msg == 0) {
		DebugKVMSH("could not copy string from user\n");
		buf = NULL;
	} else {
		ret = copy_from_user(buffer, (char *)hva_msg, count);
		if (ret) {
			DebugKVMSH("could not copy string from user, err %d\n",
				ret);
			buf = NULL;
		} else {
			buffer[count - 1] = '\0';
			buf = buffer;
		}
	}
	switch (reason) {
	case KVM_SHUTDOWN_POWEROFF:
		exit_reason = KVM_EXIT_SHUTDOWN;
		todo = "power off";
		break;
	case KVM_SHUTDOWN_RESTART:
		exit_reason = KVM_EXIT_E2K_RESTART;
		todo = "restart";
		break;
	case KVM_SHUTDOWN_PANIC:
		exit_reason = KVM_EXIT_E2K_PANIC;
		todo = "panic";
		break;
	default:
		exit_reason = KVM_EXIT_UNKNOWN;
		todo = "???";
		break;
	}
	DebugKVMSH("started to %s : %s\n",
		todo, (buf) ? buf : "??? unknown reason ???");
	if (reason == KVM_SHUTDOWN_PANIC) {
		/* FIXME: it need dump guest VCPU stack, */
		/* but it is not yet implemented here */
	}

	vcpu->arch.exit_reason = EXIT_SHUTDOWN;
	vcpu->run->exit_reason = exit_reason;

	DebugKVMSH("VCPU #%d thread exits\n", vcpu->vcpu_id);

	if (!vcpu->arch.is_hv) {
		/* return to host VCPU to handle exit reason */
		return RETURN_TO_HOST_APP_HCRET;
	} else {
		/* inject intercept as hypercall return to switch to */
		/* vcpu run thread and handle VM exit on guest shutdown */
		kvm_inject_vcpu_exit(vcpu);
	}
	return 0;
}

static int kvm_guest_failed(struct kvm_vcpu *vcpu)
{
	DebugKVMSH("%s (%d) started on unknown failure\n",
		current->comm, current->pid);

	vcpu->arch.exit_reason = EXIT_SHUTDOWN;
	vcpu->run->exit_reason = KVM_EXIT_SHUTDOWN;

	kvm_update_guest_vcpu_current_runstate(vcpu, RUNSTATE_offline);

	if (!vcpu->arch.is_hv) {
		/* return to host VCPU to handle exit reason */
		return RETURN_TO_HOST_APP_HCRET;
	} else {
		/* inject intercept as hypercall return to switch to */
		/* vcpu run thread and handle VM exit on guest failure */
		kvm_inject_vcpu_exit(vcpu);
	}
	return 0;
}

#ifdef CONFIG_KVM_ASYNC_PF

/*
 * Enable async page fault handling on current vcpu
 */
int kvm_pv_host_enable_async_pf(struct kvm_vcpu *vcpu,
				u64 apf_reason_gpa, u64 apf_id_gpa,
				u32 apf_ready_vector, u32 irq_controller)
{
	if (kvm_gfn_to_hva_cache_init(vcpu->kvm, &vcpu->arch.apf.reason_gpa,
				apf_reason_gpa, sizeof(u32)))
		return 1;

	if (kvm_gfn_to_hva_cache_init(vcpu->kvm, &vcpu->arch.apf.id_gpa,
				apf_id_gpa, sizeof(u32)))
		return 1;

	vcpu->arch.apf.cnt = 1;
	vcpu->arch.apf.host_apf_reason = KVM_APF_NO;
	vcpu->arch.apf.in_pm = false;
	vcpu->arch.apf.apf_ready_vector = apf_ready_vector;
	vcpu->arch.apf.irq_controller = irq_controller;
	vcpu->arch.apf.enabled = true;

	return 0;
}

#endif /* CONFIG_KVM_ASYNC_PF */

#define TIMEOUT_FOR_PRINT_VCPU_STACKS_MS  30000
static int wait_for_discard(struct wait_bit_key *key, int mode)
{
	freezable_schedule_unsafe();
	if (signal_pending_state(mode, current))
		return -ERESTARTSYS;
	return 0;
}
static inline void
do_wait_for_print_vcpu_stack(struct kvm_vcpu *vcpu)
{
	DebugGST("started for VCPU #%d\n", vcpu->vcpu_id);
	if (kvm_start_vcpu_show_state(vcpu)) {
		/* show of VCPU state is already in progress */
		DebugGST("show of VCPU state is already in progress on "
			"VCPU #%d\n",
			vcpu->vcpu_id);
		return;
	}
	local_irq_enable();
	DebugGST("will send SYSRQ for VCPU #%d\n", vcpu->vcpu_id);
	kvm_pic_sysrq_deliver(vcpu);
	DebugGST("goto wait on bit of completion on for VCPU #%d\n",
		vcpu->vcpu_id);
	wait_on_bit_action((void *)&vcpu->requests, KVM_REG_SHOW_STATE,
				wait_for_discard, TASK_KILLABLE);
	DO_DUMP_VCPU_STACK(vcpu) = false;
	DebugGST("waiting is completed for VCPU #%d\n", vcpu->vcpu_id);
}

static int wait_for_print_vcpu_stack(void *data)
{
	struct kvm_vcpu *vcpu = data;

	DebugGST("started for VCPU #%d\n", vcpu->vcpu_id);
	do_wait_for_print_vcpu_stack(vcpu);
	return 0;
}
static inline void
do_wait_for_print_all_guest_stacks(struct kvm *kvm)
{
	struct kvm_vcpu *vcpu;
	struct kvm_vcpu *other_vcpu;
	int r;

	mutex_lock(&kvm->lock);
	vcpu = kvm_get_vcpu(kvm, 0);
	if (vcpu == NULL) {
		mutex_unlock(&kvm->lock);
		DebugGST("nothing VCPUs detected\n");
		return;
	}
	DO_DUMP_VCPU_STATE(vcpu) = true;
	do_wait_for_print_vcpu_stack(vcpu);
	DO_DUMP_VCPU_STATE(vcpu) = false;
	kvm_for_each_vcpu(r, other_vcpu, kvm) {
		/* show state of the guest process on the VCPU */
		if (other_vcpu == NULL)
			continue;
		if (other_vcpu == vcpu)
			continue;
		DO_DUMP_VCPU_STACK(other_vcpu) = true;
		do_wait_for_print_vcpu_stack(other_vcpu);
	}
	if (!test_and_clear_kvm_mode_flag(kvm, KVMF_IN_SHOW_STATE)) {
		mutex_unlock(&kvm->lock);
		DebugGST("show of KVM state was not started\n");
		return;
	}
	mutex_unlock(&kvm->lock);
}
void wait_for_print_all_guest_stacks(struct work_struct *work)
{
	struct kvm *kvm;

	mutex_lock(&kvm_lock);
	if (list_empty(&vm_list)) {
		mutex_unlock(&kvm_lock);
		DebugGST("nothing VM detected\n");
		return;
	}
	list_for_each_entry(kvm, &vm_list, vm_list) {
		DebugGST("started for VM #%d\n", kvm->arch.vmid.nr);
		if (test_and_set_kvm_mode_flag(kvm, KVMF_IN_SHOW_STATE)) {
			DebugGST("show of VM #%d state is already "
				"in progress\n", kvm->arch.vmid.nr);
			continue;
		}
		do_wait_for_print_all_guest_stacks(kvm);
	}
	mutex_unlock(&kvm_lock);
}
static inline void
deferred_print_vcpu_stack(struct kvm_vcpu *vcpu)
{
	struct task_struct *task;

	DebugGST("started for VCPU #%d\n", vcpu->vcpu_id);

	/* create thread to show state of guest current process on the VCPU */
	/* Function wait_for_print_all_guest_stacks() wait for print */
	/* so cannot be called directly from idle thread for example */
	if (!is_idle_task(current)) {
		task = kthread_create_on_node(wait_for_print_vcpu_stack, vcpu,
						numa_node_id(),
						"show-vcpu/%d", vcpu->vcpu_id);
		if (IS_ERR(task)) {
			pr_err("%s(): could not create thread to dump VCPU #%d "
				"current stack\n",
				__func__, vcpu->vcpu_id);
			return;
		}
		wake_up_process(task);
	} else {
		int pid;

		pid = kernel_thread(wait_for_print_vcpu_stack, vcpu,
					CLONE_FS | CLONE_FILES);
		if (pid < 0) {
			pr_err("%s(): Could not create thread to dump VCPU #%d "
				"stack(s)\n",
				__func__, vcpu->vcpu_id);
			return;
		}
		rcu_read_lock();
		task = find_task_by_pid_ns(pid, &init_pid_ns);
		rcu_read_unlock();
		snprintf(task->comm, sizeof(task->comm),
				"show-vcpu/%d", vcpu->vcpu_id);
	}
	DebugGST("created thread %s (%d) to wait for completion "
		"on VCPU #%d\n",
		task->comm, task->pid, vcpu->vcpu_id);
}
void kvm_print_vcpu_stack(struct kvm_vcpu *vcpu)
{
	DebugGST("started for VCPU #%d\n", vcpu->vcpu_id);
	deferred_print_vcpu_stack(vcpu);
}
/* This could be called from IRQ context, so defer work instead of creating
 * kthread */
static inline void
deferred_print_all_guest_stacks(void)
{
	DebugGST("started for all VMs\n");
	schedule_work(&kvm_dump_stacks);
	DebugGST("done\n");
}

void kvm_print_all_vm_stacks(void)
{
	mutex_lock(&kvm_lock);
	if (list_empty(&vm_list)) {
		mutex_unlock(&kvm_lock);
		DebugGST("nothing VM detected\n");
		return;
	}
	deferred_print_all_guest_stacks();
	mutex_unlock(&kvm_lock);
}
