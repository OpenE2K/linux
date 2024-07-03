/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * The hypercall to make some simple privileged actions by host,
 * but in guest context
 */

#include <linux/syscalls.h>
#include <linux/kvm_host.h>
#include <asm/trap_table.h>
#include <asm/process.h>
#include <asm/fast_syscalls.h>

#include <asm/kvm/priv-hypercall.h>

#include "cpu.h"
#include "string.h"

/*
 * This is the privileged actions hypercalls execution.
 * Lighte hypercalls do not:
 *  - switch to kernel stacks
 *  - use data stack
 *  - call any function this data stack using
 *  - switch guest mmu context
 *  - use host global registers (current/current_thread_info()/smp_processor_id()
 *	per_cpu()
 */
__priv_hypercall __section(".text.entry_priv_hcalls")
unsigned long kvm_priv_hcalls(unsigned long hcall_num,
		unsigned long arg1, unsigned long arg2,
		unsigned long arg3, unsigned long arg4,
		unsigned long arg5, unsigned long arg6,
		unsigned long arg7)
{
	struct thread_info *thread_info = READ_CURRENT_REG();
	struct kvm_vcpu	*vcpu = thread_info->vcpu;
	unsigned long ret = 0;

	switch (hcall_num) {
	case KVM_PRIV_HCALL_FAST_TAGGED_MEMORY_COPY:
		ret = kvm_priv_tagged_memory_copy((void *)arg1,
				(void *)arg2, arg3, arg4, arg5, (int)arg6);
		break;
	case KVM_PRIV_HCALL_FAST_TAGGED_MEMORY_SET:
		ret = kvm_priv_tagged_memory_set((void *)arg1,
				arg2, arg3, arg4, arg5);
		break;
	case KVM_PRIV_HCALL_FAST_TAGGED_MEMORY_COPY_USER:
		ret = kvm_priv_tagged_memory_copy_user((void *)arg1,
				(void *)arg2, arg3, arg4, arg5, (int)arg6);
		break;
	case KVM_PRIV_HCALL_FAST_TAGGED_MEMORY_SET_USER:
		ret = kvm_priv_tagged_memory_set_user((void *)arg1,
				arg2, arg3, arg4, arg5);
		break;
	case KVM_PRIV_HCALL_RETURN_FROM_FAST_SYSCALL:
		ret = kvm_return_from_fast_syscall(thread_info, arg1);
		/* restore MMU registers state */
		pv_mmu_switch_from_fast_sys_call(vcpu, thread_info);
		break;
	case KVM_PRIV_HCALL_SWITCH_RETURN_IP:
		ret = kvm_switch_guest_kernel_return_ip(arg1);
		break;
	case KVM_PRIV_HCALL_RECOVERY_FAULTED_STORE:
		ret = kvm_priv_recovery_faulted_store(arg1, arg2,
				arg3, arg4, arg5, arg6);
		break;
	case KVM_PRIV_HCALL_RECOVERY_FAULTED_LOAD:
		ret = kvm_priv_recovery_faulted_load(arg1, (u64 *)arg2,
				(u8 *)arg3, arg4, (int)arg5);
		break;
	case KVM_PRIV_HCALL_RECOVERY_FAULTED_MOVE:
		ret = kvm_priv_recovery_faulted_move(arg1, arg2,
				arg3, arg4, arg5, (int)arg6);
		break;
	case KVM_PRIV_HCALL_RECOVERY_FAULTED_LOAD_TO_GREG:
		ret = kvm_priv_recovery_faulted_load_to_greg(arg1, (int)arg2,
				arg3, arg4, (u64 *)arg5, (u64 *)arg6);
		break;
	default:
		ret = -ENOSYS;
	}

	return ret;
}
