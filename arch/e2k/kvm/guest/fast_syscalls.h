#ifndef _E2K_KVM_GUEST_FAST_SYSCALLS_H
#define _E2K_KVM_GUEST_FAST_SYSCALLS_H

#include <linux/types.h>
#include <asm/fast_syscalls.h>

typedef int (*kvm_fast_system_call_func)(u64 arg1, u64 arg2);

extern const kvm_fast_system_call_func
		kvm_fast_sys_calls_table[NR_fast_syscalls];
extern const kvm_fast_system_call_func
		kvm_fast_sys_calls_table_32[NR_fast_syscalls];
extern const kvm_fast_system_call_func
		kvm_fast_sys_calls_table_128[NR_fast_syscalls];

#endif /* _E2K_KVM_GUEST_FAST_SYSCALLS_H */

