/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#undef TRACE_SYSTEM
#define TRACE_SYSTEM virq

#if !defined(_KVM_TRACE_KVM_VIRQ_H) || defined(TRACE_HEADER_MULTI_READ)
#define _KVM_TRACE_KVM_VIRQ_H

#include <linux/types.h>
#include <linux/smp.h>
#include <linux/tracepoint.h>
#include <asm/kvm/irq.h>

#include "irq.h"

/*
 * Tracepoint for kvm interrupt injection:
 */

#define	TRACE_PRINT_PASS_VIRQ(pass_virq_err) \
		(__print_symbolic(pass_virq_err, \
			{ injected_pass_virq,		"to guest" }, \
			{ no_pending_pass_virq,		"no pending virqs" }, \
			{ irqs_disabled_pass_virq,	"irq disabled on guest" }, \
			{ vcpu_in_trap_pass_virq,	"vcpu in trap handler" }, \
			{ already_injected_pass_virq,	"was already injected" }))

TRACE_EVENT(kvm_pass_virqs_to_guest,
	TP_PROTO(struct kvm_vcpu *vcpu, pass_virq_t pass_virq_res),
	TP_ARGS(vcpu, pass_virq_res),

	TP_STRUCT__entry(
		__field(int, vcpu_id)
		__field(pass_virq_t, pass_virq_res)
	),

	TP_fast_assign(
		__entry->vcpu_id = vcpu->vcpu_id;
		__entry->pass_virq_res = pass_virq_res;
	),

	TP_printk("vcpu #%d interrup %s injected %s\n",
		__entry->vcpu_id,
		(__entry->pass_virq_res == injected_pass_virq) ? "is" : "is not",
		TRACE_PRINT_PASS_VIRQ(__entry->pass_virq_res))
);

TRACE_EVENT(kvm_irq_disabled_on_guest,
	TP_PROTO(struct kvm_vcpu *vcpu, unsigned long trap_ip,
		 unsigned int guest_upsr, unsigned int guest_psr),
	TP_ARGS(vcpu, trap_ip, guest_upsr, guest_psr),

	TP_STRUCT__entry(
		__field(int, vcpu_id)
		__field(unsigned long, trap_ip)
		__field(unsigned int, upsr)
		__field(unsigned int, psr)
	),

	TP_fast_assign(
		__entry->vcpu_id = vcpu->vcpu_id;
		__entry->trap_ip = trap_ip;
		__entry->upsr = guest_upsr;
		__entry->psr = guest_psr;
	),

	TP_printk("vcpu #%d\n"
		"trap IP 0x%lx, guest: UPSR 0x%x PSR 0x%x\n",
		__entry->vcpu_id, __entry->trap_ip, __entry->upsr, __entry->psr)
);

TRACE_EVENT(kvm_set_guest_vcpu_PSR,
	TP_PROTO(struct kvm_vcpu *vcpu, e2k_psr_t psr, e2k_psr_t new_psr,
		 bool irqs_under_upsr, unsigned long ip, unsigned long ip_from),
	TP_ARGS(vcpu, psr, new_psr, irqs_under_upsr, ip, ip_from),

	TP_STRUCT__entry(
		__field(int, vcpu_id)
		__field(unsigned int, psr)
		__field(unsigned int, new_psr)
		__field(bool, irqs_under_upsr)
		__field(unsigned long, ip)
		__field(unsigned long, ip_from)
	),

	TP_fast_assign(
		__entry->vcpu_id = vcpu->vcpu_id;
		__entry->psr = psr.PSR_reg;
		__entry->new_psr = new_psr.PSR_reg;
		__entry->irqs_under_upsr = irqs_under_upsr;
		__entry->ip = ip;
		__entry->ip_from = ip_from;
	),

	TP_printk("vcpu #%d\n"
		"PSR: old 0x%x new 0x%x, %s at IP %psx, from IP %psx\n",
		__entry->vcpu_id, __entry->psr, __entry->new_psr,
		(__entry->irqs_under_upsr) ? "to kernel" : "to_user",
		(void *)__entry->ip, (void *)__entry->ip_from)
);

TRACE_EVENT(kvm_vcpu_interrupt,
	TP_PROTO(struct kvm_vcpu *vcpu, unsigned int virq_id,
		 bool has_pending_virqs, int virqs_num, bool wake_up),
	TP_ARGS(vcpu, virq_id, has_pending_virqs, virqs_num, wake_up),

	TP_STRUCT__entry(
		__field(int, vcpu_id)
		__field(unsigned int, virq_id)
		__field(bool, has_pending_virqs)
		__field(int, virqs_num)
		__field(bool, wake_up)
	),

	TP_fast_assign(
		__entry->vcpu_id = vcpu->vcpu_id;
		__entry->virq_id = virq_id;
		__entry->has_pending_virqs = has_pending_virqs;
		__entry->virqs_num = virqs_num;
		__entry->wake_up = wake_up;
	),

	TP_printk("vcpu #%d virq #%u %s\n"
		"virqs num %d, has %s pending virq, %s\n",
		__entry->vcpu_id,
		__entry->virq_id, kvm_get_virq_name(__entry->virq_id),
		__entry->virqs_num,
		(__entry->has_pending_virqs) ? "already" : "not",
		(__entry->wake_up) ? "need wake up" : "need not wake up")
);

#define	TRACE_PRINT_VIRQ_WAKE_UP(wake_up_err) \
		(__print_symbolic(wake_up_err, \
			{ vcpu_virq_waked_up,		"is waked up" }, \
			{ need_not_virq_wake_up,	"need not wake up" }, \
			{ no_pending_virq_wake_up,	"has not pending virqs" }, \
			{ current_vcpu_virq_wake_up,	"is current vcpu virq" }, \
			{ active_vcpu_virq_wake_up,	"is active vcpu virq" }))

TRACE_EVENT(kvm_virq_wake_up,
	TP_PROTO(struct kvm_vcpu *vcpu, unsigned int virq_id,
		 virq_wake_up_t wake_up_res, int virqs_num, bool inject, bool wake_up),
	TP_ARGS(vcpu, virq_id, wake_up_res, virqs_num, inject, wake_up),

	TP_STRUCT__entry(
		__field(int, vcpu_id)
		__field(unsigned int, virq_id)
		__field(virq_wake_up_t, wake_up_res)
		__field(int, virqs_num)
		__field(bool, do_inject)
		__field(bool, do_wake_up)
	),

	TP_fast_assign(
		__entry->vcpu_id = vcpu->vcpu_id;
		__entry->virq_id = virq_id;
		__entry->wake_up_res = wake_up_res;
		__entry->virqs_num = virqs_num;
		__entry->do_inject = inject;
		__entry->do_wake_up = wake_up;
	),

	TP_printk("vcpu #%d virq #%u %s\n"
		"%s : virqs num %d, %s inject, %s wake up\n",
		__entry->vcpu_id,
		__entry->virq_id, kvm_get_virq_name(__entry->virq_id),
		TRACE_PRINT_VIRQ_WAKE_UP(__entry->wake_up_res),
		__entry->virqs_num,
		(__entry->do_inject) ? "need" : "need not",
		(__entry->do_wake_up) ? "need" : "need not")
);

#endif /* _KVM_TRACE_KVM_VIRQ_H */

#undef	TRACE_INCLUDE_PATH
#define	TRACE_INCLUDE_PATH ../arch/e2k/kvm
#undef	TRACE_INCLUDE_FILE
#define	TRACE_INCLUDE_FILE trace-virq

/* This part must be outside protection */
#include <trace/define_trace.h>
