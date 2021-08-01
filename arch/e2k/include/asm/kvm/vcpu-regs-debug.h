/*
 * KVM guest kernel processes support
 * Copyright 2011 Salavat S. Guiliazov (atic@mcst.ru)
 */

#ifndef _E2K_KVM_VCPU_REGS_DEBUG_H
#define _E2K_KVM_VCPU_REGS_DEBUG_H

/* do not include this header directly, only through asm/kvm/guest.h */

#include <linux/types.h>

#undef	VCPU_REGS_DEBUG

typedef struct vcpu_regs {
	u64	IP;
	u64	IP_from;
	u64	clock_start;
	u64	clock_end;
	u32	psr;
	u32	upsr;
	bool	under_upsr;
	u8	updated;
	bool	injected;
} vcpu_regs_t;

#define	MAX_VCPU_REGS_TRACE_NUM		32
#define	VCPU_REGS_TRACE_MASK		(MAX_VCPU_REGS_TRACE_NUM - 1)
#define	VCPU_REGS_TRACE_INDEX(count)	((count) & VCPU_REGS_TRACE_MASK)

typedef struct vcpu_regs_trace {
	atomic_t	count;
	vcpu_regs_t	regs[MAX_VCPU_REGS_TRACE_NUM];
} vcpu_regs_trace_t;

#define	PSR_UPDATE_MASK		0x01U
#define	UPSR_UPDATE_MASK	0x02U
#define	UNDER_UPSR_UPDATE_MASK	0x04U

#define	GET_CLOCK_REG()		NATIVE_READ_CLKR_REG_VALUE()

#define GUEST_GET_IRQS_UNDER_UPSR() \
({ \
	kvm_vcpu_state_t *vcpu_state; \
	bool under_upsr; \
	\
	KVM_GET_VCPU_STATE_BASE(vcpu_state); \
	under_upsr = vcpu_state->irqs_under_upsr; \
	under_upsr; \
})

#ifdef	VCPU_REGS_DEBUG

#undef	PSR
extern bool vcpu_regs_trace_on;
extern int vcpu_regs_trace_on_num;

#define get_vcpu_regs_trace_struct() \
({ \
	struct kvm_vcpu_state *vcpu_state; \
	\
	KVM_GET_VCPU_STATE_BASE(vcpu_state); \
	&vcpu_state->trace; \
})

#define get_next_vcpu_regs_trace() \
({ \
	vcpu_regs_trace_t *trace; \
	vcpu_regs_t *regs; \
	int count; \
	\
	if (likely(!vcpu_regs_trace_on)) { \
		regs = NULL; \
	} else { \
		trace = get_vcpu_regs_trace_struct(); \
		count = atomic_inc_return(&trace->count); \
		regs = &trace->regs[VCPU_REGS_TRACE_INDEX(count)]; \
		regs->clock_start = GET_CLOCK_REG(); \
		regs->IP = NATIVE_READ_IP_REG_VALUE(); \
		regs->IP_from = NATIVE_NV_READ_CR0_HI_REG_VALUE(); \
		regs->updated = 0; \
		regs->psr = GUEST_GET_CPU_SREG(E2K_PSR); \
		regs->upsr = GUEST_GET_CPU_SREG(UPSR); \
		regs->under_upsr = GUEST_GET_IRQS_UNDER_UPSR(); \
		regs->injected = false; \
	} \
	regs; \
})

#define trace_vcpu_upsr_update(upsr_val, injected_irqs) \
do { \
	vcpu_regs_t *regs; \
	if (likely(!vcpu_regs_trace_on)) \
		break; \
	regs = get_next_vcpu_regs_trace(); \
	if (unlikely(regs == NULL)) \
		break; \
	regs->upsr = (upsr_val); \
	regs->updated |= UPSR_UPDATE_MASK; \
	if (injected_irqs) { \
		regs->injected = (injected_irqs); \
	} \
	E2K_CMD_SEPARATOR; \
	regs->clock_end = GET_CLOCK_REG(); \
} while (false)

#define trace_vcpu_psr_update(psr_val, under_upsr_mode) \
do { \
	vcpu_regs_t *regs; \
	if (likely(!vcpu_regs_trace_on)) \
		break; \
	regs = get_next_vcpu_regs_trace(); \
	if (unlikely(regs == NULL)) \
		break; \
	regs->psr = (psr_val); \
	regs->updated |= PSR_UPDATE_MASK | UNDER_UPSR_UPDATE_MASK; \
	regs->under_upsr = (under_upsr_mode); \
	E2K_CMD_SEPARATOR; \
	regs->clock_end = GET_CLOCK_REG(); \
} while (false)

#else	/* !VCPU_REGS_DEBUG */

#define	vcpu_regs_trace_on	false
#define trace_vcpu_upsr_update(upsr_val, injected_irqs)
#define trace_vcpu_psr_update(psr_val, under_upsr)

#endif	/* VCPU_REGS_DEBUG */

#endif /* ! _E2K_KVM_VCPU_REGS_DEBUG_H */
