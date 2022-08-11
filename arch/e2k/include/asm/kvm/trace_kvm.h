#if !defined(_TRACE_KVM_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_KVM_H

#include <linux/tracepoint.h>
#include <asm/kvm_host.h>

#undef TRACE_SYSTEM
#define TRACE_SYSTEM kvm

/*
 * Tracepoint for guest mode entry.
 */
TRACE_EVENT(kvm_entry,
	TP_PROTO(unsigned int vcpu_id),
	TP_ARGS(vcpu_id),

	TP_STRUCT__entry(
		__field(	unsigned int,	vcpu_id		)
	),

	TP_fast_assign(
		__entry->vcpu_id	= vcpu_id;
	),

	TP_printk("vcpu %u", __entry->vcpu_id)
);

/*
 * Tracepoint for hypercall.
 */
TRACE_EVENT(kvm_hypercall,
	TP_PROTO(unsigned long nr, unsigned long a0, unsigned long a1,
		 unsigned long a2, unsigned long a3),
	TP_ARGS(nr, a0, a1, a2, a3),

	TP_STRUCT__entry(
		__field(	unsigned long,	nr		)
		__field(	unsigned long,	a0		)
		__field(	unsigned long,	a1		)
		__field(	unsigned long,	a2		)
		__field(	unsigned long,	a3		)
	),

	TP_fast_assign(
		__entry->nr		= nr;
		__entry->a0		= a0;
		__entry->a1		= a1;
		__entry->a2		= a2;
		__entry->a3		= a3;
	),

	TP_printk("nr 0x%lx a0 0x%lx a1 0x%lx a2 0x%lx a3 0x%lx",
		 __entry->nr, __entry->a0, __entry->a1,  __entry->a2,
		 __entry->a3)
);

/*
 * Tracepoint for PIO.
 */
TRACE_EVENT(kvm_pio,
	TP_PROTO(unsigned int rw, unsigned int port, unsigned int size,
		 unsigned int count),
	TP_ARGS(rw, port, size, count),

	TP_STRUCT__entry(
		__field(	unsigned int,	rw		)
		__field(	unsigned int,	port		)
		__field(	unsigned int,	size		)
		__field(	unsigned int,	count		)
	),

	TP_fast_assign(
		__entry->rw		= rw;
		__entry->port		= port;
		__entry->size		= size;
		__entry->count		= count;
	),

	TP_printk("pio_%s at 0x%x size %d count %d",
		  __entry->rw ? "write" : "read",
		  __entry->port, __entry->size, __entry->count)
);

/*
 * Tracepoint for cpuid.
 */
TRACE_EVENT(kvm_cpuid,
	TP_PROTO(unsigned int function, unsigned long rax, unsigned long rbx,
		 unsigned long rcx, unsigned long rdx),
	TP_ARGS(function, rax, rbx, rcx, rdx),

	TP_STRUCT__entry(
		__field(	unsigned int,	function	)
		__field(	unsigned long,	rax		)
		__field(	unsigned long,	rbx		)
		__field(	unsigned long,	rcx		)
		__field(	unsigned long,	rdx		)
	),

	TP_fast_assign(
		__entry->function	= function;
		__entry->rax		= rax;
		__entry->rbx		= rbx;
		__entry->rcx		= rcx;
		__entry->rdx		= rdx;
	),

	TP_printk("func %x rax %lx rbx %lx rcx %lx rdx %lx",
		  __entry->function, __entry->rax,
		  __entry->rbx, __entry->rcx, __entry->rdx)
);

#define AREG(x) { APIC_##x, "APIC_" #x }

#define kvm_trace_symbol_apic						    \
	AREG(ID), AREG(LVR), AREG(TASKPRI), AREG(ARBPRI), AREG(PROCPRI),    \
	AREG(EOI), AREG(RRR), AREG(LDR), AREG(DFR), AREG(SPIV), AREG(ISR),  \
	AREG(TMR), AREG(IRR), AREG(ESR), AREG(ICR), AREG(ICR2), AREG(LVTT), \
	AREG(LVTTHMR), AREG(LVTPC), AREG(LVT0), AREG(LVT1), AREG(LVTERR),   \
	AREG(TMICT), AREG(TMCCT), AREG(TDCR), AREG(SELF_IPI)
/*
 * Tracepoint for apic access.
 */
TRACE_EVENT(kvm_apic,
	TP_PROTO(unsigned int rw, unsigned int reg, unsigned int val),
	TP_ARGS(rw, reg, val),

	TP_STRUCT__entry(
		__field(	unsigned int,	rw		)
		__field(	unsigned int,	reg		)
		__field(	unsigned int,	val		)
	),

	TP_fast_assign(
		__entry->rw		= rw;
		__entry->reg		= reg;
		__entry->val		= val;
	),

	TP_printk("apic_%s %s = 0x%x",
		  __entry->rw ? "write" : "read",
		  __print_symbolic(__entry->reg, kvm_trace_symbol_apic),
		  __entry->val)
);

#define trace_kvm_apic_read(reg, val)		trace_kvm_apic(0, reg, val)
#define trace_kvm_apic_write(reg, val)		trace_kvm_apic(1, reg, val)

#define CREG(x) { CEPIC_##x, "CEPIC_" #x }

#define kvm_trace_symbol_cepic						\
	CREG(CTRL), CREG(ID), CREG(CTRL2), CREG(DAT), CREG(DAT2),	\
	CREG(EPIC_INT), CREG(EPIC_INT2), CREG(EPIC_INT3), CREG(CPR),	\
	CREG(ESR), CREG(ESR2), CREG(EOI), CREG(CIR), CREG(GSTBASE_LO),	\
	CREG(GSTBASE_HI), CREG(GSTID), CREG(PNMIRR), CREG(ICR),		\
	CREG(ICR2), CREG(TIMER_LVTT), CREG(TIMER_INIT), CREG(TIMER_CUR),\
	CREG(TIMER_DIV), CREG(SVR), CREG(PNMIRR_MASK), CREG(VECT_INTA)	\

#define kvm_trace_symbol_epic	kvm_trace_symbol_cepic

/*
 * Tracepoint for 32/64 epic access
 */
TRACE_EVENT(kvm_epic,
	TP_PROTO(unsigned int rw, unsigned int dword, unsigned int reg,
		unsigned long val),
	TP_ARGS(rw, dword, reg, val),

	TP_STRUCT__entry(
		__field(unsigned int, rw)
		__field(unsigned int, dword)
		__field(unsigned int, reg)
		__field(unsigned long, val)
	),

	TP_fast_assign(
		__entry->rw = rw;
		__entry->dword = dword;
		__entry->reg = reg;
		__entry->val = val;
	),

	TP_printk("epic_%s%s %s = 0x%lx",
		  __entry->rw ? "write" : "read",
		  __entry->dword ? "64" : "32",
		  __print_symbolic(__entry->reg, kvm_trace_symbol_epic),
		  __entry->val)
);

#define trace_kvm_epic_read_w(reg, val)		trace_kvm_epic(0, 0, reg, val)
#define trace_kvm_epic_write_w(reg, val)	trace_kvm_epic(1, 0, reg, val)
#define trace_kvm_epic_read_d(reg, val)		trace_kvm_epic(0, 1, reg, val)
#define trace_kvm_epic_write_d(reg, val)	trace_kvm_epic(1, 1, reg, val)

/*
 * Tracepoint for kvm guest exit:
 */
TRACE_EVENT(kvm_exit,
	TP_PROTO(unsigned int exit_reason, unsigned long guest_rip),
	TP_ARGS(exit_reason, guest_rip),

	TP_STRUCT__entry(
		__field(	unsigned int,	exit_reason	)
		__field(	unsigned long,	guest_rip	)
	),

	TP_fast_assign(
		__entry->exit_reason	= exit_reason;
		__entry->guest_rip	= guest_rip;
	),

	TP_printk("reason %d rip 0x%lx",
		 __entry->exit_reason,
		 __entry->guest_rip)
);

/*
 * Tracepoint for kvm interrupt injection:
 */
TRACE_EVENT(kvm_inj_virq,
	TP_PROTO(unsigned int irq),
	TP_ARGS(irq),

	TP_STRUCT__entry(
		__field(	unsigned int,	irq		)
	),

	TP_fast_assign(
		__entry->irq		= irq;
	),

	TP_printk("irq %u", __entry->irq)
);

/*
 * Tracepoint for page fault.
 */
TRACE_EVENT(kvm_page_fault,
	TP_PROTO(unsigned long fault_address, unsigned int error_code),
	TP_ARGS(fault_address, error_code),

	TP_STRUCT__entry(
		__field(	unsigned long,	fault_address	)
		__field(	unsigned int,	error_code	)
	),

	TP_fast_assign(
		__entry->fault_address	= fault_address;
		__entry->error_code	= error_code;
	),

	TP_printk("address %lx error_code %x",
		  __entry->fault_address, __entry->error_code)
);

/*
 * Tracepoint for guest MSR access.
 */
TRACE_EVENT(kvm_msr,
	TP_PROTO(unsigned int rw, unsigned int ecx, unsigned long data),
	TP_ARGS(rw, ecx, data),

	TP_STRUCT__entry(
		__field(	unsigned int,	rw		)
		__field(	unsigned int,	ecx		)
		__field(	unsigned long,	data		)
	),

	TP_fast_assign(
		__entry->rw		= rw;
		__entry->ecx		= ecx;
		__entry->data		= data;
	),

	TP_printk("msr_%s %x = 0x%lx",
		  __entry->rw ? "write" : "read",
		  __entry->ecx, __entry->data)
);

#define trace_kvm_msr_read(ecx, data)		trace_kvm_msr(0, ecx, data)
#define trace_kvm_msr_write(ecx, data)		trace_kvm_msr(1, ecx, data)

/*
 * Tracepoint for guest CR access.
 */
TRACE_EVENT(kvm_cr,
	TP_PROTO(unsigned int rw, unsigned int cr, unsigned long val),
	TP_ARGS(rw, cr, val),

	TP_STRUCT__entry(
		__field(	unsigned int,	rw		)
		__field(	unsigned int,	cr		)
		__field(	unsigned long,	val		)
	),

	TP_fast_assign(
		__entry->rw		= rw;
		__entry->cr		= cr;
		__entry->val		= val;
	),

	TP_printk("cr_%s %x = 0x%lx",
		  __entry->rw ? "write" : "read",
		  __entry->cr, __entry->val)
);

#define trace_kvm_cr_read(cr, val)		trace_kvm_cr(0, cr, val)
#define trace_kvm_cr_write(cr, val)		trace_kvm_cr(1, cr, val)

TRACE_EVENT(kvm_pic_set_irq,
	    TP_PROTO(__u8 chip, __u8 pin, __u8 elcr, __u8 imr, bool coalesced),
	    TP_ARGS(chip, pin, elcr, imr, coalesced),

	TP_STRUCT__entry(
		__field(	__u8,		chip		)
		__field(	__u8,		pin		)
		__field(	__u8,		elcr		)
		__field(	__u8,		imr		)
		__field(	bool,		coalesced	)
	),

	TP_fast_assign(
		__entry->chip		= chip;
		__entry->pin		= pin;
		__entry->elcr		= elcr;
		__entry->imr		= imr;
		__entry->coalesced	= coalesced;
	),

	TP_printk("chip %u pin %u (%s%s)%s",
		  __entry->chip, __entry->pin,
		  (__entry->elcr & (1 << __entry->pin)) ? "level":"edge",
		  (__entry->imr & (1 << __entry->pin)) ? "|masked":"",
		  __entry->coalesced ? " (coalesced)" : "")
);

#define kvm_apic_dst_shorthand		\
	{0x0, "dst"},			\
	{0x1, "self"},			\
	{0x2, "all"},			\
	{0x3, "all-but-self"}

#define kvm_deliver_mode		\
	{0x0, "Fixed"},			\
	{0x1, "LowPrio"},		\
	{0x2, "SMI"},			\
	{0x3, "Res3"},			\
	{0x4, "NMI"},			\
	{0x5, "INIT"},			\
	{0x6, "SIPI"},			\
	{0x7, "ExtINT"}

TRACE_EVENT(kvm_apic_ipi,
	    TP_PROTO(__u32 icr_low, __u32 dest_id),
	    TP_ARGS(icr_low, dest_id),

	TP_STRUCT__entry(
		__field(	__u32,		icr_low		)
		__field(	__u32,		dest_id		)
	),

	TP_fast_assign(
		__entry->icr_low	= icr_low;
		__entry->dest_id	= dest_id;
	),

	TP_printk("dst %x vec %u (%s|%s|%s|%s|%s)",
		  __entry->dest_id, (u8)__entry->icr_low,
		  __print_symbolic((__entry->icr_low >> 8 & 0x7),
				   kvm_deliver_mode),
		  (__entry->icr_low & (1<<11)) ? "logical" : "physical",
		  (__entry->icr_low & (1<<14)) ? "assert" : "de-assert",
		  (__entry->icr_low & (1<<15)) ? "level" : "edge",
		  __print_symbolic((__entry->icr_low >> 18 & 0x3),
				   kvm_apic_dst_shorthand))
);

TRACE_EVENT(kvm_apic_accept_irq,
	    TP_PROTO(__u32 apicid, __u16 dm, __u8 tm, __u8 vec, bool coalesced),
	    TP_ARGS(apicid, dm, tm, vec, coalesced),

	TP_STRUCT__entry(
		__field(	__u32,		apicid		)
		__field(	__u16,		dm		)
		__field(	__u8,		tm		)
		__field(	__u8,		vec		)
		__field(	bool,		coalesced	)
	),

	TP_fast_assign(
		__entry->apicid		= apicid;
		__entry->dm		= dm;
		__entry->tm		= tm;
		__entry->vec		= vec;
		__entry->coalesced	= coalesced;
	),

	TP_printk("apicid %x vec %u (%s|%s)%s",
		  __entry->apicid, __entry->vec,
		  __print_symbolic((__entry->dm >> 8 & 0x7), kvm_deliver_mode),
		  __entry->tm ? "level" : "edge",
		  __entry->coalesced ? " (coalesced)" : "")
);

TRACE_EVENT(kvm_epic_ipi,
	    TP_PROTO(__u32 dest_id, __u32 vector),
	    TP_ARGS(dest_id, vector),

	TP_STRUCT__entry(
		__field(__u32, dest_id)
		__field(__u32, vector)
	),

	TP_fast_assign(
		__entry->dest_id = dest_id;
		__entry->vector = vector;
	),

	TP_printk("dst %u vec %u",
		  __entry->dest_id, __entry->vector)
);

#define kvm_epic_deliver_mode		\
	{0x0, "fixed(0)"},		\
	{0x1, "fixed(1)"},		\
	{0x2, "smi"},			\
	{0x3, "nm_special"},		\
	{0x4, "nmi"},			\
	{0x5, "init"},			\
	{0x6, "startup"},		\
	{0x7, "reserved"}

TRACE_EVENT(kvm_ioepic_set_irq,
	    TP_PROTO(__u32 dst, __u32 vector, __u32 dlvm, bool level, bool mask,
		int pin, int pin_status, bool coalesced),
	    TP_ARGS(dst, vector, dlvm, level, mask, pin, pin_status, coalesced),

	TP_STRUCT__entry(
		__field(	__u32,		dst		)
		__field(	__u32,		vector		)
		__field(	__u32,		dlvm		)
		__field(	bool,		level		)
		__field(	bool,		mask		)
		__field(	int,		pin		)
		__field(	int,		pin_status	)
		__field(	bool,		coalesced	)
	),

	TP_fast_assign(
		__entry->dst		= dst;
		__entry->vector		= vector;
		__entry->dlvm		= dlvm;
		__entry->level		= level;
		__entry->mask		= mask;
		__entry->pin		= pin;
		__entry->pin		= pin_status;
		__entry->coalesced	= coalesced;
	),

	TP_printk("pin %u %s. dst %d vec 0x%x (%s|%s%s)%s",
		__entry->pin, __entry->pin_status ? "set" : "unset",
		__entry->dst, __entry->vector,
		__print_symbolic(__entry->dlvm, kvm_epic_deliver_mode),
		__entry->level ? "level" : "edge",
		__entry->mask ? "|masked" : "",
		__entry->coalesced ? " (coalesced)" : "")
);

TRACE_EVENT(kvm_epic_accept_irq,
	    TP_PROTO(__u32 epicid, __u16 dm, __u8 tm, __u32 vec,
		bool coalesced),
	    TP_ARGS(epicid, dm, tm, vec, coalesced),

	TP_STRUCT__entry(
		__field(__u32, epicid)
		__field(__u16, dm)
		__field(__u8, tm)
		__field(__u32, vec)
		__field(bool, coalesced)
	),

	TP_fast_assign(
		__entry->epicid	= epicid;
		__entry->dm = dm;
		__entry->tm = tm;
		__entry->vec = vec;
		__entry->coalesced = coalesced;
	),

	TP_printk("epicid %x vec %u (%s|%s)%s",
		  __entry->epicid, __entry->vec,
		  __print_symbolic(__entry->dm, kvm_epic_deliver_mode),
		  __entry->tm ? "level" : "edge",
		  __entry->coalesced ? " (coalesced)" : "")
);

TRACE_EVENT(kvm_epic_eoi,
	    TP_PROTO(__u32 vector),
	    TP_ARGS(vector),

	TP_STRUCT__entry(
		__field(__u32, vector)
	),

	TP_fast_assign(
		__entry->vector	= vector;
	),

	TP_printk("vector %u", __entry->vector)
);

/*
 * Tracepoint for nested VMRUN
 */
TRACE_EVENT(kvm_nested_vmrun,
	    TP_PROTO(__u64 rip, __u64 vmcb, __u64 nested_rip, __u32 int_ctl,
		     __u32 event_inj, bool npt),
	    TP_ARGS(rip, vmcb, nested_rip, int_ctl, event_inj, npt),

	TP_STRUCT__entry(
		__field(	__u64,		rip		)
		__field(	__u64,		vmcb		)
		__field(	__u64,		nested_rip	)
		__field(	__u32,		int_ctl		)
		__field(	__u32,		event_inj	)
		__field(	bool,		npt		)
	),

	TP_fast_assign(
		__entry->rip		= rip;
		__entry->vmcb		= vmcb;
		__entry->nested_rip	= nested_rip;
		__entry->int_ctl	= int_ctl;
		__entry->event_inj	= event_inj;
		__entry->npt		= npt;
	),

	TP_printk("rip: 0x%016llx vmcb: 0x%016llx nrip: 0x%016llx "
		  "int_ctl: 0x%08x event_inj: 0x%08x npt: %s\n",
		__entry->rip, __entry->vmcb, __entry->nested_rip,
		__entry->int_ctl, __entry->event_inj,
		__entry->npt ? "on" : "off")
);

/*
 * Tracepoint for #VMEXIT while nested
 */
TRACE_EVENT(kvm_nested_vmexit,
	    TP_PROTO(__u64 rip, __u32 exit_code,
		     __u64 exit_info1, __u64 exit_info2,
		     __u32 exit_int_info, __u32 exit_int_info_err),
	    TP_ARGS(rip, exit_code, exit_info1, exit_info2,
		    exit_int_info, exit_int_info_err),

	TP_STRUCT__entry(
		__field(	__u64,		rip			)
		__field(	__u32,		exit_code		)
		__field(	__u64,		exit_info1		)
		__field(	__u64,		exit_info2		)
		__field(	__u32,		exit_int_info		)
		__field(	__u32,		exit_int_info_err	)
	),

	TP_fast_assign(
		__entry->rip			= rip;
		__entry->exit_code		= exit_code;
		__entry->exit_info1		= exit_info1;
		__entry->exit_info2		= exit_info2;
		__entry->exit_int_info		= exit_int_info;
		__entry->exit_int_info_err	= exit_int_info_err;
	),
	TP_printk("rip: 0x%016llx reason: %d ext_inf1: 0x%016llx "
		  "ext_inf2: 0x%016llx ext_int: 0x%08x ext_int_err: 0x%08x\n",
		  __entry->rip,
		  __entry->exit_code,
		  __entry->exit_info1, __entry->exit_info2,
		  __entry->exit_int_info, __entry->exit_int_info_err)
);

/*
 * Tracepoint for #VMEXIT reinjected to the guest
 */
TRACE_EVENT(kvm_nested_vmexit_inject,
	    TP_PROTO(__u32 exit_code,
		     __u64 exit_info1, __u64 exit_info2,
		     __u32 exit_int_info, __u32 exit_int_info_err),
	    TP_ARGS(exit_code, exit_info1, exit_info2,
		    exit_int_info, exit_int_info_err),

	TP_STRUCT__entry(
		__field(	__u32,		exit_code		)
		__field(	__u64,		exit_info1		)
		__field(	__u64,		exit_info2		)
		__field(	__u32,		exit_int_info		)
		__field(	__u32,		exit_int_info_err	)
	),

	TP_fast_assign(
		__entry->exit_code		= exit_code;
		__entry->exit_info1		= exit_info1;
		__entry->exit_info2		= exit_info2;
		__entry->exit_int_info		= exit_int_info;
		__entry->exit_int_info_err	= exit_int_info_err;
	),

	TP_printk("reason: %d ext_inf1: 0x%016llx "
		  "ext_inf2: 0x%016llx ext_int: 0x%08x ext_int_err: 0x%08x\n",
		  __entry->exit_code,
		__entry->exit_info1, __entry->exit_info2,
		__entry->exit_int_info, __entry->exit_int_info_err)
);

/*
 * Tracepoint for nested #vmexit because of interrupt pending
 */
TRACE_EVENT(kvm_nested_intr_vmexit,
	    TP_PROTO(__u64 rip),
	    TP_ARGS(rip),

	TP_STRUCT__entry(
		__field(	__u64,	rip	)
	),

	TP_fast_assign(
		__entry->rip	=	rip
	),

	TP_printk("rip: 0x%016llx\n", __entry->rip)
);

/*
 * Tracepoint for nested #vmexit because of interrupt pending
 */
TRACE_EVENT(kvm_invlpga,
	    TP_PROTO(__u64 rip, int asid, u64 address),
	    TP_ARGS(rip, asid, address),

	TP_STRUCT__entry(
		__field(	__u64,	rip	)
		__field(	int,	asid	)
		__field(	__u64,	address	)
	),

	TP_fast_assign(
		__entry->rip		=	rip;
		__entry->asid		=	asid;
		__entry->address	=	address;
	),

	TP_printk("rip: 0x%016llx asid: %d address: 0x%016llx\n",
		  __entry->rip, __entry->asid, __entry->address)
);

/*
 * Tracepoint for nested #vmexit because of interrupt pending
 */
TRACE_EVENT(kvm_skinit,
	    TP_PROTO(__u64 rip, __u32 slb),
	    TP_ARGS(rip, slb),

	TP_STRUCT__entry(
		__field(	__u64,	rip	)
		__field(	__u32,	slb	)
	),

	TP_fast_assign(
		__entry->rip		=	rip;
		__entry->slb		=	slb;
	),

	TP_printk("rip: 0x%016llx slb: 0x%08x\n",
		  __entry->rip, __entry->slb)
);

#define TIRHI_EXC_MASK		0x00000fffffffffffULL
#define TIRHI_ALS_MASK		0x0003f00000000000ULL
#define TIRHI_ALS_SHIFT		44ULL
#define TIRHI_MOVA_MASK		0x00f0000000000000ULL
#define TIRHI_MOVA0_MASK	0x0010000000000000ULL
#define TIRHI_MOVA1_MASK	0x0020000000000000ULL
#define TIRHI_MOVA2_MASK	0x0040000000000000ULL
#define TIRHI_MOVA3_MASK	0x0080000000000000ULL

#define E2K_TRACE_PRINT_TIR_HI(entry) \
	(entry & (TIRHI_EXC_MASK | TIRHI_MOVA_MASK)) ? \
		__print_flags(entry & (TIRHI_EXC_MASK | TIRHI_MOVA_MASK), "|", \
			{ TIRHI_MOVA0_MASK, "mova0" }, \
			{ TIRHI_MOVA1_MASK, "mova1" }, \
			{ TIRHI_MOVA2_MASK, "mova2" }, \
			{ TIRHI_MOVA3_MASK, "mova3" }, \
			{ exc_illegal_opcode_mask, "illegal_opcode" }, \
			{ exc_priv_action_mask, "priv_action" }, \
			{ exc_fp_disabled_mask, "fp_disabled" }, \
			{ exc_fp_stack_u_mask, "fp_stack_u" }, \
			{ exc_d_interrupt_mask, "d_interrupt" }, \
			{ exc_diag_ct_cond_mask, "diag_ct_cond" }, \
			{ exc_diag_instr_addr_mask, "diag_instr_addr" }, \
			{ exc_illegal_instr_addr_mask, "illegal_instr_addr" }, \
			{ exc_instr_debug_mask, "instr_debug" }, \
			{ exc_window_bounds_mask, "window_bounds" }, \
			{ exc_user_stack_bounds_mask, "user_stack_bounds" }, \
			{ exc_proc_stack_bounds_mask, "proc_stack_bounds" }, \
			{ exc_chain_stack_bounds_mask, "chain_stack_bounds" }, \
			{ exc_fp_stack_o_mask, "fp_stack_o" }, \
			{ exc_diag_cond_mask, "diag_cond" }, \
			{ exc_diag_operand_mask, "diag_operand" }, \
			{ exc_illegal_operand_mask, "illegal_operand" }, \
			{ exc_array_bounds_mask, "array_bounds" }, \
			{ exc_access_rights_mask, "access_rights" }, \
			{ exc_addr_not_aligned_mask, "addr_not_aligned" }, \
			{ exc_instr_page_miss_mask, "instr_page_miss" }, \
			{ exc_instr_page_prot_mask, "instr_page_prot" }, \
			{ exc_ainstr_page_miss_mask, "ainstr_page_miss" }, \
			{ exc_ainstr_page_prot_mask, "ainstr_page_prot" }, \
			{ exc_last_wish_mask, "last_wish" }, \
			{ exc_base_not_aligned_mask, "base_not_aligned" }, \
			{ exc_software_trap_mask, "software_trap" }, \
			{ exc_data_debug_mask, "data_debug" }, \
			{ exc_data_page_mask, "data_page" }, \
			{ exc_recovery_point_mask, "recovery_point" }, \
			{ exc_interrupt_mask, "interrupt" }, \
			{ exc_nm_interrupt_mask, "nm_interrupt" }, \
			{ exc_div_mask, "div" }, \
			{ exc_fp_mask, "fp" }, \
			{ exc_mem_lock_mask, "mem_lock" }, \
			{ exc_mem_lock_as_mask, "mem_lock_as" }, \
			{ exc_mem_error_out_cpu_mask, "mem_error_out_cpu" }, \
			{ exc_mem_error_MAU_mask, "mem_error_MAU" }, \
			{ exc_mem_error_L2_mask, "mem_error_L2" }, \
			{ exc_mem_error_L1_35_mask, "mem_error_L1_35" }, \
			{ exc_mem_error_L1_02_mask, "mem_error_L1_02" }, \
			{ exc_mem_error_ICACHE_mask, "mem_error_ICACHE" } \
			) : "(none)"

TRACE_EVENT(
	intc_tir,

	TP_PROTO(u64 tir_lo, u64 tir_hi),

	TP_ARGS(tir_lo, tir_hi),

	TP_STRUCT__entry(
		__field(	u64,	tir_lo	)
		__field(	u64,	tir_hi	)
	),

	TP_fast_assign(
		__entry->tir_lo = tir_lo;
		__entry->tir_hi = tir_hi;
	),

	TP_printk("TIR%lld: ip 0x%llx, als 0x%llx\n"
		"      exceptions: %s\n"
		,
		__entry->tir_hi >> 56,
		__entry->tir_lo & E2K_VA_MASK,
		(__entry->tir_hi & TIRHI_ALS_MASK) >> TIRHI_ALS_SHIFT,
		E2K_TRACE_PRINT_TIR_HI(__entry->tir_hi)
		)
);

TRACE_EVENT(
	intc_ctprs,

	TP_PROTO(u64 ctpr1, u64 ctpr1_hi, u64 ctpr2, u64 ctpr2_hi, u64 ctpr3,
		u64 ctpr3_hi),

	TP_ARGS(ctpr1, ctpr1_hi, ctpr2, ctpr2_hi, ctpr3, ctpr3_hi),

	TP_STRUCT__entry(
		__field(	u64,	ctpr1	)
		__field(	u64,	ctpr1_hi	)
		__field(	u64,	ctpr2	)
		__field(	u64,	ctpr2_hi	)
		__field(	u64,	ctpr3	)
		__field(	u64,	ctpr3_hi	)
	),

	TP_fast_assign(
		__entry->ctpr1 = ctpr1;
		__entry->ctpr1_hi = ctpr1_hi;
		__entry->ctpr2 = ctpr2;
		__entry->ctpr2_hi = ctpr2_hi;
		__entry->ctpr3 = ctpr3;
		__entry->ctpr3_hi = ctpr3_hi;
	),

	TP_printk("ctpr1 0x%llx, ctpr1_hi 0x%llx\n"
		"ctpr2 0x%llx, ctpr2_hi 0x%llx\n"
		"ctpr3 0x%llx, ctpr3_hi 0x%llx\n",
		__entry->ctpr1, __entry->ctpr1_hi,
		__entry->ctpr2, __entry->ctpr2_hi,
		__entry->ctpr3, __entry->ctpr3_hi)
);

TRACE_EVENT(
	intc_aau,

	TP_PROTO(const e2k_aau_t *aau_ctxt, u64 lsr, u64 lsr1, u64 ilcr, u64 ilcr1),

	TP_ARGS(aau_ctxt, lsr, lsr1, ilcr, ilcr1),

	TP_STRUCT__entry(
		__field(	u32,	aasr )
		__field(	u64,	lsr )
		__field(	u64,	lsr1 )
		__field(	u64,	ilcr )
		__field(	u64,	ilcr1 )
		__field(	u32,	aafstr )
		__field(	u64,	aaldm )
		__field(	u64,	aaldv )

		/* Synchronous part */
		__array(	u64, aastis, AASTIS_REGS_NUM);
		__field(	u32,	aasti_tags );

		/* Asynchronous part */
		__array(	u64, aainds, AAINDS_REGS_NUM);
		__field(	u32,	aaind_tags );
		__array(	u64, aaincrs, AAINCRS_REGS_NUM);
		__field(	u32,	aaincr_tags );
		__array(	u64, aads, AADS_REGS_NUM * 2);

		/* Since iset v6 */
		__array(	u64, aaldi, AALDIS_REGS_NUM);

	),

	TP_fast_assign(
		int i;

		__entry->aasr = AW(aau_ctxt->guest_aasr);
		__entry->lsr = lsr;
		__entry->lsr1 = lsr1;
		__entry->ilcr = ilcr;
		__entry->ilcr1 = ilcr1;
		__entry->aafstr = aau_ctxt->aafstr;
		__entry->aaldm = AW(aau_ctxt->aaldm);
		__entry->aaldv = AW(aau_ctxt->aaldv);

		for (i = 0; i < AADS_REGS_NUM; i++) {
			__entry->aads[2 * i] = AW(aau_ctxt->aads[i]).lo;
			__entry->aads[2 * i + 1] = AW(aau_ctxt->aads[i]).hi;
		}

		for (i = 0; i < AAINCRS_REGS_NUM; i++)
			__entry->aaincrs[i] = aau_ctxt->aaincrs[i];

		__entry->aaincr_tags = aau_ctxt->aaincr_tags;

		for (i = 0; i < AAINDS_REGS_NUM; i++)
			__entry->aainds[i] = aau_ctxt->aainds[i];

		__entry->aaind_tags = aau_ctxt->aaind_tags;

		for (i = 0; i < AASTIS_REGS_NUM; i++)
			__entry->aastis[i] = aau_ctxt->aastis[i];

		__entry->aasti_tags = aau_ctxt->aasti_tags;

		for (i = 0; i < AALDIS_REGS_NUM; i++)
			__entry->aaldi[i] = aau_ctxt->aaldi[i];
	),

	TP_printk("aasr 0x%x, lsr 0x%llx, lsr1 0x%llx, ilcr 0x%llx, ilcr1 0x%llx\n"
		"aaldv 0x%llx, aaldm = 0x%llx\n"
		"aads lo/hi 0x%llx/0x%llx 0x%llx/0x%llx 0x%llx/0x%llx 0x%llx/0x%llx\n"
		"0x%llx/0x%llx 0x%llx/0x%llx 0x%llx/0x%llx 0x%llx/0x%llx\n"
		"0x%llx/0x%llx 0x%llx/0x%llx 0x%llx/0x%llx 0x%llx/0x%llx\n"
		"0x%llx/0x%llx 0x%llx/0x%llx 0x%llx/0x%llx 0x%llx/0x%llx\n"
		"0x%llx/0x%llx 0x%llx/0x%llx 0x%llx/0x%llx 0x%llx/0x%llx\n"
		"0x%llx/0x%llx 0x%llx/0x%llx 0x%llx/0x%llx 0x%llx/0x%llx\n"
		"0x%llx/0x%llx 0x%llx/0x%llx 0x%llx/0x%llx 0x%llx/0x%llx\n"
		"0x%llx/0x%llx 0x%llx/0x%llx 0x%llx/0x%llx 0x%llx/0x%llx\n"
		"aaincrs 0x%llx 0x%llx 0x%llx 0x%llx 0x%llx 0x%llx 0x%llx 0x%llx\n"
		"aaincr_tags 0x%x\n"
		"aainds 0x%llx 0x%llx 0x%llx 0x%llx 0x%llx 0x%llx 0x%llx 0x%llx\n"
		"0x%llx 0x%llx 0x%llx 0x%llx 0x%llx 0x%llx 0x%llx 0x%llx\n"
		"aaind_tags 0x%x\n"
		"aastis 0x%llx 0x%llx 0x%llx 0x%llx 0x%llx 0x%llx 0x%llx 0x%llx\n"
		"0x%llx 0x%llx 0x%llx 0x%llx 0x%llx 0x%llx 0x%llx 0x%llx\n"
		"aasti_tags 0x%x\n"
		"aaldis 0x%llx 0x%llx 0x%llx 0x%llx 0x%llx 0x%llx 0x%llx 0x%llx\n"
		"0x%llx 0x%llx 0x%llx 0x%llx 0x%llx 0x%llx 0x%llx 0x%llx\n"
		"0x%llx 0x%llx 0x%llx 0x%llx 0x%llx 0x%llx 0x%llx 0x%llx\n"
		"0x%llx 0x%llx 0x%llx 0x%llx 0x%llx 0x%llx 0x%llx 0x%llx\n",
		__entry->aasr, __entry->lsr, __entry->lsr1,
		__entry->ilcr, __entry->ilcr1,
		__entry->aaldv, __entry->aaldm,
		__entry->aads[0], __entry->aads[1],
		__entry->aads[2], __entry->aads[3],
		__entry->aads[4], __entry->aads[5],
		__entry->aads[6], __entry->aads[7],
		__entry->aads[8], __entry->aads[9],
		__entry->aads[10], __entry->aads[11],
		__entry->aads[12], __entry->aads[13],
		__entry->aads[14], __entry->aads[15],
		__entry->aads[16], __entry->aads[17],
		__entry->aads[18], __entry->aads[19],
		__entry->aads[20], __entry->aads[21],
		__entry->aads[22], __entry->aads[23],
		__entry->aads[24], __entry->aads[25],
		__entry->aads[26], __entry->aads[27],
		__entry->aads[28], __entry->aads[29],
		__entry->aads[30], __entry->aads[31],
		__entry->aads[32], __entry->aads[33],
		__entry->aads[34], __entry->aads[35],
		__entry->aads[36], __entry->aads[37],
		__entry->aads[38], __entry->aads[39],
		__entry->aads[40], __entry->aads[41],
		__entry->aads[42], __entry->aads[43],
		__entry->aads[44], __entry->aads[45],
		__entry->aads[46], __entry->aads[47],
		__entry->aads[48], __entry->aads[49],
		__entry->aads[50], __entry->aads[51],
		__entry->aads[52], __entry->aads[53],
		__entry->aads[54], __entry->aads[55],
		__entry->aads[56], __entry->aads[57],
		__entry->aads[58], __entry->aads[59],
		__entry->aads[60], __entry->aads[61],
		__entry->aads[62], __entry->aads[63],
		__entry->aaincrs[0], __entry->aaincrs[1],
		__entry->aaincrs[2], __entry->aaincrs[3],
		__entry->aaincrs[4], __entry->aaincrs[5],
		__entry->aaincrs[6], __entry->aaincrs[7],
		__entry->aaincr_tags,
		__entry->aainds[0], __entry->aainds[1],
		__entry->aainds[2], __entry->aainds[3],
		__entry->aainds[4], __entry->aainds[5],
		__entry->aainds[6], __entry->aainds[7],
		__entry->aainds[8], __entry->aainds[9],
		__entry->aainds[10], __entry->aainds[11],
		__entry->aainds[12], __entry->aainds[13],
		__entry->aainds[14], __entry->aainds[15],
		__entry->aaind_tags,
		__entry->aastis[0], __entry->aastis[1],
		__entry->aastis[2], __entry->aastis[3],
		__entry->aastis[4], __entry->aastis[5],
		__entry->aastis[6], __entry->aastis[7],
		__entry->aastis[8], __entry->aastis[9],
		__entry->aastis[10], __entry->aastis[11],
		__entry->aastis[12], __entry->aastis[13],
		__entry->aastis[14], __entry->aastis[15],
		__entry->aasti_tags,
		__entry->aaldi[0], __entry->aaldi[1],
		__entry->aaldi[2], __entry->aaldi[3],
		__entry->aaldi[4], __entry->aaldi[5],
		__entry->aaldi[6], __entry->aaldi[7],
		__entry->aaldi[8], __entry->aaldi[9],
		__entry->aaldi[10], __entry->aaldi[11],
		__entry->aaldi[12], __entry->aaldi[13],
		__entry->aaldi[14], __entry->aaldi[15],
		__entry->aaldi[16], __entry->aaldi[17],
		__entry->aaldi[18], __entry->aaldi[19],
		__entry->aaldi[20], __entry->aaldi[21],
		__entry->aaldi[22], __entry->aaldi[23],
		__entry->aaldi[24], __entry->aaldi[25],
		__entry->aaldi[26], __entry->aaldi[27],
		__entry->aaldi[28], __entry->aaldi[29],
		__entry->aaldi[30], __entry->aaldi[31])
);

TRACE_EVENT(
	generic_hcall,

	TP_PROTO(unsigned long hcall_num, unsigned long arg1,
		unsigned long arg2, unsigned long arg3,
		unsigned long arg4, unsigned long arg5,
		unsigned long arg6, unsigned long gsbr,
		unsigned long cpu),

	TP_ARGS(hcall_num, arg1, arg2, arg3, arg4, arg5, arg6, gsbr, cpu),

	TP_STRUCT__entry(
		__field(	u64,	hcall_num	)
		__field(	u64,	arg1	)
		__field(	u64,	arg2	)
		__field(	u64,	arg3	)
		__field(	u64,	arg4	)
		__field(	u64,	arg5	)
		__field(	u64,	arg6	)
		__field(	u64,	gsbr	)
		__field(	u64,	cpu	)
	),

	TP_fast_assign(
		__entry->hcall_num = hcall_num;
		__entry->arg1	= arg1;
		__entry->arg2	= arg2;
		__entry->arg3	= arg3;
		__entry->arg4	= arg4;
		__entry->arg5	= arg5;
		__entry->arg6	= arg6;
		__entry->gsbr	= gsbr;
		__entry->cpu	= cpu;
	),

	TP_printk("CPU#%llu, generic hypercall %llu\n"
		"Args: 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx; gsbr: 0x%llx\n"
		,
		__entry->cpu,
		__entry->hcall_num,
		__entry->arg1,
		__entry->arg2,
		__entry->arg3,
		__entry->arg4,
		__entry->arg5,
		__entry->arg6,
		__entry->gsbr)
);

TRACE_EVENT(
	light_hcall,

	TP_PROTO(unsigned long hcall_num, unsigned long arg1,
		unsigned long arg2, unsigned long arg3,
		unsigned long arg4, unsigned long arg5,
		unsigned long arg6, unsigned long cpu),

	TP_ARGS(hcall_num, arg1, arg2, arg3, arg4, arg5, arg6, cpu),

	TP_STRUCT__entry(
		__field(	u64,	hcall_num	)
		__field(	u64,	arg1	)
		__field(	u64,	arg2	)
		__field(	u64,	arg3	)
		__field(	u64,	arg4	)
		__field(	u64,	arg5	)
		__field(	u64,	arg6	)
		__field(	u64,	cpu	)
	),

	TP_fast_assign(
		__entry->hcall_num = hcall_num;
		__entry->arg1	= arg1;
		__entry->arg2	= arg2;
		__entry->arg3	= arg3;
		__entry->arg4	= arg4;
		__entry->arg5	= arg5;
		__entry->arg6	= arg6;
		__entry->cpu	= cpu;
	),

	TP_printk("CPU#%llu, light hypercall %llu\n"
		"Args: 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx\n"
		,
		__entry->cpu,
		__entry->hcall_num,
		__entry->arg1,
		__entry->arg2,
		__entry->arg3,
		__entry->arg4,
		__entry->arg5,
		__entry->arg6)
);

TRACE_EVENT(
	generic_hcall_exit,

	TP_PROTO(unsigned long ret),

	TP_ARGS(ret),

	TP_STRUCT__entry(
		__field(	u64,	ret	)
	),

	TP_fast_assign(
		__entry->ret = ret;
	),

	TP_printk("Generic hypercall exit: %llu\n", __entry->ret)
);

TRACE_EVENT(
	light_hcall_exit,

	TP_PROTO(unsigned long ret),

	TP_ARGS(ret),

	TP_STRUCT__entry(
		__field(	u64,	ret	)
	),

	TP_fast_assign(
		__entry->ret = ret;
	),

	TP_printk("Light hypercall exit: %llu\n", __entry->ret)
);

TRACE_EVENT(
	guest_switch_to,

	TP_PROTO(struct kvm_vcpu *vcpu, int gpid_from, int gmmid_from,
		 int gpid_to, int gmmid_to, struct sw_regs *next_gsw),

	TP_ARGS(vcpu, gpid_from, gmmid_from, gpid_to, gmmid_to, next_gsw),

	TP_STRUCT__entry(
		__field(	int,		vcpu_id		)
		__field(	int,		gpid_from	)
		__field(	int,		gmmid_from	)
		__field(	int,		gpid_to		)
		__field(	int,		gmmid_to	)
		__field(	e2k_addr_t,	top		)
		__field_struct(	e2k_usd_lo_t,	usd_lo		)
		__field_struct(	e2k_usd_hi_t,	usd_hi		)
		__field_struct(	e2k_psp_lo_t,	psp_lo		)
		__field_struct(	e2k_psp_hi_t,	psp_hi		)
		__field_struct(	e2k_pcsp_lo_t,	pcsp_lo		)
		__field_struct(	e2k_pcsp_hi_t,	pcsp_hi		)
		__field(	pgprotval_t,	u_pptb		)
		__field(	gva_t,		u_vptb		)
		__field(	hpa_t,		root		)
		__field(	u64,		mmu_pptb	)
		__field(	u64,		mmu_pid		)
		__field(	u64,		ctxt_pid	)
	),

	TP_fast_assign(
		__entry->vcpu_id = vcpu->vcpu_id;
		__entry->gpid_from = gpid_from;
		__entry->gmmid_from = gmmid_from;
		__entry->gpid_to = gpid_to;
		__entry->gmmid_to = gmmid_to;
		__entry->top = next_gsw->top;
		__entry->usd_lo = next_gsw->usd_lo;
		__entry->usd_hi = next_gsw->usd_hi;
		__entry->psp_lo = next_gsw->psp_lo;
		__entry->psp_hi = next_gsw->psp_hi;
		__entry->pcsp_lo = next_gsw->pcsp_lo;
		__entry->pcsp_hi = next_gsw->pcsp_hi;
		__entry->u_pptb = vcpu->arch.mmu.get_vcpu_u_pptb(vcpu);
		__entry->u_vptb = vcpu->arch.mmu.get_vcpu_sh_u_vptb(vcpu);
		__entry->root = kvm_get_space_type_spt_u_root(vcpu);
		__entry->mmu_pptb = get_mmu_u_pptb_reg();
		__entry->mmu_pid = get_mmu_pid_reg();
		__entry->ctxt_pid = kvm_get_guest_mmu_pid(vcpu);
	),

	TP_printk("VCPU #%d: switch from gpid #%d gmm #%d to gpid #%d gmm #%d\n"
		"        USD:  base 0x%llx size 0x%x top at 0x%lx\n"
		"        PSP:  base 0x%llx ind 0x%x size 0x%x\n"
		"        PCSP: base 0x%llx ind 0x%x size 0x%x\n"
		"        MMU:  u_pptb 0x%lx u_vptb 0x%lx sh_pptb 0x%llx\n"
		"              mmu_upptb 0x%llx mmu_pid 0x%llx ctxt pid 0x%llx",
		__entry->vcpu_id,
		__entry->gpid_from, __entry->gmmid_from,
		__entry->gpid_to, __entry->gmmid_to,
		__entry->usd_lo.USD_lo_base,
		__entry->usd_hi.USD_hi_size,
		__entry->top,
		__entry->psp_lo.PSP_lo_base,
		__entry->psp_hi.PSP_hi_ind,
		__entry->psp_hi.PSP_hi_size,
		__entry->pcsp_lo.PCSP_lo_base,
		__entry->pcsp_hi.PCSP_hi_ind,
		__entry->pcsp_hi.PCSP_hi_size,
		__entry->u_pptb, __entry->u_vptb, __entry->root,
		__entry->mmu_pptb, __entry->mmu_pid, __entry->ctxt_pid
	)
);

TRACE_EVENT(
	vcpu_put,

	TP_PROTO(int vcpu, int cpu),

	TP_ARGS(vcpu, cpu),

	TP_STRUCT__entry(
		__field(	int,	vcpu	)
		__field(	int,	cpu	)
	),

	TP_fast_assign(
		__entry->vcpu = vcpu;
		__entry->cpu = cpu;
	),

	TP_printk("vcpu %d, cpu %d\n", __entry->vcpu, __entry->cpu)
);

TRACE_EVENT(
	vcpu_load,

	TP_PROTO(int vcpu, int last_cpu, int cpu),

	TP_ARGS(vcpu, last_cpu, cpu),

	TP_STRUCT__entry(
		__field(	int,	vcpu	)
		__field(	int,	last_cpu	)
		__field(	int,	cpu	)
	),

	TP_fast_assign(
		__entry->vcpu = vcpu;
		__entry->last_cpu = last_cpu;
		__entry->cpu = cpu;
	),

	TP_printk("vcpu %d, cpu %d, last_cpu %d\n", __entry->vcpu, __entry->cpu,
		__entry->last_cpu)
);

TRACE_EVENT(
	kvm_handle_rmap_range,

	TP_PROTO(u64 hva_start, u64 hva_end, u64 gpa_start, u64 gpa_end,
		void *handler),

	TP_ARGS(hva_start, hva_end, gpa_start, gpa_end, handler),

	TP_STRUCT__entry(
		__field(	u64,	hva_start	)
		__field(	u64,	hva_end	)
		__field(	u64,	gpa_start	)
		__field(	u64,	gpa_end	)
		__field(	void *,	handler	)
	),

	TP_fast_assign(
		__entry->hva_start = hva_start;
		__entry->hva_end = hva_end;
		__entry->gpa_start = gpa_start;
		__entry->gpa_end = gpa_end;
		__entry->handler = handler;
	),

	TP_printk("HVA 0x%llx - 0x%llx; GPA 0x%llx - 0x%llx; handler 0x%px\n",
		__entry->hva_start, __entry->hva_end,
		__entry->gpa_start, __entry->gpa_end,
		__entry->handler)
);

#endif /* _TRACE_KVM_H */

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH ../../arch/e2k/include/asm/kvm
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE trace_kvm

/* This part must be outside protection */
#include <trace/define_trace.h>
