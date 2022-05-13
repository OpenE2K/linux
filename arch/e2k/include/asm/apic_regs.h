#ifndef __ASM_APIC_REGS_H
#define __ASM_APIC_REGS_H


#ifndef __ASSEMBLY__

/*
 * the local APIC register structure, memory mapped. Not terribly well
 * tested, but we might eventually use this one in the future - the
 * problem why we cannot use it right now is the P5 APIC, it has an
 * errata which cannot take 8-bit reads and writes, only 32-bit ones ...
 */
#define u32 unsigned int

struct local_apic {

/*000*/	struct { u32 __reserved[4]; } __reserved_01;

/*010*/	struct { u32 __reserved_1	:  8,
			boot_strap	:  1,
			__reserved_2	:  2,
			apic_enable	:  1,
			__reserved_3	: 20;
		u32 __reserved[3];
	} bsp;

/*020*/	struct { /* APIC ID Register */
		u32   __reserved_1	: 24,
			phys_apic_id	:  4,
			__reserved_2	:  4;
		u32 __reserved[3];
	} id;

/*030*/	const
	struct { /* APIC Version Register */
		u32   version		:  8,
			__reserved_1	:  8,
			max_lvt		:  8,
			__reserved_2	:  8;
		u32 __reserved[3];
	} version;

/*040*/	struct { u32 __reserved[4]; } __reserved_03;

/*050*/	struct { u32 __reserved[4]; } __reserved_04;

/*060*/	struct { u32 __reserved[4]; } __reserved_05;

/*070*/	struct { u32 __reserved[4]; } __reserved_06;

/*080*/	struct { /* Task Priority Register */
		u32   priority	:  8,
			__reserved_1	: 24;
		u32 __reserved_2[3];
	} tpr;

/*090*/	const
	struct { /* Arbitration Priority Register */
		u32   priority	:  8,
			__reserved_1	: 24;
		u32 __reserved_2[3];
	} apr;

/*0A0*/	const
	struct { /* Processor Priority Register */
		u32   priority	:  8,
			__reserved_1	: 24;
		u32 __reserved_2[3];
	} ppr;

/*0B0*/	struct { /* End Of Interrupt Register */
		u32   eoi;
		u32 __reserved[3];
	} eoi;

/*0C0*/	struct { u32 __reserved[4]; } __reserved_07;

/*0D0*/	struct { /* Logical Destination Register */
		u32   __reserved_1	: 24,
			logical_dest	:  8;
		u32 __reserved_2[3];
	} ldr;

/*0E0*/	struct { /* Destination Format Register */
		u32   __reserved_1	: 28,
			model		:  4;
		u32 __reserved_2[3];
	} dfr;

/*0F0*/	struct { /* Spurious Interrupt Vector Register */
		u32	spurious_vector	:  8,
			apic_enabled	:  1,
			focus_cpu	:  1,
			__reserved_2	: 22;
		u32 __reserved_3[3];
	} svr;

/*100*/	struct { /* In Service Register */
/*170*/		u32 bitfield;
		u32 __reserved[3];
	} isr [8];

/*180*/	struct { /* Trigger Mode Register */
/*1F0*/		u32 bitfield;
		u32 __reserved[3];
	} tmr [8];

/*200*/	struct { /* Interrupt Request Register */
/*270*/		u32 bitfield;
		u32 __reserved[3];
	} irr [8];

/*280*/	union { /* Error Status Register */
		struct {
			u32   send_cs_error			:  1,
				receive_cs_error		:  1,
				send_accept_error		:  1,
				receive_accept_error		:  1,
				__reserved_1			:  1,
				send_illegal_vector		:  1,
				receive_illegal_vector		:  1,
				illegal_register_address	:  1,
				__reserved_2			: 24;
			u32 __reserved_3[3];
		} error_bits;
		struct {
			u32 errors;
			u32 __reserved_3[3];
		} all_errors;
	} esr;

/*290*/	struct { u32 __reserved[4]; } __reserved_08;

/*2A0*/	struct { u32 __reserved[4]; } __reserved_09;

/*2B0*/	struct { u32 __reserved[4]; } __reserved_10;

/*2C0*/	struct { u32 __reserved[4]; } __reserved_11;

/*2D0*/	struct { u32 __reserved[4]; } __reserved_12;

/*2E0*/	struct { u32 __reserved[4]; } __reserved_13;

/*2F0*/	struct { u32 __reserved[4]; } __reserved_14;

/*300*/	struct { /* Interrupt Command Register 1 */
		u32   vector			:  8,
			delivery_mode		:  3,
			destination_mode	:  1,
			delivery_status		:  1,
			__reserved_1		:  1,
			level			:  1,
			trigger			:  1,
			__reserved_2		:  2,
			shorthand		:  2,
			__reserved_3		:  12;
		u32 __reserved_4[3];
	} icr1;

/*310*/	struct { /* Interrupt Command Register 2 */
		union {
			u32   __reserved_1	: 24,
				phys_dest	:  4,
				__reserved_2	:  4;
			u32   __reserved_3	: 24,
				logical_dest	:  8;
		} dest;
		u32 __reserved_4[3];
	} icr2;

/*320*/	struct { /* LVT - Timer */
		u32   vector		:  8,
			__reserved_1	:  4,
			delivery_status	:  1,
			__reserved_2	:  3,
			mask		:  1,
			timer_mode	:  1,
			__reserved_3	: 14;
		u32 __reserved_4[3];
	} lvt_timer;

/*330*/	struct { u32 __reserved[4]; } __reserved_15;

/*340*/	struct { /* LVT - Performance Counter */
		u32   vector		:  8,
			delivery_mode	:  3,
			__reserved_1	:  1,
			delivery_status	:  1,
			__reserved_2	:  3,
			mask		:  1,
			__reserved_3	: 15;
		u32 __reserved_4[3];
	} lvt_pc;

/*350*/	struct { /* LVT - LINT0 */
		u32   vector		:  8,
			delivery_mode	:  3,
			__reserved_1	:  1,
			delivery_status	:  1,
			polarity	:  1,
			remote_irr	:  1,
			trigger		:  1,
			mask		:  1,
			__reserved_2	: 15;
		u32 __reserved_3[3];
	} lvt_lint0;

/*360*/	struct { /* LVT - LINT1 */
		u32   vector		:  8,
			delivery_mode	:  3,
			__reserved_1	:  1,
			delivery_status	:  1,
			polarity	:  1,
			remote_irr	:  1,
			trigger		:  1,
			mask		:  1,
			__reserved_2	: 15;
		u32 __reserved_3[3];
	} lvt_lint1;

/*370*/	struct { /* LVT - Error */
		u32   vector		:  8,
			__reserved_1	:  4,
			delivery_status	:  1,
			__reserved_2	:  3,
			mask		:  1,
			__reserved_3	: 15;
		u32 __reserved_4[3];
	} lvt_error;

/*380*/	struct { /* Timer Initial Count Register */
		u32   initial_count;
		u32 __reserved_2[3];
	} timer_icr;

/*390*/	const
	struct { /* Timer Current Count Register */
		u32   curr_count;
		u32 __reserved_2[3];
	} timer_ccr;

/*3A0*/	struct { u32 __reserved[4]; } __reserved_16;

/*3B0*/	struct { u32 __reserved[4]; } __reserved_17;

/*3C0*/	struct { u32 __reserved[4]; } __reserved_18;

/*3D0*/	struct { u32 __reserved[4]; } __reserved_19;

/*3E0*/	struct { /* Timer Divide Configuration Register */
		u32   divisor		:  4,
			__reserved_1	: 28;
		u32 __reserved_2[3];
	} timer_dcr;

/*3F0*/	struct { u32 __reserved[4]; } __reserved_20;
#if 0
/*3F0*/	struct { u32 __reserved[764]; } __reserved_20;
/*FE0*/ struct { /* Vector from PIC or APIC in nmi */
		 u32   nm_vector	:  8,
		       __reserved	: 24;
		 u32   __reserved[3];
	} nm_vect;
/*FF0*/ struct { /* Vector */
		 u32   vector		:  8,
		       __reserved_1	: 24;
		 u32   __reserved[3];
	} vect;
#endif
} __attribute__ ((packed));

#undef u32

#endif	/* !(__ASSEMBLY__) */

#endif	/* __ASM_APIC_REGS_H */
