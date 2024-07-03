/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _ASM_L_APICDEF_H
#define _ASM_L_APICDEF_H

/*
 * Constants for various Intel APICs. (local APIC, IOAPIC, etc.)
 *
 * Alan Cox <Alan.Cox@linux.org>, 1995.
 * Ingo Molnar <mingo@redhat.com>, 1999, 2000
 */

#define IO_APIC_DEFAULT_PHYS_BASE	0xfec00000UL
#define	APIC_DEFAULT_PHYS_BASE		0xfee00000UL

/*
 * This is the IO-APIC register space as specified
 * by Intel docs:
 */
#define IO_APIC_SLOT_SIZE		1024
#define	APIC_REGS_SIZE			0x1000

#define APIC_BSP	0x10
#define		APIC_BSP_ENABLE		0x00000800
#define		APIC_BSP_IS_BSP		0x00000100
#define		APIC_ENABLE(x)		((x) & APIC_BSP_ENABLE)
#define		BootStrap(x)		((x) & APIC_BSP_IS_BSP)
#define	APIC_ID		0x20
#define		APIC_ID_SHIFT		24
#define		APIC_ID_SIZE		8
#define		APIC_ID_BIT_MASK	((1 << APIC_ID_SIZE) - 1)
#define		APIC_ID_MASK		(APIC_ID_BIT_MASK << \
						APIC_ID_SHIFT)
#define		GET_APIC_ID(x)		(((x) >> APIC_ID_SHIFT) & \
						APIC_ID_BIT_MASK)
#define	APIC_LVR	0x30
#define		APIC_LVR_MASK		0xFF00FF
#define		APIC_LVR_DIRECTED_EOI	(1 << 24)
#define		APIC_MAXLVT		0x03
#define		APIC_VERSION		0x10
#define		GET_APIC_VERSION(x)	((x) & 0xFFu)
#define		GET_APIC_MAXLVT(x)	(((x) >> 16) & 0xFFu)
#define		SET_APIC_VERSION(x)	((x) & 0xFF)
#define		SET_APIC_MAXLVT(x)	(((x) & 0xff) << 16)
#define		APIC_XAPIC(x)		((x) >= 0x14)
#define		APIC_EXT_SPACE(x)	((x) & 0x80000000)
#define	APIC_TASKPRI	0x80
#define		APIC_TPRI_MASK		0xFFu
#define	APIC_ARBPRI	0x90
#define		APIC_ARBPRI_MASK	0xFFu
#define	APIC_PROCPRI	0xA0
#define	APIC_EOI	0xB0
#define		APIC_EOI_ACK		0x0
#define	APIC_RRR	0xC0
#define	APIC_LDR	0xD0
#define		APIC_LDR_MASK		(0xFFu << 24)
#define		GET_APIC_LOGICAL_ID(x)	(((x) >> 24) & 0xFFu)
#define		SET_APIC_LOGICAL_ID(x)	(((x) << 24))
#define		APIC_ALL_CPUS		0xFFu
#define	APIC_DFR	0xE0
#define		GET_APIC_DLVR_MODE(x)	(((x) >> 28) & 0xF)
#define		APIC_DFR_CLUSTER		0x0FFFFFFFul
#define		APIC_DFR_FLAT			0xFFFFFFFFul
#define	APIC_SPIV	0xF0
#define		APIC_SPIV_DIRECTED_EOI		(1 << 12)
#define		APIC_SPIV_FOCUS_DISABLED	(1 << 9)
#define		APIC_SPIV_APIC_ENABLED		(1 << 8)
#define		APIC_SOFT_ENABLED(x)		((x) & APIC_SPIV_APIC_ENABLED)
#define		APIC_FOCUS_DISABLED(x)		((x) & APIC_SPIV_FOCUS_DISABLED)
#define		APIC_SPIV_SPURIOUS_VECT		0x000FF
#define		GET_SPURIOUS_VECTOR(x)		((x) & APIC_SPIV_SPURIOUS_VECT)
#define		SET_SPURIOUS_VECTOR(x)		((x) & APIC_SPIV_SPURIOUS_VECT)
#define	APIC_ISR	0x100
#define		APIC_ISR_NR     0x8     /* Number of 32 bit ISR registers. */
#define	APIC_TMR	0x180
#define	APIC_IRR	0x200
#define	APIC_ESR	0x280
#define		APIC_ESR_SEND_CS	0x00001
#define		APIC_ESR_RECV_CS	0x00002
#define		APIC_ESR_SEND_ACC	0x00004
#define		APIC_ESR_RECV_ACC	0x00008
#define		APIC_ESR_SENDILL	0x00020
#define		APIC_ESR_RECVILL	0x00040
#define		APIC_ESR_ILLREGA	0x00080
#define 	APIC_LVTCMCI	0x2f0
#define	APIC_ICR	0x300
#define		APIC_DEST_SELF		0x40000
#define		APIC_DEST_ALLINC	0x80000
#define		APIC_DEST_ALLBUT	0xC0000
#define		APIC_ICR_RR_MASK	0x30000
#define		APIC_ICR_RR_INVALID	0x00000
#define		APIC_ICR_RR_INPROG	0x10000
#define		APIC_ICR_RR_VALID	0x20000
#define		APIC_INT_LEVELTRIG	0x08000
#define		APIC_INT_ASSERT		0x04000
#define		APIC_ICR_BUSY		0x01000
#define		APIC_DEST_LOGICAL	0x00800
#define		APIC_DEST_PHYSICAL	0x00000
#define		APIC_DM_FIXED		0x00000
#define		APIC_DM_LOWEST		0x00100
#define		APIC_DM_SMI		0x00200
#define		APIC_DM_REMRD		0x00300
#define		APIC_DM_NMI		0x00400
#define		APIC_DM_INIT		0x00500
#define		APIC_DM_STARTUP		0x00600
#define		APIC_DM_EXTINT		0x00700
#define		APIC_VECTOR_MASK	0x000FF
#define	APIC_ICR2	0x310
#define		GET_APIC_DEST_FIELD(x)	(((x) >> 24) & 0xFF)
#define		SET_APIC_DEST_FIELD(x)	((x) << 24)
#define	APIC_LVTT	0x320
#define	APIC_LVTTHMR	0x330
#define	APIC_LVTPC	0x340
#define	APIC_LVT0	0x350
#define		APIC_LVT_TIMER_BASE_MASK	(0x3 << 18)
#define		GET_APIC_TIMER_BASE(x)		(((x) >> 18) & 0x3)
#define		SET_APIC_TIMER_BASE(x)		(((x) << 18))
#define		APIC_TIMER_BASE_CLKIN		0x0
#define		APIC_TIMER_BASE_TMBASE		0x1
#define		APIC_TIMER_BASE_DIV		0x2
#define		APIC_LVT_TIMER_PERIODIC		(1 << 17)
#define		APIC_LVT_MASKED			(1 << 16)
#define		APIC_LVT_LEVEL_TRIGGER		(1 << 15)
#define		APIC_LVT_REMOTE_IRR		(1 << 14)
#define		APIC_INPUT_POLARITY		(1 << 13)
#define		APIC_SEND_PENDING		(1 << 12)
#define		APIC_MODE_MASK			0x700
#define		GET_APIC_DELIVERY_MODE(x)	(((x) >> 8) & 0x7)
#define		SET_APIC_DELIVERY_MODE(x, y)	(((x) & ~0x700) | ((y) << 8))
#define			APIC_MODE_FIXED		0x0
#define			APIC_MODE_NMI		0x4
#define			APIC_MODE_EXTINT	0x7
#define	APIC_LVT1	0x360
#define	APIC_LVTERR	0x370
#define	APIC_TMICT	0x380
#define	APIC_TMCCT	0x390
#define	APIC_TDCR	0x3E0
#define APIC_SELF_IPI	0x3F0
#define		APIC_TDR_DIV_TMBASE	(1 << 2)
#define		APIC_TDR_DIV_1		0xB
#define		APIC_TDR_DIV_2		0x0
#define		APIC_TDR_DIV_4		0x1
#define		APIC_TDR_DIV_8		0x2
#define		APIC_TDR_DIV_16		0x3
#define		APIC_TDR_DIV_32		0x8
#define		APIC_TDR_DIV_64		0x9
#define		APIC_TDR_DIV_128	0xA
#define	APIC_NM_TIMER_LVTT		0xf00
#define	APIC_NM_TIMER_INIT_COUNT	0xf10
#define	APIC_NM_TIMER_CURRENT_COUNT	0xf20
#define	APIC_NM_TIMER_DIVIDER		0xf30
#define APIC_LVT2			0xf40
#define APIC_LVT3			0xf50
#define		APIC_DSP		APIC_LVT3
#define APIC_LVT4			0xf60
#define	APIC_M_ERM			0xfc0
#define		APIC_NM_WATCHDOG	0x80000000
#define		APIC_NM_WATCHDOG1	0x40000000
#define		APIC_NM_SPECIAL		0x20000
#define		APIC_NM_TIMER		0x10000
#define		APIC_NM_NMI_DEBUG_MASK	0x8000
#define		APIC_NM_INTQLAPIC_MASK	0x4000
#define		APIC_NM_INT_VIOLAT_MASK	0x2000
#define	APIC_NM		0xfe0
#define		APIC_NM_BIT_MASK	0x7ff00
#define		APIC_NM_PCI		0x40000
#define		APIC_NM_SPECIAL		0x20000
#define		APIC_NM_TIMER		0x10000
#define		APIC_NM_NMI_DEBUG	0x8000
#define		APIC_NM_INTQLAPIC	0x4000
#define		APIC_NM_INT_VIOLAT	0x2000
#define		APIC_NM_STARTUP		0x1000
#define		APIC_NM_INIT		0x0800
#define		APIC_NM_NMI		0x0400
#define		APIC_NM_SMI		0x0200
#define		APIC_NM_EXTINT		0x0100
#define		APIC_NM_STARTUP_ADDR	0x00ff
#define		GET_APIC_STARTUP_ADDR(x) ((x) & APIC_NM_STARTUP_ADDR)
#define		APIC_NM_MASK(x)		((x) & APIC_NM_BIT_MASK)
#define		GET_APIC_NM_BITS(x)	(((x) & APIC_NM_BIT_MASK) >> 9)
#define		APIC_NM_IS_STRATUP(x)	((x) & APIC_NM_STARTUP)
#define		APIC_NM_IS_INIT(x)	((x) & APIC_NM_INIT)
#define		APIC_NM_IS_NMI(x)	((x) & APIC_NM_NMI)
#define		APIC_NM_IS_SMI(x)	((x) & APIC_NM_SMI)
#define	APIC_VECT	0xff0
#define		APIC_VECT_VECTOR_MASK	0x000000ff
#define		APIC_VECT_EXTINT	(1 << 31)
#define		APIC_VECT_VECTOR(x)	((x) & APIC_VECT_VECTOR_MASK)
#define		APIC_VECT_IS_EXTINT(x)	((x) & APIC_VECT_EXTINT)

#define APIC_BASE 0x00000000fee00000UL
#define X2APIC_ENABLE	(1UL << 10)

/*
 * a maximum number of IO-APICs depends on the following:
 *	each IO link can have IOHUB with IO-APIC
 *	each node can have embedded IO-APIC
 */
#define MAX_IO_APICS (MAX_NUMIOLINKS + MAX_NUMNODES)
#define MAX_LOCAL_APIC MAX_APICS

#define BAD_APICID 0xFFu

#ifndef __ASSEMBLY__
enum ioapic_irq_destination_types {
	dest_Fixed		= 0,
	dest_LowestPrio		= 1,
	dest_SMI		= 2,
	dest__reserved_1	= 3,
	dest_NMI		= 4,
	dest_INIT		= 5,
	dest__reserved_2	= 6,
	dest_ExtINT		= 7
};
#endif

#endif /* _ASM_L_APICDEF_H */
