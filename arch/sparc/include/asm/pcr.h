#ifndef __PCR_H
#define __PCR_H

struct pcr_ops {
	u64 (*read_pcr)(unsigned long);
	void (*write_pcr)(unsigned long, u64);
	u64 (*read_pic)(unsigned long);
	void (*write_pic)(unsigned long, u64);
	u64 (*nmi_picl_value)(unsigned int nmi_hz);
	u64 pcr_nmi_enable;
	u64 pcr_nmi_disable;
};
extern const struct pcr_ops *pcr_ops;

extern void deferred_pcr_work_irq(int irq, struct pt_regs *regs);
extern void schedule_deferred_pcr_work(void);

#define PCR_PIC_PRIV		0x00000001 /* PIC access is privileged */
#define PCR_STRACE		0x00000002 /* Trace supervisor events  */
#define PCR_UTRACE		0x00000004 /* Trace user events        */
#define PCR_N2_HTRACE		0x00000008 /* Trace hypervisor events  */
#define PCR_N2_TOE_OV0		0x00000010 /* Trap if PIC 0 overflows  */
#define PCR_N2_TOE_OV1		0x00000020 /* Trap if PIC 1 overflows  */
#define PCR_N2_MASK0		0x00003fc0
#define PCR_N2_MASK0_SHIFT	6
#define PCR_N2_SL0		0x0003c000
#define PCR_N2_SL0_SHIFT	14
#define PCR_N2_OV0		0x00040000
#define PCR_N2_MASK1		0x07f80000
#define PCR_N2_MASK1_SHIFT	19
#define PCR_N2_SL1		0x78000000
#define PCR_N2_SL1_SHIFT	27
#define PCR_N2_OV1		0x80000000

#define PCR_N4_OV		0x00000001 /* PIC overflow             */
#define PCR_N4_TOE		0x00000002 /* Trap On Event            */
#define PCR_N4_UTRACE		0x00000004 /* Trace user events        */
#define PCR_N4_STRACE		0x00000008 /* Trace supervisor events  */
#define PCR_N4_HTRACE		0x00000010 /* Trace hypervisor events  */
#define PCR_N4_MASK		0x000007e0 /* Event mask               */
#define PCR_N4_MASK_SHIFT	5
#define PCR_N4_SL		0x0000f800 /* Event Select             */
#define PCR_N4_SL_SHIFT		11
#define PCR_N4_PICNPT		0x00010000 /* PIC non-privileged trap  */
#define PCR_N4_PICNHT		0x00020000 /* PIC non-hypervisor trap  */
#define PCR_N4_NTC		0x00040000 /* Next-To-Commit wrap      */

extern int pcr_arch_init(void);

#ifdef CONFIG_E90S
#define E90S_PIC_NR	4


#define	E90S_PCR_PRIV_SHIFT	0

#define	E90S_PCR_SYS_SHIFT	1
#define	E90S_PCR_USR_SHIFT	2

#define	E90S_PCR_PICL_SHIFT	4
#define	E90S_PCR_PICU_MASK	0x3f
#define	E90S_PCR_PICU_SHIFT	11

#define	E90S_PCR_ULRO_SHIFT	3
#define	E90S_PCR_SC_SHIFT	18
#define	E90S_PCR_SC_MASK	0x7UL
#define	E90S_PCR_NC_SHIFT	22
#define	E90S_PCR_NC_MASK	0x7UL
#define	E90S_PCR_OVRO_SHIFT	26
#define	E90S_PCR_OVF_SHIFT	32
#define	E90S_PCR_OVF_MASK	0xfUL

#define	E90S_PCR_PRIV	(1UL << E90S_PCR_PRIV_SHIFT)
#define	E90S_PCR_SYS	(1UL << E90S_PCR_SYS_SHIFT)
#define	E90S_PCR_USR	(1UL << E90S_PCR_USR_SHIFT)
#define	E90S_PCR_ULRO	(1UL << E90S_PCR_ULRO_SHIFT)
#define	E90S_PCR_OVRO	(1UL << E90S_PCR_OVRO_SHIFT)
#define	E90S_PCR_OVF	(E90S_PCR_OVF_MASK << \
					E90S_PCR_OVF_SHIFT)

/* Performance counter register access. */
#define rd_pcr(__p)  __asm__ __volatile__("rd	%%pcr, %0" : "=r" (__p))
#define wr_pcr(__p) __asm__ __volatile__("wr	%0, 0x0, %%pcr" : : "r" (__p))
#define rd_pic(__p)  __asm__ __volatile__("rd %%pic, %0" : "=r" (__p))
#define wr_pic(__p) __asm__ __volatile__("wr	%0, 0x0, %%pic" : : "r" (__p))

#endif

#endif /* __PCR_H */
