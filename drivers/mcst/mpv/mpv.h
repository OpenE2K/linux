
/* Редакция файла mpv.h:
			  CAM - 09.12.08; home - 08.11.08.
*/

#ifndef	_MPV_H_
#define	_MPV_H_

#include <linux/mcst/mpv_io.h>

#define MPV_NAME		"mpv"
#define MPV_CARD_DEVID		0x4360
#define MPV_KPI2_DEVID		0x8014
#define MPV4_DEVID		0x8023
#define MPV_KPI2		1
#define MPV_4			2

#define MAX_MPV_INSTANCES	16
#define	MPV_IO_IN		1
#define	MPV_IO_OUT		2
#define	MPV_IO_OS		3

#define	MPV_MINOR(i, io, n)	((i) << 7 | (io) << 5 | (n))
#define	MPV_BUS(d)			(MINOR(d) & 0x1f)
#define	MPV_INST(d)			(MINOR(d) >> 7)
#define	MPV_INOUT(d)			((MINOR(d) >> 5) & 3)
#define	MPV_IN(d)			(MPV_INOUT(d) == MPV_IO_IN)
#define	MPV_OUT(d)			(MPV_INOUT(d) == MPV_IO_OUT)
#define	MPV_OS(d)			(MPV_INOUT(d) == MPV_IO_OS)

/* max mpv known non_iohub2 mpv version number */
#define  MAX_MPV_VER	100
/* rev. MPV in driver for iohub2 POVOZKA-2 */
#define  IOHUB2		(MAX_MPV_VER + 1)
/* max mpv known non_iohub2 mpv version number */
#define  MAX_IOH2_VER	100
#define  GPIO_MPV_SW	0x40	/* Enable MPV but not GPIO in POVOZKA-2 */
#define  IOHUB2_IRQ1	0x6	/* irq for line 0 in POVOZKA-2 */
#define  IOHUB2_IRQ2	0x9	/* irq for lines 1,2 in POVOZKA-2 */

#define	MPV_REG_SIZE	0x80
#define	MPV_RPV			0x00
#define	MPV_REG_MASK		0x04
#define	MPV_REG_POLARITY	0x08
#define	MPV_REG_OUT_STAT	0x0C
#define	MPV_REG_INTR_NULL	0x10
#define	MPV_REG_BASE_CNT	0x18
#define	MPV_REG_OUT_INTR	0x1C
#define	MPV_REG_CHECK		0x14	/* for mpv card rev. 1,2 */
#define	MPV_RPPV		0x20
#define	MPV_RESET_V2		0x20
#define	MPV_RESET_IOHUB2	0x10
#define	MPV_NOISE_GUARD_TIME	0x24	/* for MPVm rev.2 */
#define	MPV_NOISE_GUARD_MPV4	0x3fc	/* for MPV4 */
#define	MPV_REG_NULL_INTR	0x60
#define	MPV_REG_CONFIG_INTR	0x64
#define	MPV_SBUS_VER		0xd8	/* sbus-mpv version (sbus-mpv ver.5 ~ */
					/*		revID 2 of pci-mpv)*/
#define	MPV_RAW_IN		0x6c	/* for MPVm rev.2 only */
#define MASK_RAW_IN		0x300000
#define RAW_AFTER_2		0x0
#define RAW_AFTER_1		0x1
#define RAW_AFTER_0		0x2

/* Noise mode register */
#define	MPV_NOISE_MODE		0x78
#define USE_AFTER_2		0x0
#define USE_AFTER_1		0x1
#define USE_AFTER_0		0x2

#define	MPV_IN_MASK	0xfffff
#define	MPV_CPU_INTR 0x3 /* cpu interrupt number for sbus-mpv by default */

/*  reg. number  0     1     2     3     4     5     6     7     8     9 */
unsigned char corr_cnt_reg_v2[10] = {	/* correct counter */
		0x18, 0x28, 0x38, 0x48, 0x58, 0x88, 0x98, 0xa8, 0xb8, 0xc8};
unsigned char corr_cnt_reg_v0[4] = {	/* correct counter */
		0x18, 0x38, 0x58, 0x78};
unsigned char gen_period_reg_v2[10] = {
		0x7c, 0x2c, 0x3c, 0x4c, 0x5c, 0x8c, 0x9c, 0xac, 0xbc, 0xcc};
unsigned char intpts_cnt_reg_v2[10] = {
		0x80, 0x30, 0x40, 0x50, 0x70, 0x90, 0xa0, 0xb0, 0xc0, 0xd0};
unsigned char prev_time_reg_v2[10]  = {
		0x84, 0x34, 0x44, 0x54, 0x74, 0x94, 0xa4, 0xb4, 0xc4, 0xd4};
unsigned char corr_cnt_reg_new[4]   = {0x1c, 0x30, 0x44, 0x58};
unsigned char gen_period_reg_new[4] = {0x20, 0x34, 0x48, 0x5c};
unsigned char intpts_cnt_reg_new[4] = {0x24, 0x38, 0x4c, 0x60};
unsigned char prev_time_reg_new[4]  = {0x28, 0x3c, 0x50, 0x64};
/* basic counter copy*/
unsigned char mpv_time_reg_new[4]   = {0x2c, 0x40, 0x54, 0x68};
/*  mpv or mpv_ioh2 version                           0   1   2   3 */
/* number of corr. time  regs */
unsigned char num_time_regs_v2[MAX_MPV_VER + 1]    = {4, 5, 10, 10};
unsigned char num_time_regs_ioh2[MAX_IOH2_VER + 1] = {3};
/* number of inputs */
unsigned char num_inputs_v2[MAX_MPV_VER + 1]       = {20, 20, 20, 20};
unsigned char num_inputs_ioh2[MAX_IOH2_VER + 1]    = {3};
/* enable generetor mask */
unsigned char gen_mode_reg_v2[MAX_MPV_VER + 1]     = {0xff, 0xff, 0x68, 0x68};
unsigned char gen_mode_reg_ioh2[MAX_IOH2_VER + 1]  = {0x14};
 
typedef struct __raw_wqueue {
	struct task_struct *task;
        struct list_head task_list;
} raw_wqueue_t;

typedef struct mpv_intrk
{
	/* limit time wating for interrupt (mcs) */
	int		intr_timeout;
	/* number of got interrupts by driver */
	int		num_reciv_intr;
	/* time from sinal appear to driver enter (ns) */
	int		correct_counter_nsec;
	/* ns timeofday when interrupt was appear in controler */
	long long	intr_appear_nsec;
	/* The time when driver have sent interrupt (ns) */
	long long	time_get_comm;
	/* time_of_day when interrupt was sent (mcs) */
	long long	time_generation_intr;
	/* clock source value when interrupt was got by driver */
	long long	intr_appear_clk;
	/* previous correct counter register value */
	int		prev_time_clk;
	/* common number of interrupts register value */
	int		intpts_cnt;
	/* monotonic time when interrupt was appear in controler */
	struct timespec intr_appear_raw;
	/* real time when interrupt was appear in controler */
	struct timespec intr_appear_real;
	/* interval of interrupts genarated by MPV */
	long long	interv_gen_ns;
	/* don't leave cpu < wait_on_cpu mcs*/
	int		wait_on_cpu;
	/* if it is set some timer intrrupts are perfomed by mpv */
	long long	period_ns;
	/* timeout for read(), ioctl(MPVIO_WAIT_INTR) for return ETIME */
	long long	timeout_ns;
	/* driver enter minus OS enter time */
	long long	irq_enter_clks;
	/* interrupt appear time as basic mpv counter */
	unsigned int	mpv_time;
	int		read_cc_ns;
	struct list_head	wait1_task_list;
} mpv_intrk_t;

typedef struct mpv_state_struct {
	raw_spinlock_t		mpv_lock;
	/* registers numbers for current mpv version */
	unsigned char		num_in_bus;
	unsigned char		num_time_regs;
	unsigned char		gen_mode_reg;
	unsigned char		mpv_time_reg[10];
	unsigned char		corr_cnt_reg[10];
	unsigned char		gen_period_reg[10];
	unsigned char		intpts_cnt_reg[10];
	unsigned char		prev_time_reg[10];

	int			oncpu_irq;	/* irq to be on cpu */
	int			psecs_per_corr_clck;
	int			intr_assemble;
	mpv_intrk_t		kdata_intr[MPV_NUM_IN_INTR];
	struct list_head	any_in_task_list;
	struct pci_dev		*pdev;
	struct of_device	*op;
	int			major;
	/* mpv_new=1 mpv KPI-2 (ioh2) or mpv_new=2 for MPV4m */
	u8			mpv_new;
	u8			revision_id;
	int			inst;
	int			open_in;
	int			open_in_count[MPV_NUM_IN_INTR];
	int			stv_in_number;/* mpv-in which adjusts time */
	int			stv_intr_got; /* STV interrupt is got*/
	int			non_oncpu_irq; /* irq to be in handler*/
	int			open_out;
	int			open_st;
	int			open_in_excl;
	int			open_out_excl;
	int			open_st_excl;
	void 			*regs_base;
	int			acc_regs;
	int			base_polar;
	int			polar;
	wait_queue_head_t       pollhead;	
	int			conf_inter;
	int			current_st;
	int			current_out;
	off_t			mpv_regs_sz;
	/* The time when interrupt was sent by MPV */
	long long		time_gener_intr;
	int			dev_type;	/* sbus, pci */
	int			irq;
	int			irq_orig;
	/* listen alive and mask input on interrupt */
	int			listen_alive;
} mpv_state_t;

#endif	/* _MPV_H_ */
