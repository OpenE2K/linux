#ifndef __ASM_I8253_H__
#define __ASM_I8253_H__

/* i8253A PIT registers */
#define PIT_MODE		0x43
#define PIT_CH0			0x40
#define PIT_CH2			0x42

extern raw_spinlock_t i8253_lock;

extern struct clock_event_device *global_clock_event;

extern void setup_pit_timer(void);
#ifdef CONFIG_MCST_RT
extern int mcst_rt_pit_start(void);
extern int mcst_rt_pit_stop(void);
extern unsigned long e2k_pit_get_dintr_time(void);
#endif

#define inb_pit		inb_p
#define outb_pit	outb_p

#endif	/* __ASM_I8253_H__ */
