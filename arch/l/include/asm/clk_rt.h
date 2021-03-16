#ifndef _ASM_L_CLK_RT_H
#define _ASM_L_CLK_RT_H

#define CLK_RT_NO	0
#define CLK_RT_RTC	1
#define CLK_RT_EXT	2
#define CLK_RT_RESUME	3

extern struct clocksource clocksource_clk_rt;

extern int clk_rt_mode;
extern atomic_t num_clk_rt_register;
extern int clk_rt_register(void *);
extern struct clocksource clocksource_clk_rt;
extern int proc_clk_rt(struct ctl_table *, int,
	void __user *, size_t *, loff_t *);
extern int read_clk_rt_freq(void);
extern void clk_rt_set_mode(void *mode_arg);
extern u64 raw_read_clk_rt(void);
extern struct clocksource lt_cs;
extern struct clocksource *curr_clocksource;
#endif
