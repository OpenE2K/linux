
#ifndef _E2K_CLK_GATE_H_
#define _E2K_CLK_GATE_H_

#ifdef CONFIG_E2S_CLK_GATE
extern void do_e2s_clk_on(int cpuid);
extern void do_e2s_clk_off(int cpuid);
extern void do_e8c_clk_on(int cpuid);
extern void do_e8c_clk_off(int cpuid);
extern void e2k_clk_resume(void);
#else
void do_e2s_clk_on(int cpuid) { return; }
void do_e2s_clk_off(int cpuid) { return; }
void do_e8c_clk_on(int cpuid) { return; }
void do_e8c_clk_off(int cpuid) { return; }
void e2k_clk_resume() { return; }
#endif /* CONFIG_E2S_CLK_GATE */

#endif  /* _E2K_CLK_GATE_H_ */
