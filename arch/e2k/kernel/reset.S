#include <asm/asm-offsets.h>

/*
 * This function does the soft reset without working with memory. On the first
 * iteration it does nothing (it is needed only for code preload by processor).
 * On the second iteration it gives softreset. On the next iterations it does
 * nothing again (it is needed for waiting while softreset is being performed).
 *
 * C code:
 * void e2k_do_safe_reset_machine(u64 addr, u32 val)
 * {
 *     unsigned long i = 0;
 *     while (1) {
 *         if (i == 1) {
 *             E2K_WAIT_MA;
 *             E2K_WRITE_MAS_W(addr, val, MAS_IOADDR);
 *         }
 *         i++;
 *     }
 * }
 */

.global e2k_do_safe_reset_machine
.align  256
.type   e2k_do_safe_reset_machine, @function

e2k_do_safe_reset_machine: 
	setwd wsz = 0x5, nfx = 0x1
	setbn rsz = 0x0, rbs = 0x4, rcur = 0x0
	setbp psz = 0x0
	return %ctpr3
	addd 0, 0, %db[0]
	disp %ctpr2, M0
	cmpedb %db[0], 1, %pred1
	disp %ctpr1, M1

M0:
	cmpesb 0, 0, %pred0
	ct %ctpr1 ? ~ %pred1
	wait ma_c = 1, fl_c = 0, ld_c = 0, st_c = 0, all_e = 0, all_c = 0
	stw %r1, [ %dr0 ]0x6
	cmpesb 0, 0, %pred0

M1:
	addd %db[0], 1, %db[0]
	cmpedb %db[0], 1, %pred1
	ct %ctpr2 ? %pred0
	ct %ctpr3

/*
 * This function does infinite loop without working with memory.
 *
 * C code:
 * void e2k_safe_infinite_loop(void)
 * {
 *     while (1);
 * }
 */

.global e2k_safe_infinite_loop
.align  256
.type   e2k_safe_infinite_loop, @function

e2k_safe_infinite_loop:
	setwd wsz = 0x4, nfx = 0x1
	return %ctpr3
	setbp psz = 0x0
	disp %ctpr1, M2

M2:
	cmpesb 0, 0, %pred0
	ct %ctpr1 ? %pred0
	ct %ctpr3
