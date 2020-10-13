/* $Id: state_save.h,v 1.2 2004/01/26 14:32:35 akozyrev Exp $
 *
 */

#ifndef _E2K_STATE_SAVE_H
#define _E2K_STATE_SAVE_H

#include <linux/config.h>
#include <linux/init.h>
#include <linux/ide.h>

#include <asm/types.h>
#include <asm/e2k_api.h>
#include <asm/head.h>

extern inline void kstate_dec(void);
extern void kstate_wakeup(int cond);
extern int kstate_redirect(void);
extern int kstate_block(void);
extern int kstate_block_schedule(void);
extern void e2k_save_state(void);
extern void e2k_load_state(void);
extern void block_io_and_sched(void);
extern void init_state_save(void);

//extern ide_startstop_t e2k_ide_error(const char *msg, byte stat);
//extern int e2k_ide_wait_stat (ide_startstop_t *startstop,  byte good, byte bad, unsigned long timeout);
//extern void e2k_ide_timer_expiry (unsigned long data);
//extern void e2k_ide_intr (int irq, void *dev_id, struct pt_regs *regs);

extern unsigned long time_left;

#endif /* _E2K_STATE_SAVE_H */
