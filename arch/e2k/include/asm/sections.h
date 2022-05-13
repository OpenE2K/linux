#ifndef _E2K_SECTIONS_H
#define _E2K_SECTIONS_H

/* nothing to see, move along */
#ifndef __ASSEMBLY__
#include <asm-generic/sections.h>
#endif	/* ! __ASSEMBLY__ */

#if (defined __e2k__) && (defined __LCC__)
#define __interrupt     __attribute__((__check_stack__))
#else
#define __interrupt     __attribute__((__interrupt__))
#endif

#ifndef	CONFIG_RECOVERY
#define	__init_recv	__init
#define	__initdata_recv	__initdata
#else
#define	__init_recv
#define	__initdata_recv
#endif	/* ! (CONFIG_RECOVERY) */

#if !defined(CONFIG_RECOVERY) && !defined(CONFIG_SERIAL_PRINTK) && \
	!defined(CONFIG_LMS_CONSOLE) && !defined(CONFIG_E2K_KEXEC)
#define	__init_cons	__init
#else
#define	__init_cons
#endif	/* boot console used after init completion */

#ifndef __ASSEMBLY__
extern char _start[];
extern char __ttable_start[];
extern char __ttable_end[];
extern char __C1_wait_trap_start[], __C1_wait_trap_end[];
extern char __C3_wait_trap_start[], __C3_wait_trap_end[];
extern char __init_text_begin[], __init_text_end[];
extern char __init_data_begin[], __init_data_end[];
extern char __node_data_start[], __node_data_end[];
extern char __common_data_begin[], __common_data_end[];
extern char _edata_bss[];
extern char _t_entry[], _t_entry_end[];
extern char __entry_handlers_start[], __entry_handlers_end[];
extern char __entry_handlers_hcalls_start[], __entry_handlers_hcalls_end[];
extern char __start_ro_after_init[], __end_ro_after_init[];
#endif	/* ! __ASSEMBLY__ */

#ifdef	CONFIG_NUMA
#define __nodedata	__section(.node.data)
#define __NODEDATA	.section ".node.data","aw"
#else	/* ! CONFIG_NUMA */
#define __nodedata	__section(data)
#define __NODEDATA	.data
#endif	/* CONFIG_NUMA */

#endif	/* _E2K_SECTIONS_H */
