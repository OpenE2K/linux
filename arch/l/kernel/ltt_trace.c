#include <asm/system.h>
#include <asm/unistd.h>
#include <linux/marker.h>
#include <linux/kallsyms.h>
#include <linux/module.h>
/*
 * for LTT tracing
 */
#ifdef	CONFIG_E2K
	#define MASKA 0xffffffffffffffL
#else
#ifdef	CONFIG_SPARC64
/* sparc64 used short address (32bit) */
extern unsigned int sys_call_table[];
#else
extern unsigned long sys_call_table[];
#endif /* CONFIG_SPARC64 */
#endif /* CONFIG_E2K */

void ltt_dump_sys_call_table(void *call_data)
{
	int i;
	char namebuf[KSYM_NAME_LEN];

	for (i = 0; i < NR_syscalls; i++) {
#ifdef CONFIG_E2K
		sprint_symbol(namebuf,
			    (unsigned long)(sys_call_table[i]) & MASKA);
#else
		sprint_symbol(namebuf, (unsigned long)(sys_call_table[i]));
#endif
		__trace_mark(0, syscall_state, sys_call_table,
		call_data,
		"id %d address %p symbol %s",
		i, (void *)sys_call_table[i], namebuf);
	}
}
EXPORT_SYMBOL_GPL(ltt_dump_sys_call_table);

void ltt_dump_idt_table(void *call_data)
{
}
EXPORT_SYMBOL_GPL(ltt_dump_idt_table);

