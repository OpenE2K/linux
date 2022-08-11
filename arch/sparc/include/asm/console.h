
#ifndef	_SPARC64_CONSOLE_H_
#define	_SPARC64_CONSOLE_H_

#ifndef __ASSEMBLY__
#include <linux/init.h>
#include <asm/types.h>

#define	early_virtio_cons_enabled	false	/* cannot be used */

static inline void
virt_console_dump_putc(char c)
{
	/* virtual console is actual only on guest */
}

#include <asm-l/console.h>

#define	LMS_CONS_DATA_PORT	(0x300 + PCI_IO)
#define	LMS_CONS_STATUS_PORT	(0x301 + PCI_IO)

#endif /* __ASSEMBLY__ */

#endif  /* _SPARC64_CONSOLE_H_ */
