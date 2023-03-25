#ifndef ___ASM_SPARC_L_IDE_H
#define ___ASM_SPARC_L_IDE_H

#ifndef CONFIG_E90S
#if defined(__sparc__) && defined(__arch64__)
#include <asm/l_ide64.h>
#else
#include <asm/l_ide32.h>
#endif 
#else /* !CONFIG_E90S */
#include <asm-l/l_ide.h>
#endif /* CONFIG_E90S */

#endif

