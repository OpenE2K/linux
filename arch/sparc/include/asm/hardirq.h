#ifndef ___ASM_SPARC_HARDIRQ_H
#define ___ASM_SPARC_HARDIRQ_H
#if defined(__sparc__) && defined(__arch64__)
#ifdef CONFIG_E90S
#include <asm-l/hardirq.h>
#else
#include <asm/hardirq_64.h>
#endif
#else
#include <asm/hardirq_32.h>
#endif
#endif
