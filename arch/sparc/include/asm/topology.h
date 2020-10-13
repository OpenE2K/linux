#ifndef ___ASM_SPARC_TOPOLOGY_H
#define ___ASM_SPARC_TOPOLOGY_H
#if defined(__sparc__) && defined(__arch64__)
#ifdef CONFIG_E90S
#include <asm/topology_e90s.h>
#else
#include <asm/topology_64.h>
#endif
#else
#include <asm/topology_32.h>
#endif
#endif
