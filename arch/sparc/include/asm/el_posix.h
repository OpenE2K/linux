#ifndef _ASM_EL_POSIX_H
#define _ASM_EL_POSIX_H

#if defined(__sparc__) && defined(__arch64__)
#include <asm/el_posix_64.h>
#else
#include <asm/el_posix_32.h>
#endif

#endif
