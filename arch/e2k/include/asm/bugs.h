#ifndef _E2K_BUGS_H_
#define _E2K_BUGS_H_

#include <asm/processor.h>

/*
 * This is included by init/main.c to check for architecture-dependent bugs.
 *
 * Needs:
 *      void check_bugs(void);
 */

static inline void check_bugs(void) {
}

#endif /* _E2K_BUGS_H_ */
