#ifndef	_E2K_ISET_H
#define	_E2K_ISET_H

#include <asm/machdep.h>

struct iset {
	void (*flushts)(void);
};

extern struct iset iset_e2s;
#define	iset_e8c	iset_e2s	/* now same as e2s iset */
#define	iset_e1cp	iset_e2s	/* now same as e2s iset */
#define	iset_e8c2	iset_e2s	/* now same as e2s iset */

static inline void flushts(void)
{
	if (machine.iset && machine.iset->flushts)
		machine.iset->flushts();
}

#endif	/* _E2K_ISET_H */
