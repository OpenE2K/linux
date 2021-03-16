#ifndef _E2K_IOCTLS_H_
#define _E2K_IOCTLS_H_

/*
 * We are too far from real ioctl handling and it is difficult to predict
 * any errors now. So I accept i386(ia64) ioctl's stuff as the basis.
 */


#include <asm/ioctl.h>
#include <asm-generic/ioctls.h>

#define TIOCGHAYESESP   0x545E  /* Get Hayes ESP configuration */
#define TIOCSHAYESESP   0x545F  /* Set Hayes ESP configuration */
#define TIOCGDB         0x547F  /* enable GDB stub mode on this tty */

#endif /* _E2K_IOCTLS_H_ */
