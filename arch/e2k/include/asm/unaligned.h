#ifndef _E2K_UNALIGNED_H_
#define _E2K_UNALIGNED_H_

/*
 * The e2K arch can do unaligned accesses itself as i386.
 *
 * The strange macros are there to make sure these can't
 * be misused in a way that makes them not work on other
 * architectures where unaligned accesses aren't as simple.
 *
 * BUT there is a hardware bug which forbids usage of
 * unaligned accesses and DAM together.
 */

#ifdef CONFIG_ACCESS_CONTROL
# include <asm-generic/unaligned.h>
#else
# include <linux/unaligned/access_ok.h>
# include <linux/unaligned/generic.h>

# define get_unaligned __get_unaligned_le
# define put_unaligned __put_unaligned_le
#endif

#endif /* _E2K_UNALIGNED_H_ */
