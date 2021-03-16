/*  Generic MTRR (Memory Type Range Register) ioctls.

    Copyright (C) 1997-1999  Richard Gooch

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Library General Public
    License as published by the Free Software Foundation; either
    version 2 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Library General Public License for more details.

    You should have received a copy of the GNU Library General Public
    License along with this library; if not, write to the Free
    Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

    Richard Gooch may be reached by email at  rgooch@atnf.csiro.au
    The postal address is:
      Richard Gooch, c/o ATNF, P. O. Box 76, Epping, N.S.W., 2121, Australia.
*/
#ifndef _LINUX_MTRR_H
#define _LINUX_MTRR_H

#include <uapi/asm/mtrr.h>


/*  The following functions are for use by other drivers  */
# ifdef CONFIG_MTRR
extern int mtrr_add (unsigned long base, unsigned long size,
		     unsigned int type, char increment);
extern int mtrr_add_page (unsigned long base, unsigned long size,
		     unsigned int type, char increment);
extern int mtrr_del (int reg, unsigned long base, unsigned long size);
extern int mtrr_del_page (int reg, unsigned long base, unsigned long size);
#  else
static __inline__ int mtrr_add (unsigned long base, unsigned long size,
				unsigned int type, char increment)
{
    return -ENODEV;
}
static __inline__ int mtrr_add_page (unsigned long base, unsigned long size,
				unsigned int type, char increment)
{
    return -ENODEV;
}
static __inline__ int mtrr_del (int reg, unsigned long base,
				unsigned long size)
{
    return -ENODEV;
}
static __inline__ int mtrr_del_page (int reg, unsigned long base,
				unsigned long size)
{
    return -ENODEV;
}
#  endif

/*  The following functions are for initialisation: don't use them!  */
extern int mtrr_init (void);
#  if defined(CONFIG_SMP) && defined(CONFIG_MTRR)
extern void mtrr_init_boot_cpu (void);
extern void mtrr_init_secondary_cpu (void);
#  endif

#endif  /*  _LINUX_MTRR_H  */
