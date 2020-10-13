/*
 * Copyright (c) 1997 by MCST.
 */

#ifndef	_UAPI__LINUX_ME90_REG_H__
#define	_UAPI__LINUX_ME90_REG_H__

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef __KERNEL__
#include <sys/types.h>
#endif /* __KERNEL__ */

/*
 * Register sets of boards
 */

/* ================================================================ EPROMS : */

#define  ME90_EPROM_REG_SET_OFFSET	0x00000000 /* Open Boot EPROM memory */
typedef union  me90_eprom		/* EPROM memory structure */
{
	char *        as_chars;		/* memory as chars */
	u_char *      as_u_chars;	/* memory as unsugned chars */
#ifdef __e2k__
	int *        as_longs;		/* memory as longs */
	u_int *      as_u_longs;	/* memory as unsugned longs */
#else
	long *        as_longs;         /* memory as longs */
        u_long *      as_u_longs;       /* memory as unsugned longs */
#endif
	caddr_t       address;		/* memory address */
}	me90_eprom_t;
#define  ME90_EPROM_char		as_chars
#define  ME90_EPROM_u_char		as_u_chars
#define  ME90_EPROM_long		as_longs
#define  ME90_EPROM_u_long		as_u_longs
#define  ME90_EPROM_caddr		address
#define  ME90_MAX_EPROM_REG_SET_LEN	0x00010000 /* max lenght of memory   */
#define  ME90_EPROM_REG_SET_LEN		0x00000100 /* lenght of memory       */

#ifdef	__cplusplus
}
#endif

#endif /* _UAPI__LINUX_ME90_REG_H__ */
