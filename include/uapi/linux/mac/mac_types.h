/*
 * Copyright (c) 2001-2002, by ZAO MCST.
 * All Rights Reserved.
 */

#ifndef	_UAPI__SYS_MAC_MAC_TYPES_H
#define	_UAPI__SYS_MAC_MAC_TYPES_H


#ifdef	__KERNEL__
#include <linux/types.h>
#else
#include <sys/types.h>
#endif

#define MAXUID 2147483647

#define	VREAD	004	
#define	VWRITE	002
#define	VEXEC	001	

#if !defined(MAY_READ)
#define	MAY_READ	VREAD
#endif
#if !defined(MAY_WRITE)
#define	MAY_WRITE	VWRITE
#endif
#if !defined(MAY_EXEC)
#define	MAY_EXEC	VEXEC
#endif
/*
 * Definition of MAC access type values to use with the kernel
 * MAC interface functions for setting up of access mode.
 */

/* "read" access type for the kernel MAC interface functions */
#define	KMAC_READ_ACCESS	(int)VREAD
/* "write" access type for the kernel MAC interface functions */
#define	KMAC_WRITE_ACCESS	(int)VWRITE
/* "execute" and "search" access types for the kernel MAC interface functions */
#define	KMAC_EXEC_ACCESS	(int)VEXEC

/*
 * The file contains definitions of several basic MAC data types:
 * data object identifiers, etc.
 */

/* identifier of MAC subject */
typedef unsigned int mac_subject_id_t;

/* identifier of MAC security label */
typedef unsigned char mac_label_id_t;

/* MAC access mode to an object */
typedef unsigned char mac_mode_t;

/* identifier of MAC user */
typedef unsigned int mac_user_id_t;

/* network address for MAC network address object */
typedef unsigned int mac_addr_t;

/* network port number for MAC network port object */
typedef unsigned short int mac_port_t;

/* network protocol number for MAC network port object */
typedef unsigned int mac_proto_t;

#endif /* _UAPI__SYS_MAC_MAC_TYPES_H */

