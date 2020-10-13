#ifndef _UAPI_E2K_MMAN_H_
#define _UAPI_E2K_MMAN_H_


/*
 * Copyright (C) 1998-2000 Hewlett-Packard Co
 * Copyright (C) 1998-2000 David Mosberger-Tang <davidm@hpl.hp.com>
 *
 * Adopted for Linux/E2K. To be extended for proper E2K mem. management.
 */

#define PROT_NONE	0x0		/* page can not be accessed */
#define PROT_READ	0x1		/* page can be read */
#define PROT_WRITE	0x2		/* page can be written */
#define PROT_EXEC	0x4		/* page can be executed */
#define PROT_SEM	0x8		/* page may be used for atomic ops */
#define PROT_GROWSDOWN	0x20		/* mprotect flag: extend change */
					/* to start of growsdown vma */
#define PROT_GROWSUP	0x40		/* mprotect flag: extend change */
					/* to end of growsup vma */
#define PROT_CUI	0xffff00
#define	PROT_CUI_SHIFT	8
#define	PROT_CUI_MASK	0xFFFF

#define	GET_CUI_FROM_INT_PROT(prot)	(((prot) >> PROT_CUI_SHIFT) & \
						     PROT_CUI_MASK)
#define	PUT_CUI_TO_INT_PROT(prot, cui)	((((cui) & PROT_CUI_MASK) << \
						    PROT_CUI_SHIFT) | prot)

#define MAP_SHARED	0x000001	/* Share changes */
#define MAP_PRIVATE	0x000002	/* Changes are private */
#define MAP_TYPE	0x00000f	/* Mask for type of mapping */
#define MAP_ANONYMOUS	0x000010	/* don't use a file */
#define MAP_FIXED	0x000100	/* Interpret addr exactly */
#define MAP_DENYWRITE	0x000800	/* ETXTBSY */
#define MAP_GROWSDOWN	0x001000	/* stack-like segment */
#define MAP_GROWSUP	0x002000	/* register stack-like segment */
#define MAP_EXECUTABLE	0x004000	/* mark it as an executable */
#define MAP_LOCKED	0x008000	/* pages are locked */
#define MAP_NORESERVE	0x010000	/* don't check for reservations */
#define MAP_POPULATE	0x020000	/* populate (prefault) pagetables */
#define MAP_NONBLOCK	0x040000	/* do not block on IO */
#define MAP_FIRST32	0x080000	/* in protected mode map in  */
						/* first 2 ** 32 area */
#define MAP_WRITECOMBINED	0x100000	/* Write combine */
#define MAP_HUGETLB		0x200000	/* create a huge page mapping */

#define MS_ASYNC		1		/* sync memory asynchronously */
#define MS_INVALIDATE	2		/* invalidate the caches */
#define MS_SYNC		4		/* synchronous memory sync */

#define MCL_CURRENT	1		/* lock all current mappings */
#define MCL_FUTURE	2		/* lock all future mappings */

#define MADV_NORMAL	0		/* no further special treatment */
#define MADV_RANDOM	1		/* expect random page references */
#define MADV_SEQUENTIAL	2		/* expect sequential page references */
#define MADV_WILLNEED	3		/* will need these pages */
#define MADV_DONTNEED	4		/* don't need these pages */

/* common parameters: try to keep these consistent across architectures */
#define MADV_REMOVE	9		/* remove these pages & resources */
#define MADV_DONTFORK	10		/* don't inherit across fork */
#define MADV_DOFORK	11		/* do inherit across fork */
#define MADV_HWPOISON	100		/* poison a page for testing */
#define MADV_SOFT_OFFLINE 101		/* soft offline page for testing */

#define MADV_MERGEABLE   12		/* KSM may merge identical pages */
#define MADV_UNMERGEABLE 13		/* KSM may not merge identical pages */

#define MADV_HUGEPAGE	14		/* Worth backing with hugepages */
#define MADV_NOHUGEPAGE	15		/* Not worth backing with hugepages */

#define MADV_DONTDUMP   16		/* Explicity exclude from the core dump,
					   overrides the coredump filter bits */
#define MADV_DODUMP	17		/* Clear the MADV_NODUMP flag */

/* compatibility flags */
#define MAP_ANON	MAP_ANONYMOUS
#define MAP_FILE	0


#endif /* _UAPI_E2K_MMAN_H_ */
