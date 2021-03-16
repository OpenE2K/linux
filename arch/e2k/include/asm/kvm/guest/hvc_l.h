/******************************************************************************
 * hvc_l.h (based on XEN console interface
 *
 * HyperVisor Console I/O interface for Elbrus guest OSes.
 *
 * Copyright (c) 2005, Keir Fraser
 *		(c) 2013 Salavat Gilyazov
 */

#ifndef __L_PUBLIC_IO_CONSOLE_H__
#define __L_PUBLIC_IO_CONSOLE_H__

typedef uint32_t LCONS_RING_IDX;

#define MASK_LCONS_IDX(idx, ring)	((idx) & (sizeof(ring)-1))

typedef struct lcons_interface {
	char in[1024];				/* input buffer */
	char out[2048];				/* output buffer */
	LCONS_RING_IDX in_cons, in_prod;	/* input buffer indexes */
	LCONS_RING_IDX out_cons, out_prod;	/* output buffer indexes */
} lcons_interface_t;

#define	LCONS_OUTPUT_NOTIFIER	(('l'<<24) | ('c'<<16) | ('o'<<8) | 't')
#define	LCONS_INPUT_NOTIFIER	(('l'<<24) | ('c'<<16) | ('i'<<8) | 'n')

#endif /* __L_PUBLIC_IO_CONSOLE_H__ */
