/* $Id: oplib.h,v 1.2 2007/09/05 12:05:52 kostin Exp $
 * oplib.h:  Describes the interface and available routines in the
 *           Linux Prom library.
 *
 * Copyright (C) 1995 David S. Miller (davem@caip.rutgers.edu)
 * Copyright (C) 2005 Alexander Shmelev (ashmelev@task.sun.mcst.ru)
 */

#ifndef __OPLIB_H
#define __OPLIB_H

#include "openprom.h"
#include <linux/spinlock.h>

/* Root node of the prom device tree, this stays constant after
 * initialization is complete.
 */
extern int prom_root_node;

/* The functions... */

/* PROM device tree traversal functions... */

/* Get the child node of the given node, or zero if no child exists. */
extern int prom_getchild(int parent_node);

/* Get the next sibling node of the given node, or zero if no further
 * siblings exist.
 */
extern int prom_getsibling(int node);

/* Get the length, at the passed node, of the given property type.
 * Returns -1 on error (ie. no such property at this node).
 */
extern int prom_getproplen(int thisnode, const char *property);

/* Fetch the requested property using the given buffer.  Returns
 * the number of bytes the prom put into your buffer or -1 on error.
 */
extern int prom_getproperty(int thisnode, const char *property,
			    char *prop_buffer, int propbuf_size);

/* Acquire an integer property. */
extern int prom_getint(int node, char *property);

/* Acquire an integer property, with a default value. */
extern int prom_getintdefault(int node, char *property, int defval);

/* Acquire a boolean property, 0=FALSE 1=TRUE. */
extern int prom_getbool(int node, char *prop);

/* Acquire a string property, null string on error. */
extern void prom_getstring(int node, char *prop, char *buf, int bufsize);

/* Does the passed node have the given "name"? YES=1 NO=0 */
extern int prom_nodematch(int thisnode, char *name);

/* Puts in buffer a prom name in the form name@x,y or name (x for which_io 
 * and y for first regs phys address
 */
extern int prom_getname(int node, char *buf, int buflen);

/* Search all siblings starting at the passed node for "name" matching
 * the given string.  Returns the node on success, zero on failure.
 */
extern int prom_searchsiblings(int node_start, char *name);

/* Return the first property type, as a string, for the given node.
 * Returns a null string on error.
 */
extern char *prom_firstprop(int node, char *buffer);

/* Returns the next property after the passed property for the given
 * node.  Returns null string on failure.
 */
extern char *prom_nextprop(int node, char *prev_property, char *buffer);

/* Returns phandle of the path specified */
extern int prom_finddevice(char *name);

/* Returns 1 if the specified node has given property. */
extern int prom_node_has_property(int node, char *property);

/* Set the indicated property at the given node with the passed value.
 * Returns the number of bytes of your value that the prom took.
 */
extern int prom_setprop(int node, const char *prop_name, char *prop_value,
			int value_size);

#endif /* !(__OPLIB_H) */
