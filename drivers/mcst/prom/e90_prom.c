
#include <linux/types.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/mm.h>
#include <asm/sbus.h>
#include <asm-l/tree_entry.h>
#include <linux/of.h>

#undef DEBUG
#define DEBUG
#undef DEBUG

#ifdef DEBUG
#define  dbg(fmt, args...)      prom_printf( fmt "\n", ## args)
#else
#define  dbg(fmt, args...)
#endif
#define  info(fmt, args...)     prom_printf(KERN_INFO fmt "\n", ## args)

#ifdef __e2k__
#define prom_printf printk
#endif


int prom_getchild(int node)
{
	struct tree_entry *e = get_te_by_node(node);
	return e->child ? (int) e->child->node : 0;
}
EXPORT_SYMBOL(prom_getchild);

/* Acquire a property 'prop' at node 'node' and place it in
 * 'buffer' which has a size of 'bufsize'.  If the acquisition
 * was successful the length will be returned, else -1 is returned.
 */
int prom_getproperty(int node, const char *prop, char *buffer, int bufsize)
{
	struct tree_entry *e;
	int i;
	if (node == 0)
		return -1;
	e = get_te_by_node(node);
	for (i = 0; e->prop[i].name && i < MAX_PROPERTY; i++) {
		if (strcmp(prop, e->prop[i].name) == 0) {
			int size =
			    e->prop[i].size <
			    bufsize ? e->prop[i].size : bufsize;
			memcpy(buffer, e->prop[i].value, size);
			return size;
		}
	}
	dbg("property '%s' at node '%s' not found.", prop,
	    (char *) e->prop[ATTRIB_NAME].value);
	return -1;
}
EXPORT_SYMBOL(prom_getproperty);

int of_getintprop_default(struct device_node *np, const char *name, int def)
{
	struct property *prop;
	int len;

	prop = of_find_property(np, name, &len);
	if (!prop || len != 4)
		return def;
	return *(int *) prop->value;
}
EXPORT_SYMBOL(of_getintprop_default);

int prom_node_has_property(int node, char *prop)
{
	dbg("Fboot warning: prom_node_has_property called");
	return 0;
}

/* Return the length in bytes of property 'prop' at node 'node'.
 * Return -1 on error.
 */
int prom_getproplen(int node, const char *prop)
{
	struct tree_entry *e;
	int i;
	if (node == 0)
		return -1;
	e = get_te_by_node(node);
	for (i = 0; e->prop[i].name && i < MAX_PROPERTY; i++) {
		if (!strcmp(prop, e->prop[i].name))
			return e->prop[i].size;
	}
	dbg("property '%s' at node '%s' not found.", prop,
	    (char *) e->prop[ATTRIB_NAME].value);
	return -1;
}
EXPORT_SYMBOL(prom_getproplen);

/* Set property 'pname' at node 'node' to value 'value' which has a length
 * of 'size' bytes.  Return the number of bytes the prom accepted.
 */
int prom_setprop(int node, const char *pname, char *value, int size)
{
        struct tree_entry *e;
	int i;

        if(size == 0) return 0;
        if((pname == 0) || (value == 0) || (node == 0)) return 0;
        e = get_te_by_node(node);
        for (i = 0; i < MAX_PROPERTY; i++) {
		if (e->prop[i].name == NULL) {
			break;
		}
	}
	if (i >= MAX_PROPERTY) {
		return 0;
	}
        e->prop[i].name = kmalloc(strlen(pname) + 1, GFP_KERNEL);
        if (!e->prop[i].name) {
               return 0;
	}
        memcpy((char *)e->prop[i].name, (char *)pname, strlen(pname) + 1);

        e->prop[i].value = kmalloc(size, GFP_KERNEL);
        if (!e->prop[i].value) {
		kfree(e->prop[i].name);
		e->prop[i].name = NULL;
                return 0;
	}
        memcpy(e->prop[i].value, value, size);
	e->prop[i].size = size;

        return size;
}
EXPORT_SYMBOL(prom_setprop);

/* Return the first property name for node 'node'. */
/* buffer is unused argument, but as v9 uses it, we need to have the same interface */
char * prom_firstprop(int node, char *bufer)
{
        struct tree_entry *e;
        if (node == 0 || node == -1)
                return "";
        e = get_te_by_node(node);
        return (char *)(e->prop[0].name ? e->prop[0].name : "");
}
EXPORT_SYMBOL(prom_firstprop);


/* Return the property type string after property type 'oprop'
 * at node 'node' .  Returns empty string if no more
 * property types for this node.
 */
char * prom_nextprop(int node, char *oprop, char *buffer)
{
        struct tree_entry *e;
	int i;
        if (node == 0 || node == -1)
                return "";
        e = get_te_by_node(node);
        for (i = 0; i < MAX_PROPERTY; i++) {
		if (!e->prop[i].name)
			return "";
                if (!strcmp(e->prop[i].name, oprop)) {
                        break;
                }
        }
        if (i >= (MAX_PROPERTY - 1)) {
                return "";
        }
	if (e->prop[i + 1].name == NULL) {
		return "";
	}
	return (char *)e->prop[i + 1].name;
}
EXPORT_SYMBOL(prom_nextprop);

/* Search siblings at 'node_start' for a node with name
 * 'nodename'.  Return node if successful, zero if not.
 */
int prom_searchsiblings(int node_start, char *nodename)
{
	struct tree_entry *e;

	if (node_start == 0)
		return 0;
        e = get_te_by_node(node_start);
	for (; e; e = e->sibling) {
		int i;
		for (i = 0; e->prop[i].name && i < MAX_PROPERTY; i++) {
			if (!strcmp("name", e->prop[i].name)) {
				if (!strcmp(nodename, e->prop[i].value))
					return e->node;
				else
					break;
			}
		}
	}
	dbg("sibling '%s' at node '%s' not found.\n", nodename,
	    (char *)(get_te_by_node(node_start)->prop[ATTRIB_NAME].value));
	return 0;
}
EXPORT_SYMBOL(prom_searchsiblings);

/* Return the next sibling of node 'node' or zero if no more siblings
 * at this level of depth in the tree.
 */
int prom_getsibling(int node)
{
	struct tree_entry *e = (struct tree_entry *) node;
	extern struct tree_entry *sbus_root_node;
	if (node == 0) {
		return sbus_root_node->node;
	}
        e = get_te_by_node(node);
	return e->sibling ? e->sibling->node : 0;
}
EXPORT_SYMBOL(prom_getsibling);

/* Acquire an integer property and return its value.  Returns -1
 * on failure.
 */
int prom_getint(int node, char *prop)
{
	int intprop;
	if (prom_getproperty(node, prop, (char *) &intprop, sizeof(int)) !=
	    -1)
		return intprop;

	return -1;
}
EXPORT_SYMBOL(prom_getint);

/* Acquire a boolean property, 1=TRUE 0=FALSE. */
int prom_getbool(int node, char *prop)
{
	int retval;

	retval = prom_getproplen(node, prop);
	if (retval == -1)
		return 0;
	return 1;
}



/* Acquire an integer property, upon error return the passed default
 * integer.
 */
int prom_getintdefault(int node, char *property, int deflt)
{
	int res = prom_getint(node, property);
	return res == -1 ? deflt : res;
}
EXPORT_SYMBOL(prom_getintdefault);
/* Acquire a property whose value is a string, returns a null
 * string on error.  The char pointer is the user supplied string
 * buffer.
 */
void prom_getstring(int node, char *prop, char *user_buf, int ubuf_size)
{
	int len;
	len = prom_getproperty(node, prop, user_buf, ubuf_size);
	if (len != -1)
		return;
	user_buf[0] = 0;
	return;
}
EXPORT_SYMBOL(prom_getstring);

/* Adjust register values based upon the ranges parameters. */
static void
prom_adjust_regs(struct linux_prom_registers *regp, int nregs,
		 struct linux_prom_ranges *rangep, int nranges)
{
	int regc, rngc;

	for (regc = 0; regc < nregs; regc++) {
		for (rngc = 0; rngc < nranges; rngc++)
			if (regp[regc].which_io ==
			    rangep[rngc].ot_child_space)
				break;	/* Fount it */
		if (rngc == nranges)	/* oops */
			prom_printf
			    ("adjust_regs: Could not find range with matching bus type...\n");
		regp[regc].which_io = rangep[rngc].ot_parent_space;
		regp[regc].phys_addr -= rangep[rngc].ot_child_base;
		regp[regc].phys_addr += rangep[rngc].ot_parent_base;
	}
}

static void
prom_adjust_ranges(struct linux_prom_ranges *ranges1, int nranges1,
		   struct linux_prom_ranges *ranges2, int nranges2)
{
	int rng1c, rng2c;

	for (rng1c = 0; rng1c < nranges1; rng1c++) {
		for (rng2c = 0; rng2c < nranges2; rng2c++)
			if (ranges1[rng1c].ot_parent_space ==
			    ranges2[rng2c].ot_child_space
			    && ranges1[rng1c].ot_parent_base >=
			    ranges2[rng2c].ot_child_base
			    && ranges2[rng2c].ot_child_base +
			    ranges2[rng2c].or_size -
			    ranges1[rng1c].ot_parent_base > 0U)
				break;
		if (rng2c == nranges2)	/* oops */
			prom_printf
			    ("adjust_ranges: Could not find matching bus type...\n");
		else if (ranges1[rng1c].ot_parent_base +
			 ranges1[rng1c].or_size >
			 ranges2[rng2c].ot_child_base +
			 ranges2[rng2c].or_size)
			ranges1[rng1c].or_size =
			    ranges2[rng2c].ot_child_base +
			    ranges2[rng2c].or_size -
			    ranges1[rng1c].ot_parent_base;
		ranges1[rng1c].ot_parent_space =
		    ranges2[rng2c].ot_parent_space;
		ranges1[rng1c].ot_parent_base +=
		    ranges2[rng2c].ot_parent_base;
	}
}



void prom_apply_generic_ranges(int node, int parent,
			       struct linux_prom_registers *regs,
			       int nregs)
{
	int success;
	int num_ranges;
	struct linux_prom_ranges ranges[PROMREG_MAX];

	success = prom_getproperty(node, "ranges",
				   (char *) ranges, sizeof(ranges));
	if (success != -1) {
		num_ranges = (success / sizeof(struct linux_prom_ranges));
		if (parent) {
			struct linux_prom_ranges
			    parent_ranges[PROMREG_MAX];
			int num_parent_ranges;

			success = prom_getproperty(parent, "ranges",
						   (char *) parent_ranges,
						   sizeof(parent_ranges));
			if (success != -1) {
				num_parent_ranges =
				    (success /
				     sizeof(struct linux_prom_ranges));
				prom_adjust_ranges(ranges, num_ranges,
						   parent_ranges,
						   num_parent_ranges);
			}
		}
		prom_adjust_regs(regs, nregs, ranges, num_ranges);
	}
}


