#ifndef __TREE_ENTRY_H
#define __TREE_ENTRY_H

#define MAX_PROPERTY 8
#define ATTRIB_NAME 0

struct prom_property {
	const char *name;
	void *value;
	int size;
};
struct tree_entry {
	struct tree_entry *sibling;
	struct tree_entry *child;
	int node;
	struct prom_property prop[MAX_PROPERTY];	/*NULEWOE SWOJSTWO D.B. IMENEM */
};

extern struct tree_entry *sbus_root_node;

extern void scan_sbus(struct tree_entry *root, unsigned long start_addr,
			int slot_len, int slot_num);
extern void init_known_nodes(struct tree_entry *root);
extern struct tree_entry *get_te_by_node(int node);
extern struct tree_entry *copy_sbus_dev(struct tree_entry *dev);
extern void free_sbus_dev(struct tree_entry *dev);

extern int prom_getchild(int node);
extern int prom_getproperty(int node, const char *prop, char *buffer, int bufsize);
extern int prom_node_has_property(int node, char *prop);
extern int prom_getproplen(int node, const char *prop);
extern int prom_setprop(int node, const char *pname, char *value, int size);
extern char * prom_firstprop(int node, char *bufer);
extern char * prom_nextprop(int node, char *oprop, char *buffer);
extern int prom_searchsiblings(int node_start, char *nodename);
extern int prom_getsibling(int node);
extern int prom_getint(int node, char *prop);
extern int prom_getbool(int node, char *prop);
extern int prom_getintdefault(int node, char *property, int deflt);
extern void prom_getstring(int node, char *prop, char *user_buf, int ubuf_size);

#endif /* __TREE_ENTRY_H */
