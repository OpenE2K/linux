#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/proc_fs.h>
#include <asm-l/tree_entry.h>
#include <asm/sbus.h>

#include "sbus_proc_tree.h"

static struct proc_dir_entry *sbus_ent = NULL;

typedef knode_t node_t;

node_t *create_node(void)
{
	node_t *new_node = kmalloc(sizeof(node_t), GFP_KERNEL);
	if (new_node == NULL)
		return NULL;
	new_node->depth = 0;
	new_node->child = NULL;
	new_node->type = NO_TYPE;
	new_node->next = NULL;

	return new_node;
}

void add_child(node_t *parent, node_t *node)
{
	node->parent = parent;
	node->depth = parent->depth + 1;
	node->next = NULL;
	if (parent->child) {
		node_t *sibling = parent->child;
		while (sibling->next)
			sibling = sibling->next;
		sibling->next = node;
	} else {
		parent->child = node;
	}
}

int build_sub_tree(node_t *parent, int prom_node, int depth, int type)
{
	int len;
	node_t *node;
	char node_str[128];

	while (prom_node != 0 && prom_node != -1) {
		if ((node = create_node()) == NULL) {
			pr_err("MCT_TREE:build_sub_tree:"
			       " Error memory allocation\n");
			return -1;
		}

		len = (int)prom_getproperty(prom_node, "name",
					    node->name, sizeof(node->name));
		prom_getstring(prom_node, "device_type",
			       node_str, sizeof(node_str));

		if (!strcmp(node_str, "cpu") ||
		    !strcmp(node->name, "memory") ||
		    !strcmp(node->name, "pcin")) {
			kfree(node);
			goto next_dev;
		}

		if (depth == 0)
			type = NO_TYPE;
		node->type = type;

		if (strcmp(node->name, "sbus") == 0) {
			node->type = BUS;
			type = SBUS;
		}

		len = prom_getproperty(prom_node, "reg",
				       (char *) node->reg_addrs,
					sizeof(node->reg_addrs));
		if (len == -1) {
			node->num_registers = 0;
			goto no_regs;
		}

		if (len % sizeof(struct linux_prom_registers)) {
			pr_err("fill_sbus_device: proplen for regs of %s "
				" was %d, need multiple of %d\n",
				node->name, len,
				(int) sizeof(struct linux_prom_registers));
			return -1;
		}
		if (len > (sizeof(struct linux_prom_registers)*PROMREG_MAX)) {
			pr_err("fill_sbus_device: Too many register properties"
				" for device %s, len=%d\n",
				node->name, len);
			return -1;
		}
		node->num_registers = len/sizeof(struct linux_prom_registers);
		node->ranges_applied = 0;

		/* Compute the slot number. */
		node->slot = prom_getint(prom_node, "slot");
		if (node->slot == -1)
			node->slot = node->reg_addrs[0].which_io;
no_regs:
		len = prom_getproperty(prom_node, "ranges",
				       (char *)node->device_ranges,
					sizeof(node->device_ranges));
		if (len == -1) {
			node->num_device_ranges = 0;
			goto no_ranges;
		}
		if (len % sizeof(struct linux_prom_ranges)) {
			pr_err("fill_sbus_device: proplen for ranges of %s "
				" was %d, need multiple of %d\n",
				node->name, len,
				(int) sizeof(struct linux_prom_ranges));
			return -1;
		}
		if (len > (sizeof(struct linux_prom_ranges) * PROMREG_MAX)) {
			pr_err("fill_sbus_device: Too many range properties "
				"for device %s, len=%d\n",
				node->name, len);
			return -1;
		}
		node->num_device_ranges = len/sizeof(struct linux_prom_ranges);
no_ranges:
		add_child(parent, node);
next_dev:
		if (prom_getchild(prom_node)) {
			build_sub_tree(node, prom_getchild(prom_node),
				       depth+1, type);
		}

		prom_node = prom_getsibling(prom_node);
	}
	return 0;
}

int print_nodes(node_t *node, char *buf, int len)
{
	do {
		int i;

		if (!strcmp(node->name, ".")) {
			if (node->child) {
				len = print_nodes(node->child, buf, len);
			}
			node = node->next;
			continue;
		}

		for (i = 0; i < node->depth; i++) {
			len += sprintf(buf+len, "    ");
			buf[len] = 0;
		}

		switch (node->type) {
		case SBUS:
			len += sprintf(buf+len, "%s@0x%08x Slot %x\n",
					node->name,
					node->reg_addrs[0].phys_addr,
					node->slot);
			break;
		default:
			len += sprintf(buf+len, "%s\n", node->name);
			break;
		}

		buf[len] = 0;
		if (node->child) {
			len = print_nodes(node->child, buf, len);
		}
		node = node->next;
		buf[len] = 0;
	} while (node);

	return len;
}

int proc_sbus_entry(char *buf, char **start,
			off_t off, int count,
			int *eof, void *data) {
	int len = 0;
	node_t *root = (node_t *)data;

	len = print_nodes(root->child, buf, len);
	buf[len] = 0;

	return len;
}

void make_sbus_tree(void)
{
	int root_node;
	node_t *tree_root;
	char proc_bus_path[128] = "bus/sbus";

	if ((tree_root = create_node()) == NULL) {
		pr_err("MCT_TREE:do_build_tree: Error memory allocation\n");
		return;
	}
	tree_root->depth = 0;
	tree_root->slot = -1;

	root_node = prom_getchild(prom_root_node);
	build_sub_tree(tree_root, root_node, 0, NO_TYPE);

	if ((sbus_ent = proc_mkdir(proc_bus_path, NULL)) == NULL)
		return;

	create_proc_read_entry("devices",
				0,
				sbus_ent,
				proc_sbus_entry,
				tree_root);
}

static int __init tree_init(void)
{
	make_sbus_tree();

	return 0;
}

static void __exit tree_destroy(void)
{
	if (!sbus_ent) {
		remove_proc_entry("devices", sbus_ent);
	}
}

subsys_initcall(tree_init);
module_exit(tree_destroy);
MODULE_LICENSE("GPL");
