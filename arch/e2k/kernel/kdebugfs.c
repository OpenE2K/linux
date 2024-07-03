/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/debugfs.h>
#include <linux/export.h>
#include <linux/init.h>

struct dentry *arch_debugfs_dir;
EXPORT_SYMBOL(arch_debugfs_dir);

static int __init arch_kdebugfs_init(void)
{
	arch_debugfs_dir = debugfs_create_dir("e2k", NULL);
	return 0;
}
postcore_initcall(arch_kdebugfs_init);
