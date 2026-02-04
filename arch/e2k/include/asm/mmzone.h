/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _E2K_MMZONE_H_
#define _E2K_MMZONE_H_

#ifdef CONFIG_NUMA

#include <linux/nodemask.h>
#include <asm/smp.h>

extern struct pglist_data *node_data[];
#define NODE_DATA(nid)		(node_data[(nid)])

#endif
#endif /* _E2K_MMZONE_H_ */
