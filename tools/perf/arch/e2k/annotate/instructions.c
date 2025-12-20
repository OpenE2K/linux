/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

static struct ins e2k__instructions[] = {
	{ .name = "return",	.ops = &ret_ops,  },
	{ .name = "call",	.ops = &call_ops,  },
};

