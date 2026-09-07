/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _ASM_E2K_PTDUMP_H

#ifdef CONFIG_STRICT_KERNEL_RWX
void ptdump_check_wx(void);
#else
#define ptdump_check_wx()
#endif
#endif
