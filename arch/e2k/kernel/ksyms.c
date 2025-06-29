/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifdef CONFIG_PARAVIRT_SPINLOCKS

#include <asm/spinlock.h>

EXPORT_SYMBOL(__pv_queued_spin_unlock);

#endif /* CONFIG_PARAVIRT_SPINLOCKS */
