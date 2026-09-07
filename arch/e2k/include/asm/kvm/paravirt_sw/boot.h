/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * E2K boot-time initialization virtualization for KVM host
 */

#pragma once

#ifndef __ASSEMBLY__

#include <linux/types.h>
#include <linux/kernel.h>

#include <asm/e2k_api.h>

#ifdef	CONFIG_VIRTUALIZATION
#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is virtualized guest kernel */
#include <asm/kvm/guest/boot.h>
#endif	/* CONFIG_KVM_GUEST_KERNEL */
#endif	/* CONFIG_VIRTUALIZATION */

#endif /* ! __ASSEMBLY__ */
