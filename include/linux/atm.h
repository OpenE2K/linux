/* SPDX-License-Identifier: GPL-2.0 */
/* atm.h - general ATM declarations */
#ifndef _LINUX_ATM_H
#define _LINUX_ATM_H

#include <uapi/linux/atm.h>

#ifdef CONFIG_COMPAT
#include <linux/compat.h>
struct compat_atmif_sioc {
	int number;
	int length;
	compat_uptr_t arg;
};
#endif
#if defined(CONFIG_E2K) && defined(CONFIG_PROTECTED_MODE)
#include <asm/e2k_ptypes.h>
struct ptr128_atmif_sioc {
	int number;
	int length;
	e2k_ap_t arg;
};
#endif
#endif
