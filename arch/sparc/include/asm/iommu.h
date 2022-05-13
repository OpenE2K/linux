/* SPDX-License-Identifier: GPL-2.0 */
#ifndef ___ASM_SPARC_IOMMU_H
#define ___ASM_SPARC_IOMMU_H
#if defined(__sparc__) && defined(__arch64__)
#ifndef CONFIG_E90S
#include <asm/iommu_64.h>
#endif
#else
#include <asm/iommu_32.h>
#endif
#endif
