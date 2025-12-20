/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef __ASM_IOMMU_H
#define __ASM_IOMMU_H

#include <asm/l-iommu.h>
#include <asm/e2k-iommu.h>
#include <asm/epic.h>


static inline void iommu_shutdown(void)
{
	return cpu_has_epic() ? e2k_iommu_shutdown() : l_iommu_shutdown();
}

#endif /* __ASM_IOMMU_H */
