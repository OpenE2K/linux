/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#pragma once

extern int l_use_swiotlb;

static inline bool e2k_iommu_supported(void)
{
	if (cpu_has(CPU_HWBUG_CANNOT_DO_DMA_THROUGH_LINKS_B_AND_C) &&
			nr_online_nodes > 2) {
		return false;
	}
	return HAS_MACHINE_E2K_IOMMU;
}

