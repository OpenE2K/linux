/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _ASM_E2K_DEVICE_H
/*
 * Arch specific extensions to struct device
 *
 * This file is released under the GPLv2
 */
#include <asm/e2k-iommu.h>

struct dev_archdata {
	struct device *iommu_dev;
};

struct pdev_archdata {
};

#endif /* _ASM_E2K_DEVICE_H */
