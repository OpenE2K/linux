#ifndef ___ASM_SPARC_IOMMU_H
#define ___ASM_SPARC_IOMMU_H
#if defined(__sparc__) && defined(__arch64__)
#ifdef CONFIG_E90S
#include <asm/iommu_e90s.h>
#else
#include <asm/iommu_64.h>
#endif
#else
#include <asm/iommu_32.h>
#endif
#endif
