#ifndef __ASM_ACPI_H
#define __ASM_ACPI_H

#include <asm/mmu_regs_access.h>

#define ACPI_FLUSH_CPU_CACHE()  write_back_CACHE_all()

#include <asm-l/acpi.h>

#endif
