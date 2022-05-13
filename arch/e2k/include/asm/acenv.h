
#ifndef _ASM_E2K_ACENV_H_
#define _ASM_E2K_ACENV_H_

#include <asm/mmu_regs_access.h>
#define ACPI_FLUSH_CPU_CACHE()  write_back_CACHE_L12()
#include <asm-l/acenv.h>

#endif /* _ASM_E2K_ACENV_H_ */

