#include <asm/e2k_api.h>
#include <asm/cpu_regs.h>

unsigned long boot_rrd_v3(int reg)
{
	switch (reg) {
	case E2K_REG_CORE_MODE:
		return NATIVE_READ_CORE_MODE_REG_VALUE();
	}

	return 0;
}

void boot_rwd_v3(int reg, unsigned long value)
{
	switch (reg) {
	case E2K_REG_CORE_MODE:
		NATIVE_WRITE_CORE_MODE_REG_VALUE(value);
		return;
	}
}

