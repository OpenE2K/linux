#define BUILD_CPUHAS_INITIALIZERS
#include <linux/init.h>
#include <asm/machdep.h>

__nodedata machdep_t machine = { 0 };

int cpu_to_iset(int cpu)
{
	int iset = ELBRUS_GENERIC_ISET;

	switch (cpu) {
	case IDR_E2S_MDL:
		iset = ELBRUS_2S_ISET;
	case IDR_E8C_MDL:
		iset = ELBRUS_8C_ISET;
	case IDR_E1CP_MDL:
		iset = ELBRUS_1CP_ISET;
	case IDR_E8C2_MDL:
		iset = ELBRUS_8C2_ISET;
	case IDR_E12C_MDL:
		iset = ELBRUS_12C_ISET;
	case IDR_E16C_MDL:
		iset = ELBRUS_16C_ISET;
	case IDR_E2C3_MDL:
		iset = ELBRUS_2C3_ISET;
	}

	return iset;
}

int machdep_setup_features(int cpu, int revision)
{
	int iset_ver = cpu_to_iset(cpu);
	bool is_hardware_guest;

	if (iset_ver == ELBRUS_GENERIC_ISET)
		return 1;

	if (iset_ver < E2K_ISET_V6 || IS_ENABLED(CONFIG_KVM_GUEST_KERNEL)) {
		is_hardware_guest = false;
	} else {
		is_hardware_guest = DECOMPRESSOR_READ_CORE_MODE().gmi;
	}

	CPU_FEAT_EPIC_initializer(cpu, revision, iset_ver, cpu,
				  is_hardware_guest, &machine);
	CPU_FEAT_ISET_V6_initializer(cpu, revision, iset_ver, cpu,
				     is_hardware_guest, &machine);

	return 0;
}
