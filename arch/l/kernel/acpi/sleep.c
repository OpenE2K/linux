/*
 * sleep.c - Elbrus-specific ACPI sleep support.
 *
 *  Copyright (C) 2001-2003 Patrick Mochel
 *  Copyright (C) 2001-2003 Pavel Machek <pavel@suse.cz>
 *  Copyright (C) 2012 Evgeny Kravtsunov <kravtsunov_e@mcst.ru>
 */

#include <linux/acpi.h>

unsigned long acpi_wakeup_address;
unsigned long acpi_realmode_flags;

/**
 * acpi_save_state_mem - save kernel state
 */
int acpi_save_state_mem(void)
{
	return 0;
}

/*
 * acpi_restore_state - undo effects of acpi_save_state_mem
 */
void acpi_restore_state_mem(void)
{
}

static int __init acpi_sleep_setup(char *str)
{
	while ((str != NULL) && (*str != '\0')) {
		if (strncmp(str, "s3_bios", 7) == 0)
			acpi_realmode_flags |= 1;
		if (strncmp(str, "s3_mode", 7) == 0)
			acpi_realmode_flags |= 2;
		if (strncmp(str, "s3_beep", 7) == 0)
			acpi_realmode_flags |= 4;
#ifdef CONFIG_HIBERNATION
		if (strncmp(str, "s4_nohwsig", 10) == 0)
			acpi_no_s4_hw_signature();
		if (strncmp(str, "s4_nonvs", 8) == 0)
			acpi_s4_no_nvs();
#endif
		if (strncmp(str, "old_ordering", 12) == 0)
			acpi_old_suspend_ordering();
		str = strchr(str, ',');
		if (str != NULL)
			str += strspn(str, ", \t");
	}
	return 1;
}

__setup("acpi_sleep=", acpi_sleep_setup);

/*
 * do_suspend_lowlevel()
 */
void do_suspend_lowlevel(void)
{
	return;
}
