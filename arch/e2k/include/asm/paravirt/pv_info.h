/*
 * Copyright (c) 2016 MCST, Salavat Gilyazov atic@mcst.ru
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */


#ifndef __ASM_E2K_PARAVIRT_INFO_H
#define __ASM_E2K_PARAVIRT_INFO_H

#ifndef __ASSEMBLY__

#include <linux/types.h>

/*
 * general info
 */
typedef struct pv_info {
	int paravirt_enabled;
	unsigned long page_offset;
	unsigned long vmalloc_start;
	unsigned long vmalloc_end;
	unsigned long vmemmap_start;
	unsigned long vmemmap_end;
	const char *name;
} pv_info_t;

extern pv_info_t pv_info;

/*
 * general info
 */
#define	PARAVIRT_ENABLED		(pv_info.paravirt_enabled)
#define	BOOT_PARAVIRT_ENABLED		boot_get_vo_value(PARAVIRT_ENABLED)

#ifndef	CONFIG_BOOT_E2K
#define	pv_paravirt_enabled()		PARAVIRT_ENABLED
#define	boot_pv_paravirt_enabled()	BOOT_PARAVIRT_ENABLED
#else	/* CONFIG_BOOT_E2K */
#define	pv_paravirt_enabled()		false
#define	boot_pv_paravirt_enabled()	false
#endif	/* ! CONFIG_BOOT_E2K */

#define	PV_PAGE_OFFSET			(pv_info.page_offset)
#define	PV_TASK_SIZE			PV_PAGE_OFFSET
#define	PV_VMALLOC_START		(pv_info.vmalloc_start)
#define	PV_VMALLOC_END			(pv_info.vmalloc_end)
#define	PV_VMEMMAP_START		(pv_info.vmemmap_start)
#define	PV_VMEMMAP_END			(pv_info.vmemmap_end)

#define	BOOT_PV_PAGE_OFFSET		\
		boot_get_vo_value(PV_PAGE_OFFSET)
#define	BOOT_PV_TASK_SIZE		BOOT_PV_PAGE_OFFSET

#ifdef	CONFIG_PARAVIRT_GUEST

static inline int paravirt_enabled(void)
{
	return pv_paravirt_enabled();
}
#define	boot_paravirt_enabled()		boot_pv_paravirt_enabled()

#define	PAGE_OFFSET			PV_PAGE_OFFSET
#define	TASK_SIZE			PV_TASK_SIZE
#define	VMALLOC_START			PV_VMALLOC_START
#define	VMALLOC_END			PV_VMALLOC_END
#define	VMEMMAP_START			PV_VMEMMAP_START
#define	VMEMMAP_END			PV_VMEMMAP_END

#define	BOOT_PAGE_OFFSET		BOOT_PV_PAGE_OFFSET
#define	BOOT_TASK_SIZE			BOOT_PV_TASK_SIZE
#endif	/* CONFIG_PARAVIRT_GUEST */

#endif	/* ! __ASSEMBLY__ */

#endif /* __ASM_E2K_PARAVIRT_INFO_H */
