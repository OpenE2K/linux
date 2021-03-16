#ifndef _L_IDE_H_
#define _L_IDE_H_

#include <linux/ata.h>

static void l_init_iops (ide_hwif_t *hwif)
{
}

#define	L_FORCE_NATIVE_MODE	1
#define	L_DEAULT_IDE_DMA_MODE	ATA_UDMA5	/* default max UDMA capable */

#endif /*_L_IDE_H_*/
