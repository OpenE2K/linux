/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/mtd/spi-nor.h>

#include "core.h"

static const struct flash_info zetta_parts[] = {
	/* Zetta */
	{ "z25lq128", INFO(0xba4218, 0, 64 * 1024,  256,
			   SECT_4K | SPI_NOR_DUAL_READ) },
};

static void zetta_default_init(struct spi_nor *nor)
{
	nor->params->quad_enable = NULL;
}

static const struct spi_nor_fixups zetta_fixups = {
	.default_init = zetta_default_init,
};

const struct spi_nor_manufacturer spi_nor_zetta = {
	.name = "zetta",
	.parts = zetta_parts,
	.nparts = ARRAY_SIZE(zetta_parts),
	.fixups = &zetta_fixups,
};
