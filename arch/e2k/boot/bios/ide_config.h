/*
 * $Id: ide_config.h,v 1.1 2006/03/30 16:53:22 kostin Exp $
 * Southbridge configuration.
 * IDE Configuration Registers (Function 1)
 */

#ifndef _IDE_CONFIG_H_
#define _IDE_CONFIG_H_

#define		SB_PCICMD	0x4		// 0x4-0x5
#define 		SB_PCICMD_IOSE	0x1	// access to the Legacy IDE ports

#define 	SB_IDETIM	0x40	// 0x40-0x41=Primary Cnannel
					// 0x42-0x43=Secondary Channel
#define			SB_IDETIM_DECODE_ENABLE	0x8000
#define			SB_IDETIM_SHIFT		16

#endif
