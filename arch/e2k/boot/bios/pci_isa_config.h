/* 
 * Southbridge configuration.
 * PCI/ISA Bridge Configuration Registers (Function 0).
 */
#ifndef _PCI_ISA_CONFIG_H_
#define _PCI_ISA_CONFIG_H_

#include <asm/head.h>
#include <asm/mas.h>
#include <asm/e2k_api.h>

#define	PSI_ISA_CONFIG_REGS_FUNC		0

/* REG XBCS
 * X-BUS CHIP SELECT REGISTER 4E-4F default 0x3
 */
#define		SB_XBCS			0x4E	// 4E-4F
#define		SB_XBCS_io_lo		0x4E	// 4E-4F
#define		SB_XBCS_io_hi		0x4F	// 4E-4F
#define 		SB_XBCS_DEFAULT				0x0003
#define		 	SB_XBCS_RTC_ENABLE			0x0001
#define 		SB_XBCS_KBC_ENABLE			0x0002
#define 		SB_XBCS_BIOSWP_ENABLE			0x0004
#define 		SB_XBCS_PORT61ALIAS_ENABLE		0x0008
#define 		SB_XBCS_IRQ12_MOUSE_ENABLE		0x0010
#define 		SB_XBCS_COERR_ENABLE			0x0020
#define 		SB_XBCS_LOWER_BIOS_ENABLE		0x0040
#define 		SB_XBCS_EXT_BIOS_ENABLE			0x0080
#define 		SB_XBCS_IOAPIC_ENABLE			0x0100
#define 		SB_XBCS_1M_EXT_BIOS_ENABLE		0x0200
/* Micro Controller Adress Location */
#define 		SB_XBCS_MCA_LOCATION_ENABLE		0x0400

#define 		SB_XBCS_MASK				0x07FF

/* REG SERIRQC
 * SERIAL IRQ CONTROL REGISTER 64H default 0x10
 */
#define		SB_SERIRQC			0x64
/* Start Frame Pulse Width bits 1:0 */
#define			SB_SERIRQC_SFP_4CLOCK			0x00
#define			SB_SERIRQC_SFP_6CLOCK			0x01
#define			SB_SERIRQC_SFP_8CLOCK			0x02
#define			SB_SERIRQC_SFP_RESERVED			0x03
#define			SB_SERIRQC_SFP_MASK			0x03
/* Serial IRQ Frame Size bits 5:2, only 0100b supported by PIIX4 */
#define			SB_SERIRQC_FRAME_SIZE			0x10
#define			SB_SERIRQC_FRAME_MASK			0x3C
/* Serial IRQ Mode Select bit 6, 0 - quite mode 1 - continuous mode */
#define 		SB_SERIRQC_SHIFT			6
#define			SB_SERIRQC_CONT_MODE			0x40
/* Serial IRQ Enable, bit 16 in register offset B0h-B3h must also be 1 */
#define			SB_SERIRQC_IRQ_ENABLE			0x80

/* REG GENCFG
 * GENERAL CONFIGURATION REGISTER B0-B3h default 0
 */
#define		SB_GENCFG			0XB0 // B0 - B4
#define		SB_GENCFG1			0XB0
#define		SB_GENCFG2			0XB1
#define		SB_GENCFG3			0XB2
#define		SB_GENCFG4			0XB3
/* 0=EOI 1=ISA */
#define			SB_GENCFG_ISA_SELECT			0x00000001
#define			SB_GENCFG_DECODE_CONFIG			0x00000002
#define			SB_GENCFG_CONFIG_1			0x00000004
#define			SB_GENCFG_CONFIG_2			0x00000008
/* 0 - primary&secondary interface, 1 - primary0&primary1 */
#define			SB_GENCFG_IDE_INTERFACE			0x00000010
#define			SB_GENCFG_ALT_ACCESS_MODE		0x00000020
#define			SB_GENCFG_PnP_ADDR_DECODE_ENABLE	0x00000040
//#define		SB_GENCFG_RESERVED			0x00000080
#define			SB_GENCFG_SIGNAL_PIN_SELECTED8		0x00000100
#define			SB_GENCFG_SIGNAL_PIN_SELECTED9		0x00000200
#define			SB_GENCFG_SIGNAL_PIN_SELECTED10		0x00000400
#define			SB_GENCFG_PRIMARY_IDE_SigIn		0x00000800
#define			SB_GENCFG_SECONDARY_IDE_SigIn		0x00001000
//#define		SB_GENCFG_RESERVED			0x00002000
/* 14 - 31 bits Signal Pin Selected*/
#define			SB_GENCFG_SIGNAL_PIN_SELECTED14		0x00004000
#define			SB_GENCFG_SERIRQ_PIN_SELECTED		0x00010000

#endif /* _PCI_ISA_CONFIG_H_ */
