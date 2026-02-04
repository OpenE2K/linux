/*
 * Copyright (c) 2015, Verisilicon Inc. - All Rights Reserved
 *
 * This software is dual licensed, either GPL-2.0 or BSD-3-Clause, at your
 * option.
 *
 ********************************************************************************
 *
 * GPL-2.0
 *
 ********************************************************************************
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; version 2.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51 Franklin
 * Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 ********************************************************************************
 *
 * Alternatively, This software may be distributed under the terms of
 * BSD-3-Clause, in which case the following provisions apply instead of the ones
 * mentioned above :
 *
 ********************************************************************************
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors
 * may be used to endorse or promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/*
 * Table of contents
 * 1. Include header
 * 2. External compiler flags
 * 3. Module defines
 */
#ifndef VCMD_SWHWREGISTERS_H
#define VCMD_SWHWREGISTERS_H

#ifdef __cplusplus
extern "C" {
#endif

/* 1. Include headers  */
#ifndef MODEL_SIMULATION
#include <linux/ioctl.h>
#include <linux/kernel.h>
#include <linux/module.h>
#endif

#include "hantrodec.h"

#undef PDEBUG /* undef it, just in case */
#ifdef REGISTER_DEBUG
#ifdef __KERNEL__
/* This one if debugging is on, and kernel space */
#define PDEBUG(fmt, args...) pr_info(DRIVER_NAME "_vcmd: " fmt, ##args)
#else
/* This one for user space */
#define PDEBUG(fmt, args...) fprintf(stderr, fmt, ##args)
#endif
#else
#define PDEBUG(fmt, ...) /* not debugging: nothing */
#endif

/* 2. External compiler flags */

/* 3. Module defines */
#ifdef HANTROVCMD_ENABLE_IP_SUPPORT
/*only cover regular and init_cmd registers,
 * sinit related cmd should be set in secure domain (Tee world)
 */
#define VCMD_REG_ID_SW_INIT_CMD0				32
#define ASIC_VCMD_SWREG_AMOUNT					64
#else
#define ASIC_VCMD_SWREG_AMOUNT					31
#endif


//TODO: rename to VCMD_REG_ID_xxx
#define VCMD_REGISTER_SW_EXT_INT_SRC_OFFSET      0x8
#define VCMD_REGISTER_EXE_CMDBUF_COUNT_OFFSET    0x0C
#define VCMD_REGISTER_HW_APB_ARBITER_MODE_OFFSET 0x3C
#define VCMD_REGISTER_HW_INIT_MODE_OFFSET        0x3C
#define VCMD_REGISTER_CONTROL_OFFSET             0x40
#define VCMD_REGISTER_INT_STATUS_OFFSET          0x44
#define VCMD_REGISTER_INT_CTL_OFFSET             0x48
#define VCMD_REGISTER_TIMEOUT_OFFSET             0x4c
#define VCMD_REGISTER_CMDBUF_EXE_ADDR_LSB_OFFSET 0x50
#define VCMD_REGISTER_CMDBUF_EXE_ADDR_MSB_OFFSET 0x54
#define VCMD_REGISTER_CMDBUF_EXE_LEN_OFFSET      0x58
#define VCMD_REGISTER_SWAP_OFFSET                0x5c
#define VCMD_REGISTER_RDY_CMDBUF_COUNT_OFFSET    0x60
#define VCMD_REGISTER_EXT_INT_GATE_OFFSET        0x64
#define VCMD_REGISTER_ARBITER_CONFIG_OFFSET      0x70
#define VCMD_REGISTER_ARB_OFFSET                 0x74

/* for vcmd version >= v1.5.10 */
#define VCMD_REGISTER_CMDBUF_TIMEOUT_OFFSET      0x70

#define VCMD_ARBITER_WEIGHT(w) (((w) & 0x1F) << 16)
#define VCMD_ARBITER_URGENT(u) (((u) & 0x1) << 9)
#define VCMD_ARBITER_ENABLE (0x1 << 8)
#define VCMD_ARBITER_BW_OVERFLOW(o) (((o) & 0x1) << 10)
#define VCMD_ARBITER_TIME_WINDOW_EXP(t) (t)
#define VCMD_ARBITER_PARAMS(w, u, o, t)               \
							(VCMD_ARBITER_WEIGHT(w) | \
							 VCMD_ARBITER_URGENT(u) | \
							 VCMD_ARBITER_BW_OVERFLOW(o) | \
							 VCMD_ARBITER_ENABLE | \
							 VCMD_ARBITER_TIME_WINDOW_EXP(t))

#define HW_APB_ARBITER_MODE_BIT         (10)
#define HW_INIT_MODE_BIT                (9)

#define VCMD_IRQ_CMDBUF_TIMEOUT (1 << 9)
#define VCMD_IRQ_ARBITER_RESET	(1 << 7)
#define VCMD_IRQ_JMP			(1 << 6)
#define VCMD_IRQ_ARBITER_ERR	(1 << 5)
#define VCMD_IRQ_ABORT			(1 << 4)
#define VCMD_IRQ_CMD_ERR		(1 << 3)
#define VCMD_IRQ_TIMEOUT		(1 << 2)
#define VCMD_IRQ_BUS_ERR		(1 << 1)
#define VCMD_IRQ_END			(1 << 0)

#define VCMD_IRQ_ERR_MASK	(VCMD_IRQ_CMDBUF_TIMEOUT | \
							 VCMD_IRQ_ARBITER_RESET | \
							 VCMD_IRQ_ARBITER_ERR | \
							 VCMD_IRQ_ABORT | \
							 VCMD_IRQ_CMD_ERR | \
							 VCMD_IRQ_TIMEOUT | \
							 VCMD_IRQ_BUS_ERR)
/* HW Register field names */
typedef enum {
#include "vcmdregisterenum.h"
	VcmdRegisterAmount
} regVcmdName;

/* HW Register field descriptions */
typedef struct {
	u32 name; /* Register name and index  */
	int base; /* Register base address  */
	u32 mask; /* Bitmask for this field */
	int lsb; /* LSB for this field [31..0] */
	int trace; /* Enable/disable writing in swreg_params.trc */
	int rw; /* 1=Read-only 2=Write-only 3=Read-Write */
	char *description; /* Field description */
} regVcmdField_s;

/* Flags for read-only, write-only and read-write */
#define RO 1
#define WO 2
#define RW 3

#define REGBASE(reg) (asicVcmdRegisterDesc[reg].base)

/* Description field only needed for system model build. */
#ifdef TEST_DATA
#define VCMDREG(name, base, mask, lsb, trace, rw, desc) \
	{name, base, mask, lsb, trace, rw, desc}
#else
#define VCMDREG(name, base, mask, lsb, trace, rw, desc) \
	{name, base, mask, lsb, trace, rw, ""}
#endif

/* 4. Function prototypes */

extern const regVcmdField_s asicVcmdRegisterDesc[];

/*
 * EncAsicSetRegisterValue

 * Set a value into a defined register field
 */
static inline void vcmd_set_reg_mirror(u32 *reg_mirror,
						  regVcmdName name, u32 value)
{
	const regVcmdField_s *field;
	u32 regVal;

	field = &asicVcmdRegisterDesc[name];

#ifdef DEBUG_PRINT_REGS
	PDEBUG("%s, 0x%2x 0x%08x Value: %10d  %s\n", __func__,
	       field->base, field->mask, value, field->description);
#endif

	/* Check that value fits in field */
	PDEBUG("field->name == name=%d\n", field->name == name);
	PDEBUG("((field->mask >> field->lsb) << field->lsb) == field->mask=%d\n",
	       ((field->mask >> field->lsb) << field->lsb) == field->mask);
	PDEBUG("(field->mask >> field->lsb) >= value=%d\n",
	       (field->mask >> field->lsb) >= value);
	PDEBUG("field->base < ASIC_VCMD_SWREG_AMOUNT * 4=%d\n",
	       field->base < ASIC_VCMD_SWREG_AMOUNT * 4);

	/* Clear previous value of field in register */
	regVal = reg_mirror[field->base / 4] & ~(field->mask);

	/* Put new value of field in register */
	reg_mirror[field->base / 4] =
		regVal | ((value << field->lsb) & field->mask);
}

static inline u32 vcmd_get_reg_mirror(u32 *reg_mirror,
						 regVcmdName name)
{
	const regVcmdField_s *field;
	u32 regVal;

	field = &asicVcmdRegisterDesc[name];

	/* Check that value fits in field */
	PDEBUG("field->name == name=%d\n", field->name == name);
	PDEBUG("((field->mask >> field->lsb) << field->lsb) == field->mask=%d\n",
	       ((field->mask >> field->lsb) << field->lsb) == field->mask);
	PDEBUG("field->base < ASIC_VCMD_SWREG_AMOUNT * 4=%d\n",
	       field->base < ASIC_VCMD_SWREG_AMOUNT * 4);

	regVal = reg_mirror[field->base / 4];
	regVal = (regVal & field->mask) >> field->lsb;

#ifdef DEBUG_PRINT_REGS
	PDEBUG("%s 0x%2x  0x%08x  Value: %10d  %s\n", __func__,
	       field->base, field->mask, regVal, field->description);
#endif
	return regVal;
}

u32 vcmd_read_reg(const void *hwregs, u32 offset);

void vcmd_write_reg(const void *hwregs, u32 offset, u32 val);

void vcmd_write_register_value(const void *hwregs, u32 *reg_mirror,
			       regVcmdName name, u32 value);
u32 vcmd_get_register_value(const void *hwregs, u32 *reg_mirror,
			    regVcmdName name);

#define VCMDGetAddrRegisterValue(reg_base, reg_mirror, name)  \
	((sizeof(addr_t) == 8) ? \
	((((addr_t)vcmd_get_register_value((reg_base), (reg_mirror), name)) |  \
	(((addr_t)vcmd_get_register_value((reg_base), (reg_mirror), name##_MSB)) << 32))) \
	: ((addr_t)vcmd_get_register_value((reg_base), (reg_mirror), (name))))

#ifdef __cplusplus
}
#endif

#endif /* VCMD_SWHWREGISTERS_H */
