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

#include "subsys.h"

/* subsystem configuration */
#include "subsys_cfg.h"
//extern u32 total_vcmd_core_num;
//extern unsigned long multicorebase[];
//extern int irq[];
//extern unsigned int iosize[];
//extern int reg_count[];
extern unsigned long gBaseHdwr;


/*
 * Convert subsys_array & core_array to subsys_config array
 */
void CheckSubsysCoreArray(struct subsys_config *subsys, int *subsys_num, int *vcmd)
{
	int num = ARRAY_SIZE(subsys_array);
	int i, j, index = 0;

	memset(subsys, 0, sizeof(subsys[0]) * MAX_SUBSYS_NUM);
	for (i = 0; i < MAX_SUBSYS_NUM; i++) {
		index = (i < num) ? subsys_array[i].index : i;
		subsys[index].base_addr = (i < num) ? subsys_array[i].base + gBaseHdwr : 0;
		subsys[i].irq = -1;
		for (j = 0; j < HW_CORE_MAX; j++) {
			subsys[index].submodule_offset[j] = 0xffff;
			subsys[index].submodule_iosize[j] = 0;
			subsys[index].submodule_hwregs[j] = NULL;
		}
	}

	for (i = 0; i < ARRAY_SIZE(core_array); i++) {
		if (!subsys[core_array[i].subsys].base_addr) {
			/* undefined subsystem */
			continue;
		}
		if (core_array[i].core_type == HW_VCDJ)
			core_array[i].core_type = HW_VCD;
		subsys[core_array[i].subsys].submodule_offset[core_array[i].core_type] =
			core_array[i].offset;
		subsys[core_array[i].subsys].submodule_iosize[core_array[i].core_type] =
			core_array[i].iosize;
		if (subsys[core_array[i].subsys].irq != -1 &&
		    core_array[i].irq != -1) {
			if (subsys[core_array[i].subsys].irq !=
			    core_array[i].irq) {
				pr_info(DRIVER_NAME ": hw core type %d irq %d != subsystem irq %d\n",
					core_array[i].core_type,
				       core_array[i].irq,
				       subsys[core_array[i].subsys].irq);
				pr_info(DRIVER_NAME ": hw cores of a subsystem should have same irq\n");
			}
		} else if (core_array[i].irq != -1) {
			subsys[core_array[i].subsys].irq = core_array[i].irq;
		}
		subsys[core_array[i].subsys].has_apbfilter[core_array[i].core_type] =
			core_array[i].has_apb;
		/* vcmd found */
		if (core_array[i].core_type == HW_VCMD)
			*vcmd = 1;
		else if (core_array[i].core_type == HW_VCD)
			subsys[core_array[i].subsys].subsys_type = DECODER_TYPE; /* vcd */
	}

	pr_info(DRIVER_NAME ": vcmd found = %d\n", *vcmd);

	*subsys_num = num;
}
