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

/* Register interface based on the document version v1.5.3 */
	HWIF_VCMD_HW_ID,
	HWIF_VCMD_HW_VERSION,
	HWIF_VCMD_HW_BUILDDATE,
	HWIF_VCMD_EXT_ABN_INTR_SRC,
	HWIF_VCMD_EXT_NORM_INTR_SRC,
	HWIF_VCMD_EXE_CMDBUF_COUNT,
	HWIF_VCMD_CMD_EXE,
	HWIF_VCMD_CMD_EXE_MSB,
	HWIF_VCMD_AXI_TOTALARLEN,
	HWIF_VCMD_AXI_TOTALR,
	HWIF_VCMD_AXI_TOTALAR,
	HWIF_VCMD_AXI_TOTALRLAST,
	HWIF_VCMD_AXI_TOTALAWLEN,
	HWIF_VCMD_AXI_TOTALW,
	HWIF_VCMD_AXI_TOTALAW,
	HWIF_VCMD_AXI_TOTALWLAST,
	HWIF_VCMD_AXI_TOTALB,
	HWIF_VCMD_AXI_ARVALID,
	HWIF_VCMD_AXI_ARREADY,
	HWIF_VCMD_AXI_RVALID,
	HWIF_VCMD_AXI_RREADY,
	HWIF_VCMD_AXI_AWVALID,
	HWIF_VCMD_AXI_AWREADY,
	HWIF_VCMD_AXI_WVALID,
	HWIF_VCMD_AXI_WREADY,
	HWIF_VCMD_AXI_BVALID,
	HWIF_VCMD_AXI_BREADY,
	HWIF_VCMD_HW_APBARBITER,
	HWIF_VCMD_HW_INITMODE,
	HWIF_VCMD_CORE_STATE,
	HWIF_VCMD_INIT_MODE,
	HWIF_VCMD_WORK_STATE,
	HWIF_VCMD_ARB_CHECK_EN,
	HWIF_VCMD_INIT_ENABLE,
	HWIF_VCMD_AXI_CLK_GATE_DISABLE,
	HWIF_VCMD_MASTER_OUT_CLK_GATE_DISABLE,
	HWIF_VCMD_CORE_CLK_GATE_DISABLE,
	HWIF_VCMD_ABORT_MODE,
	HWIF_VCMD_RESET_CORE,
	HWIF_VCMD_RESET_ALL,
	HWIF_VCMD_START_TRIGGER,
	HWIF_VCMD_IRQ_ARBRST,
	HWIF_VCMD_IRQ_JMP,
	HWIF_VCMD_IRQ_ARBERR,
	HWIF_VCMD_IRQ_ABORT,
	HWIF_VCMD_IRQ_CMDERR,
	HWIF_VCMD_IRQ_TIMEOUT,
	HWIF_VCMD_IRQ_BUSERR,
	HWIF_VCMD_IRQ_ENDCMD,
	HWIF_VCMD_IRQ_ARBRST_EN,
	HWIF_VCMD_IRQ_JMP_EN,
	HWIF_VCMD_IRQ_ARBERR_EN,
	HWIF_VCMD_IRQ_ABORT_EN,
	HWIF_VCMD_IRQ_CMDERR_EN,
	HWIF_VCMD_IRQ_TIMEOUT_EN,
	HWIF_VCMD_IRQ_BUSERR_EN,
	HWIF_VCMD_IRQ_ENDCMD_EN,
	HWIF_VCMD_TIMEOUT_ENABLE,
	HWIF_VCMD_TIMEOUT_CYCLES,
	HWIF_VCMD_CMDBUF_EXE_ADDR,
	HWIF_VCMD_CMDBUF_EXE_ADDR_MSB,
	HWIF_VCMD_CMDBUF_EXE_LENGTH,
	HWIF_VCMD_CMD_SWAP,
	HWIF_VCMD_DATA_SWAP,
	HWIF_VCMD_MAX_BURST_LEN,
	HWIF_VCMD_AXI_ID_RD,
	HWIF_VCMD_AXI_ID_WR,
	HWIF_VCMD_RDY_CMDBUF_COUNT,
	HWIF_VCMD_EXT_ABN_INTR_GATE,
	HWIF_VCMD_EXT_NORM_INTR_GATE,
	HWIF_VCMD_CMDBUF_EXE_ID,
	HWIF_VCMD_SRAM_TIMING_CTRL,
	HWIF_VCMD_ARB_WEIGHT,
	HWIF_VCMD_ARB_BW_OVERFLOW,
	HWIF_VCMD_ARB_URGENT,
	HWIF_VCMD_ARB_ENABLE,
	HWIF_VCMD_ARB_TIME_WINDOW_EXP,
	HWIF_VCMD_ARB_WINER_ID,
	HWIF_VCMD_ARB_CUR_ID,
	HWIF_VCMD_ARB_GRP_INFO,
	HWIF_VCMD_ARB_STATE,
	HWIF_VCMD_ARB_RST,
	HWIF_VCMD_ARB_ACK,
	HWIF_VCMD_ARB_FE,
	HWIF_VCMD_ARB_REQ,
	HWIF_VCMD_ARB_SATISFACTION,
