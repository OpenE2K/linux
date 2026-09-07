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
	VCMDREG(HWIF_VCMD_HW_ID,                           0, 0xffff0000,       16,        0, RO, "ID of HW ASIIC(CB)"),
	VCMDREG(HWIF_VCMD_HW_VERSION,                      0, 0x0000ffff,        0,        0, RO, "Version of HW (1.5.3) [15:12]-Major [11:8]-Minor [7:0]-Build"),
	VCMDREG(HWIF_VCMD_HW_BUILDDATE,                    4, 0xffffffff,        0,        0, RO, "HW package generation date in BCD code;For example 0x20210803"),
	VCMDREG(HWIF_VCMD_EXT_ABN_INTR_SRC,                8, 0xffff0000,       16,        0, RO, "The abnormal (not wait by STALL) interrupts source from IPs to CPU."),
	VCMDREG(HWIF_VCMD_EXT_NORM_INTR_SRC,               8, 0x0000ffff,        0,        0, RO, "Extenal normal interrupt source from other Ips"),
	VCMDREG(HWIF_VCMD_EXE_CMDBUF_COUNT,               12, 0xffffffff,        0,        0, RW, "HW increases this counter by 1 after one more command buffer was excuted (executed JMP or END command) in normal mode. This counter should loop back to 0 after overflow from 32'hFFFFFFFF."),
	VCMDREG(HWIF_VCMD_CMD_EXE,                        16, 0xffffffff,        0,        0, RO, "The 1st 32bits of the command which is executing currently"),
	VCMDREG(HWIF_VCMD_CMD_EXE_MSB,                    20, 0xffffffff,        0,        0, RO, "The 2nd 32bits of the command which is executing currently"),
	VCMDREG(HWIF_VCMD_AXI_TOTALARLEN,                 24, 0xffffffff,        0,        0, RO, "AXI debug reset to 0 when sw_start_trigger=0->1"),
	VCMDREG(HWIF_VCMD_AXI_TOTALR,                     28, 0xffffffff,        0,        0, RO, "AXI debug reset to 0 when sw_start_trigger=0->1"),
	VCMDREG(HWIF_VCMD_AXI_TOTALAR,                    32, 0xffffffff,        0,        0, RO, "AXI debug reset to 0 when sw_start_trigger=0->1"),
	VCMDREG(HWIF_VCMD_AXI_TOTALRLAST,                 36, 0xffffffff,        0,        0, RO, "AXI debug reset to 0 when sw_start_trigger=0->1"),
	VCMDREG(HWIF_VCMD_AXI_TOTALAWLEN,                 40, 0xffffffff,        0,        0, RO, "AXI debug reset to 0 when sw_start_trigger=0->1"),
	VCMDREG(HWIF_VCMD_AXI_TOTALW,                     44, 0xffffffff,        0,        0, RO, "AXI debug reset to 0 when sw_start_trigger=0->1"),
	VCMDREG(HWIF_VCMD_AXI_TOTALAW,                    48, 0xffffffff,        0,        0, RO, "AXI debug reset to 0 when sw_start_trigger=0->1"),
	VCMDREG(HWIF_VCMD_AXI_TOTALWLAST,                 52, 0xffffffff,        0,        0, RO, "AXI debug reset to 0 when sw_start_trigger=0->1"),
	VCMDREG(HWIF_VCMD_AXI_TOTALB,                     56, 0xffffffff,        0,        0, RO, "AXI debug reset to 0 when sw_start_trigger=0->1"),
	VCMDREG(HWIF_VCMD_AXI_ARVALID,                    60, 0x80000000,       31,        0, RO, "AXI bus debug"),
	VCMDREG(HWIF_VCMD_AXI_ARREADY,                    60, 0x40000000,       30,        0, RO, "AXI bus debug"),
	VCMDREG(HWIF_VCMD_AXI_RVALID,                     60, 0x20000000,       29,        0, RO, "AXI bus debug"),
	VCMDREG(HWIF_VCMD_AXI_RREADY,                     60, 0x10000000,       28,        0, RO, "AXI bus debug"),
	VCMDREG(HWIF_VCMD_AXI_AWVALID,                    60, 0x08000000,       27,        0, RO, "AXI bus debug"),
	VCMDREG(HWIF_VCMD_AXI_AWREADY,                    60, 0x04000000,       26,        0, RO, "AXI bus debug"),
	VCMDREG(HWIF_VCMD_AXI_WVALID,                     60, 0x02000000,       25,        0, RO, "AXI bus debug"),
	VCMDREG(HWIF_VCMD_AXI_WREADY,                     60, 0x01000000,       24,        0, RO, "AXI bus debug"),
	VCMDREG(HWIF_VCMD_AXI_BVALID,                     60, 0x00800000,       23,        0, RO, "AXI bus debug"),
	VCMDREG(HWIF_VCMD_AXI_BREADY,                     60, 0x00400000,       22,        0, RO, "AXI bus debug"),
	VCMDREG(HWIF_VCMD_HW_APBARBITER,                  60, 0x00000400,       10,        0, RO, "Current HW support APB arbiter mode or not. 0-not support 1-supported"),
	VCMDREG(HWIF_VCMD_HW_INITMODE,                    60, 0x00000200,        9,        0, RO, "Current HW support init_mode or not. 0-not support 1-supported"),
	VCMDREG(HWIF_VCMD_CORE_STATE,                     60, 0x000001f0,        4,        0, RO, "HW core state machine. 0-ILDE 1-DECODE 2-WREG 3-END 4-NOP 5-RREG 7-JMP 8-STALL 9-CLRINT 10-ABORT 11-ERROR"),
	VCMDREG(HWIF_VCMD_INIT_MODE,                      60, 0x00000008,        3,        0, RO, "Current mode is init mode or normal mode. 0-normal mode 1-init mode"),
	VCMDREG(HWIF_VCMD_WORK_STATE,                     60, 0x00000007,        0,        0, RO, "HW work state. 0-IDLE 1-WORK 2-STALL 3-PEND 4-ABORT"),
	VCMDREG(HWIF_VCMD_ARB_CHECK_EN,                   64, 0x00000100,        8,        0, RW, "Enable/disable the Arb Checker (checking on arbitration status) when SW directly access VPU core swreg."),
	VCMDREG(HWIF_VCMD_INIT_ENABLE,                    64, 0x00000080,        7,        0, RW, "Execute init commands (sw_init_cmd*)or not when sw_start_trigger=0->1. After executed a END command in init mode VCMD will get back to normal mode which fetch and execute commands from DDR (sw_cmdbuf_exe_addr)"),
	VCMDREG(HWIF_VCMD_AXI_CLK_GATE_DISABLE,           64, 0x00000040,        6,        0, RW, "Keep axi_clk always on when this bit is set to 1"),
	VCMDREG(HWIF_VCMD_MASTER_OUT_CLK_GATE_DISABLE,    64, 0x00000020,        5,        0, RW, "Keep master_out_clk (APB/AHB master) always on when this bit is set to 1"),
	VCMDREG(HWIF_VCMD_CORE_CLK_GATE_DISABLE,          64, 0x00000010,        4,        0, RW, "Keep core_clk always on when this bit is set to 1"),
	VCMDREG(HWIF_VCMD_ABORT_MODE,                     64, 0x00000008,        3,        0, RW, "Stop on current command or JMP/END command for abort operation (SW write 0 to sw_start_trigger)."),
	VCMDREG(HWIF_VCMD_RESET_CORE,                     64, 0x00000004,        2,        0, RW, "SW write 1 to this bit will reset HW core logic when AXI/APB bus is idle. HW will clear this bit to 0 when reset is done. SW can try triger this bit when met sw_irq_timeout. if the issue can't be fixed trigger sw_reset_all can be considered. "),
	VCMDREG(HWIF_VCMD_RESET_ALL,                      64, 0x00000002,        1,        0, RW, "SW write 1 to this bit will reset HW immediately include all swregs and AXI/APB bus logic. HW will clear this bit to 0 when reset is done. It may cause AXI bus hang if there are trasctions on AXI bus. So please don't use it unless AXI bus hang or crash."),
	VCMDREG(HWIF_VCMD_START_TRIGGER,                  64, 0x00000001,        0,        0, RW, "SW write 1 to this bit will trigger HW to fetch and execute commands start from sw_cmdbuf_exe_addr in norml mode or execute init commands (sw_init_cmd*) if in init mode."),
	VCMDREG(HWIF_VCMD_IRQ_ARBRST,                     68, 0x00000080,        7,        0, RW, "Interrupt source which is triggered by external VCARB executes a reset operation (ARB_RE==1). Write 1 to clear this bit."),
	VCMDREG(HWIF_VCMD_IRQ_JMP,                        68, 0x00000040,        6,        0, RW, "Interrupt source which is triggered by JMP command. Write 1 to clear this bit."),
	VCMDREG(HWIF_VCMD_IRQ_ARBERR,                     68, 0x00000020,        5,        0, RW, "Interrupt source which is triggered by a blocked VPU swreg access when sw_arb_check_en is 1. Write 1 to clear this bit."),
	VCMDREG(HWIF_VCMD_IRQ_ABORT,                      68, 0x00000010,        4,        0, RW, "interrupt source which is triggered by sucessful abort operation. Write 1 to clear this bit."),
	VCMDREG(HWIF_VCMD_IRQ_CMDERR,                     68, 0x00000008,        3,        0, RW, "interrupt source which is triggered by any illegal command. Write 1 to clear this bit."),
	VCMDREG(HWIF_VCMD_IRQ_TIMEOUT,                    68, 0x00000004,        2,        0, RW, "interrupt source which is triggered by timeout. Write 1 to clear this bit."),
	VCMDREG(HWIF_VCMD_IRQ_BUSERR,                     68, 0x00000002,        1,        0, RW, "interrupt source which is triggered by ERROR response from AXI bus. Write 1 to clear this bit."),
	VCMDREG(HWIF_VCMD_IRQ_ENDCMD,                     68, 0x00000001,        0,        0, RW, "interrupt source which is triggered by END command.Write 1 to clear this bit."),
	VCMDREG(HWIF_VCMD_IRQ_ARBRST_EN,                  72, 0x00000080,        7,        0, RW, "interrupt enable for sw_irq_arbrst;Turning off this switch only prevents interrupts from being sent to the CPU but won't impact the interrupt source generation"),
	VCMDREG(HWIF_VCMD_IRQ_JMP_EN,                     72, 0x00000040,        6,        0, RW, "interrupt enable for sw_irq_jmp;Turning off this switch only prevents interrupts from being sent to the CPU but won't impact the interrupt source generation"),
	VCMDREG(HWIF_VCMD_IRQ_ARBERR_EN,                  72, 0x00000020,        5,        0, RW, "interrupt enable for sw_irq_arberr;Turning off this switch only prevents interrupts from being sent to the CPU but won't impact the interrupt source generation"),
	VCMDREG(HWIF_VCMD_IRQ_ABORT_EN,                   72, 0x00000010,        4,        0, RW, "interrupt enable for sw_irq_abort;Turning off this switch only prevents interrupts from being sent to the CPU but won't impact the interrupt source generation"),
	VCMDREG(HWIF_VCMD_IRQ_CMDERR_EN,                  72, 0x00000008,        3,        0, RW, "interrupt enable for sw_irq_cmderr;Turning off this switch only prevents interrupts from being sent to the CPU but won't impact the interrupt source generation"),
	VCMDREG(HWIF_VCMD_IRQ_TIMEOUT_EN,                 72, 0x00000004,        2,        0, RW, "interrupt enable for sw_irq_timeout;Turning off this switch only prevents interrupts from being sent to the CPU but won't impact the interrupt source generation"),
	VCMDREG(HWIF_VCMD_IRQ_BUSERR_EN,                  72, 0x00000002,        1,        0, RW, "interrupt enable for sw_irq_buserr;Turning off this switch only prevents interrupts from being sent to the CPU but won't impact the interrupt source generation"),
	VCMDREG(HWIF_VCMD_IRQ_ENDCMD_EN,                  72, 0x00000001,        0,        0, RW, "interrupt enable for sw_irq_endcmd;Turning off this switch only prevents interrupts from being sent to the CPU but won't impact the interrupt source generation"),
	VCMDREG(HWIF_VCMD_TIMEOUT_ENABLE,                 76, 0x80000000,       31,        0, RW, "Enable bit for timeout function; Set this bit to 0 will disable the sw_irq_timeout generation"),
	VCMDREG(HWIF_VCMD_TIMEOUT_CYCLES,                 76, 0x7fffffff,        0,        0, RW, "sw_irq_timeout will be generated when timeout counter equal to this value and sw_timeout_enable==1; timeout counter is only increased when both AXI and APB bus are idle"),
	VCMDREG(HWIF_VCMD_CMDBUF_EXE_ADDR,                80, 0xffffffff,        0,        0, RW, "The low 32 bits address of start command buffer. The low 6 bits (sw_cmdbuf_exe_addr[5:0]) is always 0 since command buffer should be aligned to 64 bytes.This address can't be changed by SW after HW has been started. HW will update it to the DDR address of which command is executing currently"),
	VCMDREG(HWIF_VCMD_CMDBUF_EXE_ADDR_MSB,            84, 0xffffffff,        0,        0, RW, "The high 32 bits address of start command buffer. This address can't be changed by SW after HW has been started. HW will update it to the DDR address of which command is executing currently"),
	VCMDREG(HWIF_VCMD_CMDBUF_EXE_LENGTH,              88, 0x0000ffff,        0,        0, RW, "The length of current command buffer in unit of 64bits. This length can't be changed by SW after HW has been started. HW will update it to the remaining length of current command buffer when executing. The NextCmdBufLength in JMP command will be loaded into here after JMP command has been executed"),
	VCMDREG(HWIF_VCMD_CMD_SWAP,                       92, 0xf0000000,       28,        0, RW, "AXI endian swap for read CMDBUF."),
	VCMDREG(HWIF_VCMD_DATA_SWAP,                      92, 0x0f000000,       24,        0, RW, "AXI endian swap for DDR read or write through M2M RREG commands"),
	VCMDREG(HWIF_VCMD_MAX_BURST_LEN,                  92, 0x00ff0000,       16,        0, RW, "Max burst length which will be sent to AXI bus;"),
	VCMDREG(HWIF_VCMD_AXI_ID_RD,                      92, 0x0000ff00,        8,        0, RW, "The ARID which will be used on AXI bus reading"),
	VCMDREG(HWIF_VCMD_AXI_ID_WR,                      92, 0x000000ff,        0,        0, RW, "The AWID/WID which will be used on AXI bus writing"),
	VCMDREG(HWIF_VCMD_RDY_CMDBUF_COUNT,               96, 0xffffffff,        0,        0, RW, "SW increases this counter by 1 after one more command buffer was linked into current command buffer queue. This counter should loop back to 0 after overflow from 32'hFFFFFFFF."),
	VCMDREG(HWIF_VCMD_EXT_ABN_INTR_GATE,             100, 0xffff0000,       16,        0, RW, "gate the abnormal (not wait by STALL) interrupts from IPs to CPU."),
	VCMDREG(HWIF_VCMD_EXT_NORM_INTR_GATE,            100, 0x0000ffff,        0,        0, RW, "gate the normal interrupts from IPs to CPU."),
	VCMDREG(HWIF_VCMD_CMDBUF_EXE_ID,                 104, 0xffffffff,        0,        0, RW, "The ID of current command buffer. This ID can't be changed by SW after HW has been started. The NextCmdBufId in JMP command will be loaded into here after JMP command has been executed"),
	VCMDREG(HWIF_VCMD_SRAM_TIMING_CTRL,              108, 0xffffffff,        0,        0, RW, "Global SRAM timing control; the detail bit field spec is decided by customer when they're doing SRAM replacment to this IP"),
	VCMDREG(HWIF_VCMD_ARB_WEIGHT,                    112, 0x001f0000,       16,        0, RW, "This registers is not used to control VCMD but the corresponding master port of VCARB which connected to current VCMD."),
	VCMDREG(HWIF_VCMD_ARB_BW_OVERFLOW,               112, 0x00000400,       10,        0, RW, "This register is not used to control VCMD but the corresponding master port of VCARB which connected to current VCMD."),
	VCMDREG(HWIF_VCMD_ARB_URGENT,                    112, 0x00000200,        9,        0, RW, "This register is not used to control VCMD but the corresponding master port of VCARB which connected to current VCMD."),
	VCMDREG(HWIF_VCMD_ARB_ENABLE,                    112, 0x00000100,        8,        0, RW, "This register is not used to control VCMD but the corresponding master port of VCARB which connected to current VCMD."),
	VCMDREG(HWIF_VCMD_ARB_TIME_WINDOW_EXP,           112, 0x0000001f,        0,        0, RW, "This register is not used to control VCMD but the external VCARB and it's effective only when current VCMD is VCMD0 for VCARB"),
	VCMDREG(HWIF_VCMD_ARB_WINER_ID,                  116, 0x00ff0000,       16,        0, RO, "For VCARB debug; The arbitration ID of the VCMD under service by VCARB"),
	VCMDREG(HWIF_VCMD_ARB_CUR_ID,                    116, 0x0000ff00,        8,        0, RO, "For VCARB debug; The arbitration ID of this VCMD"),
	VCMDREG(HWIF_VCMD_ARB_GRP_INFO,                  116, 0x000000c0,        6,        0, RO, "For VCARB debug; The group info of this VCMD in VCARB"),
	VCMDREG(HWIF_VCMD_ARB_STATE,                     116, 0x00000030,        4,        0, RO, "For VCARB debug; The FSM of VCARB"),
	VCMDREG(HWIF_VCMD_ARB_RST,                       116, 0x00000008,        3,        0, RW, "When VCARB hang write 1 to this bit will send reset request to external VCARB through ARB_RST and this bit will be automatically cleared to 0 in next cycle."),
	VCMDREG(HWIF_VCMD_ARB_ACK,                       116, 0x00000004,        2,        0, RO, "This register is used to read the approve status from external VCARB through ARB_ACK."),
	VCMDREG(HWIF_VCMD_ARB_FE,                        116, 0x00000002,        1,        0, RW, "Write 1 to this bit will manually send frame end pulse to external VCARB through ARB_FE and this bit will be automatically cleared to 0 in next cycle. The pulse of ARB_FE could clear sw_arb_req to 0."),
	VCMDREG(HWIF_VCMD_ARB_REQ,                       116, 0x00000001,        0,        0, RW, "Write 1 to this bit will manually send arbitration request to external VCARB through ARB_REQ. This bit can be cleared to 0 when VCMD core drive ARB_FE to 1 or SW write 1 to sw_arb_fe."),
	VCMDREG(HWIF_VCMD_ARB_SATISFACTION,              120, 0xffffffff,        0,        0, RO, "For VCARB debug; The satisfaction value of this VCMD in VCARB"),
