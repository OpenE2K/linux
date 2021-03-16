/*!
 *****************************************************************************
 *
 * @File       ltp_regs.h
 * @Title      This file contains register definitions.
 * @Description    This file contains register definitions.
 * ---------------------------------------------------------------------------
 *
 * Copyright (c) Imagination Technologies Ltd.
 * 
 * The contents of this file are subject to the MIT license as set out below.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a 
 * copy of this software and associated documentation files (the "Software"), 
 * to deal in the Software without restriction, including without limitation 
 * the rights to use, copy, modify, merge, publish, distribute, sublicense, 
 * and/or sell copies of the Software, and to permit persons to whom the 
 * Software is furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in 
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, 
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN 
 * THE SOFTWARE.
 * 
 * Alternatively, the contents of this file may be used under the terms of the 
 * GNU General Public License Version 2 ("GPL")in which case the provisions of
 * GPL are applicable instead of those above. 
 * 
 * If you wish to allow use of your version of this file only under the terms 
 * of GPL, and not to allow others to use your version of this file under the 
 * terms of the MIT license, indicate your decision by deleting the provisions 
 * above and replace them with the notice and other provisions required by GPL 
 * as set out in the file called "GPLHEADER" included in this distribution. If 
 * you do not delete the provisions above, a recipient may use your version of 
 * this file under the terms of either the MIT license or GPL.
 * 
 * This License is also included in this distribution in the file called 
 * "MIT_COPYING".
 *
 *****************************************************************************/

#ifndef _REGCONV_H_ltp_regs_h
#define _REGCONV_H_ltp_regs_h

#ifdef __cplusplus 
#include "img_types.h"
#include "systemc_utils.h"
#endif 

/*** CONTROL UNIT REGISTERS ***/

/* Register CR_LTP_ENABLE */
#define LTP_CR_LTP_ENABLE           0x0000
#define MASK_LTP_LTP_ENABLE         0x00000001
#define SHIFT_LTP_LTP_ENABLE        0
#define REGNUM_LTP_LTP_ENABLE       0x0000
#define SIGNED_LTP_LTP_ENABLE       0
#define MAX_LTP_LTP_ENABLE          1
#define MIN_LTP_LTP_ENABLE          0

#define MASK_LTP_LTP_TOFF           0x00000002
#define SHIFT_LTP_LTP_TOFF          1
#define REGNUM_LTP_LTP_TOFF         0x0000
#define SIGNED_LTP_LTP_TOFF         0
#define MAX_LTP_LTP_TOFF            1
#define MIN_LTP_LTP_TOFF            0

#define MASK_LTP_LTP_TSTOPPED       0x00000004
#define SHIFT_LTP_LTP_TSTOPPED      2
#define REGNUM_LTP_LTP_TSTOPPED     0x0000
#define SIGNED_LTP_LTP_TSTOPPED     0
#define MAX_LTP_LTP_TSTOPPED        1
#define MIN_LTP_LTP_TSTOPPED        0

#define MASK_LTP_LTP_STEP_REC       0x000000F0
#define SHIFT_LTP_LTP_STEP_REC      4
#define REGNUM_LTP_LTP_STEP_REC     0x0000
#define SIGNED_LTP_LTP_STEP_REC     0
#define MAX_LTP_LTP_STEP_REC        15
#define MIN_LTP_LTP_STEP_REC        0

#define MASK_LTP_LTP_THREAD_ID           0x00000300
#define SHIFT_LTP_LTP_THREAD_ID          8
#define REGNUM_LTP_LTP_THREAD_ID         0x0000
#define SIGNED_LTP_LTP_THREAD_ID         0
#define MAX_LTP_LTP_THREAD_ID            3
#define MIN_LTP_LTP_THREAD_ID            0

#define MASK_LTP_LTP_TCAPS          0x0000F000
#define SHIFT_LTP_LTP_TCAPS         12
#define REGNUM_LTP_LTP_TCAPS        0x0000
#define SIGNED_LTP_LTP_TCAPS        0
#define MAX_LTP_LTP_TCAPS           255
#define MIN_LTP_LTP_TCAPS           0

#define MASK_LTP_LTP_MIN_REV        0x00FF0000
#define SHIFT_LTP_LTP_MIN_REV       16
#define REGNUM_LTP_LTP_MIN_REV      0x0000
#define SIGNED_LTP_LTP_MIN_REV      0
#define MAX_LTP_LTP_MIN_REV         255
#define MIN_LTP_LTP_MIN_REV         0

#define MASK_LTP_LTP_MAJ_REV        0xFF000000
#define SHIFT_LTP_LTP_MAJ_REV       24
#define REGNUM_LTP_LTP_MAJ_REV      0x0000
#define SIGNED_LTP_LTP_MAJ_REV      0
#define MAX_LTP_LTP_MAJ_REV         255
#define MIN_LTP_LTP_MAJ_REV         0

/* Register CR_LTP_STATUS */
#define LTP_CR_LTP_STATUS           0x0010
#define MASK_LTP_LTP_CF_C           0x00000001
#define SHIFT_LTP_LTP_CF_C          0
#define REGNUM_LTP_LTP_CF_C         0x0010
#define SIGNED_LTP_LTP_CF_C         0
#define MAX_LTP_LTP_CF_C            1
#define MIN_LTP_LTP_CF_C            0

#define MASK_LTP_LTP_CR_V           0x00000002
#define SHIFT_LTP_LTP_CR_V          1
#define REGNUM_LTP_LTP_CR_V         0x0010
#define SIGNED_LTP_LTP_CR_V         0
#define MAX_LTP_LTP_CR_V            1
#define MIN_LTP_LTP_CR_V            0

#define MASK_LTP_LTP_CF_N           0x00000004
#define SHIFT_LTP_LTP_CF_N          2
#define REGNUM_LTP_LTP_CF_N         0x0010
#define SIGNED_LTP_LTP_CF_N         0
#define MAX_LTP_LTP_CF_N            1
#define MIN_LTP_LTP_CF_N            0

#define MASK_LTP_LTP_CF_Z           0x00000008
#define SHIFT_LTP_LTP_CF_Z          3
#define REGNUM_LTP_LTP_CF_Z         0x0010
#define SIGNED_LTP_LTP_CF_Z         0
#define MAX_LTP_LTP_CF_Z            1
#define MIN_LTP_LTP_CF_Z            0

#define MASK_LTP_LTP_SCC           0x00000010
#define SHIFT_LTP_LTP_SCC          4
#define REGNUM_LTP_LTP_SCC         0x0010
#define SIGNED_LTP_LTP_SCC         0
#define MAX_LTP_LTP_SCC            1
#define MIN_LTP_LTP_SCC            0

#define MASK_LTP_LTP_LNK_OK           0x00000020
#define SHIFT_LTP_LTP_LNK_OK          5
#define REGNUM_LTP_LTP_LNK_OK         0x0010
#define SIGNED_LTP_LTP_LNK_OK         0
#define MAX_LTP_LTP_LNK_OK            1
#define MIN_LTP_LTP_LNK_OK            0

#define MASK_LTP_LTP_LSM_STEP       0x00000700
#define SHIFT_LTP_LTP_LSM_STEP      8
#define REGNUM_LTP_LTP_LSM_STEP     0x0010
#define SIGNED_LTP_LTP_LSM_STEP     0
#define MAX_LTP_LTP_LSM_STEP        7
#define MIN_LTP_LTP_LSM_STEP        0

#define MASK_LTP_LTP_L_STEP       0x00000800
#define SHIFT_LTP_LTP_L_STEP      11
#define REGNUM_LTP_LTP_L_STEP     0x0010
#define SIGNED_LTP_LTP_L_STEP     0
#define MAX_LTP_LTP_L_STEP        1
#define MIN_LTP_LTP_L_STEP        0

#define MASK_LTP_LTP_IRQ_STAT       0x0000F000
#define SHIFT_LTP_LTP_IRQ_STAT      12
#define REGNUM_LTP_LTP_IRQ_STAT     0x0010
#define SIGNED_LTP_LTP_IRQ_STAT     0
#define MAX_LTP_LTP_IRQ_STAT        255
#define MIN_LTP_LTP_IRQ_STAT        0

#define MASK_LTP_LTP_ISTAT       0x00010000
#define SHIFT_LTP_LTP_ISTAT      16
#define REGNUM_LTP_LTP_ISTAT     0x0010
#define SIGNED_LTP_LTP_ISTAT     0
#define MAX_LTP_LTP_ISTAT        1
#define MIN_LTP_LTP_ISTAT        0

#define MASK_LTP_LTP_PSTAT       0x00020000
#define SHIFT_LTP_LTP_PSTAT      17
#define REGNUM_LTP_LTP_PSTAT     0x0010
#define SIGNED_LTP_LTP_PSTAT     0
#define MAX_LTP_LTP_PSTAT        1
#define MIN_LTP_LTP_PSTAT        0

#define MASK_LTP_LTP_HREASON        0x000C0000
#define SHIFT_LTP_LTP_HREASON       18
#define REGNUM_LTP_LTP_HREASON      0x0010
#define SIGNED_LTP_LTP_HREASON      0
#define MAX_LTP_LTP_HREASON         3
#define MIN_LTP_LTP_HREASON         0

#define MASK_LTP_LTP_FREASON        0x00300000
#define SHIFT_LTP_LTP_FREASON       20
#define REGNUM_LTP_LTP_FREASON      0x0010
#define SIGNED_LTP_LTP_FREASON      0
#define MAX_LTP_LTP_FREASON         3
#define MIN_LTP_LTP_FREASON         0

#define MASK_LTP_LTP_CBMARK        0x00400000
#define SHIFT_LTP_LTP_CBMARK       22
#define REGNUM_LTP_LTP_CBMARK      0x0010
#define SIGNED_LTP_LTP_CBMARK      0
#define MAX_LTP_LTP_CBMARK         1
#define MIN_LTP_LTP_CBMARK         0

#define MASK_LTP_LTP_CBMARK1        0x00800000
#define SHIFT_LTP_LTP_CBMARK1       23
#define REGNUM_LTP_LTP_CBMARK1      0x0010
#define SIGNED_LTP_LTP_CBMARK1      0
#define MAX_LTP_LTP_CBMARK1         1
#define MIN_LTP_LTP_CBMARK1         0

#define MASK_LTP_LTP_FPACTIVE        0x010000000
#define SHIFT_LTP_LTP_FPACTIVE       24
#define REGNUM_LTP_LTP_FPACTIVE      0x0010
#define SIGNED_LTP_LTP_FPACTIVE      0
#define MAX_LTP_LTP_FPACTIVE         1
#define MIN_LTP_LTP_FPACTIVE         0

#define MASK_LTP_LTP_IRPCOUNT        0x0E0000000
#define SHIFT_LTP_LTP_IRPCOUNT       25
#define REGNUM_LTP_LTP_IRPCOUNT      0x0010
#define SIGNED_LTP_LTP_IRPCOUNT      0
#define MAX_LTP_LTP_IRPCOUNT         7
#define MIN_LTP_LTP_IRPCOUNT         0

#define MASK_LTP_LTP_IEXCEPT        0x100000000
#define SHIFT_LTP_LTP_IEXCEPT       28
#define REGNUM_LTP_LTP_IEXCEPT      0x0010
#define SIGNED_LTP_LTP_IEXCEPT      0
#define MAX_LTP_LTP_IEXCEPT         1
#define MIN_LTP_LTP_IEXCEPT         0

#define MASK_LTP_LTP_IWAIT        0x200000000
#define SHIFT_LTP_LTP_IWAIT       29
#define REGNUM_LTP_LTP_IWAIT      0x0010
#define SIGNED_LTP_LTP_IWAIT      0
#define MAX_LTP_LTP_IWAIT         1
#define MIN_LTP_LTP_IWAIT         0

#define MASK_LTP_LTP_ISTATE        0x100000000
#define SHIFT_LTP_LTP_ISTATE       30
#define REGNUM_LTP_LTP_ISTATE      0x0010
#define SIGNED_LTP_LTP_ISTATE      0
#define MAX_LTP_LTP_ISTATE         1
#define MIN_LTP_LTP_ISTATE         0

#define MASK_LTP_LTP_IPTOOGLE        0x100000000
#define SHIFT_LTP_LTP_IPTOOGLE       31
#define REGNUM_LTP_LTP_IPTOOGLE      0x0010
#define SIGNED_LTP_LTP_IPTOOGLE      0
#define MAX_LTP_LTP_IPTOOGLE         1
#define MIN_LTP_LTP_IPTOOGLE         0


/* Register CR_LTP_CLKCTRL */
#define LTP_CR_LTP_CLKCTRL				0x00B0
#define MASK_LTP_DCACHE_CLK_CONTROL		0x00300000
#define SHIFT_LTP_DCACHE_CLK_CONTROL	20
#define MASK_LTP_ICACHE_CLK_CONTROL		0x03000000
#define SHIFT_LTP_ICACHE_CLK_CONTROL	24


/* Register CR_LTP_PRIVEXT */
#define LTP_CR_LTP_PRIVEXT				0x00E8
#define MASK_LTP_MINIM_ENABLE			0x00000080
#define SHIFT_LTP_MINIM_ENABLE			7


/* Register CR_LTP_ACTCYC */
#define LTP_CR_LTP_ACTCYC				0x00F0
#define MASK_LTP_CYCLE_ACTIVE			0x00ffffff
#define SHIFT_LTP_CYCLE_ACTIVE			0


/* Register CR_LTP_IDLCYC */
#define LTP_CR_LTP_IDLCYC				0x00F8
#define MASK_LTP_CYCLE_IDLE				0x00ffffff
#define SHIFT_LTP_CYCLE_IDLE			0


/* Register CR_LTP_SYSC_DCPART0 */
#define MASK_LTP_CACHED_WRITE_ENABLE	0x80000000
#define SHIFT_LTP_CACHED_WRITE_ENABLE	31
#define MASK_LTP_GLOBAL_ADDR_MASK_T0	0x00000f00
#define SHIFT_LTP_GLOBAL_ADDR_MASK_T0	8
#define MASK_LTP_LOCAL_ADDR_MASK_T0		0x0000000f
#define SHIFT_LTP_LOCAL_ADDR_MASK_T0	0


/* Register CR_LTP_MMCU_LOCAL_EBCTRL */
#define MASK_LTP_LOCAL_IC_WIN_MODE		0x0000c000
#define SHIFT_LTP_LOCAL_IC_WIN_MODE		14
#define MASK_LTP_LOCAL_DC_WIN_MODE		0x000000c0
#define SHIFT_LTP_LOCAL_DC_WIN_MODE		6


/* Register CR_LTP_MMCU_GLOBAL_EBCTRL */
#define MASK_LTP_GLOBAL_IC_WIN_MODE		0x0000c000
#define SHIFT_LTP_GLOBAL_IC_WIN_MODE	14
#define MASK_LTP_GLOBAL_DC_WIN_MODE		0x000000c0
#define SHIFT_LTP_GLOBAL_DC_WIN_MODE	6


/* Register CR_LTP_SYSC_DCACHE_FLUSH */
#define MASK_LTP_SYSC_DCACHE_FLUSH		0x00000001
#define SHIFT_LTP_SYSC_DCACHE_FLUSH		0


/* Register CR_LTP_SYSC_ICACHE_FLUSH */
#define MASK_LTP_SYSC_ICACHE_FLUSH		0x00000001
#define SHIFT_LTP_SYSC_ICACHE_FLUSH		0


/*** THREAD 0 REGISTERS ***/

/* Register CR_LTP_KICK */
#define LTP_CR_LTP_KICK             0x0800
#define MASK_LTP_LTP_KICK           0x0000FFFF
#define SHIFT_LTP_LTP_KICK          0
#define REGNUM_LTP_LTP_KICK         0x0800
#define SIGNED_LTP_LTP_KICK         0
#define MAX_LTP_LTP_KICK            65535
#define MIN_LTP_LTP_KICK            0

/* Register CR_LTP_KICKI */
#define LTP_CR_LTP_KICKI            0x0808
#define MASK_LTP_LTP_KICKI          0x0000FFFF
#define SHIFT_LTP_LTP_KICKI         0
#define REGNUM_LTP_LTP_KICKI        0x0808
#define SIGNED_LTP_LTP_KICKI        0
#define MAX_LTP_LTP_KICKI           65535
#define MIN_LTP_LTP_KICKI           0

/* Register CR_LTP_FAULT0 */
#define LTP_CR_LTP_FAULT0           0x0090
#define MASK_LTP_REQ_SB             0x000000FF
#define SHIFT_LTP_REQ_SB            0
#define REGNUM_LTP_REQ_SB           0x0090
#define SIGNED_LTP_REQ_SB           0
#define MAX_LTP_REQ_SB              255
#define MIN_LTP_REQ_SB              0

#define MASK_LTP_REQ_RN_W           0x00000100
#define SHIFT_LTP_REQ_RN_W          8
#define REGNUM_LTP_REQ_RN_W         0x0090
#define SIGNED_LTP_REQ_RN_W         0
#define MAX_LTP_REQ_RN_W            1
#define MIN_LTP_REQ_RN_W            0

#define MASK_LTP_REQ_STATE          0x00000C00
#define SHIFT_LTP_REQ_STATE         10
#define REGNUM_LTP_REQ_STATE        0x0090
#define SIGNED_LTP_REQ_STATE        0
#define MAX_LTP_REQ_STATE           3
#define MIN_LTP_REQ_STATE           0

#define MASK_LTP_REQ_LD_DEST        0x00FF0000
#define SHIFT_LTP_REQ_LD_DEST       16
#define REGNUM_LTP_REQ_LD_DEST      0x0090
#define SIGNED_LTP_REQ_LD_DEST      0
#define MAX_LTP_REQ_LD_DEST         255
#define MIN_LTP_REQ_LD_DEST         0

#define MASK_LTP_REQ_LD_REG         0xF8000000
#define SHIFT_LTP_REQ_LD_REG        27
#define REGNUM_LTP_REQ_LD_REG       0x0090
#define SIGNED_LTP_REQ_LD_REG       0
#define MAX_LTP_REQ_LD_REG          31
#define MIN_LTP_REQ_LD_REG          0

/* Register CR_LTP_REGISTER_READ_WRITE_DATA */
#define LTP_CR_LTP_REGISTER_READ_WRITE_DATA 0xFFF0
/* Register CR_LTP_REGISTER_READ_WRITE_REQUEST */
#define LTP_CR_LTP_REGISTER_READ_WRITE_REQUEST 0xFFF8
#define MASK_LTP_LTP_USPECIFIER     0x0000000F
#define SHIFT_LTP_LTP_USPECIFIER    0
#define REGNUM_LTP_LTP_USPECIFIER   0xFFF8
#define SIGNED_LTP_LTP_USPECIFIER   0
#define MAX_LTP_LTP_USPECIFIER      15
#define MIN_LTP_LTP_USPECIFIER      0

#define MASK_LTP_LTP_RSPECIFIER     0x000001F0
#define SHIFT_LTP_LTP_RSPECIFIER    4
#define REGNUM_LTP_LTP_RSPECIFIER   0xFFF8
#define SIGNED_LTP_LTP_RSPECIFIER   0
#define MAX_LTP_LTP_RSPECIFIER      31
#define MIN_LTP_LTP_RSPECIFIER      0

#define MASK_LTP_LTP_TSPECIFIER     0x00003000
#define SHIFT_LTP_LTP_TSPECIFIER    12
#define REGNUM_LTP_LTP_TSPECIFIER   0xFFF8
#define SIGNED_LTP_LTP_TSPECIFIER   0
#define MAX_LTP_LTP_TSPECIFIER      3
#define MIN_LTP_LTP_TSPECIFIER      0

#define MASK_LTP_LTP_RNW            0x00010000
#define SHIFT_LTP_LTP_RNW           16
#define REGNUM_LTP_LTP_RNW          0xFFF8
#define SIGNED_LTP_LTP_RNW          0
#define MAX_LTP_LTP_RNW             1
#define MIN_LTP_LTP_RNW             0

#define MASK_LTP_LTP_DSPEXT            0x00020000
#define SHIFT_LTP_LTP_DSPEXT           17
#define REGNUM_LTP_LTP_DSPEXT          0xFFF8
#define SIGNED_LTP_LTP_DSPEXT          0
#define MAX_LTP_LTP_DSPEXT             1
#define MIN_LTP_LTP_DSPEXT             0

#define MASK_LTP_LTP_DREADY         0x80000000
#define SHIFT_LTP_LTP_DREADY        31
#define REGNUM_LTP_LTP_DREADY       0xFFF8
#define SIGNED_LTP_LTP_DREADY       0
#define MAX_LTP_LTP_DREADY          1
#define MIN_LTP_LTP_DREADY          0

/*** META CORE REGISTERS ***/

/* Register CR_LTP_RAM_ACCESS_DATA_EXCHANGE */
#define LTP_CR_LTP_RAM_ACCESS_DATA_EXCHANGE 0x0300
/* Register CR_LTP_RAM_ACCESS_DATA_TRANSFER */
#define LTP_CR_LTP_RAM_ACCESS_DATA_TRANSFER 0x0308
/* Register CR_LTP_RAM_ACCESS_CONTROL */
#define LTP_CR_LTP_RAM_ACCESS_CONTROL 0x0310
#define MASK_LTP_LTP_MCMR           0x00000001
#define SHIFT_LTP_LTP_MCMR          0
#define REGNUM_LTP_LTP_MCMR         0x0310
#define SIGNED_LTP_LTP_MCMR         0
#define MAX_LTP_LTP_MCMR            1
#define MIN_LTP_LTP_MCMR            0

#define MASK_LTP_LTP_MCMAI          0x00000002
#define SHIFT_LTP_LTP_MCMAI         1
#define REGNUM_LTP_LTP_MCMAI        0x0310
#define SIGNED_LTP_LTP_MCMAI        0
#define MAX_LTP_LTP_MCMAI           1
#define MIN_LTP_LTP_MCMAI           0

#define MASK_LTP_LTP_MCM_ADDR       0x000FFFFC
#define SHIFT_LTP_LTP_MCM_ADDR      2
#define REGNUM_LTP_LTP_MCM_ADDR     0x0310
#define SIGNED_LTP_LTP_MCM_ADDR     0
#define MAX_LTP_LTP_MCM_ADDR        262143
#define MIN_LTP_LTP_MCM_ADDR        0

#define MASK_LTP_LTP_MCMID          0x0FF00000
#define SHIFT_LTP_LTP_MCMID         20
#define REGNUM_LTP_LTP_MCMID        0x0310
#define SIGNED_LTP_LTP_MCMID        0
#define MAX_LTP_LTP_MCMID           255
#define MIN_LTP_LTP_MCMID           0

#define MASK_LTP_LTP_TR31_BIT          0x80000000
#define SHIFT_LTP_LTP_TR31_BIT         31
#define REGNUM_LTP_LTP_TR31_BIT        0x0310
#define SIGNED_LTP_LTP_TR31_BIT        0
#define MAX_LTP_LTP_TR31_BIT           1
#define MIN_LTP_LTP_TR31_BIT           0

/* Register CR_LTP_RAM_ACCESS_STATUS */
#define LTP_CR_LTP_RAM_ACCESS_STATUS 0x0318
#define MASK_LTP_LTP_LTP_MCM_STAT   0x00000001
#define SHIFT_LTP_LTP_LTP_MCM_STAT  0
#define REGNUM_LTP_LTP_LTP_MCM_STAT 0x0318
#define SIGNED_LTP_LTP_LTP_MCM_STAT 0
#define MAX_LTP_LTP_LTP_MCM_STAT    1
#define MIN_LTP_LTP_LTP_MCM_STAT    0

#if 0
/* Register CR_MTX_SOFT_RESET */
#define MTX_CR_MTX_SOFT_RESET       0x0200
#define MASK_MTX_MTX_RESET          0x00000001
#define SHIFT_MTX_MTX_RESET         0
#define REGNUM_MTX_MTX_RESET        0x0200
#define SIGNED_MTX_MTX_RESET        0
#define MAX_MTX_MTX_RESET           1
#define MIN_MTX_MTX_RESET           0

/* Register CR_MTX_SYSC_CDMAC */
#define MTX_CR_MTX_SYSC_CDMAC       0x0340
#define MASK_MTX_LENGTH             0x0000FFFF
#define SHIFT_MTX_LENGTH            0
#define REGNUM_MTX_LENGTH           0x0340
#define SIGNED_MTX_LENGTH           0
#define MAX_MTX_LENGTH              65535
#define MIN_MTX_LENGTH              0

#define MASK_MTX_ENABLE             0x00010000
#define SHIFT_MTX_ENABLE            16
#define REGNUM_MTX_ENABLE           0x0340
#define SIGNED_MTX_ENABLE           0
#define MAX_MTX_ENABLE              1
#define MIN_MTX_ENABLE              0

#define MASK_MTX_RNW                0x00020000
#define SHIFT_MTX_RNW               17
#define REGNUM_MTX_RNW              0x0340
#define SIGNED_MTX_RNW              0
#define MAX_MTX_RNW                 1
#define MIN_MTX_RNW                 0

#define MASK_MTX_BURSTSIZE          0x07000000
#define SHIFT_MTX_BURSTSIZE         24
#define REGNUM_MTX_BURSTSIZE        0x0340
#define SIGNED_MTX_BURSTSIZE        0
#define MAX_MTX_BURSTSIZE           7
#define MIN_MTX_BURSTSIZE           0

/* Register CR_MTX_SYSC_CDMAA */
#define MTX_CR_MTX_SYSC_CDMAA       0x0344
#define MASK_MTX_CDMAA_ADDRESS      0x03FFFFFC
#define SHIFT_MTX_CDMAA_ADDRESS     2
#define REGNUM_MTX_CDMAA_ADDRESS    0x0344
#define SIGNED_MTX_CDMAA_ADDRESS    0
#define MAX_MTX_CDMAA_ADDRESS       16777215
#define MIN_MTX_CDMAA_ADDRESS       0

/* Register CR_MTX_SYSC_CDMAS0 */
#define MTX_CR_MTX_SYSC_CDMAS0      0x0348
#define MASK_MTX_DONOTHING          0x00000001
#define SHIFT_MTX_DONOTHING         0
#define REGNUM_MTX_DONOTHING        0x0348
#define SIGNED_MTX_DONOTHING        0
#define MAX_MTX_DONOTHING           1
#define MIN_MTX_DONOTHING           0

#define MASK_MTX_DMAREQUEST         0x00000010
#define SHIFT_MTX_DMAREQUEST        4
#define REGNUM_MTX_DMAREQUEST       0x0348
#define SIGNED_MTX_DMAREQUEST       0
#define MAX_MTX_DMAREQUEST          1
#define MIN_MTX_DMAREQUEST          0

#define MASK_MTX_RAMNUMBER          0x00000F00
#define SHIFT_MTX_RAMNUMBER         8
#define REGNUM_MTX_RAMNUMBER        0x0348
#define SIGNED_MTX_RAMNUMBER        0
#define MAX_MTX_RAMNUMBER           15
#define MIN_MTX_RAMNUMBER           0

#define MASK_MTX_COUNT              0xFFFF0000
#define SHIFT_MTX_COUNT             16
#define REGNUM_MTX_COUNT            0x0348
#define SIGNED_MTX_COUNT            0
#define MAX_MTX_COUNT               65535
#define MIN_MTX_COUNT               0

/* Register CR_MTX_SYSC_CDMAS1 */
#define MTX_CR_MTX_SYSC_CDMAS1      0x034C
#define MASK_MTX_CDMAS1_ADDRESS     0x03FFFFFC
#define SHIFT_MTX_CDMAS1_ADDRESS    2
#define REGNUM_MTX_CDMAS1_ADDRESS   0x034C
#define SIGNED_MTX_CDMAS1_ADDRESS   0
#define MAX_MTX_CDMAS1_ADDRESS      16777215
#define MIN_MTX_CDMAS1_ADDRESS      0

/* Register CR_MTX_SYSC_CDMAT */
#define MTX_CR_MTX_SYSC_CDMAT       0x0350
#define MASK_MTX_TRANSFERDATA       0xFFFFFFFF
#define SHIFT_MTX_TRANSFERDATA      0
#define REGNUM_MTX_TRANSFERDATA     0x0350
#define SIGNED_MTX_TRANSFERDATA     0
#define MAX_MTX_TRANSFERDATA        4294967295
#define MIN_MTX_TRANSFERDATA        0
#endif

/*
	Byte range covering the group LTP_CORE file
*/

#define LTP_LTP_CORE_REGISTERS_START		0x00000000
#define LTP_LTP_CORE_REGISTERS_END  		0x00030308

/*
	Byte range covering the whole register file
*/
/*
{0x0000, 0x00000000, 0xFFFFF8F7, 0, "CR_MTX_ENABLE" } ,\
{0x0008, 0x00000000, 0x000C070F, 0, "CR_MTX_STATUS" } ,\
{0x0080, 0x00000000, 0x0000FFFF, 0, "CR_MTX_KICK" } ,\
{0x0088, 0x00000000, 0x0000FFFF, 0, "CR_MTX_KICKI" } ,\
{0x0090, 0x00000000, 0xF8FF0DFF, 0, "CR_MTX_FAULT0" } , \
{0x00F8, 0x00000000, 0x00000000, 0, "CR_MTX_REGISTER_READ_WRITE_DATA" }, \
{0x00FC, 0x00000000, 0x8001007F, 0, "CR_MTX_REGISTER_READ_WRITE_REQUEST" }, \
{0x0100, 0x00000000, 0x00000000, 0, "CR_MTX_RAM_ACCESS_DATA_EXCHANGE" }, \
{0x0104, 0x00000000, 0x00000000, 0, "CR_MTX_RAM_ACCESS_DATA_TRANSFER" }, \
{0x0108, 0x00000000, 0x0FFFFFFF, 0, "CR_MTX_RAM_ACCESS_CONTROL" }, \
{0x010C, 0x00000000, 0x00000001, 0, "CR_MTX_RAM_ACCESS_STATUS" }, \
{0x0200, 0x00000000, 0x00000001, 0, "CR_MTX_SOFT_RESET" } ,\
{0x0340, 0x00000000, 0x0703FFFF, 0, "CR_MTX_SYSC_CDMAC" } ,\
{0x0344, 0x00000000, 0x03FFFFFC, 0, "CR_MTX_SYSC_CDMAA" } ,\
{0x0348, 0x00000001, 0xFFFF0F11, 1, "CR_MTX_SYSC_CDMAS0" } ,\
{0x034C, 0x00000000, 0x03FFFFFC, 1, "CR_MTX_SYSC_CDMAS1" } ,\
{0x0350, 0x00000000, 0xFFFFFFFF, 0, "CR_MTX_SYSC_CDMAT" } ,\
*/
#define LTP_REGISTERS_START		0x00000000
#define LTP_REGISTERS_END  		0x00030308
#define LTP_REG_DEFAULT_TABLE struct {\
			IMG_UINT32 uRegOffset;\
			IMG_UINT32 uRegDefault;\
			IMG_UINT32 uRegMask;\
			bool bReadonly;\
			const char* pszName;\
		} LTP_Defaults[] = {\
	{0x0000, 0x00000000, 0xFFFFF3F7, 0, "CR_LTP_ENABLE" } ,\
	{0x0010, 0x00000000, 0xFFFFFF3F, 0, "CR_LTP_STATUS" } ,\
	{0x0808, 0x00000000, 0x0000FFFF, 0, "CR_LTP_KICK" } ,\
	{0x0808, 0x00000000, 0x0000FFFF, 0, "CR_LTP_KICKI" } ,\
	{0xFFF0, 0x00000000, 0x00000000, 0, "CR_LTP_REGISTER_READ_WRITE_DATA" } ,\
	{0xFFF8, 0x00000000, 0x800338FF, 0, "CR_LTP_REGISTER_READ_WRITE_REQUEST" }, \
	{0x30300, 0x00000000, 0x00000000, 0, "CR_LTP_RAM_ACCESS_DATA_EXCHANGE" } ,\
	{0x30308, 0x00000000, 0x00000000, 0, "CR_LTP_RAM_ACCESS_DATA_TRANSFER" }, \
	{0x30310, 0x00000000, 0x80FFFFFF, 0, "CR_LTP_RAM_ACCESS_CONTROL" }, \
	{0x30318, 0x00000000, 0x00000001, 0, "CR_LTP_RAM_ACCESS_STATUS" } ,\
{ 0 }}

#define LTP_REGS_INIT(uBase) \
	{ \
		int n;\
		LTP_REG_DEFAULT_TABLE;\
		for (n = 0; n < sizeof(LTP_Defaults)/ sizeof(LTP_Defaults[0] ) -1; n++)\
		{\
			RegWriteNoTrap(LTP_Defaults[n].uRegOffset + uBase, LTP_Defaults[n].uRegDefault); \
		}\
	}
#endif
