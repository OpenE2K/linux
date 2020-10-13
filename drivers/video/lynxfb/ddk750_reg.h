/*******************************************************************
*Copyright (c) 2012 by Silicon Motion, Inc. (SMI)
*Permission is hereby granted, free of charge, to any person obtaining a copy
*of this software and associated documentation files (the "Software"), to deal
*in the Software without restriction, including without limitation the rights to
*use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
*of the Software, and to permit persons to whom the Software is furnished to
*do so, subject to the following conditions:
*
*THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
*EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
*OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
*NONINFRINGEMENT.  IN NO EVENT SHALL Mill.Chen and Monk.Liu OR COPYRIGHT
*HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
*WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
*FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
*OTHER DEALINGS IN THE SOFTWARE.
*******************************************************************/
#ifndef DDK750_REG_H__
#define DDK750_REG_H__

/* New register for SM750LE */
#ifdef OPENSOURCE
#define MISC_CTRL                                     0x000004
#define MISC_CTRL_DAC_POWER_LSB                       20
#define MISC_CTRL_LOCALMEM_SIZE_LSB                   12
#define MISC_CTRL_LOCALMEM_SIZE_8M                    3
#define MISC_CTRL_LOCALMEM_SIZE_16M                   0
#define MISC_CTRL_LOCALMEM_SIZE_32M                   1
#define MISC_CTRL_LOCALMEM_SIZE_64M                   2
#define MISC_CTRL_LOCALMEM_RESET_LSB                  6
#define SYSTEM_CTRL                                   0x000000
#define SYSTEM_CTRL_DPMS_LSB                          30
#define SYSTEM_CTRL_DPMS_VPHP                         0
#define SYSTEM_CTRL_DPMS_VPHN                         1
#define SYSTEM_CTRL_DPMS_VNHP                         2
#define SYSTEM_CTRL_DPMS_VNHN                         3
#define SYSTEM_CTRL_PCI_BURST_LSB                     29
#define SYSTEM_CTRL_DE_FIFO_LSB                       23
#define SYSTEM_CTRL_DE_FIFO_NOTEMPTY                  0
#define SYSTEM_CTRL_DE_FIFO_EMPTY                     1
#define SYSTEM_CTRL_DE_STATUS_LSB                     22
#define SYSTEM_CTRL_DE_STATUS_IDLE                    0
#define SYSTEM_CTRL_DE_STATUS_BUSY                    1
#define SYSTEM_CTRL_DE_MEM_FIFO_LSB                   21
#define SYSTEM_CTRL_DE_MEM_FIFO_NOTEMPTY              0
#define SYSTEM_CTRL_DE_MEM_FIFO_EMPTY                 1
#define SYSTEM_CTRL_PANEL_VSYNC_LSB                   18
#define SYSTEM_CTRL_PANEL_VSYNC_INACTIVE              0
#define SYSTEM_CTRL_PANEL_VSYNC_ACTIVE                1
#define SYSTEM_CTRL_CRT_VSYNC_LSB                     19
#define SYSTEM_CTRL_CRT_VSYNC_INACTIVE                0
#define SYSTEM_CTRL_CRT_VSYNC_ACTIVE                  1
#define SYSTEM_CTRL_DE_ABORT_LSB                          13

#define DE_STATE1                                        0x100054
#define DE_STATE1_DE_ABORT_LSB                               0

#define DE_STATE2                                        0x100058
#define DE_STATE2_DE_FIFO_LSB                            3
#define DE_STATE2_DE_FIFO_NOTEMPTY                       0
#define DE_STATE2_DE_FIFO_EMPTY                          1
#define DE_STATE2_DE_STATUS_LSB                          2
#define DE_STATE2_DE_STATUS_IDLE                         0
#define DE_STATE2_DE_STATUS_BUSY                         1
#define DE_STATE2_DE_MEM_FIFO_LSB                        1
#define DE_STATE2_DE_MEM_FIFO_NOTEMPTY                   0
#define DE_STATE2_DE_MEM_FIFO_EMPTY                      1
#endif

#ifdef OPENSOURCE
#define GPIO_MUX                                      0x000008
#define GPIO_MUX_31_LSB                                   31
#define GPIO_MUX_30_LSB                                   30
#endif
#define CURRENT_GATE                                  0x000040
#ifdef OPENSOURCE
#define CURRENT_GATE_M2XCLK_LSB                         12
#define CURRENT_GATE_MCLK_LSB                           14
#define CURRENT_GATE_PWM_LSB                            9
#define CURRENT_GATE_I2C_LSB                            8
#define CURRENT_GATE_SSP_LSB                            7
#define CURRENT_GATE_GPIO_LSB                           6
#define CURRENT_GATE_ZVPORT_LSB                         5
#define CURRENT_GATE_CSC_LSB                            4
#define CURRENT_GATE_DE_LSB                             3
#define MODE0_GATE                                    0x000044
#define CURRENT_GATE_DISPLAY_LSB                           2
#define CURRENT_GATE_LOCALMEM_LSB                          1
#define CURRENT_GATE_DMA_LSB                               0
#endif
#ifdef OPENSOURCE
#define MODE0_GATE                                    0x000044
#define MODE0_GATE_I2C_LSB                            8
#define MODE0_GATE_GPIO_LSB                           6
#endif


#ifdef OPENSOURCE
#define MODE1_GATE                                    0x000048
#define POWER_MODE_CTRL                               0x00004C
#define POWER_MODE_CTRL_MODE_LSB                          0
#define POWER_MODE_CTRL_MODE_MODE0                    0
#define POWER_MODE_CTRL_MODE_MODE1                    1
#define POWER_MODE_CTRL_MODE_SLEEP                    2
#ifdef VALIDATION_CHIP
#define POWER_MODE_CTRL_336CLK_LSB                    4
#endif
#define POWER_MODE_CTRL_OSC_INPUT_LSB                     3
#endif

#define PLL_CLK_COUNT                                 0x000058

#ifdef OPENSOURCE
#define PANEL_PLL_CTRL                                0x00005C
#ifdef VALIDATION_CHIP
#define PANEL_PLL_CTRL_OD_LSB                     14
#else
#define PANEL_PLL_CTRL_POD_LSB                    14
#define PANEL_PLL_CTRL_OD_LSB                     12
#endif
#define PANEL_PLL_CTRL_N_LSB                           8
#define PANEL_PLL_CTRL                                0x00005C
#define PANEL_PLL_CTRL_BYPASS_LSB                     18
#define PANEL_PLL_CTRL_POWER_LSB                      17
#define PANEL_PLL_CTRL_POWER_OFF                      0
#define PANEL_PLL_CTRL_POWER_ON                       1
#define PANEL_PLL_CTRL_INPUT_LSB                      16
#ifdef VALIDATION_CHIP
#define PANEL_PLL_CTRL_OD_LSB                     14
#else
#define PANEL_PLL_CTRL_POD_LSB                    14
#define PANEL_PLL_CTRL_OD_LSB                     12
#endif
#define PANEL_PLL_CTRL_N_LSB                           8
#define PANEL_PLL_CTRL_M_LSB                           0
#define CRT_PLL_CTRL_POWER_LSB                        17
#define CRT_PLL_CTRL_POWER_OFF                        0
#define CRT_PLL_CTRL_POWER_ON                         1
#endif
#define MXCLK_PLL_CTRL                                0x000070
#define CRT_PLL_CTRL                                  0x000060
#define VGA_PLL0_CTRL                                 0x000064
#define VGA_PLL1_CTRL                                 0x000068

#define HOST_CONTROL                                  0x000074
#define HOST_CONTROL_BIG_ENDIANESS_LSB                7

#ifdef OPENSOURCE
#define VGA_CONFIGURATION                             0x000088
#define VGA_CONFIGURATION_PLL_LSB                         2
#define VGA_CONFIGURATION_MODE_LSB                        1
#endif

#define GPIO_DATA                                       0x010000
#define GPIO_DATA_DIRECTION                             0x010004


#ifdef OPENSOURCE
#define PANEL_DISPLAY_CTRL                            0x080000
#define PANEL_DISPLAY_CTRL_RESERVED_1_MASK_LSB        30
#define PANEL_DISPLAY_CTRL_SELECT_LSB                 28
#define PANEL_DISPLAY_CTRL_RESERVED_2_MASK_LSB        20
#define PANEL_DISPLAY_CTRL_RESERVED_3_MASK_LSB        15
#define PANEL_DISPLAY_CTRL_FPEN_LSB                   27
#define PANEL_DISPLAY_CTRL_VBIASEN_LSB                26
#define PANEL_DISPLAY_CTRL_DATA_LSB                   25
#define PANEL_DISPLAY_CTRL_DATA_DISABLE               0
#define PANEL_DISPLAY_CTRL_DATA_ENABLE                1
#define PANEL_DISPLAY_CTRL_TFT_DISP_LSB		      18
#define PANEL_DISPLAY_CTRL_TIMING_LSB                 8
#define PANEL_DISPLAY_CTRL_TIMING_DISABLE             0
#define PANEL_DISPLAY_CTRL_TIMING_ENABLE              1
#define PANEL_DISPLAY_CTRL_CLOCK_PHASE_LSB            14
#define PANEL_DISPLAY_CTRL_VSYNC_PHASE_LSB            13
#define PANEL_DISPLAY_CTRL_HSYNC_PHASE_LSB            12
#define PANEL_DISPLAY_CTRL_VSYNC_LSB                  11
#define PANEL_DISPLAY_CTRL_PLANE_LSB                  2
#define PANEL_DISPLAY_CTRL_FORMAT_LSB                 0
#endif


#ifdef OPENSOURCE
#define PANEL_FB_ADDRESS                             0x08000C
#define PANEL_FB_ADDRESS_STATUS_LSB                  31
#define PANEL_FB_ADDRESS_EXT_LSB                     27
#define PANEL_FB_ADDRESS_ADDRESS_LSB                 0

#define PANEL_FB_WIDTH                                0x080010
#define PANEL_FB_WIDTH_WIDTH_LSB                      16
#define PANEL_FB_WIDTH_OFFSET_LSB                     0

#define PANEL_WINDOW_WIDTH                            0x080014
#define PANEL_WINDOW_WIDTH_WIDTH_LSB                  16
#define PANEL_WINDOW_WIDTH_X_LSB                      0

#define PANEL_WINDOW_HEIGHT                           0x080018
#define PANEL_WINDOW_HEIGHT_HEIGHT_LSB                16
#define PANEL_WINDOW_HEIGHT_Y_LSB                     0

#define PANEL_PLANE_TL                                0x08001C
#define PANEL_PLANE_TL_TOP_LSB                        16
#define PANEL_PLANE_TL_LEFT_LSB                       0

#define PANEL_PLANE_BR                                0x080020
#define PANEL_PLANE_BR_BOTTOM_LSB                     16
#define PANEL_PLANE_BR_RIGHT_LSB                      0
#endif


#ifdef OPENSOURCE
#define PANEL_HORIZONTAL_TOTAL                        0x080024
#define PANEL_HORIZONTAL_TOTAL_TOTAL_LSB                  16
#define PANEL_HORIZONTAL_TOTAL_DISPLAY_END_LSB            0
#define PANEL_HORIZONTAL_SYNC                         0x080028
#define PANEL_HORIZONTAL_SYNC_WIDTH_LSB                   16
#define PANEL_HORIZONTAL_SYNC_START_LSB                   0
#define PANEL_VERTICAL_TOTAL                          0x08002C
#define PANEL_VERTICAL_TOTAL_TOTAL_LSB                    16
#define PANEL_VERTICAL_TOTAL_DISPLAY_END_LSB              0
#define PANEL_VERTICAL_SYNC                           0x080030
#define PANEL_VERTICAL_SYNC_HEIGHT_LSB                    16
#define PANEL_VERTICAL_SYNC_START_LSB                     0
#endif


/* Video Control */
#ifdef OPENSOURCE
#define VIDEO_DISPLAY_CTRL                              0x080040
#define VIDEO_DISPLAY_CTRL_PLANE_LSB                    2
#endif
/* Alpha Control */
#ifdef OPENSOURCE
#define ALPHA_DISPLAY_CTRL                            0x080100
#define ALPHA_DISPLAY_CTRL_PLANE_LSB                      2
#endif

/* Video Alpha Control */
#ifdef OPENSOURCE
#define VIDEO_ALPHA_DISPLAY_CTRL                        0x080080
#define VIDEO_ALPHA_DISPLAY_CTRL_PLANE_LSB              2
#endif

/* CRT Graphics Control */
#ifdef OPENSOURCE
#define CRT_DISPLAY_CTRL                              0x080200
#define CRT_DISPLAY_CTRL_TIMING_LSB                   8
#define CRT_DISPLAY_CTRL_TIMING_DISABLE               0
#define CRT_DISPLAY_CTRL_TIMING_ENABLE                1
#define CRT_DISPLAY_CTRL_PLANE_LSB                    2
#define CRT_DISPLAY_CTRL_CLK_LSB                         27
#define CRT_DISPLAY_CTRL_RESERVED_1_MASK_LSB	      27
#define CRT_DISPLAY_CTRL_RESERVED_2_MASK_LSB 	      24
#define CRT_DISPLAY_CTRL_SELECT_LSB                   18
#define CRT_DISPLAY_CTRL_RESERVED_3_MASK_LSB 	      15
#define CRT_DISPLAY_CTRL_CLOCK_PHASE_LSB              14
#define CRT_DISPLAY_CTRL_BLANK_LSB                    10
#define CRT_DISPLAY_CTRL_BLANK_OFF                    0
#define CRT_DISPLAY_CTRL_BLANK_ON                     1
#define CRT_DISPLAY_CTRL_RESERVED_4_MASK_LSB 	       9
/* SM750LE definition */
#define CRT_DISPLAY_CTRL_DPMS_LSB                      30
#define CRT_DISPLAY_CTRL_DPMS_0                       0
#define CRT_DISPLAY_CTRL_DPMS_1                       1
#define CRT_DISPLAY_CTRL_DPMS_2                       2
#define CRT_DISPLAY_CTRL_DPMS_3                       3
#define CRT_DISPLAY_CTRL_CLK_LSB                       27
#define CRT_DISPLAY_CTRL_CRTSELECT_LSB                 25
#define CRT_DISPLAY_CTRL_RGBBIT_LSB                    24
#define CRT_DISPLAY_CTRL_VSYNC_PHASE_LSB               13
#define CRT_DISPLAY_CTRL_HSYNC_PHASE_LSB               12
#define CRT_DISPLAY_CTRL_FORMAT_LSB                    0
#endif


#ifdef OPENSOURCE
#define CRT_FB_ADDRESS                                0x080204
#define CRT_FB_ADDRESS_STATUS_LSB                     31
#define CRT_FB_ADDRESS_STATUS_CURRENT                 0
#define CRT_FB_ADDRESS_STATUS_PENDING                 1
#define CRT_FB_ADDRESS_EXT_LSB                        27
#define CRT_FB_ADDRESS_EXT_LOCAL                      0
#define CRT_FB_ADDRESS_EXT_EXTERNAL                   1
#define CRT_FB_ADDRESS_ADDRESS_LSB                    0
#endif


#ifdef OPENSOURCE
#define CRT_FB_WIDTH                                  0x080208
#define CRT_FB_WIDTH_WIDTH_LSB                        16
#define CRT_FB_WIDTH_OFFSET_LSB                       0
#endif

#ifdef OPENSOURCE
#define CRT_HORIZONTAL_TOTAL                          0x08020C
#define CRT_HORIZONTAL_TOTAL_TOTAL_LSB                16
#define CRT_HORIZONTAL_TOTAL_DISPLAY_END_LSB          0
#define CRT_HORIZONTAL_SYNC                           0x080210
#define CRT_HORIZONTAL_SYNC_WIDTH_LSB                 16
#define CRT_HORIZONTAL_SYNC_START_LSB                 0
#define CRT_VERTICAL_TOTAL                            0x080214
#define CRT_VERTICAL_TOTAL_TOTAL_LSB                  16
#define CRT_VERTICAL_TOTAL_DISPLAY_END_LSB            0
#define CRT_VERTICAL_SYNC                             0x080218
#define CRT_VERTICAL_SYNC_HEIGHT_LSB                  16
#define CRT_VERTICAL_SYNC_START_LSB                   0
#endif


#ifndef VALIDATION_CHIP
    /* Auto Centering */
#ifdef OPENSOURCE
#define CRT_AUTO_CENTERING_TL                     0x080280
#define CRT_AUTO_CENTERING_TL_TOP_LSB             16
#define CRT_AUTO_CENTERING_TL_LEFT_LSB            0
#define CRT_AUTO_CENTERING_BR                     0x080284
#define CRT_AUTO_CENTERING_BR_BOTTOM_LSB              16
#define CRT_AUTO_CENTERING_BR_RIGHT_LSB               0
#endif
#endif

/* sm750le new register to control panel output */
#define DISPLAY_CONTROL_750LE 	0x80288
/* Palette RAM */

/* Panel Pallete register starts at 0x080400 ~ 0x0807FC */
#define PANEL_PALETTE_RAM                             0x080400

/* Panel Pallete register starts at 0x080C00 ~ 0x080FFC */
#define CRT_PALETTE_RAM                               0x080C00

/* 2D registers
 * move their defination into general lynx_accel.h file
 * because all smi graphic chip share the same drawing engine
 * register format */

#ifdef OPENSOURCE
#define I2C_CTRL                                        0x010041
#define I2C_CTRL_MODE_LSB                               1
#define I2C_CTRL_EN_LSB                                 0
#define I2C_STATUS                                      0x010042
#define I2C_STATUS_TX_LSB                               3
#define I2C_CTRL_CTRL_LSB                               2
#define I2C_STATUS_TX_COMPLETED                         1
#define I2C_SLAVE_ADDRESS                               0x010043
#define I2C_RESET                                       0x010042
#define I2C_SLAVE_ADDRESS                               0x010043
#define I2C_DATA0                                       0x010044
#define I2C_BYTE_COUNT                                  0x010040
#endif

#ifdef OPENSOURCE
#define DMA_ABORT_INTERRUPT                             0x0D0020
#define DMA_ABORT_INTERRUPT_ABORT_1_LSB                     5
#endif



/* Default i2c CLK and Data GPIO. These are the default i2c pins */
#define DEFAULT_I2C_SCL                     30
#define DEFAULT_I2C_SDA                     31

#define GPIO_DATA_SM750LE                               0x020018
#define GPIO_DATA_DIRECTION_SM750LE                     0x02001C
#endif
