/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <generated/asm-offsets.h>

#include <linux/linkage.h>

SYM_FUNC_START(clear_rf_6)
	{
	nop 5
	return %ctpr3
	setwd wsz=6
	addd 0, 0, %dr0
	addd 0, 0, %dr1
	addd 0, 0, %dr2
	addd 0, 0, %dr3
	addd 0, 0, %dr4
	addd 0, 0, %dr5
	}
	{
	addd 0, 0, %dr6
	addd 0, 0, %dr7
	addd 0, 0, %dr8
	addd 0, 0, %dr9
	addd 0, 0, %dr10
	addd 0, 0, %dr11
	ct %ctpr3
	}
SYM_FUNC_END(clear_rf_6)

SYM_FUNC_START(clear_rf_9)
	{
	nop 4
	return %ctpr3
	setwd wsz=9
	addd 0, 0, %dr0
	addd 0, 0, %dr1
	addd 0, 0, %dr2
	addd 0, 0, %dr3
	addd 0, 0, %dr4
	addd 0, 0, %dr5
	}
	{
	addd 0, 0, %dr6
	addd 0, 0, %dr7
	addd 0, 0, %dr8
	addd 0, 0, %dr9
	addd 0, 0, %dr10
	addd 0, 0, %dr11
	}
	{
	addd 0, 0, %dr12
	addd 0, 0, %dr13
	addd 0, 0, %dr14
	addd 0, 0, %dr15
	addd 0, 0, %dr16
	addd 0, 0, %dr17
	ct %ctpr3
	}
SYM_FUNC_END(clear_rf_9)

SYM_FUNC_START(clear_rf_18)
	{
	nop 2
	disp %ctpr1, clear_rf_18_loop
	setwd wsz=18
	setbn rbs=0, rsz=17, rcur=0
	rwd 6UL | E2K_LSR_VLC, %lsr
	}
	{
	return %ctpr3
	}
clear_rf_18_loop:
	{
	loop_mode
	addd 0, 0, %db[0]
	addd 0, 0, %db[1]
	addd 0, 0, %db[12]
	addd 0, 0, %db[13]
	addd 0, 0, %db[24]
	addd 0, 0, %db[25]
	alc alcf = 1, alct = 1
	abn abnf = 1, abnt = 1
	ct %ctpr1 ? %NOT_LOOP_END
	}
	ct %ctpr3
SYM_FUNC_END(clear_rf_18)

SYM_FUNC_START(clear_rf_21)
	{
	nop 2
	disp %ctpr1, clear_rf_21_loop
	setwd wsz=21
	setbn rbs=0, rsz=20, rcur=0
	rwd 7UL | E2K_LSR_VLC, %lsr
	}
	{
	return %ctpr3
	}
clear_rf_21_loop:
	{
	loop_mode
	addd 0, 0, %db[0]
	addd 0, 0, %db[1]
	addd 0, 0, %db[18]
	addd 0, 0, %db[19]
	addd 0, 0, %db[36]
	addd 0, 0, %db[37]
	alc alcf = 1, alct = 1
	abn abnf = 1, abnt = 1
	ct %ctpr1 ? %NOT_LOOP_END
	}
	ct %ctpr3
SYM_FUNC_END(clear_rf_21)

SYM_FUNC_START(clear_rf_24)
	{
	nop 2
	disp %ctpr1, clear_rf_24_loop
	setwd wsz=24
	setbn rbs=0, rsz=23, rcur=0
	rwd 8UL | E2K_LSR_VLC, %lsr
	}
	{
	return %ctpr3
	}
clear_rf_24_loop:
	{
	loop_mode
	addd 0, 0, %db[0]
	addd 0, 0, %db[1]
	addd 0, 0, %db[18]
	addd 0, 0, %db[19]
	addd 0, 0, %db[36]
	addd 0, 0, %db[37]
	alc alcf = 1, alct = 1
	abn abnf = 1, abnt = 1
	ct %ctpr1 ? %NOT_LOOP_END
	}
	ct %ctpr3
SYM_FUNC_END(clear_rf_24)

SYM_FUNC_START(clear_rf_27)
	{
	nop 2
	disp %ctpr1, clear_rf_27_loop
	setwd wsz=27
	setbn rbs=0, rsz=26, rcur=0
	rwd 9UL | E2K_LSR_VLC, %lsr
	}
	{
	return %ctpr3
	}
clear_rf_27_loop:
	{
	loop_mode
	addd 0, 0, %db[0]
	addd 0, 0, %db[1]
	addd 0, 0, %db[18]
	addd 0, 0, %db[19]
	addd 0, 0, %db[36]
	addd 0, 0, %db[37]
	alc alcf = 1, alct = 1
	abn abnf = 1, abnt = 1
	ct %ctpr1 ? %NOT_LOOP_END
	}
	ct %ctpr3
SYM_FUNC_END(clear_rf_27)

SYM_FUNC_START(clear_rf_36)
	{
	nop 2
	disp %ctpr1, clear_rf_36_loop
	setwd wsz=36
	setbn rbs=0, rsz=35, rcur=0
	rwd 12UL | E2K_LSR_VLC, %lsr
	}
	{
	return %ctpr3
	}
clear_rf_36_loop:
	{
	loop_mode
	addd 0, 0, %db[0]
	addd 0, 0, %db[1]
	addd 0, 0, %db[24]
	addd 0, 0, %db[25]
	addd 0, 0, %db[48]
	addd 0, 0, %db[49]
	alc alcf = 1, alct = 1
	abn abnf = 1, abnt = 1
	ct %ctpr1 ? %NOT_LOOP_END
	}
	ct %ctpr3
SYM_FUNC_END(clear_rf_36)

SYM_FUNC_START(clear_rf_45)
	{
	nop 2
	disp %ctpr1, clear_rf_45_loop
	setwd wsz=45
	setbn rbs=0, rsz=44, rcur=0
	rwd 15UL | E2K_LSR_VLC, %lsr
	}
	{
	return %ctpr3
	}
clear_rf_45_loop:
	{
	loop_mode
	addd 0, 0, %db[0]
	addd 0, 0, %db[1]
	addd 0, 0, %db[30]
	addd 0, 0, %db[31]
	addd 0, 0, %db[60]
	addd 0, 0, %db[61]
	alc alcf = 1, alct = 1
	abn abnf = 1, abnt = 1
	ct %ctpr1 ? %NOT_LOOP_END
	}
	ct %ctpr3
SYM_FUNC_END(clear_rf_45)

SYM_FUNC_START(clear_rf_54)
	{
	nop 2
	disp %ctpr1, clear_rf_54_loop
	setwd wsz=54
	setbn rbs=0, rsz=53, rcur=0
	rwd 18UL | E2K_LSR_VLC, %lsr
	}
	{
	return %ctpr3
	}
clear_rf_54_loop:
	{
	loop_mode
	addd 0, 0, %db[0]
	addd 0, 0, %db[1]
	addd 0, 0, %db[36]
	addd 0, 0, %db[37]
	addd 0, 0, %db[72]
	addd 0, 0, %db[73]
	alc alcf = 1, alct = 1
	abn abnf = 1, abnt = 1
	ct %ctpr1 ? %NOT_LOOP_END
	}
	ct %ctpr3
SYM_FUNC_END(clear_rf_54)

SYM_FUNC_START(clear_rf_63)
	{
	nop 2
	disp %ctpr1, clear_rf_63_loop
	setwd wsz=63
	setbn rbs=0, rsz=62, rcur=0
	rwd 21UL | E2K_LSR_VLC, %lsr
	}
	{
	return %ctpr3
	}
clear_rf_63_loop:
	{
	loop_mode
	addd 0, 0, %db[0]
	addd 0, 0, %db[1]
	addd 0, 0, %db[42]
	addd 0, 0, %db[43]
	addd 0, 0, %db[84]
	addd 0, 0, %db[85]
	alc alcf = 1, alct = 1
	abn abnf = 1, abnt = 1
	ct %ctpr1 ? %NOT_LOOP_END
	}
	ct %ctpr3
SYM_FUNC_END(clear_rf_63)

SYM_FUNC_START(clear_rf_78)
	{
	nop 1
	disp %ctpr1, clear_rf_78_loop_1
	setwd wsz=78
	setbn rbs=0, rsz=62, rcur=0
	rwd 21UL | E2K_LSR_VLC, %lsr
	}
	{
	disp %ctpr2, clear_rf_78_loop_2
	}
	{
	return %ctpr3
	}
clear_rf_78_loop_1:
	{
	loop_mode
	addd 0, 0, %db[0]
	addd 0, 0, %db[1]
	addd 0, 0, %db[42]
	addd 0, 0, %db[43]
	addd 0, 0, %db[84]
	addd 0, 0, %db[85]
	alc alcf = 1, alct = 1
	abn abnf = 1, abnt = 1
	ct %ctpr1 ? %NOT_LOOP_END
	}
	{
	nop 3
	setbn rbs=63, rsz=14, rcur=0
	rwd 5UL | E2K_LSR_VLC, %lsr
	}
clear_rf_78_loop_2:
	{
	loop_mode
	addd 0, 0, %db[0]
	addd 0, 0, %db[1]
	addd 0, 0, %db[10]
	addd 0, 0, %db[11]
	addd 0, 0, %db[20]
	addd 0, 0, %db[21]
	alc alcf = 1, alct = 1
	abn abnf = 1, abnt = 1
	ct %ctpr2 ? %NOT_LOOP_END
	}
	ct %ctpr3
SYM_FUNC_END(clear_rf_78)

SYM_FUNC_START(clear_rf_90)
	{
	nop 1
	disp %ctpr1, clear_rf_90_loop_1
	setwd wsz=90
	setbn rbs=0, rsz=62, rcur=0
	rwd 21UL | E2K_LSR_VLC, %lsr
	}
	{
	disp %ctpr2, clear_rf_90_loop_2
	}
	{
	return %ctpr3
	}
clear_rf_90_loop_1:
	{
	loop_mode
	addd 0, 0, %db[0]
	addd 0, 0, %db[1]
	addd 0, 0, %db[42]
	addd 0, 0, %db[43]
	addd 0, 0, %db[84]
	addd 0, 0, %db[85]
	alc alcf = 1, alct = 1
	abn abnf = 1, abnt = 1
	ct %ctpr1 ? %NOT_LOOP_END
	}
	{
	nop 3
	setbn rbs=63, rsz=26, rcur=0
	rwd 9UL | E2K_LSR_VLC, %lsr
	}
clear_rf_90_loop_2:
	{
	loop_mode
	addd 0, 0, %db[0]
	addd 0, 0, %db[1]
	addd 0, 0, %db[18]
	addd 0, 0, %db[19]
	addd 0, 0, %db[36]
	addd 0, 0, %db[37]
	alc alcf = 1, alct = 1
	abn abnf = 1, abnt = 1
	ct %ctpr2 ? %NOT_LOOP_END
	}
	ct %ctpr3
SYM_FUNC_END(clear_rf_90)

SYM_FUNC_START(clear_rf_99)
	{
	nop 1
	disp %ctpr1, clear_rf_90_loop_1
	setwd wsz=90
	setbn rbs=0, rsz=62, rcur=0
	rwd 21UL | E2K_LSR_VLC, %lsr
	}
	{
	disp %ctpr2, clear_rf_90_loop_2
	}
	{
	return %ctpr3
	}
clear_rf_99_loop_1:
	{
	loop_mode
	addd 0, 0, %db[0]
	addd 0, 0, %db[1]
	addd 0, 0, %db[42]
	addd 0, 0, %db[43]
	addd 0, 0, %db[84]
	addd 0, 0, %db[85]
	alc alcf = 1, alct = 1
	abn abnf = 1, abnt = 1
	ct %ctpr1 ? %NOT_LOOP_END
	}
	{
	nop 3
	setbn rbs=63, rsz=35, rcur=0
	rwd 12UL | E2K_LSR_VLC, %lsr
	}
clear_rf_99_loop_2:
	{
	loop_mode
	addd 0, 0, %db[0]
	addd 0, 0, %db[1]
	addd 0, 0, %db[18]
	addd 0, 0, %db[19]
	addd 0, 0, %db[36]
	addd 0, 0, %db[37]
	alc alcf = 1, alct = 1
	abn abnf = 1, abnt = 1
	ct %ctpr2 ? %NOT_LOOP_END
	}
	ct %ctpr3
SYM_FUNC_END(clear_rf_99)

SYM_FUNC_START(clear_rf_108)
	{
	nop 1
	disp %ctpr1, clear_rf_108_loop_1
	setwd wsz=108
	setbn rbs=0, rsz=62, rcur=0
	rwd 21UL | E2K_LSR_VLC, %lsr
	}
	{
	disp %ctpr2, clear_rf_108_loop_2
	}
	{
	return %ctpr3
	}
clear_rf_108_loop_1:
	{
	loop_mode
	addd 0, 0, %db[0]
	addd 0, 0, %db[1]
	addd 0, 0, %db[42]
	addd 0, 0, %db[43]
	addd 0, 0, %db[84]
	addd 0, 0, %db[85]
	alc alcf = 1, alct = 1
	abn abnf = 1, abnt = 1
	ct %ctpr1 ? %NOT_LOOP_END
	}
	{
	nop 3
	setbn rbs=63, rsz=44, rcur=0
	rwd 15UL | E2K_LSR_VLC, %lsr
	}
clear_rf_108_loop_2:
	{
	loop_mode
	addd 0, 0, %db[0]
	addd 0, 0, %db[1]
	addd 0, 0, %db[30]
	addd 0, 0, %db[31]
	addd 0, 0, %db[60]
	addd 0, 0, %db[61]
	alc alcf = 1, alct = 1
	abn abnf = 1, abnt = 1
	ct %ctpr2 ? %NOT_LOOP_END
	}
	ct %ctpr3
SYM_FUNC_END(clear_rf_108)
