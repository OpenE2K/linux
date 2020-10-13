#include <asm/asm-offsets.h>

.global clear_rf_9
.type clear_rf_9,@function
clear_rf_9:
	{
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
.size clear_rf_18, .-clear_rf_18

.global clear_rf_18
.type clear_rf_18,@function
clear_rf_18:
	{
	nop 3
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
.size clear_rf_18, .-clear_rf_18

.global clear_rf_27
.type clear_rf_27,@function
clear_rf_27:
	{
	nop 3
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
.size clear_rf_27, .-clear_rf_27

.global clear_rf_36
.type clear_rf_36,@function
clear_rf_36:
	{
	nop 3
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
.size clear_rf_36, .-clear_rf_36

.global clear_rf_45
.type clear_rf_45,@function
clear_rf_45:
	{
	nop 3
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
.size clear_rf_45, .-clear_rf_45

.global clear_rf_54
.type clear_rf_54,@function
clear_rf_54:
	{
	nop 3
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
.size clear_rf_54, .-clear_rf_54

.global clear_rf_63
.type clear_rf_63,@function
clear_rf_63:
	{
	nop 3
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
.size clear_rf_63, .-clear_rf_63

.global clear_rf_78
.type clear_rf_78,@function
clear_rf_78:
	{
	nop 2
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
	nop 4
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
.size clear_rf_78, .-clear_rf_78

.global clear_rf_90
.type clear_rf_90,@function
clear_rf_90:
	{
	nop 2
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
	nop 4
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
.size clear_rf_90, .-clear_rf_90

.global clear_rf_108
.type clear_rf_108,@function
clear_rf_108:
	{
	nop 2
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
	nop 4
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
.size clear_rf_108, .-clear_rf_108
