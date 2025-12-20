/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <asm/trap_table.h>

.section ".entry.text", "ax"

.global fill_handler_0
fill_handler_0:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=0
        }
.size $fill_handler_0, . - $fill_handler_0
.global fill_handler_1
fill_handler_1:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=1
        }
.size $fill_handler_1, . - $fill_handler_1
.global fill_handler_2
fill_handler_2:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=2
        }
.size $fill_handler_2, . - $fill_handler_2
.global fill_handler_3
fill_handler_3:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=3
        }
.size $fill_handler_3, . - $fill_handler_3
.global fill_handler_4
fill_handler_4:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=4
        }
.size $fill_handler_4, . - $fill_handler_4
.global fill_handler_5
fill_handler_5:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=5
        }
.size $fill_handler_5, . - $fill_handler_5
.global fill_handler_6
fill_handler_6:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=6
        }
.size $fill_handler_6, . - $fill_handler_6
.global fill_handler_7
fill_handler_7:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=7
        }
.size $fill_handler_7, . - $fill_handler_7
.global fill_handler_8
fill_handler_8:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=8
        }
.size $fill_handler_8, . - $fill_handler_8
.global fill_handler_9
fill_handler_9:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=9
        }
.size $fill_handler_9, . - $fill_handler_9
.global fill_handler_10
fill_handler_10:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=10
        }
.size $fill_handler_10, . - $fill_handler_10
.global fill_handler_11
fill_handler_11:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=11
        }
.size $fill_handler_11, . - $fill_handler_11
.global fill_handler_12
fill_handler_12:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=12
        }
.size $fill_handler_12, . - $fill_handler_12
.global fill_handler_13
fill_handler_13:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=13
        }
.size $fill_handler_13, . - $fill_handler_13
.global fill_handler_14
fill_handler_14:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=14
        }
.size $fill_handler_14, . - $fill_handler_14
.global fill_handler_15
fill_handler_15:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=15
        }
.size $fill_handler_15, . - $fill_handler_15
.global fill_handler_16
fill_handler_16:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=16
        }
.size $fill_handler_16, . - $fill_handler_16
.global fill_handler_17
fill_handler_17:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=17
        }
.size $fill_handler_17, . - $fill_handler_17
.global fill_handler_18
fill_handler_18:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=18
        }
.size $fill_handler_18, . - $fill_handler_18
.global fill_handler_19
fill_handler_19:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=19
        }
.size $fill_handler_19, . - $fill_handler_19
.global fill_handler_20
fill_handler_20:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=20
        }
.size $fill_handler_20, . - $fill_handler_20
.global fill_handler_21
fill_handler_21:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=21
        }
.size $fill_handler_21, . - $fill_handler_21
.global fill_handler_22
fill_handler_22:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=22
        }
.size $fill_handler_22, . - $fill_handler_22
.global fill_handler_23
fill_handler_23:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=23
        }
.size $fill_handler_23, . - $fill_handler_23
.global fill_handler_24
fill_handler_24:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=24
        }
.size $fill_handler_24, . - $fill_handler_24
.global fill_handler_25
fill_handler_25:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=25
        }
.size $fill_handler_25, . - $fill_handler_25
.global fill_handler_26
fill_handler_26:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=26
        }
.size $fill_handler_26, . - $fill_handler_26
.global fill_handler_27
fill_handler_27:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=27
        }
.size $fill_handler_27, . - $fill_handler_27
.global fill_handler_28
fill_handler_28:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=28
        }
.size $fill_handler_28, . - $fill_handler_28
.global fill_handler_29
fill_handler_29:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=29
        }
.size $fill_handler_29, . - $fill_handler_29
.global fill_handler_30
fill_handler_30:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=30
        }
.size $fill_handler_30, . - $fill_handler_30
.global fill_handler_31
fill_handler_31:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=31
        }
.size $fill_handler_31, . - $fill_handler_31
.global fill_handler_32
fill_handler_32:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=32
        }
.size $fill_handler_32, . - $fill_handler_32
.global fill_handler_33
fill_handler_33:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=33
        }
.size $fill_handler_33, . - $fill_handler_33
.global fill_handler_34
fill_handler_34:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=34
        }
.size $fill_handler_34, . - $fill_handler_34
.global fill_handler_35
fill_handler_35:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=35
        }
.size $fill_handler_35, . - $fill_handler_35
.global fill_handler_36
fill_handler_36:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=36
        }
.size $fill_handler_36, . - $fill_handler_36
.global fill_handler_37
fill_handler_37:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=37
        }
.size $fill_handler_37, . - $fill_handler_37
.global fill_handler_38
fill_handler_38:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=38
        }
.size $fill_handler_38, . - $fill_handler_38
.global fill_handler_39
fill_handler_39:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=39
        }
.size $fill_handler_39, . - $fill_handler_39
.global fill_handler_40
fill_handler_40:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=40
        }
.size $fill_handler_40, . - $fill_handler_40
.global fill_handler_41
fill_handler_41:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=41
        }
.size $fill_handler_41, . - $fill_handler_41
.global fill_handler_42
fill_handler_42:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=42
        }
.size $fill_handler_42, . - $fill_handler_42
.global fill_handler_43
fill_handler_43:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=43
        }
.size $fill_handler_43, . - $fill_handler_43
.global fill_handler_44
fill_handler_44:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=44
        }
.size $fill_handler_44, . - $fill_handler_44
.global fill_handler_45
fill_handler_45:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=45
        }
.size $fill_handler_45, . - $fill_handler_45
.global fill_handler_46
fill_handler_46:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=46
        }
.size $fill_handler_46, . - $fill_handler_46
.global fill_handler_47
fill_handler_47:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=47
        }
.size $fill_handler_47, . - $fill_handler_47
.global fill_handler_48
fill_handler_48:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=48
        }
.size $fill_handler_48, . - $fill_handler_48
.global fill_handler_49
fill_handler_49:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=49
        }
.size $fill_handler_49, . - $fill_handler_49
.global fill_handler_50
fill_handler_50:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=50
        }
.size $fill_handler_50, . - $fill_handler_50
.global fill_handler_51
fill_handler_51:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=51
        }
.size $fill_handler_51, . - $fill_handler_51
.global fill_handler_52
fill_handler_52:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=52
        }
.size $fill_handler_52, . - $fill_handler_52
.global fill_handler_53
fill_handler_53:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=53
        }
.size $fill_handler_53, . - $fill_handler_53
.global fill_handler_54
fill_handler_54:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=54
        }
.size $fill_handler_54, . - $fill_handler_54
.global fill_handler_55
fill_handler_55:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=55
        }
.size $fill_handler_55, . - $fill_handler_55
.global fill_handler_56
fill_handler_56:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=56
        }
.size $fill_handler_56, . - $fill_handler_56
.global fill_handler_57
fill_handler_57:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=57
        }
.size $fill_handler_57, . - $fill_handler_57
.global fill_handler_58
fill_handler_58:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=58
        }
.size $fill_handler_58, . - $fill_handler_58
.global fill_handler_59
fill_handler_59:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=59
        }
.size $fill_handler_59, . - $fill_handler_59
.global fill_handler_60
fill_handler_60:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=60
        }
.size $fill_handler_60, . - $fill_handler_60
.global fill_handler_61
fill_handler_61:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=61
        }
.size $fill_handler_61, . - $fill_handler_61
.global fill_handler_62
fill_handler_62:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=62
        }
.size $fill_handler_62, . - $fill_handler_62
.global fill_handler_63
fill_handler_63:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=63
        }
.size $fill_handler_63, . - $fill_handler_63
.global fill_handler_64
fill_handler_64:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=64
        }
.size $fill_handler_64, . - $fill_handler_64
.global fill_handler_65
fill_handler_65:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=65
        }
.size $fill_handler_65, . - $fill_handler_65
.global fill_handler_66
fill_handler_66:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=66
        }
.size $fill_handler_66, . - $fill_handler_66
.global fill_handler_67
fill_handler_67:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=67
        }
.size $fill_handler_67, . - $fill_handler_67
.global fill_handler_68
fill_handler_68:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=68
        }
.size $fill_handler_68, . - $fill_handler_68
.global fill_handler_69
fill_handler_69:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=69
        }
.size $fill_handler_69, . - $fill_handler_69
.global fill_handler_70
fill_handler_70:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=70
        }
.size $fill_handler_70, . - $fill_handler_70
.global fill_handler_71
fill_handler_71:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=71
        }
.size $fill_handler_71, . - $fill_handler_71
.global fill_handler_72
fill_handler_72:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=72
        }
.size $fill_handler_72, . - $fill_handler_72
.global fill_handler_73
fill_handler_73:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=73
        }
.size $fill_handler_73, . - $fill_handler_73
.global fill_handler_74
fill_handler_74:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=74
        }
.size $fill_handler_74, . - $fill_handler_74
.global fill_handler_75
fill_handler_75:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=75
        }
.size $fill_handler_75, . - $fill_handler_75
.global fill_handler_76
fill_handler_76:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=76
        }
.size $fill_handler_76, . - $fill_handler_76
.global fill_handler_77
fill_handler_77:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=77
        }
.size $fill_handler_77, . - $fill_handler_77
.global fill_handler_78
fill_handler_78:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=78
        }
.size $fill_handler_78, . - $fill_handler_78
.global fill_handler_79
fill_handler_79:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=79
        }
.size $fill_handler_79, . - $fill_handler_79
.global fill_handler_80
fill_handler_80:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=80
        }
.size $fill_handler_80, . - $fill_handler_80
.global fill_handler_81
fill_handler_81:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=81
        }
.size $fill_handler_81, . - $fill_handler_81
.global fill_handler_82
fill_handler_82:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=82
        }
.size $fill_handler_82, . - $fill_handler_82
.global fill_handler_83
fill_handler_83:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=83
        }
.size $fill_handler_83, . - $fill_handler_83
.global fill_handler_84
fill_handler_84:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=84
        }
.size $fill_handler_84, . - $fill_handler_84
.global fill_handler_85
fill_handler_85:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=85
        }
.size $fill_handler_85, . - $fill_handler_85
.global fill_handler_86
fill_handler_86:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=86
        }
.size $fill_handler_86, . - $fill_handler_86
.global fill_handler_87
fill_handler_87:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=87
        }
.size $fill_handler_87, . - $fill_handler_87
.global fill_handler_88
fill_handler_88:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=88
        }
.size $fill_handler_88, . - $fill_handler_88
.global fill_handler_89
fill_handler_89:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=89
        }
.size $fill_handler_89, . - $fill_handler_89
.global fill_handler_90
fill_handler_90:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=90
        }
.size $fill_handler_90, . - $fill_handler_90
.global fill_handler_91
fill_handler_91:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=91
        }
.size $fill_handler_91, . - $fill_handler_91
.global fill_handler_92
fill_handler_92:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=92
        }
.size $fill_handler_92, . - $fill_handler_92
.global fill_handler_93
fill_handler_93:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=93
        }
.size $fill_handler_93, . - $fill_handler_93
.global fill_handler_94
fill_handler_94:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=94
        }
.size $fill_handler_94, . - $fill_handler_94
.global fill_handler_95
fill_handler_95:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=95
        }
.size $fill_handler_95, . - $fill_handler_95
.global fill_handler_96
fill_handler_96:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=96
        }
.size $fill_handler_96, . - $fill_handler_96
.global fill_handler_97
fill_handler_97:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=97
        }
.size $fill_handler_97, . - $fill_handler_97
.global fill_handler_98
fill_handler_98:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=98
        }
.size $fill_handler_98, . - $fill_handler_98
.global fill_handler_99
fill_handler_99:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=99
        }
.size $fill_handler_99, . - $fill_handler_99
.global fill_handler_100
fill_handler_100:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=100
        }
.size $fill_handler_100, . - $fill_handler_100
.global fill_handler_101
fill_handler_101:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=101
        }
.size $fill_handler_101, . - $fill_handler_101
.global fill_handler_102
fill_handler_102:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=102
        }
.size $fill_handler_102, . - $fill_handler_102
.global fill_handler_103
fill_handler_103:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=103
        }
.size $fill_handler_103, . - $fill_handler_103
.global fill_handler_104
fill_handler_104:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=104
        }
.size $fill_handler_104, . - $fill_handler_104
.global fill_handler_105
fill_handler_105:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=105
        }
.size $fill_handler_105, . - $fill_handler_105
.global fill_handler_106
fill_handler_106:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=106
        }
.size $fill_handler_106, . - $fill_handler_106
.global fill_handler_107
fill_handler_107:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=107
        }
.size $fill_handler_107, . - $fill_handler_107
.global fill_handler_108
fill_handler_108:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=108
        }
.size $fill_handler_108, . - $fill_handler_108
.global fill_handler_109
fill_handler_109:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=109
        }
.size $fill_handler_109, . - $fill_handler_109
.global fill_handler_110
fill_handler_110:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=110
        }
.size $fill_handler_110, . - $fill_handler_110
.global fill_handler_111
fill_handler_111:
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                nop 3
                rrd %osr0, GVCPUSTATE
        }
        {
                call %ctpr1, wbs=111
        }
.size $fill_handler_111, . - $fill_handler_111
