/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/linkage.h>

#include <asm/trap_table.h>

.section ".entry.text", "ax"

SYM_FUNC_START(fill_handler_0)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=0
        }
SYM_FUNC_END(fill_handler_0)

SYM_FUNC_START(fill_handler_1)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=1
        }
SYM_FUNC_END(fill_handler_1)

SYM_FUNC_START(fill_handler_2)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=2
        }
SYM_FUNC_END(fill_handler_2)

SYM_FUNC_START(fill_handler_3)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=3
        }
SYM_FUNC_END(fill_handler_3)

SYM_FUNC_START(fill_handler_4)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=4
        }
SYM_FUNC_END(fill_handler_4)

SYM_FUNC_START(fill_handler_5)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=5
        }
SYM_FUNC_END(fill_handler_5)

SYM_FUNC_START(fill_handler_6)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=6
        }
SYM_FUNC_END(fill_handler_6)

SYM_FUNC_START(fill_handler_7)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=7
        }
SYM_FUNC_END(fill_handler_7)

SYM_FUNC_START(fill_handler_8)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=8
        }
SYM_FUNC_END(fill_handler_8)

SYM_FUNC_START(fill_handler_9)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=9
        }
SYM_FUNC_END(fill_handler_9)

SYM_FUNC_START(fill_handler_10)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=10
        }
SYM_FUNC_END(fill_handler_10)

SYM_FUNC_START(fill_handler_11)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=11
        }
SYM_FUNC_END(fill_handler_11)

SYM_FUNC_START(fill_handler_12)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=12
        }
SYM_FUNC_END(fill_handler_12)

SYM_FUNC_START(fill_handler_13)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=13
        }
SYM_FUNC_END(fill_handler_13)

SYM_FUNC_START(fill_handler_14)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=14
        }
SYM_FUNC_END(fill_handler_14)

SYM_FUNC_START(fill_handler_15)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=15
        }
SYM_FUNC_END(fill_handler_15)

SYM_FUNC_START(fill_handler_16)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=16
        }
SYM_FUNC_END(fill_handler_16)

SYM_FUNC_START(fill_handler_17)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=17
        }
SYM_FUNC_END(fill_handler_17)

SYM_FUNC_START(fill_handler_18)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=18
        }
SYM_FUNC_END(fill_handler_18)

SYM_FUNC_START(fill_handler_19)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=19
        }
SYM_FUNC_END(fill_handler_19)

SYM_FUNC_START(fill_handler_20)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=20
        }
SYM_FUNC_END(fill_handler_20)

SYM_FUNC_START(fill_handler_21)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=21
        }
SYM_FUNC_END(fill_handler_21)

SYM_FUNC_START(fill_handler_22)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=22
        }
SYM_FUNC_END(fill_handler_22)

SYM_FUNC_START(fill_handler_23)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=23
        }
SYM_FUNC_END(fill_handler_23)

SYM_FUNC_START(fill_handler_24)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=24
        }
SYM_FUNC_END(fill_handler_24)

SYM_FUNC_START(fill_handler_25)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=25
        }
SYM_FUNC_END(fill_handler_25)

SYM_FUNC_START(fill_handler_26)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=26
        }
SYM_FUNC_END(fill_handler_26)

SYM_FUNC_START(fill_handler_27)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=27
        }
SYM_FUNC_END(fill_handler_27)

SYM_FUNC_START(fill_handler_28)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=28
        }
SYM_FUNC_END(fill_handler_28)

SYM_FUNC_START(fill_handler_29)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=29
        }
SYM_FUNC_END(fill_handler_29)

SYM_FUNC_START(fill_handler_30)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=30
        }
SYM_FUNC_END(fill_handler_30)

SYM_FUNC_START(fill_handler_31)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=31
        }
SYM_FUNC_END(fill_handler_31)

SYM_FUNC_START(fill_handler_32)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=32
        }
SYM_FUNC_END(fill_handler_32)

SYM_FUNC_START(fill_handler_33)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=33
        }
SYM_FUNC_END(fill_handler_33)

SYM_FUNC_START(fill_handler_34)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=34
        }
SYM_FUNC_END(fill_handler_34)

SYM_FUNC_START(fill_handler_35)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=35
        }
SYM_FUNC_END(fill_handler_35)

SYM_FUNC_START(fill_handler_36)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=36
        }
SYM_FUNC_END(fill_handler_36)

SYM_FUNC_START(fill_handler_37)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=37
        }
SYM_FUNC_END(fill_handler_37)

SYM_FUNC_START(fill_handler_38)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=38
        }
SYM_FUNC_END(fill_handler_38)

SYM_FUNC_START(fill_handler_39)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=39
        }
SYM_FUNC_END(fill_handler_39)

SYM_FUNC_START(fill_handler_40)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=40
        }
SYM_FUNC_END(fill_handler_40)

SYM_FUNC_START(fill_handler_41)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=41
        }
SYM_FUNC_END(fill_handler_41)

SYM_FUNC_START(fill_handler_42)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=42
        }
SYM_FUNC_END(fill_handler_42)

SYM_FUNC_START(fill_handler_43)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=43
        }
SYM_FUNC_END(fill_handler_43)

SYM_FUNC_START(fill_handler_44)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=44
        }
SYM_FUNC_END(fill_handler_44)

SYM_FUNC_START(fill_handler_45)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=45
        }
SYM_FUNC_END(fill_handler_45)

SYM_FUNC_START(fill_handler_46)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=46
        }
SYM_FUNC_END(fill_handler_46)

SYM_FUNC_START(fill_handler_47)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=47
        }
SYM_FUNC_END(fill_handler_47)

SYM_FUNC_START(fill_handler_48)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=48
        }
SYM_FUNC_END(fill_handler_48)

SYM_FUNC_START(fill_handler_49)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=49
        }
SYM_FUNC_END(fill_handler_49)

SYM_FUNC_START(fill_handler_50)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=50
        }
SYM_FUNC_END(fill_handler_50)

SYM_FUNC_START(fill_handler_51)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=51
        }
SYM_FUNC_END(fill_handler_51)

SYM_FUNC_START(fill_handler_52)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=52
        }
SYM_FUNC_END(fill_handler_52)

SYM_FUNC_START(fill_handler_53)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=53
        }
SYM_FUNC_END(fill_handler_53)

SYM_FUNC_START(fill_handler_54)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=54
        }
SYM_FUNC_END(fill_handler_54)


SYM_FUNC_START(fill_handler_55)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=55
        }
SYM_FUNC_END(fill_handler_55)

SYM_FUNC_START(fill_handler_56)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=56
        }
SYM_FUNC_END(fill_handler_56)

SYM_FUNC_START(fill_handler_57)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=57
        }
SYM_FUNC_END(fill_handler_57)

SYM_FUNC_START(fill_handler_58)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=58
        }
SYM_FUNC_END(fill_handler_58)

SYM_FUNC_START(fill_handler_59)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=59
        }
SYM_FUNC_END(fill_handler_59)

SYM_FUNC_START(fill_handler_60)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=60
        }
SYM_FUNC_END(fill_handler_60)

SYM_FUNC_START(fill_handler_61)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=61
        }
SYM_FUNC_END(fill_handler_61)

SYM_FUNC_START(fill_handler_62)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=62
        }
SYM_FUNC_END(fill_handler_62)

SYM_FUNC_START(fill_handler_63)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=63
        }
SYM_FUNC_END(fill_handler_63)

SYM_FUNC_START(fill_handler_64)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=64
        }
SYM_FUNC_END(fill_handler_64)

SYM_FUNC_START(fill_handler_65)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=65
        }
SYM_FUNC_END(fill_handler_65)

SYM_FUNC_START(fill_handler_66)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=66
        }
SYM_FUNC_END(fill_handler_66)

SYM_FUNC_START(fill_handler_67)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=67
        }
SYM_FUNC_END(fill_handler_67)

SYM_FUNC_START(fill_handler_68)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=68
        }
SYM_FUNC_END(fill_handler_68)

SYM_FUNC_START(fill_handler_69)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=69
        }
SYM_FUNC_END(fill_handler_69)

SYM_FUNC_START(fill_handler_70)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=70
        }
SYM_FUNC_END(fill_handler_70)

SYM_FUNC_START(fill_handler_71)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=71
        }
SYM_FUNC_END(fill_handler_71)

SYM_FUNC_START(fill_handler_72)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=72
        }
SYM_FUNC_END(fill_handler_72)

SYM_FUNC_START(fill_handler_73)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=73
        }
SYM_FUNC_END(fill_handler_73)

SYM_FUNC_START(fill_handler_74)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=74
        }
SYM_FUNC_END(fill_handler_74)

SYM_FUNC_START(fill_handler_75)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=75
        }
SYM_FUNC_END(fill_handler_75)

SYM_FUNC_START(fill_handler_76)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=76
        }
SYM_FUNC_END(fill_handler_76)

SYM_FUNC_START(fill_handler_77)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=77
        }
SYM_FUNC_END(fill_handler_77)

SYM_FUNC_START(fill_handler_78)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=78
        }
SYM_FUNC_END(fill_handler_78)

SYM_FUNC_START(fill_handler_79)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=79
        }
SYM_FUNC_END(fill_handler_79)

SYM_FUNC_START(fill_handler_80)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=80
        }
SYM_FUNC_END(fill_handler_80)

SYM_FUNC_START(fill_handler_81)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=81
        }
SYM_FUNC_END(fill_handler_81)

SYM_FUNC_START(fill_handler_82)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=82
        }
SYM_FUNC_END(fill_handler_82)

SYM_FUNC_START(fill_handler_83)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=83
        }
SYM_FUNC_END(fill_handler_83)

SYM_FUNC_START(fill_handler_84)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=84
        }
SYM_FUNC_END(fill_handler_84)

SYM_FUNC_START(fill_handler_85)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=85
        }
SYM_FUNC_END(fill_handler_85)

SYM_FUNC_START(fill_handler_86)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=86
        }
SYM_FUNC_END(fill_handler_86)

SYM_FUNC_START(fill_handler_87)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=87
        }
SYM_FUNC_END(fill_handler_87)

SYM_FUNC_START(fill_handler_88)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=88
        }
SYM_FUNC_END(fill_handler_88)

SYM_FUNC_START(fill_handler_89)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=89
        }
SYM_FUNC_END(fill_handler_89)

SYM_FUNC_START(fill_handler_90)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=90
        }
SYM_FUNC_END(fill_handler_90)

SYM_FUNC_START(fill_handler_91)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=91
        }
SYM_FUNC_END(fill_handler_91)

SYM_FUNC_START(fill_handler_92)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=92
        }
SYM_FUNC_END(fill_handler_92)

SYM_FUNC_START(fill_handler_93)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=93
        }
SYM_FUNC_END(fill_handler_93)

SYM_FUNC_START(fill_handler_94)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=94
        }
SYM_FUNC_END(fill_handler_94)

SYM_FUNC_START(fill_handler_95)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=95
        }
SYM_FUNC_END(fill_handler_95)

SYM_FUNC_START(fill_handler_96)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=96
        }
SYM_FUNC_END(fill_handler_96)

SYM_FUNC_START(fill_handler_97)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=97
        }
SYM_FUNC_END(fill_handler_97)

SYM_FUNC_START(fill_handler_98)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=98
        }
SYM_FUNC_END(fill_handler_98)

SYM_FUNC_START(fill_handler_99)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=99
        }
SYM_FUNC_END(fill_handler_99)

SYM_FUNC_START(fill_handler_100)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=100
        }
SYM_FUNC_END(fill_handler_100)

SYM_FUNC_START(fill_handler_101)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=101
        }
SYM_FUNC_END(fill_handler_101)

SYM_FUNC_START(fill_handler_102)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=102
        }
SYM_FUNC_END(fill_handler_102)

SYM_FUNC_START(fill_handler_103)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=103
        }
SYM_FUNC_END(fill_handler_103)

SYM_FUNC_START(fill_handler_104)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=104
        }
SYM_FUNC_END(fill_handler_104)

SYM_FUNC_START(fill_handler_105)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=105
        }
SYM_FUNC_END(fill_handler_105)

SYM_FUNC_START(fill_handler_106)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=106
        }
SYM_FUNC_END(fill_handler_106)

SYM_FUNC_START(fill_handler_107)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=107
        }
SYM_FUNC_END(fill_handler_107)

SYM_FUNC_START(fill_handler_108)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=108
        }
SYM_FUNC_END(fill_handler_108)

SYM_FUNC_START(fill_handler_109)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=109
        }
SYM_FUNC_END(fill_handler_109)

SYM_FUNC_START(fill_handler_110)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=110
        }
SYM_FUNC_END(fill_handler_110)

SYM_FUNC_START(fill_handler_111)
        {
                movtd GVCPUSTATE, %ctpr1
        }
        {
                call %ctpr1, wbs=111
        }
SYM_FUNC_END(fill_handler_111)
