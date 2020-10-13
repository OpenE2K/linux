#include <asm/asm-offsets.h>

/*
 * This function cannot be implemented in C because we don't know whether
 * the original function that was replaced by this hook should return
 * any value. If it returns value, then it is in dr0-dr7 and these
 * registers should not be changed. There is no way to make compiler
 * obey this in C, so the only solution is to use assembler (assembler
 * is also better performance-wise).
 *
 * dr0-dr7 - original return value, should not be changed
 * db[0] - used to load current->curr_ret_stack and compare it with 0
 * r8 - original value of upsr
 * r9 - new value of upsr
 * db[1] - stores base filed from pcsp.lo
 * db[2] - stores cr_ind field from pcsp.hi
 * db[3] - stores pcshtp
 *
 * (db[1], db[2] and db[3] are used this way only when
 * CONFIG_HAVE_FUNCTION_GRAPH_FP_TEST is set)
 */

/* This is what return_to_hook does:
u64 return_to_hook(u64 dr0, u64 dr1, u64 dr2, u64 dr3,
		u64 dr4, u64 dr5, u64 dr6, u64 dr7)
{
	u64 original_return_point;
	unsigned long flags;
#ifdef CONFIG_HAVE_FUNCTION_GRAPH_FP_TEST
	e2k_pcsp_lo_t pcsp_lo;
	e2k_pcsp_hi_t pcsp_hi;
	e2k_pcshtp_t pcshtp;
	u64 cr_ind;
	u64 base;
#endif

	if (current->curr_ret_stack < 0)
		return;

	raw_all_irq_save(flags);
#ifdef CONFIG_HAVE_FUNCTION_GRAPH_FP_TEST
	pcsp_lo = READ_PCSP_LO_REG();
	pcsp_hi = READ_PCSP_HI_REG();
	base = AS(pcsp_lo).base;
	cr_ind = AS_STRUCT(pcsp_hi).ind;
	pcshtp = READ_PCSHTP_REG_SVALUE();

	original_return_point = ftrace_return_to_handler(base +
			cr_ind + pcshtp);
#else
	original_return_point = ftrace_return_to_handler(0);
#endif
	E2K_SET_DSREG(cr0.hi, original_return_point);
	raw_all_irq_restore(flags);
}*/

.global return_to_hook
.type return_to_hook,@function
return_to_hook:
{
	setwd wsz = 0x9, nfx = 0x1
	/* Allocate space for the first argument
	 * of ftrace_return_to_handler(). */
	getsp -16, %empty
	setbn rsz = 0x3, rbs = 0x5, rcur = 0x0
}
{
	rrs %upsr, %r8

	disp %ctpr1, $ftrace_return_to_handler

	/* Avoid touching dr0-dr7, use r8, r9 and db[] instead */
	ldw [ %g17 + TSK_CURR_RET_STACK ], %b[0]
}
{
	nop 2

	cmplsb %b[0], 0, %pred0

	return %ctpr3
	ipd 0
}
{
	ands %r8, _f16s,_lts0lo 0xff5f, %r9

	ct %ctpr3 ? %pred0
}
{
	nop 4
	rws %r9, %upsr
}
#ifdef CONFIG_HAVE_FUNCTION_GRAPH_FP_TEST
	rrd %pcshtp, %db[3]
	rrd %pcsp.lo, %db[1]
{
	rrd %pcsp.hi, %db[2]
	shld %db[3], 53, %db[3]
}
{
	andd %db[1], 0x0000ffffffffffff, %db[1]
	sard %db[3], 53, %db[3]
}
{
	addd %db[3], %db[1], %db[0]
	getfd %db[2], _f16s,_lts0hi 0x6800, %db[2]
}
{
	/* There must be three commands between reading pcsp and a call */
	addd %db[0], %db[2], %db[0]
}
{
	call %ctpr1, wbs = 0x5
}
#else
	/* db[0] is initialized already and it's
	 * value in this case does not matter. */
	call %ctpr1, wbs = 0x5
#endif
	/* Order is important: first we change cr0.hi
	 * and then use it in return. */
	rwd %db[0], %cr0.hi
{
	nop 4
	ipd 2
	return %ctpr3
	rws %r8, %upsr
}
	ct %ctpr3
.size return_to_hook, .-return_to_hook
.global panic_ftrace_graph_cr
.global return_to_handler_0
return_to_handler_0:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=0
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=0
.global return_to_handler_1
return_to_handler_1:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=1
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=1
.global return_to_handler_2
return_to_handler_2:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=2
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=2
.global return_to_handler_3
return_to_handler_3:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=3
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=3
.global return_to_handler_4
return_to_handler_4:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=4
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=4
.global return_to_handler_5
return_to_handler_5:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=5
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=5
.global return_to_handler_6
return_to_handler_6:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=6
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=6
.global return_to_handler_7
return_to_handler_7:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=7
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=7
.global return_to_handler_8
return_to_handler_8:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=8
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=8
.global return_to_handler_9
return_to_handler_9:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=9
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=9
.global return_to_handler_10
return_to_handler_10:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=10
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=10
.global return_to_handler_11
return_to_handler_11:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=11
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=11
.global return_to_handler_12
return_to_handler_12:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=12
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=12
.global return_to_handler_13
return_to_handler_13:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=13
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=13
.global return_to_handler_14
return_to_handler_14:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=14
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=14
.global return_to_handler_15
return_to_handler_15:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=15
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=15
.global return_to_handler_16
return_to_handler_16:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=16
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=16
.global return_to_handler_17
return_to_handler_17:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=17
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=17
.global return_to_handler_18
return_to_handler_18:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=18
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=18
.global return_to_handler_19
return_to_handler_19:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=19
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=19
.global return_to_handler_20
return_to_handler_20:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=20
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=20
.global return_to_handler_21
return_to_handler_21:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=21
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=21
.global return_to_handler_22
return_to_handler_22:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=22
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=22
.global return_to_handler_23
return_to_handler_23:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=23
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=23
.global return_to_handler_24
return_to_handler_24:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=24
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=24
.global return_to_handler_25
return_to_handler_25:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=25
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=25
.global return_to_handler_26
return_to_handler_26:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=26
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=26
.global return_to_handler_27
return_to_handler_27:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=27
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=27
.global return_to_handler_28
return_to_handler_28:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=28
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=28
.global return_to_handler_29
return_to_handler_29:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=29
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=29
.global return_to_handler_30
return_to_handler_30:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=30
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=30
.global return_to_handler_31
return_to_handler_31:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=31
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=31
.global return_to_handler_32
return_to_handler_32:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=32
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=32
.global return_to_handler_33
return_to_handler_33:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=33
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=33
.global return_to_handler_34
return_to_handler_34:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=34
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=34
.global return_to_handler_35
return_to_handler_35:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=35
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=35
.global return_to_handler_36
return_to_handler_36:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=36
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=36
.global return_to_handler_37
return_to_handler_37:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=37
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=37
.global return_to_handler_38
return_to_handler_38:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=38
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=38
.global return_to_handler_39
return_to_handler_39:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=39
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=39
.global return_to_handler_40
return_to_handler_40:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=40
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=40
.global return_to_handler_41
return_to_handler_41:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=41
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=41
.global return_to_handler_42
return_to_handler_42:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=42
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=42
.global return_to_handler_43
return_to_handler_43:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=43
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=43
.global return_to_handler_44
return_to_handler_44:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=44
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=44
.global return_to_handler_45
return_to_handler_45:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=45
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=45
.global return_to_handler_46
return_to_handler_46:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=46
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=46
.global return_to_handler_47
return_to_handler_47:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=47
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=47
.global return_to_handler_48
return_to_handler_48:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=48
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=48
.global return_to_handler_49
return_to_handler_49:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=49
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=49
.global return_to_handler_50
return_to_handler_50:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=50
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=50
.global return_to_handler_51
return_to_handler_51:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=51
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=51
.global return_to_handler_52
return_to_handler_52:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=52
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=52
.global return_to_handler_53
return_to_handler_53:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=53
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=53
.global return_to_handler_54
return_to_handler_54:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=54
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=54
.global return_to_handler_55
return_to_handler_55:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=55
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=55
.global return_to_handler_56
return_to_handler_56:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=56
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=56
.global return_to_handler_57
return_to_handler_57:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=57
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=57
.global return_to_handler_58
return_to_handler_58:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=58
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=58
.global return_to_handler_59
return_to_handler_59:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=59
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=59
.global return_to_handler_60
return_to_handler_60:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=60
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=60
.global return_to_handler_61
return_to_handler_61:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=61
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=61
.global return_to_handler_62
return_to_handler_62:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=62
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=62
.global return_to_handler_63
return_to_handler_63:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=63
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=63
.global return_to_handler_64
return_to_handler_64:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=64
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=64
.global return_to_handler_65
return_to_handler_65:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=65
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=65
.global return_to_handler_66
return_to_handler_66:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=66
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=66
.global return_to_handler_67
return_to_handler_67:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=67
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=67
.global return_to_handler_68
return_to_handler_68:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=68
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=68
.global return_to_handler_69
return_to_handler_69:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=69
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=69
.global return_to_handler_70
return_to_handler_70:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=70
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=70
.global return_to_handler_71
return_to_handler_71:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=71
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=71
.global return_to_handler_72
return_to_handler_72:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=72
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=72
.global return_to_handler_73
return_to_handler_73:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=73
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=73
.global return_to_handler_74
return_to_handler_74:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=74
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=74
.global return_to_handler_75
return_to_handler_75:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=75
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=75
.global return_to_handler_76
return_to_handler_76:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=76
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=76
.global return_to_handler_77
return_to_handler_77:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=77
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=77
.global return_to_handler_78
return_to_handler_78:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=78
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=78
.global return_to_handler_79
return_to_handler_79:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=79
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=79
.global return_to_handler_80
return_to_handler_80:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=80
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=80
.global return_to_handler_81
return_to_handler_81:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=81
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=81
.global return_to_handler_82
return_to_handler_82:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=82
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=82
.global return_to_handler_83
return_to_handler_83:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=83
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=83
.global return_to_handler_84
return_to_handler_84:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=84
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=84
.global return_to_handler_85
return_to_handler_85:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=85
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=85
.global return_to_handler_86
return_to_handler_86:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=86
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=86
.global return_to_handler_87
return_to_handler_87:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=87
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=87
.global return_to_handler_88
return_to_handler_88:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=88
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=88
.global return_to_handler_89
return_to_handler_89:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=89
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=89
.global return_to_handler_90
return_to_handler_90:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=90
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=90
.global return_to_handler_91
return_to_handler_91:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=91
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=91
.global return_to_handler_92
return_to_handler_92:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=92
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=92
.global return_to_handler_93
return_to_handler_93:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=93
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=93
.global return_to_handler_94
return_to_handler_94:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=94
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=94
.global return_to_handler_95
return_to_handler_95:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=95
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=95
.global return_to_handler_96
return_to_handler_96:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=96
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=96
.global return_to_handler_97
return_to_handler_97:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=97
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=97
.global return_to_handler_98
return_to_handler_98:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=98
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=98
.global return_to_handler_99
return_to_handler_99:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=99
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=99
.global return_to_handler_100
return_to_handler_100:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=100
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=100
.global return_to_handler_101
return_to_handler_101:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=101
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=101
.global return_to_handler_102
return_to_handler_102:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=102
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=102
.global return_to_handler_103
return_to_handler_103:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=103
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=103
.global return_to_handler_104
return_to_handler_104:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=104
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=104
.global return_to_handler_105
return_to_handler_105:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=105
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=105
.global return_to_handler_106
return_to_handler_106:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=106
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=106
.global return_to_handler_107
return_to_handler_107:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=107
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=107
.global return_to_handler_108
return_to_handler_108:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=108
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=108
.global return_to_handler_109
return_to_handler_109:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=109
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=109
.global return_to_handler_110
return_to_handler_110:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=110
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=110
.global return_to_handler_111
return_to_handler_111:
	disp %ctpr1, return_to_hook
	call %ctpr1, wbs=111
	disp %ctpr1, panic_ftrace_graph_cr
	call %ctpr1, wbs=111
