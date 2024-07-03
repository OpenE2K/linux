/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <stdio.h>
#include <stdlib.h>

#include "../../../include/generated/autoconf.h"
#include "ttable_wbs.h"

#define B "\t\t\""
#define E "\\n\" \\\n"

enum {
	TYPE_INTERRUPT,
	TYPE_SYSCALL,
	TYPE_SYSCALL_PROT,
	TYPE_SETBN
};


static int return_printed;
static void print_header(int wsz, int rbs, int rsz, int type)
{
	printf(B "{" E);
	if (!(type == TYPE_SETBN))
		printf(B "setwd wsz=%d" E, wsz);
	printf(B "setbn rbs=%d, rsz=%d, rcur=0" E, rbs, rsz);
	if ((type == TYPE_SYSCALL || type == TYPE_SYSCALL_PROT) &&
			!return_printed) {
		return_printed = 1;
		printf(B "return %%%%ctpr3" E);
	}
	if (type == TYPE_SYSCALL_PROT) {
		printf(B "puttagd %%[_r2], %%[_tag2], %%%%dr2" E);
		printf(B "puttagd %%[_r3], %%[_tag3], %%%%dr3" E);
		printf(B "addd %%[_r0], 0, %%%%dr0" E);
		printf(B "addd %%[_r1], 0, %%%%dr1" E);
	}
	if (type == TYPE_SYSCALL)
		printf(B "addd %%[_r0], 0, %%%%dr0" E);
	printf(B "}" E);
}

/*
 * @name - macro name
 * @regs - number of *quadro* registers to clear
 * @keep - number of *double* registers to keep
 * @interrupt - should we use "done" or "return" + "ct" to return
 */
static void print_clear_macro(char *name, int regs, int type)
{
	int i, bn = 0, keep;

	return_printed = 0;

	switch (type) {
	case TYPE_INTERRUPT:
		keep = 0;
		if (regs < FINISH_USER_TRAP_HANDLER_SW_FILL_SIZE)
			regs = FINISH_USER_TRAP_HANDLER_SW_FILL_SIZE;
		break;
	case TYPE_SYSCALL:
		keep = 1;
		if (regs < FINISH_SYSCALL_SW_FILL_SIZE)
			regs = FINISH_SYSCALL_SW_FILL_SIZE;
		break;
	case TYPE_SYSCALL_PROT:
		keep = 4;
		if (regs < FINISH_SYSCALL_SW_FILL_SIZE)
			regs = FINISH_SYSCALL_SW_FILL_SIZE;
		break;
	default:
		exit(1);
	}

	printf("#define %s(", name);
	for (i = 0; i < keep; i++)
		printf("r%d%s", i, (i + 1 != keep) ? ", " : "");
	if (type == TYPE_SYSCALL_PROT)
		printf(", tag2, tag3");
	printf( ") \\\n"
		"do { \\\n"
		"\tasm volatile ( \\\n");

	for (i = 0; i < regs; i++) {
		if (i == 0) {
			bn = 0;
			print_header(regs, 0, (regs < 64) ? (regs - 1) : 63, type);
		}
		if (i == 63) {
			bn = 0;
			print_header(regs, 63, regs - 63 - 1, TYPE_SETBN);
		}
		if ((bn % 3) == 0)
			printf(B "{" E);

		if (2 * i >= keep)
			printf(B "addd 0, 0, %%%%db[%d]" E, 2 * bn);

		if (2 * i + 1 >= keep)
			printf(B "addd 0, 0, %%%%db[%d]" E, 2 * bn + 1);

		if ((bn % 3) == 2 || i + 1 == regs)
			printf(B "}" E);

		++bn;
	}

	if (type == TYPE_INTERRUPT) {
		/* #80747: must repeat interrupted barriers */
		printf(B "{wait st_c=1} {nop 2; mmurw %%%%db[0], %%%%dam_inv} {done}" E);
	} else {
		/* System call return */
		printf(B "{nop 2; mmurw %%%%db[0], %%%%dam_inv}" E);
		printf(B "{ct %%%%ctpr3}" E);
	}

	printf("\t\t::");
	for (i = 0; i < keep; i++)
		printf(" [_r%d] \"ir\" (r%d)%s",
				i, i, (i + 1 != keep) ? "," : "");
	if (type == TYPE_SYSCALL_PROT)
		printf(", \\\n\t\t[_tag2] \"ir\" (tag2), [_tag3] \"ir\" (tag3)");
	printf(" \\\n\t\t: \"ctpr3\"");
	printf("); \\\n");
	printf("} while (0)\n");
}

int main(void)
{
	print_clear_macro("CLEAR_USER_TRAP_HANDLER_WINDOW",
			  USER_TRAP_HANDLER_SIZE, TYPE_INTERRUPT);
#ifdef CONFIG_PROTECTED_MODE
	print_clear_macro("CLEAR_TTABLE_ENTRY_8_WINDOW",
			  TTABLE_ENTRY_8_SIZE, TYPE_SYSCALL);
	print_clear_macro("CLEAR_TTABLE_ENTRY_8_WINDOW_PROT",
			  TTABLE_ENTRY_8_SIZE, TYPE_SYSCALL_PROT);
#endif
	print_clear_macro("CLEAR_RET_FROM_FORK_WINDOW",
			  RET_FROM_FORK_SIZE, TYPE_SYSCALL);
	print_clear_macro("CLEAR_HANDLE_SYS_CALL_WINDOW",
			  HANDLE_SYS_CALL_SIZE, TYPE_SYSCALL);
	print_clear_macro("CLEAR_DO_SIGRETURN_INTERRUPT",
			  DO_SIGRETURN_SIZE, TYPE_INTERRUPT);
	print_clear_macro("CLEAR_DO_SIGRETURN_SYSCALL",
			  DO_SIGRETURN_SIZE, TYPE_SYSCALL);
	print_clear_macro("CLEAR_DO_SIGRETURN_SYSCALL_PROT",
			  DO_SIGRETURN_SIZE, TYPE_SYSCALL_PROT);
#ifdef CONFIG_KVM_HOST_MODE
	print_clear_macro("CLEAR_RETURN_PV_VCPU_TRAP_WINDOW",
			  RETURN_PV_VCPU_TRAP_SIZE, TYPE_INTERRUPT);
	print_clear_macro("CLEAR_HANDLE_PV_VCPU_SYS_CALL_WINDOW",
			  HANDLE_PV_VCPU_SYS_CALL_SIZE, TYPE_SYSCALL);
	print_clear_macro("CLEAR_HANDLE_PV_VCPU_SYS_FORK_WINDOW",
			  HANDLE_PV_VCPU_SYS_FORK_SIZE, TYPE_SYSCALL);
#endif

	return 0;
}
