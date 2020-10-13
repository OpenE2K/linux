#include <stdio.h>
#include <stdlib.h>
#include "ttable_wbs.h"

#define B "\t\t\""
#define E "\\n\" \\\n"

enum {
	TYPE_INTERRUPT,
	TYPE_SYSCALL,
	TYPE_SYSCALL_PROT
};


static int return_printed;
static void print_header(int rbs, int rsz, int type)
{
	printf(B "{" E);
	printf(B "setbn rbs=%d, rsz=%d, rcur=0" E, rbs, rsz);
	if (type != TYPE_INTERRUPT && !return_printed) {
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
		break;
	case TYPE_SYSCALL:
		keep = 1;
		break;
	case TYPE_SYSCALL_PROT:
		keep = 4;
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
			print_header(0, (regs < 64) ? (regs - 1) : 63, type);
		}
		if (i == 64) {
			bn = 0;
			print_header(64, regs - 64 - 1, type);
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
		printf(B "{nop 3} {done}" E);
	} else {
		/* System call return */
		printf(B "{" E);
		printf(B "ct %%%%ctpr3" E);
		printf(B "}" E);
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
	print_clear_macro("CLEAR_TTABLE_ENTRY_10_WINDOW",
			  TTABLE_ENTRY_10_SIZE, TYPE_SYSCALL);
	print_clear_macro("CLEAR_TTABLE_ENTRY_10_WINDOW_PROT",
			  TTABLE_ENTRY_10_SIZE, TYPE_SYSCALL_PROT);
	print_clear_macro("CLEAR_HARD_SYS_CALLS_WINDOW",
			  HARD_SYS_CALLS_SIZE, TYPE_SYSCALL);
	print_clear_macro("CLEAR_SIMPLE_SYS_CALLS_WINDOW",
			  SIMPLE_SYS_CALLS_SIZE, TYPE_SYSCALL);

	return 0;
}
