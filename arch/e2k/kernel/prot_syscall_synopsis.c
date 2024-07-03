/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <asm/e2k_ptypes.h>
#include <asm/unistd.h>
#include <asm/protected_mode.h>
#include <asm/time.h>
#include <asm/prot_loader.h>
#include <asm/ucontext.h>
#include <asm-generic/statfs.h>
#include <asm/prot_compat.h>
#include <asm/signal.h>
#include <asm/prot_signal.h>
#include <asm-generic/poll.h>
#include <linux/utime.h>
#include <linux/time.h>
#include <linux/times.h>
#include <linux/resource.h>
#include <linux/uio.h>
#include <linux/capability.h>
#include <uapi/asm/stat.h>
#include <uapi/linux/aio_abi.h>
#include <uapi/linux/io_uring.h>
#include <uapi/linux/msg.h>
#include <uapi/linux/sched/types.h>
#include <uapi/linux/time.h>

/*
 * Following table specifies types (or masks) of protected syscall arguments.
 * These data are used by initial pre-processing of system call arguments
 * (for details see function ttable_entry*_C (ttable.c and related stuff).
 *
 * Format:
 *         <mask>, / *   syscall    #     <legend>   * / size1,..,size6
 * NB> Mask is hexadecimal expression of the bitmask binary value.
 * NB> Bits in the bitmask (byte per argument) get coded right to left
 *					 starting with the bit #4 so that:
 *     - bit  #0    is SIZE_ADJUSTMENT bit (see below);
 *     - bit  #1    is NEGATIVE_DESCRIPTOR_SIZE_ALLOWED bit (see below);
 *     - bits #2-7  unused for the moment;
 *     - bits #8-15  define type of system call argument #1;
 *     - bits #16-23 define type of system call argument #2;
 *     - bits #24-31 define type of system call argument #3; ...
 *                                 and so forth thru arg #6;
 *     - bits #56-63 - unused for the moment.
 * NB> Arg mask consists of argument type (bits 0..3) and flags (bits 4..7).
 * NB> Arg type mnemonic legend:
 *     - upper case character means argument is mandatory;
 *     - lower case character means argument is optional.
 *     Upper cases only are used in the comments below.
 * NB> Arg mask codes:
 *     o bits 0..3: argument type
 *       - arg type codes (see the legend below) are:
 *		0(L) / 1(P) / 2(?) / 3(S) / 4(I) / 5(F) / 6(S/L) / 7(S/i) / 8(P/I) / 0xF(X);
 *		NB> S/L - 'String' or 'Long';
 *		    S/i - 'String' or 'int';
 *		    P/I - 'Pointer' or 'Int';
 *		    '?' - 'Pointer' or 'Long'.
 *     o bits 4..7: flags
 *       - bit #4: this is non-empty argument (mandatory);
 *       - bit #5: unused;
 *       - bit #6: unused;
 *       - bit #7: this is optional argument (may be empty/uninitialized).
 * NB> Legend describes type of signal call arguments; left-to-right;
 *                                         starting with argument #1:
 *     'L' - is for 'long' - this argument gets passed as-is
 *                                to system call handler function;
 *     'P' - is for 'pointer' - this argument would be pre-processed in
 *              ttable_entry8_C to convert 'long' pointer descriptor used in
 *              the protected mode into the 'short' one used by kernel;
 *     '?' - may be either 'pointer' or 'long' depending on other arguments;
 *     'S' - is for string descriptor;
 *     'I' - is for 'int';
 *     'F' - pointer to function (function label);
 *     'X' - the agrument and those that follow don't exist.
 *     For example: LSLP legend is coded a system call like:
 *                               syscall( long, <string>, long, <pointer> ).
 *     Optional args are enclosed in curly brackets.
 * NB> Size(i) specifies minimum required size for syscall argument (i).
 * NB> Negative size means the actual value to be taken from the corresponding
 *     syscall argument. For example, size2 value '-3' means the minimum size
 *     for syscall argument #2 is provided thru argument #3 of the system call.
 *     If the actual value appears greater than the size of the corresponding
 *                  descriptor argument, and SIZE_ADJUSTMENT bit is set to'1',
 *                  then the actual size is set to the size of the descriptor.
 * NB> If an argument-descriptor has negative size (i.e. size < offset), and
 *     NEGATIVE_DESCRIPTOR_SIZE_ALLOWED bit is not empty, warning to be issued;
 *     if NEGATIVE_DESCRIPTOR_SIZE_ALLOWED bit is empty, error to be issued.
 * NB> Element [NR_syscalls] contains default mask for empty lines in the table.
 */
const struct prot_syscall_arg_attrs prot_syscall_arg_masks[NR_syscalls + 1] = {
	[__NR_exit] =
		{ 0xFFFFFFFFFF0400,	/*	exit	1	IX	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_read] =
		{ 0xFFFFFF00010401,	/*	read	3	IPL	*/
					0, -3, 0, 0, 0, 0 },
	[__NR_write] =
		{ 0xFFFFFF00010401,	/*	write	4	IPL	*/
					0, -3, 0, 0, 0, 0 },
	[__NR_open] =
		{ 0xFFFFFF84041300,	/*	open	5	SI{I}	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_close] =
		{ 0xFFFFFFFFFF0400,	/*	close	6	IX	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_waitpid] =
		{ 0xFFFFFF04010400,	/*	waitpid	7	IPI	*/
					0, sizeof(int), 0, 0, 0, 0 },
	[__NR_creat] =
		{ 0xFFFFFFFF041300,	/*	creat	8	SI	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_link] =
		{ 0xFFFFFFFF030300,	/*	link	9	SS	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_unlink] =
		{ 0xFFFFFFFFFF0300,	/*	unlink	10	SX	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_execve] =
		{ 0xFFFFFF01010300,	/*	execve	11	SPP	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_chdir] =
		{ 0xFFFFFFFFFF1300,	/*	chdir	12	SX	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_time] =
		{ 0xFFFFFFFFFF0100,	/*	time	13	PX	*/
					sizeof(__kernel_old_time_t), 0, 0, 0, 0, 0 },
	[__NR_mknod] =
		{ 0xFFFFFF00040300,	/*	mknod	14	SIL	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_chmod] =
		{ 0xFFFFFFFF041300,	/*	chmod	15	SI	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_lchown] =
		{ 0xFFFFFF00000300,	/*	lchown	16	SLL	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_break] =
		{ 0xFFFFFFFFFFFF00,	/*	break	17	XX	ni_syscall */
					0, 0, 0, 0, 0, 0 },
	[__NR_oldstat] =
		{ 0xFFFFFFFFFFFF00,	/*	oldstat	18	SP	ni_syscall */
					0, 0, 0, 0, 0, 0 },
	[__NR_lseek] =
		{ 0xFFFFFF04000400,	/*	lseek	19	ILI	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_mount] =
		{ 0xFF010003030300,	/*	mount	21	SSSLP	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_umount] =
		{ 0xFFFFFFFFFF0300,	/*	umount	22	SX	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_setuid] =
		{ 0xFFFFFFFFFF0400,	/*	setuid	23	IX	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_stime] =
		{ 0xFFFFFFFFFF0100,	/*	stime	25	PX	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_ptrace] =
		{ 0xFFFF0202040000,	/*	ptrace 26	LI??	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_alarm] =
		{ 0xFFFFFFFFFF0400,	/*	alarm	27	IX	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_oldfstat] =
		{ 0xFFFFFFFFFFFF00,	/*	oldfstat 28	LP	ni_syscall */
					0, 0, 0, 0, 0, 0 },
	[__NR_pause] =
		{ 0xFFFFFFFFFFFF00,	/*	pause	29	XX	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_utime] =
		{ 0xFFFFFFFF010300,	/*	utime	30	SP	*/
					0, sizeof(struct utimbuf), 0, 0, 0, 0 },
	[__NR_stty] =
		{ 0xFFFFFFFFFFFF00,	/*	stty	31		ni_syscall */
					0, 0, 0, 0, 0, 0 },
	[__NR_gtty] =
		{ 0xFFFFFFFFFFFF00,	/*	gtty	32		ni_syscall */
					0, 0, 0, 0, 0, 0 },
	[__NR_access] =
		{ 0xFFFFFFFF040300,	/*	access	33	SI	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_nice] =
		{ 0xFFFFFFFFFF0400,	/*	nice	34	IX	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_ftime] =
		{ 0xFFFFFFFFFFFF00,	/*	ftime	35	PX	ni_syscall */
					0, 0, 0, 0, 0, 0 },
	[__NR_sync] =
		{ 0xFFFFFFFFFFFF00,	/*	sync	36	XX	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_kill] =
		{ 0xFFFFFFFF040400,	/*	kill	37	II	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_rename] =
		{ 0xFFFFFFFF030300,	/*	rename	38	SS	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_mkdir] =
		{ 0xFFFFFFFF041300,	/*	mkdir	39	SI	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_rmdir] =
		{ 0xFFFFFFFFFF0300,	/*	rmdir	40	SX	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_dup] =
		{ 0xFFFFFFFFFF0400,	/*	dup	41	IX	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_pipe] =
		{ 0xFFFFFFFFFF0100,	/*	pipe	42	PX	*/
					sizeof(int), 0, 0, 0, 0, 0 },
	[__NR_times] =
		{ 0xFFFFFFFFFF0100,	/*	times	43	PX	*/
					sizeof(struct tms), 0, 0, 0, 0, 0 },
	[__NR_prof] =
		{ 0xFFFFFFFFFFFF00,	/*	prof	44		ni_syscall */
					0, 0, 0, 0, 0, 0 },
	[__NR_brk] =
		{ 0xFFFFFFFFFFFF00,	/*	brk	45	?X	ni_syscall */
					0, 0, 0, 0, 0, 0 },
	[__NR_setgid] =
		{ 0xFFFFFFFFFF0400,	/*	setgid	46	IX	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_getgid] =
		{ 0xFFFFFFFFFFFF00,	/*	getgid	47	XX	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_signal] =
		{ 0xFFFFFFFFFFFF00,	/*	signal	48	LP	ni_syscall */
					0, 0, 0, 0, 0, 0 },
	[__NR_geteuid] =
		{ 0xFFFFFFFFFFFF00,	/*	geteuid	49	XX	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_getegid] =
		{ 0xFFFFFFFFFFFF00,	/*	getegid	50	XX	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_acct] =
		{ 0xFFFFFFFFFF0300,	/*	acct	51	SX	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_umount2] =
		{ 0xFFFFFFFF040300,	/*	umount2	52	SI	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_ioctl] =
		{ 0xFFFFFF02000400,	/*	ioctl	54	IL?	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_fcntl] =
		{ 0xFFFFFF02040400,	/*	fcntl	55	II?	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_setpgid] =
		{ 0xFFFFFFFF040400,	/*	setpgid	57	II	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_ulimit] =
		{ 0xFFFFFFFFFFFF00,	/*	ulimit	58	LL	ni_syscall */
					0, 0, 0, 0, 0, 0 },
	[__NR_oldolduname] =
		{ 0xFFFFFFFFFFFF00,	/* oldolduname 59	PX	ni_syscall */
					0, 0, 0, 0, 0, 0 },
	[__NR_umask] =
		{ 0xFFFFFFFFFF0400,	/*	umask	60	IX	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_chroot] =
		{ 0xFFFFFFFFFF0300,	/*	chroot	61	SX	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_ustat] =
		{ 0xFFFFFFFF010400,	/*	ustat	62	IP	*/
					0, sizeof(struct ustat), 0, 0, 0, 0 },
	[__NR_dup2] =
		{ 0xFFFFFFFF040400,	/*	dup2	63	II	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_getppid] =
		{ 0xFFFFFFFFFFFF00,	/*	getppid	64	XX	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_getpgrp] =
		{ 0xFFFFFFFFFFFF00,	/*	getpgrp	65	XX	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_setsid] =
		{ 0xFFFFFFFFFFFF00,	/*	setsid	66	XX	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_sigaction] =
		{ 0xFFFFFFFFFFFF00,	/*	sigaction 67	LPP	ni_syscall */
					0, 0, 0, 0, 0, 0 },
	[__NR_sgetmask] =
		{ 0xFFFFFFFFFFFF00,	/*	sgetmask 68	XX	ni_syscall */
					0, 0, 0, 0, 0, 0 },
	[__NR_ssetmask] =
		{ 0xFFFFFFFFFFFF00,	/*	ssetmask 69	LX	ni_syscall */
					0, 0, 0, 0, 0, 0 },
	[__NR_setreuid] =
		{ 0xFFFFFFFF040400,	/*	setreuid 70	II	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_setregid] =
		{ 0xFFFFFFFF040400,	/*	setregid 71	II	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_sigsuspend] =
		{ 0xFFFFFFFFFFFF00,	/* sigsuspend	72	PX	ni_syscall */
					0, 0, 0, 0, 0, 0 },
	[__NR_sigpending] =
		{ 0xFFFFFFFFFF0100,	/* sigpending	73	PX	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_sethostname] =
		{ 0xFFFFFFFF040300,	/* sethostname	74	SI	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_setrlimit] =
		{ 0xFFFFFFFF010400,	/* setrlimit	75	IP	*/
					0, sizeof(struct rlimit), 0, 0, 0, 0 },
	[__NR_getrlimit] =
		{ 0xFFFFFFFF010400,	/* getrlimit	76	IP	*/
					0, sizeof(struct rlimit), 0, 0, 0, 0 },
	[__NR_getrusage] =
		{ 0xFFFFFFFF010400,	/* getrusage	77	IP	*/
					0, sizeof(struct rusage), 0, 0, 0, 0 },
	[__NR_gettimeofday] =
		{ 0xFFFFFFFF010100,	/* gettimeofday	78	PP	*/
					sizeof(struct __kernel_old_timeval),
					sizeof(struct timezone), 0, 0, 0, 0 },
	[__NR_settimeofday] =
		{ 0xFFFFFFFF010100,	/* settimeofday	79	PP	*/
					sizeof(struct __kernel_old_timeval),
					sizeof(struct timezone), 0, 0, 0, 0 },
	[__NR_getgroups] =
		{ 0xFFFFFFFF010400,	/* getgroups	80	IP	*/
					0, sizeof(gid_t), 0, 0, 0, 0 },
	[__NR_setgroups] =
		{ 0xFFFFFFFF010400,	/*	setgroups 81	IP	*/
					0, sizeof(gid_t), 0, 0, 0, 0 },
	[__NR_select] =
		{ 0xFF010101010400,	/*	select	82	IPPPP	*/
/* NB> See comment to the '_newselect' syscall below. */
					0,   0,   0,   0,
					sizeof(struct __kernel_old_timeval), 0 },
	[__NR_symlink] =
		{ 0xFFFFFFFF031300,	/*	symlink	83		SS	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_oldlstat] =
		{ 0xFFFFFFFFFFFF00,	/*	oldlstat 84		ni_syscall */
					0, 88, 0, 0, 0, 0 },
	[__NR_readlink] =
		{ 0xFFFFFF04011301,	/*	readlink 85		SPI	*/
					0, -3, 0, 0, 0, 0 },
	[__NR_uselib] =
		{ 0xFFFFFFFFFFFF00,	/*	uselib 86		SP	*/
					0, sizeof(umdd_t), 0, 0, 0, 0 },
	[__NR_swapon] =
		{ 0xFFFFFFFF040300,	/*	swapon	87		SI	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_reboot] =
		{ 0xFFFF8104040400,	/*	reboot	88		IIIP	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_readdir] =
		{ 0xFFFFFF04010400,	/*	readdir	89		IPI	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_mmap] =
		{ 0x00000000000202,	/*	mmap	90		?LLLLL	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_munmap] =
		{ 0xFFFFFFFF000101,	/*	munmap	91		PL	*/
					-2, 0, 0, 0, 0, 0 },
	[__NR_truncate] =
		{ 0xFFFFFFFF001300,	/*	truncate 92		SL	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_ftruncate] =
		{ 0xFFFFFFFF000400,	/*	ftruncate 93		IL	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_fchmod] =
		{ 0xFFFFFFFF040400,	/*	fchmod	94		II	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_fchown] =
		{ 0xFFFFFF04040400,	/*	fchown	95		III	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_getpriority] =
		{ 0xFFFFFFFF040400,	/* getpriority 96		II	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_setpriority] =
		{ 0xFFFFFF04040400,	/* setpriority	97		III	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_profil] =
		{ 0xFFFFFFFFFFFF00,	/*	profil	98		PLLL	ni_syscall */
					0, 0, 0, 0, 0, 0 },
	[__NR_statfs] =
		{ 0xFFFFFFFF011300,	/*	statfs	99		SP	*/
					0, sizeof(struct statfs), 0, 0, 0, 0 },
	[__NR_fstatfs] =
		{ 0xFFFFFFFF010400,	/*	fstatfs	100		IP	*/
					0, sizeof(struct statfs), 0, 0, 0, 0 },
	[__NR_ioperm] =
		{ 0xFFFFFF04000000,	/*	ioperm	101		LLI	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_socketcall] =
		{ 0xFFFFFFFF010400,	/*	socketcall 102		IP	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_syslog] =
		{ 0xFFFFFF04010401,	/*	syslog	103		IPI	*/
					0, -3, 0, 0, 0, 0 },
	[__NR_setitimer] =
		{ 0xFFFFFF01010400,	/*	setitimer 104		IPP	*/
					0,
					sizeof(struct __kernel_old_itimerval),
					sizeof(struct __kernel_old_itimerval),
					0, 0, 0 },
	[__NR_getitimer] =
		{ 0xFFFFFFFF010400,	/*	getitimer 105		IP	*/
					0,
					sizeof(struct __kernel_old_itimerval),
					0, 0, 0, 0 },
	[__NR_stat] =
		{ 0xFFFFFFFF011300,	/*	stat	106		SP	*/
					0, sizeof(struct stat), 0, 0, 0, 0 },
	[__NR_lstat] =
		{ 0xFFFFFFFF011300,	/*	lstat	107		SP	*/
					0, sizeof(struct stat), 0, 0, 0, 0 },
	[__NR_fstat] =
		{ 0xFFFFFFFF010400,	/*	fstat	108		IP	*/
					0, sizeof(struct stat), 0, 0, 0, 0 },
	[__NR_olduname] =
		{ 0xFFFFFFFFFF0100,	/*	olduname 109		PX	*/
					325, 0, 0, 0, 0, 0 },
	[__NR_iopl] =
		{ 0xFFFFFFFFFFFF00,	/*	iopl	110		LX	ni_syscall */
					0, 0, 0, 0, 0, 0 },
	[__NR_vhangup] =
		{ 0xFFFFFFFFFFFF00,	/*	vhangup	111		XX	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_idle] =
		{ 0xFFFFFFFFFFFF00,	/*	idle	112		ni_syscall */
					0, 0, 0, 0, 0, 0 },
	[__NR_vm86old] =
		{ 0xFFFFFFFFFFFF00,	/*	vm86old	113		ni_syscall */
					0, 0, 0, 0, 0, 0 },
	[__NR_wait4] =
		{ 0xFFFF0104010400,	/*	wait4	114		IPIP	*/
					0, 4, 0, 144, 0, 0 },
	[__NR_swapoff] =
		{ 0xFFFFFFFFFF0300,	/*	swapoff	115		SX	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_sysinfo] =
		{ 0xFFFFFFFFFF0100,	/*	sysinfo	116		PX	*/
					sizeof(struct sysinfo), 0, 0, 0, 0, 0 },
	[__NR_ipc] =
		{ 0x80810200040400,	/*	ipc	117		IIL?pl	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_fsync] =
		{ 0xFFFFFFFFFF0400,	/*	fsync	118		IX	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_sigreturn] =
		{ 0xFFFFFFFFFFFF00,	/*	sigreturn 119		ni_syscall */
					0, 0, 0, 0, 0, 0 },
	[__NR_clone] =
		{ 0xFF828181010000,	/*	clone	120		LPpp?	*/
					0, 0, 0, 0, 4, 0 },
	[__NR_setdomainname] =
		{ 0xFFFFFFFF040101,	/* setdomainname 121		PI	*/
					-2, 0, 0, 0, 0, 0 },
	[__NR_uname] =
		{ 0xFFFFFFFFFF0100,	/*	uname	122		PX	*/
					390, 0, 0, 0, 0, 0 },
	[__NR_modify_ldt] =
		{ 0xFFFFFFFFFFFF00,	/* modify_ldt	123	LPL	ni_syscall */
					0, 0, 0, 0, 0, 0 },
	[__NR_adjtimex] =
		{ 0xFFFFFFFFFF0100,	/*	adjtimex 124		PX	*/
					sizeof(struct __kernel_timex), 0, 0, 0, 0, 0 },
	[__NR_mprotect] =
		{ 0xFFFFFF04000101,	/*	mprotect 125		PLI	*/
					-2, 0, 0, 0, 0, 0 },
	[__NR_sigprocmask] =
		{ 0xFFFFFF01010400,	/* sigprocmask	126		IPP	*/
					0, 8, 8, 0, 0, 0 },
	[__NR_init_module] =
		{ 0xFFFFFF03000100,	/* init_module	128		PLS	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_delete_module] =
		{ 0xFFFFFFFF040300,	/* delete_module 129		SI	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_get_kernel_syms] =
		{ 0xFFFFFFFFFFFF00,	/* get_kernel_syms 130		ni_syscall */
					0, 0, 0, 0, 0, 0 },
	[__NR_quotactl] =
		{ 0xFFFF0104030400,	/*	quotactl 131		ISIP	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_getpgid] =
		{ 0xFFFFFFFFFF0400,	/*	getpgid	132		IX	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_fchdir] =
		{ 0xFFFFFFFFFF0400,	/*	fchdir	133		IX	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_bdflush] =
		{ 0xFFFFFFFF000400,	/*	bdflush	134		IL [Obsolete] */
					0, 0, 0, 0, 0, 0 },
	[__NR_sysfs] =
		{ 0xFFFFFF81870400,	/*	sysfs	135		i?s	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_personality] =
		{ 0xFFFFFFFFFF0400,	/* personality	136		IX	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_afs_syscall] =
		{ 0xFFFFFFFFFFFF00,	/*	afs_syscall 137		ni_syscall */
					0, 0, 0, 0, 0, 0 },
	[__NR_setfsuid] =
		{ 0xFFFFFFFFFF0400,	/*	setfsuid 138		IX	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_setfsgid] =
		{ 0xFFFFFFFFFF0400,	/*	setfsgid 139		IX	*/
					0, 0, 0, 0, 0, 0 },
	[__NR__llseek] =
		{ 0xFF040100000400,	/*	_llseek	140		ILLPI	*/
					0, 0, 0, 8, 0, 0 },
	[__NR_getdents] =
		{ 0xFFFFFF04010401,	/*	getdents 141		IPI	*/
					0, -3, 0, 0, 0, 0 },
	[__NR__newselect] =
		{ 0xFF010101010400,	/*	_newselect 142		IPPPP	*/
/*					0,
 *					sizeof(fd_set), sizeof(fd_set), sizeof(fd_set),
 *					sizeof(struct timeval),
 *					0 },
 *	NB> "The Linux kernel allows file descriptor sets of arbitrary size, determining
 *	     the length of the sets to be checked from the value of nfds." (Linux Pages)
 *	NB> Real array size in args 2-3-4 is defined by arg#1.
 *		Size may be smaller than the kernel structure size.
 */
					0,   0,   0,   0,
					sizeof(struct __kernel_old_timeval), 0 },
	[__NR_flock] =
		{ 0xFFFFFFFF040400,	/*	flock	143		II	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_msync] =
		{ 0xFFFFFF04000100,	/*	msync	144		PLI	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_readv] =
		{ 0xFFFFFF00010000,	/*	readv	145		LPL	*/
					0, sizeof(struct iovec), 0, 0, 0, 0 },
	[__NR_writev] =
		{ 0xFFFFFF00010000,	/*	writev	146		LPL	*/
					0, sizeof(struct iovec), 0, 0, 0, 0 },
	[__NR_getsid] =
		{ 0xFFFFFFFFFF0400,	/*	getsid	147		IX	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_fdatasync] =
		{ 0xFFFFFFFFFF0400,	/*	fdatasync 148		IX	*/
					0, 0, 0, 0, 0, 0 },
	[__NR__sysctl] =
		{ 0xFFFFFFFFFFFF00,	/*	_sysctl	149		PX	ni_syscall */
					128, 0, 0, 0, 0, 0 },
	[__NR_mlock] =
		{ 0xFFFFFFFF000200,	/*	mlock	150		?L	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_munlock] =
		{ 0xFFFFFFFF000200,	/*	munlock	151		?L	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_mlockall] =
		{ 0xFFFFFFFFFF0400,	/*	mlockall 152		IX	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_sched_setparam] =
		{ 0xFFFFFFFF010400,	/* sched_setparam 154		IP	*/
					0, sizeof(struct sched_param), 0, 0, 0, 0 },
	[__NR_sched_getparam] =
		{ 0xFFFFFFFF010400,	/* sched_getparam 155		IP	*/
					0, sizeof(struct sched_param), 0, 0, 0, 0 },
	[__NR_sched_setscheduler] =
		{ 0xFFFFFF01040400,	/* sched_setscheduler 156	IIP	*/
					0, 0, sizeof(struct sched_param), 0, 0, 0 },
	[__NR_sched_getscheduler] =
		{ 0xFFFFFFFFFF0400,	/* sched_getscheduler 157	IX	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_sched_yield] =
		{ 0xFFFFFFFFFFFF00,	/* sched_yield	158		XX	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_sched_get_priority_max] =
		{ 0xFFFFFFFFFF0400,	/* sched_get_priority_max 159	IX	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_sched_get_priority_min] =
		{ 0xFFFFFFFFFF0400,	/* sched_get_priority_min 160	IX	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_sched_rr_get_interval] =
		{ 0xFFFFFFFF010400,	/* sched_rr_get_interval 161	IP	*/
					0, sizeof(struct __kernel_timespec), 0, 0, 0, 0 },
	[__NR_nanosleep] =
		{ 0xFFFFFFFF010100,	/*	nanosleep 162		PP	*/
					sizeof(struct __kernel_timespec),
					sizeof(struct __kernel_timespec),
					0, 0, 0, 0 },
	[__NR_mremap] =
		{ 0xFF020000000100,	/*	mremap	163		PLLL?	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_setresuid] =
		{ 0xFFFFFF04040400,	/*	setresuid 164		III	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_getresuid] =
		{ 0xFFFFFF01010100,	/*	getresuid 165		PPP	*/
					sizeof(uid_t), sizeof(uid_t), sizeof(uid_t), 0, 0, 0 },
	[__NR_vm86] =
		{ 0xFFFFFFFFFFFF00,	/*	vm86	166		ni_syscall */
					0, 0, 0, 0, 0, 0 },
	[__NR_query_module] =
		{ 0xFFFFFFFFFFFF00,	/* query_module	167		PLPLP	ni_syscall */
					0, 0, 0, 0, 0, 0 },
	[__NR_poll] =
		{ 0xFFFFFF04040100,	/*	poll	168		PII	*/
					sizeof(struct pollfd), 0, 0, 0, 0, 0 },
	[__NR_nfsservctl] =
		{ 0xFFFFFFFFFFFF00,	/* nfsservctl	169		LPP	ni_syscall */
					0, 0, 0, 0, 0, 0 },
	[__NR_setresgid] =
		{ 0xFFFFFF04040400,	/*	setresgid 170		III	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_getresgid] =
		{ 0xFFFFFF01010100,	/*	getresgid 171		PPP	*/
					sizeof(gid_t), sizeof(gid_t), sizeof(gid_t), 0, 0, 0 },
	[__NR_prctl] =
		{ 0xFF808282820400,	/*	prctl	172		I???l	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_rt_sigreturn] =
		{ 0xFFFFFFFFFFFF00,	/* rt_sigreturn 173		ni_syscall */
					0, 0, 0, 0, 0, 0 },
	[__NR_rt_sigaction] =
		{ 0xFFFF0001010400,	/* rt_sigaction	174		IPPL	*/
					0,
					sizeof(struct prot_sigaction),
					sizeof(struct prot_sigaction), 0, 0, 0 },
	[__NR_rt_sigprocmask] =
		{ 0xFFFF0001010400,	/* rt_sigprocmask 175		IPPL	*/
					0, sizeof(sigset_t), sizeof(sigset_t), 0, 0, 0 },
	[__NR_rt_sigpending] =
		{ 0xFFFFFFFF000100,	/* rt_sigpending 176		PL	*/
					-2, 0, 0, 0, 0, 0 },
	[__NR_rt_sigtimedwait] =
		{ 0xFFFF0001010100,	/* rt_sigtimedwait 177		PPPL	*/
					sizeof(sigset_t),
					sizeof(struct prot_siginfo),
					sizeof(struct __kernel_timespec), 0, 0, 0 },
	[__NR_rt_sigqueueinfo] =
		{ 0xFFFFFF01040400,	/* rt_sigqueueinfo 178		IIP	*/
					0, 0, sizeof(struct prot_siginfo), 0, 0, 0 },
	[__NR_rt_sigsuspend] =
		{ 0xFFFFFFFF000100,	/* rt_sigsuspend 179		PL	*/
					-2, 0, 0, 0, 0, 0 },
	[__NR_pread] =
		{ 0xFFFF0000010401,	/*	pread	180		IPLL	*/
					0, -3, 0, 0, 0, 0 },
	[__NR_pwrite] =
		{ 0xFFFF0000010401,	/*	pwrite	181		IPLL	*/
					0, -3, 0, 0, 0, 0 },
	[__NR_chown] =
		{ 0xFFFFFF04040300,	/*	chown	182		SII	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_getcwd] =
		{ 0xFFFFFFFF000101,	/*	getcwd	183		PL	*/
					-2, 0, 0, 0, 0, 0 },
	[__NR_capget] =
		{ 0xFFFFFFFF010100,	/*	capget	184		PP	*/
					sizeof(cap_user_header_t), sizeof(cap_user_data_t),
					0, 0, 0, 0 },
	[__NR_capset] =
		{ 0xFFFFFFFF010100,	/*	capset	185		PP	*/
					sizeof(cap_user_header_t), sizeof(cap_user_data_t),
					0, 0, 0, 0 },
	[__NR_sigaltstack] =
		{ 0xFFFFFFFF010100,	/* sigaltstack	186		PP	*/
					sizeof(struct prot_stack),
					sizeof(struct prot_stack),
					0, 0, 0, 0 },
	[__NR_sendfile] =
		{ 0xFFFF0001040400,	/* sendfile	187		IIPL	*/
					0, 0, sizeof(off_t), 0, 0, 0 },
	[__NR_getpmsg] =
		{ 0xFFFFFFFFFFFF00,	/*	getpmsg	188		ni_syscall */
					0, 0, 0, 0, 0, 0 },
	[__NR_putpmsg] =
		{ 0xFFFFFFFFFFFF00,	/*	putpmsg	189		ni_syscall */
					0, 0, 0, 0, 0, 0 },
	[__NR_vfork] =
		{ 0xFFFFFFFFFFFF00,	/*	vfork	190		XX	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_ugetrlimit] =
		{ 0xFFFFFFFF010400,	/* ugetrlimit	191		IP	*/
					0, sizeof(struct rlimit), 0, 0, 0, 0 },
	[__NR_mmap2] =
		{ 0x00040404000200,	/*	mmap2	192		?LIIIL	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_truncate64] =
		{ 0xFFFFFFFFFFFF00,	/* truncate64 193		ni_syscall */
					0, 0, 0, 0, 0, 0 },
	[__NR_ftruncate64] =
		{ 0xFFFFFFFFFFFF00,	/* ftruncate64 194		ni_syscall */
					0, 0, 0, 0, 0, 0 },
	[__NR_stat64] =
		{ 0xFFFFFFFF010300,	/*	stat64	195		SP	*/
					0, sizeof(struct stat), 0, 0, 0, 0 },
	[__NR_lstat64] =
		{ 0xFFFFFFFF010300,	/*	lstat64	196		SP	*/
					0, sizeof(struct stat), 0, 0, 0, 0 },
	[__NR_fstat64] =
		{ 0xFFFFFFFF010000,	/*	fstat64	197		LP	*/
					0, sizeof(struct stat), 0, 0, 0, 0 },

	[__NR_pidfd_send_signal] =
		{ 0xFFFF0401040400,	/* pidfd_send_signal 205	IIPI	*/
					0, 0, sizeof(struct prot_siginfo), 0, 0, 0 },
	[__NR_pidfd_open] =
		{ 0xFFFFFFFF040400,	/*	pidfd_open 206		II	*/
					0, 0, 0, 0, 0, 0 },

	/* NB> Temporal stuff; remove it as soon as syscall numbers get fixed in glibc */
	[198] =	{ 0xFFFFFF04040300,	/*	lchown32	198	Sii	*/},
	[199] =	{ 0xFFFFFFFFFFFF00,	/*	getuid32	199	XX	*/},
	[200] =	{ 0xFFFFFFFFFFFF00,	/*	getgid32	200	XX	*/},
	[201] =	{ 0xFFFFFFFFFFFF00,	/*	geteuid32	201	XX	*/},
	[202] =	{ 0xFFFFFFFFFFFF00,	/*	getegid32	202	XX	*/},
	[203] =	{ 0xFFFFFFFF040400,	/*	setreuid32	203	ii	*/},
	[204] =	{ 0xFFFFFFFF040400,	/*	setregid32	204	ii	*/},

	[207] =	{ 0xFFFFFF04040400,	/*	fchown32	207	iii	*/},
	[208] =	{ 0xFFFFFF04040400,	/*	setresuid32	208	iii	*/},
	[209] =	{ 0xFFFFFF01010100,	/*	getresuid32	209	PPP	*/},
	[210] =	{ 0xFFFFFF04040400,	/*	setresgid32	210	iii	*/},
	[211] =	{ 0xFFFFFF01010100,	/*	getresgid32	211	PPP	*/},
	[212] =	{ 0xFFFFFF04040300,	/*	chown32	212		Sii	*/},
	[213] =	{ 0xFFFFFFFFFF0400,	/*	setuid32 213		iX	*/},
	[214] =	{ 0xFFFFFFFFFF0400,	/*	setgid32 214		iX	*/},
	[215] =	{ 0xFFFFFFFFFF0400,	/*	setfsuid32 215		iX	*/},
	[216] =	{ 0xFFFFFFFFFF0400,	/*	setfsgid32 216		iX	*/},

	[__NR_pivot_root] =
		{ 0xFFFFFFFF030300,	/*	pivot_root 217		SS	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_mincore] =
		{ 0xFFFFFF01000200,	/*	mincore	218		?LP	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_madvise] =
		{ 0xFFFFFF04000101,	/*	madvise	219		PLI	*/
					-2, 0, 0, 0, 0, 0 },
	/* NB> Linux notes on madvise:
	 *     If there are some parts of the specified address range that are not mapped,
	 *     the Linux version of madvise() ignores them and applies the call to the
	 *     rest (but returns ENOMEM from the system call, as it should).
	 */
	[__NR_getdents64] =
		{ 0xFFFFFF04010401,	/*	getdents64 220		IPI	*/
					0, -3, 0, 0, 0, 0 },
	[__NR_fcntl64] =
		{ 0xFFFFFF02040400,	/*	fcntl64	221		II?	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_macctl] =
		{ 0xFFFFFF04010400,	/*	macctl	223		IPI	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_newfstatat] =
		{ 0xFFFF0401030400,	/*	newfstatat 224		ISPI	*/
					0, 0, sizeof(struct stat), 0, 0, 0 },
	[__NR_e2k_syswork] =
	/* NB> This syscall must not work in the protected execution mode */
		{ 0xFFFFFFFFFFFF00,	/*	e2k_syswork 228		XXXXXX	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_e2k_longjmp2] =
		{ 0xFFFFFFFF000100,	/*	e2k_longjmp2	230	PL	*/
					sizeof(e2k_jmp_info_t), 0, 0, 0, 0, 0 },
	[__NR_setxattr] =
		{ 0xFF040001030301,	/*	setxattr	232	SSPLI	*/
					0, 0, -4, 0, 0, 0 },
	[__NR_lsetxattr] =
		{ 0xFF040001030301,	/*	lsetxattr	233	SSPLI	*/
					0, 0, -4, 0, 0, 0 },
	[__NR_fsetxattr] =
		{ 0xFF040001030401,	/*	fsetxattr	234	ISPLI	*/
					0, 0, -4, 0, 0, 0 },
	[__NR_getxattr] =
		{ 0xFFFF0001030301,	/*	getxattr	235	SSPL	*/
					0, 0, -4, 0, 0, 0 },
	[__NR_lgetxattr] =
		{ 0xFFFF0001030301,	/*	lgetxattr	236	SSPL	*/
					0, 0, -4, 0, 0, 0 },
	[__NR_fgetxattr] =
		{ 0xFFFF0001030401,	/*	fgetxattr	237	ISPL	*/
					0, 0, -4, 0, 0, 0 },
	[__NR_listxattr] =
		{ 0xFFFFFF00010300,	/*	listxattr	238	SPL	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_llistxattr] =
		{ 0xFFFFFF00010300,	/*	llistxattr	239	SPL	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_flistxattr] =
		{ 0xFFFFFF00010400,	/*	flistxattr	240	IPL	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_removexattr] =
		{ 0xFFFFFFFF030300,	/*	removexattr	241	SS	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_lremovexattr] =
		{ 0xFFFFFFFF030300,	/*	lremovexattr	242	SS	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_fremovexattr] =
		{ 0xFFFFFFFF030400,	/*	fremovexattr	243	IS	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_readahead] =
		{ 0xFFFFFF00000400,	/*	readahead	245	ILL	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_tkill] =
		{ 0xFFFFFFFF040400,	/*	tkill	246		II	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_sendfile64] =
		{ 0xFFFF0001040400,	/* sendfile64	247		IIPL	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_futex] = /* NB> args 4,5 are checked in the syscall wrapper */
		{ 0x84828884040100,	/*	futex	248		PII{??i} */
					sizeof(uint32_t), 0, 0,
					sizeof(struct __kernel_timespec),
					sizeof(uint32_t), 0 },
	[__NR_sched_setaffinity] =
		{ 0xFFFFFF01040400,	/* sched_setaffinity 249	IIP	*/
					0, 0, -2, 0, 0, 0 },
	[__NR_sched_getaffinity] =
		{ 0xFFFFFF01040400,	/* sched_getaffinity 250	IIP	*/
					0, 0, -2, 0, 0, 0 },
	[__NR_pipe2] =
		{ 0xFFFFFFFF040100,	/*	pipe2	251		PI	*/
					2 * sizeof(int), 0, 0, 0, 0, 0 },
	[__NR_set_backtrace] =
		{ 0xFFFF0000000100,	/*	set_backtrace 252	PLLL	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_get_backtrace] =
		{ 0xFFFF0000000100,	/*	get_backtrace 253	PLLL	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_access_hw_stacks] =
		{ 0xFF010001010000,	/*	access_hw_stacks 254	LPPLP	*/
					0, sizeof(unsigned long long), -4,
					0, sizeof(unsigned long), 0 },
	[__NR_el_posix] =
		{ 0xFF040202020400,	/*	el_posix	255	I???I	*/
					0, 0, 0, 0, 0, 0 },

	[__NR_io_uring_setup] =		{ 0xFFFFFFFF010400, /* #256	IP	*/
					0, sizeof(struct io_uring_params), 0, 0, 0, 0 },

	[__NR_io_uring_enter] =		{ 0x00010404040400, /* #257	IIIIPL	*/
					0, 0, 0, 0, sizeof(sigset_t), 0 },

	[__NR_io_uring_register] =	{ 0xFFFF0402040400, /* #258	IIPI	*/
					0, 0, 0, 0, 0, 0 },

	[__NR_set_tid_address] =
		{ 0xFFFFFFFFFF0100,	/*	set_tid_address	259	PX	*/
					sizeof(int), 0, 0, 0, 0, 0 },
	[__NR_timer_create] =
		{ 0xFFFFFF01010400,	/*	timer_create	261	IPP	*/
					0,
					sizeof(struct prot_sigevent),
					sizeof(timer_t), 0, 0, 0 },
	[__NR_timer_settime] =
		{ 0xFFFF0101040400,	/* timer_settime 262		IIPP	*/
					0, 0,
					sizeof(struct __kernel_itimerspec),
					sizeof(struct __kernel_itimerspec), 0, 0 },
	[__NR_timer_gettime] =
		{ 0xFFFFFFFF010400,	/* timer_gettime 263		IP	*/
					0, sizeof(struct __kernel_itimerspec), 0, 0, 0, 0 },
	[__NR_timer_getoverrun] =
		{ 0xFFFFFFFFFF0400,	/* timer_getoverrun 264		IX	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_timer_delete] =
		{ 0xFFFFFFFFFF0400,	/* timer_delete	265		IX	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_clock_settime] =
		{ 0xFFFFFFFF010400,	/* clock_settime 266		IP	*/
					0, sizeof(struct __kernel_timespec), 0, 0, 0, 0 },
	[__NR_clock_gettime] =
		{ 0xFFFFFFFF010400,	/* clock_gettime 267		IP	*/
					0, sizeof(struct __kernel_timespec), 0, 0, 0, 0 },
	[__NR_clock_getres] =
		{ 0xFFFFFFFF010400,	/* clock_getres	268		IP	*/
					0, sizeof(struct __kernel_timespec), 0, 0, 0, 0 },
	[__NR_clock_nanosleep] =
		{ 0xFFFF0101040400,	/* clock_nanosleep 269		IIPP	*/
					0, 0,
					sizeof(struct __kernel_timespec),
					sizeof(struct __kernel_timespec), 0, 0 },
	[__NR_msgget] =
		{ 0xFFFFFFFF040400,	/*	msgget	270		II	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_msgctl] =
		{ 0xFFFFFF01040400,	/*	msgctl	271		IIP	*/
					0, 0, sizeof(struct msqid_ds), 0, 0, 0 },
	[__NR_msgrcv] =
		{ 0xFF040000010400,	/*	msgrcv	272		IPLLI	*/
					0, sizeof(struct msgbuf), 0, 0, 0, 0 },
	[__NR_msgsnd] =
		{ 0xFFFF0400010400,	/*	msgsnd	273		IPLI	*/
					0, sizeof(struct msgbuf), 0, 0, 0, 0 },
	[__NR_semget] =
		{ 0xFFFFFF04040400,	/*	semget	274		III	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_semctl] =
		{ 0xFFFF0204040400,	/*	semctl	275		III?	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_semtimedop] =
		{ 0xFFFF0104010400,	/* semtimedop	276		IPIP	*/
					0,
					sizeof(struct sembuf), 0,
					sizeof(struct __kernel_timespec), 0, 0 },
	[__NR_semop] =
		{ 0xFFFFFF00010400,	/*	semop	277		IPL	*/
					0, sizeof(struct sembuf), 0, 0, 0, 0 },
	[__NR_shmget] =
		{ 0xFFFFFF04000400,	/*	shmget	278		ILI	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_shmctl] =
		{ 0xFFFFFF01040400,	/*	shmctl	279		IIP	*/
					0, 0, sizeof(struct shmid_ds), 0, 0, 0 },
	[__NR_shmat] =
		{ 0xFFFFFF04020400,	/*	shmat	280		i?i	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_shmdt] =
		{ 0xFFFFFFFFFF0100,	/*	shmdt	281		P	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_open_tree] =
		{ 0xFFFFFF04030400,	/*	open_tree 282		ISI	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_move_mount] =
		{ 0xFF040304030400,	/*	move_mount 283		ISISI */
					0, 0, 0, 0, 0, 0 },

	[__NR_accept4] =
		{ 0xFFFF0401010400,	/*	accept4	286		IPPI	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_sched_setattr] =
		{ 0xFFFFFF04010400,	/* sched_setattr 287		IPI	*/
					0, SCHED_ATTR_SIZE_VER0, 0, 0, 0, 0 },
	[__NR_sched_getattr] =
		{ 0xFFFF0404010400,	/* sched_getattr 288		IPII	*/
					0, SCHED_ATTR_SIZE_VER0, 0, 0, 0, 0 },
	[__NR_ioprio_set] =
		{ 0xFFFFFF04040400,	/* ioprio_set	289		III	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_ioprio_get] =
		{ 0xFFFFFFFF040400,	/* ioprio_get	290		II	*/
					0, 0, 0, 0, 0, 0 },

	[__NR_inotify_add_watch] =
		{ 0xFFFFFF04030400,	/* inotify_add_watch 292	ISI	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_inotify_rm_watch] =
		{ 0xFFFFFFFF040400,	/* inotify_rm_watch 293		II	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_io_setup] =
		{ 0xFFFFFFFF010400,	/*	io_setup 294		IP	*/
					0, sizeof(aio_context_t), 0, 0, 0, 0 },
	[__NR_io_destroy] =
		{ 0xFFFFFFFFFF0000,	/*	io_destroy 295		LX	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_io_getevents] =
		{ 0xFF010100000000,	/*	io_getevents 296	LLLPP	*/
					0, 0, 0,
					sizeof(struct io_event),
					sizeof(struct __kernel_timespec), 0 },
	[__NR_io_submit] =
		{ 0xFFFFFF01000000,	/*	io_submit 297		LLP	*/
		/* NB> Size of the argument #3 is checked in the syscall wrapper function */
					0, 0, 0, 0, 0, 0 },
	[__NR_io_cancel] =
		{ 0xFFFFFF01010000,	/*	io_cancel 298		LPP	*/
					0,
					sizeof(struct iocb),
					sizeof(struct io_event), 0, 0, 0 },
	[__NR_fadvise64] =
		{ 0xFFFF0400000400,	/*	fadvise64 299		ILLI	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_exit_group] =
		{ 0xFFFFFFFFFF0400,	/* exit_group	300		IX	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_lookup_dcookie] =
		{ 0xFFFFFF00010000,	/* lookup_dcookie 301		LPL	*/
					0, -3, 0, 0, 0, 0 },
	[__NR_epoll_create] =
		{ 0xFFFFFFFFFF0400,	/* epoll_create	302		IX	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_epoll_ctl] =
		{ 0xFFFF0104040400,	/*	epoll_ctl 303		IIIP	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_epoll_wait] =
		{ 0xFFFF0404010400,	/* epoll_wait	304		IPII	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_remap_file_pages] =
		{ 0xFF000000000100,	/* remap_file_pages 305		PLLLL	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_statfs64] =
		{ 0xFFFFFF01000300,	/*	statfs64 306		SLP	*/
					0, 0, sizeof(struct statfs), 0, 0, 0 },
	[__NR_fstatfs64] =
		{ 0xFFFFFF01000400,	/*	fstatfs64 307		ILP	*/
					0, 0, sizeof(struct statfs64), 0, 0, 0 },
	[__NR_tgkill] =
		{ 0xFFFFFF04040400,	/*	tgkill	308		III	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_utimes] =
		{ 0xFFFFFFFF010300,	/*	utimes	309		SP	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_fadvise64_64] =
		{ 0xFFFF0400000400,	/*	fadvise64_64 310	ILLI	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_mbind] =
		{ 0x04000100000100,	/*	mbind	312		PLLPLI	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_get_mempolicy] =
		{ 0xFF000000010100,	/*	get_mempolicy 313	PPLLL	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_set_mempolicy] =
		{ 0xFFFFFF00010400,	/*	set_mempolicy 314	IPL	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_mq_open] =
		{ 0xFFFF0104040300,	/*	mq_open	315		SIIP	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_mq_unlink] =
		{ 0xFFFFFFFFFF0300,	/* mq_unlink       (__NR_mq_open+1) SX	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_mq_timedsend] =
		{ 0xFF010400010400,	/* mq_timedsend    (__NR_mq_open+2) IPLIP */
					0, 0, 0, 0, 0, 0 },
	[__NR_mq_timedreceive] =
		{ 0xFF010100010400,	/* mq_timedreceive (__NR_mq_open+3) IPLPP */
					0, 0, 0, 0, 0, 0 },
	[__NR_mq_notify] =
		{ 0xFFFFFFFF010400,	/*	mq_notify  (__NR_mq_open+4)  IP	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_mq_getsetattr] =
		{ 0xFFFFFF01010400,	/* mq_getsetattr   (__NR_mq_open+5) IPP	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_kexec_load] =
		{ 0xFFFF0001000000,	/*	kexec_load	321	LLPL	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_waitid] =
		{ 0xFF010401040400,	/*	waitid	322		IIPIP	*/
					0, 0, 128, 0, sizeof(struct rusage), 0 },
	[__NR_add_key] =
		{ 0xFF040001030301,	/*	add_key	323		SSPLI	*/
					0, 0, 0, -4, 0, 0 },
	[__NR_request_key] =
		{ 0xFFFF0401010100,	/* request_key	324		PPPI	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_keyctl] =
		{ 0xFF020202020400,	/*	keyctl	325		i????	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_getcpu] =
		{ 0xFFFFFF01010100,	/*	getcpu	327		PPP	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_move_pages] =
		{ 0x04010101000000,	/*	move_pages 328		LLPPPI	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_splice] =
		{ 0x04000104010400,	/*	splice	329		IPIPLI	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_vmsplice] =
		{ 0xFFFF0400010400,	/*	vmsplice 330		IPLI	*/
					0, 24, 0, 0, 0, 0 },
	[__NR_tee] =
		{ 0xFFFF0400040400,	/*	tee	331		IILI	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_migrate_pages] =
		{ 0xFFFF0101000400,	/* migrate_pages 332		ILPP	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_utimensat] =
		{ 0xFFFF0401010400,	/*	utimensat 333		IPPI	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_rt_tgsigqueueinfo] =
		{ 0xFFFF0104040400,	/* rt_tgsigqueueinfo 334	IIIP	*/
					0, 0, 0, sizeof(struct prot_siginfo), 0, 0 },
	[__NR_openat] =
		{ 0xFFFF0404030400,	/*	openat	335		ISII	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_mkdirat] =
		{ 0xFFFFFF04030400,	/*	mkdirat	336		ISI	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_mknodat] =
		{ 0xFFFF0404030400,	/*	mknodat	337		ISII	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_fchownat] =
		{ 0xFF040404030400,	/*	fchownat 338		ISIII	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_unlinkat] =
		{ 0xFFFFFF04030400,	/*	unlinkat 339		ISI	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_renameat] =
		{ 0xFFFF0304030400,	/*	renameat 340		ISIS	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_linkat] =
		{ 0xFF040304030400,	/*	linkat	341		ISISI	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_symlinkat] =
		{ 0xFFFFFF03040300,	/*	symlinkat 342		SIS	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_readlinkat] =
		{ 0xFFFF0401030401,	/*	readlinkat 343		ISPI	*/
					0, 0, -4, 0, 0, 0 },
	[__NR_fchmodat] =
		{ 0xFFFFFF04030400,	/*	fchmodat 344		ISI	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_faccessat] =
		{ 0xFFFFFF04030400,	/*	faccessat 345		ISI	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_epoll_pwait] =
		{ 0x00010404010400,	/*	epoll_pwait 346		IPIIPL	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_signalfd4] =
		{ 0xFFFF0400010400,	/*	signalfd4 347		IPLI	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_eventfd2] =
		{ 0xFFFFFFFF040400,	/*	eventfd2 348		II	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_recvmmsg] =
		{ 0xFF010404010400,	/*	recvmmsg 349		IPIIP	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_timerfd_create] =
		{ 0xFFFFFFFF040400,	/* timerfd_create 351		II	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_timerfd_settime] =
		{ 0xFFFF0101040400,	/* timerfd_settime 352		IIPP	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_timerfd_gettime] =
		{ 0xFFFFFFFF010400,	/* timerfd_gettime 353		IP	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_preadv] =
		{ 0xFF000000010000,	/*	preadv	354		LPLLL	*/
					0, 32, 0, 0, 0, 0 },
	[__NR_pwritev] =
		{ 0xFF000000010000,	/*	pwritev	355		LPLLL	*/
					0, 32, 0, 0, 0, 0 },
	[__NR_fallocate] =
		{ 0xFFFF0000040400,	/*	fallocate 356		IILL	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_sync_file_range] =
		{ 0xFFFF0400000400,	/* sync_file_range 357		ILLI	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_dup3] =
		{ 0xFFFFFF04040400,	/*	dup3	358		III	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_inotify_init1] =
		{ 0xFFFFFFFFFF0400,	/* inotify_init1 359		IX	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_epoll_create1] =
		{ 0xFFFFFFFFFF0400,	/* epoll_create1 360		IX	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_fstatat64] =
		{ 0xFFFF0401030400,	/*	fstatat64 361		ISPI	*/
					0, 0, 88, 0, 0, 0 },
	[__NR_futimesat] =
		{ 0xFFFFFF01030400,	/*	futimesat 362		ISP	*/
					0, 0, 32, 0, 0, 0 },
	[__NR_perf_event_open] =
		{ 0xFF000404040100,	/* perf_event_open 363		PIIIL	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_unshare] =
		{ 0xFFFFFFFFFF0000,	/*	unshare	364		LX	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_get_robust_list] =
		{ 0xFFFFFF01010400,	/* get_robust_list 365		IPP	*/
					0, 16, 8, 0, 0, 0 },
	[__NR_set_robust_list] =
		{ 0xFFFFFFFF000100,	/* set_robust_list 366		PL	*/
					0x30, 0, 0, 0, 0, 0 },
	[__NR_pselect6] =
		{ 0x01010101010400,	/*	pselect6 367		IPPPPP */
/*					0,
 *					sizeof(fd_set), sizeof(fd_set), sizeof(fd_set),
 *					16, 16 },
 * NB> See comment to the '_newselect' syscall.
 */
					0,   0,   0,   0,
					sizeof(struct __kernel_timespec), 16 },
	[__NR_ppoll] =
		{ 0xFF000101040100,	/*	ppoll	368		PIPPL	*/
					8, 0, 16, 8, 0, 0 },
	[__NR_setcontext] =
		{ 0xFFFFFFFF040100,	/*	setcontext 369		PI	*/
					offsetofend(struct ucontext_prot, uc_extra.pfpfr),
					0, 0, 0, 0, 0 },
	[__NR_makecontext] =
		{ 0xFF040100050100,	/*	makecontext 370		PFLPI	*/
					offsetofend(struct ucontext_prot, uc_extra.pfpfr),
					0, 0, 0, 0, 0 },
	[__NR_swapcontext] =
		{ 0xFFFFFF04010100,	/*	swapcontext 371		PPI	*/
					offsetofend(struct ucontext_prot, uc_extra.pfpfr),
					offsetofend(struct ucontext_prot, uc_extra.pfpfr),
					0, 0, 0, 0 },
	[__NR_freecontext] =
		{ 0xFFFFFFFFFF0100,	/*	freecontext 372		PX	*/
					offsetofend(struct ucontext_prot, uc_extra.pfpfr),
					0, 0, 0, 0, 0 },
	[__NR_fanotify_init] =
		{ 0xFFFFFFFF040400,	/*	fanotify_init 373	II	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_fanotify_mark] =
		{ 0xFF030400040400,	/* fanotify_mark 374		IILIS	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_prlimit64] =
		{ 0xFFFF0101040400,	/*	prlimit64 375		IIPP	*/
					0, 0,
					sizeof(struct rlimit), sizeof(struct rlimit), 0, 0 },
	[__NR_clock_adjtime] =
		{ 0xFFFFFFFF010400,	/*clock_adjtime	376		IP	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_syncfs] =
		{ 0xFFFFFFFFFF0400,	/*	syncfs	377		IX	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_sendmmsg] =
		{ 0xFFFF0404010400,	/*	sendmmsg 378		IPII	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_setns] =
		{ 0xFFFFFFFF040400,	/*	setns	379		II	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_process_vm_readv] =
		{ 0x00000100010400,	/* process_vm_readv 380		IPLPLL	*/
					0, 32, 0, 32, 0, 0 },
	[__NR_process_vm_writev] =
		{ 0x00000100010400,	/* process_vm_writev 381	IPLPLL	*/
					0, 32, 0, 32, 0, 0 },
	[__NR_kcmp] =
		{ 0xFF000004040400,	/*	kcmp	382		IIILL	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_finit_module] =
		{ 0xFFFFFF04030400,	/*	finit_module 383	ISI	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_renameat2] =
		{ 0xFF040304030400,	/*	renameat2 384		ISISI	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_getrandom] =
		{ 0xFFFFFF04000100,	/*	getrandom 385		PLI	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_memfd_create] =
		{ 0xFFFFFFFF040100,	/*	memfd_create 386	PI	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_bpf] =
		{ 0xFFFFFF04010400,	/*	bpf	387		IPI	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_execveat] =
		{ 0xFF040101030400,	/*	execveat 388		ISPPI	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_userfaultfd] =
		{ 0xFFFFFFFFFF0400,	/*	userfaultfd 389		IX	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_membarrier] =
		{ 0xFFFFFFFF040400,	/*	membarrier 390		II	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_mlock2] =
		{ 0xFFFFFF04000200,	/*	mlock2	391		?LI	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_seccomp] =
		{ 0xFFFFFF01040400,	/*	seccomp	392		IIP	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_shutdown] =
		{ 0xFFFFFFFF040400,	/*	shutdown 393		II	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_copy_file_range] =
		{ 0x04000104010400,	/* copy_file_range 394		IPIPLI	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_preadv2] =
		{ 0x00000000010000,	/*	preadv2	395		LPLLLL	*/
					0, 32, 0, 0, 0, 0 },
	[__NR_pwritev2] =
		{ 0x00000000010000,	/*	pwritev2 396		LPLLLL	*/
					0, 32, 0, 0, 0, 0 },

	[__NR_name_to_handle_at] =
		{ 0xFF040101030400,	/* name_to_handle_at 400	ISPPI	*/
					0, 0, 8, 0, 0, 0 },
	[__NR_open_by_handle_at] =
		{ 0xFFFFFF04010400,	/* open_by_handle_at 401	IPI	*/
					0, 8, 0, 0, 0, 0 },
	[__NR_statx] =
		{ 0xFF010404030400,	/*	statx	402		ISIIP	*/
					0, 0, 0, 0, sizeof(struct statx), 0 },
	[__NR_socket] =
		{ 0xFFFFFF04040400,	/*	socket	403		III	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_connect] =
		{ 0xFFFFFF04010400,	/*	connect	404		IPI	*/
					0, sizeof(struct sockaddr), 0, 0, 0, 0 },
	[__NR_accept] =
		{ 0xFFFFFF01010400,	/*	accept	405		IPP	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_sendto] =
		{ 0x04010400010400,	/*	sendto	406		IPLIPI	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_recvfrom] =
		{ 0x01010400010400,	/*	recvfrom 407		IPLIPP	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_sendmsg] =
		{ 0xFFFFFF04010400,	/*	sendmsg	408		IPI	*/
					0, sizeof(struct protected_user_msghdr),
					0, 0, 0, 0 },
	[__NR_recvmsg] =
		{ 0xFFFFFF04010400,	/*	recvmsg	409		IPI	*/
					0, sizeof(struct protected_user_msghdr),
					0, 0, 0, 0 },
	[__NR_bind] =
		{ 0xFFFFFF04010400,	/*	bind	410		IPI	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_listen] =
		{ 0xFFFFFFFF040400,	/*	listen	411		II	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_getsockname] =
		{ 0xFFFFFF01010400,	/*	getsockname 412		IPP	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_getpeername] =
		{ 0xFFFFFF01010400,	/*	getpeername	413	IPP	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_socketpair] =
		{ 0xFFFF0104040400,	/*	socketpair	414	IIIP	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_setsockopt] =
		{ 0xFF040104040400,	/*	setsockopt	415	IIIPI	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_getsockopt] =
		{ 0xFF010104040400,	/*	getsockopt	416	IIIPP	*/
					0, 0, 0, 0, 0, 0 },

	[__NR_arch_prctl] =
		{ 0xFF808282821400,	/*	arch_prctl 419		I???l	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_newuselib] =
		{ 0xFFFFFFFF010300,	/* newuselib	420		SP	*/
					0, sizeof(umdd_t), 0, 0, 0, 0 },
	[__NR_rt_sigaction_ex] =
		{ 0xFFFF0001010400,	/* rt_sigaction_ex 421		IPPL	*/
					0,
					sizeof(struct prot_sigaction),
					sizeof(struct prot_sigaction), 0, 0, 0 },

	[__NR_clean_descriptors] =
		{ 0xFFFFFF00000100,	/* clean_descriptors 424	PLL	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_unuselib] =
		{ 0xFFFFFFFFFF0100,	/*	unuselib 425		PX	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_clone3] =
		{ 0xFFFFFFFF000100,	/*	clone3	426		PL	*/
					-2, 0, 0, 0, 0, 0 },
	[__NR_fsopen] =
		{ 0xFFFFFFFF040300,	/*	fsopen	427		SI	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_fsconfig] =
		{ 0xFF040103040400,	/*	fsconfig 428		IISPI	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_fsmount] =
		{ 0xFFFFFF04040400,	/*	fsmount	429		III	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_fspick] =
		{ 0xFFFFFF04030400,	/*	fspick	430		ISI	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_close_range] =
		{ 0xFFFFFF04040400,	/*	close_range 431		III	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_openat2] =
		{ 0xFFFF0001030400,	/*	openat2 432		ISPL	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_pidfd_getfd] =
		{ 0xFFFFFF04040400,	/*	pidfd_getfd 433		III	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_faccessat2] =
		{ 0xFFFF0404030400,	/*	faccessat2 434		ISII	*/
					0, 0, 0, 0, 0, 0 },
	[__NR_process_madvise] =
		{ 0xFF040400010400,	/* process_madvise 435		IPLII	*/
					0, 0, 0, 0, 0, 0 },
/*
 * NB> The mask below is default mask for syscalls missed in the table above.
 *     The default mask is used in ttable_entry8_C() [arch/e2k/kernel/ttable.c]
 *     !!! DONT REMOVE IT !!!
 */
	[NR_syscalls] =
		{ 0x80808080808000,	/*	default			llllll	*/
					0, 0, 0, 0, 0, 0 }
};

/*
 * System call name table:
 */
const char *sys_call_ID_to_name[NR_syscalls] = {
	"restart_syscall", /* 0 */
	"exit",
	"fork",
	"read",
	"write",
	"open",		/* 5 */
	"close",
	"waitpid",
	"creat",
	"link",
	"unlink",	/* 10 */
	"execve",
	"chdir",
	"time",
	"mknod",
	"chmod",	/* 15 */
	"lchown",
	"old_break",	/* place holder / ni_syscall */
	"old_stat",	/* ditto */
	"lseek",
	"getpid",	/* 20 */
	"mount",
	"oldumount",
	"setuid",
	"getuid",
	"stime",	/* 25 */
	"ptrace",
	"alarm",
	"old_fstat",	/* place holder / ni_syscal */
	"pause",
	"utime",	/* 30 */
	"old_stty",	/* place holder / ni_syscal */
	"old_gtty",	/* ditto */
	"access",
	"nice",
	"old_ftime",	/* 35, place holder / ni_syscal */
	"sync",
	"kill",
	"rename",
	"mkdir",
	"rmdir",	/* 40 */
	"dup",
	"pipe",
	"times",
	"old_prof",	/* place holder / ni_syscal */
	"brk",		/* 45 */
	"setgid",
	"getgid",
	"signal",	/* place holder / ni_syscal / to be emulated by rt_sigaction() */
	"geteuid",
	"getegid",	/* 50 */
	"acct",
	"umount",	/* recycled never used phys() */
	"old_lock",	/* old lock syscall holder */
	"ioctl",

	"fcntl",	/* 55 */

	"old_mpx",	/* place holder / ni_syscal */
	"setpgid",
	"old_ulimit",	/* place holder / ni_syscal */
	"old_olduname",	/* ditto */
	"umask",	/* 60 */
	"chroot",
	"ustat",
	"dup2",
	"getppid",
	"getpgrp",	/* 65 */
	"setsid",
	"sigaction",	/* no sys_sigaction() */
	"sgetmask",
	"ssetmask",
	"setreuid",	/* 70 */
	"setregid",
	"sigsuspend",	/* place holder / ni_syscal */
	"sigpending",
	"sethostname",
	"setrlimit",	/* 75 */
	"old_getrlimit",
	"getrusage",
	"gettimeofday",
	"settimeofday",
	"getgroups",	/* 80 */
	"setgroups",
	"old_select",
	"symlink",
	"old_lstat",	/* place holder / ni_syscal */
	"readlink",	/* 85 */
	"uselib",
	"swapon",
	"reboot",
	"old_readdir",
	"mmap",		/* 90 */
	"munmap",

	"truncate",
	"ftruncate",

	"fchmod",
	"fchown",	/* 95 */
	"getpriority",
	"setpriority",
	"old_profil",	/* place holder / ni_syscal */
	"statfs",
	"fstatfs",	/* 100 */
	"ioperm",
	"socketcall",
	"syslog",
	"setitimer",
	"getitimer",	/* 105 */

	"newstat",	/* in libc used in ptr64 mode */
	"newlstat",	/* in libc used in ptr64 mode */
	"newfstat",	/* in libc used in ptr64 mode */

	"uname",
	"iopl",		/* 110 */
	"vhangup",
	"old_idle",	/* place holder / ni_syscal */
	"vm86old",	/* ditto */
	"wait4",
	"swapoff",	/* 115 */
	"sysinfo",
	"ipc",
	"fsync",
	"sigreturn",	/* place holder / ni_syscal */
	"clone",	/* 120 */
	"setdomainname",
	"newuname",
	"modify_ldt",	/* place holder / ni_syscal */
	"adjtimex",
	"mprotect",	/* 125 */
	"sigprocmask",
	"create_module",/* place holder / ni_syscal */
	"init_module",
	"delete_module",
	"get_kernel_syms", /* 130 / place holder / ni_syscal */
	"quotactl",
	"getpgid",
	"fchdir",
	"bdflush",
	"sysfs",	/* 135 - obsolete */
	"personality",
	"old_afs",	/* place holder / ni_syscal */
	"setfsuid",
	"setfsgid",
	"llseek",	/* 140 */
	"getdents",
	"select",
	"flock",
	"msync",
	"readv",	/* 145 */
	"writev",
	"getsid",
	"fdatasync",
	"_sysctl",
	"mlock",	/* 150 */
	"munlock",
	"mlockall",
	"munlockall",
	"sched_setparam",
	"sched_getparam",   /* 155 */
	"sched_setscheduler",
	"sched_getscheduler",
	"sched_yield",
	"sched_get_priority_max",
	"sched_get_priority_min",  /* 160 */
	"sched_rr_get_interval",
	"nanosleep",
	"mremap",
	"setresuid",
	"getresuid",	/* 165 */
	"vm86",		/* place holder / ni_syscal */
	"query_module",	/* ditto */
	"poll",
	"nfsservctl",	/* 169 place holder / ni_syscal */
	"setresgid",	/* 170 */
	"getresgid",
	"prctl",
	"rt_sigreturn",	/* 173 */
	"rt_sigaction",
	"rt_sigprocmask",	/* 175 */
	"rt_sigpending",
	"rt_sigtimedwait",
	"rt_sigqueueinfo",
	"rt_sigsuspend",
	"pread64",		/* 180 */
	"pwrite64",
	"chown",
	"getcwd",
	"capget",
	"capset",	/* 185 */
	"sigaltstack",
	"sendfile64",
	"getpmsg",	/* 188 place holder / ni_syscal */
	"putpmsg",	/* 189 place holder / ni_syscal */
	"vfork",	/* 190 */
	"getrlimit",
	"mmap2",

	/* Entries 193-194 are for BITS_PER_LONG == 32; and this is 64 bit OS */
	"truncate64", /* 193 place holder / ni_syscal */
	"ftruncate64",	/* 194 ditto	*/

	"stat64",	/* 195 */
	"lstat64",
	"fstat64",

	"lchown",
	"getuid32",
	"getgid32",	/* 200 */
	"geteuid32",
	"getegid32",
	"setreuid32",
	"setregid32",
	"pidfd_send_signal",	/* 205 */
	"pidfd_open",
	"fchown",
	"setresuid32",
	"getresuid32",
	"setresgid32",	/* 210 */
	"getresgid32",
	"chown",
	"setuid",
	"setgid",
	"setfsuid",	/* 215 */
	"setfsgid",
	"pivot_root",
	"mincore",
	"madvise",
	"getdents64",	/* 220 */
	"fcntl64",	/* 221 */
	"core",		/* place holder / ni_syscal */
	"macctl",	/* 223 */
	"newfstatat",
	"emergency",	/* 225 place holder / ni_syscal */
	"e2k_setjmp",	/* ditto */
	"e2k_longjmp",	/* ditto */
	"e2k_syswork",
	"clone_thread",
	"e2k_longjmp2", /* 230 */
	"soft_debug",	/* place holder / ni_syscal */
	"setxattr",
	"lsetxattr",
	"fsetxattr",
	"getxattr",	/* 235 */
	"lgetxattr",
	"fgetxattr",
	"listxattr",
	"llistxattr",
	"flistxattr",	/* 240 */
	"removexattr",
	"lremovexattr",
	"fremovexattr",
	"gettid",
	"readahead",	/* 245 */
	"tkill",
	"sendfile64",
	"futex",
	"sched_setaffinity",
	"sched_getaffinity",	/* 250 */
	"pipe2",
	"set_backtrace",
	"get_backtrace",
	"access_hw_stacks",
	"el_posix",	/* 255 */
	"io_uring_setup",
	"io_uring_enter",
	"io_uring_register",
	"set_tid_address",
	"el_binary", /* 260 */
	"timer_create",
	"timer_settime",
	"timer_gettime",
	"timer_getoverrun",
	"timer_delete",	/* 265 */
	"clock_settime",
	"clock_gettime",
	"clock_getres",
	"clock_nanosleep",
	"msgget",	/* 270 */
	"msgctl",
	"msgrcv",
	"msgsnd",
	"semget",
	"semctl",	/* 275 */
	"semtimedop",
	"semop",
	"shmget",
	"shmctl",
	"shmat",	/* 280 */
	"shmdt",
	"open_tree",
	"move_mount",
	"rseq",
	"io_pgetevents", /* 285 */
	"accept4",
	"sched_setattr",
	"sched_getattr",
	"ioprio_set",	/* 289 */
	"ioprio_get",	/* 290 */
	"inotify_init",	/* 291 */
	"inotify_add_watch",
	"inotify_rm_watch",
	"io_setup",	/* 294 */
	"io_destroy",
	"io_getevents",
	"io_submit",
	"io_cancel",
	"fadvise64",
	"exit_group",	/* 300 */
	"lookup_dcookie",
	"epoll_create",
	"epoll_ctl",
	"epoll_wait",
	"remap_file_pages",
	"statfs64",
	"fstatfs64",
	"tgkill",
	"utimes",
	"fadvise64_64",	/* 310 */

	"vserver",	/*  place holder / ni_syscal
			 *	isn't implemented in the Linux 2.6.14 kernel
			 */
	"mbind",
	"get_mempolicy",
	"set_mempolicy",
	"mq_open",
	"mq_unlink",
	"mq_timedsend",
	"mq_timedreceive",
	"mq_notify",
	"mq_getsetattr", /* 320 */
	"kexec_load",
	"waitid",
	"add_key",
	"request_key",
	"keyctl",
	"mcst_rt",	/* place holder / ni_syscal */
	"getcpu",
	"move_pages",
	"splice",
	"vmsplice",	/* 330 */
	"tee",
	"migrate_pages",
	"utimensat",
	"rt_tgsigqueueinfo",
	"openat",
	"mkdirat",
	"mknodat",
	"fchownat",
	"unlinkat",
	"renameat",	/* 340 */
	"linkat",
	"symlinkat",
	"readlinkat",
	"fchmodat",
	"faccessat",
	"epoll_pwait",
	"signalfd4",
	"eventfd2",
	"recvmmsg",
	"RESERVED",	/* 350 - ni_syscal */
	"timerfd_create",
	"timerfd_settime",
	"timerfd_gettime",
	"preadv",
	"pwritev",
	"fallocate",
	"sync_file_range",
	"dup3",
	"inotify_init1",
	"epoll_create1",	/* 360 */
	"fstatat64",
	"futimesat",
	"perf_event_open",
	"unshare",
	"get_robust_list",	/* 365 */
	"set_robust_list",
	"pselect6",
	"ppoll",
	"setcontext",
	"makecontext",		/* 370 */
	"swapcontext",
	"freecontext",
	"fanotify_init",
	"fanotify_mark",
	"prlimit64",
	"clock_adjtime",
	"syncfs",
	"sendmmsg",
	"setns",
	"process_vm_readv",	/* 380 */
	"process_vm_writev",
	"kcmp",
	"finit_module",
	/* added in linux-4.4 */
	"renameat2",
	"getrandom",		/* 385 */
	"memfd_create",
	"bpf",
	"execveat",
	"userfaultfd",
	"membarrier",		/* 390 */
	"mlock2",
	/* added in linux-4.9 */
	"seccomp",
	"shutdown",
	"copy_file_range",
	"preadv2",		/* 395 */
	"pwritev2",

	/* free (unused) items */
	"RESERVED",		/* 397 - ni_syscall */
	"RESERVED",		/* 398 - ni_syscall */
	"RESERVED",		/* 399 - ni_syscall */

	"name_to_handle_at",	/* 400 */
	"open_by_handle_at",	/* 401 */
	"statx",		/* 402 */
	/* added for compatibility with x86_64 */
	"socket",	/* 403 */
	"connect",	/* 404 */
	"accept",	/* 405 */
	"sendto",	/* 406 */
	"recvfrom",	/* 407 */
	"sendmsg",	/* 408 */
	"recvmsg",	/* 409 */
	"bind",		/* 410 */
	"listen",	/* 411 */
	"getsockname",	/* 412 */
	"getpeername",	/* 413 */
	"socketpair",	/* 414 */
	"setsockopt",	/* 415 */
	"getsockopt",	/* 416 */

	/* free (unused) items */
	"RESERVED",	/* 417 - ni_syscall */
	"RESERVED",	/* 418 - ni_syscall */

	/* protected specific system calls entries */
	"arch_prctl",	/* 419 */
	"newuselib",	/* 420 __NR_newuselib */
	"rt_sigaction_ex", /* 421 */
	"get_mem",	/* 422 */
	"free_mem",	/* 423 */
	"clean_descriptors", /* 424 */
	"unuselib", /* 425 */

	"clone3",
	"fsopen",
	"fsconfig",
	"fsmount",
	"fspick",	/* 430 */
	"close_range",
	"openat2",
	"pidfd_getfd",
	"faccessat2",
	"process_madvise", /* 435 */
};
