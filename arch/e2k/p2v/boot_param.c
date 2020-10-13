/*
 * Boot-time command line parsing.
 *
 * Copyright (C) 2011-2013 Pavel V. Panteleev (panteleev_p@mcst.ru)
 */

#include <asm/boot_param.h>
#include <asm/console.h>
#include <asm/setup.h>
#include <asm/boot_head.h>

#include <linux/string.h>

/*
 * One should store original cmdline passed by boot to restore it in
 * setup_arch() function.
 */
char __initdata saved_boot_cmdline[COMMAND_LINE_SIZE];

extern struct boot_kernel_param __boot_setup_start[], __boot_setup_end[];

struct kernel_param;
extern int parse_one(char *param,
		     char *val,
		     const char *doing,
		     const struct kernel_param *params,
		     unsigned num_params,
		     s16 min_level,
		     s16 max_level,
		     int (*handle_unknown)(char *param, char *val,
				     const char *doing));

/*
 * This function is based on simple_guess_base function from lib/vsprintf.c
 */
static unsigned int __init boot_simple_guess_base(const char *cp)
{
	if (cp[0] == '0') {
		if (BOOT_TOLOWER(cp[1]) == 'x' && boot_isxdigit(cp[2]))
			return 16;
		else
			return 8;
	} else {
		return 10;
	}
}

/*
 * This function is based on simple_strtoull function from lib/vsprintf.c
 *
 * boot_simple_strtoull - convert a string to an unsigned long long
 * @cp: The start of the string
 * @endp: A pointer to the end of the parsed string will be placed here
 * @base: The number base to use
 */
unsigned long long __init
boot_simple_strtoull(const char *cp, char **endp, unsigned int base)
{
	unsigned long long result = 0;

	if (!base)
		base = boot_simple_guess_base(cp);

	if (base == 16 && cp[0] == '0' && BOOT_TOLOWER(cp[1]) == 'x')
		cp += 2;

	while (boot_isxdigit(*cp)) {
		unsigned int value;

		value = boot_isdigit(*cp) ? *cp - '0' : BOOT_TOLOWER(*cp) - 'a' + 10;
		if (value >= base)
			break;
		result = result * base + value;
		cp++;
	}
	if (endp)
		*endp = (char *)cp;

	return result;
}

/*
 * This function is based on simple_strtoul function from lib/vsprintf.c
 *
 * boot_simple_strtoul - convert a string to an unsigned long
 * @cp: The start of the string
 * @endp: A pointer to the end of the parsed string will be placed here
 * @base: The number base to use
 */
unsigned long __init
boot_simple_strtoul(const char *cp, char **endp, unsigned int base)
{
	return boot_simple_strtoull(cp, endp, base);
}

/*
 * This function is based on simple_strtol function from lib/vsprintf.c
 *
 * boot_simple_strtol - convert a string to a signed long
 * @cp: The start of the string
 * @endp: A pointer to the end of the parsed string will be placed here
 * @base: The number base to use
 */
long __init boot_simple_strtol(const char *cp, char **endp, unsigned int base)
{
	if (*cp == '-')
		return -boot_simple_strtoul(cp + 1, endp, base);

	return boot_simple_strtoul(cp, endp, base);
}

/*
 * This function is based on simple_strtoll function from lib/vsprintf
 *
 * boot_simple_strtoll - convert a string to a signed long long
 * @cp: The start of the string
 * @endp: A pointer to the end of the parsed string will be placed here
 * @base: The number base to use
 */
long long __init
boot_simple_strtoll(const char *cp, char **endp, unsigned int base)
{
	if (*cp == '-')
		return -boot_simple_strtoull(cp + 1, endp, base);

	return boot_simple_strtoull(cp, endp, base);
}

/*
 * This function is based on get_option function from lib/cmdline.c
 *
 * boot_get_option - Parse integer from an option string
 * @str: option string
 * @pint: (output) integer value parsed from @str
 *
 * Read an int from an option string; if available accept a subsequent
 * comma as well.
 *
 * Return values:
 * 0 - no int in string
 * 1 - int found, no subsequent comma
 * 2 - int found including a subsequent comma
 * 3 - hyphen found to denote a range
 */
int __init boot_get_option (char **str, int *pint)
{
	char *cur = *str;

	if (!cur || !(*cur))
		return 0;
	*pint = boot_simple_strtol (cur, str, 0);
	if (cur == *str)
		return 0;
	if (**str == ',') {
		(*str)++;
		return 2;
	}
	if (**str == '-')
		return 3;

	return 1;
}

/*
 * This function is based on skip_spaces function from lib/string.c
 */
char __init *boot_skip_spaces(const char *str)
{
	while (boot_isspace(*str))
		++str;
	return (char *)str;
}

/*
 * This function is based on next_arg function from kernel/params.c
 *
 * It uses boot_skip_spaces and boot_isspace instead of original funcs.
 * You can use " around spaces, but can't escape ".
 * Hyphens and underscores equivalent in parameter names.
 */
static char __init
*boot_next_arg(char *args, char **param, char **val)
{
	unsigned int i, equals = 0;
	int in_quote = 0, quoted = 0;
	char *next;

	if (*args == '"') {
		args++;
		in_quote = 1;
		quoted = 1;
	}

	for (i = 0; args[i]; i++) {
		if (boot_isspace(args[i]) && !in_quote)
			break;
		if (equals == 0) {
			if (args[i] == '=')
				equals = i;
		}
		if (args[i] == '"')
			in_quote = !in_quote;
	}

	*param = args;
	if (!equals)
		*val = NULL;
	else {
		args[equals] = '\0';
		*val = args + equals + 1;

		/* Don't include quotes in value. */
		if (**val == '"') {
			(*val)++;
			if (args[i-1] == '"')
				args[i-1] = '\0';
		}
		if (quoted && args[i-1] == '"')
			args[i-1] = '\0';
	}

	if (args[i]) {
		args[i] = '\0';
		next = args + i + 1;
	} else
		next = args + i;

	/* Chew up trailing spaces. */
	return boot_skip_spaces(next);
}

/*
 * This function is based on do_early_param function in init/main.c
 */
static int __init
boot_do_param(char *param, char *val)
{
	struct boot_kernel_param *p;
	struct boot_kernel_param *start = boot_vp_to_pp(__boot_setup_start);
	struct boot_kernel_param *end = boot_vp_to_pp(__boot_setup_end);

	for (p = start; p < end; p++) {
		if (strcmp(param, boot_vp_to_pp(p->str)) == 0) {
			if (((int (*)(char *))boot_vp_to_pp(
						p->setup_func))(val) != 0)
				do_boot_printk(KERN_WARNING
				       "Malformed boot option '%s'\n", param);
			return 1;
		}
	}

	return 0;
}

/*
 * This function is based on parse_args function from kernel/params.c
 *
 * It uses boot_skip_spaces instead of skip_spaces.
 * Args looks like "foo=bar,bar2 baz=fuz wiz".
 */
static int __init
boot_parse_args(const char *name, char *args, char *boot_cmdline)
{
	char *param, *val, *args_start = args;
	int del_cnt = 0;

	/* Chew leading spaces */
	args = boot_skip_spaces(args);

	while (*args) {
		char *args_prev, *del_start, *del_end;
		int cmdline_len, ret;

		args_prev = args;
		args = boot_next_arg(args, &param, &val);
		ret = boot_do_param(param, val);
		
		switch (ret) {
		case 0:
			/* boot param not found */
			break;
		case 1:
			/*
			 * boot param found: we should exclude it from kernel
			 * cmd line
			 */
			del_start = boot_cmdline +
				(int)(args_prev - args_start) - del_cnt;
			del_end = boot_cmdline +
				(int)(args - args_start) - del_cnt;
			cmdline_len = strlen(boot_cmdline);
			memcpy(del_start, del_end,
				cmdline_len - (int)(del_end - boot_cmdline));
			memset(boot_cmdline + cmdline_len - args + args_prev,
				0, 1);
			del_cnt += args - args_prev;
			break;
		default:
			do_boot_printk(KERN_ERR
			       "%s: `%s' invalid for parameter `%s'\n",
			       name, val ?: "", param);
			return ret;
		}
	}

	/* All parsed OK. */
	return 0;
}

void __init
boot_parse_param(bootblock_struct_t *bootblock)
{
	char tmp_cmdline[COMMAND_LINE_SIZE];
	char *boot_cmdline;
	int  boot_cmdline_len;

	if (!strncmp(bootblock->info.kernel_args_string,
			BOOT_KERNEL_ARGS_STRING_EX_SIGNATURE,
			KERNEL_ARGS_STRING_EX_SIGN_SIZE)) {
		/* Extended command line (512 bytes) */
		boot_cmdline = bootblock->info.bios.kernel_args_string_ex;
		boot_cmdline_len = KSTRMAX_SIZE_EX;
	} else {
		/* Standart command line (128 bytes) */
		boot_cmdline = bootblock->info.kernel_args_string;
		boot_cmdline_len = KSTRMAX_SIZE;
	}

	strlcpy(boot_saved_boot_cmdline, boot_cmdline, boot_cmdline_len);
	strlcpy(tmp_cmdline, boot_cmdline, boot_cmdline_len);
	boot_parse_args("boot options", tmp_cmdline, boot_cmdline);
}
