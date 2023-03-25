/*
 * Boot-time command line parsing.
 *
 * Copyright (C) 2011-2013 Pavel V. Panteleev (panteleev_p@mcst.ru)
 */

#ifndef __E2K_P2V_BOOT_PARAM_H
#define __E2K_P2V_BOOT_PARAM_H

#include <asm/p2v/boot_head.h>

#include <linux/ctype.h>

#define _boot_ctype	(boot_vp_to_pp((unsigned char *)_ctype))
#define __boot_ismask(x) (_boot_ctype[(int)(unsigned char)(x)])

#define boot_isalnum(c)		((__boot_ismask(c)&(_U|_L|_D)) != 0)
#define boot_isalpha(c)		((__boot_ismask(c)&(_U|_L)) != 0)
#define boot_iscntrl(c)		((__boot_ismask(c)&(_C)) != 0)
#define boot_isdigit(c)		((__boot_ismask(c)&(_D)) != 0)
#define boot_isgraph(c)		((__boot_ismask(c)&(_P|_U|_L|_D)) != 0)
#define boot_islower(c)		((__boot_ismask(c)&(_L)) != 0)
#define boot_isprint(c)		((__boot_ismask(c)&(_P|_U|_L|_D|_SP)) != 0)
#define boot_ispunct(c)		((__boot_ismask(c)&(_P)) != 0)
/* Note: isspace() must return false for %NUL-terminator */
#define boot_isspace(c)		((__boot_ismask(c)&(_S)) != 0)
#define boot_isupper(c)		((__boot_ismask(c)&(_U)) != 0)
#define boot_isxdigit(c)	((__boot_ismask(c)&(_D|_X)) != 0)

/* Works only for digits and letters, but small and fast */
#define BOOT_TOLOWER(x) ((x) | 0x20)

/*
 *	Example of usage:
 *
 *	int test = 0;
 *	.....
 *	int boot_test(char *str)
 *	{
 *		boot_get_option(&str, boot_vp_to_pp(&test));
 *		return 0;
 *	}
 *
 *	boot_param("test", boot_test);
 *	.....
 *	Function 'boot_test' would be called in case of kernel command line
 *	contains parameter 'test'. Input argument 'str' would point to the
 *	value of 'test' parameter.
 */

typedef struct boot_kernel_param {
	const char *str;
	int (*setup_func)(char *);
} boot_kernel_param_t;

extern boot_kernel_param_t __boot_setup_start[], __boot_setup_end[];

/*
 * Only for really core code.  See moduleparam.h for the normal way.
 *
 * Force the alignment so the compiler doesn't space elements of the
 * boot_kernel_param "array" too far apart in .boot.setup.
 */
#define __boot_setup_param(str, unique_id, fn)				\
	static const char __boot_setup_str_##unique_id[] __initconst	\
		__aligned(1) = str; 					\
	static struct boot_kernel_param __boot_setup_##unique_id	\
		__used __section(.boot.setup)				\
		__attribute__((aligned((sizeof(long)))))		\
		= { __boot_setup_str_##unique_id, fn }

#define boot_param(str, fn)						\
	__boot_setup_param(str, fn, fn)

char* boot_skip_spaces(const char *str);
int boot_get_option(char **str, int *pint);
long long boot_simple_strtoll(const char *cp, char **endp, unsigned int base);
long boot_simple_strtol(const char *cp, char **endp, unsigned int base);
unsigned long boot_simple_strtoul(
			const char *cp, char **endp, unsigned int base);
unsigned long long boot_simple_strtoull(
			const char *cp, char **endp, unsigned int base);
void boot_native_parse_param(bootblock_struct_t *bootblock);

struct kernel_param;

extern char saved_boot_cmdline[];
#define boot_saved_boot_cmdline		\
		boot_vp_to_pp((char *)saved_boot_cmdline)

#if	defined(CONFIG_PARAVIRT_GUEST)
/* it is paravirtualized host and guest kernel */
#include <asm/paravirt/boot.h>
#elif	defined(CONFIG_KVM_GUEST_KERNEL)
/* it is pure guest kernel (not paravirtualized based on pv_ops */
#include <asm/kvm/guest/boot.h>
#else	/* native kernel */
/* it is native kernel without any virtualization */
/* or it is native host kernel with virtualization support */
static inline  void
boot_parse_param(bootblock_struct_t *bootblock)
{
	boot_native_parse_param(bootblock);
}
#endif	/* CONFIG_PARAVIRT_GUEST */

#endif /* __E2K_P2V_BOOT_PARAM_H */
