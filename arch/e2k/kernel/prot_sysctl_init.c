/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 MCST
 */

/*
 * This is implementation of kernel sysctl controls for the E2K secure computing (protected) mode:
 */

#if defined(CONFIG_MCST) && defined(CONFIG_E2K) && defined(CONFIG_PROTECTED_MODE)

#include <linux/module.h>
#include <linux/sysctl.h>
#include <linux/syscalls.h>
#include <linux/kmemleak.h>
#include <asm/protected_mode.h>
#include <asm/protected_syscalls.h>
#include "protected_error_messages.in"


struct scm_controls_struct scm_controls = {
	.prot_malloc_mode_control = -1,
};

static struct ctl_table e2k_SCM_table[] = {
	{
		.procname = "syscall_debug_mode_enabled",
		.data = &scm_controls.syscall_debug_mode_enabled,
		.maxlen = sizeof(scm_controls.syscall_debug_mode_enabled),
		.mode = 0644,
		.proc_handler = proc_douintvec_minmax,
	},
	{
		.procname = "default_syscall_debug_mode",
		.data = &scm_controls.default_syscall_debug_mode,
		.maxlen = sizeof(scm_controls.default_syscall_debug_mode),
		.mode = 0644,
		.proc_handler = proc_douintvec_minmax,
	},
	{
		.procname = "dangling_pointers_control",
		.data = &scm_controls.dangling_pointers_control,
		.maxlen = sizeof(scm_controls.dangling_pointers_control),
		.mode = 0644,
		.proc_handler = proc_douintvec_minmax,
	},
	{
		.procname = "prot_malloc_mode_control",
		.data = &scm_controls.prot_malloc_mode_control,
		.maxlen = sizeof(scm_controls.prot_malloc_mode_control),
		.mode = 0644,
		.proc_handler = proc_douintvec_minmax,
	},
	{
		.procname = "dynamic_syscall_debug_control_disabled",
		.data = &scm_controls.dynamic_syscall_debug_control_disabled,
		.maxlen = sizeof(scm_controls.dynamic_syscall_debug_control_disabled),
		.mode = 0644,
		.proc_handler = proc_douintvec_minmax,
	},
	{
		.procname = "protected_syscall_ptrace_enabled",
		.data = &scm_controls.protected_syscall_ptrace_enabled,
		.maxlen = sizeof(scm_controls.protected_syscall_ptrace_enabled),
		.mode = 0644,
		.proc_handler = proc_douintvec_minmax,
	},
	{
		.procname = "syscall_unsafe_uint64_to_ptr_enabled",
		.data = &scm_controls.syscall_unsafe_uint64_to_ptr_enabled,
		.maxlen = sizeof(scm_controls.syscall_unsafe_uint64_to_ptr_enabled),
		.mode = 0644,
		.proc_handler = proc_douintvec_minmax,
	},
	{ }
};

static struct ctl_path e2k_scm_sysctl_path[] = {
	{ .procname = "kernel", },
	{ .procname = "e2k", },
	{ .procname = "SCM", },
	{ }
};

static int __init e2k_scm_init_sysctl(void)
{
	struct ctl_table_header *hdr;

	hdr = register_sysctl_paths(e2k_scm_sysctl_path, e2k_SCM_table);
	if (!hdr)
		pr_warn("sysctl registration failed for e2k/SCM\n");
	else
		kmemleak_not_leak(hdr);

	return 0;
}
late_initcall(e2k_scm_init_sysctl);


void print_sysctld_SCM_controls(void)
{
	printk(KERN_INFO "E2K/SCM controls setup:\n");
	printk(KERN_INFO "\tsyscall_debug_mode_enabled = %d\n",
		scm_controls.syscall_debug_mode_enabled);
	printk(KERN_INFO "\tdefault_syscall_debug_mode = %d\n",
		scm_controls.default_syscall_debug_mode);
	printk(KERN_INFO "\tdangling_pointers_control = %d\n",
		scm_controls.dangling_pointers_control);
	printk(KERN_INFO "\tprot_malloc_mode_control = %d\n",
		scm_controls.prot_malloc_mode_control);
	printk(KERN_INFO "\tdynamic_syscall_debug_control_disabled = %d\n",
		scm_controls.dynamic_syscall_debug_control_disabled);
	printk(KERN_INFO "\tprotected_syscall_ptrace_enabled = %d\n",
		scm_controls.protected_syscall_ptrace_enabled);
	printk(KERN_INFO "\tsyscall_unsafe_uint64_to_ptr_enabled = %d\n",
		scm_controls.syscall_unsafe_uint64_to_ptr_enabled);
}

/* ################### Dynamic controls thru env vars: ################### */

/*
 * Scans environment for the given env var.
 * Reports: value of the given env var; 0 - if doesn't exist.
 */
static inline
char *pm_getenv(const char *env_var_name, const size_t max_len)
{
	/* NB> Length of the environment record expected less that 'max_len'. */
	unsigned long uenvp;
	size_t len, lenvar;
	unsigned long kenvp;
	unsigned long lmax = 128;
	long copied;

	if (!current->mm || !current->mm->env_start)
		return NULL;
	if (current->mm->env_start >= current->mm->env_end)
		return NULL;
	lenvar = strlen(env_var_name);
	kenvp = (unsigned long)kvmalloc(lmax,  GFP_KERNEL_ACCOUNT);
	for (uenvp = current->mm->env_start;
	     uenvp < current->mm->env_end;
	     uenvp += len) /* strnlen_user accounts terminating '\0' */ {
		len = strnlen_user((const void __user *)uenvp,
					current->mm->env_end - uenvp);
		if (!len)
			break;
		else if ((len < lenvar) || (len > max_len))
			continue;
		if (lmax < len) {
			unsigned long new_lmax = (len + 127) & 0xffffff80;

			kenvp = (unsigned long)kvrealloc((void *)kenvp,
							lmax, new_lmax, GFP_KERNEL_ACCOUNT);
			lmax = new_lmax;
		}
		copied = strncpy_from_user((void *)kenvp,
					(const void __user *)uenvp, len);
		if (!copied) {
			continue;
		} else if (copied < 0) {
			pr_alert("%s:%d: Cannot strncpy_from_user(len = %zd)\n",
				 __func__, __LINE__, len);
			break;
		}
		if (!strncmp(env_var_name, (void *)kenvp, min(lenvar, len))) {
			if (current->mm->context.pm_sc_debug_mode
						& PM_SC_DBG_MODE_DEBUG)
				pr_info("ENVP: %s\n", (char *)kenvp);
			if (*((char *)(kenvp + lenvar)) == '=') {
				size_t vallen = len - (lenvar + 1);
				char *res = (char *)kvmalloc(vallen, GFP_KERNEL_ACCOUNT);
				if (res == NULL) {
					kvfree((void *)kenvp);
					pr_warn("%s: no memory\n", __func__);
					return NULL;
				}
				strncpy(res, (char *)(kenvp + lenvar + 1), vallen);
				kvfree((void *)kenvp);
				return res;
			}
			if (current->mm->context.pm_sc_debug_mode
						& PM_SC_DBG_MODE_DEBUG)
				pr_info("Env var \"%s\" is not \"%s\"\n",
					(char *)kenvp, env_var_name);
		}
	}
	kvfree((void *)kenvp);
	return NULL;
}

/*
 * Setup PM error messaging language.
 * 'max_len' - maximum expected env var length.
 * Returns: -1 - if env.var. is not set;
 *          mask to apply to 'pm_sc_debug_mode' if env var is "set";
 *           0 - otherwise.
 */
static
unsigned long check_PM_lang_setup(const char *env_var_name, const size_t max_len)
{
	char *env_val;
	unsigned long res = 0;
	/* This is check for RUSSIAN language setup:
	 * ru_RU.KOI8-R, ru_RU.KOI8_R, ru_RU.KOI8R
	 * ru_RU.UTF-8, ru_RU.UTF_8, ru_RU.UTF8, ru_RU
	 */
	env_val = pm_getenv(env_var_name, max_len);
	if (!env_val) {
		return ULONG_MAX;
	}

	if (!strstr(env_val, "RU")) {
		res = 0;
	} else if (strstr(env_val, "ru_RU.KOI8")) {
		res = PM_SC_ERR_MESSAGES_KOI8_R;
	} else if (strstr(env_val, "ru_RU.UTF")) {
		res = PM_SC_ERR_MESSAGES_RU_UTF;
	} else if (strstr(env_val, "ru_RU")) {
		return PM_SC_ERR_MESSAGES_RU_UTF;
	} else {
		pr_err("Wrong value of the env var %s = %s\n", env_var_name, env_val);
		pr_err("Legal values: ru_RU.UTF-8, ru_RU.UTF_8, ru_RU.UTF8, ru_RU,\n");
		pr_err("\t\t ru_RU.KOI8-R, ru_RU.KOI8_R, ru_RU.KOI8R\n");
	}
	kvfree(env_val);
	return res;
}

/*
 * Checks for PM debug mode env var setup and outputs corresponding debug mask.
 * 'max_len' - maximum expected env var length.
 * Returns: mask to apply to 'pm_sc_debug_mode' if env var is "set";
 *           0 - otherwise.
 */
static
unsigned int check_debug_value(const char *env_var_name, const size_t max_len)
{
	char *env_val;
	int value = 0, ret;

	env_val = pm_getenv(env_var_name, max_len);
	if (!env_val)
		return 0;

	ret = kstrtoint(env_val, 0, &value);
	if (ret || value < 0)
		pr_err("Wrong value of the env var %s = %s\n", env_var_name, env_val);
	kvfree(env_val);
	return value;
}

/** protected_mode_check_env_debug_mask() - Return PM debug mode mask
 *                                          based on env var setting.
 * @env_var_name: Name of the environment variable to read.
 * @max_len:      Maximum expected length of the env var value.
 *
 * Reads the environment variable of the current process specified by
 * @env_var_name. If the variable is set positive, returns a debug mask for |.
 * If the variable is set negative, returns an inverted mask for &.
 * If the variable is not set or an error occurs during parsing, returns 0.
 *
 * Return: Mask to apply to 'pm_sc_debug_mode' or 'pm_soft_options_mask'
 *         if env var is "set"; 0 - otherwise.
 */
unsigned long protected_mode_check_env_debug_mask(const char *env_var_name,
						  const size_t max_len,
						  const unsigned long mask)
{
	char *env_val;
	unsigned long res = 0;

	env_val = pm_getenv(env_var_name, max_len);
	if (!env_val)
		return 0;

	if (!*env_val || env_val[1]) /* single char expected as env var value */
		goto wrong_val_out;

	if ((*env_val == '1') || (*env_val == 'y') || (*env_val == 'Y')) {
		res = mask;
		goto val_out;
	}
	if ((*env_val == '0') || (*env_val == 'n') || (*env_val == 'N')) {
		res = ~mask;
		goto val_out;
	}
wrong_val_out:
	pr_alert("Wrong value of the env var %s = %s\n",
			 env_var_name, env_val);
	pr_alert("Legal values: 0/1/y/n/Y/N\n");
val_out:
	kvfree(env_val);
	return res;
}
EXPORT_SYMBOL_GPL(protected_mode_check_env_debug_mask);

#define CHECK_DEBUG_MASK(mask_name) \
do { \
	mask = protected_mode_check_env_debug_mask(#mask_name, 48, mask_name); \
	if (mask) { \
		if (mask & mask_name) /* positive mask */ \
			context->pm_sc_debug_mode |= mask; \
		else /* negative mask */ \
			context->pm_sc_debug_mode &= mask; \
	} \
} while (0)

static inline
long protected_mode_check_env_malloc_mode(mm_context_t *context)
{
	char *env_val = pm_getenv("PM_MALLOC_MODE", 48);
	long rv = 0;

	if (!env_val)
		return -1;

	if (*env_val && !env_val[1]) /* single char value mode (number) */
		rv = *env_val - '0';
	/* Symbolic value: compatible/zeroing/emptying */
	else if (!strcmp(env_val, "compatible"))
		rv = PM_MALLOC_MODE_COMPATIBLE;
	else if (!strcmp(env_val, "zeroing"))
		rv = PM_MALLOC_MODE_ZEROING;
	else if (!strcmp(env_val, "emptying"))
		rv = PM_MALLOC_MODE_EMPTYING;
	else
		rv = -1;

	if ((rv < 0) || (rv > MAX_PM_MALLOC_MODE)) {
		rv = -1;
		pr_alert("Wrong value of the env var PM_MALLOC_MODE = \"%s\"\n", env_val);
		pr_alert("Legal values: 0/1/2/compatible/zeroing/emptying\n");
	}

	kvfree(env_val);
	return rv;
}

static inline
void reset_PM_MM_default_setup(mm_context_t *context, int save_flag)
{
	if (context->pm_sc_debug_mode & PM_MM_CHECK_4_DANGLING_POINTERS
			&& save_flag != PM_MM_CHECK_4_DANGLING_POINTERS)
		context->pm_sc_debug_mode &= ~PM_MM_CHECK_4_DANGLING_POINTERS;
	if (context->pm_sc_debug_mode & PM_MM_ZEROING_FREED_POINTERS
			&& save_flag != PM_MM_ZEROING_FREED_POINTERS)
		context->pm_sc_debug_mode &= ~PM_MM_ZEROING_FREED_POINTERS;
	if (context->pm_sc_debug_mode & PM_MM_EMPTYING_FREED_POINTERS
			&& save_flag != PM_MM_EMPTYING_FREED_POINTERS)
		context->pm_sc_debug_mode &= ~PM_MM_EMPTYING_FREED_POINTERS;
}

#if IS_ENABLED(CONFIG_SOFT_PM)

static void (*arch_init_soft_pm_mode)(void *context_ptr) = NULL;

void init_arch_init_soft_pm_mode(void (*initer)(void *context_ptr))
{
	WRITE_ONCE(arch_init_soft_pm_mode, initer);
}
EXPORT_SYMBOL_GPL(init_arch_init_soft_pm_mode);

void remove_arch_init_soft_pm_mode(void)
{
	WRITE_ONCE(arch_init_soft_pm_mode, NULL);
}
EXPORT_SYMBOL_GPL(remove_arch_init_soft_pm_mode);

#endif /* CONFIG_SOFT_PM */

/*
 * Initialization of the E2K Secure Computing execution mode.
 */
void arch_init_secure_computing_mode(void *context_ptr)
{
	mm_context_t *context = (mm_context_t *)context_ptr;
	unsigned long mask;
	int reset_PM_MM_default; /* once env var encountered, we need to reset default setup */
	int ival;
#if IS_ENABLED(CONFIG_SOFT_PM)
	void (*soft_pm_initer)(void *) = READ_ONCE(arch_init_soft_pm_mode);
#endif /* CONFIG_SOFT_PM */

	if (!context)
		context = &current->mm->context;

	memset(context->pm_sc_warned_once_msgs, 0, sizeof(context->pm_sc_warned_once_msgs));

	/* sysctl.d controls check: */
	context->pm_sc_debug_mode = get_sysctld_default_syscall_debug_mode();
	context->pm_sc_unsafe_uint64_to_ptr_mode = 0;
	if (get_sysctld_protected_syscall_ptrace_enabled())
		context->pm_sc_debug_mode |= PM_SC_PTRACE_ENABLED;
	if (get_sysctld_syscall_unsafe_uint64_to_ptr_enabled()) {
		context->pm_sc_debug_mode |= PM_SC_UNSAFE_UINT64_TO_PTR_ENABLED;
		if (get_unsafe_uint64_to_ptr_whole_stack_mode()) {
			context->pm_sc_unsafe_uint64_to_ptr_mode |=
						PM_SC_UNSAFE_UINT64_TO_PTR_WHOLE_STACK_MODE;
		}
	}
	if (get_sysctld_syscall_debug_mode_enabled())
		context->pm_sc_debug_mode |= PROTECTED_MODE_SOFT | PM_SC_DBG_MODE_CHECK
				| PM_MM_DEFAULT_FREE_PTR_MODE | PM_DIAG_MESSAGES_IN_STDERR
				| PM_SC_DBG_WARNINGS;
	ival = get_sysctld_dangling_pointers_control();
	if (ival == 1) {
		context->pm_sc_debug_mode |= PM_MM_ZEROING_FREED_POINTERS;
	} else if (ival == 2) {
		context->pm_sc_debug_mode |= PM_MM_EMPTYING_FREED_POINTERS;
	} else if (ival == 3) {
		context->pm_sc_debug_mode |= PM_MM_CHECK_4_DANGLING_POINTERS;
	} else if (e2k_scm_sysctld_controls_enabled()) {
		pr_alert("Wrong value in sysctl.d: \"dangling_pointers_control = %d\"\n", ival);
		pr_alert("Legal values: 1/2/3\n");
	}
	ival = get_sysctld_prot_malloc_mode_control();
	if ((ival >= 0) && (ival <= MAX_PM_MALLOC_MODE)) {
		context->pm_sc_debug_mode |= ival << PM_MM_MALLOC_MODE_MASK_SHIFT;
	} else if (e2k_scm_sysctld_controls_enabled()) {
		pr_alert("Wrong value in sysctl.d: \"prot_malloc_mode_control = %d\"\n", ival);
		pr_alert("Legal values: 0/1/2\n");
	}
	if (get_sysctld_dynamic_syscall_debug_control_disabled())
		goto out;

	/* Checking for dynamic controls thru env vars: */

	CHECK_DEBUG_MASK(PM_SC_DBG_MODE_DEBUG);
	CHECK_DEBUG_MASK(PM_SC_DBG_MODE_COMPLEX_WRAPPERS);
	CHECK_DEBUG_MASK(PM_SC_DBG_STRING_ARGS);
	CHECK_DEBUG_MASK(PM_SC_DBG_MODE_CHECK);
	CHECK_DEBUG_MASK(PM_SC_DBG_MODE_CONV_STRUCT);
	CHECK_DEBUG_MASK(PM_SC_DBG_MODE_SIGNALS);
	CHECK_DEBUG_MASK(PM_SC_DBG_MODE_NO_ERR_MESSAGES);
	CHECK_DEBUG_MASK(PM_DIAG_MESSAGES_IN_JOURNAL);
	CHECK_DEBUG_MASK(PM_DIAG_MESSAGES_IN_STDERR);
	CHECK_DEBUG_MASK(PM_SC_CHECK4TAGS_IN_BUFF);
	if (context->pm_sc_debug_mode &  PM_SC_CHECK4TAGS_IN_BUFF) {
		context->pm_sc_check4tags_max_size =
				check_debug_value("PM_SC_CHECK4TAGS_MAX_SIZE", 48);
		if (PM_SC_CHECK4TAGS_IN_BUFF && context->pm_sc_check4tags_max_size == 0)
			context->pm_sc_check4tags_max_size = PM_SC_CHECK4TAGS_DEFAULT_MAX_SIZE;
	}
	/* Protected mode setup: */
	CHECK_DEBUG_MASK(PROTECTED_MODE_SOFT);
	if (!mask) {
		/* Alias for backward compatibility: */
		mask = protected_mode_check_env_debug_mask(
				"PM_SC_DBG_MODE_WARN_ONLY",
				48, PM_SC_DBG_MODE_WARN_ONLY);
		if (mask) {
			if (mask & PROTECTED_MODE_SOFT) /* positive mask */
				context->pm_sc_debug_mode |= mask;
			else /* negative mask */
				context->pm_sc_debug_mode &= mask;
		}
	}
	CHECK_DEBUG_MASK(PM_SC_DBG_WARNINGS);
	CHECK_DEBUG_MASK(PM_SC_DBG_WARNINGS_AS_ERRORS);
	CHECK_DEBUG_MASK(PM_SC_PTRACE_ENABLED);
	CHECK_DEBUG_MASK(PM_SC_UNSAFE_UINT64_TO_PTR_ENABLED);
	if (context->pm_sc_debug_mode & PM_SC_UNSAFE_UINT64_TO_PTR_ENABLED) {
		mask = protected_mode_check_env_debug_mask(
				"PM_SC_UNSAFE_UINT64_TO_PTR_WHOLE_STACK_MODE", 48, 1);
		if (mask) {
			context->pm_sc_unsafe_uint64_to_ptr_mode |=
						PM_SC_UNSAFE_UINT64_TO_PTR_WHOLE_STACK_MODE;
		}
	}

	/* libc mmu control stuff: */
	reset_PM_MM_default = 1;
	CHECK_DEBUG_MASK(PM_MM_CHECK_4_DANGLING_POINTERS);
	if (mask) {
		reset_PM_MM_default_setup(context, PM_MM_CHECK_4_DANGLING_POINTERS);
		reset_PM_MM_default = 0;
	}
	CHECK_DEBUG_MASK(PM_MM_ZEROING_FREED_POINTERS);
	if (mask && reset_PM_MM_default) {
		reset_PM_MM_default_setup(context, PM_MM_ZEROING_FREED_POINTERS);
		reset_PM_MM_default = 0;
	}
	CHECK_DEBUG_MASK(PM_MM_EMPTYING_FREED_POINTERS);
	if (mask && reset_PM_MM_default) {
		reset_PM_MM_default_setup(context, PM_MM_EMPTYING_FREED_POINTERS);
		reset_PM_MM_default = 0;
	}

	long env_pm_malloc_mode = protected_mode_check_env_malloc_mode(context);
	if (env_pm_malloc_mode < 0)
		env_pm_malloc_mode = PM_MM_MALLOC_MODE_DEFAULT;
	context->pm_sc_debug_mode &= ~PM_MM_MALLOC_MODE_MASK;
	context->pm_sc_debug_mode |=  (env_pm_malloc_mode << PM_MM_MALLOC_MODE_MASK_SHIFT);

	CHECK_DEBUG_MASK(PM_SC_NO_CLEAN_DESCRIPTORS);

	CHECK_DEBUG_MASK(PM_SC_DBG_WARN_ON_REPAIRED_SAP);
	CHECK_DEBUG_MASK(PM_SC_UNSAFE_EXT_REPAIRED_BOUNDARIES);

	/* Language setup: */
	mask = check_PM_lang_setup("LC_ALL", 48);
	if ((long) mask >= 0) {
		goto select_lang;
	} else {
		mask = check_PM_lang_setup("LC_MESSAGES", 48);
		if (mask >= 0)
			goto select_lang;
		mask = check_PM_lang_setup("LANG", 48);
		if (mask < 0)
			mask = 0;
	}
select_lang:
	if ((long) mask >= 0) {
		context->pm_sc_debug_mode &= ~(PM_SC_ERR_MESSAGES_RU_UTF /* lang mask cleanup */
						| PM_SC_ERR_MESSAGES_KOI8_R);
		context->pm_sc_debug_mode |= mask;
	}

	if (context->pm_sc_debug_mode & PM_SC_ERR_MESSAGES_RU_UTF)
		protected_error_list = &protected_error_list_RU[0];
	else if (context->pm_sc_debug_mode & PM_SC_ERR_MESSAGES_KOI8_R)
		protected_error_list = &protected_error_list_RU_KOI8[0];
	else
		protected_error_list = &protected_error_list_C[0];

	BUILD_BUG_ON(ARRAY_SIZE(protected_error_list_C) != PMSCERRMSG_NUMBER ||
			ARRAY_SIZE(protected_error_list_RU) != PMSCERRMSG_NUMBER ||
			ARRAY_SIZE(protected_error_list_RU_KOI8) != PMSCERRMSG_NUMBER);

	mask = protected_mode_check_env_debug_mask("PM_SC_DBG_MODE_DISABLED", 48, 1);
	if (mask == 1) {
		context->pm_sc_debug_mode -= (context->pm_sc_debug_mode & PM_SC_DBG_DIAG_MASK_ALL);
		context->pm_sc_debug_mode |= PM_SC_DBG_MODE_NO_ERR_MESSAGES;
	} else {
		mask = protected_mode_check_env_debug_mask("PM_SC_DBG_MODE_ALL", 48,
							   PM_SC_DBG_MODE_ALL);
		if (mask & PM_SC_DBG_MODE_ALL) { /* positive mask */
			context->pm_sc_debug_mode |= PM_SC_DBG_MODE_ALL;
			if (context->pm_sc_debug_mode & PM_SC_DBG_MODE_DEBUG) {
				pr_info("ENVP: PM_SC_DBG_MODE_ALL=1\n");
			}
		}
	}

out:
	if (context->pm_sc_debug_mode & PM_SC_NO_CLEAN_DESCRIPTORS)
		context->pm_sc_debug_mode &= ~PM_MM_FREE_PTR_MODE_MASK;
	if ((context->pm_sc_debug_mode & PM_MM_FREE_PTR_MODE_MASK) == 0) {
		if (context->pm_sc_debug_mode & PM_SC_UNSAFE_UINT64_TO_PTR_ENABLED) {
			PROTECTED_MODE_WARNING(PMSCERRMSG_FILLING_FREED_MEM_BLOCKED, NULL);
		} else {
			context->pm_sc_debug_mode |= PM_MM_DEFAULT_FREE_PTR_MODE; /* RM-18187 */
			protected_mode_message(PM_SC_DBG_MODE_MSG_TYPE_ERROR,
					       PMSCERRMSG_FILLING_FREED_MEM_IN_UNSAFE_PM, NULL);
		}
	}

	if (context->pm_sc_debug_mode & PM_SC_DBG_MODE_DEBUG) {
		char *env_val;

		if (e2k_scm_sysctld_controls_enabled())
			print_sysctld_SCM_controls();
		env_val = pm_getenv("LC_ALL", 48 /*max_len*/);
		if (env_val) {
			pr_info("LC_ALL: %s\n", env_val);
			kvfree(env_val);
		}
		pr_info("\tpm_sc_debug_mode = 0x%lx\n",
					context->pm_sc_debug_mode);
		if (context->pm_sc_debug_mode & PM_SC_CHECK4TAGS_IN_BUFF
				&& context->pm_sc_check4tags_max_size != 0)
			pr_info("\tpm_sc_check4tags_max_size = %d\n",
					context->pm_sc_check4tags_max_size);
	}

	env_pm_malloc_mode = (context->pm_sc_debug_mode & PM_MM_MALLOC_MODE_MASK)
					>> PM_MM_MALLOC_MODE_MASK_SHIFT;
	if ((env_pm_malloc_mode != PM_MM_MALLOC_MODE_DEFAULT) &&
			(context->pm_sc_debug_mode & (PM_SC_DBG_MODE_DEBUG | PM_SC_DBG_WARNINGS)))
		pr_info("PM_MALLOC_MODE = \"%ld\"\n", env_pm_malloc_mode);

#if IS_ENABLED(CONFIG_SOFT_PM)
	if (soft_pm_initer)
		soft_pm_initer(context_ptr);
#endif /* CONFIG_SOFT_PM */
	return;
}

#endif /* CONFIG_PROTECTED_MODE */
