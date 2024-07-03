/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _E2K_BOOT_STRING_H_
#define _E2K_BOOT_STRING_H_

/* boot-time initialization string library functions */


#include <linux/compiler.h>	/* for inline */
#include <linux/types.h>	/* for size_t */
#include <linux/stddef.h>	/* for NULL */
#include <stdarg.h>

extern char *boot_strcpy(char *, const char *);
extern char *boot_strncpy(char *, const char *, __kernel_size_t);
extern size_t boot_strlcpy(char *, const char *, size_t);
extern int boot_strcmp(const char *, const char *);
extern int boot_strncmp(const char *, const char *, __kernel_size_t);
extern __kernel_size_t boot_strlen(const char *);
extern __kernel_size_t boot_strnlen(const char *, __kernel_size_t);
extern void *boot_memset(void *, int, __kernel_size_t);
extern void *boot_memcpy(void *, const void *, __kernel_size_t);

#endif /* _E2K_BOOT_STRING_H_ */
