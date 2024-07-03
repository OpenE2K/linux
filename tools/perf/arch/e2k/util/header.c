/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/compiler.h>
#include <linux/stringify.h>

#if __BITS_PER_LONG != 64
# error Bad configuration
#endif

static int cpuid_initialized;
static char *e2k_get_cpuid(void)
{
	char *id;

	if (!cpuid_initialized) {
		__builtin_cpu_init();
		cpuid_initialized = 1;
	}

	if (__builtin_cpu_is("elbrus-v1"))
		id = "v1";
	else if (__builtin_cpu_is("elbrus-v2"))
		id = "v2";
	else if (__builtin_cpu_is("elbrus-v3"))
		id = "v3";
	else if (__builtin_cpu_is("elbrus-v4"))
		id = "v4";
	else if (__builtin_cpu_is("elbrus-v5"))
		id = "v5";
	else if (__builtin_cpu_is("elbrus-v6"))
		id = "v6";
	else
		id = NULL;

	return id;
}

int get_cpuid(char *buffer, size_t sz)
{
	char *id;
	size_t len = 3;

	if (sz < len)
		return -1;

	id = e2k_get_cpuid();
	if (!id)
		return -1;

	strncpy(buffer, id, len);
	buffer[len-1] = 0;

	return 0;
}

char *get_cpuid_str(void)
{
	char *id, *bufp;
	int len = 3;

	id = e2k_get_cpuid();
	if (!id)
		return NULL;

	bufp = malloc(len);
	if (!bufp)
		return NULL;

	strncpy(bufp, id, len);
	bufp[len-1] = 0;

	return bufp;
}
