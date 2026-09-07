/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef	_E2K_PAGE_TAGS_H
#define	_E2K_PAGE_TAGS_H


#define TAGS_BITS_PER_LONG	4
#define TAGS_BYTES_PER_PAGE	(PAGE_SIZE / sizeof(long) * TAGS_BITS_PER_LONG / 8)

#if defined(CONFIG_PROTECTED_MODE) && CONFIG_CPU_ISET_MAX >= 7
/* Use 4 bits to save color of 16 byte chunk */
#define CLRS_BYTES_PER_PAGE	(TAGS_BYTES_PER_PAGE / 2)
#else
#define CLRS_BYTES_PER_PAGE 0
#endif

#define TAGS_PER_PAGE	(PAGE_SIZE / (TAGS_BYTES_PER_PAGE + CLRS_BYTES_PER_PAGE))

#endif
