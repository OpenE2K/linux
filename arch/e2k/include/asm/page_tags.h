/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef	_E2K_PAGE_TAGS_H
#define	_E2K_PAGE_TAGS_H


#define TAGS_BITS_PER_LONG	4
#define TAGS_BYTES_PER_PAGE	(PAGE_SIZE / sizeof(long) * TAGS_BITS_PER_LONG / 8)

#endif
