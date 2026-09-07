/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _EL_POSIX__H_
#define _EL_POSIX__H_

#ifndef STANDALONE
#ifdef CONFIG_MCST
#ifdef CONFIG_E90
#define do_postpone_tick(a)	do {} while (0)
#else
extern void do_postpone_tick(int to_netxt_inrt_ns);
#endif
#endif
#endif

#endif /* _EL_POSIX__H_ */

