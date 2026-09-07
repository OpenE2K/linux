/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef __CHECKER__
#define CREATE_TRACE_POINTS
#include <asm/trace-pt-atomic.h>
#include <asm/trace.h>
#include <asm/trace/irq_vectors.h>
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
#include <asm/kvm/paravirt_sw/trace-hw-stacks.h>
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
#endif
