# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2023 MCST

extra-y		:= vmlinux.lds

ifdef CONFIG_VIRTUALIZATION
 EXTRA_CFLAGS += -Wframe-larger-than=6144
endif

ifneq ($(CONFIG_CPU_HW_CLEAR_RF),y)
obj-y		+= clear_rf.o
extra-y		+= ttable_asm.h
hostprogs	:= mkclearwindow
endif
extra-y		+= ttable_wbs.h ttable_tmp.o

quiet_cmd_gen_ttable_wbs_h = GEN	  $@
cmd_gen_ttable_wbs_h = rm -f $(obj)/ttable_wbs.h; \
	touch $(obj)/ttable_wbs.h; \
	$(OBJDUMP) -me2k -d $(obj)/ttable_tmp.o | sed -n -e '/<user_trap_handler>/,/<*>:/ s/.*setwd wsz = \(0x[0-9a-f][0-9a-f]*\).*/\#define USER_TRAP_HANDLER_SIZE \1/p' | sort -k 3 -g | tail -1 >> $(obj)/ttable_wbs.h; \
	$(OBJDUMP) -me2k -d $(obj)/ttable_tmp.o | sed -n -e '/<ttable_entry8_C>/,/<*>:/ s/.*setwd wsz = \(0x[0-9a-f][0-9a-f]*\).*/\#define TTABLE_ENTRY_8_SIZE \1/p' | sort -k 3 -g | tail -1 >> $(obj)/ttable_wbs.h; \
	$(OBJDUMP) -me2k -d $(obj)/ttable_tmp.o | sed -n -e '/<__ret_from_fork>/,/<*>:/ s/.*setwd wsz = \(0x[0-9a-f][0-9a-f]*\).*/\#define RET_FROM_FORK_SIZE \1/p' | sort -k 3 -g | tail -1 >> $(obj)/ttable_wbs.h; \
	$(OBJDUMP) -me2k -d $(obj)/ttable_tmp.o | sed -n -e '/<handle_sys_call>/,/<*>:/ s/.*setwd wsz = \(0x[0-9a-f][0-9a-f]*\).*/\#define HANDLE_SYS_CALL_SIZE \1/p' | sort -k 3 -g | tail -1 >> $(obj)/ttable_wbs.h; \
	$(OBJDUMP) -me2k -d $(obj)/ttable_tmp.o | sed -n -e '/<do_sigreturn>/,/<*>:/ s/.*setwd wsz = \(0x[0-9a-f][0-9a-f]*\).*/\#define DO_SIGRETURN_SIZE \1/p' | sort -k 3 -g | tail -1 >> $(obj)/ttable_wbs.h; \
	$(OBJDUMP) -me2k -d $(obj)/ttable_tmp.o | sed -n -e '/<finish_user_trap_handler_sw_fill>/,/<*>:/ s/.*setwd wsz = \(0x[0-9a-f][0-9a-f]*\).*/\#define FINISH_USER_TRAP_HANDLER_SW_FILL_SIZE \1/p' | sort -k 3 -g | tail -1 >> $(obj)/ttable_wbs.h; \
	$(OBJDUMP) -me2k -d $(obj)/ttable_tmp.o | sed -n -e '/<finish_syscall_sw_fill>/,/<*>:/ s/.*setwd wsz = \(0x[0-9a-f][0-9a-f]*\).*/\#define FINISH_SYSCALL_SW_FILL_SIZE \1/p' | sort -k 3 -g | tail -1 >> $(obj)/ttable_wbs.h
ifeq ($(CONFIG_KVM_GUEST_KERNEL),y)
cmd_gen_ttable_wbs_h += ; $(OBJDUMP) -me2k -d $(obj)/ttable_tmp.o | sed -n -e '/<kvm_trap_handler>/,/<*>:/ s/.*setwd wsz = \(0x[0-9a-f][0-9a-f]*\).*/\#define KVM_TRAP_HANDLER_SIZE \1/p' | sort -k 3 -g | tail -1 >> $(obj)/ttable_wbs.h
endif
ifeq ($(CONFIG_KVM_PARAVIRTUALIZATION),y)
cmd_gen_ttable_wbs_h += ; \
	$(OBJDUMP) -me2k -d $(obj)/ttable_tmp.o | sed -n -e '/<return_to_injected_syscall_sw_fill>/,/<*>:/ s/.*setwd wsz = \(0x[0-9a-f][0-9a-f]*\).*/\#define RETURN_TO_INJECTED_SYSCALL_SW_FILL_SIZE \1/p' | sort -k 3 -g | tail -1 >> $(obj)/ttable_wbs.h; \
	$(OBJDUMP) -me2k -d $(obj)/ttable_tmp.o | sed -n -e '/<return_pv_vcpu_trap>/,/<*>:/ s/.*setwd wsz = \(0x[0-9a-f][0-9a-f]*\).*/\#define RETURN_PV_VCPU_TRAP_SIZE \1/p' | sort -k 3 -g | tail -1 >> $(obj)/ttable_wbs.h; \
	$(OBJDUMP) -me2k -d $(obj)/ttable_tmp.o | sed -n -e '/<return_pv_vcpu_syscall_fork>/,/<*>:/ s/.*setwd wsz = \(0x[0-9a-f][0-9a-f]*\).*/\#define HANDLE_PV_VCPU_SYS_FORK_SIZE \1/p' | sort -k 3 -g | tail -1 >> $(obj)/ttable_wbs.h; \
	$(OBJDUMP) -me2k -d $(obj)/ttable_tmp.o | sed -n -e '/<return_pv_vcpu_syscall>/,/<*>:/ s/.*setwd wsz = \(0x[0-9a-f][0-9a-f]*\).*/\#define HANDLE_PV_VCPU_SYS_CALL_SIZE \1/p' | sort -k 3 -g | tail -1 >> $(obj)/ttable_wbs.h
endif

$(obj)/ttable_tmp.o: $(src)/ttable_tmp.c FORCE

$(obj)/ttable_wbs.h: $(obj)/ttable_tmp.o FORCE
	$(call if_changed,gen_ttable_wbs_h)

ifneq ($(CONFIG_CPU_HW_CLEAR_RF),y)
quiet_cmd_mkclearwindow = GEN	  $@
cmd_mkclearwindow = $(obj)/mkclearwindow > $@

$(obj)/mkclearwindow: $(obj)/ttable_wbs.h

$(obj)/ttable_asm.h: $(obj)/ttable_wbs.h $(obj)/mkclearwindow FORCE
	$(call if_changed,mkclearwindow)

$(obj)/ttable.o: $(obj)/ttable_asm.h
else
$(obj)/ttable.o: $(obj)/ttable_wbs.h
endif

# "-fexclude-ctpr2" - to make sure that AAU is not zeroed before we get to it.
# "-fno-dam" - hardware bug 124206 workaround (CPU_HWBUG_L1I_STOPS_WORKING)
# "-fno-semi-spec-ld" - to make sure nothing bad happens between restoring %cont
# and %root_ptb registers and DONE instruction.
CC_FLAGS_KERNEL_ENTRY := $(call lcc-option,-fexclude-ctpr2) $(call lcc-option,-fno-semi-spec-ld)
ifeq ($(CONFIG_MIGHT_HAVE_CPU_HWBUG_L1I_STOPS_WORKING),y)
CC_FLAGS_KERNEL_ENTRY += $(call lcc-option,-fno-dam)
endif

CFLAGS_ttable.o     := $(CC_FLAGS_KERNEL_ENTRY)
CFLAGS_ttable_tmp.o := $(CC_FLAGS_KERNEL_ENTRY) -DGENERATING_HEADER

ifdef CONFIG_CPU_ISET_MIN
ifeq ($(shell test $(CONFIG_CPU_ISET_MIN) -lt 6; echo $$?),0)
# To compile gregs and ctpr saving for iset v6
AFLAGS_REMOVE_trap_table.o = $(CFLAGS_ALL_CPUS)
AFLAGS_trap_table.o += -march=elbrus-v6
endif
endif

# We should not instrument these files
KASAN_SANITIZE_ttable_tmp.o := n
KASAN_SANITIZE_ttable.o     := n
CFLAGS_REMOVE_ttable.o     := -fprofile-generate-kernel $(call lcc-option,-fsemi-spec-ld) \
			      $(call lcc-option,-fglobal-regs)
CFLAGS_REMOVE_ttable_tmp.o := $(CFLAGS_REMOVE_ttable.o)

# Profiling leads to unexpected branches in trap exit code
GCOV_PROFILE_ttable.o := n
GCOV_PROFILE_ttable_tmp.o := n

obj-y	+=	trap_table.o ttable.o process.o copy-hw-stacks.o trampolines.o \
		signal.o io.o e2k_sic.o setup.o time.o sys_e2k.o traps.o \
		systable.o ptrace.o e2k_syswork.o sys_32.o recovery.o \
		proc_context.o backtrace.o trace_clock.o topology.o fpu.o \
		rtc.o e2k.o trace.o nmi.o getsp.o alternative.o convert_array.o \
		fill_handler_entry.o proc_context_stacks.o kdebugfs.o \
		setjmp.o devtree.o sched_clock.o

obj-y				+= cpu/

ifdef CONFIG_FUNCTION_TRACER
# Do not profile debug and lowlevel utilities
CFLAGS_REMOVE_trace_stack.o = $(CC_FLAGS_FTRACE)
CFLAGS_REMOVE_time.o = $(CC_FLAGS_FTRACE)
CFLAGS_REMOVE_smpboot.o = $(CC_FLAGS_FTRACE)
CFLAGS_REMOVE_ftrace.o = $(CC_FLAGS_FTRACE)
CFLAGS_REMOVE_e2k_sic.o = $(CC_FLAGS_FTRACE)
CFLAGS_REMOVE_hw_breakpoint.o = $(CC_FLAGS_FTRACE)
endif

obj-$(CONFIG_SCLKR_CLOCKSOURCE) += sclkr.o
obj-$(CONFIG_SCLKR_CLOCKSOURCE) += proc_sclkr.o
obj-$(CONFIG_ESCLKR_CLOCKSOURCE) += esclkr.o

CFLAGS_prot_sysctl_init.o = $(call cc-option,-Wno-invalid-source-encoding)
obj-$(CONFIG_PROTECTED_MODE) += prot_sysctl_init.o protected_syscalls.o clean_aps.o \
	unsafe_uint64_to_ptr.o prot_syscall_synopsis.o binfmt_elf32_3P.o binfmt_elf64_3P.o

obj-$(CONFIG_HAVE_HW_BREAKPOINT) += hw_breakpoint.o
obj-$(CONFIG_ELF_CORE)		+= elfcore.o
obj-$(CONFIG_PERF_EVENTS)	+= perf_event/
obj-$(CONFIG_SMP)		+= smp.o smpboot.o
KASAN_SANITIZE_smpboot.o := n
obj-$(CONFIG_MODULES)		+= module.o ksyms.o
obj-$(CONFIG_KPROBES)		+= kprobes.o
obj-$(CONFIG_PRECISE_TIME)	+= precise_time.o
obj-$(CONFIG_FUNCTION_TRACER)	+= ftrace.o
obj-$(CONFIG_FTRACE_SYSCALLS)   += ftrace.o
obj-$(CONFIG_FUNCTION_GRAPH_TRACER) += ftrace_graph_entry.o
obj-$(CONFIG_STACKTRACE)        += stacktrace.o
obj-$(CONFIG_E2K_STACKS_TRACER) += trace_stack.o
obj-$(CONFIG_HOTPLUG_CPU) += hotplug-cpu.o
ifeq ($(PROFILE_GENERATE), 1)
obj-$(CONFIG_EPROF_KERNEL) += libeprof/
endif
obj-$(CONFIG_E2K_KEXEC) += kexec.o
obj-$(CONFIG_KEXEC) += machine_kexec.o relocate_kernel.o
obj-$(CONFIG_CRASH_DUMP) += crash_dump.o
obj-$(CONFIG_SOFT_PM) += soft_pm.o

# For E2K_WAIT_ALL and atomic operations support on phys memory
CFLAGS_kexec.o += -DE2K_P2V $(call lcc-option,-fno-semi-spec-ld) \
		  $(call lcc-option,-fno-spec-ld) \
		  -ftrivial-auto-var-init=uninitialized
CFLAGS_REMOVE_kexec.o := -fprofile-generate-kernel $(call lcc-option,-fsemi-spec-ld)

GCOV_PROFILE_kexec.o := n # Since it disables virtual memory

kernelclean:	dummy
