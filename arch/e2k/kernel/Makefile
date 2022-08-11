#
# Makefile for the linux kernel.
# /arch/e2k/kernel
# Note! Dependencies are done automagically by 'make dep', which also
# removes any old dependencies. DON'T put your own dependencies here
# unless it's something special (ie not a .c file).
#

subdir-ccflags-y := -Werror -Wswitch -Wenum-compare

extra-y		:= vmlinux.lds
EXTRA_AFLAGS	:= $(CFLAGS)
EXTRA_CFLAGS	:= $(CFLAGS) -Ifs

ifdef CONFIG_VIRTUALIZATION
 EXTRA_CFLAGS += -Wframe-larger-than=6144
endif

ifneq ($(CONFIG_CPU_HW_CLEAR_RF),y)
obj-y		+= clear_rf.o
extra-y		+= ttable_asm.h
hostprogs-y	:= mkclearwindow
endif
extra-y		+= ttable_wbs.h ttable_tmp.o

quiet_cmd_gen_ttable_wbs_h = GEN	  $@
cmd_gen_ttable_wbs_h = rm -f $(obj)/ttable_wbs.h; \
	touch $(obj)/ttable_wbs.h; \
	$(OBJDUMP) -me2k -d $(obj)/ttable_tmp.o | sed -n -e '/<user_trap_handler>/,/<*>:/ s/.*setwd wsz = \(0x[0-9a-f][0-9a-f]*\).*/\#define USER_TRAP_HANDLER_SIZE \1/p' | sort -k 3 -g | tail -1 >> $(obj)/ttable_wbs.h; \
	$(OBJDUMP) -me2k -d $(obj)/ttable_tmp.o | sed -n -e '/<ttable_entry8_C>/,/<*>:/ s/.*setwd wsz = \(0x[0-9a-f][0-9a-f]*\).*/\#define TTABLE_ENTRY_8_SIZE \1/p' | sort -k 3 -g | tail -1 >> $(obj)/ttable_wbs.h; \
	$(OBJDUMP) -me2k -d $(obj)/ttable_tmp.o | sed -n -e '/<ttable_entry10_C>/,/<*>:/ s/.*setwd wsz = \(0x[0-9a-f][0-9a-f]*\).*/\#define TTABLE_ENTRY_10_SIZE \1/p' | sort -k 3 -g | tail -1 >> $(obj)/ttable_wbs.h; \
	$(OBJDUMP) -me2k -d $(obj)/ttable_tmp.o | sed -n -e '/<__ret_from_fork>/,/<*>:/ s/.*setwd wsz = \(0x[0-9a-f][0-9a-f]*\).*/\#define RET_FROM_FORK_SIZE \1/p' | sort -k 3 -g | tail -1 >> $(obj)/ttable_wbs.h; \
	$(OBJDUMP) -me2k -d $(obj)/ttable_tmp.o | sed -n -e '/<makecontext_trampoline_switched>/,/<*>:/ s/.*setwd wsz = \(0x[0-9a-f][0-9a-f]*\).*/\#define MAKECONTEXT_SIZE \1/p' | sort -k 3 -g | tail -1 >> $(obj)/ttable_wbs.h; \
	$(OBJDUMP) -me2k -d $(obj)/ttable_tmp.o | sed -n -e '/<handle_sys_call>/,/<*>:/ s/.*setwd wsz = \(0x[0-9a-f][0-9a-f]*\).*/\#define HANDLE_SYS_CALL_SIZE \1/p' | sort -k 3 -g | tail -1 >> $(obj)/ttable_wbs.h; \
	$(OBJDUMP) -me2k -d $(obj)/ttable_tmp.o | sed -n -e '/<do_sigreturn>/,/<*>:/ s/.*setwd wsz = \(0x[0-9a-f][0-9a-f]*\).*/\#define DO_SIGRETURN_SIZE \1/p' | sort -k 3 -g | tail -1 >> $(obj)/ttable_wbs.h; \
	$(OBJDUMP) -me2k -d $(obj)/ttable_tmp.o | sed -n -e '/<return_pv_vcpu_trap>/,/<*>:/ s/.*setwd wsz = \(0x[0-9a-f][0-9a-f]*\).*/\#define RETURN_PV_VCPU_TRAP_SIZE \1/p' | sort -k 3 -g | tail -1 >> $(obj)/ttable_wbs.h; \
	$(OBJDUMP) -me2k -d $(obj)/ttable_tmp.o | sed -n -e '/<return_pv_vcpu_syscall_fork>/,/<*>:/ s/.*setwd wsz = \(0x[0-9a-f][0-9a-f]*\).*/\#define HANDLE_PV_VCPU_SYS_FORK_SIZE \1/p' | sort -k 3 -g | tail -1 >> $(obj)/ttable_wbs.h; \
	$(OBJDUMP) -me2k -d $(obj)/ttable_tmp.o | sed -n -e '/<return_pv_vcpu_syscall>/,/<*>:/ s/.*setwd wsz = \(0x[0-9a-f][0-9a-f]*\).*/\#define HANDLE_PV_VCPU_SYS_CALL_SIZE \1/p' | sort -k 3 -g | tail -1 >> $(obj)/ttable_wbs.h

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

# -fexclude-ctpr2 - to make sure that AAU is not zeroed before we get to it
# -fno-dam - hardware bug 124206 workaround (CPU_HWBUG_L1I_STOPS_WORKING)
CFLAGS_ttable.o := -fno-dam -fexclude-ctpr2
CFLAGS_ttable_tmp.o := -fno-dam -fexclude-ctpr2 -DGENERATING_HEADER

# To compile gregs and ctpr saving for iset v6
AFLAGS_REMOVE_trap_table.o = $(CFLAGS_ALL_CPUS)
AFLAGS_trap_table.o += -march=elbrus-v6

# We should no instrument these files
CFLAGS_REMOVE_ttable.o := -fprofile-generate-kernel
CFLAGS_REMOVE_ttable_tmp.o := -fprofile-generate-kernel

CFLAGS_ptrace.o += -Wframe-larger-than=12288

obj-y	+=	trap_table.o ttable.o page_tables.o process.o copy-hw-stacks.o \
		entry_user.o signal.o io.o setup.o time.o sys_e2k.o traps.o \
		systable.o ptrace.o e2k_syswork.o sys_32.o $(GDBSTART) \
		proc_context.o backtrace.o trace_clock.o topology.o \
		rtc.o e2k.o trace.o nmi.o getsp.o e2k-iommu.o alternative.o \
		convert_array.o protected_mq_notify.o protected_timer_create.o \
		protected_syscalls.o

ifneq ($(CONFIG_CPU_HAS_FILL_INSTRUCTION),y)
obj-y += fill_handler_entry.o
endif
obj-$(CONFIG_HAVE_HW_BREAKPOINT) += hw_breakpoint.o

CFLAGS_process.o += -fno-tail-calls

obj-y				+= cpu/

ifeq ($(CONFIG_E2K_MACHINE),y)
else
#CFLAGS_e2k_sic.o		= $(CFLAGS_E2K_SIC)
endif
obj-y				+= e2k_sic.o

ifdef CONFIG_FUNCTION_TRACER
# Do not profile debug and lowlevel utilities
CFLAGS_REMOVE_trace_stack.o = -pg
CFLAGS_REMOVE_time.o = -pg 
CFLAGS_REMOVE_smpboot.o = -pg 
CFLAGS_REMOVE_ftrace.o = -pg 
CFLAGS_REMOVE_e2k_sic.o = -pg
CFLAGS_REMOVE_hw_breakpoint.o = -pg
endif

ifdef CONFIG_CPU_ES2
CFLAGS_REMOVE_sclkr.o = $(CFLAGS_ALL_CPUS)
CFLAGS_sclkr.o += -march=elbrus-v3
endif

obj-$(CONFIG_SCLKR_CLOCKSOURCE) += sclkr.o
obj-$(CONFIG_SCLKR_CLOCKSOURCE) += proc_sclkr.o

obj-$(CONFIG_ELF_CORE)		+= elfcore.o
obj-$(CONFIG_PERF_EVENTS)	+= perf_event/
obj-$(CONFIG_MONITORS)		+= monitors.o
obj-$(CONFIG_SMP)		+= smp.o
obj-$(CONFIG_SMP)		+= smpboot.o
obj-$(CONFIG_IOCTL_ELF32)	+= ioctl32.o
obj-$(CONFIG_RECOVERY)		+= recovery.o
obj-$(CONFIG_MODULES)		+= module.o ksyms.o
obj-$(CONFIG_KPROBES)		+= kprobes.o
obj-$(CONFIG_SECONDARY_SPACE_SUPPORT)	+= sec_space.o
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
obj-$(CONFIG_OF) += devtree.o
obj-$(CONFIG_E2K_KEXEC) += kexec.o

# For E2K_WAIT_ALL and atomic operations support on phys memory
CFLAGS_kexec.o += -DE2K_P2V
ifeq ($(call cc-option-yn,-fno-semi-spec-ld -fno-spec-ld),y)
	CFLAGS_kexec.o += -fno-semi-spec-ld -fno-spec-ld
else
	CFLAGS_kexec.o += -fno-ld-spec
endif

GCOV_PROFILE_kexec.o := n # Since it disables virtual memory

kernelclean:	dummy
