#
# Makefile for the linux kernel.
# /arch/e2k/kernel
# Note! Dependencies are done automagically by 'make dep', which also
# removes any old dependencies. DON'T put your own dependencies here
# unless it's something special (ie not a .c file).
#

extra-y		:= vmlinux.lds ttable_wbs.h ttable_asm.h ttable_tmp.o
hostprogs-y	:= mkclearwindow
EXTRA_AFLAGS	:= $(CFLAGS)
EXTRA_CFLAGS	:= $(CFLAGS) -Ifs

quiet_cmd_gen_ttable_wbs_h = GEN	  $@
cmd_gen_ttable_wbs_h = rm -f $(obj)/ttable_wbs.h; \
	touch $(obj)/ttable_wbs.h; \
	$(OBJDUMP) -me2k -d $(obj)/ttable_tmp.o | sed -n -e '/<user_trap_handler>/,/<*>:/ s/.*setwd wsz = \(0x[0-9a-f][0-9a-f]*\).*/\#define USER_TRAP_HANDLER_SIZE \1/p' >> $(obj)/ttable_wbs.h; \
	$(OBJDUMP) -me2k -d $(obj)/ttable_tmp.o | sed -n -e '/<ttable_entry8_C>/,/<*>:/ s/.*setwd wsz = \(0x[0-9a-f][0-9a-f]*\).*/\#define TTABLE_ENTRY_8_SIZE \1/p' >> $(obj)/ttable_wbs.h; \
	$(OBJDUMP) -me2k -d $(obj)/ttable_tmp.o | sed -n -e '/<ttable_entry10_C>/,/<*>:/ s/.*setwd wsz = \(0x[0-9a-f][0-9a-f]*\).*/\#define TTABLE_ENTRY_10_SIZE \1/p' >> $(obj)/ttable_wbs.h; \
	$(OBJDUMP) -me2k -d $(obj)/ttable_tmp.o | sed -n -e '/<hard_sys_calls>/,/<*>:/ s/.*setwd wsz = \(0x[0-9a-f][0-9a-f]*\).*/\#define HARD_SYS_CALLS_SIZE \1/p' >> $(obj)/ttable_wbs.h; \
	$(OBJDUMP) -me2k -d $(obj)/ttable_tmp.o | sed -n -e '/<simple_sys_calls>/,/<*>:/ s/.*setwd wsz = \(0x[0-9a-f][0-9a-f]*\).*/\#define SIMPLE_SYS_CALLS_SIZE \1/p' >> $(obj)/ttable_wbs.h

quiet_cmd_mkclearwindow = GEN	  $@
cmd_mkclearwindow = $(obj)/mkclearwindow > $@

$(obj)/ttable_tmp.o: $(src)/ttable_tmp.c FORCE

$(obj)/ttable_wbs.h: $(obj)/ttable_tmp.o FORCE
	$(call if_changed,gen_ttable_wbs_h)

$(obj)/mkclearwindow: $(obj)/ttable_wbs.h

$(obj)/ttable_asm.h: $(obj)/ttable_wbs.h $(obj)/mkclearwindow FORCE
	$(call if_changed,mkclearwindow)

$(obj)/ttable.o: $(obj)/ttable_asm.h

# To make sure that AAU is not zeroed before we get to it
CFLAGS_ttable.o := -fexclude-ctpr2
CFLAGS_ttable_tmp.o := -fexclude-ctpr2 -DGENERATING_HEADER

obj-y	:=	trap_table.o ttable.o page_tables.o process.o entry_user.o \
		signal.o traps.o irq.o io.o setup.o time.o sys_e2k.o \
		systable.o ptrace.o e2k_syswork.o sys_32.o $(GDBSTART) \
		cpufreq.o backtrace.o clear_rf.o trace_clock.o \
		topology.o reset.o procsic.o

obj-y				+= i8253.o
obj-y				+= rtc.o
obj-y				+= e2k.o

CFLAGS_iset_e2s.o		= $(CFLAGS_E2S)
obj-y				+= iset_e2s.o

ifeq ($(CONFIG_E2K_MACHINE),y)
obj-$(CONFIG_E2K_E3M_SIM)	+= lms.o
obj-$(CONFIG_E2K_E3M)		+= e3m.o
obj-$(CONFIG_E2K_E3M_IOHUB_SIM)	+= e3m_iohub_lms.o
obj-$(CONFIG_E2K_E3M_IOHUB)	+= e3m_iohub.o
obj-$(CONFIG_E2K_E3S_SIM)	+= e3s_lms.o e2k_sic.o
obj-$(CONFIG_E2K_E3S)		+= e3s.o e2k_sic.o
obj-$(CONFIG_E2K_ES2_DSP_SIM)	+= es2_lms.o e2k_sic.o
obj-$(CONFIG_E2K_ES2_DSP)	+= es2.o e2k_sic.o
obj-$(CONFIG_E2K_ES2_RU_SIM)	+= es2_lms.o e2k_sic.o
obj-$(CONFIG_E2K_ES2_RU)	+= es2.o e2k_sic.o
obj-$(CONFIG_E2K_E2S_SIM)	+= e2s_lms.o e2k_sic.o
obj-$(CONFIG_E2K_E2S)		+= e2s.o e2k_sic.o
obj-$(CONFIG_E2K_E8C_SIM)	+= e8c_lms.o e2k_sic.o
obj-$(CONFIG_E2K_E8C)		+= e8c.o e2k_sic.o
obj-$(CONFIG_E2K_E1CP_SIM)	+= e1cp_lms.o e2k_sic.o
obj-$(CONFIG_E2K_E1CP)		+= e1cp.o e2k_sic.o
obj-$(CONFIG_E2K_E8C2_SIM)	+= e8c2_lms.o e2k_sic.o
obj-$(CONFIG_E2K_E8C2)		+= e8c2.o e2k_sic.o
else
CFLAGS_lms.o			= $(CFLAGS_E3M)
CFLAGS_e3m.o			= $(CFLAGS_E3M)
CFLAGS_e3m_iohub_lms.o		= $(CFLAGS_E3M)
CFLAGS_e3m_iohub.o		= $(CFLAGS_E3M)
CFLAGS_e3s_lms.o		= $(CFLAGS_E3S)
CFLAGS_e3s.o			= $(CFLAGS_E3S)
CFLAGS_es2_lms.o		= $(CFLAGS_ES2)
CFLAGS_es2.o			= $(CFLAGS_ES2)
CFLAGS_e2s_lms.o		= $(CFLAGS_E2S)
CFLAGS_e2s.o			= $(CFLAGS_E2S)
CFLAGS_e8c_lms.o		= $(CFLAGS_E8C)
CFLAGS_e8c.o			= $(CFLAGS_E8C)
CFLAGS_e1cp_lms.o		= $(CFLAGS_E1CP)
CFLAGS_e1cp.o			= $(CFLAGS_E1CP)
CFLAGS_e8c2_lms.o		= $(CFLAGS_E8C2)
CFLAGS_e8c2.o			= $(CFLAGS_E8C2)
CFLAGS_e2k_sic.o		= $(CFLAGS_E2K_SIC)
obj-y				+= lms.o e3m.o e3m_iohub_lms.o e3m_iohub.o \
				   e3s_lms.o e3s.o \
				   es2_lms.o es2.o e2s.o e2s_lms.o \
				   e8c_lms.o e8c.o e1cp_lms.o e1cp.o \
				   e8c2_lms.o e8c2.o e2k_sic.o
endif

ifdef CONFIG_FUNCTION_TRACER
# Do not profile debug and lowlevel utilities
CFLAGS_REMOVE_trace_stack.o = -pg
CFLAGS_REMOVE_time.o = -pg 
CFLAGS_REMOVE_smpboot.o = -pg 
CFLAGS_REMOVE_ftrace.o = -pg 
CFLAGS_REMOVE_lms.o = -pg
CFLAGS_REMOVE_e3m.o = -pg
CFLAGS_REMOVE_e3m_iohub_lms.o = -pg
CFLAGS_REMOVE_e3m_iohub.o = -pg
CFLAGS_REMOVE_e3s_lms.o = -pg
CFLAGS_REMOVE_e3s.o = -pg
CFLAGS_REMOVE_es2_lms.o = -pg
CFLAGS_REMOVE_es2.o = -pg
CFLAGS_REMOVE_e2s_lms.o = -pg
CFLAGS_REMOVE_e2s.o = -pg
CFLAGS_REMOVE_e8c_lms.o = -pg
CFLAGS_REMOVE_e8c.o = -pg
CFLAGS_REMOVE_e1cp_lms.o = -pg
CFLAGS_REMOVE_e1cp.o = -pg
CFLAGS_REMOVE_e8c2_lms.o = -pg
CFLAGS_REMOVE_e8c2.o = -pg
CFLAGS_REMOVE_e2k_sic.o = -pg
CFLAGS_REMOVE_perf_event.o = -pg
CFLAGS_REMOVE_perf_event_uncore.o = -pg
endif

obj-$(CONFIG_PERF_EVENTS)	+= perf_event_uncore.o
obj-$(CONFIG_PERF_EVENTS)	+= perf_event.o
obj-$(CONFIG_MONITORS)		+= monitors.o
obj-$(CONFIG_SMP)		+= smp.o
obj-$(CONFIG_SMP)		+= smpboot.o
obj-$(CONFIG_IOCTL_ELF32)	+= ioctl32.o
obj-$(CONFIG_RECOVERY)		+= recovery.o
obj-$(CONFIG_RECOVERY)		+= cnt_point.o
obj-$(CONFIG_STATE_SAVE)	+= state_save.o e2k_ide_drv.o
obj-$(CONFIG_MODULES)		+= module.o
obj-$(CONFIG_KPROBES)		+= kprobes.o
ifeq ($(CONFIG_SECONDARY_SPACE_SUPPORT), y)
obj-$(CONFIG_SECONDARY_SPACE_SUPPORT)	+= sec_space.o
else
endif
obj-$(CONFIG_PRECISE_TIME)	+= precise_time.o

obj-$(CONFIG_FUNCTION_TRACER)	+= ftrace.o
obj-$(CONFIG_FTRACE_SYSCALLS)   += ftrace.o
obj-$(CONFIG_FUNCTION_GRAPH_TRACER) += ftrace_graph_entry.o
obj-$(CONFIG_STACKTRACE)        += stacktrace.o
obj-$(CONFIG_BOOT_TRACE) += boot_profiling.o

obj-$(CONFIG_E2K_STACKS_TRACER) += trace_stack.o

CFLAGS_clk_gate.o			= $(CFLAGS_E2S)
obj-$(CONFIG_E2S_CLK_GATE)		+= clk_gate.o

kernelclean:	dummy

