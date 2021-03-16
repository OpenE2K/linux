obj-y := iset_v2.o iset_v3.o iset_v5.o iset_v6.o cacheinfo.o recovery_string_v5.o

CFLAGS_REMOVE_iset_v2.o = $(CFLAGS_ALL_CPUS)
CFLAGS_REMOVE_iset_v3.o = $(CFLAGS_ALL_CPUS)
CFLAGS_REMOVE_iset_v5.o = $(CFLAGS_ALL_CPUS)
CFLAGS_REMOVE_iset_v6.o = $(CFLAGS_ALL_CPUS)
AFLAGS_REMOVE_recovery_string_v5.o = $(CFLAGS_ALL_CPUS)

CFLAGS_iset_v2.o := -march=elbrus-v2
CFLAGS_iset_v3.o := -march=elbrus-v3
CFLAGS_iset_v5.o := -march=elbrus-v5
CFLAGS_iset_v6.o := -march=elbrus-v6
AFLAGS_recovery_string_v5.o := -march=elbrus-v5

CFLAGS_REMOVE_boot_iset_v2.o += -pg
CFLAGS_boot_iset_v2.o += -DE2K_P2V -fno-ld-spec

CFLAGS_REMOVE_boot_iset_v3.o += -pg
CFLAGS_boot_iset_v3.o += -DE2K_P2V -fno-ld-spec

CFLAGS_REMOVE_boot_iset_v6.o += -pg
CFLAGS_boot_iset_v6.o += -DE2K_P2V -fno-ld-spec

ifdef CONFIG_FUNCTION_TRACER
# Do not profile debug and lowlevel utilities
CFLAGS_REMOVE_es2.o = -pg
CFLAGS_REMOVE_e2s.o = -pg
CFLAGS_REMOVE_e8c.o = -pg
CFLAGS_REMOVE_e1cp.o = -pg
CFLAGS_REMOVE_e8c2.o = -pg
CFLAGS_REMOVE_e12c.o = -pg
CFLAGS_REMOVE_e16c.o = -pg
CFLAGS_REMOVE_e2c3.o = -pg
endif

ifeq ($(CONFIG_E2K_MACHINE),y)
obj-$(CONFIG_E2K_ES2_DSP)	+= es2.o
obj-$(CONFIG_E2K_ES2_RU)	+= es2.o
obj-$(CONFIG_E2K_E2S)		+= e2s.o
obj-$(CONFIG_E2K_E8C)		+= e8c.o
obj-$(CONFIG_E2K_E1CP)		+= e1cp.o
obj-$(CONFIG_E2K_E8C2)		+= e8c2.o
obj-$(CONFIG_E2K_E12C)		+= e12c.o
obj-$(CONFIG_E2K_E16C)		+= e16c.o
obj-$(CONFIG_E2K_E2C3)		+= e2c3.o
else
CFLAGS_es2.o			= $(CFLAGS_ES2)
CFLAGS_e2s.o			= $(CFLAGS_E2S)
CFLAGS_e8c.o			= $(CFLAGS_E8C)
CFLAGS_e1cp.o			= $(CFLAGS_E1CP)
CFLAGS_e8c2.o			= $(CFLAGS_E8C2)
CFLAGS_e12c.o			= $(CFLAGS_E12C)
CFLAGS_e16c.o			= $(CFLAGS_E16C)
CFLAGS_e2c3.o			= $(CFLAGS_E2C3)
obj-y				+= es2.o e2s.o e8c.o e1cp.o e8c2.o e12c.o \
				   e16c.o e2c3.o
endif

