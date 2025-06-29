


EXTRA_CFLAGS += -I..
EXTRA_CFLAGS += -Ilibqdma/qdma_access
EXTRA_CFLAGS += -Iqdma_access
EXTRA_CFLAGS += -I../libqdma
EXTRA_CFLAGS += -I../libqdma/qdma_access
EXTRA_CFLAGS += -I../libqdma/qdma_access/qdma_soft_access
EXTRA_CFLAGS += -I../libqdma/qdma_access/eqdma_soft_access
EXTRA_CFLAGS += -I../libqdma/qdma_access/eqdma_cpm5_access
EXTRA_CFLAGS += -I../libqdma/qdma_access/qdma_cpm4_access


obj-$(CONFIG_MCST_QDMA_PF)+= qdma-pf.o

qdma-pf-objs := ../nl.o ../cdev.o ../qdma_mod.o

qdma-pf-objs += ../libqdma/qdma_mbox.o ../libqdma/qdma_intr.o ../libqdma/qdma_st_c2h.o \
        ../libqdma/qdma_thread.o ../libqdma/libqdma_export.o ../libqdma/qdma_context.o \
        ../libqdma/qdma_sriov.o ../libqdma/qdma_platform.o ../libqdma/qdma_descq.o ../libqdma/qdma_regs.o \
        ../libqdma/qdma_debugfs.o ../libqdma/qdma_debugfs_dev.o ../libqdma/qdma_debugfs_queue.o \
        ../libqdma/libqdma_config.o ../libqdma/qdma_device.o ../libqdma/xdev.o ../libqdma/thread.o

qdma-pf-objs += ../libqdma/qdma_access/qdma_mbox_protocol.o ../libqdma/qdma_access/qdma_list.o \
        ../libqdma/qdma_access/qdma_access_common.o ../libqdma/qdma_access/qdma_resource_mgmt.o \
        ../libqdma/qdma_access/qdma_cpm4_access/qdma_cpm4_access.o \
        ../libqdma/qdma_access/qdma_cpm4_access/qdma_cpm4_reg_dump.o \
        ../libqdma/qdma_access/qdma_soft_access/qdma_soft_access.o \
        ../libqdma/qdma_access/eqdma_soft_access/eqdma_soft_access.o \
        ../libqdma/qdma_access/eqdma_soft_access/eqdma_soft_reg_dump.o \
        ../libqdma/qdma_access/eqdma_cpm5_access/eqdma_cpm5_access.o \
        ../libqdma/qdma_access/eqdma_cpm5_access/eqdma_cpm5_reg_dump.o

