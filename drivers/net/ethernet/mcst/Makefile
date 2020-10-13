#
# Makefile for the MCST device drivers.
#

obj-$(CONFIG_ETH1000) += l_e1000.o
l_e1000-objs := l_e1000_nort.o l_e1000_rt.o
obj-$(CONFIG_SBUS_SUNLANCE) += sunlance_sbus.o
obj-$(CONFIG_PCI_SUNLANCE) += pci_sunlance.o
obj-$(CONFIG_RDMA_NET) += rdma_net/
obj-$(CONFIG_MCST_PCC) += pcc.o
