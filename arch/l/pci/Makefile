CFLAGS_pci.o += -Wno-deprecated-declarations
CFLAGS_irq.o += -Wno-deprecated-declarations

obj-$(CONFIG_PCI_ELBRUS)	+= direct.o
obj-$(CONFIG_PCI_ELBRUS)	+= l_pci.o

obj-$(CONFIG_PCI_ELBRUS)	+= pci.o
obj-$(CONFIG_ACPI)		+= acpi.o
obj-$(CONFIG_IOHUB_DOMAINS)	+= numa.o
obj-$(CONFIG_PCI_ELBRUS)	+= irq.o

obj-$(CONFIG_PCI_ELBRUS)	+= common.o
