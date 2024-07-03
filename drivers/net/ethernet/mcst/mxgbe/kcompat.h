/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef MXGBE_KCOMPAT_H__
#define MXGBE_KCOMPAT_H__


#define MXGBE_I2C_CLASS I2C_CLASS_DEPRECATED
#define MXGBE_I2C_CHIPDEV parent

#ifndef DEFINE_PCI_DEVICE_TABLE
#define DEFINE_PCI_DEVICE_TABLE(_table) struct pci_device_id _table[]
#endif


#endif /* MXGBE_KCOMPAT_H__ */
