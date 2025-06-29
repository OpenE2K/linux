/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef MXGBE_DEBUGFS_H__
#define MXGBE_DEBUGFS_H__


#ifdef CONFIG_DEBUG_FS
void mxgbe_dbg_board_init(mxgbe_priv_t *priv);
void mxgbe_dbg_board_exit(mxgbe_priv_t *priv);
void mxgbe_dbg_init(void);
void mxgbe_dbg_exit(void);
#else
static inline void mxgbe_dbg_board_init(mxgbe_priv_t *priv) {}
static inline void mxgbe_dbg_board_exit(mxgbe_priv_t *priv) {}
static inline void mxgbe_dbg_init(void) {}
static inline void mxgbe_dbg_exit(void) {}
#endif /* CONFIG_DEBUG_FS */


#endif /* MXGBE_DEBUGFS_H__ */
