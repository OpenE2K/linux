/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef ELCAN_DEBUGFS_H__
#define ELCAN_DEBUGFS_H__


#ifdef CONFIG_DEBUG_FS
void elcan_dbg_board_init(struct elcan_priv *priv);
void elcan_dbg_board_exit(struct elcan_priv *priv);
void elcan_dbg_init(void);
void elcan_dbg_exit(void);
#else
static inline void elcan_dbg_board_init(struct elcan_priv *priv) {}
static inline void elcan_dbg_board_exit(struct elcan_priv *priv) {}
static inline void elcan_dbg_init(void) {}
static inline void elcan_dbg_exit(void) {}
#endif /* CONFIG_DEBUG_FS */


#endif /* ELCAN_DEBUGFS_H__ */
