#ifndef MXGBE_DEBUGFS_H__
#define MXGBE_DEBUGFS_H__


void mxgbe_print_all_regs(mxgbe_priv_t *priv, uint32_t regmsk);

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
