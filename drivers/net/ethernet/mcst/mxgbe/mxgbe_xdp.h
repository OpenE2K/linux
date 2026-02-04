/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef MXGBE_XDP_H__
#define MXGBE_XDP_H__

int mxgbe_run_xdp(struct bpf_prog *prog,
		  struct xdp_buff *xdp, mxgbe_priv_t *priv,
				mxgbe_rx_buff_t *rxq_buff, int qn);
int mxgbe_xdp_xmit_to_q(struct xdp_frame *xdpf,
			mxgbe_priv_t *priv, int qn, bool ndo);

#endif /* MXGBE_XDP_H__ */
