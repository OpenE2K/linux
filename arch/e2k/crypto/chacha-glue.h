/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2026 MCST
 */

void chacha_crypt_e2kv3(u32 *state, u8 *dst, const u8 *src, unsigned int bytes,
			int nrounds);
void chacha_crypt_e2kv6(u32 *state, u8 *dst, const u8 *src, unsigned int bytes,
			int nrounds);

extern struct skcipher_alg algs_chacha_e2kv3[1];
extern struct skcipher_alg algs_chacha_e2kv6[1];
