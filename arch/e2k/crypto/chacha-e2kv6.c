/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2026 MCST
 */

/*
 * The e2k 128-bit SIMD accelerated ChaCha20 (RFC7539)
 */

#include <crypto/algapi.h>
#include <crypto/internal/chacha.h>
#include <crypto/internal/simd.h>
#include <crypto/internal/skcipher.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sizes.h>
#include <asm/simd.h>

#include <e2kintrin.h>

/* 128-bit SIMD version (it will also work for E2Kv5, but lcc-29-0 produce extremely slow code.) */

/* QUARTERROUND updates a, b, c, d with a ChaCha "quarter" round. */
#define QUARTERROUND(a, b, c, d)                                               \
	(x[a] = __builtin_e2k_qpaddw(x[a], x[b]),                              \
	 x[d] = __builtin_e2k_qpsrcw(__builtin_e2k_qpxor(x[d], x[a]),          \
				     32 - 16),                                 \
	 x[c] = __builtin_e2k_qpaddw(x[c], x[d]),                              \
	 x[b] = __builtin_e2k_qpsrcw(__builtin_e2k_qpxor(x[b], x[c]),          \
				     32 - 12),                                 \
	 x[a] = __builtin_e2k_qpaddw(x[a], x[b]),                              \
	 x[d] = __builtin_e2k_qpsrcw(__builtin_e2k_qpxor(x[d], x[a]), 32 - 8), \
	 x[c] = __builtin_e2k_qpaddw(x[c], x[d]),                              \
	 x[b] = __builtin_e2k_qpsrcw(__builtin_e2k_qpxor(x[b], x[c]), 32 - 7))

void chacha_crypt_e2kv6(u32 *state, u8 *dst, const u8 *src, unsigned int bytes,
			int nrounds)
{
	__v2di input_x4[CHACHA_STATE_WORDS];
	__v2di buf[CHACHA_STATE_WORDS];
	size_t todo, i;

#pragma ivdep
#pragma unroll(16)
	for (i = 0; i < CHACHA_STATE_WORDS; i++) {
		const __v2di fmt_x4 =
			(__v2di){ 0x0302010003020100LL, 0x0302010003020100LL };
		__v2di input = __builtin_e2k_qppackdl(0, (u64)state[i]);
		input_x4[i] = __builtin_e2k_qppermb(input, input, fmt_x4);
	}

	state[12] += round_up(bytes, CHACHA_BLOCK_SIZE) / CHACHA_BLOCK_SIZE;
	input_x4[12] = __builtin_e2k_qpaddw(
		input_x4[12], (__v2di){ 0x100000000LL, 0x300000002LL });

#pragma loop count(1000)
	while (bytes > 0) {
		__v2di buf_tran[CHACHA_STATE_WORDS];
		__v2di x[CHACHA_STATE_WORDS];
		__v2di *__restrict__ outw = (__v2di *)dst;

		for (i = 0; i < CHACHA_STATE_WORDS; i++)
			x[i] = input_x4[i];

#pragma loop count(10)
		for (i = nrounds; i > 0; i -= 2) {
			QUARTERROUND(0, 4, 8, 12);
			QUARTERROUND(1, 5, 9, 13);
			QUARTERROUND(2, 6, 10, 14);
			QUARTERROUND(3, 7, 11, 15);
			QUARTERROUND(0, 5, 10, 15);
			QUARTERROUND(1, 6, 11, 12);
			QUARTERROUND(2, 7, 8, 13);
			QUARTERROUND(3, 4, 9, 14);
		}

#pragma ivdep
#pragma unroll(16)
		for (i = 0; i < CHACHA_STATE_WORDS; i++)
			buf[i] = __builtin_e2k_qpaddw(x[i], input_x4[i]);
#pragma ivdep
#pragma unroll(4)
		for (i = 0; i < CHACHA_STATE_WORDS; i += 4) {
			const __v2di f1 = { 0x1716151407060504LL,
					    0x1f1e1d1c0f0e0d0cLL };
			const __v2di f0 = { 0x1312111003020100LL,
					    0x1b1a19180b0a0908LL };

			const __v2di f3 = { 0x0f0e0d0c0b0a0908LL,
					    0x1f1e1d1c1b1a1918LL };
			const __v2di f2 = { 0x0706050403020100LL,
					    0x1716151413121110LL };

			__v2di t0 =
				__builtin_e2k_qppermb(buf[i + 1], buf[i], f0);
			__v2di t1 =
				__builtin_e2k_qppermb(buf[i + 1], buf[i], f1);
			__v2di t2 = __builtin_e2k_qppermb(buf[i + 3],
							  buf[i + 2], f0);
			__v2di t3 = __builtin_e2k_qppermb(buf[i + 3],
							  buf[i + 2], f1);

			buf_tran[i / 4] = __builtin_e2k_qppermb(t2, t0, f2);
			buf_tran[i / 4 + 4] = __builtin_e2k_qppermb(t3, t1, f2);
			buf_tran[i / 4 + 8] = __builtin_e2k_qppermb(t2, t0, f3);
			buf_tran[i / 4 + 12] =
				__builtin_e2k_qppermb(t3, t1, f3);
		}

		todo = CHACHA_BLOCK_SIZE * 4;
		if (unlikely(bytes < todo)) {
			todo = round_down(bytes, sizeof(*outw));
#pragma ivdep
#pragma loop count(15)
			for (i = 0; i < todo; i += sizeof(*outw)) {
				*outw++ = __builtin_e2k_qpxor(
					*(__v2di *)&src[i], buf_tran[i / 16]);
			}
#pragma ivdep
#pragma loop count(15)
			for (; i < bytes; i++) {
				dst[i] = src[i] ^ ((u8 *)buf_tran)[i];
			}
			return;
		}

#pragma ivdep
#pragma unroll(16)
		for (i = 0; i < todo; i += sizeof(*outw)) {
			*outw++ = __builtin_e2k_qpxor(*(__v2di *)&src[i],
						      buf_tran[i / 16]);
		}

		/*Advance 32-bit counters */
		input_x4[12] = __builtin_e2k_qpaddw(
			input_x4[12], (__v2di){ 0x400000004LL, 0x400000004LL });

		dst += todo;
		src += todo;
		bytes -= todo;
	}
}

static int chacha_e2kv6_stream_xor(struct skcipher_request *req,
				   const struct chacha_ctx *ctx, const u8 *iv)
{
	u32 state[CHACHA_STATE_WORDS] __aligned(16);
	struct skcipher_walk walk;
	int err;

	err = skcipher_walk_virt(&walk, req, false);

	chacha_init_generic(state, ctx->key, iv);

	while (walk.nbytes > 0) {
		unsigned int nbytes = walk.nbytes;

		if (nbytes < walk.total)
			nbytes = round_down(nbytes, walk.stride);

		if (crypto_simd_usable()) {
			chacha_crypt_e2kv6(state, walk.dst.virt.addr,
					   walk.src.virt.addr, nbytes,
					   ctx->nrounds);
		} else {
			chacha_crypt_generic(state, walk.dst.virt.addr,
					     walk.src.virt.addr, nbytes,
					     ctx->nrounds);
		}
		err = skcipher_walk_done(&walk, walk.nbytes - nbytes);
	}

	return err;
}

static int chacha_simd_e2kv6(struct skcipher_request *req)
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	struct chacha_ctx *ctx = crypto_skcipher_ctx(tfm);

	return chacha_e2kv6_stream_xor(req, ctx, req->iv);
}

struct skcipher_alg algs_chacha_e2kv6[1] = {
	{
		.base.cra_name = "chacha20",
		.base.cra_driver_name = "chacha20-e2kv6",
		.base.cra_priority = 300,
		.base.cra_blocksize = 1,
		.base.cra_ctxsize = sizeof(struct chacha_ctx),
		.base.cra_module = THIS_MODULE,

		.min_keysize = CHACHA_KEY_SIZE,
		.max_keysize = CHACHA_KEY_SIZE,
		.ivsize = CHACHA_IV_SIZE,
		.chunksize = CHACHA_BLOCK_SIZE,
		.setkey = chacha20_setkey,
		.encrypt = chacha_simd_e2kv6,
		.decrypt = chacha_simd_e2kv6,
	},
};
