/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2026 MCST
 */

/*
 * The e2k 64-bit SIMD accelerated ChaCha20 (RFC7539)
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

/* QUARTERROUND updates a, b, c, d with a ChaCha "quarter" round. */
#define QUARTERROUND(a, b, c, d)                                      \
	(x[a] = __builtin_e2k_paddw(x[a], x[b]),                      \
	 tt = __builtin_e2k_pxord(x[d], x[a]),                        \
	 x[d] = __builtin_e2k_pshufb(tt, tt, 0x0504070601000302ull),  \
	 x[c] = __builtin_e2k_paddw(x[c], x[d]),                      \
	 tt = __builtin_e2k_pxord(x[b], x[c]),                        \
	 x[b] = __builtin_e2k_pord(__builtin_e2k_psllw(tt, 12),       \
				   __builtin_e2k_psrlw(tt, 32 - 12)), \
	 x[a] = __builtin_e2k_paddw(x[a], x[b]),                      \
	 tt = __builtin_e2k_pxord(x[d], x[a]),                        \
	 x[d] = __builtin_e2k_pshufb(tt, tt, 0x0605040702010003ull),  \
	 x[c] = __builtin_e2k_paddw(x[c], x[d]),                      \
	 tt = __builtin_e2k_pxord(x[b], x[c]),                        \
	 x[b] = __builtin_e2k_pord(__builtin_e2k_psllw(tt, 7),        \
				   __builtin_e2k_psrlw(tt, 32 - 7)))

void chacha_crypt_e2kv3(u32 *state, u8 *dst, const u8 *src, unsigned int bytes,
			int nrounds)
{
	u64 input_x2[CHACHA_STATE_WORDS];
	u64 buf[CHACHA_STATE_WORDS];
	size_t todo, i;

#pragma ivdep
#pragma unroll(16)
	for (i = 0; i < CHACHA_STATE_WORDS; i++) {
		input_x2[i] = state[i] * 0x100000001ull;
	}

	state[12] += round_up(bytes, CHACHA_BLOCK_SIZE) / CHACHA_BLOCK_SIZE;
	input_x2[12] = __builtin_e2k_paddw(input_x2[12], 0x100000000ull);

#pragma loop count(1000)
	while (bytes > 0) {
		u64 buf_tran[CHACHA_STATE_WORDS];
		u64 x[CHACHA_STATE_WORDS], tt;
		u64 *__restrict__ outw = (u64 *)dst;

		for (i = 0; i < CHACHA_STATE_WORDS; i++)
			x[i] = input_x2[i];

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
#pragma loop count(16)
		for (i = 0; i < CHACHA_STATE_WORDS; i++)
			buf[i] = __builtin_e2k_paddw(x[i], input_x2[i]);

#pragma unroll(8)
#pragma ivdep
		for (i = 0; i < CHACHA_STATE_WORDS; i += 2) {
			const u64 fmtl = 0x0b0a090803020100ull;
			const u64 fmtr = 0x0f0e0d0c07060504ull;

			buf_tran[i / 2] =
				__builtin_e2k_pshufb(buf[i + 1], buf[i], fmtl);
			buf_tran[i / 2 + 8] =
				__builtin_e2k_pshufb(buf[i + 1], buf[i], fmtr);
		}

		todo = CHACHA_BLOCK_SIZE * 2;
		if (unlikely(bytes < todo)) {
			todo = round_down(bytes, sizeof(*outw));

#pragma ivdep
#pragma loop count(16)
			for (i = 0; i < todo; i += sizeof(*outw)) {
				*outw++ = __builtin_e2k_pxord(*(u64 *)&src[i],
							      buf_tran[i / 8]);
			}
#pragma ivdep
#pragma loop count(7)
			for (; i < bytes; i++) {
				dst[i] = src[i] ^ ((u8 *)buf_tran)[i];
			}
			return;
		}

#pragma ivdep
#pragma unroll(16)
		for (i = 0; i < todo; i += sizeof(*outw)) {
			*outw++ = __builtin_e2k_pxord(*(u64 *)&src[i],
						      buf_tran[i / 8]);
		}

		/*Advance 32-bit counters */
		input_x2[12] =
			__builtin_e2k_paddw(input_x2[12], 0x200000002ull);

		dst += todo;
		src += todo;
		bytes -= todo;
	}
}

static int chacha_e2kv3_stream_xor(struct skcipher_request *req,
				   const struct chacha_ctx *ctx, const u8 *iv)
{
	u32 state[CHACHA_STATE_WORDS] __aligned(8);
	struct skcipher_walk walk;
	int err;

	err = skcipher_walk_virt(&walk, req, false);

	chacha_init_generic(state, ctx->key, iv);

	while (walk.nbytes > 0) {
		unsigned int nbytes = walk.nbytes;

		if (nbytes < walk.total)
			nbytes = round_down(nbytes, walk.stride);

		if (crypto_simd_usable()) {
			chacha_crypt_e2kv3(state, walk.dst.virt.addr,
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

static int chacha_simd_e2kv3(struct skcipher_request *req)
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	struct chacha_ctx *ctx = crypto_skcipher_ctx(tfm);

	return chacha_e2kv3_stream_xor(req, ctx, req->iv);
}

struct skcipher_alg algs_chacha_e2kv3[] = {
	{
		.base.cra_name = "chacha20",
		.base.cra_driver_name = "chacha20-e2kv3",
		.base.cra_priority = 300,
		.base.cra_blocksize = 1,
		.base.cra_ctxsize = sizeof(struct chacha_ctx),
		.base.cra_module = THIS_MODULE,

		.min_keysize = CHACHA_KEY_SIZE,
		.max_keysize = CHACHA_KEY_SIZE,
		.ivsize = CHACHA_IV_SIZE,
		.chunksize = CHACHA_BLOCK_SIZE,
		.setkey = chacha20_setkey,
		.encrypt = chacha_simd_e2kv3,
		.decrypt = chacha_simd_e2kv3,
	},
};
