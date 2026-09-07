/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2026 MCST
 */

/*
 * e2k SIMD accelerated ChaCha20 (RFC7539)
 */

#include <crypto/algapi.h>
#include <crypto/internal/chacha.h>
#include <crypto/internal/simd.h>
#include <crypto/internal/skcipher.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sizes.h>
#include <asm/simd.h>

#include "chacha-glue.h"

void hchacha_block_arch(const u32 *state, u32 *stream, int nrounds)
{
	/* TODO: need implement hchacha_block_arch() later */
	hchacha_block_generic(state, stream, nrounds);
}
EXPORT_SYMBOL(hchacha_block_arch);

static __ro_after_init DEFINE_STATIC_KEY_FALSE(chacha_use_simd128);

void chacha_init_arch(u32 *state, const u32 *key, const u8 *iv)
{
	chacha_init_generic(state, key, iv);
}
EXPORT_SYMBOL(chacha_init_arch);

void chacha_crypt_arch(u32 *state, u8 *dst, const u8 *src, unsigned int bytes,
		       int nrounds)
{
	if (!crypto_simd_usable() /*|| bytes < CHACHA_BLOCK_SIZE*/)
		return chacha_crypt_generic(state, dst, src, bytes, nrounds);

	if (static_branch_likely(&chacha_use_simd128))
		return chacha_crypt_e2kv6(state, dst, src, bytes, nrounds);

	return chacha_crypt_e2kv3(state, dst, src, bytes, nrounds);
}
EXPORT_SYMBOL(chacha_crypt_arch);

static int __init chacha_simd_mod_init(void)
{
	if (!IS_REACHABLE(CONFIG_CRYPTO_SKCIPHER))
		return 0;

	if (cpu_has(CPU_FEAT_ISET_V6)) {
		static_branch_enable(&chacha_use_simd128);
		return crypto_register_skciphers(algs_chacha_e2kv6,
						 ARRAY_SIZE(algs_chacha_e2kv6));
	}
	return crypto_register_skciphers(algs_chacha_e2kv3,
					 ARRAY_SIZE(algs_chacha_e2kv3));
}

static void __exit chacha_simd_mod_fini(void)
{
	if (!IS_REACHABLE(CONFIG_CRYPTO_SKCIPHER))
		return;

	if (static_branch_likely(&chacha_use_simd128)) {
		return crypto_unregister_skciphers(
			algs_chacha_e2kv6, ARRAY_SIZE(algs_chacha_e2kv6));
	}
	return crypto_unregister_skciphers(algs_chacha_e2kv3,
					   ARRAY_SIZE(algs_chacha_e2kv3));
}

module_init(chacha_simd_mod_init);
module_exit(chacha_simd_mod_fini);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("MCST");
MODULE_DESCRIPTION("ChaCha20 stream cipher (e2k SIMD accelerated)");
MODULE_ALIAS_CRYPTO("chacha20");
MODULE_ALIAS_CRYPTO("chacha20-e2k");
