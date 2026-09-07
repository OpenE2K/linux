/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2026 MCST
 */

/*
 * Using hardware CLMUL instruction to accelerate the CRC32 disposal.
 * CRC32C polynomial:0x1EDC6F41(BE)/0x82F63B78(LE)
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <crypto/internal/hash.h>
#include "crc32c-e2kv6.h"

static int __init crc32c_e2kv6_mod_init(void)
{
	if (cpu_has(CPU_FEAT_ISET_V6))
		return crypto_register_shash(&alg_crc32c_e2kv6);

	return -ENODEV;
}

static void __exit crc32c_e2kv6_mod_fini(void)
{
	crypto_unregister_shash(&alg_crc32c_e2kv6);
}

module_init(crc32c_e2kv6_mod_init);
module_exit(crc32c_e2kv6_mod_fini);

MODULE_AUTHOR("Rogerio Alves <rogealve@br.ibm.com>, "
	      "Alexander Troosh <trush@yandex.ru>");
MODULE_DESCRIPTION("CRC32c (Castagnoli) optimization using E2Kv6+ operations");
MODULE_LICENSE("GPL v2");

MODULE_ALIAS_CRYPTO("crc32c");
MODULE_ALIAS_CRYPTO("crc32c-e2kv6");
