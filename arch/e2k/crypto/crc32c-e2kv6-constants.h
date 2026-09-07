/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2026 MCST
 */

/*
 * Using hardware CLMUL instruction to accelerate the CRC32 disposal.
 * CRC32C polynomial:0x1EDC6F41(BE)/0x82F63B78(LE)
 *
 */

#define MAX_SIZE 32768

/* Reduce 262144 kbits to 1024 bits */
static const u32
	crc_long_const[2 * (((MAX_SIZE * 8) / 1024) - 1)] __aligned(4) = {
		/* x^261120 mod p(x)`, x^261184 mod p(x)` */
		0x4e1be204, 0x5b654f10,
		/* x^260096 mod p(x)`, x^260160 mod p(x)` */
		0xda8ef936, 0x1a8124d4,
		/* x^259072 mod p(x)`, x^259136 mod p(x)` */
		0x03925ce8, 0xc316d62a,
		/* x^258048 mod p(x)`, x^258112 mod p(x)` */
		0xe002997f, 0xec3fda46,
		/* x^257024 mod p(x)`, x^257088 mod p(x)` */
		0x782d49b1, 0xf9cdb4cf,
		/* x^256000 mod p(x)`, x^256064 mod p(x)` */
		0xf0803cb8, 0x80ed08da,
		/* x^254976 mod p(x)`, x^255040 mod p(x)` */
		0x52b9b377, 0xe55ab8f0,
		/* x^253952 mod p(x)`, x^254016 mod p(x)` */
		0xc9008942, 0x6381067f,
		/* x^252928 mod p(x)`, x^252992 mod p(x)` */
		0xb138b6cd, 0x66d768d7,
		/* x^251904 mod p(x)`, x^251968 mod p(x)` */
		0x66cbf66f, 0xf40277fe,
		/* x^250880 mod p(x)`, x^250944 mod p(x)` */
		0x2c4095e0, 0x3be1f51d,
		/* x^249856 mod p(x)`, x^249920 mod p(x)` */
		0x445c6097, 0x346f98da,
		/* x^248832 mod p(x)`, x^248896 mod p(x)` */
		0x918591a6, 0x582cdb61,
		/* x^247808 mod p(x)`, x^247872 mod p(x)` */
		0x8905a0b7, 0xa2fdc76c,
		/* x^246784 mod p(x)`, x^246848 mod p(x)` */
		0xcba57658, 0x65e048b4,
		/* x^245760 mod p(x)`, x^245824 mod p(x)` */
		0x4771f913, 0x2e7776e1,
		/* x^244736 mod p(x)`, x^244800 mod p(x)` */
		0x844d5d4d, 0x23eba743,
		/* x^243712 mod p(x)`, x^243776 mod p(x)` */
		0x32889c39, 0xa03f4f11,
		/* x^242688 mod p(x)`, x^242752 mod p(x)` */
		0x2e03f608, 0xed4b3ded,
		/* x^241664 mod p(x)`, x^241728 mod p(x)` */
		0xc3ac8492, 0x3644c1b4,
		/* x^240640 mod p(x)`, x^240704 mod p(x)` */
		0x71aed3e3, 0x7968a64c,
		/* x^239616 mod p(x)`, x^239680 mod p(x)` */
		0x020ac2ad, 0xcc9e356a,
		/* x^238592 mod p(x)`, x^238656 mod p(x)` */
		0x39b0bbac, 0xa341e8d6,
		/* x^237568 mod p(x)`, x^237632 mod p(x)` */
		0xbb010e94, 0xd3e49f36,
		/* x^236544 mod p(x)`, x^236608 mod p(x)` */
		0xe1ac7e85, 0x8108f485,
		/* x^235520 mod p(x)`, x^235584 mod p(x)` */
		0xffbd160c, 0x088ca01f,
		/* x^234496 mod p(x)`, x^234560 mod p(x)` */
		0x796cfbf2, 0x0e1930d5,
		/* x^233472 mod p(x)`, x^233536 mod p(x)` */
		0xb678fce4, 0xa71bd31a,
		/* x^232448 mod p(x)`, x^232512 mod p(x)` */
		0x857c93cd, 0x39bc3606,
		/* x^231424 mod p(x)`, x^231488 mod p(x)` */
		0x027880f4, 0x8ee01bfc,
		/* x^230400 mod p(x)`, x^230464 mod p(x)` */
		0x385e78c2, 0x18a19efe,
		/* x^229376 mod p(x)`, x^229440 mod p(x)` */
		0x0546f321, 0x4e6f41a4,
		/* x^228352 mod p(x)`, x^228416 mod p(x)` */
		0x31750986, 0x1c69e153,
		/* x^227328 mod p(x)`, x^227392 mod p(x)` */
		0xf598e5d9, 0x8d92f930,
		/* x^226304 mod p(x)`, x^226368 mod p(x)` */
		0xb83c1a24, 0x0b14f378,
		/* x^225280 mod p(x)`, x^225344 mod p(x)` */
		0xd3425a63, 0xb041c5a6,
		/* x^224256 mod p(x)`, x^224320 mod p(x)` */
		0x129e52da, 0x3d22008e,
		/* x^223232 mod p(x)`, x^223296 mod p(x)` */
		0x2bda58f1, 0x1137a0bd,
		/* x^222208 mod p(x)`, x^222272 mod p(x)` */
		0x5b5e8426, 0x22f5975a,
		/* x^221184 mod p(x)`, x^221248 mod p(x)` */
		0x91e16ac9, 0xa22ceb86,
		/* x^220160 mod p(x)`, x^220224 mod p(x)` */
		0x0aced7e7, 0xea0376c1,
		/* x^219136 mod p(x)`, x^219200 mod p(x)` */
		0x93f0d327, 0xb06470d4,
		/* x^218112 mod p(x)`, x^218176 mod p(x)` */
		0x2b4303aa, 0x13dd404c,
		/* x^217088 mod p(x)`, x^217152 mod p(x)` */
		0xf330d574, 0x36c9680c,
		/* x^216064 mod p(x)`, x^216128 mod p(x)` */
		0x7c1630b3, 0x976bf1f9,
		/* x^215040 mod p(x)`, x^215104 mod p(x)` */
		0x627ce3d7, 0x16e43bc4,
		/* x^214016 mod p(x)`, x^214080 mod p(x)` */
		0x3a101e90, 0x0c1205dc,
		/* x^212992 mod p(x)`, x^213056 mod p(x)` */
		0xcc0b9829, 0x0d69c0ac,
		/* x^211968 mod p(x)`, x^212032 mod p(x)` */
		0xe7455d2a, 0x9cb5bc79,
		/* x^210944 mod p(x)`, x^211008 mod p(x)` */
		0xc286aeca, 0x8d34099a,
		/* x^209920 mod p(x)`, x^209984 mod p(x)` */
		0xeb0491ce, 0x90823997,
		/* x^208896 mod p(x)`, x^208960 mod p(x)` */
		0x0acaf824, 0x50a06c86,
		/* x^207872 mod p(x)`, x^207936 mod p(x)` */
		0x21667704, 0xdb90af6d,
		/* x^206848 mod p(x)`, x^206912 mod p(x)` */
		0x851c4eba, 0xd578ef9e,
		/* x^205824 mod p(x)`, x^205888 mod p(x)` */
		0x954206d3, 0x14e8adc5,
		/* x^204800 mod p(x)`, x^204864 mod p(x)` */
		0x0e8c0e06, 0x78d4b491,
		/* x^203776 mod p(x)`, x^203840 mod p(x)` */
		0x345be8fb, 0xd640681e,
		/* x^202752 mod p(x)`, x^202816 mod p(x)` */
		0x2d878a7e, 0x0788eab5,
		/* x^201728 mod p(x)`, x^201792 mod p(x)` */
		0xbcf4f398, 0xf8e01151,
		/* x^200704 mod p(x)`, x^200768 mod p(x)` */
		0xe709b46b, 0xb9e80571,
		/* x^199680 mod p(x)`, x^199744 mod p(x)` */
		0x8961d426, 0xea7ff256,
		/* x^198656 mod p(x)`, x^198720 mod p(x)` */
		0x6f4a07f7, 0xb76e2d72,
		/* x^197632 mod p(x)`, x^197696 mod p(x)` */
		0x7f44b5bf, 0xf8d010a0,
		/* x^196608 mod p(x)`, x^196672 mod p(x)` */
		0xfbcba18e, 0x65059450,
		/* x^195584 mod p(x)`, x^195648 mod p(x)` */
		0x29f4c4dd, 0xc9471851,
		/* x^194560 mod p(x)`, x^194624 mod p(x)` */
		0x1c90668b, 0x4bd8d801,
		/* x^193536 mod p(x)`, x^193600 mod p(x)` */
		0xf37abcdc, 0x58adfc83,
		/* x^192512 mod p(x)`, x^192576 mod p(x)` */
		0x3a49e585, 0x208e2ea9,
		/* x^191488 mod p(x)`, x^191552 mod p(x)` */
		0xdee9bb6c, 0xe1b79980,
		/* x^190464 mod p(x)`, x^190528 mod p(x)` */
		0xb5d6ff73, 0x88c913f0,
		/* x^189440 mod p(x)`, x^189504 mod p(x)` */
		0x38ef2e2c, 0x08a6a381,
		/* x^188416 mod p(x)`, x^188480 mod p(x)` */
		0x229f98be, 0x22c5adcc,
		/* x^187392 mod p(x)`, x^187456 mod p(x)` */
		0x90b3ae67, 0x9718fdc7,
		/* x^186368 mod p(x)`, x^186432 mod p(x)` */
		0xfa04f749, 0x2e7b0cec,
		/* x^185344 mod p(x)`, x^185408 mod p(x)` */
		0x79b5ce44, 0x31fa6c59,
		/* x^184320 mod p(x)`, x^184384 mod p(x)` */
		0x1b59cc7a, 0x209c6e45,
		/* x^183296 mod p(x)`, x^183360 mod p(x)` */
		0xba47cd6e, 0xe94f7470,
		/* x^182272 mod p(x)`, x^182336 mod p(x)` */
		0xdf4a7600, 0x35045674,
		/* x^181248 mod p(x)`, x^181312 mod p(x)` */
		0x5ba1b86b, 0x93ea1008,
		/* x^180224 mod p(x)`, x^180288 mod p(x)` */
		0x8ba685cc, 0x0cebb5b1,
		/* x^179200 mod p(x)`, x^179264 mod p(x)` */
		0x5f7e0352, 0xd8a38fb7,
		/* x^178176 mod p(x)`, x^178240 mod p(x)` */
		0xd7092944, 0xfb260ce6,
		/* x^177152 mod p(x)`, x^177216 mod p(x)` */
		0x4ae0cd9a, 0x001e0750,
		/* x^176128 mod p(x)`, x^176192 mod p(x)` */
		0xd3c24b79, 0xa6b9d5fb,
		/* x^175104 mod p(x)`, x^175168 mod p(x)` */
		0xd629c850, 0xb1075c22,
		/* x^174080 mod p(x)`, x^174144 mod p(x)` */
		0x154076b7, 0xa3b2a824,
		/* x^173056 mod p(x)`, x^173120 mod p(x)` */
		0xfd4d8094, 0x33da83bf,
		/* x^172032 mod p(x)`, x^172096 mod p(x)` */
		0xf54a494f, 0x087ff103,
		/* x^171008 mod p(x)`, x^171072 mod p(x)` */
		0x92fa182e, 0x07f7478f,
		/* x^169984 mod p(x)`, x^170048 mod p(x)` */
		0xa38f1001, 0xed137dd7,
		/* x^168960 mod p(x)`, x^169024 mod p(x)` */
		0x9969129d, 0xd9d45ec4,
		/* x^167936 mod p(x)`, x^168000 mod p(x)` */
		0x79359ac9, 0x7479c4c7,
		/* x^166912 mod p(x)`, x^166976 mod p(x)` */
		0x5e45b3d8, 0x58686946,
		/* x^165888 mod p(x)`, x^165952 mod p(x)` */
		0x9d413779, 0x187953cc,
		/* x^164864 mod p(x)`, x^164928 mod p(x)` */
		0x40a41642, 0x07dd0801,
		/* x^163840 mod p(x)`, x^163904 mod p(x)` */
		0x73b983e1, 0x5edcdeb9,
		/* x^162816 mod p(x)`, x^162880 mod p(x)` */
		0x6a503f64, 0x3ae9dfad,
		/* x^161792 mod p(x)`, x^161856 mod p(x)` */
		0x0b881080, 0x778fcc50,
		/* x^160768 mod p(x)`, x^160832 mod p(x)` */
		0x6da03243, 0x344e3b01,
		/* x^159744 mod p(x)`, x^159808 mod p(x)` */
		0xc96dbfc4, 0xb6afd2ff,
		/* x^158720 mod p(x)`, x^158784 mod p(x)` */
		0xc5fb3d8f, 0xe8695ce5,
		/* x^157696 mod p(x)`, x^157760 mod p(x)` */
		0x3e048b1f, 0x20f3da38,
		/* x^156672 mod p(x)`, x^156736 mod p(x)` */
		0x056d6030, 0xe5db24af,
		/* x^155648 mod p(x)`, x^155712 mod p(x)` */
		0x5ec18b57, 0x80295058,
		/* x^154624 mod p(x)`, x^154688 mod p(x)` */
		0xcf84d5aa, 0xec77fdae,
		/* x^153600 mod p(x)`, x^153664 mod p(x)` */
		0x928aaaa1, 0xecb4c29e,
		/* x^152576 mod p(x)`, x^152640 mod p(x)` */
		0xc7edac41, 0x291e6671,
		/* x^151552 mod p(x)`, x^151616 mod p(x)` */
		0x73ca59fa, 0x0f121b5e,
		/* x^150528 mod p(x)`, x^150592 mod p(x)` */
		0xb7cdd811, 0x6ee8e1d1,
		/* x^149504 mod p(x)`, x^149568 mod p(x)` */
		0x14864cbc, 0x0cfe7f1c,
		/* x^148480 mod p(x)`, x^148544 mod p(x)` */
		0x41e079a8, 0xe74aedb2,
		/* x^147456 mod p(x)`, x^147520 mod p(x)` */
		0xb9f53314, 0x57ac1403,
		/* x^146432 mod p(x)`, x^146496 mod p(x)` */
		0xe45a7005, 0x8031c47b,
		/* x^145408 mod p(x)`, x^145472 mod p(x)` */
		0x6f4aeb55, 0xbcf65005,
		/* x^144384 mod p(x)`, x^144448 mod p(x)` */
		0x85bfb924, 0x91208535,
		/* x^143360 mod p(x)`, x^143424 mod p(x)` */
		0x99371d03, 0x2144743e,
		/* x^142336 mod p(x)`, x^142400 mod p(x)` */
		0x5db16173, 0xb62a486d,
		/* x^141312 mod p(x)`, x^141376 mod p(x)` */
		0xab525961, 0x68e38fb7,
		/* x^140288 mod p(x)`, x^140352 mod p(x)` */
		0x8eff3b1d, 0xda670453,
		/* x^139264 mod p(x)`, x^139328 mod p(x)` */
		0x3de65471, 0xa335d306,
		/* x^138240 mod p(x)`, x^138304 mod p(x)` */
		0xc308c7d5, 0xfb624452,
		/* x^137216 mod p(x)`, x^137280 mod p(x)` */
		0x88d32d44, 0x9dfd8341,
		/* x^136192 mod p(x)`, x^136256 mod p(x)` */
		0x1ab2f0e2, 0x34874f2a,
		/* x^135168 mod p(x)`, x^135232 mod p(x)` */
		0x97681541, 0x1409a35b,
		/* x^134144 mod p(x)`, x^134208 mod p(x)` */
		0x6243767e, 0xab232012,
		/* x^133120 mod p(x)`, x^133184 mod p(x)` */
		0x00dca8d9, 0xb031d46e,
		/* x^132096 mod p(x)`, x^132160 mod p(x)` */
		0x240a1c8b, 0x8b5331b1,
		/* x^131072 mod p(x)`, x^131136 mod p(x)` */
		0xee157092, 0xbf455269,
		/* x^130048 mod p(x)`, x^130112 mod p(x)` */
		0xa0b62c6b, 0xb9475886,
		/* x^129024 mod p(x)`, x^129088 mod p(x)` */
		0x523cba25, 0xd847ebfd,
		/* x^128000 mod p(x)`, x^128064 mod p(x)` */
		0x4b651d13, 0x84950b74,
		/* x^126976 mod p(x)`, x^127040 mod p(x)` */
		0x7f911ea7, 0x5282b1be,
		/* x^125952 mod p(x)`, x^126016 mod p(x)` */
		0x87426d21, 0x6ca434d9,
		/* x^124928 mod p(x)`, x^124992 mod p(x)` */
		0xdb0dd1e8, 0xe45901d7,
		/* x^123904 mod p(x)`, x^123968 mod p(x)` */
		0x340796f4, 0x2b825750,
		/* x^122880 mod p(x)`, x^122944 mod p(x)` */
		0x43b954d4, 0x9714afd1,
		/* x^121856 mod p(x)`, x^121920 mod p(x)` */
		0xaaf94ade, 0x8e84845e,
		/* x^120832 mod p(x)`, x^120896 mod p(x)` */
		0x2cafc941, 0xc9f6cbf5,
		/* x^119808 mod p(x)`, x^119872 mod p(x)` */
		0xb258e12d, 0x9d078e29,
		/* x^118784 mod p(x)`, x^118848 mod p(x)` */
		0x7deb3e28, 0x86162060,
		/* x^117760 mod p(x)`, x^117824 mod p(x)` */
		0x4b03b134, 0x7fb7d61f,
		/* x^116736 mod p(x)`, x^116800 mod p(x)` */
		0xe9447266, 0xbd9b04e0,
		/* x^115712 mod p(x)`, x^115776 mod p(x)` */
		0xf5560dee, 0x44646491,
		/* x^114688 mod p(x)`, x^114752 mod p(x)` */
		0xf8f51cf1, 0xba8dd573,
		/* x^113664 mod p(x)`, x^113728 mod p(x)` */
		0xf5b2837e, 0x83ca94b9,
		/* x^112640 mod p(x)`, x^112704 mod p(x)` */
		0x87c037ff, 0xb158055f,
		/* x^111616 mod p(x)`, x^111680 mod p(x)` */
		0x8204240f, 0x06bda026,
		/* x^110592 mod p(x)`, x^110656 mod p(x)` */
		0xc413029a, 0x3b1d89ea,
		/* x^109568 mod p(x)`, x^109632 mod p(x)` */
		0x2c7e39f0, 0x7b6e116c,
		/* x^108544 mod p(x)`, x^108608 mod p(x)` */
		0x1c8e2cdc, 0x3ed57030,
		/* x^107520 mod p(x)`, x^107584 mod p(x)` */
		0xc5b1c200, 0x99acd5be,
		/* x^106496 mod p(x)`, x^106560 mod p(x)` */
		0x8b9c7ae2, 0x456ea1c5,
		/* x^105472 mod p(x)`, x^105536 mod p(x)` */
		0x467be36d, 0xf6df7ef5,
		/* x^104448 mod p(x)`, x^104512 mod p(x)` */
		0xf7cbfd8b, 0x2082707c,
		/* x^103424 mod p(x)`, x^103488 mod p(x)` */
		0x81098710, 0x5a454111,
		/* x^102400 mod p(x)`, x^102464 mod p(x)` */
		0x6dcb444c, 0xde5a3422,
		/* x^101376 mod p(x)`, x^101440 mod p(x)` */
		0x5a823daf, 0x9949e705,
		/* x^100352 mod p(x)`, x^100416 mod p(x)` */
		0x85c87ed9, 0xb8868422,
		/* x^99328 mod p(x)`, x^99392 mod p(x)` */
		0x241a5197, 0x8bc83fb7,
		/* x^98304 mod p(x)`, x^98368 mod p(x)` */
		0x2ce47958, 0x43eefc9f,
		/* x^97280 mod p(x)`, x^97344 mod p(x)` */
		0x91676284, 0x2cb874d8,
		/* x^96256 mod p(x)`, x^96320 mod p(x)` */
		0x0519866d, 0xc2d95be8,
		/* x^95232 mod p(x)`, x^95296 mod p(x)` */
		0xa5238a46, 0xee77077e,
		/* x^94208 mod p(x)`, x^94272 mod p(x)` */
		0x21630e5c, 0x186d1391,
		/* x^93184 mod p(x)`, x^93248 mod p(x)` */
		0x097f34b0, 0x97c92d0c,
		/* x^92160 mod p(x)`, x^92224 mod p(x)` */
		0x6ded1610, 0x6e971abe,
		/* x^91136 mod p(x)`, x^91200 mod p(x)` */
		0x88912086, 0x038e406f,
		/* x^90112 mod p(x)`, x^90176 mod p(x)` */
		0x4bbd9038, 0x8a898a05,
		/* x^89088 mod p(x)`, x^89152 mod p(x)` */
		0xa02821c7, 0xefc3b747,
		/* x^88064 mod p(x)`, x^88128 mod p(x)` */
		0xa3e42074, 0xafc0eb67,
		/* x^87040 mod p(x)`, x^87104 mod p(x)` */
		0xe63e4467, 0xceeca6df,
		/* x^86016 mod p(x)`, x^86080 mod p(x)` */
		0xa3b59ad2, 0x9b9e9037,
		/* x^84992 mod p(x)`, x^85056 mod p(x)` */
		0x9ea96a84, 0x3346656f,
		/* x^83968 mod p(x)`, x^84032 mod p(x)` */
		0x4725f197, 0xd8c96934,
		/* x^82944 mod p(x)`, x^83008 mod p(x)` */
		0x0120907f, 0x71879d3c,
		/* x^81920 mod p(x)`, x^81984 mod p(x)` */
		0x6ef66eda, 0x8778fbde,
		/* x^80896 mod p(x)`, x^80960 mod p(x)` */
		0x6a6a01de, 0xfad639c0,
		/* x^79872 mod p(x)`, x^79936 mod p(x)` */
		0xb9a5c4d5, 0x8c117538,
		/* x^78848 mod p(x)`, x^78912 mod p(x)` */
		0x873d2c6b, 0x61d19c24,
		/* x^77824 mod p(x)`, x^77888 mod p(x)` */
		0xfcf8274e, 0xde8a8e12,
		/* x^76800 mod p(x)`, x^76864 mod p(x)` */
		0x5b49112f, 0x2b0016bb,
		/* x^75776 mod p(x)`, x^75840 mod p(x)` */
		0xcdc69f9f, 0xa32be27a,
		/* x^74752 mod p(x)`, x^74816 mod p(x)` */
		0xd43a788f, 0x89ba16be,
		/* x^73728 mod p(x)`, x^73792 mod p(x)` */
		0x86ad212a, 0xce2c905d,
		/* x^72704 mod p(x)`, x^72768 mod p(x)` */
		0x5dd97aeb, 0x290b696b,
		/* x^71680 mod p(x)`, x^71744 mod p(x)` */
		0xbce6071b, 0x9b7ad6c5,
		/* x^70656 mod p(x)`, x^70720 mod p(x)` */
		0xee50ed25, 0xc583df5b,
		/* x^69632 mod p(x)`, x^69696 mod p(x)` */
		0x7f58d0c9, 0x6d8f49d8,
		/* x^68608 mod p(x)`, x^68672 mod p(x)` */
		0x68f776eb, 0x05cb7d1d,
		/* x^67584 mod p(x)`, x^67648 mod p(x)` */
		0x47d6cdda, 0xeccb4578,
		/* x^66560 mod p(x)`, x^66624 mod p(x)` */
		0xc4249c72, 0x07253bd1,
		/* x^65536 mod p(x)`, x^65600 mod p(x)` */
		0xde174de0, 0x28461564,
		/* x^64512 mod p(x)`, x^64576 mod p(x)` */
		0xfcb2c534, 0x10ab9540,
		/* x^63488 mod p(x)`, x^63552 mod p(x)` */
		0x0dc9127e, 0xdc2ced79,
		/* x^62464 mod p(x)`, x^62528 mod p(x)` */
		0x2ad97dc2, 0xb7bc423a,
		/* x^61440 mod p(x)`, x^61504 mod p(x)` */
		0xc58481a4, 0xda1c4087,
		/* x^60416 mod p(x)`, x^60480 mod p(x)` */
		0x8e65eaf5, 0x4aeee379,
		/* x^59392 mod p(x)`, x^59456 mod p(x)` */
		0x03d723fc, 0xecbbe106,
		/* x^58368 mod p(x)`, x^58432 mod p(x)` */
		0xb9565f60, 0x75f6dccd,
		/* x^57344 mod p(x)`, x^57408 mod p(x)` */
		0xe371ff90, 0xefcf4f49,
		/* x^56320 mod p(x)`, x^56384 mod p(x)` */
		0x70d9c3a2, 0xd251fca9,
		/* x^55296 mod p(x)`, x^55360 mod p(x)` */
		0x3c8ac2d9, 0x717a8910,
		/* x^54272 mod p(x)`, x^54336 mod p(x)` */
		0x5629dc4a, 0x25500f9f,
		/* x^53248 mod p(x)`, x^53312 mod p(x)` */
		0xf6af967a, 0x59f4852c,
		/* x^52224 mod p(x)`, x^52288 mod p(x)` */
		0xefa45970, 0x064e5155,
		/* x^51200 mod p(x)`, x^51264 mod p(x)` */
		0x024e0e31, 0xa8b4118b,
		/* x^50176 mod p(x)`, x^50240 mod p(x)` */
		0xbe230609, 0x1b7e73c6,
		/* x^49152 mod p(x)`, x^49216 mod p(x)` */
		0xadf26d3f, 0x481bee08,
		/* x^48128 mod p(x)`, x^48192 mod p(x)` */
		0x879c7b34, 0x6994c2c1,
		/* x^47104 mod p(x)`, x^47168 mod p(x)` */
		0x1cfa0500, 0xda17456b,
		/* x^46080 mod p(x)`, x^46144 mod p(x)` */
		0x5ea60862, 0x0a154c1c,
		/* x^45056 mod p(x)`, x^45120 mod p(x)` */
		0x216d8ecc, 0x84e3f8c8,
		/* x^44032 mod p(x)`, x^44096 mod p(x)` */
		0xe482dd73, 0x2b7fc988,
		/* x^43008 mod p(x)`, x^43072 mod p(x)` */
		0x034ea075, 0xaca289d5,
		/* x^41984 mod p(x)`, x^42048 mod p(x)` */
		0x4727dd68, 0xf1dad8f4,
		/* x^40960 mod p(x)`, x^41024 mod p(x)` */
		0x23df6ea3, 0x8eeafe04,
		/* x^39936 mod p(x)`, x^40000 mod p(x)` */
		0x131cb5fc, 0xb3af8661,
		/* x^38912 mod p(x)`, x^38976 mod p(x)` */
		0x1bcdf5c9, 0x68e46ea2,
		/* x^37888 mod p(x)`, x^37952 mod p(x)` */
		0x055d72a5, 0x8af5e9ec,
		/* x^36864 mod p(x)`, x^36928 mod p(x)` */
		0x03f35094, 0xf65e86d6,
		/* x^35840 mod p(x)`, x^35904 mod p(x)` */
		0x056f14e9, 0x66fb3d79,
		/* x^34816 mod p(x)`, x^34880 mod p(x)` */
		0x7cba622e, 0x2600ffa6,
		/* x^33792 mod p(x)`, x^33856 mod p(x)` */
		0x73bd6305, 0x796c32bf,
		/* x^32768 mod p(x)`, x^32832 mod p(x)` */
		0xa2c4ac0b, 0x35d73a62,
		/* x^31744 mod p(x)`, x^31808 mod p(x)` */
		0x1c71b15f, 0xa957c550,
		/* x^30720 mod p(x)`, x^30784 mod p(x)` */
		0x3fcc8d32, 0x02331c01,
		/* x^29696 mod p(x)`, x^29760 mod p(x)` */
		0x7d1b369d, 0xd597ad7e,
		/* x^28672 mod p(x)`, x^28736 mod p(x)` */
		0xd15d9a78, 0x3a5275ea,
		/* x^27648 mod p(x)`, x^27712 mod p(x)` */
		0x1454cc0f, 0xebd59d26,
		/* x^26624 mod p(x)`, x^26688 mod p(x)` */
		0xede3395f, 0xd46d3063,
		/* x^25600 mod p(x)`, x^25664 mod p(x)` */
		0x5826bbfb, 0x9e7b1c10,
		/* x^24576 mod p(x)`, x^24640 mod p(x)` */
		0x922006cb, 0x5f60970f,
		/* x^23552 mod p(x)`, x^23616 mod p(x)` */
		0xa6525a0a, 0xe31b4008,
		/* x^22528 mod p(x)`, x^22592 mod p(x)` */
		0x97f1649c, 0xf373c3ac,
		/* x^21504 mod p(x)`, x^21568 mod p(x)` */
		0xfd7680f3, 0x46bf959e,
		/* x^20480 mod p(x)`, x^20544 mod p(x)` */
		0x3f40767f, 0xb5a50ab7,
		/* x^19456 mod p(x)`, x^19520 mod p(x)` */
		0x4c6d774a, 0xe31e7f5b,
		/* x^18432 mod p(x)`, x^18496 mod p(x)` */
		0x850276f5, 0xafc81338,
		/* x^17408 mod p(x)`, x^17472 mod p(x)` */
		0xe005a292, 0xe6aef08f,
		/* x^16384 mod p(x)`, x^16448 mod p(x)` */
		0xb814b2a8, 0x0d65762a,
		/* x^15360 mod p(x)`, x^15424 mod p(x)` */
		0xc0d7d524, 0x15e8653c,
		/* x^14336 mod p(x)`, x^14400 mod p(x)` */
		0xc2d18ffd, 0x196b1eae,
		/* x^13312 mod p(x)`, x^13376 mod p(x)` */
		0x1234fb04, 0x0e36a726,
		/* x^12288 mod p(x)`, x^12352 mod p(x)` */
		0x34c00815, 0x835305c9,
		/* x^11264 mod p(x)`, x^11328 mod p(x)` */
		0x88f54e54, 0x69c2af09,
		/* x^10240 mod p(x)`, x^10304 mod p(x)` */
		0xde8e94e7, 0x71892b1b,
		/* x^9216 mod p(x)`, x^9280 mod p(x)` */
		0xd9a5cac0, 0x4f47bf52,
		/* x^8192 mod p(x)`, x^8256 mod p(x)` */
		0x183b02a7, 0xe4172b16,
		/* x^7168 mod p(x)`, x^7232 mod p(x)` */
		0x95304752, 0x654f84e7,
		/* x^6144 mod p(x)`, x^6208 mod p(x)` */
		0x3c2682ff, 0x631bb273,
		/* x^5120 mod p(x)`, x^5184 mod p(x)` */
		0xb7786c15, 0xb469724f,
		/* x^4096 mod p(x)`, x^4160 mod p(x)` */
		0x3aded22a, 0x74c360a4,
		/* x^3072 mod p(x)`, x^3136 mod p(x)` */
		0x1ee050e2, 0x67db2c4a,
		/* x^2048 mod p(x)`, x^2112 mod p(x)` */
		0x74d2ec5f, 0x88e56f72,
		/* x^1024 mod p(x)`, x^1088 mod p(x)` */
		0xb04de25a, 0xb8fdb1e7
	};

/*
 * Reduce final 1024-2048 bits to 64 bits, shifting 32 bits to include
 * the trailing 32 bits of zeros
 */
static const __v2di vcrc_short_const[(1024 * 2) / 128] __aligned(16) = {
	/* x^1952 mod p(x) , x^1984 mod p(x) , x^2016 mod p(x) , x^2048 mod p(x)  */
	{ 0x5cf015c388e56f72, 0x7fec2963e5bf8048 },
	/* x^1824 mod p(x) , x^1856 mod p(x) , x^1888 mod p(x) , x^1920 mod p(x)  */
	{ 0x963a18920246e2e6, 0x38e888d4844752a9 },
	/* x^1696 mod p(x) , x^1728 mod p(x) , x^1760 mod p(x) , x^1792 mod p(x)  */
	{ 0x419a441956993a31, 0x42316c00730206ad },
	/* x^1568 mod p(x) , x^1600 mod p(x) , x^1632 mod p(x) , x^1664 mod p(x)  */
	{ 0x924752ba2b830011, 0x543d5c543e65ddf9 },
	/* x^1440 mod p(x) , x^1472 mod p(x) , x^1504 mod p(x) , x^1536 mod p(x)  */
	{ 0x55bd7f9518e4a304, 0x78e87aaf56767c92 },
	/* x^1312 mod p(x) , x^1344 mod p(x) , x^1376 mod p(x) , x^1408 mod p(x)  */
	{ 0x6d76739fe0553f1e, 0x8f68fcec1903da7f },
	/* x^1184 mod p(x) , x^1216 mod p(x) , x^1248 mod p(x) , x^1280 mod p(x)  */
	{ 0xc133722b1fe0b5c3, 0x3f4840246791d588 },
	/* x^1056 mod p(x) , x^1088 mod p(x) , x^1120 mod p(x) , x^1152 mod p(x)  */
	{ 0x64b67ee0e55ef1f3, 0x34c96751b04de25a },
	/* x^928 mod p(x) , x^960 mod p(x) , x^992 mod p(x) , x^1024 mod p(x)  */
	{ 0x069db049b8fdb1e7, 0x156c8e180b4a395b },
	/* x^800 mod p(x) , x^832 mod p(x) , x^864 mod p(x) , x^896 mod p(x)  */
	{ 0xa11bfaf3c9e90b9e, 0xe0b99ccbe661f7be },
	/* x^672 mod p(x) , x^704 mod p(x) , x^736 mod p(x) , x^768 mod p(x)  */
	{ 0x817cdc5119b29a35, 0x041d37768cd75659 },
	/* x^544 mod p(x) , x^576 mod p(x) , x^608 mod p(x) , x^640 mod p(x)  */
	{ 0x1ce9d94b36c41f1c, 0x3a0777818cfaa965 },
	/* x^416 mod p(x) , x^448 mod p(x) , x^480 mod p(x) , x^512 mod p(x)  */
	{ 0x4f256efcb82be955, 0x0e148e8252377a55 },
	/* x^288 mod p(x) , x^320 mod p(x) , x^352 mod p(x) , x^384 mod p(x)  */
	{ 0xec1631edb2dea967, 0x9c25531d19e65dde },
	/* x^160 mod p(x) , x^192 mod p(x) , x^224 mod p(x) , x^256 mod p(x)  */
	{ 0x5d27e147510ac59a, 0x790606ff9957c0a6 },
	/* x^32 mod p(x) , x^64 mod p(x) , x^96 mod p(x) , x^128 mod p(x)  */
	{ 0xa66805eb18b8ea18, 0x82f63b786ea2d55c }
};
