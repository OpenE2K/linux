#ifndef _ASM_L_PCIE_FIXUP_H_
#define _ASM_L_PCIE_FIXUP_H_

#undef	memset_io
#define memset_io(a,b,c)					\
({								\
	u64 i;							\
	for (i = 0; i != (c); i++) {				\
		writeb((b), (u8 *)(a) + i);			\
		readb((u8 *)(a) + i);				\
	}							\
})

#undef	memcpy_fromio
#define memcpy_fromio(a,b,c)    				\
({								\
	u64 i;							\
	for (i = 0; i != (c); i++) {				\
		u8 t = readb((u8 *)(b) + i);			\
		*((u8 *)(a) + i) = t;				\
	}							\
})

#undef	memcpy_toio
#define memcpy_toio(a,b,c)    					\
({								\
	u64 i;							\
	for (i = 0; i != (c); i++) {				\
		writeb(*((u8 *)(b) + i), (u8 *)(a) + i);	\
		readb((u8 *)(a) + i);				\
	}							\
})

#endif /*_ASM_L_PCIE_FIXUP_H_*/
