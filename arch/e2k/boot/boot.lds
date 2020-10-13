OUTPUT_FORMAT("elf64-e2k", "elf64-e2k", "elf64-e2k")
/* OUTPUT_ARCH(e2k) Defined by Makefile */
ENTRY(start)

MEMORY {
 AREA1 (RX) : ORIGIN = 0,   LENGTH = 64K
 AREA2 (RX) : ORIGIN = 64K, LENGTH = (64M - 64K)
}

SECTIONS {

	.x86 : {
		_x86 = .;
			arch/e2k/boot/x86.o(.rodata)
		_ex86 = .;
	} > AREA1

	.kernel : {
		. = ALIGN(512);
		_kernel = .;
			piggy.o(.rodata)
		_ekernel = .;
	} > AREA2

	__kernel_size  = _ekernel - _kernel;

}
