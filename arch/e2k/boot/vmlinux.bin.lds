/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

SECTIONS
{
	.rodata : {
		input_data = .;
		*(.data)
		input_data_end = .;
	}
}
