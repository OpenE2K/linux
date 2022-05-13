SECTIONS
{
	.rodata : {
		input_data = .;
		*(.data)
		input_data_end = .;
	}
}
