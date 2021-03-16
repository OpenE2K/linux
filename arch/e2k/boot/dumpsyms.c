#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <malloc.h>
#include <fcntl.h>
#include <elf.h>

static Elf64_Shdr * elf_shdr_p;
static int input_fd;

static int
open_file (char * name,
           int flags,
           int mode)
{
    char error_message[1024];
    int fd;

    fd = open (name, flags, mode);
    if (fd < 0)
    {
        sprintf (error_message, "Can not open \'%s\'", name);
        perror (error_message);
        exit (1);
    }

    return fd;
}

static void *
read_from_file (long offset,
                long size)
{
    int r;
    void * ptr;

    ptr = malloc (size);
    if (ptr == 0)
    {
        perror ("malloc");
        exit (1);
    }

    r = lseek (input_fd, offset, SEEK_SET);
    if (r < 0)
    {
        perror ("lseek");
        exit (1);
    }

    r = read (input_fd, ptr, size);
    if (r < 0)
    {
        perror ("read");
        exit (1);
    }

    return ptr;
}

static void *
read_section (int section_index,
              long * size_p)
{
    long size, offset;

    size = elf_shdr_p[section_index].sh_size;
    offset = elf_shdr_p[section_index].sh_offset;

    if (size_p != 0)
    {
        *size_p = size;
    }

    return read_from_file (offset, size);
}

int
main (int argc, char **argv)
{
    Elf64_Ehdr elf_ehdr;
    Elf64_Off e_shoff, e_shentsize, e_shnum;
    int symtab_fd, strtab_fd, r, i, symtab_index, strtab_index;
    char * elf_sym_p, * elf_str_p;
    long symtab_size, strtab_size;

    if (argc != 4)
    {
        fprintf (stderr, "Usage: %s <input_file> <output_symtab> <output_strtab>\n", argv[0]);
        exit (1);
    }

    input_fd = open_file (argv[1], O_RDONLY, 0);
    symtab_fd = open (argv[2], O_CREAT | O_WRONLY, 0644);
    strtab_fd = open (argv[3], O_CREAT | O_WRONLY, 0644);

    /* ELF header */

    r = read (input_fd, (void *) &elf_ehdr, sizeof (elf_ehdr));
    if (r < 0)
    {
        perror ("read");
        exit (1);
    }

    if (elf_ehdr.e_ident[EI_CLASS] != ELFCLASS64)
    {
        fprintf (stderr, "Not ELF64\n");
        exit (1);
    }

    e_shoff = elf_ehdr.e_shoff;
    e_shentsize = elf_ehdr.e_shentsize;
    e_shnum = elf_ehdr.e_shnum;

    /* Section header table */

    elf_shdr_p = read_from_file (e_shoff, e_shentsize * e_shnum);

    /* Symbol table */

    symtab_index = 0;
    for (i = 0; i < e_shnum; i++)
    {
        if (elf_shdr_p[i].sh_type == SHT_SYMTAB)
        {
            symtab_index = i;
            break;
        }
    }

    if (symtab_index == 0)
    {
        fprintf (stderr, "Can not find symbol table\n");
        exit (1);
    }

    elf_sym_p = read_section (symtab_index, &symtab_size);

    /* String table */

    strtab_index = elf_shdr_p[symtab_index].sh_link;

    elf_str_p = read_section (strtab_index, &strtab_size);

    /* Write */

    r = write (symtab_fd, elf_sym_p, symtab_size);
    if (r < 0)
    {
        perror ("write");
        exit (1);
    }
    if (r != symtab_size)
    {
        fprintf (stderr, "Error while write symtab\n");
        exit (1);
    }

    r = write (strtab_fd, elf_str_p, strtab_size);
    if (r < 0)
    {
        perror ("write");
        exit (1);
    }
    if (r != strtab_size)
    {
        fprintf (stderr, "Error while write strtab\n");
        exit (1);
    }

    return 0;
}
