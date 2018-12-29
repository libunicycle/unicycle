#pragma once

#include <stddef.h>
#include <stdint.h>

struct __attribute__((packed)) uniboot_info {
    uint64_t magic;   // have to be UNIBOOT_MAGIC
    uint32_t version; // version of the boot info
    uint32_t length;  // total length of the info struct
    // entries data starts here
};

#define UNIBOOT_MAGIC 0x554e4943594b4cULL // 'UNICYKL'

// The struct is aligned by 8-bytes
struct __attribute__((packed)) uniboot_entry {
    uint32_t type;   // UNIBOOT_ENTRY_*
    uint32_t length; // length of the entry including this struct and following data
    // entry data starts here
};

#define UNIBOOT_ENTRY_MEMORY_MAP 1
#define UNIBOOT_ENTRY_SEGMENT_LIST 2
#define UNIBOOT_ENTRY_SECTION_LIST 3
#define UNIBOOT_ENTRY_FRAMEBUFFER 4
#define UNIBOOT_ENTRY_ACPI_INFO 5

#define UNIBOOT_MEM_RESERVED 1
#define UNIBOOT_MEM_UNUSABLE 2
#define UNIBOOT_MEM_ACPI 3
#define UNIBOOT_MEM_RAM 4
#define UNIBOOT_MEM_NVS 5

struct __attribute__((packed)) uniboot_memory_area {
    uint64_t type;   // UNIBOOT_MEM_*
    uint64_t start;  // memory area start address
    uint64_t length; // memory area length
};

struct __attribute__((packed)) uniboot_memory_map {
    uint32_t num; // number of areas in the map
    struct uniboot_memory_area areas[];
};

#define UNIBOOT_SEGTYPE_NULL 0    /* Program header table entry unused */
#define UNIBOOT_SEGTYPE_LOAD 1    /* Loadable program segment */
#define UNIBOOT_SEGTYPE_DYNAMIC 2 /* Dynamic linking information */
#define UNIBOOT_SEGTYPE_INTERP 3  /* Program interpreter */
#define UNIBOOT_SEGTYPE_NOTE 4    /* Auxiliary information */
#define UNIBOOT_SEGTYPE_SHLIB 5   /* Reserved */
#define UNIBOOT_SEGTYPE_PHDR 6    /* Entry for header table itself */
#define UNIBOOT_SEGTYPE_TLS 7     /* Thread-local storage segment */

#define UNIBOOT_SEGFLAG_X (1 << 0) /* Segment is executable */
#define UNIBOOT_SEGFLAG_W (1 << 1) /* Segment is writable */
#define UNIBOOT_SEGFLAG_R (1 << 2) /* Segment is readable */

struct __attribute__((packed)) uniboot_segment {
    uint32_t type;   /* Segment type */
    uint32_t flags;  /* Segment flags */
    uint64_t offset; /* Segment file offset */
    uint64_t vaddr;  /* Segment virtual address */
    uint64_t paddr;  /* Segment physical address */
    uint64_t filesz; /* Segment size in file */
    uint64_t memsz;  /* Segment size in memory */
    uint64_t align;  /* Segment alignment */
};

struct __attribute__((packed)) uniboot_segment_list {
    uint16_t num; // number of segments
    struct uniboot_segment segments[];
};

#define UNIBOOT_SECTTYPE_NULL 0           /* Section header table entry unused */
#define UNIBOOT_SECTTYPE_PROGBITS 1       /* Program data */
#define UNIBOOT_SECTTYPE_SYMTAB 2         /* Symbol table */
#define UNIBOOT_SECTTYPE_STRTAB 3         /* String table */
#define UNIBOOT_SECTTYPE_RELA 4           /* Relocation entries with addends */
#define UNIBOOT_SECTTYPE_HASH 5           /* Symbol hash table */
#define UNIBOOT_SECTTYPE_DYNAMIC 6        /* Dynamic linking information */
#define UNIBOOT_SECTTYPE_NOTE 7           /* Notes */
#define UNIBOOT_SECTTYPE_NOBITS 8         /* Program space with no data (bss) */
#define UNIBOOT_SECTTYPE_REL 9            /* Relocation entries, no addends */
#define UNIBOOT_SECTTYPE_SHLIB 10         /* Reserved */
#define UNIBOOT_SECTTYPE_DYNSYM 11        /* Dynamic linker symbol table */
#define UNIBOOT_SECTTYPE_INIT_ARRAY 14    /* Array of constructors */
#define UNIBOOT_SECTTYPE_FINI_ARRAY 15    /* Array of destructors */
#define UNIBOOT_SECTTYPE_PREINIT_ARRAY 16 /* Array of pre-constructors */
#define UNIBOOT_SECTTYPE_GROUP 17         /* Section group */
#define UNIBOOT_SECTTYPE_SYMTAB_SHNDX 18  /* Extended section indices */
#define UNIBOOT_SECTTYPE_NUM 19           /* Number of defined types. */

#define UNIBOOT_SECTFLAG_WRITE (1 << 0)            /* Writable */
#define UNIBOOT_SECTFLAG_ALLOC (1 << 1)            /* Occupies memory during execution */
#define UNIBOOT_SECTFLAG_EXECINSTR (1 << 2)        /* Executable */
#define UNIBOOT_SECTFLAG_MERGE (1 << 4)            /* Might be merged */
#define UNIBOOT_SECTFLAG_STRINGS (1 << 5)          /* Contains nul-terminated strings */
#define UNIBOOT_SECTFLAG_INFO_LINK (1 << 6)        /* `sh_info' contains SHT index */
#define UNIBOOT_SECTFLAG_LINK_ORDER (1 << 7)       /* Preserve order after combining */
#define UNIBOOT_SECTFLAG_OS_NONCONFORMING (1 << 8) /* Non-standard OS specific handling required */
#define UNIBOOT_SECTFLAG_GROUP (1 << 9)            /* Section is member of a group. */
#define UNIBOOT_SECTFLAG_TLS (1 << 10)             /* Section hold thread-local data. */

struct __attribute__((packed)) uniboot_section {
    uint32_t name;      /* Section name (string tbl index) */
    uint32_t type;      /* Section type UNIBOOT_SECTTYPE_* */
    uint64_t flags;     /* Section flags UNIBOOT_SECTFLAG_* */
    uint64_t addr;      /* Section virtual addr at execution */
    uint64_t size;      /* Section size in bytes */
    uint64_t addralign; /* Section alignment */
    uint64_t entsize;   /* Entry size if section holds table */
};

struct __attribute__((packed)) uniboot_section_list {
    uint16_t num; // number of ELF sections
    struct uniboot_section sections[];
};

struct __attribute__((packed)) uniboot_framebuffer {
    uint64_t base; // physical base addr
    uint32_t width;
    uint32_t height;
    uint32_t stride;
    uint32_t format;
};

// Framebuffer pixel format
#define UNIBOOT_PIXEL_FORMAT_UNKNOWN 0
#define UNIBOOT_PIXEL_FORMAT_RGB_x888 1
#define UNIBOOT_PIXEL_FORMAT_RGB_332 2
#define UNIBOOT_PIXEL_FORMAT_RGB_565 3
#define UNIBOOT_PIXEL_FORMAT_RGB_2220 4

struct __attribute__((packed)) uniboot_acpi_info {
    uint64_t acpi_root; // ACPI structure address
};

typedef __attribute__((noreturn)) void (*uniboot_entry_point_t)(struct uniboot_info *info);
