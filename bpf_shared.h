#ifndef __section
#define __section(x)    __attribute__((section(x), used))
#endif

enum {
    BPF_MAP_ID_ARP_COUNT,
    __MAX_BPF_MAP_ID
};

/* ELF file layout used by traffic control */
struct bpf_elf_map {
    __u32 type;
    __u32 size_key;
    __u32 size_value;
    __u32 max_elem;
    __u32 flags;
    __u32 id;
    __u32 pinning;
};