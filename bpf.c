#include <stddef.h>
#include <stdint.h>

#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/pkt_cls.h>

#include <sys/socket.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>

#include "bpf_shared.h"
#include "bpf_helpers.h"

#define DEBUG 1

#if DEBUG
#define trace_printk(fmt, ...) do { \
        char _fmt[] = fmt; \
        bpf_trace_printk(_fmt, sizeof(_fmt), ##__VA_ARGS__); \
    } while (0)
#else
#define trace_printk(fmt, ...) {}
#endif

struct bpf_elf_map __section("maps") map_arp_cnt = {
    .type       = BPF_MAP_TYPE_HASH,
    .id         = BPF_MAP_ID_ARP_COUNT,
    .size_key   = sizeof(__u32),
    .size_value = sizeof(__u64),
    .max_elem   = 256,
};

static inline int is_arp_packet(struct __sk_buff *skb)
{
    __u16 proto = load_half(skb, offsetof(struct ethhdr, h_proto));
    return (proto == ETH_P_ARP);
}

static inline int arp_packet_type(struct __sk_buff *skb)
{
    return load_half(skb, ETH_HLEN + offsetof(struct arphdr, ar_op));
}

static inline void add_arp_cnt(__u32 ip, __s64 value)
{
    __u64 *cnt = bpf_map_lookup_elem(&map_arp_cnt, &ip);
    if (!cnt) {
        bpf_map_update_elem(&map_arp_cnt, &ip, &value, BPF_ANY);
    } else {
        __sync_fetch_and_add(cnt, value);
    }
}

static inline __u64 get_arp_cnt(__u32 ip)
{
    __u64 *cnt = bpf_map_lookup_elem(&map_arp_cnt, &ip);
    return (!cnt) ? 0 : *cnt;
}

__section("classifier") int cls_main(struct __sk_buff *skb)
{
    if (is_arp_packet(skb)) {
        trace_printk("[egress] ARP Packet: %d\n", arp_packet_type(skb));

        if (arp_packet_type(skb) != ARPOP_REQUEST) {
            goto KEEP;
        }

        /* In this moment, we only consider ARP protocol for IPv4. */
        __u16 proto = load_half(skb, ETH_HLEN + offsetof(struct arphdr, ar_pro));
        if (proto == ETH_P_IP) {
            __u32 ip = load_word(skb, ETH_HLEN + sizeof(struct arphdr) + 2 * ETH_ALEN + 4);
            add_arp_cnt(ip, 1);

            trace_printk("[egress] %x: %llu\n", ip, get_arp_cnt(ip));
        }
    }

KEEP:
    return -1;
}

__section("action") int act_main(struct __sk_buff *skb)
{
    if (is_arp_packet(skb)) {
        trace_printk("[ingress] ARP Packet: %d\n", arp_packet_type(skb));

        if (arp_packet_type(skb) != ARPOP_REPLY) {
            goto KEEP;
        }

        /* In this moment, we only consider ARP protocol for IPv4. */
        __u16 proto = load_half(skb, ETH_HLEN + offsetof(struct arphdr, ar_pro));
        if (proto == ETH_P_IP) {
            __u32 ip = load_word(skb, ETH_HLEN + sizeof(struct arphdr) + ETH_ALEN);
            if (get_arp_cnt(ip) > 0) {
                add_arp_cnt(ip, -1);

                trace_printk("[ingress] %x: %llu\n", ip, get_arp_cnt(ip));
            } else {
                trace_printk("[ingress] Ignored ARP packet (%x)\n", ip);

                goto DROP;
            }
        }
    }

KEEP:
    return TC_ACT_UNSPEC;

DROP:
    return TC_ACT_SHOT;
}

char __license[] __section("license") = "GPL";