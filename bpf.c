#include <linux/bpf.h>
#include <linux/pkt_cls.h>

#include "bpf_helpers.h"

#ifndef __section
#define __section(x)  __attribute__((section(x), used))
#endif

__section("classifier") int cls_main(struct __sk_buff *skb)
{
    return TC_ACT_UNSPEC;
}

__section("action") int act_main(struct __sk_buff *skb)
{
    goto KEEP;

KEEP:
    return TC_ACT_UNSPEC;

DROP:
    return TC_ACT_SHOT;
}

char __license[] __section("license") = "GPL";