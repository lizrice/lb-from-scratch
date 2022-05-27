#include "xdp_kern.h"
#include "xdp_liz.h"

#define IP_ADDRESS(x) (unsigned int)(172 + (17 << 8) + (0 << 16) + (x << 24))

struct bpf_map_def SEC("maps") my_map = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(__u32),
    .max_entries = 128,
};

SEC("xdp_liz")
int xdp_liz_hello(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    bpf_printk("Hey it's liz");

    struct S trace;
    int ret;
    trace.time = bpf_ktime_get_ns();
    ret = bpf_perf_event_output(ctx, &my_map, 0, &trace, sizeof(trace));
    if (ret)
        bpf_printk("perf_event_output failed: %d\n", ret);

    struct ethhdr *eth = data;
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_ABORTED;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    struct iphdr *iph = data + sizeof(struct ethhdr);
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
        return XDP_ABORTED;

    if (iph->protocol != IPPROTO_TCP)
        return XDP_PASS;

    bpf_printk("Got TCP packet from %x", iph->saddr);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
