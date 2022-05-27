#include <stddef.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf_helpers.h>
#include <bpf_endian.h>

SEC("xdp/bye")
int goodbye_ping(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_ABORTED;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    struct iphdr *iph = data + sizeof(struct ethhdr);
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
        return XDP_ABORTED;

    // This is a ping packet
    if (iph->protocol == IPPROTO_ICMP) {
        bpf_printk("Got ICMP packet\n");
        return XDP_PASS;
    }

    if (iph->protocol == IPPROTO_TCP)
        bpf_printk("Got TCP packet\n");

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
