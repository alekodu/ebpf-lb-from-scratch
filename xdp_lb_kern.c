#include "xdp_lb_kern.h"

// Hard codes containers IP addresses
#define IP_ADDRESS(x) (unsigned int)(172 + (17 << 8) + (0 << 16) + (x << 24))

#define BACKEND_A 4
#define BACKEND_B 5
#define CLIENT 6
#define LB 3

SEC("xdp_lb")
int xdp_load_balancer(struct xdp_md *ctx)
{
    // Locates the ethernet header and the IP header in the packet (context data)
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    bpf_printk("got something");

    struct ethhdr *eth = data;
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_ABORTED;

    // Filter to only process IPv4 packets
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    struct iphdr *iph = data + sizeof(struct ethhdr);
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
        return XDP_ABORTED;

    // Filter to only process TCP packets
    if (iph->protocol != IPPROTO_TCP)
        return XDP_PASS;

    bpf_printk("Got TCP packet from %x", iph->saddr);

    // Checks that the packet comes from the client (a client request)
    if (iph->saddr == IP_ADDRESS(CLIENT))
    {
        // Implements a pseudo-random load balancing algorithm
        char be = BACKEND_A;
        if (bpf_ktime_get_ns() % 2)
            be = BACKEND_B;

        // Updates destination IP and MAC addresses based on the chosen backend (a request)
        iph->daddr = IP_ADDRESS(be);
        eth->h_dest[5] = be;
    } // Otherwise, packet comes from the backend (a backend response)
    else
    {
        // Updates destination IP and MAC addresses to the one of the client (a response)
        iph->daddr = IP_ADDRESS(CLIENT);
        eth->h_dest[5] = CLIENT;
    }

    // Updates source IP and MAC addresses to the one of the load balancer (for both requests and responses)
    iph->saddr = IP_ADDRESS(LB);
    eth->h_source[5] = LB;

    // Recalculates and replaces IP header checksum (since they have been updated)
    iph->check = iph_csum(iph);

    return XDP_TX;
}

char _license[] SEC("license") = "GPL";