#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define ETH_ALEN 6
#define ETH_P_ARP 0x0806
#define ETH_P_IP 0x0800
#define ARPHRD_ETHER 1
#define XDP_PASS 2
#define XDP_DROP 1

char _license[] SEC("license") = "GPL";

// ARP event structure for ring buffer communication
struct arp_event
{
	unsigned char src_mac[ETH_ALEN];
	unsigned char dst_mac[ETH_ALEN];
	__be32 src_ip;
	__be32 dst_ip;
	__u16 opcode;
	__u64 timestamp;
};

// Ring buffer for event communication with userspace
struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} rb SEC(".maps");

static __inline __u64 now_ns(void)
{
	return bpf_ktime_get_ns();
}

SEC("xdp")
int capture_arp(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	// Validate ethernet header bounds
	if (data + sizeof(struct ethhdr) > data_end)
	{
		return XDP_PASS;
	}

	struct ethhdr *eth = data;

	// Only process ARP packets
	if (eth->h_proto != bpf_htons(ETH_P_ARP))
	{
		return XDP_PASS;
	}

	// Validate ARP header bounds
	if (data + sizeof(struct ethhdr) + sizeof(struct arphdr) > data_end)
	{
		return XDP_PASS;
	}

	struct arphdr *arp = data + sizeof(struct ethhdr);

	// Only process IPv4 ARP (Ethernet hardware, IPv4 protocol)
	if (arp->ar_hrd != bpf_htons(ARPHRD_ETHER) ||
		arp->ar_pro != bpf_htons(ETH_P_IP))
	{
		return XDP_PASS;
	}

	// Validate complete ARP packet bounds
	if (data + sizeof(struct ethhdr) + sizeof(struct arphdr) + 2 * ETH_ALEN +
			2 * sizeof(__be32) >
		data_end)
	{
		return XDP_PASS;
	}

	struct arp_event event = {};
	unsigned char *arp_data = (unsigned char *)(arp + 1);

	// Additional bounds check for ARP data access
	if ((unsigned char *)arp_data + 2 * ETH_ALEN + 2 * sizeof(__be32) >
		(unsigned char *)data_end)
	{
		return XDP_PASS;
	}

	// Extract MAC and IP addresses from ARP payload
	__builtin_memcpy(event.src_mac, arp_data, ETH_ALEN);
	event.src_ip = bpf_ntohl(*(__be32 *)(arp_data + ETH_ALEN));
	__builtin_memcpy(
		event.dst_mac,
		arp_data + ETH_ALEN + sizeof(__be32),
		ETH_ALEN
	);
	event.dst_ip =
		bpf_ntohl(*(__be32 *)(arp_data + ETH_ALEN + sizeof(__be32) + ETH_ALEN));

	event.opcode = bpf_ntohs(arp->ar_op);
	event.timestamp = now_ns();

	// Reserve space in ring buffer for event
	struct arp_event *ringbuf_space =
		bpf_ringbuf_reserve(&rb, sizeof(struct arp_event), 0);
	if (!ringbuf_space)
	{
		return XDP_PASS; // Skip if ring buffer is full
	}

	// Copy event data to ring buffer and submit
	__builtin_memcpy(ringbuf_space, &event, sizeof(struct arp_event));
	bpf_ringbuf_submit(ringbuf_space, 0);

	return XDP_PASS;
}
