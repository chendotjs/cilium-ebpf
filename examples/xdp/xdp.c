// +build ignore

#include "bpf_endian.h"
#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_MAP_ENTRIES 16

static inline __sum16 csum_fold(u32 csum)
{
	u32 sum = csum;
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	return ~sum;
}

/* Define an LRU hash map for storing packet count by source IPv4 address */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, MAX_MAP_ENTRIES);
	__type(key, __u32);   // source IPv4 address
	__type(value, __u32); // packet count
} xdp_stats_map SEC(".maps");

/*
Attempt to parse the IPv4 source address from the packet.
Returns 0 if there is no IPv4 header field; otherwise returns non-zero.
*/
static __always_inline int parse_ip_src_addr(struct xdp_md *ctx, __u32 *ip_src_addr) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;

	// First, parse the ethernet header.
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end) {
		return 0;
	}

	if (eth->h_proto != bpf_htons(ETH_P_IP)) {
		// The protocol is not IPv4, so we can't parse an IPv4 source address.
		return 0;
	}

	// Then parse the IP header.
	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end) {
		return 0;
	}

	// Return the source IP address in network byte order.
	*ip_src_addr = (__u32)(ip->saddr);

	u16 old_csum = ip->check;
	ip->check = 0;
	struct iphdr iphdr_old = *ip;
	ip->ttl--;
	// ip->ttl++;

	s64 csum_diff = bpf_csum_diff((__be32 *)&iphdr_old, sizeof(struct iphdr), (__be32 *)ip, sizeof(struct iphdr), 0);
	bpf_printk("csum_diff: %llx\n", csum_diff);


	// Method 1: 计算 diff 然后，在旧包的 checksum 基础上做增量更新。
	// 参考: https://github.com/xdp-project/xdp-tutorial/blob/9807816aa19be3cba73f3d35061c7cacad161b86/packet-solutions/xdp_prog_kern_03.c#L119-L123
	// bpf_csum_diff 的实现很简单，基于 csum_partial(). 这里计算基于修改 ttl 后的 iphdr 基于 iphdr_old 的增量。
	// ~old_csum 代表的含义: ~(Σiphdr) = checksum， 因此 ~checksum = Σiphdr
	u32 new_csum = bpf_csum_diff((__be32 *)&iphdr_old, sizeof(struct iphdr), (__be32 *)ip, sizeof(struct iphdr), ~old_csum);
	bpf_printk("new_csum: %llx\n", new_csum);

	// Method 2: 全量计算新的 csum
	// 参考: https://github.com/lizrice/lb-from-scratch/blob/86c369c8366f8a4b4b563d759959c18245b678d9/xdp_lb_kern.h#L23-L28
	// u32 new_csum = bpf_csum_diff(0, 0, (__be32 *)ip, sizeof(struct iphdr), 0);
	// bpf_printk("new_csum: %llx\n", new_csum);

	// 最后折叠 32bit 到 16bit
	ip->check = csum_fold(new_csum);

	return 1;
}

SEC("xdp")
int xdp_prog_func(struct xdp_md *ctx) {
	__u32 ip;
	if (!parse_ip_src_addr(ctx, &ip)) {
		// Not an IPv4 packet, so don't count it.
		goto done;
	}

	__u32 *pkt_count = bpf_map_lookup_elem(&xdp_stats_map, &ip);
	if (!pkt_count) {
		// No entry in the map for this IP address yet, so set the initial value to 1.
		__u32 init_pkt_count = 1;
		bpf_map_update_elem(&xdp_stats_map, &ip, &init_pkt_count, BPF_ANY);
	} else {
		// Entry already exists for this IP address,
		// so increment it atomically using an LLVM built-in.
		__sync_fetch_and_add(pkt_count, 1);
	}

done:
	// Try changing this to XDP_DROP and see what happens!
	return XDP_PASS;
}
