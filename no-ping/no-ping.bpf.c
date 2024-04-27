#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

static __always_inline unsigned int lookup_protocol(struct xdp_md *ctx)
{
	unsigned char protocol = 0;
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	if (data + sizeof(struct ethhdr) > data_end)
		return 0;

	if (bpf_ntohs(eth->h_proto) == ETH_P_IP)
	{
		struct iphdr *iph = data + sizeof(struct ethhdr);
		if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) <= data_end)
			protocol = iph->protocol;
	}
	return protocol;
}

int xdp_no_ping(struct xdp_md *ctx)
{
	int protocol = lookup_protocol(ctx);

	if (protocol == 1) {
		bpf_trace_printk("Hola - %d\n", protocol);
		return XDP_DROP;
	}

	return XDP_PASS;
}
