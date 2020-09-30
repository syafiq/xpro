#include <arpa/inet.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <string.h>
#include <bpf/bpf_helpers.h>

SEC("xdp_prog")
int xdp_program(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	struct iphdr *ip;
	struct udphdr *udp;
	unsigned char *payload, *msg;
	unsigned int payload_size;
	unsigned char dest_inside[14];
	unsigned char msg_inside[5];
	unsigned int msg_n, dest_n;

	// sanity check
	ip = data + sizeof(*eth);
	udp = (void *)ip + sizeof(*ip);
	if ((void *)udp + sizeof(*udp) > data_end) {
		return XDP_PASS;
	}

	// if UDP
	if (ip->protocol == IPPROTO_UDP) {

		payload_size = ntohs(udp->len) - sizeof(*udp);
		payload = (unsigned char *)udp + sizeof(*udp);
		if ((void *)payload + payload_size > data_end)
			return XDP_PASS;

		if (htons(udp->dest) == 5683) { // if CoAP
			dest_n = bpf_probe_read_kernel_str(dest_inside, sizeof(dest_inside), payload);
			msg = (unsigned char *)payload + 14;
			msg_n = bpf_probe_read_kernel_str(msg_inside, sizeof(msg_inside), msg);
			if ((dest_n > 0) && (msg_n > 0)) {
				// bpf_printk("dest %s \n", dest_inside);
				// bpf_printk("msg %s \n", msg_inside);
			}
		}
	}

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
