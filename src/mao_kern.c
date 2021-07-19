#define KBUILD_MODNAME "mao"
#include <uapi/linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("mao_nat66")
int mao_nat66_xdp(struct xdp_md* ctx)
{
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
