#define KBUILD_MODNAME "mao"

#include <linux/if_ether.h>
#include <linux/ipv6.h>

#include <uapi/linux/bpf.h>
#include <bpf/bpf_helpers.h>



struct {

        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
        __type(key, u32);
        __type(value, u64);
        __uint(max_entries, 50);

} rx_counter SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_DEVMAP);
        __uint(key_size, sizeof(int));
        __uint(value_size, sizeof(int));
        __uint(max_entries, 100);
} tx_port SEC(".maps");


int indexM = 0;




inline unsigned short mao_ntohs_htons(char * firstP)
{
        unsigned short ret;
        *((char*)(&ret)) = firstP[1];
        *(((char*)(&ret))+1) = firstP[0];
        return ret;
}

inline unsigned int mao_ntohl_htonl(char * firstP)
{
        //no use
        unsigned int ret;
        *((char*)(&ret)) = firstP[3];
        *(((char*)(&ret))+1) = firstP[2];
        *(((char*)(&ret))+2) = firstP[1];
        *(((char*)(&ret))+3) = firstP[0];
        return ret;
}

inline unsigned short mao_ntohs_htons_val(unsigned short val)
{
        return mao_ntohs_htons((char*)(&val));
}

inline unsigned int mao_ntohl_htonl_val(unsigned int val)
{
        return mao_ntohl_htonl((char*)(&val));
}



SEC("mao_nat66")
int mao_nat66_xdp(struct xdp_md* ctx)
{
        u64 *counter = bpf_map_lookup_elem(&rx_counter, &indexM);
        if (counter) {
                *counter += 1;
        }


        void *data = (void *)(long)ctx->data;
        void *data_end = (void *)(long)(ctx->data_end);
        if (data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) > data_end) {
                return XDP_PASS;
        }

        struct ethhdr *eth = data;
        if (mao_ntohs_htons_val(eth->h_proto) != 0x86DD) {
                return XDP_PASS;
        }

        struct ipv6hdr *v6 = data + sizeof(struct ethhdr);
        if ((v6->daddr.in6_u.u6_addr8[0] & 0xF0) != 0x20) {
                return XDP_PASS;
        }

        return bpf_redirect_map(&tx_port, ctx->ingress_ifindex, XDP_PASS);
        // return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
