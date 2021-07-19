
#include <linux/bpf.h>
#include <linux/if_link.h>

#include <bpf/libbpf.h>

#include <unistd.h> // getopt()
#include <libgen.h> // basename()
#include <stdio.h>

int flags = XDP_FLAGS_UPDATE_IF_NOEXIST;

static void usage(const char* prog)
{
	fprintf(stderr,
		"%s: %s [OPTS] interface name list\n\n"
		"OPTS:\n"
		"    -S    use skb-mode\n"
		"    -F    force loading prog\n",
		__func__, prog);
}

int main(int argc, char **argv)
{

	int opt;
	const char *optstr = "S";
	while ((opt = getopt(argc, argv, optstr)) != -1) {
		switch (opt) {
			case 'S':
			{
				flags |= XDP_FLAGS_SKB_MODE;
				break;
			}
			default:
				usage(basename(argv[0]));
				return -1;
		}
	}
	if(!(flags & XDP_FLAGS_SKB_MODE))
		flags |= XDP_FLAGS_DRV_MODE;


	int prog_fd;
	struct bpf_object *obj;
	struct bpf_prog_load_attr mao_prog_load_attr = {
		.prog_type = BPF_PROG_TYPE_XDP,
		.file = "./mao_kern.o"
	};
	int ret = bpf_prog_load_xattr(&mao_prog_load_attr, &obj, &prog_fd);
	if (ret) {
		fprintf(stdout, "Fail to load xdp program, %d", ret);
		return ret;
	}
    return 0;
}

