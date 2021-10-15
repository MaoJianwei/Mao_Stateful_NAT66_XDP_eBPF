
#include <linux/bpf.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>


#include <linux/if_link.h>
#include <net/if.h>

#include <unistd.h> // getopt()
#include <libgen.h> // basename()
#include <stdio.h>
#include <errno.h> // errno, strerror()
#include <signal.h> // signal()
#include <stdlib.h> // exit()

int flags = XDP_FLAGS_UPDATE_IF_NOEXIST;

#define SUPPORTED_IFINDEX_NUM 3
int ifindex_list[SUPPORTED_IFINDEX_NUM] = {0,};
__u32 intf_prog_id[SUPPORTED_IFINDEX_NUM] = {0,};


#define CPU_NUMS_DEBUG 48


static int rx_counter_array_fd;
static int tx_port_map_fd;



static void usage(const char* prog)
{
        fprintf(stderr,
                "%s: %s [OPTS] interface name list\n\n"
                "OPTS:\n"
                "    -S    use skb-mode\n"
                "    -F    force loading prog\n",
                __func__, prog);
}


enum mao_log_level
{
        DEBUG = 1,
        INFO,
        WARN,
        ERROR
};
static void mao_print_log_ln(enum mao_log_level level, const char *str)
{
        char *l;
        switch(level) {
                case INFO: l = "INFO"; break;
                case WARN: l = "WARN"; break;
                case ERROR: l = "ERROR"; break;

                case DEBUG:
                default: l = "DEBUG"; break;
        }
        printf("\n====== Mao: [%s] %s\n\n", l, str);
}



static void hook_exit(int sig)
{
        mao_print_log_ln(INFO, "Detach XDP program from interfaces ...");

        __u32 prog_id;
        for(int i = 0; i < SUPPORTED_IFINDEX_NUM; i++) {

                if (0 == ifindex_list[i])
                        continue;

                prog_id = 0;
                int ret = bpf_get_link_xdp_id(ifindex_list[i], &prog_id, flags);
                if (ret) {
                        printf("Fail to get prog_id for ifindex: %d, flags: %d, ret: %d - %s\n", ifindex_list[i], flags, ret, strerror(errno));
                        continue;
                }

                if (intf_prog_id[i] == prog_id) {
                        int r_ret = bpf_set_link_xdp_fd(ifindex_list[i], -1, flags);
                        printf("Unset ifindex %d, flags: %X, ret: %d\n", ifindex_list[i], flags, r_ret);
                } else if (0 == prog_id) {
                        printf("No XDP program attached to ifindex: %d, flags: %d\n", ifindex_list[i], flags);
                } else {
                        printf("Our XDP program is replaced by prog_id %d, not detaching. ifindex: %d, flags: %d\n", prog_id, ifindex_list[i], flags);
                }
        }

        mao_print_log_ln(INFO, "Exit.");
        exit(0);
}


static void monitor_counter(void)
{

        int index = 0;

        __u64 prev[CPU_NUMS_DEBUG+1] = {0,};
        __u64 counter[CPU_NUMS_DEBUG+1] = {0,};

        int pps;


        int count = 1;
        while(1) {
                sleep(1);

                int ret = bpf_map_lookup_elem(rx_counter_array_fd, &index, counter+1);
                if (ret) {
                        printf("Fail to read rx counter, ret: %d, error: %s\n", ret, strerror(errno));
                        continue;
                }

                pps = 0;
                for (int i = 0; i < CPU_NUMS_DEBUG+1; i++) {
                        pps += (counter[i] - prev[i]);
                }
                memcpy(prev, counter, (CPU_NUMS_DEBUG+1) * sizeof(__u64));

                printf("========== Count: %d, %d pps ==========\n", count++, pps);
                for (int i = 0; i < CPU_NUMS_DEBUG+1; i++) {
                        printf("rx_counter[%d] = %lld\n", i, counter[i]);
                }
        }

}

int main(int argc, char **argv)
{

        int i;



        mao_print_log_ln(INFO, "Loading CLI params ...");

        int opt;
        const char *optstr = "S";
        while ((opt = getopt(argc, argv, optstr)) != -1) {
                switch (opt) {
                        case 'S':
                        {
                                flags |= XDP_FLAGS_SKB_MODE;
                                printf("Using skb mode ...\n");
                                break;
                        }
                        default:
                                usage(basename(argv[0]));
                                return -1;
                }
        }
        if(!(flags & XDP_FLAGS_SKB_MODE)) {
                flags |= XDP_FLAGS_DRV_MODE;
                printf("Using driver mode ...\n");
        }




        mao_print_log_ln(INFO, "Loading XDP program ...");

        int prog_fd;
        struct bpf_object *obj;
        struct bpf_prog_load_attr mao_prog_load_attr = {
                .prog_type = BPF_PROG_TYPE_XDP,
                .file = "./mao_kern.o"
        };
        int ret = bpf_prog_load_xattr(&mao_prog_load_attr, &obj, &prog_fd);
        if (ret) {
                printf("Fail to load xdp program, %d\n", ret);
                return ret;
        } else {
                printf("Loaded xdp program, prog_fd: %d\n", prog_fd);
        }



        mao_print_log_ln(INFO, "Search datastore maps ...");

        rx_counter_array_fd = bpf_object__find_map_fd_by_name(obj, "rx_counter");
        if (rx_counter_array_fd < 0) {
                printf("Fail to find rx_counter_array_fd\n");
                return rx_counter_array_fd;
        }
        tx_port_map_fd = bpf_object__find_map_fd_by_name(obj, "tx_port");
        if (tx_port_map_fd < 0) {
                printf("Fail to find tx_port_map_fd\n");
                return tx_port_map_fd;
        }



        mao_print_log_ln(INFO, "Get interface's index ...");

        ifindex_list[0] = if_nametoindex("eno1"); // to ip-S1
        ifindex_list[1] = if_nametoindex("eno2"); // to ip-S3
        for (i = 0; i < SUPPORTED_IFINDEX_NUM; i++) {
                printf("ifindex_list[%d] = %d\n", i, ifindex_list[i]);
        }
        // --- debug test as a line ---
        ret = bpf_map_update_elem(tx_port_map_fd, ifindex_list, ifindex_list+1, 0);
        if (ret != 0) {
                printf("Fail to add switch peer %d -> %d\n", ifindex_list[0], ifindex_list[1]);
                return ret;
        }
        ret = bpf_map_update_elem(tx_port_map_fd, ifindex_list+1, ifindex_list, 0);
                if (ret != 0) {
                printf("Fail to add switch peer %d -> %d\n", ifindex_list[1], ifindex_list[0]);
                return ret;
        }
        // ----------------------------


        mao_print_log_ln(INFO, "Attach XDP program to interfaces ...");

        for(i = 0; i < SUPPORTED_IFINDEX_NUM; i++) {

                if (0 == ifindex_list[i])
                        continue;

                int ret = bpf_set_link_xdp_fd(ifindex_list[i], prog_fd, flags);
                if (ret < 0) {
                        printf("Fail to set prog_fd %d => ifindex %d, flags: %X, ret: %d\n", prog_fd, ifindex_list[i], flags, ret);

                        // Rollback
                        int j;
                        for (j = 0; j < i; j++) {
                                int r_ret = bpf_set_link_xdp_fd(ifindex_list[i], -1, flags);
                                printf("Rollback ifindex %d, flags: %X, ret: %d\n", ifindex_list[i], flags, r_ret);
                        }
                        return ret;
                }


                struct bpf_prog_info info = {};
                __u32 info_len = sizeof(info);
                ret = bpf_obj_get_info_by_fd(prog_fd, &info, &info_len);
                if (ret) {
                        printf("Fail to get prog info - %d, %s\n", ret, strerror(errno));
                        return ret;
                }

                intf_prog_id[i] = info.id;

                printf("Set prog_fd %d => ifindex %d, flags: %X, prog_id: %d\n", prog_fd, ifindex_list[i], flags, info.id);
        }
        for (i = 0; i < SUPPORTED_IFINDEX_NUM; i++) {
                printf("intf_prog_id[%d] = %d\n", i, intf_prog_id[i]);
        }


        mao_print_log_ln(INFO, "Attach OK.");

        signal(SIGINT, hook_exit);
        signal(SIGTERM, hook_exit);

        mao_print_log_ln(INFO, "Set system signal hook for SIGINT & SIGTERM, OK. ");


        monitor_counter();

    return 0;
}

