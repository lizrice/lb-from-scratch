#include <stdio.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>
#include <signal.h>
#include <libbpf.h>
#include "xdp_liz.h"

static __u64 time_get_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000ull + ts.tv_nsec;
}

static __u64 start_time;
static __u64 cnt;

#define MAX_CNT 100000ll

static void print_bpf_output(void *ctx, int cpu, void *data, __u32 size)
{
    struct S *trace = data;

    printf("%lld\n", trace->time);
}

int main(int argc, char **argv)
{
    struct perf_buffer_opts pb_opts = {};
    struct bpf_link *link = NULL;
    struct perf_buffer *pb;
    struct bpf_object *obj;
    int map_fd, ret = 0;
    FILE *f;

    obj = bpf_object__open_file("xdp_liz_kern.o", NULL);
    if (libbpf_get_error(obj))
    {
        fprintf(stderr, "ERROR: opening BPF object file failed\n");
        return 0;
    }

    /* load BPF program */
    if (bpf_object__load(obj))
    {
        fprintf(stderr, "ERROR: loading BPF object file failed\n");
        goto cleanup;
    }

    map_fd = bpf_object__find_map_fd_by_name(obj, "my_map");
    if (map_fd < 0)
    {
        fprintf(stderr, "ERROR: finding a map in obj file failed\n");
        goto cleanup;
    }

    pb_opts.sample_cb = print_bpf_output;
    pb = perf_buffer__new(map_fd, 8, &pb_opts);
    ret = libbpf_get_error(pb);
    if (ret)
    {
        printf("failed to setup perf_buffer: %d\n", ret);
        return 1;
    }

    f = popen("taskset 1 dd if=/dev/zero of=/dev/null", "r");
    (void)f;

    start_time = time_get_ns();
    while ((ret = perf_buffer__poll(pb, 1000)) >= 0 && cnt < MAX_CNT)
    {
    }
    kill(0, SIGINT);

cleanup:
    bpf_link__destroy(link);
    bpf_object__close(obj);
    return ret;
}
