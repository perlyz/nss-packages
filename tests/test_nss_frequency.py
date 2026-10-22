#!/usr/bin/env python3
"""Exercise actual NSS 11.4 frequency handlers with simulated sysctl/workqueues."""
import argparse
from pathlib import Path
from source_probe import function, run


PRELUDE = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#define compat_const const
#define __user
#define GFP_ATOMIC 0
#define NSS_CORE_0 0
#define NSS_CORE_STATE_INITIALIZED 1
#define NSS_FREQ_MAX_SCALE 3
#define NSS_FREQ_MID_SCALE 1
#define NSS_SAMPLE_BUFFER_SIZE 4
#define NSS_SAMPLE_BUFFER_MASK 3
#define NSS_MESSAGE_RATE_LIMIT 15000
#define NSS_FREQUENCY_SCALE_RATE_LIMIT_UP 2
#define NSS_FREQUENCY_SCALE_RATE_LIMIT_DOWN 60000
#define nss_trace(...) ((void)0)
#define nss_info(...) ((void)0)
#define printk(...) ((void)0)
#define BUG_ON(x) assert(!(x))
#define INIT_WORK(...) ((void)0)
typedef int nss_freq_scales_t;
struct ctl_table {void *data;};
struct workqueue_struct {int dummy;};
struct work_struct {int dummy;};
typedef struct {struct work_struct work; uint32_t frequency, stats_enable;} nss_work_t;
struct nss_ctx_instance {int state;};
static struct {struct nss_ctx_instance nss[1];} nss_top_main;
static struct {int current_freq, auto_scale;} nss_cmd_buf;
static struct {
    struct {uint32_t frequency, minimum, maximum;} freq_scale[3];
    uint32_t freq_scale_index, freq_scale_ready, freq_scale_rate_limit_up, freq_scale_rate_limit_down;
    uint32_t buffer[4], buffer_index, sum, sample_count, average, message_rate_limit, initialized;
} nss_runtime_samples;
static struct workqueue_struct queue;
static struct workqueue_struct *nss_wq;
static nss_work_t *nss_work;
static int fail_alloc, parser_error, queued, scaling_requests;
static uint32_t last_frequency, last_stats;
static int proc_dointvec(const struct ctl_table *ctl, int write, void *buffer, size_t *lenp, loff_t *ppos) {
    if (!*lenp) return 0;
    if (!write) {
        if (*ppos) {*lenp=0;return 0;}
        *(int *)buffer=*(int *)ctl->data; *lenp=sizeof(int); *ppos+=*lenp; return 0;
    }
    /* Include a parser that writes a partial value before reporting failure. */
    *(int *)ctl->data=*(int *)buffer; *ppos+=*lenp; return parser_error;
}
static void *kmalloc(size_t size, int flags) {return fail_alloc?NULL:malloc(size);}
static int queue_work(struct workqueue_struct *q, struct work_struct *w) {
    assert(q); nss_work_t *work=(void *)w;
    ++queued; last_frequency=work->frequency; last_stats=work->stats_enable; free(work); return 1;
}
static bool nss_freq_queue_work(void) {++scaling_requests;return true;}
'''

CHECKS = r'''
typedef int (*handler)(const struct ctl_table *,int,void *,size_t *,loff_t *);
static void reset(void) {
    memset(&nss_runtime_samples,0,sizeof(nss_runtime_samples));
    for(int i=0;i<3;++i) {
        nss_runtime_samples.freq_scale[i].frequency=100U<<i;
        nss_runtime_samples.freq_scale[i].minimum=10;
        nss_runtime_samples.freq_scale[i].maximum=100;
    }
    nss_runtime_samples.freq_scale_index=1; nss_runtime_samples.freq_scale_ready=1;
    nss_cmd_buf.current_freq=200; nss_cmd_buf.auto_scale=1;
    nss_wq=&queue; nss_top_main.nss[0].state=NSS_CORE_STATE_INITIALIZED;
    fail_alloc=parser_error=queued=scaling_requests=0;
}
static int request(handler h,int *data,int value) {
    struct ctl_table ctl={.data=data}; size_t len=sizeof(value); loff_t pos=0;
    return h(&ctl,1,&value,&len,&pos);
}
static void unchanged(void) {
    assert(nss_cmd_buf.current_freq==200 && nss_cmd_buf.auto_scale==1);
    assert(nss_runtime_samples.freq_scale_index==1 && nss_runtime_samples.freq_scale_ready==1);
    assert(!queued);
}
int main(void) {
    handler handlers[]={nss_current_freq_handler,nss_auto_scale_handler};
    for(int i=0;i<2;++i) {
        reset(); int *data=i?&nss_cmd_buf.auto_scale:&nss_cmd_buf.current_freq;
        struct ctl_table ctl={.data=data};
        int output=-1; size_t len=sizeof(output);loff_t pos=0;
        nss_wq=NULL;
        assert(!handlers[i](&ctl,0,&output,&len,&pos));
        assert(len==sizeof(int) && output==*data); unchanged();
        len=sizeof(output);
        assert(!handlers[i](&ctl,0,&output,&len,&pos) && !len); unchanged();
        int value=i?0:400;
        assert(request(handlers[i],data,value)==-EAGAIN); unchanged();
        nss_wq=&queue; nss_top_main.nss[0].state=0;
        assert(request(handlers[i],data,value)==-EAGAIN); unchanged();
        nss_top_main.nss[0].state=NSS_CORE_STATE_INITIALIZED;
        parser_error=-EINVAL;
        assert(request(handlers[i],data,value)==-EINVAL); unchanged();
        parser_error=0; fail_alloc=1;
        assert(request(handlers[i],data,value)==-ENOMEM); unchanged();
        fail_alloc=0;
        assert(request(handlers[i],data,i?2:999)==-EINVAL); unchanged();
    }
    reset();
    assert(!request(nss_current_freq_handler,&nss_cmd_buf.current_freq,400));
    assert(!nss_cmd_buf.auto_scale && nss_cmd_buf.current_freq==400 && last_frequency==400 && last_stats==1);
    int old_queued=queued;
    for(int i=0;i<20;++i)nss_freq_scale_frequency(&nss_top_main.nss[0],20);
    assert(!nss_cmd_buf.auto_scale && !scaling_requests && queued==old_queued);
    assert(nss_runtime_samples.initialized && nss_runtime_samples.average==20);
    assert(!request(nss_auto_scale_handler,&nss_cmd_buf.auto_scale,1));
    assert(nss_cmd_buf.auto_scale==1 && nss_cmd_buf.current_freq==200 && last_stats==1);
    assert(!nss_runtime_samples.sample_count && !nss_runtime_samples.freq_scale_ready);
    reset();
    assert(nss_freq_sched_change(2,false));
    assert(nss_runtime_samples.freq_scale_index==2 && !nss_cmd_buf.auto_scale && last_frequency==400);
    assert(!request(nss_auto_scale_handler,&nss_cmd_buf.auto_scale,0));
    assert(nss_cmd_buf.current_freq==400 && last_frequency==400 && last_stats==1);
    reset(); fail_alloc=1;
    assert(!nss_freq_sched_change(2,false)); unchanged();
    fail_alloc=0; nss_wq=NULL;
    assert(!nss_freq_sched_change(2,false)); unchanged();
    nss_wq=&queue;
    assert(!nss_freq_sched_change(-1,false) && !nss_freq_sched_change(3,false)); unchanged();
    nss_runtime_samples.freq_scale[0].frequency=0;
    assert(!nss_freq_sched_change(0,false)); unchanged();
    puts("PASS: read/EOF, parser/readiness/allocation failures, input validation, fixed stats, autoscale and PM index consistency");
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path, help='prepared NSS 11.4 driver source directory')
    root = parser.parse_args().source
    init, freq = (root / 'nss_init.c').read_text(), (root / 'nss_freq.c').read_text()
    extracted = ''.join(function(init, name) for name in (
        'nss_reset_frequency_stats_samples', 'nss_current_freq_handler', 'nss_auto_scale_handler'))
    extracted += function(freq, 'nss_freq_scale_frequency') + function(freq, 'nss_freq_sched_change')
    run(PRELUDE + extracted + CHECKS)


if __name__ == '__main__':
    main()
