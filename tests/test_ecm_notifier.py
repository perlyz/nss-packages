#!/usr/bin/env python3
"""Host-side probes of extracted ECM code; no kernel/module/device operations."""
from pathlib import Path
import re
import subprocess
import tempfile

import argparse

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('source', type=Path, help='prepared qca-nss-ecm source directory')
parser.add_argument('kernel', type=Path, help='prepared Linux source directory')
args = parser.parse_args()
ECM = args.source / 'ecm_conntrack_notifier.c'
KERNEL = args.kernel


def function(source, name):
    match = re.search(r'^(?:static\s+)?(?:int|void)\s+' + name + r'\s*\(', source, re.M)
    assert match, name
    start = match.start()
    opening = source.index('{', match.end())
    depth, end = 1, opening + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end] + '\n'


PRELUDE = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
typedef uint32_t u32;
#define KERNEL_VERSION(a,b,c) (((a)<<16)|((b)<<8)|(c))
#define LINUX_VERSION_CODE KERNEL_VERSION(6,12,112)
#define NOTIFY_DONE 0
#define NOTIFY_STOP_MASK 0x8000
#define ECM_IPV6_ENABLE 1
#define CONFIG_NF_CONNTRACK_MARK 1
#define NFPROTO_IPV4 2
#define NFPROTO_IPV6 10
#define AF_INET 2
#define AF_INET6 10
#define IPCT_DESTROY 2
#define IPCT_MARK 8
#define DEBUG_ERROR(...) ((void)0)
#define DEBUG_WARN(...) ((void)0)
#define DEBUG_INFO(...) ((void)0)
#define DEBUG_TRACE(...) ((void)0)
#define unlikely(x) (x)
#define spin_lock_bh(x) ((void)(x))
#define spin_unlock_bh(x) ((void)(x))
#define spin_lock_irqsave(x,f) ((void)(x), (f)=0)
#define spin_unlock_irqrestore(x,f) ((void)(x), (void)(f))
#define rcu_assign_pointer(p,v) ((p)=(v))
#define rcu_dereference_raw(x) (x)
#define rcu_read_lock() ((void)0)
#define rcu_read_unlock() ((void)0)
#define trace_notifier_register(...) ((void)0)
#define trace_notifier_unregister(...) ((void)0)
#define trace_notifier_run(...) ((void)0)
#define WARN(...) ((void)0)
#define S_IRUGO 0444
#define S_IWUSR 0200
struct nf_conn { int family; };
struct nf_ct_event { struct nf_conn *ct; u32 portid; int report; int ret; };
struct nf_ct_event_notifier {
    int (*ct_event)(unsigned int, const struct nf_ct_event *);
};
struct notifier_block {
    int (*notifier_call)(struct notifier_block *, unsigned long, void *);
    struct notifier_block *next;
    int priority;
};
struct atomic_notifier_head { unsigned int lock; struct notifier_block *head; };
struct net { struct { struct atomic_notifier_head nf_conntrack_chain; } ct; };
static struct net init_net;
static const struct nf_ct_event_notifier *single_cb;
static int sync_count;
#define synchronize_rcu() (++sync_count)
struct dentry { int dummy; };
static struct dentry directory;
static struct dentry *ecm_conntrack_notifier_dentry;
static int ecm_conntrack_notifier_lock, ecm_conntrack_notifier_stopped;
static int ecm_front_end_ipv4_stopped, ecm_front_end_ipv6_stopped;
static int destroys4, destroys6, marks4, marks6;
static int fault_proto, refs4, refs6;
static struct dentry *debugfs_create_dir(const char *n, struct dentry *p) { return &directory; }
static int ecm_debugfs_create_u32(const char *n, int m, struct dentry *p, u32 *v) { return 1; }
static void debugfs_remove_recursive(struct dentry *p) {}
static int nf_ct_l3num(struct nf_conn *ct) { return ct->family; }
static void ecm_conntrack_ipv4_event_destroy(struct nf_conn *ct) { ++destroys4; }
static void ecm_conntrack_ipv6_event_destroy(struct nf_conn *ct) { ++destroys6; }
static void ecm_conntrack_ipv4_event_mark(struct nf_conn *ct) { ++marks4; }
static void ecm_conntrack_ipv6_event_mark(struct nf_conn *ct) { ++marks6; }
static int nf_ct_netns_get(struct net *n, int proto) {
    if (fault_proto == proto) return -ENOMEM;
    if (proto == NFPROTO_IPV4) ++refs4; else ++refs6;
    return 0;
}
static void nf_ct_netns_put(struct net *n, int proto) {
    if (proto == NFPROTO_IPV4) { assert(refs4 > 0); --refs4; }
    else { assert(refs6 > 0); --refs6; }
}
'''

NONCHAIN = r'''
static void nf_conntrack_register_notifier(struct net *n, const struct nf_ct_event_notifier *nb) { single_cb=nb; }
static void nf_conntrack_unregister_notifier(struct net *n) { single_cb=NULL; }
'''

CHECKS = r'''
static int registered(void) {
#ifdef CONFIG_NF_CONNTRACK_CHAIN_EVENTS
    struct notifier_block *n=init_net.ct.nf_conntrack_chain.head;
    while (n) { if (n == &ecm_conntrack_notifier) return 1; n=n->next; }
    return 0;
#elif defined(CONFIG_NF_CONNTRACK_EVENTS)
    return single_cb != NULL;
#else
    return 0;
#endif
}
#ifdef CONFIG_NF_CONNTRACK_EVENTS
static void dispatch(struct nf_ct_event *ev, unsigned int events) {
#ifdef CONFIG_NF_CONNTRACK_CHAIN_EVENTS
    assert(atomic_notifier_call_chain(&init_net.ct.nf_conntrack_chain,events,ev)==NOTIFY_DONE);
#else
    assert(single_cb->ct_event(events,ev)==NOTIFY_DONE);
#endif
}
#endif
#ifdef CONFIG_NF_CONNTRACK_CHAIN_EVENTS
static int other_calls;
static int other_listener(struct notifier_block *nb, unsigned long events, void *ptr) {
    struct nf_ct_event *ev=ptr;
    ++other_calls;
    if (!ev->ret) ev->ret=-ENOBUFS;
    return NOTIFY_DONE;
}
static void coexist(int other_first) {
    struct notifier_block other={.notifier_call=other_listener};
    if (other_first) assert(!nf_conntrack_register_notifier(&init_net,&other));
    assert(!ecm_conntrack_notifier_init(&directory));
    if (!other_first) assert(!nf_conntrack_register_notifier(&init_net,&other));
    struct nf_conn ct={.family=AF_INET};
    struct nf_ct_event ev={.ct=&ct};
    int old_other=other_calls, old_destroy=destroys4;
    dispatch(&ev,1U<<IPCT_DESTROY);
    assert(other_calls==old_other+1 && destroys4==old_destroy+1);
    assert(ev.ret==-ENOBUFS);
    /* Also exercise a retried event with an already recorded error. */
    dispatch(&ev,1U<<IPCT_DESTROY);
    assert(other_calls==old_other+2 && destroys4==old_destroy+2);
    assert(ev.ret==-ENOBUFS);
    ecm_conntrack_notifier_exit();
    assert(!registered());
    assert(!nf_conntrack_unregister_notifier(&init_net,&other));
}
#endif
int main(void) {
    assert(!ecm_conntrack_notifier_init(&directory));
#ifdef CONFIG_NF_CONNTRACK_EVENTS
    assert(registered() && refs4==1 && refs6==1);
    struct nf_conn ct={.family=AF_INET};
    struct nf_ct_event ev={.ct=&ct,.ret=-ENOBUFS};
    dispatch(&ev,(1U<<IPCT_DESTROY)|(1U<<IPCT_MARK));
    assert(destroys4==1 && marks4==1 && destroys6==0);
    assert(ev.ret==-ENOBUFS);
    ct.family=AF_INET6;
    dispatch(&ev,(1U<<IPCT_DESTROY)|(1U<<IPCT_MARK));
    assert(destroys6==1 && marks6==1);
    ct.family=99;
    dispatch(&ev,~0U);
    ev.ct=NULL; dispatch(&ev,~0U);
    ev.ct=&ct; ct.family=AF_INET;
    ecm_conntrack_notifier_stopped=1; dispatch(&ev,~0U);
    ecm_conntrack_notifier_stopped=0;
    ecm_front_end_ipv4_stopped=1; dispatch(&ev,~0U);
    ecm_front_end_ipv4_stopped=0;
    assert(destroys4==1 && marks4==1 && destroys6==1 && marks6==1);
#else
    assert(!registered() && !refs4 && !refs6);
#endif
    ecm_conntrack_notifier_exit();
    assert(!registered() && !refs4 && !refs6);
#ifdef CONFIG_NF_CONNTRACK_CHAIN_EVENTS
    assert(sync_count==1);
    coexist(0); coexist(1);
    puts("PASS: ECM and another subscriber both run in either registration order; errors preserved");
#endif
    puts("PASS: event dispatch/filtering and normal init/exit");
#ifdef CONFIG_NF_CONNTRACK_EVENTS
    for (int proto=NFPROTO_IPV4; proto<=NFPROTO_IPV6; proto+=8) {
        fault_proto=proto;
        int result=ecm_conntrack_notifier_init(&directory);
        assert(result==-ENOMEM);
        assert(refs4==0 && refs6==0);
        assert(!registered());
        printf("PASS: netns_get(%d) failure unregisters ECM and releases acquired references\n",proto);
    }
#endif
}
'''


def build_source(source, chain):
    callback = source[source.index('#ifdef CONFIG_NF_CONNTRACK_EVENTS'):
                      source.index('/*\n * ecm_conntrack_notifier_stop()')]
    helpers = ''.join(function(source, name) for name in
                      ('ecm_conntrack_ipv4_event', 'ecm_conntrack_ipv6_event'))
    lifecycle = ''.join(function(source, name) for name in
                        ('ecm_conntrack_notifier_init', 'ecm_conntrack_notifier_exit'))
    if chain:
        notifier=(KERNEL/'kernel/notifier.c').read_text()
        engine=''.join(function(notifier,name) for name in
                       ('notifier_chain_register','notifier_chain_unregister','notifier_call_chain',
                        'atomic_notifier_chain_register','atomic_notifier_chain_unregister',
                        'atomic_notifier_call_chain'))
        ecache=(KERNEL/'net/netfilter/nf_conntrack_ecache.c').read_text()
        engine+=''.join(function(ecache,name) for name in
                        ('nf_conntrack_register_notifier','nf_conntrack_unregister_notifier'))
    else:
        engine=NONCHAIN
    return PRELUDE+engine+helpers+callback+lifecycle+CHECKS


def main():
    source = ECM.read_text()
    with tempfile.TemporaryDirectory(prefix='test-ecm-notifier-') as directory:
        d = Path(directory)
        for mode in ('chain', 'single', 'events-off'):
            c, binary = d / 'probe.c', d / 'probe'
            c.write_text(build_source(source, mode == 'chain'))
            flags = []
            if mode != 'events-off':
                flags += ['-DCONFIG_NF_CONNTRACK_EVENTS=1']
            if mode == 'chain':
                flags += ['-DCONFIG_NF_CONNTRACK_CHAIN_EVENTS=1']
            subprocess.run(['cc', '-std=gnu11', '-O1', '-Wall', '-Wextra', '-Werror',
                            '-Wno-unused-parameter', '-Wno-unused-variable', '-Wno-unused-function',
                            '-fsanitize=undefined', *flags, str(c), '-o', str(binary)], check=True)
            print(mode, flush=True)
            subprocess.run([str(binary)], check=True)


if __name__=='__main__':
    main()
