#!/usr/bin/env python3
"""Exercise prepared ECM VLAN lookup and all eight NSS rule tag assignments."""
import argparse
from pathlib import Path
import re
import subprocess
import tempfile


def braces(source, start):
    opening = source.index('{', start)
    depth, end = 1, opening + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return end


PRELUDE = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#define ECM_DB_IFACE_HEIRARCHY_MAX 8
#define BRIDGE_VLAN_INFO_PVID 2
#define BRIDGE_VLAN_INFO_UNTAGGED 4
#define ECM_FRONT_END_VLAN_ID_NOT_CONFIGURED 0xffffffffU
#define NSS_IPV4_RULE_CREATE_VLAN_VALID 1
#define NSS_IPV6_RULE_CREATE_VLAN_VALID 1
#define DEBUG_WARN(...) ((void)0)
#define DEBUG_TRACE(...) ((void)0)
#define rcu_read_lock() ((void)0)
#define rcu_read_unlock() ((void)0)
struct net_device { int kind, refs, index; bool filtering, port, member; uint16_t vid, flags;
                    const char *name; struct net_device *real, *master; };
struct ecm_db_iface_instance { int index; };
struct bridge_vlan_info { uint16_t flags, vid; };
static int init_net;
static struct net_device devices[8];
static int ecm_db_iface_interface_identifier_get(struct ecm_db_iface_instance *i) { return i->index; }
static struct net_device *dev_get_by_index(void *n, int i) {
    if (i < 0 || i >= 8 || !devices[i].name) return NULL;
    ++devices[i].refs; return &devices[i];
}
static void dev_put(struct net_device *d) { assert(d->refs > 0); --d->refs; }
static int is_vlan_dev(struct net_device *d) { return d->kind == 1; }
static int netif_is_bridge_master(struct net_device *d) { return d->kind == 2; }
static int netif_is_bridge_port(struct net_device *d) { return d->port; }
static int br_vlan_enabled(struct net_device *d) { return d->filtering; }
static struct net_device *vlan_dev_next_dev(struct net_device *d) { return d->real; }
static struct net_device *vlan_dev_real_dev(struct net_device *d) {
    d=d->real; while (is_vlan_dev(d)) d=d->real; return d;
}
static uint16_t vlan_dev_vlan_id(struct net_device *d) { return d->vid; }
static struct net_device *netdev_master_upper_dev_get_rcu(struct net_device *d) { return d->master; }
static int br_vlan_get_info_rcu(struct net_device *d, uint16_t vid, struct bridge_vlan_info *i) {
    if (!d->member || vid != d->vid) return -1;
    i->vid=vid; i->flags=d->flags; return 0;
}
struct rule { struct {uint32_t ingress_vlan_tag, egress_vlan_tag;} vlan_primary_rule, vlan_secondary_rule;
              uint32_t valid_flags; };
static struct rule fresh(void) {
    struct rule r={.vlan_primary_rule={0xffffffffU,0xffffffffU},
                   .vlan_secondary_rule={0xffffffffU,0xffffffffU}}; return r;
}
static void balanced(void) { for (int i=0; i<8; ++i) assert(!devices[i].refs); }
'''

CHECKS = r'''
int main(void) {
    devices[0]=(struct net_device){.kind=2,.filtering=true,.name="br0"};
    devices[1]=(struct net_device){.name="eth0",.port=true,.master=&devices[0],.member=true,
                                  .vid=100,.flags=BRIDGE_VLAN_INFO_PVID|BRIDGE_VLAN_INFO_UNTAGGED};
    devices[2]=(struct net_device){.kind=1,.name="br0.100",.vid=100,.real=&devices[0]};
    devices[3]=(struct net_device){.kind=1,.name="br0.100.200",.vid=200,.real=&devices[2]};
    devices[4]=(struct net_device){.name="eth1"};
    devices[5]=(struct net_device){.kind=1,.name="eth1.200",.vid=200,.real=&devices[4]};
    struct ecm_db_iface_instance port={1},bridge={0},outer={2},inner={3},plain={5},missing={7};
    struct ecm_db_iface_instance *ifaces[8]={&port,&bridge,&outer,&inner};
    for (int i=4;i<8;++i) ifaces[i]=&missing;
    assert(ecm_interface_bridge_vlan_wire_tagged(&outer,ifaces,0)==0); balanced();
    assert(ecm_interface_bridge_vlan_wire_tagged(&inner,ifaces,0)==1); balanced();
    devices[3].vid=100; /* Equal VIDs must not strip the inner QinQ header. */
    assert(ecm_interface_bridge_vlan_wire_tagged(&inner,ifaces,0)==1); balanced();
    devices[3].vid=200;
    assert(ecm_interface_bridge_vlan_wire_tagged(&plain,ifaces,0)==1); balanced();
    devices[0].filtering=false;
    assert(ecm_interface_bridge_vlan_wire_tagged(&outer,ifaces,0)==1); balanced();
    devices[0].filtering=true;
    devices[1].flags=0;
    assert(ecm_interface_bridge_vlan_wire_tagged(&outer,ifaces,0)==1); balanced();
    devices[1].flags=BRIDGE_VLAN_INFO_PVID;
    assert(ecm_interface_bridge_vlan_wire_tagged(&outer,ifaces,0)==-1); balanced();
    devices[1].flags=BRIDGE_VLAN_INFO_UNTAGGED;
    assert(ecm_interface_bridge_vlan_wire_tagged(&outer,ifaces,0)==-1); balanced();
    devices[1].member=false;
    assert(ecm_interface_bridge_vlan_wire_tagged(&outer,ifaces,0)==-1); balanced();
    devices[1].member=true;
    assert(ecm_interface_bridge_vlan_wire_tagged(&outer,ifaces,1)==-1); balanced();
    assert(ecm_interface_bridge_vlan_wire_tagged(&missing,ifaces,0)==-1); balanced();
    assert(ecm_interface_bridge_vlan_wire_tagged(&port,ifaces,0)==-1); balanced();
    devices[1].flags=BRIDGE_VLAN_INFO_PVID|BRIDGE_VLAN_INFO_UNTAGGED;
    for (int i=0;i<8;++i) {
        struct rule r=fresh();
        assert(assignments[i](&r,&outer,ifaces,0,0,100));
        assert(!r.valid_flags);
        assert(assignments[i](&r,&inner,ifaces,0,1,200));
        assert(r.valid_flags);
        if (i%2==0) {
            assert(r.vlan_primary_rule.ingress_vlan_tag==200);
            assert(r.vlan_secondary_rule.ingress_vlan_tag==0xffffffffU);
        } else {
            assert(r.vlan_primary_rule.egress_vlan_tag==200);
            assert(r.vlan_secondary_rule.egress_vlan_tag==0xffffffffU);
        }
        balanced();
    }
    puts("PASS: tagged/access/asymmetric/missing memberships, QinQ (including equal VIDs), references and all 8 tag assignments");
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path, help='prepared ECM source directory')
    root = parser.parse_args().source
    source = (root / 'ecm_interface.c').read_text()
    start = source.index('int ecm_interface_bridge_vlan_wire_tagged(')
    helper = source[start:braces(source, start)]
    blocks = []
    for name in ('ecm_nss_ported_ipv4.c', 'ecm_nss_ported_ipv6.c',
                 'ecm_nss_non_ported_ipv4.c', 'ecm_nss_non_ported_ipv6.c'):
        source = (root / 'frontends/nss' / name).read_text()
        for match in re.finditer(r'switch \(ecm_interface_bridge_vlan_wire_tagged\(', source):
            block = source[match.start():braces(source, match.start())]
            number = len(blocks)
            blocks.append(f'''static bool assign{number}(struct rule *nircm,
                struct ecm_db_iface_instance *ii, struct ecm_db_iface_instance *ifaces[],
                int first, int count, uint32_t vlan_value) {{
                struct ecm_db_iface_instance **from_ifaces=ifaces, **to_ifaces=ifaces;
                int from_ifaces_first=first, to_ifaces_first=first;
                int interface_type_counts[]={{count}}, ii_type=0;
                bool rule_invalid=false;
                {block}
                return !rule_invalid;
            }}''')
    assert len(blocks) == 8
    signatures = '''static bool (*assignments[])(struct rule *, struct ecm_db_iface_instance *,
                    struct ecm_db_iface_instance **, int, int, uint32_t) = {''' + ','.join(f'assign{i}' for i in range(8)) + '};\n'
    with tempfile.TemporaryDirectory(prefix='test-ecm-vlan-') as directory:
        c, binary = Path(directory) / 'test.c', Path(directory) / 'test'
        c.write_text(PRELUDE + helper + '\n' + '\n'.join(blocks) + signatures + CHECKS)
        subprocess.run(['cc', '-std=gnu11', '-O1', '-Wall', '-Wextra', '-Werror',
                        '-Wno-unused-parameter', '-Wno-unused-variable', '-Wno-unused-function',
                        '-fsanitize=undefined', str(c), '-o', str(binary)], check=True)
        subprocess.run([str(binary)], check=True)


if __name__ == '__main__':
    main()
