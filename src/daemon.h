/* SPDX-License-Identifier: MIT */
#ifndef KBOX_DAEMON_H
#define KBOX_DAEMON_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "seccomp.h"
#include "syscall-nr.h"

#define KBOX_DAEMON_DEFAULT_SOCK "/tmp/kboxd.sock"
#define KBOX_DAEMON_DEFAULT_CONFIG_REL ".config/kbox-config.yaml"
#define KBOX_DAEMON_BRIDGE_NAME "br0"
#define KBOX_DAEMON_DEFAULT_START_IP "172.18.0.2"
#define KBOX_DAEMON_DEFAULT_GW_IP "172.18.0.1"
#define KBOX_DAEMON_HOST_MASK "255.255.255.255"
#define KBOX_DAEMON_DNS_PORT 53
#define KBOX_DAEMON_MAX_HOSTS 512
#define KBOX_DAEMON_MAX_ALIAS 128

struct kbox_daemon_config {
    char start_ip[32];
    char gateway_ip[32];
};

int kbox_daemon_load_config(const char *path, struct kbox_daemon_config *cfg);
void kbox_daemon_set_config_path(const char *path);
int kbox_daemon_main(int argc, char **argv);
int kbox_daemon_run(const char *sock_path, const char *cmdline, int verbose);

/* Network subsystem (src/daemon-net.c). */
int kbox_daemon_net_init(const struct kbox_sysnrs *sysnrs,
                         const struct kbox_daemon_config *cfg,
                         int verbose);
void kbox_daemon_net_cleanup(void);
const char *kbox_daemon_net_gateway_ip(void);
int kbox_daemon_net_create_veth(const struct kbox_sysnrs *sysnrs,
                                const char *host_if,
                                const char *peer_if,
                                long peer_netns_fd,
                                const char *peer_ip);
int kbox_daemon_net_delete_link(const struct kbox_sysnrs *sysnrs,
                                const char *ifname,
                                const char *peer_ip);
int kbox_daemon_net_alloc_ip(char *buf, size_t len);
int kbox_daemon_dns_register(const char *name, const char *ip_str);
void kbox_daemon_dns_unregister_ip(const char *ip_str);
size_t kbox_daemon_dns_format_hosts(char *buf, size_t cap);
int kbox_daemon_port_add(const struct kbox_sysnrs *sysnrs,
                         const char *host_ip,
                         int host_port,
                         const char *container_ip,
                         int container_port);
void kbox_daemon_port_remove_ip(const char *container_ip);

#endif /* KBOX_DAEMON_H */
