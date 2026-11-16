/* SPDX-License-Identifier: MIT */

#ifndef KBOX_NET_H
#define KBOX_NET_H

struct kbox_sysnrs;

int kbox_net_add_device(void);
int kbox_net_configure(const struct kbox_sysnrs *sysnrs);
int kbox_net_configure_ipv4(const struct kbox_sysnrs *sysnrs,
                            const char *ifname,
                            const char *ip_str,
                            const char *mask_str,
                            const char *gw_str);
int kbox_net_add_host_route(const struct kbox_sysnrs *sysnrs,
                            const char *ifname,
                            const char *ip_str);
int kbox_net_del_host_route(const struct kbox_sysnrs *sysnrs,
                            const char *ifname,
                            const char *ip_str);
void kbox_net_cleanup(void);
int kbox_net_is_active(void);
int kbox_net_register_socket(int lkl_fd, int supervisor_fd, int sock_type);
int kbox_net_pop_dgram_addr(int lkl_fd,
                            void *addr_out,
                            unsigned int *addrlen_io,
                            int peek);
void kbox_net_flush_socket(int lkl_fd);
void kbox_net_deregister_socket(int lkl_fd);
void kbox_net_set_listening(int lkl_fd);
void kbox_net_clear_listening_notify(int lkl_fd);

#endif /* KBOX_NET_H */
