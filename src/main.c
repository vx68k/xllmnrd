#include "llmnr.h"
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

static void run_service(void);

struct options {
    bool foreground;
};

static const struct in6_addr in6addr_llmnr = {
    {
        0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 3
    }
};

int main(int argc, char **argv) {
    struct options options = {
        .foreground = false,
    };

    if (options.foreground || daemon(false, false) == 0) {
        run_service();
    }
}

void run_service(void) {
    int so = llmnr_new_udp_socket();
    if (so < 0) {
        perror(NULL);
        return;
    }

    for (;;) {
        struct sockaddr_in6 from = {};
        char packet[512];
        char control[1024];
        struct iovec iov[1] = {
            {
                .iov_base = packet,
                .iov_len = 512,
            },
        };
        struct msghdr msg = {
            .msg_name = &from,
            .msg_namelen = sizeof from,
            .msg_iov = iov,
            .msg_iovlen = 1,
            .msg_control = control,
            .msg_controllen = 1024,
        };
        recvmsg(so, &msg, 0);
    }   
}

int llmnr_new_udp_socket(void) {
    int udp_socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (udp_socket != -1) {
        int reuseaddr = 1;
        struct sockaddr_in6 sin6 = {
            .sin6_family = AF_INET6,
            .sin6_port = htons(LLMNR_PORT),
            .sin6_addr = in6addr_any,
        };
        if (setsockopt(udp_socket, SOL_SOCKET, SO_REUSEADDR,
                &reuseaddr, sizeof reuseaddr) == 0 &&
            bind(udp_socket, (struct sockaddr*)&sin6, sizeof sin6) == 0) {

            struct ipv6_mreq ipv6mr = {
                .ipv6mr_multiaddr = in6addr_llmnr,
            };
            int recvpktinfo = 1;
            if (setsockopt(udp_socket, IPPROTO_IPV6, IPV6_JOIN_GROUP,
                    &ipv6mr, sizeof ipv6mr) == 0 &&
                setsockopt(udp_socket, IPPROTO_IPV6, IPV6_RECVPKTINFO,
                    &recvpktinfo, sizeof recvpktinfo) == 0) {

                int unicast_hops = 1;
                setsockopt(udp_socket, IPPROTO_IPV6, IPV6_UNICAST_HOPS,
                    &unicast_hops, sizeof unicast_hops);

#if 0
#ifdef IP_ADD_MEMBERSHIP
                struct ip_mreq imr;
                imr.imr_multiaddr.s_addr = htonl((in_addr_t)0xe00000fc);
                imr.imr_interface.s_addr = htonl(INADDR_ANY);
                setsockopt(udp_socket, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                    &imr, sizeof imr);
#endif
#endif

                return udp_socket;
            }
        }

        close(udp_socket);
    }
    return -1;
}