#include <netinet/ip.h>
#include <sys/socket.h>
#include <stdint.h>

static const struct in6_addr in6addr_llmnr = {{{
      0xff,2,0,0,0,0,0,0,
      0,0,0,0,0,1,0,3}}};

int main(int argc, char **argv) {
  struct sockaddr_in6 addr = {};
  struct ipv6_mreq mreq;
  struct ip_mreq mreq4;
  char packet[512];
  int so = socket(AF_INET6, SOCK_DGRAM, 0);

  addr.sin6_family = AF_INET6;
  addr.sin6_port = htons(5355);
  addr.sin6_flowinfo = 0;
  addr.sin6_addr = in6addr_any;
  addr.sin6_scope_id = 0;
  bind(so, (struct sockaddr *)&addr, sizeof addr);

  mreq.ipv6mr_multiaddr = in6addr_llmnr;
  mreq.ipv6mr_interface = 0;
  setsockopt(so, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof mreq);

  mreq4.imr_multiaddr.s_addr = htonl((in_addr_t)0xe00000fc);
  mreq4.imr_interface.s_addr = htonl(INADDR_ANY);
  setsockopt(so, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq4, sizeof mreq4);

  for(;;) {
    recv(so, packet, 512, 0);
  }
}
