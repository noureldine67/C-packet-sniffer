#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

typedef struct ethernet_header ethernet_header;
typedef struct arp_header arp_header;

#pragma pack(push, 1)
struct ethernet_header {
  uint8_t ethernet_dest_addr[6];
  uint8_t ethernet_source_addr[6];
  uint16_t frame_type;
};

struct arp_header {
  uint16_t hardware_type;
  uint16_t protocol_type;
  uint8_t hardware_size;
  uint8_t protocol_size;
  uint16_t operation;
  uint8_t sender_ethernet_addr[6];
  uint32_t sender_ip_addr;
  uint8_t target_ethernet_addr[6];
  uint32_t target_ip_addr;
};

#pragma pack(pop)

#define FRAME_LEN (sizeof(ethernet_header) + sizeof(arp_header))

#define CHECK(op)                                                              \
  do {                                                                         \
    if (op == -1)                                                              \
      perror(#op);                                                             \
    exit(EXIT_FAILURE);                                                        \
  } while (0)

void arp_broadast_discovry_buidl(uint8_t *frame, struct ifreq *ifr, int fd) {
  ethernet_header *eth_header = (ethernet_header *)frame;
  arp_header *a_header = (arp_header *)(frame + sizeof(*eth_header));

  /* Initialisation de l'entête ETHERNET */
  memset(eth_header->ethernet_dest_addr, 0xFF,
         sizeof(eth_header->ethernet_dest_addr));
  memcpy(eth_header->ethernet_source_addr, ifr->ifr_hwaddr.sa_data, 6);
  eth_header->frame_type = htons(ETHERTYPE_ARP);

  /* Initialisation de l'entête  ARP */
  a_header->hardware_type = htons(ARPHRD_ETHER);
  a_header->protocol_type = htons(ETHERTYPE_IP);
  a_header->hardware_size = 6;
  a_header->protocol_size = 4;
  a_header->operation = htons(ARPOP_REQUEST);

  memcpy(a_header->sender_ethernet_addr, ifr->ifr_hwaddr.sa_data, 6);
  struct in_addr ip_sender = ((struct sockaddr_in *)&(ifr->ifr_addr))->sin_addr;
  memcpy(&(a_header->sender_ip_addr), &(ip_sender.s_addr),
         sizeof(ip_sender.s_addr));
  memset(a_header->target_ethernet_addr, 0x00, 6);

  uint32_t base_ip = ntohl(ip_sender.s_addr) & 0xFFFFFF00;
  for (uint8_t i = 1; i < 255; i++) {
    uint32_t ip_target = htonl(base_ip | i);
    if (ip_target == ip_sender.s_addr) {
      continue;
    }
    memcpy(&(a_header->target_ip_addr), &ip_target, sizeof(ip_target));
    CHECK(sendto(fd, frame, FRAME_LEN, 0, NULL, NULL));
  }
}

int main(void) {

  int fd = 0;
  CHECK((fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP))));

  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, "wlan0", IFNAMSIZ - 1);

  CHECK(ioctl(fd, SIOCGIFINDEX, &ifr));
  CHECK(ioctl(fd, SIOCGIFHWADDR, &ifr));
  CHECK(ioctl(fd, SIOCGIFADDR, &ifr));

  struct sockaddr_ll sa;
  memset(&sa, 0x00, sizeof(sa));
  sa.sll_family = AF_PACKET;
  sa.sll_protocol = htons(ETH_P_ARP);
  sa.sll_ifindex = ifr.ifr_ifindex;

  uint8_t frame[FRAME_LEN];
  memset(frame, 0x00, sizeof(frame));

  arp_broadast_discovry_buidl(frame, &ifr, fd);

  CHECK(close(fd));
  return EXIT_SUCCESS;
}
