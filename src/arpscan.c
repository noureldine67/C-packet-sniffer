#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <pthread.h>
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
    if ((op) == -1) {                                                          \
      perror(#op);                                                             \
      exit(EXIT_FAILURE);                                                      \
    }                                                                          \
  } while (0)

static volatile int keep_listening = 1;

/* --- THREAD D'ÉCOUTE --- */
void *arp_listen_thread(void *arg) {
  int fd = *(int *)arg;

  struct timeval tv = {.tv_sec = 0, .tv_usec = 500000};
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  uint8_t recv_buf[1500];

  while (keep_listening) {
    ssize_t len = recvfrom(fd, recv_buf, sizeof(recv_buf), 0, NULL, NULL);
    if (len < 0)
      continue;

    if (len < (ssize_t)FRAME_LEN)
      continue;

    ethernet_header *eth = (ethernet_header *)recv_buf;
    arp_header *arp = (arp_header *)(recv_buf + sizeof(ethernet_header));

    if (ntohs(eth->frame_type) == ETHERTYPE_ARP &&
        ntohs(arp->operation) == ARPOP_REPLY) {
      char ip_str[INET_ADDRSTRLEN];
      struct in_addr addr = {.s_addr = arp->sender_ip_addr};
      inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));

      printf("Host found : IP = %-15s | MAC = "
             "%02X:%02X:%02X:%02X:%02X:%02X.\n",
             ip_str, arp->sender_ethernet_addr[0], arp->sender_ethernet_addr[1],
             arp->sender_ethernet_addr[2], arp->sender_ethernet_addr[3],
             arp->sender_ethernet_addr[4], arp->sender_ethernet_addr[5]);
    }
  }

  return NULL;
}

void arp_broadast_discovry_build(uint8_t *frame, struct ifreq *ifr_mac,
                                 struct ifreq *ifr_ip, int ifindex, int fd) {
  ethernet_header *eth_header = (ethernet_header *)frame;
  arp_header *a_header = (arp_header *)(frame + sizeof(*eth_header));

  /* En-tête ETHERNET */
  memset(eth_header->ethernet_dest_addr, 0xFF,
         sizeof(eth_header->ethernet_dest_addr));
  memcpy(eth_header->ethernet_source_addr, ifr_mac->ifr_hwaddr.sa_data,
         6); // Vraie MAC
  eth_header->frame_type = htons(ETHERTYPE_ARP);

  /* En-tête ARP */
  a_header->hardware_type = htons(ARPHRD_ETHER);
  a_header->protocol_type = htons(ETHERTYPE_IP);
  a_header->hardware_size = 6;
  a_header->protocol_size = 4;
  a_header->operation = htons(ARPOP_REQUEST);

  memcpy(a_header->sender_ethernet_addr, ifr_mac->ifr_hwaddr.sa_data, 6);
  struct in_addr ip_sender =
      ((struct sockaddr_in *)&(ifr_ip->ifr_addr))->sin_addr;
  memcpy(&(a_header->sender_ip_addr), &(ip_sender.s_addr),
         sizeof(ip_sender.s_addr));
  memset(a_header->target_ethernet_addr, 0x00, 6);

  /* Masque de sous-réseau */
  struct ifreq ifr_mask;
  memset(&ifr_mask, 0, sizeof(ifr_mask));
  strncpy(ifr_mask.ifr_name, ifr_mac->ifr_name, IFNAMSIZ - 1);
  CHECK(ioctl(fd, SIOCGIFNETMASK, &ifr_mask));
  struct in_addr netmask =
      ((struct sockaddr_in *)&ifr_mask.ifr_netmask)->sin_addr;

  char mask_str[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &netmask, mask_str, sizeof(mask_str));

  uint32_t base_ip = ntohl(ip_sender.s_addr) & 0xFFFFFF00;
  printf("\nHosts discovery : %u.%u.%u.%u (Mask: %s).\n",
         *((uint8_t *)(&base_ip) + 3), *((uint8_t *)(&base_ip) + 2),
         *((uint8_t *)(&base_ip) + 1), *((uint8_t *)&base_ip), mask_str);

  /* Structure d'adresse d'envoi */
  struct sockaddr_ll sa;
  memset(&sa, 0x00, sizeof(sa));
  sa.sll_family = AF_PACKET;
  sa.sll_protocol = htons(ETH_P_ARP);
  sa.sll_ifindex = ifindex;
  sa.sll_halen = 6;
  memset(sa.sll_addr, 0xFF, 6);

  /* Lancement des requêtes ARP */
  printf("\nARP requests sending beginning.\n");
  for (uint16_t i = 1; i < 255; i++) {
    uint32_t ip_target = htonl(base_ip | i);
    if (ip_target == ip_sender.s_addr)
      continue;

    memcpy(&(a_header->target_ip_addr), &ip_target, sizeof(ip_target));
    CHECK(sendto(fd, frame, FRAME_LEN, 0, (struct sockaddr *)&sa, sizeof(sa)));
    usleep(2000); // 2ms de délai
  }
  printf("\nEnd of sending.\n");
}

static void print_banner(void) {
  fputs("\n⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠟⠋⠁⠀⠀⠀⠀⠉⠉⠉⠛⠛⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿\n"
        "⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿\n"
        "⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿\n"
        "⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿\n"
        "⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿\n"
        "⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿\n"
        "⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿\n"
        "⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣤⣶⣿⣿⣿⣿⣿⣿⣿⣿⣷⣦⠀⠀⠀⠀⠀⠀⠀⠹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿\n"
        "⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠿⠛⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿\n"
        "⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⢻⣿⣿⣿⣿⣿⣿⣿⣿⠿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿\n"
        "⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⣀⣀⣀⣀⠀⠙⠻⣿⣿⣿⣿⣿⡃⠀⠀⢀⣴⣶⣿⣷⡦⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿\n"
        "⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠁⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣷⣦⣤⣾⣿⣿⣿⡿⠃⣠⣴⣿⣿⣿⣿⡿⠃⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿\n"
        "⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠈⠉⠁⠀⠀⠈⠉⠻⣿⣿⣿⣿⣇⣼⠟⠋⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿\n"
        "⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⣀⡀⠀⠀⠀⠀⠀⢀⣿⣿⣿⣿⣿⣿⣄⣀⠀⠀⠀⣀⣠⣴⣶⡄⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿\n"
        "⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⣾⣿⣿⣷⣶⣶⣶⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠇⠀⠀⠀⠀⠀⠀⠈⣿⣿⣿⣿⣿⣿⣿⣿⣿\n"
        "⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡆⠀⠀⠀⠀⠀⠹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠋⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿\n"
        "⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣇⠀⠀⠀⠀⠀⠀⠘⠻⠿⠿⠿⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣛⡛⠛⠛⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿\n"
        "⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⢶⣾⣿⣿⣏⠛⠿⣿⣿⡿⠋⢉⣿⣿⣿⣿⠀⠀⢰⡇⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿\n"
        "⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠘⣆⠀⠈⠛⠿⠿⠿⠃⠀⠀⠀⠀⠀⠙⠿⠛⠛⠁⠀⢠⡿⠀⠀⠀⠀⠀⠀⠀⠀⣸⣿⣿⣿⣿⣿⣿⣿⣿⣿\n"
        "⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⠀⠀⠀⠀⠀⠀⠘⣧⠀⢀⣀⣀⣀⠀⠀⠸⠿⠆⠀⣀⣀⣠⣤⠀⢠⡿⠁⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿\n"
        "⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⠀⠀⠀⠀⠀⠀⠀⠈⢧⡀⢉⡛⠿⠿⠿⠶⠶⠾⠿⠿⠟⠋⠁⢠⡾⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿\n"
        "⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠟⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢳⣾⣿⣿⣷⣄⠀⠀⠀⢠⣤⣶⡆⣠⡟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⠻⢿⣿⣿⣿⣿⣿\n"
        "⣿⣿⣿⣿⣿⡿⠿⠛⠋⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⣿⣿⣿⣿⠀⠀⠀⢸⣿⣿⣷⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠉⠛\n"
        "⡿⠛⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⣿⣿⡄⠀⠀⢸⣿⣿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n",
        stdout);
  fflush(stdout);
}

int main(void) {
  int fd = 0;
  CHECK((fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP))));

  print_banner();

  // Utilisation de structures séparées pour ne pas écraser la mémoire
  struct ifreq ifr_idx, ifr_mac, ifr_ip;
  memset(&ifr_idx, 0, sizeof(ifr_idx));
  memset(&ifr_mac, 0, sizeof(ifr_mac));
  memset(&ifr_ip, 0, sizeof(ifr_ip));

  strncpy(ifr_idx.ifr_name, "wlan0", IFNAMSIZ - 1);
  strncpy(ifr_mac.ifr_name, "wlan0", IFNAMSIZ - 1);
  strncpy(ifr_ip.ifr_name, "wlan0", IFNAMSIZ - 1);

  CHECK(ioctl(fd, SIOCGIFINDEX, &ifr_idx));
  CHECK(ioctl(fd, SIOCGIFHWADDR, &ifr_mac));
  CHECK(ioctl(fd, SIOCGIFADDR, &ifr_ip));

  uint8_t frame[FRAME_LEN];
  memset(frame, 0x00, sizeof(frame));

  /* 1. DÉMARRAGE DU THREAD D'ÉCOUTE */
  pthread_t thread_id;
  CHECK(pthread_create(&thread_id, NULL, arp_listen_thread, &fd));

  /* 2. ENVOI DES TRAMES ARP (avec ifr_mac et ifr_ip bien séparés) */
  arp_broadast_discovry_build(frame, &ifr_mac, &ifr_ip, ifr_idx.ifr_ifindex,
                              fd);

  /* 3. Attente des réponses */
  sleep(2);

  /* 4. ARRÊT DU THREAD */
  keep_listening = 0;
  pthread_join(thread_id, NULL);

  CHECK(close(fd));
  return EXIT_SUCCESS;
}
