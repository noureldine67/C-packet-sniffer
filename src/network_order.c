#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

void print_2bytes(const uint8_t *ptr) {
  for (size_t i = 0; i < sizeof(short); i++) {
    // On a 64 bits architecture, the length is 8 bytes
    printf("%lx\t", (uintptr_t)(ptr + i));
  }

  printf("\n");

  for (size_t i = 0; i < sizeof(int); i++) {
    printf("%02x\t", *(ptr + i));
  }

  printf("\n");
}

int main(void) {
  // Must use htons for ETH_P_ALL because the EtherType field in an Ethernet
  // frame is a 2-byte field
  // memory 03 00
  short eth_p_all = ETH_P_ALL;
  // memory 00 03
  short eth_p_all_htons = htons(ETH_P_ALL);
  printf("ETH_P_ALL : \n");
  print_2bytes((uint8_t *)&eth_p_all);
  printf("\nhtons(ETH_P_ALL) : \n");
  print_2bytes((uint8_t *)&eth_p_all_htons);

  // Do not use htons for IPPROTO_ICMP because the IPv4 header has an 8-bit
  // field originally called the Type of Service
  // memory 01 00
  short ipproto_icmp = IPPROTO_ICMP;
  // memory 00 01
  short ipproto_icmp_htons = htons(IPPROTO_ICMP);

  printf("IPPROTO_ICMP : \n");
  print_2bytes((uint8_t *)&ipproto_icmp);
  printf("\nhtons(IPPROTO_ICMP) : \n");
  print_2bytes((uint8_t *)&ipproto_icmp_htons);
  return EXIT_SUCCESS;
}
