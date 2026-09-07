/**
 * @file sniffer.c
 * @brief Sniffer réseau en mode promiscuous, avec pause/reprise au clavier.
 *
 * Ce programme active le mode promiscuous directement sur l'interface
 * réseau demandée (drapeau IFF_PROMISC via ioctl), ouvre un socket raw
 * (AF_PACKET/SOCK_RAW) lié à cette interface, puis capture en boucle les
 * trames qui y transitent et affiche pour chacune : adresses MAC
 * source/destination, adresses IP source/destination, protocole de
 * transport (TCP, UDP ou ICMP) avec les détails associés, et un dump
 * hexadécimal + ASCII des données utiles.
 *
 * Contrôles :
 *   Ctrl+C   quitte proprement (SIGINT, un vrai signal POSIX)
 *
 * Nécessite les privilèges root (ou CAP_NET_RAW / CAP_NET_ADMIN) : la
 * création du socket raw et la modification des drapeaux de l'interface
 * exigent tous les deux des privilèges élevés.
 *
 * Usage : ./sniffer <interface>   (ex : ./sniffer wlan0)
 */

#include <arpa/inet.h>
#include <errno.h>
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
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define MAX 65535 /* Taille max d'une trame lue via recvfrom() */

#define ERROR_CHECK(op)                                                        \
  do {                                                                         \
    if ((op) == -1) {                                                          \
      perror(#op);                                                             \
      exit(EXIT_FAILURE);                                                      \
    }                                                                          \
  } while (0)

static volatile sig_atomic_t keepRunning = 1;

/**
 * @brief Gestionnaire du signal SIGINT (Ctrl+C).
 */
void intHandler(int dummy) {
  (void)dummy;
  keepRunning = 0;
}

/**
 * @brief Affiche le bandeau ASCII du programme au lancement.
 */
static void print_banner(void) {
  fputs("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"
        "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"
        "⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"
        "⢠⣾⣿⣏⠉⠉⠉⠉⠉⠉⢡⣶⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠻⢿⣿⣿⣿⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⡄⠀\n"
        "⠈⣿⣿⣿⣿⣦⣽⣦⡀⠀⠀⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠛⢧⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣿⣿⠀⠀\n"
        "⠀⠘⢿⣿⣿⣿⣿⣿⣿⣦⣄⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⣿⣿⠇⠀⠀\n"
        "⠀⠀⠈⠻⣿⣿⣿⣿⡟⢿⠻⠛⠙⠉⠋⠛⠳⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣿⣿⣿⡟⠀⠀⠀\n"
        "⠀⠀⠀⠀⠈⠙⢿⡇⣠⣤⣶⣶⣾⡉⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⣰⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠠⠾⢇⠀⠀⠀⠀⠀⣴⣿⣿⣿⣿⠃⠀⠀⠀\n"
        "⠀⠀⠀⠀⠀⠀⠀⠱⣿⣿⣿⣿⣿⣿⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⣰⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⠤⢤⣀⣀⣀⣀⣀⣀⣠⣤⣤⣤⣬⣭⣿⣿⠀⠀⠀⠀\n"
        "⠀⠀⠀⠀⠀⠀⠀⠀⠈⠛⢿⣿⣿⣿⣿⣿⣶⣤⣄⣀⣀⣠⣴⣾⣿⣿⣿⣷⣤⣀⡀⠀⠀⠀⠀⠀⠀⣀⣀⣤⣾⣿⣿⣿⣿⡿⠿⠛⠛⠻⣿⣿⣿⣿⣇⠀⠀⠀\n"
        "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣶⣤⣤⣘⡛⠿⢿⡿⠟⠛⠉⠁⠀⠀⠀⠀⠀⠈⠻⣿⣿⣿⣦⠀⠀\n"
        "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⢿⣿⣿⣿⣿⣿⣶⣦⣤⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⣿⣿⡄⠀\n"
        "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣾⣿⣿⣿⠿⠛⠉⠁⠀⠈⠉⠙⠛⠛⠻⠿⠿⠿⠿⠟⠛⠃⠀⠀⠀⠉⠉⠉⠛⠛⠛⠿⠿⠿⣶⣦⣄⡀⠀⠀⠀⠀⠀⠈⠙⠛⠂\n"
        "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠠⠿⠛⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀\n",
        stdout);
  fflush(stdout);
}

/**
 * @brief Restaure les drapeaux d'origine d'une interface réseau.
 */
void restore_interface_flags(int sock, const char *iface_name,
                             short original_flags) {
  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  snprintf(ifr.ifr_name, IFNAMSIZ, "%s", iface_name);
  strncpy(ifr.ifr_name, iface_name, IFNAMSIZ - 1);
  ifr.ifr_flags = original_flags;

  ERROR_CHECK(ioctl(sock, SIOCSIFFLAGS, &ifr));
}

/**
 * @brief Crée un socket raw et active le mode promiscuous sur l'interface.
 */
int set_promiscuous_socket(const char *iface_name, short *original_flags) {
  int sock;
  ERROR_CHECK((sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))));

  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, iface_name, IFNAMSIZ - 1);

  ERROR_CHECK(ioctl(sock, SIOCGIFFLAGS, &ifr));
  *original_flags = ifr.ifr_flags;

  ifr.ifr_flags |= IFF_PROMISC;
  ERROR_CHECK(ioctl(sock, SIOCSIFFLAGS, &ifr));

  unsigned int ifindex = if_nametoindex(iface_name);
  if (ifindex == 0) {
    fprintf(stderr, "Interface \"%s\" introuvable\n", iface_name);
    restore_interface_flags(sock, iface_name, *original_flags);
    close(sock);
    return -1;
  }

  struct sockaddr_ll sa;
  memset(&sa, 0, sizeof(sa));
  sa.sll_family = AF_PACKET;
  sa.sll_protocol = htons(ETH_P_ALL);
  sa.sll_ifindex = (int)ifindex;

  if (bind(sock, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
    perror("bind");
    restore_interface_flags(sock, iface_name, *original_flags);
    close(sock);
    return -1;
  }

  /* Configuration d'un timeout de 1s sur recvfrom() pour débloquer Ctrl+C */
  struct timeval tv;
  tv.tv_sec = 1;
  tv.tv_usec = 0;
  setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));

  return sock;
}

/**
 * @brief Décode et affiche un paquet capturé (Ethernet/IP/TCP, UDP ou ICMP).
 */
void print_packet(const uint8_t *buffer, size_t n_bytes, const char *pkttype) {

  static unsigned long packet_count = 0;
  const struct ether_header *ethernet = (const struct ether_header *)buffer;

  uint16_t ethertype = ntohs(ethernet->ether_type);

  if (ethertype != ETH_P_IP) {
    return;
  }

  printf("\n----- %s #%lu (%zu octets) -----\n", pkttype, ++packet_count,
         n_bytes);
  printf("  (ethertype 0x%04x)\n", ethertype);
  printf("%02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x\n",
         ethernet->ether_shost[0], ethernet->ether_shost[1],
         ethernet->ether_shost[2], ethernet->ether_shost[3],
         ethernet->ether_shost[4], ethernet->ether_shost[5],
         ethernet->ether_dhost[0], ethernet->ether_dhost[1],
         ethernet->ether_dhost[2], ethernet->ether_dhost[3],
         ethernet->ether_dhost[4], ethernet->ether_dhost[5]);

  size_t offset = ETH_HLEN;

  const struct iphdr *ip = (const struct iphdr *)(buffer + offset);
  size_t ip_hlen = (size_t)ip->ihl * 4u;

  char src_ip[INET_ADDRSTRLEN];
  char dst_ip[INET_ADDRSTRLEN];

  inet_ntop(AF_INET, &ip->saddr, src_ip, sizeof(src_ip));
  inet_ntop(AF_INET, &ip->daddr, dst_ip, sizeof(dst_ip));
  printf("%s -> %s (protocole %u)\n", src_ip, dst_ip, ip->protocol);

  offset += ip_hlen;
  const uint8_t *payload = NULL;
  size_t payload_len = 0;

  if (ip->protocol == IPPROTO_TCP) {
    const struct tcphdr *tcp = (const struct tcphdr *)(buffer + offset);
    size_t tcp_hlen = (size_t)tcp->doff * 4u;

    printf("TCP port %u -> port %u  [%s%s%s%s%s%s]\n", ntohs(tcp->source),
           ntohs(tcp->dest), tcp->syn ? "SYN " : "", tcp->ack ? "ACK " : "",
           tcp->fin ? "FIN " : "", tcp->rst ? "RST " : "",
           tcp->psh ? "PSH " : "", tcp->urg ? "URG " : "");
    offset += tcp_hlen;
    payload = (const uint8_t *)(buffer + offset);
    payload_len = (n_bytes > offset) ? (n_bytes - offset) : 0;

  } else if (ip->protocol == IPPROTO_UDP) {
    const struct udphdr *udp = (const struct udphdr *)(buffer + offset);
    printf("UDP port %u -> port %u\n", ntohs(udp->source), ntohs(udp->dest));
    offset += sizeof(struct udphdr);
    payload = (const uint8_t *)buffer + offset;
    payload_len = (n_bytes > offset) ? (n_bytes - offset) : 0;

  } else if (ip->protocol == IPPROTO_ICMP) {
    const struct icmphdr *icmp = (const struct icmphdr *)(buffer + offset);

    printf("ICMP Type %u", icmp->type);
    if (icmp->type == ICMP_ECHO) {
      printf(" (Echo Request / Ping Request) ID: %u, Seq: %u\n",
             ntohs(icmp->un.echo.id), ntohs(icmp->un.echo.sequence));
    } else if (icmp->type == ICMP_ECHOREPLY) {
      printf(" (Echo Reply / Ping Reply) ID: %u, Seq: %u\n",
             ntohs(icmp->un.echo.id), ntohs(icmp->un.echo.sequence));
    } else {
      printf(" (Code %u)\n", icmp->code);
    }

    offset += sizeof(struct icmphdr);
    payload = (const uint8_t *)(buffer + offset);
    payload_len = (n_bytes > offset) ? (n_bytes - offset) : 0;

  } else {
    printf("protocole IP %u (non decode), pas de decodage spécifique\n",
           ip->protocol);
  }

  if (payload_len == 0) {
    printf("(aucune donnee utile)\n");
    return;
  }

  printf("== DONNEES (%zu octets) ==\n", payload_len);
  for (size_t i = 0; i < payload_len; i += 16) {
    size_t line_len = (payload_len - i < 16) ? (payload_len - i) : 16;
    printf("  %04zx  ", i);
    for (size_t j = 0; j < 16; j++) {
      if (j < line_len) {
        printf("%02x ", payload[i + j]);
      } else {
        printf("   ");
      }
      if (j == 7)
        printf(" ");
    }
    printf(" |");
    for (size_t j = 0; j < line_len; j++) {
      uint8_t c = payload[i + j];
      putchar((c >= 32 && c < 127) ? (int)c : '.');
    }
    printf("|\n");
  }
}

///////////////////////////////// MAIN /////////////////////////////////
/**
 * @brief Point d'entree du programme.
 */
int main(int argc, char *argv[]) {
  if (argc != 2) {
    fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
    return EXIT_FAILURE;
  }
  const char *iface_name = argv[1];

  struct sigaction sa_sig;
  memset(&sa_sig, 0, sizeof(sa_sig));
  sa_sig.sa_handler = &intHandler;
  sigaction(SIGINT, &sa_sig, NULL);

  short original_flags = 0;
  int sock = set_promiscuous_socket(iface_name, &original_flags);

  static uint8_t buffer[MAX];

  print_banner();

  printf("== DEBUT DE LA CAPTURE sur %s (Ctrl+C: quitter) ==\n", iface_name);

  ssize_t n_bytes = 0;
  const char *pkttype;
  struct sockaddr_ll from;
  socklen_t fromlen = sizeof(from);
  memset(&from, 0, sizeof(from));

  while (keepRunning) {
    n_bytes =
        recvfrom(sock, buffer, MAX, 0, (struct sockaddr *)&from, &fromlen);

    if (n_bytes == -1) {
      /* Si c'est un timeout ou un signal, on boucle pour verifier keepRunning
       */
      if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
        continue;
      }
      perror("recvfrom");
      break;
    }

    switch (from.sll_pkttype) {
    case PACKET_HOST:
      pkttype = "PACKET_HOST";
      break;
    case PACKET_OUTGOING:
      pkttype = "SORTANT";
      break;
    case PACKET_BROADCAST:
      pkttype = "PACKET_BROADCAST";
      break;
    case PACKET_MULTICAST:
      pkttype = "ENTRANT (multicast)";
      break;
    case PACKET_OTHERHOST:
      pkttype = "PACKET_OTHERHOST";
      break;
    default:
      pkttype = "PACKET_UNKNOW";
      break;
    }

    print_packet(buffer, (size_t)n_bytes, pkttype);
  }

  printf("\n== FIN DE LA CAPTURE ==\n");

  restore_interface_flags(sock, iface_name, original_flags);
  ERROR_CHECK(close(sock));
  return EXIT_SUCCESS;
}
