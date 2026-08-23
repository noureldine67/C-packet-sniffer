/**
 * @file sniffer.c
 * @brief Sniffer réseau en mode promiscuous, avec pause/reprise au clavier.
 *
 * Ce programme active le mode promiscuous directement sur l'interface
 * réseau demandée (drapeau IFF_PROMISC via ioctl), ouvre un socket raw
 * (AF_PACKET/SOCK_RAW) lié à cette interface, puis capture en boucle les
 * trames qui y transitent et affiche pour chacune : adresses MAC
 * source/destination, adresses IP source/destination, protocole de
 * transport (TCP ou UDP) avec les ports, et un dump hexadécimal + ASCII
 * des données utiles.
 *
 * Contrôles :
 *   Ctrl+C   quitte proprement (SIGINT, un vrai signal POSIX)
 *   Ctrl+D   met la capture en pause / la relance
 *
 * Important à propos de Ctrl+D : contrairement à Ctrl+C (SIGINT), ce
 * n'est PAS un signal POSIX. C'est un caractère de contrôle interprété
 * par le pilote du terminal : tapé sur une ligne vide, il fait que le
 * prochain read() sur l'entrée standard renvoie 0 (condition de fin de
 * fichier / EOF), sans qu'il soit nécessaire d'appuyer sur Entrée. Ce
 * programme surveille donc stdin avec select() en même temps que le
 * socket, et bascule l'état pause/reprise à chaque EOF détecté.
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
#include <unistd.h>

#define MAX 65535 /**< Taille max d'une trame lue via recvfrom() */

/* Macro robuste : do { ... } while(0) permet une utilisation sûre y
 * compris dans un if/else sans accolades. Les parenthèses autour de (op)
 * évitent les mauvaises surprises si l'expression passée contient un
 * opérateur de priorité inférieure à ==. */
#define ERROR_CHECK(op)                                                        \
  do {                                                                         \
    if ((op) == -1) {                                                          \
      perror(#op);                                                             \
      exit(EXIT_FAILURE);                                                      \
    }                                                                          \
  } while (0)

/* volatile sig_atomic_t est le seul type dont la lecture/écriture est
 * garantie sûre à la fois dans un gestionnaire de signal et dans le
 * programme principal (contrairement à un simple "volatile int", qui
 * fonctionne en pratique sur la plupart des systèmes mais n'est pas
 * portable au sens strict de la norme C). */
static volatile sig_atomic_t keepRunning = 1;

/**
 * @brief Gestionnaire du signal SIGINT (Ctrl+C).
 *
 * Se contente de positionner un drapeau : un gestionnaire de signal ne
 * doit appeler que des fonctions "async-signal-safe" au sens POSIX, ce
 * que printf() n'est pas garanti être (elle peut être interrompue en
 * plein milieu d'un autre appel stdio, par exemple si le signal arrive
 * pendant un printf() de print_packet()). L'affichage du message de fin
 * se fait donc dans main(), après la boucle, une fois qu'on est sûr
 * qu'aucun autre appel stdio n'est en cours.
 *
 * @param dummy Numéro du signal reçu (non utilisé).
 */
void intHandler(int dummy) {
  (void)dummy;
  keepRunning = 0;
}

/**
 * @brief Restaure les drapeaux d'origine d'une interface réseau.
 *
 * Annule l'activation de IFF_PROMISC faite par set_promiscuous_socket().
 * Sans cette étape, l'interface resterait en mode promiscuous pour tout
 * le système (visible via `ip link show`, et affectant potentiellement
 * d'autres logiciels) même après la fin de ce programme -- c'est un bug
 * réel de la version précédente, qui ne remettait jamais les drapeaux
 * en place.
 *
 * Fonction "best effort" : en cas d'échec, on avertit l'utilisateur avec
 * la commande manuelle de secours plutôt que de faire planter le
 * programme pendant sa phase de nettoyage.
 *
 * @param sock        Socket déjà lié à l'interface (utilisé pour l'ioctl).
 * @param iface_name  Nom de l'interface (ex : "wlan0").
 * @param original_flags Drapeaux à restaurer, tels que sauvegardés par
 *                        set_promiscuous_socket().
 */
void restore_interface_flags(int sock, const char *iface_name,
                             short original_flags) {
  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, iface_name, IFNAMSIZ - 1);
  ifr.ifr_flags = original_flags;

  ERROR_CHECK(ioctl(sock, SIOCSIFFLAGS, &ifr));
}

/**
 * @brief Crée un socket raw et active le mode promiscuous sur l'interface.
 *
 * Étapes : création du socket AF_PACKET/SOCK_RAW (ETH_P_ALL), lecture des
 * drapeaux actuels de l'interface (SIOCGIFFLAGS, sauvegardés dans
 * *original_flags pour restauration ultérieure), ajout du drapeau
 * IFF_PROMISC (SIOCSIFFLAGS), résolution de l'index de l'interface, puis
 * liaison (bind) du socket dessus.
 *
 * Notez la différence avec l'autre méthode classique (setsockopt avec
 * PACKET_ADD_MEMBERSHIP) : celle-ci modifie l'état du socket uniquement,
 * et le mode promiscuous est automatiquement désactivé à la fermeture du
 * socket. Ici, on modifie l'état de l'interface elle-même (visible par
 * tout le système), d'où la nécessité de le restaurer explicitement.
 *
 * @param iface_name      Nom de l'interface à écouter (ex : "wlan0").
 * @param original_flags  [out] reçoit les drapeaux d'origine de
 *                         l'interface, à conserver pour
 * restore_interface_flags().
 * @return Le descripteur de socket, ou -1 en cas d'erreur (message déjà
 *         affiché via perror/fprintf).
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

  return sock;
}

/**
 * @brief Décode et affiche un paquet capturé (Ethernet/IP/TCP ou UDP).
 *
 * Affiche les adresses MAC, puis si la trame est de l'IPv4, les adresses
 * IP, le protocole de transport avec les ports (TCP avec ses flags, ou
 * UDP), et enfin un dump hexadécimal + ASCII des données utiles.
 *
 * Chaque étape vérifie que @p n_bytes est suffisant AVANT de déréférencer
 * l'en-tête correspondant. C'est essentiel : la version précédente
 * supposait que chaque trame était forcément de l'IPv4 en TCP, et
 * calculait `payload_len` en soustrayant les tailles d'en-têtes de
 * n_bytes sans jamais vérifier que ce résultat restait positif. Sur un
 * paquet ARP, IPv6, UDP, ICMP, ou simplement tronqué, `ip`/`tcp` pointent
 * sur des données qui ne sont pas réellement un en-tête IP/TCP, et
 * `payload_len` (de type size_t, donc non signé) peut "déborder" vers une
 * valeur énorme au lieu de devenir négative : la boucle d'affichage lit
 * alors très loin en dehors du tampon, ce qui plante le programme ou
 * affiche de la mémoire qui n'a rien à voir avec le paquet.
 *
 * @param buffer Trame brute reçue (non modifiée).
 * @param n_bytes Nombre d'octets réellement reçus (résultat de recvfrom()).
 * @param index Numéro de capture (#1, #2, ...) pour l'affichage.
 */
void print_packet(const uint8_t *buffer, ssize_t n_bytes, unsigned long index) {
  if (n_bytes < 0) {
    return; /* ne devrait pas arriver : verifie deja par l'appelant */
  }
  size_t n = (size_t)n_bytes;

  if (n < sizeof(struct ether_header)) {
    printf("[#%lu] trame trop courte (%zu octets), ignoree\n", index, n);
    return;
  }

  const struct ether_header *ethernet = (const struct ether_header *)buffer;

  printf("\n----- Paquet #%lu (%zu octets) -----\n", index, n);
  printf("%02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x",
         ethernet->ether_shost[0], ethernet->ether_shost[1],
         ethernet->ether_shost[2], ethernet->ether_shost[3],
         ethernet->ether_shost[4], ethernet->ether_shost[5],
         ethernet->ether_dhost[0], ethernet->ether_dhost[1],
         ethernet->ether_dhost[2], ethernet->ether_dhost[3],
         ethernet->ether_dhost[4], ethernet->ether_dhost[5]);

  uint16_t ethertype = ntohs(ethernet->ether_type);
  printf("  (ethertype 0x%04x)\n", ethertype);

  if (ethertype != ETH_P_IP) {
    printf("(trame non-IPv4 : pas de decodage IP/TCP/UDP)\n");
    return;
  }

  size_t offset = sizeof(struct ether_header);
  if (n < offset + sizeof(struct iphdr)) {
    printf("en-tete IP tronque, ignore\n");
    return;
  }

  const struct iphdr *ip = (const struct iphdr *)(buffer + offset);
  size_t ip_hlen = (size_t)ip->ihl * 4u;
  if (ip->ihl < 5 || n < offset + ip_hlen) {
    printf("en-tete IP invalide ou tronque, ignore\n");
    return;
  }

  char src_ip[INET_ADDRSTRLEN];
  char dst_ip[INET_ADDRSTRLEN];
  /* inet_ntop() remplace inet_ntoa(), qui n'est pas thread-safe (elle
   * renvoie un pointeur vers un tampon statique interne partage) : sans
   * consequence dans ce programme mono-thread, mais inet_ntop() est la
   * fonction moderne recommandee et evite d'y penser plus tard. */
  inet_ntop(AF_INET, &ip->saddr, src_ip, sizeof(src_ip));
  inet_ntop(AF_INET, &ip->daddr, dst_ip, sizeof(dst_ip));
  printf("%s -> %s (ttl %u, protocole %u)\n", src_ip, dst_ip, ip->ttl,
         ip->protocol);

  offset += ip_hlen;
  const uint8_t *payload = NULL;
  size_t payload_len = 0;

  if (ip->protocol == IPPROTO_TCP && n >= offset + sizeof(struct tcphdr)) {
    const struct tcphdr *tcp = (const struct tcphdr *)(buffer + offset);
    size_t tcp_hlen = (size_t)tcp->doff * 4u;
    if (tcp->doff < 5 || n < offset + tcp_hlen) {
      printf("en-tete TCP invalide ou tronque, ignore\n");
      return;
    }
    printf("TCP port %u -> port %u  [%s%s%s%s%s%s]\n", ntohs(tcp->source),
           ntohs(tcp->dest), tcp->syn ? "SYN " : "", tcp->ack ? "ACK " : "",
           tcp->fin ? "FIN " : "", tcp->rst ? "RST " : "",
           tcp->psh ? "PSH " : "", tcp->urg ? "URG " : "");
    offset += tcp_hlen;
    payload = buffer + offset;
    payload_len = n - offset; /* sur d'etre >= 0, verifie juste au-dessus */

  } else if (ip->protocol == IPPROTO_UDP &&
             n >= offset + sizeof(struct udphdr)) {
    const struct udphdr *udp = (const struct udphdr *)(buffer + offset);
    printf("UDP port %u -> port %u\n", ntohs(udp->source), ntohs(udp->dest));
    offset += sizeof(struct udphdr);
    payload = buffer + offset;
    payload_len = n - offset;

  } else {
    printf("protocole IP %u (ni TCP ni UDP), pas de decodage des ports\n",
           ip->protocol);
    return;
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
      /* On ne recopie jamais un octet non imprimable tel quel dans le
       * terminal : un paquet est une donnee non fiable, et certains
       * octets (ex: sequences d'echappement) pourraient perturber
       * l'affichage du terminal, voire dans de rares cas y injecter des
       * commandes. On remplace donc tout ce qui n'est pas de l'ASCII
       * imprimable par un simple point. */
      putchar((c >= 32 && c < 127) ? (int)c : '.');
    }
    printf("|\n");
  }
}

///////////////////////////////// MAIN /////////////////////////////////
/**
 * @brief Point d'entree du programme.
 *
 * Ouvre le socket promiscuous, puis entre dans la boucle principale : un
 * select() bloquant attend soit un paquet sur le socket, soit une
 * activite sur l'entree standard (si elle est un terminal). Un EOF sur
 * stdin (Ctrl+D) bascule l'etat pause/reprise ; un paquet recu est
 * affiche via print_packet() sauf en pause (mais toujours lu, pour
 * eviter que le tampon noyau du socket ne se remplisse). Ctrl+C
 * (SIGINT) fait sortir proprement de la boucle, apres quoi les drapeaux
 * de l'interface sont restaures avant fermeture du socket.
 *
 * @param argc Nombre d'arguments.
 * @param argv argv[1] doit etre le nom de l'interface a ecouter.
 * @return EXIT_SUCCESS en cas d'arret normal, EXIT_FAILURE sinon.
 */
int main(int argc, char *argv[]) {
  if (argc != 2) {
    fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
    return EXIT_FAILURE;
  }
  const char *iface_name = argv[1];

  signal(SIGINT, intHandler);

  short original_flags = 0;
  int sock = set_promiscuous_socket(iface_name, &original_flags);
  if (sock == -1) {
    fprintf(stderr, "Impossible d'initialiser la capture sur \"%s\"\n",
            iface_name);
    return EXIT_FAILURE;
  }

  /* Si l'entree standard n'est pas un terminal interactif (ex: programme
   * lance depuis un script, une tache cron, ou avec stdin redirige
   * depuis /dev/null), on ne la surveille pas : /dev/null est toujours
   * "pret" en lecture et renvoie systematiquement un EOF immediat, ce
   * qui declencherait une bascule pause/reprise en boucle serree (donc
   * 100% d'un coeur CPU pour rien) au lieu d'attendre une vraie touche. */
  bool stdin_is_tty = isatty(STDIN_FILENO);
  if (!stdin_is_tty) {
    fprintf(stderr, "(entree standard non interactive : Ctrl+D desactive, "
                    "seul Ctrl+C fonctionnera)\n");
  }

  static uint8_t buffer[MAX]; /* statique plutot que sur la pile de main */
  bool paused = false;
  unsigned long packet_count = 0;

  printf("== DEBUT DE LA CAPTURE sur %s (Ctrl+C: quitter, Ctrl+D: "
         "pause/reprise) ==\n",
         iface_name);

  while (keepRunning) {
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(sock, &rfds);
    int maxfd = sock;
    if (stdin_is_tty) {
      FD_SET(STDIN_FILENO, &rfds);
      if (STDIN_FILENO > maxfd)
        maxfd = STDIN_FILENO;
    }

    int ready = select(maxfd + 1, &rfds, NULL, NULL, NULL);
    if (ready == -1) {
      if (errno == EINTR)
        continue; /* interrompu par SIGINT : keepRunning va etre a 0 */
      perror("select");
      break;
    }

    if (stdin_is_tty && FD_ISSET(STDIN_FILENO, &rfds)) {
      char discard[256];
      ssize_t r = read(STDIN_FILENO, discard, sizeof(discard));
      if (r == 0) {
        /* EOF sur le terminal : Ctrl+D tape sur une ligne vide. */
        paused = !paused;
        printf(paused ? "\n== PAUSE (Ctrl+D pour reprendre) ==\n"
                      : "\n== REPRISE DE LA CAPTURE ==\n");
        fflush(stdout);
      }
      /* r > 0 : l'utilisateur a tape une ligne puis Entree ; on l'ignore,
       * ce programme n'a pas de commandes textuelles. */
    }

    if (FD_ISSET(sock, &rfds)) {
      ssize_t n_bytes = recvfrom(sock, buffer, MAX, 0, NULL, NULL);
      if (n_bytes == -1) {
        if (errno == EINTR)
          continue;
        perror("recvfrom");
        break;
      }
      /* Meme en pause, on vide le socket pour ne pas laisser le tampon
       * noyau se remplir ; on n'affiche simplement rien. */
      if (!paused) {
        packet_count++;
        print_packet(buffer, n_bytes, packet_count);
      }
    }
  }

  printf("\n== FIN DE LA CAPTURE (%lu paquets affiches) ==\n", packet_count);

  restore_interface_flags(sock, iface_name, original_flags);
  ERROR_CHECK(close(sock));
  return EXIT_SUCCESS;
}
