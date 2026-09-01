#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

uint32_t my_htonl(uint32_t value) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  return (((value & 0x000000FF) << 24) | ((value & 0x0000FF00) << 8) |
          ((value & 0x00FF0000) >> 8) | ((value & 0xFF000000) >> 24));
#else
  return value;
#endif
}

uint32_t my_ntohl(uint32_t value) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  return my_htonl(value);
#else
  return value;
#endif
}

int main(void) {

  printf("\n");
  uint32_t value = 0x12345678;
  uint32_t value_big_endian = my_htonl(value);
  uint32_t value_little_endian = my_ntohl(value_big_endian);
  printf("value : %x\n", value);
  printf("my_htonl(%x) : %x\n", value, value_big_endian);
  printf("my_ntohl(%x) : %x\n", value_big_endian, value_little_endian);

  return EXIT_SUCCESS;
}
