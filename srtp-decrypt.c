#include <sys/types.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <assert.h>

#include "srtp.h"

#include <pcap.h>

static const char b64chars[] = 
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static unsigned char shiftb64(unsigned char c) {
  char *p = strchr(b64chars, c);
  assert(p);
  return p-b64chars;
}

static void decode_block(unsigned char *in, unsigned char *out) {
  unsigned char shifts[4];
  int i;

  for (i = 0; i < 4; i++) {
    shifts[i] = shiftb64(in[i]);
  }

  out[0] = (shifts[0]<<2)|(shifts[1]>>4);
  out[1] = (shifts[1]<<4)|(shifts[2]>>2);
  out[2] = (shifts[2]<<6)|shifts[3];
}

static void decode_sdes(unsigned char *in,
  unsigned char *key, unsigned char *salt) {
  int i;
  size_t len = strlen((char *) in);
  assert(len == 40);
  unsigned char raw[30];

  for (i = 0; 4*i < len; i++) {
    decode_block(in+4*i, raw+3*i);
  }

  memcpy(key, raw, 16);
  memcpy(salt, raw+16, 14);
}

static srtp_session_t *s = NULL;

static void hexdump(const void *ptr, size_t size) {
  int i, j;
  const unsigned char *cptr = ptr;

  for (i = 0; i < size; i += 16) {
    printf("%04x ", i);
    for (j = 0; j < 16 && i+j < size; j++) {
      printf("%02x ", cptr[i+j]);
    }
    printf("\n");
  }
}

static int rtp_offset = 42 /* 14 + 20 + 8 */;
static int frame_nr = -1;
static struct timeval start_tv = {0, 0};

static void handle_pkt(u_char *arg, const struct pcap_pkthdr *hdr,
  const u_char *bytes) {
  unsigned char buffer[2048];
  size_t pktsize;
  int ret;
  struct timeval delta;

  frame_nr += 1;
  if (start_tv.tv_sec == 0 && start_tv.tv_sec == 0) {
    start_tv = hdr->ts;
  } 

  if (hdr->caplen < rtp_offset) {
    fprintf(stderr, "frame %d dropped: too short\n", frame_nr);
    return;
  }

  memcpy(buffer, bytes + rtp_offset, hdr->caplen - rtp_offset);
  pktsize = hdr->caplen - rtp_offset;

  ret = srtp_recv(s, buffer, &pktsize);
  if (ret != 0) {
    fprintf(stderr, "frame %d dropped: decoding failed '%s'\n", frame_nr,
      strerror(ret));
    return;
  }

  timersub(&hdr->ts, &start_tv, &delta);
  printf("%02ld:%02ld.%06lu\n", delta.tv_sec/60, delta.tv_sec%60, delta.tv_usec);

  hexdump(buffer, pktsize);
}

static void usage(const char *arg0) {
  fprintf(stderr, "usage: %s -k <base64 SDES key> [-d <rtp offset in frames>]\n", arg0);
  exit(1);
}

int main(int argc, char **argv) {
  unsigned char key[16], salt[14];
  int c;
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *pcap;
  unsigned char *sdes = NULL;

  while ((c = getopt(argc, argv, "k:d:")) != -1) {
    switch (c) {
    case 'k':
      sdes = (unsigned char *) optarg;
      break;
    case 'd':
      rtp_offset = atoi(optarg);
      break;
    default:
      usage(argv[0]);
    }
  }

  if (sdes == NULL) {
    usage(argv[0]);
  }

  decode_sdes(sdes, key, salt);

  s = srtp_create(SRTP_ENCR_AES_CM, SRTP_AUTH_HMAC_SHA1, 10,
    SRTP_PRF_AES_CM, 0);
  assert(s != NULL);
  srtp_setkey(s, key, sizeof(key), salt, sizeof(salt));

  pcap = pcap_open_offline("-", errbuf);
  if (!pcap) {
    fprintf(stderr, "libpcap failed to open file '%s'\n", errbuf);
    exit(1);
  }
  assert(pcap != NULL);

  pcap_loop(pcap, 0, handle_pkt, NULL);

  srtp_destroy(s);

  return 0;
}
