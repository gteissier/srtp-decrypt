#include <sys/types.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <assert.h>

#include <glib.h>

#include "srtp.h"

#include <pcap.h>

static void decode_sdes(
    unsigned char *in,
    unsigned char *key,
    unsigned char *salt) {
  guchar * gbuf = NULL;
  gsize    out_len = 0;

  gbuf = g_base64_decode((gchar*)in, &out_len);
  assert(gbuf && (out_len == 30));

  memcpy(key, gbuf, 16);
  memcpy(salt, gbuf+16, 14);

  g_free(gbuf);
}

static void decode_key(
		unsigned char *in,
		unsigned char *key)  {
	guchar * gbuf = NULL;
	gsize    out_len = 0;

	gbuf = g_base64_decode((gchar*)in, &out_len);
	assert(gbuf && (out_len == 16));

	memcpy(key, gbuf, 16);

	g_free(gbuf);
}

static void decode_salt(
		unsigned char *in,
		unsigned char *salt) {
	guchar * gbuf = NULL;
	gsize    out_len = 0;

	gbuf = g_base64_decode((gchar*)in, &out_len);
	assert(gbuf && (out_len == 14));

	memcpy(salt, gbuf, 14);

	g_free(gbuf);
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

static int rtp_offset = -1;
static int frame_nr = -1;
static int decoded_packets = 0;
static struct timeval start_tv = {0, 0};

static void handle_pkt(u_char *arg, const struct pcap_pkthdr *hdr,
  const u_char *bytes) {
  unsigned char buffer[2048];
  size_t pktsize;
  int ret;
  struct timeval delta;

  frame_nr += 1;

  if (hdr->caplen < rtp_offset) {
    fprintf(stderr, "frame %d dropped: too short\n", frame_nr);
    return;
  }

  memcpy(buffer, bytes + rtp_offset, hdr->caplen - rtp_offset);
  pktsize = hdr->caplen - rtp_offset;

  if (frame_nr == 0) {
    start_tv = hdr->ts;
  }

  if (decoded_packets == 0) {
    srtp_init_seq (s, buffer);
  }

  ret = srtp_recv(s, buffer, &pktsize);
  if (ret != 0) {
    fprintf(stderr, "frame %d dropped: decoding failed '%s'\n", frame_nr,
      strerror(ret));

    return;
  }

  decoded_packets++;

  timersub(&hdr->ts, &start_tv, &delta);
  printf("%02ld:%02ld.%06lu\n", delta.tv_sec/60, delta.tv_sec%60, delta.tv_usec);

  hexdump(buffer, pktsize);

}

static void usage(const char *arg0) {
  fprintf(stderr, "usage: %s [-k <base64 SDES key>] | [-m <base64 key> -s <base64 salt>] [-d <rtp byte offset in packet>] [-t <srtp hmac tag length in bytes>] [-f <srtp flags>]\n", arg0);
  fprintf(stderr, "where <srtp flags> is OR'ed decimal of:\n\t0x1  - do not encrypt SRTP packets\n\t0x2  - do not encrypt SRTCP packets\n\t0x4  - authenticate only SRTCP packets\n");
  fprintf(stderr, "\t0x10 - use Roll-over-Counter Carry mode 1\n\t0x20 - use Roll-over-Counter Carry mode 2\n\t0x30 - use Roll-over-Counter Carry mode 3 (insecure)\n");

  exit(1);
}

int main(int argc, char **argv) {
  unsigned char key[16], salt[14];
  int c;
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *pcap;
  unsigned char *sdes  = NULL;
  unsigned char *pkey  = NULL;
  unsigned char *psalt = NULL;
  int taglen = 10;
  struct bpf_program pcap_filter;
  unsigned srtp_flags = 0;

  while ((c = getopt(argc, argv, "k:d:t:m:s:f:")) != -1) {
    switch (c) {
    case 'k':
      sdes = (unsigned char *) optarg;
      break;
    case 'm':
      pkey = (unsigned char *) optarg;
      break;
    case 's':
      psalt = (unsigned char *) optarg;
      break;
    case 'f':
      srtp_flags |= (unsigned)atoi(optarg);
      break;
    case 'd':
      rtp_offset = atoi(optarg);
      break;
    case 't':
      taglen = atoi(optarg);
      break;
    default:
      usage(argv[0]);
    }
  }

  if (sdes == NULL) {
	  if ((pkey == NULL) || (psalt == NULL))
		  usage(argv[0]);
	  else {
		  decode_key(pkey, key);
		  decode_salt(psalt, salt);
	  }
  }
  else {
	  decode_sdes(sdes, key, salt);
  }

  srtp_flags &= SRTP_FLAGS_MASK;

  s = srtp_create(SRTP_ENCR_AES_CM, SRTP_AUTH_HMAC_SHA1, taglen,
    SRTP_PRF_AES_CM, srtp_flags);
  assert(s != NULL);
  srtp_setkey(s, key, sizeof(key), salt, sizeof(salt));

  pcap = pcap_open_offline("-", errbuf);
  if (!pcap) {
    fprintf(stderr, "libpcap failed to open file '%s'\n", errbuf);
    exit(1);
  }
  assert(pcap != NULL);

  // We are only interested in udp traffic
  if (pcap_compile(pcap, &pcap_filter, "udp", 1, PCAP_NETMASK_UNKNOWN) == 0) {
    pcap_setfilter(pcap, &pcap_filter);
  }

  if (rtp_offset == -1) {
    switch(pcap_datalink(pcap)) {
        case DLT_LINUX_SLL: rtp_offset = 44; break; /* 16 + 20 + 8 */;
        default:
            rtp_offset = 42; /* 14 + 20 + 8 */;
    }
  }

  pcap_loop(pcap, 0, handle_pkt, NULL);

  srtp_destroy(s);

  return 0;
}
