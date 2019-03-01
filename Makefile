CFLAGS=-g -Os -Wall
CFLAGS+=`pkg-config --cflags glib-2.0`

LDFLAGS=`pkg-config --libs glib-2.0`

all: srtp.o srtp-decrypt.o
	$(CC) -o srtp-decrypt srtp-decrypt.o srtp.o $(LDFLAGS) -lpcap -lgcrypt

check:
	./srtp-decrypt -k aSBrbm93IGFsbCB5b3VyIGxpdHRsZSBzZWNyZXRz < ./marseillaise-srtp.pcap | text2pcap -t "%M:%S." -u 10000,10000 - - > ./marseillaise-rtp.pcap
