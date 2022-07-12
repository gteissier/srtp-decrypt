CFLAGS=-g -Os -Wall -Werror

all: srtp.o srtp-decrypt.o
	$(CC) -o srtp-decrypt srtp-decrypt.o srtp.o -lpcap -lgcrypt

clean:
	rm -rf srtp-decrypt *.o

check:
	./srtp-decrypt -k aSBrbm93IGFsbCB5b3VyIGxpdHRsZSBzZWNyZXRz < ./marseillaise-srtp.pcap | text2pcap -t "%M:%S." -u 10000,10000 - - > ./marseillaise-rtp.pcap
	./srtp-decrypt -E -k aSBrbm93IGFsbCB5b3VyIGxpdHRsZSBzZWNyZXRz < ./marseillaise-rtp.pcap | text2pcap -t "%M:%S." -u 10000,10000 - - > ./marseillaise-srtp-new.pcap
