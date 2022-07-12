CFLAGS=-g -Os -Wall -Werror

all: srtp.o srtp-util.o
	$(CC) -o srtp-util srtp-util.o srtp.o -lpcap -lgcrypt

clean:
	rm -rf srtp-util *.o

check:
	# Decrypt the pcap
	./srtp-util -k aSBrbm93IGFsbCB5b3VyIGxpdHRsZSBzZWNyZXRz < ./marseillaise-srtp.pcap | text2pcap -t "%M:%S." -u 10000,10000 - - > ./marseillaise-rtp.pcap
	# Encrypt already decrypted pcap
	./srtp-util -E -k aSBrbm93IGFsbCB5b3VyIGxpdHRsZSBzZWNyZXRz < ./marseillaise-rtp.pcap | text2pcap -t "%M:%S." -u 10000,10000 - - > ./marseillaise-srtp-new.pcap
