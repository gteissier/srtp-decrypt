srtp-decrypt
============

srtp-decrypt is a tool that deciphers SRTP packets contained in a network capture. It needs the Master Key exchanged by other means to do its job.
Deciphered RTP is dumped in such a way that output can be fed to text2pcap, to recreate a deciphered capture.

dependencies
============

SRTP part has been taken from VLC project. It depends on libgcrypt for ciphering and MAC.
Pcap processing is based on libpcap.

Typically, on Debian, # apt-get install libpcap-dev libgcrypt-dev.

caveats
=======

Isolating a single RTP flow from a network capture is a hard job, too hard to be done in this tool. Hence, srtp-decrypt expects to process a single RTP flow.
Network capture shall not contain ICMP, ARP or reverse RTP flow for example, as those packets will not be deciphered correctly by the tool.
Moreover, RTP offset in frames is expected to be constant, by default 42, but can be set to 46 in case of 802.1q tagging.

How to use
==========

1. Get network capture.
2. Filter RTP only packets and export from wireshark in .pcap format (that is important as it understand .pcap only), better use SSRC filtering too for different media sessions.
3. For SDES (p-series) media run srtp-decrypt like:
  * ./srtp-decrypt -k crypto-inline-from-SIP-SDP -f 4 \< filtered-rtp-from-above-name.pcap \> dump-file–name.txt
4. For DTLS (soft-phone) media run srtp-decrypt like:
  * ./srtp-decrypt -m key-from-rtpengine-log -s salt-from-rtpengine-log \< filtered-rtp-from-above-name.pcap \> dump-file-name.txt
5. In wireshark select File-\>"Import From Hex Dump”, navigate to dump-file-name.txt, select “Dummy Header”-\>”UDP”, enter Source and Destination ports, press OK
6. Right click on any packet, select "Decode As" -\> RTP
7. After that you can use Telephony -\> RTP -> Analyze Stream -\> Player (use RTP timestamp for decoding) -\> Play


Here is how to use it in general:
=================================

./srtp-decrypt [-k \<base64 SDES key\>] | [-m \<base64 key\> -s \<base64 salt\>] [-d \<rtp byte offset in packet\>] [-t \<srtp hmac tag length in bytes\>] [-f \<srtp flags\>]

- where \<srtp flags\> is OR'ed decimal of:
  - 0x1  - do not encrypt SRTP packets
  - 0x2  - do not encrypt SRTCP packets
  - 0x4  - authenticate only SRTCP packets
  - 0x10 - use Roll-over-Counter Carry mode 1
  - 0x20 - use Roll-over-Counter Carry mode 2
  - 0x30 - use Roll-over-Counter Carry mode 3 (insecure)
