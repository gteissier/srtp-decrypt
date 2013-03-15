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
