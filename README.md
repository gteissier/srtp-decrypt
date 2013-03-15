srtp-decrypt
============

srtp-decrypt is a tool that deciphers SRTP packets contained in a network capture. It needs the Master Key exchanged by other means to do its job.
Deciphered RTP is dumped in such a way that output can be fed to text2pcap, to recreate a deciphered capture.

dependencies
============

SRTP part has been taken from VLC project. It depends on libgcrypt for ciphering and MAC.
Pcap processing is based on libpcap.

Typically, on Debian, # apt-get install libpcap-dev libgcrypt-dev.
