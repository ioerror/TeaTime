#!/usr/bin/python
#
# TeaTime: TLS Estimates Accurate Timing Information More Entropically
# by Jacob Appelbaum <jacob@appelbaum.net>
#
# TODO:
# Basic argument parsing
# Perhaps extend this beyond the weird TLS side channel/info leak with:
#  Fetch remote HTTP date/time
#  Fetch remote IP date/time
#
# For TLS we want the first four bytes of the random value sent by the server
# This is clasically the remote value of gmt_unix_time
# eg: connection.session.serverRandom[:4] is four hex bytes that represent a
# long and need to be cast as a float to work with time.ctime()
#
# Wireshark C example:
#
#  http://anonsvn.wireshark.org/wireshark/trunk/epan/dissectors/packet-ssl.c
#    gmt_unix_time.secs = tvb_get_ntohl(tvb, offset);
#    gmt_unix_time.nsecs = 0;
#
# Wireshark converts '4e663912' to:
#
#   gmt_unix_time: Sep  6, 2011 17:15:30.000000000 CEST
#

from socket import *
from tlslite.api import *
import time
import struct
import binascii

remote_host = "www.torproject.org"
remote_port = 443

sock = socket(AF_INET, SOCK_STREAM)
sock.connect( (remote_host, remote_port))
sock.settimeout(5)

connection = TLSConnection(sock)

# You MUST have a patched handshakeClientCert()
# If you don't, you won't have an easy way to fetch serverRandom
connection.handshakeClientCert()
connection.close()

# We want the first four bytes of the random value sent by the server
# This is clasically the remote value of gmt_unix_time
# eg: connection.session.serverRandom[:4] is four hex bytes that represent
# a long and need to be cast as a float to work with time.ctime()
#
# Wireshark C example:
#
#  http://anonsvn.wireshark.org/wireshark/trunk/epan/dissectors/packet-ssl.c
#    gmt_unix_time.secs = tvb_get_ntohl(tvb, offset);
#    gmt_unix_time.nsecs = 0;
#
# Wireshark converts '4e663912' to:
#
#   gmt_unix_time: Sep  6, 2011 17:15:30.000000000 CEST
#

remote_hex_long_time = binascii.b2a_hex(connection.session.serverRandom[:4])
remote_long_time = struct.unpack('!l', remote_hex_long_time.decode('hex'))[0]

local_time = time.time()
print "The remote system believes that TeaTime is : " + str(float(remote_long_time))
print "asctime() says: " + str(time.ctime(float(remote_long_time)))
print "We believe that the local time is : " + str(local_time)
print "asctime() says: " + str(time.ctime(local_time))

# This is the start of the HTTP client time fetcher
#
# h = HTTPTLSConnection(remote_host, remote_port)
# h.request("GET", "")
# r  = h.getresponse()
# dir(r)
# print r
