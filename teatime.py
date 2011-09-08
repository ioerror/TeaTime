#!/usr/bin/python
#
# TeaTime: TLS Estimates Accurate Timing Information More Entropically
# by Jacob Appelbaum <jacob@appelbaum.net>
#
# TODO:
#  Perhaps extend this beyond the weird TLS side channel/info leak with:
#  Fetch remote IP date/time
#  Fetch TCP date/time
#  Fetch ICMP date/time
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
from optparse import OptionParser

def parse_args():
  parser = OptionParser("usage: %prog [options]")
  parser.add_option( "-r", "--remotehost", dest="remote_host", type="string", default="www.torproject.org", help="set the remote hostname")
  parser.add_option( "-p", "--port", dest="remote_port", type="int", default=443, help="set the target port")
  parser.add_option( "-t", "--tls", dest="probe_tls", action="store_false", default=True, help="probe target's TLS port")
  parser.add_option( "-T", "--tls-port", dest="remote_tls_port", type="int", default=443, help="set the target TLS port")
  parser.add_option( "-s", "--https", dest="probe_https", action="store_true", default=False, help="probe target's HTTPS port")
  parser.add_option( "-S", "--https-port", type="int", default=443, help="set the target HTTPS port")
  # XXX Implement this sometime
  #parser.add_option( "-n", "--no-validation", dest="validation", action="store_true", default=False, help="disable certificate validation")
  parser.add_option( "-v", "--verbose", dest="verbose", action="store_true", default=True, help="set phasers to verbose")
  (options, args) = parser.parse_args()
  return options, args

# This is a basic TLS connection that validates certs
# You MUST have a patched handshakeClientCert()
# If you don't, you won't have an easy way to fetch serverRandom
def tls_time_fetcher(remote_host, remote_port):
  sock = socket(AF_INET, SOCK_STREAM)
  sock.connect( (remote_host, remote_port))
  sock.settimeout(5)
  connection = TLSConnection(sock)
  connection.handshakeClientCert()
  connection.close()
  remote_hex_long_time = binascii.b2a_hex(connection.session.serverRandom[:4])
  remote_long_time = struct.unpack('!l', remote_hex_long_time.decode('hex'))[0]
  return float(remote_long_time)

# This is a basic HTTPS client time fetcher
def https_time_fetcher(remote_host, remote_port):
  h = HTTPTLSConnection(remote_host, remote_port)
  h.request("GET", "")
  r  = h.getresponse()
  http_date = r.getheader("date")
  return http_date

options, args = parse_args()
local_time = time.time()
if options.verbose:
  print "We're checking the time by connecting to %s on port %s" % (options.remote_host, options.remote_port)
  print "We believe that the local time is : " + str(local_time)
  print "asctime() says: " + str(time.ctime(local_time))

if options.probe_tls:
  remote_tls_time = tls_time_fetcher(options.remote_host, options.remote_port)
  print "The remote system %s believes that TeaTime is : %s" % (options.remote_host, remote_tls_time)
  print "asctime() says: " + str(time.ctime(remote_tls_time))

if options.probe_https:
  remote_https_time = https_time_fetcher(options.remote_host, options.remote_port)
  print "The remote HTTPS system %s believes that HTTPTime is : %s" % (options.remote_host, remote_https_time)
