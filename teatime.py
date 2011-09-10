#!/usr/bin/python
#
# TeaTime: TLS Estimates Accurate Timing Information More Entropically
# by Jacob Appelbaum <jacob@appelbaum.net>
#
# TODO:
#  TLS/SSL session resumption timing even without a valid session
#
#  Optionally set system time
#
#  Perhaps extend this beyond the weird TLS side channel/info leak with:
#  Fetch remote IP date/time
#  Fetch TCP date/time
#  Fetch remote FTP date/time with the old "put foo/dir foo" trick
#  Fetch SMTP banner
#  STARTTLS for various protocols (most need TLS for auth)
#  Daytime
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
import urllib2
import time
import struct
import binascii
from optparse import OptionParser

# We'll pretend to be Torbuton's UA by default
default_user_agent = "Mozilla/5.0 (Windows NT 6.1; rv:5.0) Gecko/20100101 Firefox/5.0"
# We'll use privoxy or whatever local proxy is on 8118
default_proxy = {'http': 'http://127.0.0.1:8118/'}
# Someone might have a different sense of the beginning of time...?
default_epoch = 2208988800L
# RFC2030 has other defaults but this one is ours
default_sntp_recv_bytes = 48
# Default socket timeout
default_socket_timeout = 10

def parse_args():
  parser = OptionParser("usage: %prog [options]")
  parser.add_option( "-r", "--remotehost", dest="remote_host", type="string", default="www.torproject.org", help="set the remote hostname")
  parser.add_option( "-p", "--port", dest="remote_port", type="int", default=443, help="set the target port")
  parser.add_option( "-t", "--tls", dest="probe_tls", action="store_true", default=False, help="probe target's TLS port")
  parser.add_option( "-T", "--tls-port", dest="remote_tls_port", type="int", default=443, help="set the target TLS port")
  parser.add_option( "-s", "--https", dest="probe_https", action="store_true", default=False, help="probe target's HTTPS port")
  parser.add_option( "-S", "--https-port", type="int", default=443, help="set the target HTTPS port")
  parser.add_option( "-u", "--http", dest="probe_http", action="store_true", default=False, help="probe target's HTTP port")
  parser.add_option( "-U", "--http-port", type="int", default=80, dest="remote_http_port", help="set the target HTTP port")
  parser.add_option( "-x", "--use-proxy", dest="use_proxy", action="store_true", default=False, help="use proxy (HTTP/HTTPS only)")
  parser.add_option( "-n", "--sntp", dest="probe_sntp", action="store_true", default=False, help="probe target's SNTP port")
  parser.add_option( "-N", "--sntp-port", type="int", default=123, dest="remote_sntp_port", help="set the target SNTP port")
  parser.add_option( "-i", "--icmp", dest="probe_icmp", action="store_true", default=False, help="probe target with ICMP")
  parser.add_option( "-z", "--zee-number-of-loops", type="int", default=1, dest="num_of_tries",help="number of times to run selected tests (default: 1)")
  # XXX Implement these sometime:
  #
  # parser.add_option( "-n", "--no-validation", dest="validation", action="store_true", default=False, help="disable certificate validation")
  #
  # Reserved for future implementation:
  #
  # parser.add_option( "-R", "--tls-resume-session", dest="tls_resume_session",
  # action="store_true", default=False, help="attempt to resume TLS session
  # with random session")
  #
  # http://en.wikipedia.org/wiki/ICMP_Timestamp
  # http://caia.swin.edu.au/cv/szander/cprobe/skew_probing.html
  #
  # parser.add_option( "-I", "--tcp", dest="ip", action="store_true", default=False, help="probe target with TCP")
  #
  parser.add_option( "-v", "--verbose", dest="verbose", action="store_true", default=True, help="set phasers to verbose")
  (options, args) = parser.parse_args()
  return options, args

# This is a basic TLS connection that validates certs
# You MUST have a patched handshakeClientCert()
# If you don't, you won't have an easy way to fetch serverRandom
def tls_time_fetcher(remote_host, remote_port):
  sock = socket(AF_INET, SOCK_STREAM)
  sock.connect( (remote_host, remote_port))
  sock.settimeout(default_socket_timeout)
  connection = TLSConnection(sock)
  connection.handshakeClientCert()
  connection.close()
  remote_hex_long_time = binascii.b2a_hex(connection.session.serverRandom[:4])
  remote_long_time = struct.unpack('!l', remote_hex_long_time.decode('hex'))[0]
  return float(remote_long_time)

def start_tls_xmpp_time_fetcher(remote_host, remote_port):
  # Open a socket to XMPP server and StartTLS like so:
  # <?xml version='1.0' ?>\r\n
  # <stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='%s' version='1.0'>\r\n
  # <starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>\r\n
  # read until /stream:features for urn:ietf:params:xml:ns:xmpp-tls
  # if we find <proceed, we're good
  # StartTLS here and then parse connection.session.serverRandom
  remote_long_time = 0.0
  return float(remote_long_time)

def start_tls_pop3_time_fetcher(remote_host, remote_port):
  # Open a socket to a pop3 service and StartTLS like so:
  # "STLS\r\n"
  # read from the socket and if we see "+OK" - we're golden
  #  StartTLS here and then parse connection.session.serverRandom
  remote_long_time = 0.0
  return float(remote_long_time)

def start_tls_imap_time_fetcher(remote_host, remote_port):
  # Open a socket to a imap service and StartTLS like so:
  # ". STARTTLS\r\n"
  # read from the socket and if we see ". OK" - we're good to go
  #  StartTLS here and then parse connection.session.serverRandom
  remote_long_time = 0.0
  return float(remote_long_time)

def start_tls_ftp_time_fetcher(remote_host, remote_port):
  # Open a socket to a ftp service and StartTLS like so:
  # "AUTH TLS\r\n"
  # read from the socket and look for "234 AUTH TLS successful"
  #  StartTLS here and then parse connection.session.serverRandom
  remote_long_time = 0.0
  return float(remote_long_time)

def start_tls_smtp_time_fetcher(remote_host, remote_port):
  # Open a socket to a ftp service and StartTLS like so:
  # "EHLO %s\r\n" where %s is "our" hostname
  # read from the socket and look for "250" and then write "STARTTLS\r\n"
  # If we see a "220" - we're good to go.
  #  StartTLS here and then parse connection.session.serverRandom
  remote_long_time = 0.0
  return float(remote_long_time)

# This implements the most basic SNTP client possible ( RFC 2030 )
# THIS IS NOT PROXY SAFE IT USES *UDP* AND IT LEAKS DNS
def sntp_time_fetcher(remote_host, remote_port):
  remote_long_time = 0.0
  server_response = ""
  remote_ip = gethostbyname(remote_host)
  sock = socket(AF_INET, SOCK_DGRAM)
  sock.settimeout(default_socket_timeout)
  sntp_request = "\x1b" + 47 * '\0'
  bytes_sent = sock.sendto(sntp_request, (remote_ip, remote_port))
  server_response, address = sock.recvfrom(default_sntp_recv_bytes)
  sock.close()
  if len(server_response) == 48:
    # network order, unsigned int from the 40th to the 44th byte of the 48byte
    # reply returned as as an int, not a tuple
    remote_time = struct.unpack( '!1I', server_response[40:44])[0]
    remote_time -= default_epoch
    remote_long_time = remote_time
  else:
    remote_long_time = 0.0
  return float(remote_long_time)

# This is a very basic ICMP Timestamp fetcher. It needs SOCK_RAW privileges.
# Note that ICMP returns milliseconds since midnight UTC, not unixtime.
# Based on a Python ping implementation by Pierre Bourdon and George Notaras
# available at http://pypi.python.org/pypi/ping/0.1 (GPLv2)
def icmp_time_fetcher(remote_host):
  remote_long_time = 0.0
  # ICMP Timestamp request packet;    type, code, chksum, id, seq, orig, rx, tx
  request = struct.pack("bbHxbxbIII", 13,   0,    0xfdf2, 1,  1,   0,    0,  0)
  try:
    sock = socket(AF_INET, SOCK_RAW, getprotobyname("icmp"))
  except error, (errno, msg):
    # Operation not permitted?
    if errno == 1: 
      msg = msg + " - ICMP probes need SOCK_RAW privileges (are you root?)"
      raise error(msg)
    raise
  sock.settimeout(10)
  sock.sendto(request, (remote_host, 1))
  recPacket, addr = sock.recvfrom(40)
  sock.close()
  payload = recPacket[24:40]
  packetID, sequence, tx = struct.unpack("xbxbxxxxxxxxI", payload)
  if packetID == sequence == 1:
    # Convert milliseconds to seconds
    remote_long_time = ntohl(tx)/1000.0
  else:
    remote_long_time = 0.0
  return float(remote_long_time)

# This is a basic HTTPS client time fetcher
def https_time_fetcher(remote_host, remote_port):
  h = HTTPTLSConnection(remote_host, remote_port)
  h.request("GET", "")
  r  = h.getresponse()
  https_date = r.getheader("date")
  return https_date

# This is a basic HTTP client time fetcher
def http_time_fetcher(remote_host, remote_port):
  # This may not be the most optimal url but it should work well enough
  remote_url = "http://" + remote_host + ":" + str(remote_port) + "/"
  default_headers = { "User-Agent" : default_user_agent }
  request = urllib2.Request(url=remote_url, headers=default_headers)
  response = urllib2.urlopen(request)
  http_date = response.headers.get("date")
  return http_date

options, args = parse_args()
if options.use_proxy:
  urllib2.ProxyHandler(default_proxy)
else:
  # No proxy
  urllib2.ProxyHandler({"":""})

for x in xrange(options.num_of_tries):
  local_time = time.time()
  if options.verbose:
    print "We're checking the time by connecting to %s" % (options.remote_host)
    print "This is run number: %i of %i" % (x, options.num_of_tries)
    print "We believe that the local time is : " + str(local_time)
    print "asctime() says: " + str(time.ctime(local_time)) + " (" + str(time.time()) + ")"

  if options.probe_tls:
    print "time before TLS probe: " + str(time.ctime(time.time())) + " (" + str(time.time()) + ")"
    remote_tls_time = tls_time_fetcher(options.remote_host, options.remote_port)
    print "time after TLS probe: " + str(time.ctime(time.time())) + " (" + str(time.time()) + ")"
    print "The remote system %s believes that TeaTime is : %s" % (options.remote_host, remote_tls_time)
    print "asctime() says: " + str(time.ctime(remote_tls_time))

  if options.probe_https:
    print "time before HTTPS probe: " + str(time.ctime(time.time())) + " (" + str(time.time()) + ")"
    remote_https_time = https_time_fetcher(options.remote_host, options.remote_port)
    print "time after HTTPS probe: " + str(time.ctime(time.time())) + " (" + str(time.time()) + ")"
    print "The remote HTTPS system %s believes that HTTPSTime is : %s" % (options.remote_host, remote_https_time)

  if options.probe_http:
    print "time before HTTP probe: " + str(time.ctime(time.time())) + " (" + str(time.time()) + ")"
    remote_http_time = http_time_fetcher(options.remote_host, options.remote_http_port)
    print "time after HTTP probe: " + str(time.ctime(time.time())) + " (" + str(time.time()) + ")"
    print "The remote HTTP system %s believes that HTTPTime is : %s" % (options.remote_host, remote_http_time)

  # This can't ever work with a proxy
  if options.probe_sntp and options.use_proxy == False:
    print "time before SNTP probe: " + str(time.ctime(time.time())) + " (" + str(time.time()) + ")"
    remote_sntp_time = sntp_time_fetcher(options.remote_host, options.remote_sntp_port)
    print "time after SNTP probe: " + str(time.ctime(time.time())) + " (" + str(time.time()) + ")"
    print "The remote system %s believes that SNTP is : %s" % (options.remote_host, remote_sntp_time)
    print "asctime() says: " + str(time.ctime(remote_sntp_time))

  # This can't ever work with a proxy
  if options.probe_icmp and options.use_proxy == False:
    print "time before ICMP probe: " + str(time.ctime(time.time())) + " (" + str(time.time()) + ")"
    remote_icmp_time = icmp_time_fetcher(options.remote_host)
    print "time after ICMP probe: " + str(time.ctime(time.time())) + " (" + str(time.time()) + ")"
    # ICMP does not actually return unixtime, but rather "time since midnight UTC" 
    print "The remote system %s believes that ICMPTime (seconds today in UTC) is : %s" % (options.remote_host, remote_icmp_time)
    print "asctime() says: " + str(time.ctime(remote_icmp_time))

