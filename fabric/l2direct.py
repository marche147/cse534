#!/usr/bin/env python
# -*- coding: utf-8 -*-

import select
import socket
import sys

from pytun import TunTapDevice, IFF_TAP, IFF_NO_PI
import sh

def main():
  if len(sys.argv) == 3:
    s = socket.socket()
    port = int(sys.argv[1])
    tap_ip = sys.argv[2]
    s.bind(('0.0.0.0', port))

    print("Listening on port {}...".format(port))
    s.listen(5) 
    conn, address = s.accept()
    print("Accepted connection from {}:{}".format(address[0], address[1]))
    s.close()
  elif len(sys.argv) == 4:
    addr, port, tap_ip = sys.argv[1:]
    conn = socket.socket()
    conn.connect((addr, int(port)))
    print("Connected to {}:{}".format(addr, port))
  else:
    print("Usage: \n{argv0} [port] [tap_ip] - use as server\n{argv0} [ip] [port] [tap_ip] - use as client".format(argv0=sys.argv[0]))
    return 1

  mtu = 1472
  tap = TunTapDevice(flags=IFF_TAP|IFF_NO_PI)
  if tap_ip != "undefined":
    sh.ip.addr.add(tap_ip, 'dev', tap.name)
  sh.ip.link.set(tap.name, 'up')
  sh.ip.link.set(tap.name, 'mtu', str(mtu))

  print("TAP Device {} up.".format(tap.name))
  while True:
    r, w, x = select.select([tap, conn], [], [], 0.001)
    if tap in r:
      buf = tap.read(tap.mtu).ljust(tap.mtu, b'\x00')
      conn.sendall(buf)
    if conn in r:
      buf = b''
      while len(buf) != tap.mtu:
        buf += conn.recv(tap.mtu - len(buf))
      tap.write(buf)

  return 0

if __name__ == '__main__':
  sys.exit(main())
