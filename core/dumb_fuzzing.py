from core.logger import get_logger

import socket
import sys
from types import *
import struct
import time
import logging

class DFuzz(object):

    def __init__(self, r0obj):
        self.r0obj = r0obj
        self.HOST = "127.0.0.1"
        self.dest_port = 5020
        self.verbosity = self.r0obj.log_level

        self.logger = get_logger("Dumbfuzz", self.verbosity)

    def create_connection(self, dest_ip, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except socket.error as msg:
            self.logger.error("[-] Unable to establish socket connection")
            sys.exit(1)

        self.HOST = dest_ip
        try:
            sock.settimeout(0.5)
            sock.connect((self.HOST, self.dest_port))
        except socket.error as msg:
            self.logger.error(msg)
        else:
            self.logger.info("[+] Connected to Server: %s" % dest_ip)

        return sock


    def hexstr(self, s):
        return '-'.join('%02x' % ord(c) for c in s)


    def dumb_fuzzing(self):
      sock = self.create_connection(self.HOST, self.dest_port)
      length1 = 0
      length2 = 6
      unitID = 1

      for transID1 in range(0,0xff):
        for protoID1 in range(0,0xff):
          for functionCode in range(0,0xff):
            for functionData1 in range(0,0xff):
              for functionData2 in range(0,0xff):
                TotalModbusPacket = struct.pack(">H", transID1)
                TotalModbusPacket += struct.pack(">H", protoID1)
                TotalModbusPacket += struct.pack(">B", length1)
                TotalModbusPacket += struct.pack(">B", length2)
                TotalModbusPacket += struct.pack(">B", unitID)
                TotalModbusPacket += struct.pack(">B", functionCode)
                TotalModbusPacket += struct.pack(">H", functionData1)
                TotalModbusPacket += struct.pack(">H", functionData2)
                self.logger.debug("[+] Packet sent: %s" % str(TotalModbusPacket))
                try:
                  sock.send(TotalModbusPacket)
                  print >>sys.stderr,'received: %s'% self.hexstr(sock.recv(1024).decode("utf-8"))
                except socket.timeout:
                  self.logger.warning("Sending Timed Out!")
                except socket.error:
                  self.logger.warning("Sending Failed!")
                  sock.close()
                  sock = self.create_connection(self.HOST, self.dest_port)
                  #logging.info("Try to Reconnect...")
                else:
                  self.logger.debug("[+] Sent Packet: %s" % self.hexstr(TotalModbusPacket.decode("utf-8")))

