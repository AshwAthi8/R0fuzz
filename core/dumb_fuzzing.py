#from core.logger import get_logger

import socket
import sys
from types import *
import struct
import time
import logging

HOST = '127.0.0.1'    
dest_port = 5020       
sock = None
dumbflagset = 0;
logging.basicConfig(filename='./fuzzer.log', filemode='a', level=logging.DEBUG, format='[%(asctime)s][%(levelname)s] %(message)s')

def create_connection(dest_ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as msg:
        sys.stderr.write("[ERROR] %s\n" % msg[1])
        sys.exit(1)

    HOST = dest_ip
    try:
        sock.settimeout(0.5)
        sock.connect((HOST, dest_port))
    except socket.error as msg:
        logging.exception("Connection Failed!")
    else:
        logging.info("Connected to Server: %s" % dest_ip)

    return sock


def hexstr(s):
    return '-'.join('%02x' % ord(c) for c in s)


def dumb_fuzzing(dest_ip):
  sock = create_connection(dest_ip, dest_port)
  length1 = 0
  length2 = 6
  unitID = 1

  for transID1 in range(0,0xff):
    for protoID1 in range(0,0xff):
      for functionCode in range(0,0xff):
        for functionData1 in range(0,0xff):
          for functionData2 in range(0,0xff):
            TotalModbusPacket =  ""
            TotalModbusPacket += struct.pack(">H", transID1)
            TotalModbusPacket += struct.pack(">H", protoID1)
            TotalModbusPacket += struct.pack(">B", length1)
            TotalModbusPacket += struct.pack(">B", length2)
            TotalModbusPacket += struct.pack(">B", unitID)
            TotalModbusPacket += struct.pack(">B", functionCode)
            TotalModbusPacket += struct.pack(">H", functionData1)
            TotalModbusPacket += struct.pack(">H", functionData2)
            logging.debug("%s" % hexstr(TotalModbusPacket))
            try:
              sock.send(TotalModbusPacket)
              print >>sys.stderr,'received: %s'% hexstr(sock.recv(1024))
            except socket.timeout:
              logging.exception("Sending Timed Out!")
            except socket.error:
              #logging.exception("Sending Failed!")
              sock.close()
              sock = create_connection(dest_ip, dest_port)
              #logging.info("Try to Reconnect...")
            else:
              logging.debug("Sent Packet: %s" % hexstr(TotalModbusPacket))
              print("Sent: %s" % hexstr(TotalModbusPacket))


dumb_fuzzing(HOST)
