import socket
import sys
from types import *
import struct
import time
import logging

HOST = '127.0.0.1'    
dest_port = 5002       
TANGO_DOWN = ''
sock = None
dumbflagset = 0;
logging.basicConfig(filename='./fuzzer.log', filemode='a', level=logging.DEBUG, format='[%(asctime)s][%(levelname)s] %(message)s')

def create_connection(dest_ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error, msg:
        sys.stderr.write("[ERROR] %s\n" % msg[1])
        sys.exit(1)

    HOST = dest_ip
    try:
        sock.settimeout(0.5)
        sock.connect((HOST, dest_port))
    except socket.error, msg:
        logging.exception("Connection Failed!")
    else:
        logging.info("Connected to Server: %s" % dest_ip)

    return sock


def hexstr(s):
    return '-'.join('%02x' % ord(c) for c in s)


def dumb_fuzzing(dest_ip):
  sock = create_connection(dest_ip, dest_port)
  unitID = 0
  protoID = 0
  transID = 0
  lengthOfFunctionData = 1
  prevField = ""
  for functionCode in range(0,255):
    for functionData6 in range(0, 255):
      for functionData5 in range(0, 255):
        for functionData4 in range(0, 255):
          for functionData3 in range(0, 255):
            for functionData2 in range(0, 255):
              for functionData1 in range(0, 255):
                functionDataField = prevField + struct.pack(">B", functionData1)
                length = 2 + lengthOfFunctionData
                ModbusPacket = struct.pack(">H", transID) + \
                     struct.pack(">H", protoID) + \
                     struct.pack(">H", length) + \
                     struct.pack(">B", unitID) + \
                     struct.pack(">B", functionCode) + \
                     functionDataField
                logging.debug("%s" % hexstr(ModbusPacket))
                try:
                  sock.send(ModbusPacket)
                except socket.timeout:
                  logging.exception("Sending Timed Out!")
                except socket.error:
                  logging.exception("Sending Failed!")
                  sock.close()
                  sock = create_connection(dest_ip, dest_port)
                  logging.info("Try to Reconnect...")
                else:
                  logging.debug("Sent Packet: %s" % hexstr(ModbusPacket))
                  print "Sent: %s" % hexstr(ModbusPacket)


dumb_fuzzing(HOST)
