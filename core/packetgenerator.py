from core.logger import get_logger

import socket
import sys	
from types import *
import struct
import time
import logging
import pickle
from scapy.all import *

'''FORMAT = ('%(asctime)-15s %(threadName)-15s'
' %(levelname)-8s %(module)-15s:%(lineno)-8s %(message)s')

logging.basicConfig(format=FORMAT)
log = logging.getLogger()
log.setLevel(logging.DEBUG)'''

class Modbus(Packet):
	name = "Modbus/tcp"
	fields_desc = [ ShortField("Transaction Identifier", 1),
				ShortField("Protocol Identifier", 0),
				ShortField("Length", 2),
				XByteField("Unit Identifier",0),
				ByteField("Function Code", 0)
				]


class PackGen(object):

	def __init__(self, r0obj):
		self.r0obj = r0obj
		self.HOST = "127.0.0.1"
		self.src_port = 49901
		self.dest_port = 5020
		self.verbosity = self.r0obj.log_level
	
		self.logger = get_logger("Packgen", self.verbosity)

	def create_connection(self, port):
		try:
			sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		except socket.error as msg:sys.stderr.write("[ERROR] %s\n" % msg[1])
		sys.exit(1)
		try:
			#sock.bind((HOST,src_port))
			sock.settimeout(0.5)
			sock.connect((self.HOST, self.dest_port))
		except socket.error as msg:
			self.logger.warning("[-] Connection Failed!")
		else:
			self.logger.info("[+] Connected to Server: %s" % self.HOST)
		return sock
	
	def hexstr(self, s):
		t = ""
		for i in range(0,len(s)):
			t = t + str(hex(s[i]))[2:] + '-'  
		return t[:-1]

	def make_packet(self, packet):

		TotalModbusPacket =  ""
		TotalModbusPacket += struct.pack(">B", packet['transID1'])
		TotalModbusPacket += struct.pack(">B", packet['transID2'])
		TotalModbusPacket += struct.pack(">B", packet['protoID1'])
		TotalModbusPacket += struct.pack(">B", packet['protoID2'])
		TotalModbusPacket += struct.pack(">B", packet['length1'])
		TotalModbusPacket += struct.pack(">B", packet['length2'])
		TotalModbusPacket += struct.pack(">B", packet['unitID'])
		TotalModbusPacket += struct.pack(">B", packet['functionCode'])
		TotalModbusPacket += struct.pack(">H", packet['functionData1'])
		TotalModbusPacket += struct.pack(">H", packet['functionData2'])

		return TotalModbusPacket


	def AddToPCAP(self, packet):
		pkt = Ether()/IP()/TCP(sport=self.src_port, dport = self.dest_port)/packet/Modbus()
		wrpcap('test.pcap', pkt, append=True)

	def send_packet(self, packet):
		sock = self.create_connection(self.dest_port)

		for functionCode in [0x10] : # Fuzzing specific parameters
			for functionData1 in [0x21]:
				for functionData2 in [65535]:

					packet['functionCode'] = functionCode
					packet['functionData1'] = functionData1
					packet['functionData2'] = functionData2

					ModbusPacket = self.make_packet(packet) 
					#AddToPCAP(ModbusPacket)
					#AddToPCAP(RespPacket)
					try:
						sock.send(ModbusPacket)
					except socket.timeout:
						self.logger.error("Sending Timed Out!")
					except socket.error:
						#self.logger.error("Sending Failed!")
						sock.close()
						sock = create_connection(self.HOST, self.dest_port)
						#self.logger.info("Try to Reconnect...")
					else:
						self.logger.debug("[+] Sent Packet: %s" % hexstr(ModbusPacket))
						print("Sent: %s" % hexstr(ModbusPacket))
						RespPacket = sock.recv(1024)
						print >>sys.stderr,'received: %s'% hexstr(RespPacket)

	def formPacket(self, fields_dict):
		self.logger.debug("formPacket")

		for i in range(0,50):
			packet = {}
			for key in fields_dict.keys():
				packet[key] = fields_dict[key][i]
		print(packet)
		self.send_packet(packet)