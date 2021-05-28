from core.logger import get_logger

from scapy.all import *
from os.path import join
import binascii

class Extractor(object):

    def __init__(self, r0obj):
        #needed pcap
        self.r0obj = r0obj
        self.input = self.r0obj.seed
        self.layer = "TCP"
        self.field = "load"
        self.PORT = 502
        self.verbosity = self.r0obj.log_level

        self.logger = get_logger("Extractor", self.verbosity)        

    def extract_load(self, pac):
        """ 
        Extract the fields form sample packet
        Return: dictionary
        """

        c = 0
        fields_dic = {"transID1":[],
            "transID2":[],
            "protoID1":[],
            "protoID2":[],
            "length1":[],
            "length2":[],
            "unitID":[],
            "functionCode":[],
            "functionData1":[],
            "functionData2":[]}
        for p in pac:
            if (p.haslayer("TCP") and p[self.layer].sport == self.PORT ):
                field_value = getattr(p[self.layer], self.field)
                hex_val = binascii.hexlify(field_value)
                w = len(hex_val)
                #print(hex_val,w,(21-w%21))
                if(w<21):
                    hex_val = hex_val + (21-w%21)*b'0'
                else:
                    continue
                #print(hex_val)
                fields_dic["transID1"].append(int(hex_val[:2],16))
                fields_dic["transID2"].append(int(hex_val[2:4],16))
                fields_dic["protoID1"].append(int(hex_val[4:6],16))
                fields_dic["protoID2"].append(int(hex_val[6:8],16))
                fields_dic["length1"].append(int(hex_val[8:10],16))
                fields_dic["length2"].append(int(hex_val[10:12],16))
                fields_dic["unitID"].append(int(hex_val[12:14],16))
                fields_dic["functionCode"].append(int(hex_val[14:16],16))
                fields_dic["functionData1"].append(int(hex_val[16:20],16))
                fields_dic["functionData2"].append(int(hex_val[20:],16))
            '''c=c+1
            print("read ",c)
            if(c==10):
                return fields_dic'''
        self.logger.debug('[+] Extracted fields')
        return fields_dic

    
    def generate_fields(self):
        try:
            pac1 = rdpcap(self.input)
        except Exception as e:
            self.logger.error(e)
            self.logger.warning('[*] Unable to read the file') 
            return False

        self.logger.debug('[+] Read file: ' + self.input)
        return self.extract_load(pac1)
        #print(extracted_fields)

'''
{'transaction_id': [b'0796', b'0796', b'7a18', b'7a18', b'2d04', b'2d04'], 'proc_id': [b'0000', b'0000', b'0000', b'0000', b'0000', b'0000'], 'length': [b'001d', b'001d', b'0005', b'0005', b'001d', b'001d'], 'Unit_id': [b'01', b'01', b'', b'', b'01', b'01'], 'func_code': [b'03', b'03', b'', b'', b'03', b'03'], 'count': [b'1a', b'1a', b'', b'', b'1a', b'1a'], 'reg_values': [b'001c000000590000001e00010059000000000000138800001388', b'001c000000590000001e00010059000000000000138800001388', b'', b'', b'00180000005a0000001500000059000000000000138800001388', b'00180000005a0000001500000059000000000000138800001388']}
'''


