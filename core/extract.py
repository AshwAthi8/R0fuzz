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
        fields_dic = {"transaction_id":[],
            "proc_id":[],
            "length1":[],
            "length2";[],
            "Unit_id":[],
            "func_code":[],
            "funcdata1":[],
            "funcdata2":[]}
        for p in pac:
            if (p.haslayer("TCP") and p[self.layer].sport == self.PORT ):
                field_value = getattr(p[self.layer], self.field)
                hex_val = binascii.hexlify(field_value)
                fields_dic["transaction_id"].append(hex_val[:4])
                fields_dic["proc_id"].append(hex_val[4:8])
                fields_dic["length1"].append(hex_val[8:10])
                fields_dic["length2"].append(hex_val[10:12])
                fields_dic["Unit_id"].append(hex_val[12:14])
                fields_dic["func_code"].append(hex_val[14:16])
                fields_dic["funcdata1"].append(hex_val[16:20])
                fields_dic["funcdata2"].append(hex_val[20:])
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


