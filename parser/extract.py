from scapy.all import *
import binascii
#needed pcap
pac1 = rdpcap('ics.pcapng')
print("-----------read completed---------")
layer = "TCP"
field = "load"
PORT = 502
fields_dic = {"transaction_id":[],
            "proc_id":[],
            "length":[],
            "Unit_id":[],
            "func_code":[],
            "count":[],
            "reg_values":[]}

def extract_load(pac):
    c = 0
    for p in pac:
        if(p.haslayer("TCP") and p[layer].sport == PORT ):
            field_value = getattr(p[layer], field)
            hex_val = binascii.hexlify(field_value)
            fields_dic["transaction_id"].append(hex_val[:4])
            fields_dic["proc_id"].append(hex_val[4:8])
            fields_dic["length"].append(hex_val[8:12])
            fields_dic["Unit_id"].append(hex_val[12:14])
            fields_dic["func_code"].append(hex_val[14:16])
            fields_dic["count"].append(hex_val[16:18])
            fields_dic["reg_values"].append(hex_val[18:])
        #c=c+1
        #print("read ",c)
        #if(c==10):
        #    return fields_dic
    return fields_dic

print(extract_load(pac1))

'''
{'transaction_id': [b'0796', b'0796', b'7a18', b'7a18', b'2d04', b'2d04'], 'proc_id': [b'0000', b'0000', b'0000', b'0000', b'0000', b'0000'], 'length': [b'001d', b'001d', b'0005', b'0005', b'001d', b'001d'], 'Unit_id': [b'01', b'01', b'', b'', b'01', b'01'], 'func_code': [b'03', b'03', b'', b'', b'03', b'03'], 'count': [b'1a', b'1a', b'', b'', b'1a', b'1a'], 'reg_values': [b'001c000000590000001e00010059000000000000138800001388', b'001c000000590000001e00010059000000000000138800001388', b'', b'', b'00180000005a0000001500000059000000000000138800001388', b'00180000005a0000001500000059000000000000138800001388']}
'''


