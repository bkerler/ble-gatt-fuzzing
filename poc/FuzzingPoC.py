from scapy.layers.bluetooth import *
from scapy.layers.bluetooth4LE import *
import scapy

import random

def mutator(ATT_type):
    """ mutator() forges the random PDU"""

    if ATT_type == "Request":

        rand_att_func = random.choice(list(att_request_dict.values()))   # Choose a Request ATT primitive to be sent

    pdu_payload,length = mutate_fill_payload(rand_att_func)              # Forge the PDU payload

    pdu_header  = BTLE_DATA()/L2CAP_Hdr(len=length,cid=0x0004)/ATT_Hdr() # Forge the PDU header

    return pdu_header/pdu_payload                                        # Forge the PDU

def mutate_fill_payload(att_proc):
    """ mutate_fill_payload(att_proc) fill and return the ATT primitive"""

    match att_proc:

            ################################
            #  ATT_Exchange_MTU_Request    #
            ################################

        case scapy.layers.bluetooth.ATT_Exchange_MTU_Request:

            _mtu = random.randint(0,512)

            return ATT_Exchange_MTU_Request(mtu = _mtu) , 3

            ################################
            #  ATT_Execute_Write_Request   #
            ################################

        case scapy.layers.bluetooth.ATT_Execute_Write_Request:

            _flags = random.randint(0,255)

            return ATT_Execute_Write_Request(flags = _flags) , 2

            #####################################
            #  ATT_Find_By_Type_Value_Request   #
            #####################################

        case scapy.layers.bluetooth.ATT_Find_By_Type_Value_Request:

            _start = random.randint(0,65534)
            _end   = random.randint(_start,65535)
            _uuid  = random.randint(0,65535)
            n      = random.randint(0,80)
            _data  = random.randbytes(n)

            return ATT_Find_By_Type_Value_Request(start = _start,
                                                  end   = _end,
                                                  uuid  = _uuid,
                                                  data  = _data) , 7 + n

            ###################################
            #  ATT_Find_Information_Request   #
            ###################################

        case scapy.layers.bluetooth.ATT_Find_Information_Request:

            _start = random.randint(0,65534)
            _end   = random.randint(_start,65535)
            return ATT_Find_Information_Request(start = _start,
                                                end   = _end) , 5

            ################################
            #  ATT_Prepare_Write_Request   #
            ################################

        case scapy.layers.bluetooth.ATT_Prepare_Write_Request:

            _gatt_handle = random.choice(range(0x01,0x16))
            _offset      = random.randint(0,65535)
            n            = random.randint(0,80)
            _data        = random.randbytes(n)

            return ATT_Prepare_Write_Request(gatt_handle = _gatt_handle,
                                             offset      = _offset,
                                             data        = _data) , 5 + n

            #############################
            #  ATT_Read_Blob_Request    #
            #############################

        case scapy.layers.bluetooth.ATT_Read_Blob_Request:

            _gatt_handle = random.choice(range(0x01,0x16))
            _offset      = random.randint(0,65535)

            return ATT_Read_Blob_Request(gatt_handle = _gatt_handle,
                                         offset      = _offset) , 5

            #######################################
            #  ATT_Read_By_Group_Type_Request     #
            #######################################

        case scapy.layers.bluetooth.ATT_Read_By_Group_Type_Request:

            _start = random.randint(0,65534)
            _end   = random.randint(_start,65535)
            _uuid  = random.randint(0,65535)

            return ATT_Read_By_Group_Type_Request(start = _start,
                                                  end   = _end,
                                                  uuid  = _uuid) , 7

            ################################
            #  ATT_Read_By_Type_Request    #
            ################################

        case scapy.layers.bluetooth.ATT_Read_By_Type_Request:

            _start = random.randint(0,65534)
            _end   = random.randint(_start,65535)
            _uuid  = random.randint(0,65535)

            return ATT_Read_By_Type_Request(start = _start,
                                            end  = _end,
                                            uuid = _uuid) , 7

            #######################################
            #  ATT_Read_By_Type_Request_128bit    #
            #######################################

        case scapy.layers.bluetooth.ATT_Read_By_Type_Request_128bit:

            _start = random.randint(0,65534)
            _end   = random.randint(_start,65535)
            _uuid1 = int.from_bytes(random.randbytes(8))
            _uuid2 = int.from_bytes(random.randbytes(8))

            return ATT_Read_By_Type_Request_128bit(start = _start,
                                                   end   = _end,
                                                   uuid1 = _uuid1,
                                                   uuid2 = _uuid2) , 21

            ################################
            #  ATT_Read_Multiple_Request   #
            ################################

        case scapy.layers.bluetooth.ATT_Read_Multiple_Request:

            n        = 20
            _handles = [random.randint(0,65535) for _ in range(n)]

            return ATT_Read_Multiple_Request(handles = _handles) , 1 + 2*n

            ######################
            #  ATT_Read_Request  #
            ######################

        case scapy.layers.bluetooth.ATT_Read_Request:

            _gatt_handle =  random.choice(range(0x01,0x16))

            return ATT_Read_Request(gatt_handle = _gatt_handle) , 3

            ######################
            # ATT_Write_Request  #
            ######################

        case scapy.layers.bluetooth.ATT_Write_Request:

            _gatt_handle =  random.choice(range(0x01,0x16))
            n            = random.randint(0,80)
            _data        = random.randbytes(n)

            return ATT_Write_Request(gatt_handle = _gatt_handle,
                                     data        = _data) , 3 + n


att_request_dict = {# ATT Request
                    'ATT_Exchange_MTU_Request': ATT_Exchange_MTU_Request,
                    'ATT_Find_By_Type_Value_Request': ATT_Find_By_Type_Value_Request,
                    'ATT_Find_Information_Request': ATT_Find_Information_Request,
                    'ATT_Read_Blob_Request': ATT_Read_Blob_Request,
                    'ATT_Read_By_Group_Type_Request': ATT_Read_By_Group_Type_Request,
                    'ATT_Read_By_Type_Request': ATT_Read_By_Type_Request,
                    'ATT_Read_By_Type_Request_128bit': ATT_Read_By_Type_Request_128bit,
                    'ATT_Read_Multiple_Request': ATT_Read_Multiple_Request,
                    'ATT_Read_Request': ATT_Read_Request,
                    'ATT_Write_Request': ATT_Write_Request,
                }


