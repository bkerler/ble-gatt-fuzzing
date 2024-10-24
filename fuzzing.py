from scapy.layers.bluetooth import *
from scapy.layers.bluetooth4LE import *
import scapy

import random
import time
from datetime import datetime

from whad.ble import Central, Peripheral

from scenario import Scenario

def mutator(ATT_pdu_type: str, gatt_handle: list[int]) -> tuple[Packet,Packet]:
    """Forge the requested type of PDU.
    """

    if ATT_pdu_type == "Random":
        ATT_pdu = random.choice(list(att_dict.values()))                  # Choose an ATT primitive to be sent

    elif ATT_pdu_type == "Request":
        ATT_pdu = random.choice(list(att_request_dict.values()))          # Choose a Request ATT primitive to be sent

    elif ATT_pdu_type == "Response":
        ATT_pdu = random.choice(list(att_response_dict.values()))         # Choose a Request ATT primitive to be sent

    elif ATT_pdu_type == "PDUs_with_no_response":
        ATT_pdu = random.choice(list(att_no_response_dict.values()))      # Choose a Request ATT primitive to be sent

    elif ATT_pdu_type == "Prepare_Write_Request":
        ATT_pdu = ATT_Prepare_Write_Request                               # Choose ATT_Prepare_Write_Request primitive to be sent

    elif ATT_pdu_type == "Execute_Write_Request":
        ATT_pdu = ATT_Prepare_Write_Request                               # Choose ATT_Prepare_Write_Request primitive to be sent

    elif ATT_pdu_type == "Request_No_MTU":
        ATT_pdu = random.choice(list(att_request_dict_no_mtu.values()))   # Choose a Request ATT primitive to be sent

    pdu_payload, length = mutate_fill_payload(ATT_pdu, gatt_handle)       # Forge the PDU payload

    pdu_header  = BTLE_DATA()/L2CAP_Hdr(len=length,cid=0x0004)/ATT_Hdr()  # Forge the PDU header

    return pdu_header/pdu_payload, ATT_pdu                                # Forge and return the PDU and the PDU method

def mutate_fill_payload(ATT_pdu: Packet, gatt_handle: list[int]) -> tuple[Packet,int]:
    """Fill and return the ATT primitive and its length.
    """

    match ATT_pdu:

            ##########################
            #  ATT_Error_Response    #
            ##########################

        case scapy.layers.bluetooth.ATT_Error_Response:
            
            _request = random.randint(0,255)
            _handle  = random.choice(gatt_handle)
            _ecode   = random.randint(0,255)

            errorcodes = [i for i in range(256)]
            weights    = [0.2] * 18 + [0.01] * 238
            _ecode     = random.choices(errorcodes,weights) 

            return ATT_Error_Response(request = _request,
                                      handle  = _handle,
                                      ecode   = _ecode) , 5

            ################################
            #  ATT_Exchange_MTU_Request    #
            ################################

        case scapy.layers.bluetooth.ATT_Exchange_MTU_Request:

            _mtu = random.randint(0,512)

            return ATT_Exchange_MTU_Request(mtu = _mtu) , 3

            ################################
            #  ATT_Exchange_MTU_Response   #
            ################################

        case scapy.layers.bluetooth.ATT_Exchange_MTU_Response:

            _mtu = random.randint(0,512)

            return ATT_Exchange_MTU_Response(mtu = _mtu) ,3

            ################################
            #  ATT_Execute_Write_Request   #
            ################################

        case scapy.layers.bluetooth.ATT_Execute_Write_Request:

            _flags = random.choices([0,1,random.randint(2,255)], weights=(30,30,40))

            return ATT_Execute_Write_Request(flags = _flags) , 2

            #################################
            #  ATT_Execute_Write_Response   #
            #################################

        case scapy.layers.bluetooth.ATT_Execute_Write_Response:

            return ATT_Execute_Write_Response() , 1

            #####################################
            #  ATT_Find_By_Type_Value_Request   #
            #####################################

        case scapy.layers.bluetooth.ATT_Find_By_Type_Value_Request:

            _end   = random.choice(range(1,gatt_handle[-1]))
            _start = random.randint(0,_end)
            _uuid  = random.randint(0,65535)
            n      = random.randint(0,80)
            _data  = random.randbytes(n)

            return ATT_Find_By_Type_Value_Request(start = _start,
                                                  end   = _end,
                                                  uuid  = _uuid,
                                                  data  = _data) , 7 + n

            #####################################
            #  ATT_Find_By_Type_Value_Response  #
            #####################################

        case scapy.layers.bluetooth.ATT_Find_By_Type_Value_Response:

            n        = random.randint(0,20)
            _handles = [ATT_Handle(handle=random.randint(0,65535),value=random.randint(0,65535)) for _ in range(n)]

            return ATT_Find_By_Type_Value_Response(handles = _handles), 1 + 4*n

            ###################################
            #  ATT_Find_Information_Request   #
            ###################################

        case scapy.layers.bluetooth.ATT_Find_Information_Request:

            _end   = random.choice(range(1,gatt_handle[-1]))
            _start = random.randint(0,_end)
            return ATT_Find_Information_Request(start = _start,
                                                end   = _end) , 5

            ###################################
            #  ATT_Find_Information_Response  #
            ###################################

        case scapy.layers.bluetooth.ATT_Find_Information_Response:

            _format = random.choices([0,1,random.randint(2,255)], weights=(30,30,40))
            n = random.randint(1,13)
            rand_var = random.randint(0,1)

            if rand_var == 0:

                _handles = [ATT_Handle(handle=random.randint(0,65535),value=random.randint(0,65535)) for _ in range(n)]
                length   = 4 * n

            else :

                _handles = [ATT_Handle_UUID128(handle=random.randint(0,65535),value=random.randint(0,340282366920938463463374607431768211455)) for _ in range(n)]
                length   = 18 * n

            return ATT_Find_Information_Response(format  = _format,
                                                 handles = _handles) , 2 + length

            ###################################
            #  ATT_Handle_Value_Indication    #
            ###################################

        case scapy.layers.bluetooth.ATT_Handle_Value_Indication:

            _gatt_handle = random.choice(gatt_handle)
            n            = random.randint(0,80)
            _value       = random.randbytes(n)

            return ATT_Handle_Value_Indication(gatt_handle = _gatt_handle,
                                               value       = _value) , 3 + n

            ###################################
            #  ATT_Handle_Value_Notification  #
            ###################################

        case scapy.layers.bluetooth.ATT_Handle_Value_Notification:

            _gatt_handle = random.choice(gatt_handle)
            n            = random.randint(0,80)
            _value       = random.randbytes(n)

            return ATT_Handle_Value_Notification(gatt_handle = _gatt_handle,
                                                 value       = _value) , 3 + n

            ################################
            #  ATT_Prepare_Write_Request   #
            ################################

        case scapy.layers.bluetooth.ATT_Prepare_Write_Request:

            _gatt_handle = random.choice(gatt_handle)
            _offset      = random.randint(0,65535)
            n            = random.randint(0,80)
            _data        = random.randbytes(n)

            return ATT_Prepare_Write_Request(gatt_handle = _gatt_handle,
                                             offset      = _offset,
                                             data        = _data) , 5 + n

            ################################
            #  ATT_Prepare_Write_Response  #
            ################################

        case scapy.layers.bluetooth.ATT_Prepare_Write_Response:

            _gatt_handle = random.choice(gatt_handle)
            _offset      = random.randint(0,65535)
            n            = random.randint(0,80)
            _data        = random.randbytes(n)

            return ATT_Prepare_Write_Response(gatt_handle = _gatt_handle,
                                              offset      = _offset,
                                              data        = _data) , 5 + n

            #############################
            #  ATT_Read_Blob_Request    #
            #############################

        case scapy.layers.bluetooth.ATT_Read_Blob_Request:

            _gatt_handle = random.choice(gatt_handle)
            _offset      = random.randint(0,65535)

            return ATT_Read_Blob_Request(gatt_handle = _gatt_handle,
                                         offset      = _offset) , 5

            #############################
            #  ATT_Read_Blob_Response   #
            #############################

        case scapy.layers.bluetooth.ATT_Read_Blob_Response:

            n      = random.randint(0,80)
            _value = random.randbytes(n)

            return ATT_Read_Blob_Response(value = _value) , 1 + n

            #######################################
            #  ATT_Read_By_Group_Type_Request     #
            #######################################

        case scapy.layers.bluetooth.ATT_Read_By_Group_Type_Request:

            _end   = random.choice(range(1,gatt_handle[-1]))
            _start = random.randint(0,_end)
            _uuid  = random.randint(0,65535)

            return ATT_Read_By_Group_Type_Request(start = _start,
                                                  end   = _end,
                                                  uuid  = _uuid) , 7

            #######################################
            #  ATT_Read_By_Group_Type_Response    #
            #######################################

        case scapy.layers.bluetooth.ATT_Read_By_Group_Type_Response:

            _length = random.randint(0,255)
            n       = random.randint(0,80)
            _data   = random.randbytes(n)

            return ATT_Read_By_Group_Type_Response(length = _length,
                                                   data   = _data) , n + 2

            ################################
            #  ATT_Read_By_Type_Request    #
            ################################

        case scapy.layers.bluetooth.ATT_Read_By_Type_Request:

            _end   = random.choice(range(1,gatt_handle[-1]))
            _start = random.randint(0,_end)
            _uuid  = random.randint(0,65535)

            return ATT_Read_By_Type_Request(start = _start,
                                            end  = _end,
                                            uuid = _uuid) , 7

            #######################################
            #  ATT_Read_By_Type_Request_128bit    #
            #######################################

        case scapy.layers.bluetooth.ATT_Read_By_Type_Request_128bit:

            _end   = random.choice(range(1,gatt_handle[-1]))
            _start = random.randint(0,_end)
            _uuid1 = int.from_bytes(random.randbytes(8))
            _uuid2 = int.from_bytes(random.randbytes(8))

            return ATT_Read_By_Type_Request_128bit(start = _start,
                                                   end   = _end,
                                                   uuid1 = _uuid1,
                                                   uuid2 = _uuid2) , 21

            ################################
            #  ATT_Read_By_Type_Response   #
            ################################

        case scapy.layers.bluetooth.ATT_Read_By_Type_Response:

            _len     = random.randint(0,255)
            n        = random.randint(1,10)
            _handles = [ATT_Handle(handle=random.choice(gatt_handle),value=random.randint(0,2**(8*2))) for _ in range(n)]

            return ATT_Read_By_Type_Response(len     = _len,
                                             handles = _handles) , 2 + n * _len

            ################################
            #  ATT_Read_Multiple_Request   #
            ################################

        case scapy.layers.bluetooth.ATT_Read_Multiple_Request:

            n        = random.randint(0,20) # 20 is a Random taken value 
            _handles = [random.choice(gatt_handle) for _ in range(n)]

            return ATT_Read_Multiple_Request(handles = _handles) , 1 + 2*n

            ################################
            #  ATT_Read_Multiple_Response  #
            ################################

        case scapy.layers.bluetooth.ATT_Read_Multiple_Response:

            n       = random.randint(0,80)
            _values = random.randbytes(n)

            return ATT_Read_Multiple_Response(values = _values) , 1 + n

            ######################
            #  ATT_Read_Request  #
            ######################

        case scapy.layers.bluetooth.ATT_Read_Request:
                
            _gatt_handle = random.choice(gatt_handle)

            return ATT_Read_Request(gatt_handle = _gatt_handle) , 3

            ######################
            # ATT_Read_Response  #
            ######################

        case scapy.layers.bluetooth.ATT_Read_Response:

            n      = random.randint(0,80)
            _value = random.randbytes(n)

            return ATT_Read_Response(value = _value) , 1 + n

            ######################
            # ATT_Write_Command  #
            ######################

        case scapy.layers.bluetooth.ATT_Write_Command:

            _gatt_handle = random.choice(gatt_handle)
            n            = random.randint(0,80)
            _data        = random.randbytes(n)

            return ATT_Write_Command(gatt_handle = _gatt_handle,
                                     data        = _data) , 3 + n

            ######################
            # ATT_Write_Request  #
            ######################

        case scapy.layers.bluetooth.ATT_Write_Request:

            _gatt_handle = random.choice(gatt_handle)
            n            = random.randint(0,80)
            _data        = random.randbytes(n)

            return ATT_Write_Request(gatt_handle = _gatt_handle,
                                     data        = _data) , 3 + n

            ######################
            # ATT_Write_Response # 
            ######################

        case scapy.layers.bluetooth.ATT_Write_Response:

            return ATT_Write_Response() , 1

def expected_response(ATT: Packet) -> Packet:
    """ Maps the corresponding expected return value to the input ATT.
    """

    match ATT:

            ################################
            #  ATT_Exchange_MTU_Request    #
            ################################

        case scapy.layers.bluetooth.ATT_Exchange_MTU_Request:

            return scapy.layers.bluetooth.ATT_Exchange_MTU_Response

            ################################
            #  ATT_Execute_Write_Request   #
            ################################

        case scapy.layers.bluetooth.ATT_Execute_Write_Request:

            return  scapy.layers.bluetooth.ATT_Execute_Write_Response

            #####################################
            #  ATT_Find_By_Type_Value_Request   #
            #####################################

        case scapy.layers.bluetooth.ATT_Find_By_Type_Value_Request:

            return scapy.layers.bluetooth.ATT_Find_By_Type_Value_Response

            ###################################
            #  ATT_Find_Information_Request   #
            ###################################

        case scapy.layers.bluetooth.ATT_Find_Information_Request:

            return scapy.layers.bluetooth.ATT_Find_Information_Response

            ################################
            #  ATT_Prepare_Write_Request   #
            ################################

        case scapy.layers.bluetooth.ATT_Prepare_Write_Request:

            return scapy.layers.bluetooth.ATT_Prepare_Write_Response

            #############################
            #  ATT_Read_Blob_Request    #
            #############################

        case scapy.layers.bluetooth.ATT_Read_Blob_Request:

            return scapy.layers.bluetooth.ATT_Read_Blob_Response

            #######################################
            #  ATT_Read_By_Group_Type_Request     #
            #######################################

        case scapy.layers.bluetooth.ATT_Read_By_Group_Type_Request:

            return scapy.layers.bluetooth.ATT_Read_By_Group_Type_Response

            ################################
            #  ATT_Read_By_Type_Request    #
            ################################

        case scapy.layers.bluetooth.ATT_Read_By_Type_Request:

            return scapy.layers.bluetooth.ATT_Read_By_Type_Response

            ######################################
            #  ATT_Read_By_Type_Request_128bit   #
            ######################################

        case scapy.layers.bluetooth.ATT_Read_By_Type_Request_128bit:

            return scapy.layers.bluetooth.ATT_Read_By_Type_Response

            ################################
            #  ATT_Read_Multiple_Request   #
            ################################

        case scapy.layers.bluetooth.ATT_Read_Multiple_Request:

            return scapy.layers.bluetooth.ATT_Read_Multiple_Response

            ######################
            #  ATT_Read_Request  #
            ######################

        case scapy.layers.bluetooth.ATT_Read_Request:

            return scapy.layers.bluetooth.ATT_Read_Response

            ######################
            # ATT_Write_Request  #
            ######################

        case scapy.layers.bluetooth.ATT_Write_Request:

            return scapy.layers.bluetooth.ATT_Write_Response

            ################################
            # ATT_Handle_Value_Indication  #
            ################################

        case scapy.layers.bluetooth.ATT_Handle_Value_Indication:

            return scapy.layers.bluetooth.ATT_Handle_Value_Notification     # Base on experimentation because there is no 
                                                                            # ATT_Handle_Value_Confirmation opcode 0x1e in scapy
            ################################
            # ATT_Any_Response  #
            ################################

        case _:
            return None

def check_expected_get(pdu: Packet, expected_resp: Packet,  role: Central|Peripheral, time_stamp: float, test_case_folder: str, scenario: Scenario) -> bool:
    """Compare the received pdu to the expected one.
    """
    if pdu != None:

        pdu.show()
        scenario.none_cnt = 0

        if pdu.LLID == 2: #10b = LL DATA PDU : Start of an L2CAP message or a complete L2CAP msg with no frag

            if pdu.layers()[2] == ATT_Hdr :

                if pdu.opcode == 0x13 :
                    get_resp = scapy.layers.bluetooth.ATT_Write_Response
                    write_trace_att_rsp(test_case_folder, time_stamp, "ATT_Write_Reponse")

                elif pdu.opcode == 0x1e :
                    get_resp = scapy.layers.bluetooth.ATT_Handle_Value_Notification
                    write_trace_att_rsp(test_case_folder, time_stamp, "ATT_Handle_Value_Notification")

                elif pdu.opcode == 0x19 :
                    get_resp = scapy.layers.bluetooth.ATT_Execute_Write_Response
                    write_trace_att_rsp(test_case_folder, time_stamp, "ATT_Execute_Write_Response")

                else:
                    get_resp = pdu.layers()[3]
                    write_trace_att_rsp(test_case_folder, time_stamp, pdu[3].show(dump=True))

                if get_resp != expected_resp and get_resp != scapy.layers.bluetooth.ATT_Error_Response:
                    print('DIFFERENT PDU : Expected = %s and Get = %s'%(expected_resp, get_resp))
                    #return True

            else :  # if L2CAP PDU, get next PDU 

                pdu_new = role.wait_packet(timeout=1)
                time_stamp = time.time()
                check_expected_get(pdu_new, expected_resp, role, time_stamp, test_case_folder, scenario)

        else: #if fragmented packet, get next PDU

            pdu_new = role.wait_packet(timeout=1)
            time_stamp = time.time()
            check_expected_get(pdu_new, expected_resp, role, time_stamp, test_case_folder, scenario)

    else:
        scenario.none_cnt = scenario.none_cnt + 1
        print("none_cnt:",scenario.none_cnt)
        if scenario.none_cnt == scenario.MAX_NONE_CNT:
            print("MAX_NONE_CNT reached")
            return True

def write_trace_att_rsp(test_case_folder: str, time_stamp: float, att_rsp: str):
    """Write ATT_Response PDU in text file.
    """
    f = open(test_case_folder + "/trace.txt","a")
    f.write("RECEIVED ATT PDU =\n")
    f.write(att_rsp)
    f.write("\n")
    f.write("timestamp PDU = ")
    f.write(str(datetime.fromtimestamp(time_stamp))+"\n")
    f.write("\n")
    f.close()

att_dict = {# ATT
            'ATT_Error_Response': ATT_Error_Response,
            'ATT_Exchange_MTU_Request': ATT_Exchange_MTU_Request,
            'ATT_Exchange_MTU_Response': ATT_Exchange_MTU_Response,
            'ATT_Execute_Write_Request': ATT_Execute_Write_Request,
            'ATT_Execute_Write_Response':  ATT_Execute_Write_Response,
            'ATT_Find_By_Type_Value_Request': ATT_Find_By_Type_Value_Request,
            'ATT_Find_By_Type_Value_Response': ATT_Find_By_Type_Value_Response,
            'ATT_Find_Information_Request': ATT_Find_Information_Request,
            #'ATT_Find_Information_Response': ATT_Find_Information_Response,
            'ATT_Handle_Value_Indication': ATT_Handle_Value_Indication,
            'ATT_Handle_Value_Notification': ATT_Handle_Value_Notification,
            'ATT_Prepare_Write_Request': ATT_Prepare_Write_Request,
            'ATT_Prepare_Write_Response': ATT_Prepare_Write_Response,
            'ATT_Read_Blob_Request': ATT_Read_Blob_Request,
            'ATT_Read_Blob_Response': ATT_Read_Blob_Response,
            'ATT_Read_By_Group_Type_Request': ATT_Read_By_Group_Type_Request,
            'ATT_Read_By_Group_Type_Response': ATT_Read_By_Group_Type_Response,
            'ATT_Read_By_Type_Request_128bit': ATT_Read_By_Type_Request_128bit,
            'ATT_Read_By_Type_Request': ATT_Read_By_Type_Request,
            #'ATT_Read_By_Type_Response': ATT_Read_By_Type_Response,
            'ATT_Read_Multiple_Request': ATT_Read_Multiple_Request,
            'ATT_Read_Multiple_Response': ATT_Read_Multiple_Response,
            'ATT_Read_Request': ATT_Read_Request,
            'ATT_Read_Response': ATT_Read_Response,
            'ATT_Write_Command': ATT_Write_Command,
            'ATT_Write_Request': ATT_Write_Request,
            'ATT_Write_Response': ATT_Write_Response,
            }

att_request_dict = {# ATT Request
                    'ATT_Exchange_MTU_Request': ATT_Exchange_MTU_Request,
                    'ATT_Execute_Write_Request': ATT_Execute_Write_Request,
                    'ATT_Find_By_Type_Value_Request': ATT_Find_By_Type_Value_Request,
                    'ATT_Find_Information_Request': ATT_Find_Information_Request,
                    'ATT_Prepare_Write_Request': ATT_Prepare_Write_Request,
                    'ATT_Read_Blob_Request': ATT_Read_Blob_Request,
                    'ATT_Read_By_Group_Type_Request': ATT_Read_By_Group_Type_Request,
                    'ATT_Read_By_Type_Request': ATT_Read_By_Type_Request,
                    'ATT_Read_By_Type_Request_128bit': ATT_Read_By_Type_Request_128bit,
                    'ATT_Read_Multiple_Request': ATT_Read_Multiple_Request,
                    'ATT_Read_Request': ATT_Read_Request,
                    'ATT_Write_Request': ATT_Write_Request,
                    }

att_response_dict = {# ATT Response
                    'ATT_Error_Response': ATT_Error_Response,
                    'ATT_Exchange_MTU_Response': ATT_Exchange_MTU_Response,
                    'ATT_Execute_Write_Response':  ATT_Execute_Write_Response,
                    'ATT_Find_By_Type_Value_Response': ATT_Find_By_Type_Value_Response,
                    #'ATT_Find_Information_Response': ATT_Find_Information_Response,
                    'ATT_Prepare_Write_Response': ATT_Prepare_Write_Response,
                    'ATT_Read_Blob_Response': ATT_Read_Blob_Response,
                    'ATT_Read_By_Group_Type_Response': ATT_Read_By_Group_Type_Response,
                    #'ATT_Read_By_Type_Response': ATT_Read_By_Type_Response,
                    'ATT_Read_Multiple_Response': ATT_Read_Multiple_Response,
                    'ATT_Read_Response': ATT_Read_Response,
                    'ATT_Write_Response': ATT_Write_Response,
                    }

att_no_response_dict = {# ATT with no response
                        'ATT_Handle_Value_Notification': ATT_Handle_Value_Notification,
                        #'ATT_Multiple_Handle_Value_Notification': ATT_Multiple_Handle_Value_Notification, #Spec v5
                        'ATT_Write_Command': ATT_Write_Command,
                        #'ATT_Signed_Write_Command': ATT_Signed_Command, #Spec v4.2 but not in scapy
                        }

att_request_dict_no_mtu = {# ATT Request
                    'ATT_Execute_Write_Request': ATT_Execute_Write_Request,
                    'ATT_Find_By_Type_Value_Request': ATT_Find_By_Type_Value_Request,
                    'ATT_Find_Information_Request': ATT_Find_Information_Request,
                    'ATT_Prepare_Write_Request': ATT_Prepare_Write_Request,
                    'ATT_Read_Blob_Request': ATT_Read_Blob_Request,
                    'ATT_Read_By_Group_Type_Request': ATT_Read_By_Group_Type_Request,
                    'ATT_Read_By_Type_Request': ATT_Read_By_Type_Request,
                    'ATT_Read_By_Type_Request_128bit': ATT_Read_By_Type_Request_128bit,
                    'ATT_Read_Multiple_Request': ATT_Read_Multiple_Request,
                    'ATT_Read_Request': ATT_Read_Request,
                    'ATT_Write_Request': ATT_Write_Request,
                    }