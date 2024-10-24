from scapy.layers.bluetooth import *
from scapy.layers.bluetooth4LE import *

import os
import time
import fuzzing as Fuzz
import pip._vendor.requests as requests

from whad.ble import Central, PeripheralClient

from scenario import Scenario

class Scenario3Client(Scenario):
    """Scenario 3 Client side

    Send many Prepare_Write_Request.
    """

    def __init__(self):
        super().__init__()

    def run(self, central: Central, bt_addr: str, is_addr_random: bool, post_url: str, gatt_handle: list[int]):
        """Run the fuzzing scenario #3.
        """
        os.mkdir(self.current_log_case)
        monitor_main = self.create_monitor(central,"log")

        print("\nNew connection")
        central.connect(bt_addr, random=is_addr_random)
        central.enable_synchronous(True)

        try :
            for _ in range(self.PREPARE_WRITE_REQUEST_NUMBER):

                os.mkdir(self.test_case_folder)
                self.write_associated_pkts_number(monitor_main, "start")
                monitor_trace = self.create_monitor(central, "trace")

                my_pdu, ATT_layer = Fuzz.mutator("Prepare_Write_Request", gatt_handle) # Craft a Prepare_Write_Request pdu
                expected_resp = Fuzz.expected_response(ATT_layer)                      # Get expected response if request

                central.send_pdu(pdu = my_pdu, conn_handle=central.connection.conn_handle) # Send PDU
                time_stamp_my_pdu = time.time()

                self.write_trace(my_pdu, time_stamp_my_pdu)

                received_pdu = central.wait_packet(timeout=1) # Receive what is supposed to be the PDU response
                time_stamp_received_pdu = time.time()

                if Fuzz.check_expected_get(received_pdu, expected_resp, central, time_stamp_received_pdu, self.test_case_folder, self):

                        requests.post(post_url, data=f"Device doesn't respond anymore (none_cnt > {self.MAX_NONE_CNT})".encode(encoding='utf-8'))
                        self.restart(monitor_main, monitor_trace)

                        break

                monitor_trace.stop()
                monitor_trace.close()

                self.write_associated_pkts_number(monitor_main, "end")

                self.case_cnt += 1

            pdu_exec = BTLE_DATA()/L2CAP_Hdr(len=2,cid=0x0004)/ATT_Hdr()/ATT_Execute_Write_Request(flags = 0x01)
            central.send_pdu(pdu = pdu_exec,conn_handle=central.connection.conn_handle)

            # Send multiple Requests to observe the behavior of the server
            # after receiving numerous Prepare Write Request.
            for _ in range(20):
                my_pdu, ATT_layer = Fuzz.mutator("Request", gatt_handle) # Craft a Request pdu
                central.send_pdu(pdu = my_pdu, conn_handle=central.connection.conn_handle) # Send PDU

        except ImportError as IE: # ImportError
            self.TreatError(IE, post_url, monitor_main, monitor_trace, self.ERROR_MSG_IE)

        except Exception as error: # Catch ConnectionLostException for instance
                self.TreatError(error, post_url, monitor_main, monitor_trace, self.ERROR_MSG)

        if not(self.error_occured):
            self.restart(monitor_main, None)
        else:
            self.error_occured = False


class Scenario3Server(Scenario):
    """Scenario 3 Server side

    Send many Prepare_Write_Request.
    """
    def __init__(self):
        super().__init__()

    def run(self, periph: PeripheralClient, post_url: str, gatt_handle: list[int]):
        """Run the fuzzing scenario #3."""
        os.mkdir(self.current_log_case)
        monitor_main = self.create_monitor(periph,"log")

        periph.enable_synchronous(True)

        while periph.is_connected():

            try :
                for _ in range(self.PREPARE_WRITE_REQUEST_NUMBER):

                    os.mkdir(self.test_case_folder)
                    self.write_associated_pkts_number(monitor_main, "start")
                    monitor_trace = self.create_monitor(periph, "trace")

                    my_pdu, ATT_layer = Fuzz.mutator("Prepare_Write_Request", gatt_handle) # Craft a Prepare_Write_Request pdu
                    expected_resp = Fuzz.expected_response(ATT_layer)

                    periph.send_data_pdu(pdu = my_pdu, conn_handle=periph.connection.conn_handle) # Send PDU #1
                    time_stamp_my_pdu = time.time()

                    self.write_trace(my_pdu, time_stamp_my_pdu)

                    received_pdu = periph.wait_packet(timeout=1) # Receive what is supposed to be the PDU response
                    time_stamp_received_pdu = time.time()

                    if Fuzz.check_expected_get(received_pdu, expected_resp, periph, time_stamp_received_pdu, self.test_case_folder, self):

                        requests.post(post_url, data=f"Device doesn't respond anymore (none_cnt > {self.MAX_NONE_CNT})".encode(encoding='utf-8'))
                        self.restart(monitor_main, monitor_trace)
                        break
                    if received_pdu != None:
                        received_pdu.show()

                    monitor_trace.stop()
                    monitor_trace.close()

                    self.write_associated_pkts_number(monitor_main, "end")

                    self.case_cnt += 1

                pdu_exec = BTLE_DATA()/L2CAP_Hdr(len=2,cid=0x0004)/ATT_Hdr()/ATT_Execute_Write_Request(flags = 0x01)
                periph.send_data_pdu(pdu = pdu_exec,conn_handle=periph.connection.conn_handle)

                # Send multiple Requests to observe the behavior of the server
                # after receiving numerous Prepare Write Request.
                for _ in range(20):
                    my_pdu, ATT_layer = Fuzz.mutator("Request", gatt_handle) # Craft a Random pdu
                    periph.send_data_pdu(pdu = my_pdu, conn_handle=periph.connection.conn_handle)  # Send PDU

            except ImportError as IE: # ImportError
                self.TreatError(IE, post_url, monitor_main, monitor_trace, self.ERROR_MSG_IE)
                break

            except Exception as error: # Catch ConnectionLostException for instance
                self.TreatError(error, post_url, monitor_main, monitor_trace, self.ERROR_MSG)
                break

        #Disconnect
        print("Stop connection")
        if not(self.error_occured):
            self.restart(monitor_main, None)
        else:
            self.error_occured = False
