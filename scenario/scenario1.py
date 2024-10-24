from scapy.layers.bluetooth import *
from scapy.layers.bluetooth4LE import *

import os
import time
import fuzzing as Fuzz
import pip._vendor.requests as requests

from datetime import datetime
from whad.ble import Central, PeripheralClient

from scenario import Scenario

class Scenario1(Scenario):
    """Scenario 1

    Send two PDUs consecutively
    """

    def __init__(self):
        super().__init__()

    def write_trace(self, pdus: list[Packet], time_stamps: list[float]) -> None:
        """Write the PDU in a text file."""
        f = open(self.test_case_folder + "/trace.txt","w")
        pdu_cnt = 1
        for (pdu,time_stamp) in zip(pdus,time_stamps):
            f.write(f"SENT ATT PDU #{pdu_cnt} =\n ")
            f.write(pdu[3].show(dump=True))
            f.write("\n")
            f.write(f"timestamp PDU #{pdu_cnt} = ")
            f.write(str(datetime.fromtimestamp(time_stamp))+"\n")
            f.write("\n")
            pdu_cnt += 1
        f.close()

class Scenario1Client(Scenario1):
    """Scenario 1 from Client side

    Send two PDUs consecutively
    """

    def __init__(self):
        super().__init__()

    def run(self, central: Central, bt_addr: str, is_addr_random: bool, post_url: str, gatt_handle: list[int]):
        """Run the fuzzing scenario #1."""
        os.mkdir(self.current_log_case)
        monitor_main = self.create_monitor(central,"log")

        print("\nNew connection")
        central.connect(bt_addr, random=is_addr_random)
        central.enable_synchronous(True)

        while True:

            try :

                os.mkdir(self.test_case_folder)
                self.write_associated_pkts_number(monitor_main, "start")
                monitor_trace = self.create_monitor(central, "trace")

                my_pdu_1, ATT_layer_1 = Fuzz.mutator("Request", gatt_handle) # Craft a Request pdu
                my_pdu_2, ATT_layer_2 = Fuzz.mutator("Random", gatt_handle)  # Craft a Random pdu
                expected_resp_1 = Fuzz.expected_response(ATT_layer_1)        # Get expected response if request
                expected_resp_2 = Fuzz.expected_response(ATT_layer_2)        # Get expected response if request
                expected_resp = [expected_resp_1, expected_resp_2]

                central.send_pdu(pdu = my_pdu_1, conn_handle=central.connection.conn_handle) # Send PDU #1
                time_stamp_my_pdu_1 = time.time()
                central.send_pdu(pdu = my_pdu_2, conn_handle=central.connection.conn_handle) # Send PDU #2
                time_stamp_my_pdu_2 = time.time()

                self.write_trace([my_pdu_1,my_pdu_2], [time_stamp_my_pdu_1,time_stamp_my_pdu_2])

                for i in range(2):

                    received_pdu = central.wait_packet(timeout=1) # Receive what is supposed to be the PDU response
                    time_stamp_received_pdu = time.time()

                    if Fuzz.check_expected_get(received_pdu, expected_resp[i], central, time_stamp_received_pdu, self.test_case_folder, self):

                        requests.post(post_url, data=f"Device doesn't respond anymore (none_cnt > {self.MAX_NONE_CNT})".encode(encoding='utf-8'))
                        self.restart(monitor_main, monitor_trace)

                        break

                monitor_trace.stop()
                monitor_trace.close()

                self.write_associated_pkts_number(monitor_main, "end")

                self.case_cnt += 1

            except ImportError as IE:  # ImportError
                self.TreatError(IE, post_url, monitor_main, monitor_trace, self.ERROR_MSG_IE)
                break

            except Exception as error: # Catch ConnectionLostException for instance
                self.TreatError(error, post_url, monitor_main, monitor_trace, self.ERROR_MSG)
                break

class Scenario1Server(Scenario1):
    """Scenario 1 from Server side

    Send two PDUs consecutively
    """
    def __init__(self):
        super().__init__()

    def run(self, periph: PeripheralClient, post_url: str, gatt_handle: list[int]):
        """Run the fuzzing scenario #1."""
        os.mkdir(self.current_log_case)
        monitor_main = self.create_monitor(periph,"log")

        periph.enable_synchronous(True)

        while periph.is_connected():

            try :

                os.mkdir(self.test_case_folder)
                self.write_associated_pkts_number(monitor_main, "start")
                monitor_trace = self.create_monitor(periph, "trace")

                my_pdu_1, ATT_layer_1 = Fuzz.mutator("Request", gatt_handle) # Craft a Request pdu
                my_pdu_2, ATT_layer_2 = Fuzz.mutator("Random", gatt_handle)  # Craft a Random pdu
                expected_resp_1 = Fuzz.expected_response(ATT_layer_1)        # Get expected response if request
                expected_resp_2 = Fuzz.expected_response(ATT_layer_2)        # Get expected response if request
                expected_resp = [expected_resp_1, expected_resp_2]

                periph.send_data_pdu(pdu = my_pdu_1, conn_handle=periph.connection.conn_handle) # Send PDU #1
                time_stamp_my_pdu_1 = time.time()
                periph.send_data_pdu(pdu = my_pdu_2, conn_handle=periph.connection.conn_handle) # Send PDU #2
                time_stamp_my_pdu_2 = time.time()

                self.write_trace([my_pdu_1,my_pdu_2], [time_stamp_my_pdu_1,time_stamp_my_pdu_2])

                for i in range(2):

                    received_pdu = periph.wait_packet(timeout=1) # Receive what is supposed to be the PDU response
                    time_stamp_received_pdu = time.time()

                    if Fuzz.check_expected_get(received_pdu, expected_resp[i], periph, time_stamp_received_pdu, self.test_case_folder, self):

                        requests.post(post_url, data=f"Device doesn't respond anymore (none_cnt > {self.MAX_NONE_CNT})".encode(encoding='utf-8'))
                        self.restart(monitor_main, monitor_trace)

                        break

                monitor_trace.stop()
                monitor_trace.close()

                self.write_associated_pkts_number(monitor_main, "end")

                self.case_cnt += 1

            except ImportError as IE:  # ImportError
                self.TreatError(IE, post_url, monitor_main, monitor_trace, self.ERROR_MSG_IE)
                break

            except Exception as error: # Catch ConnectionLostException for instance
                self.TreatError(error, post_url, monitor_main, monitor_trace, self.ERROR_MSG)
                break

        #Disconnect
        print("Stop connection")
        self.restart(monitor_main,None)
