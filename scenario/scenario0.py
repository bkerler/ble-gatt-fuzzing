import os
import time
import fuzzing as Fuzz
import pip._vendor.requests as requests

from whad.ble import Central
import pip._vendor.requests as requests

from scenario import Scenario 

class Scenario0(Scenario):
    """Basic Fuzzer on PDUs
    """

    def __init__(self):
        super().__init__()

    def run(self, central: Central, bt_addr: str, is_addr_random: bool, post_url: str, gatt_handle: list[int]):
        """Run the fuzzing scenario #0."""
        os.mkdir(self.current_log_case)
        monitor_main = self.create_monitor(central,"log")

        print("\nNew connection")
        central.connect(bt_addr, random=is_addr_random)
        # ADD .wait or .sleep TO WAIT FOR THE SERVICE DISCOVERY DONE OR L2CAP FIRST EXCHANGE
        central.enable_synchronous(True)

        while True:

            try :

                os.mkdir(self.test_case_folder)
                self.write_associated_pkts_number(monitor_main, "start")
                monitor_trace = self.create_monitor(central, "trace")

                my_pdu, ATT_layer = Fuzz.mutator("Random", gatt_handle) # Craft a Random pdu
                expected_resp = Fuzz.expected_response(ATT_layer)       # Get expected response if request

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

            except ImportError as IE:  # ImportError
                self.TreatError(IE, post_url, monitor_main, monitor_trace, self.ERROR_MSG_IE)
                break

            except Exception as error: # Catch ConnectionLostException for instance
                self.TreatError(error, post_url, monitor_main, monitor_trace, self.ERROR_MSG)
                break
