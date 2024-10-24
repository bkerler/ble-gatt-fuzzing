from scapy.layers.bluetooth import *
from scapy.layers.bluetooth4LE import *

import time
import pip._vendor.requests as requests

from datetime import datetime
from whad.common.monitors import PcapWriterMonitor
from whad.ble import Central, Peripheral

class Scenario:

    ERROR_MSG = "An error has occured in main while. Error message: "
    ERROR_MSG_IE = "An error has occured in main while. IE: "

    def __init__(self):
        self.session_cnt = 0
        self.none_cnt = 0
        self.case_cnt = 0
        self.error_occured = False
        self.MAX_NONE_CNT = 0
        self.PREPARE_WRITE_REQUEST_NUMBER = 0 
    @property
    def current_log_case(self) -> str:
        return "log_case_"+str(self.session_cnt)

    @property
    def previous_log_case(self) -> str:
        return "log_case_"+str(self.session_cnt-1)

    @property
    def test_case_folder(self) -> str:
        return self.current_log_case+ "/f_" + str(self.case_cnt)

    def get_none_cnt(self) -> int:
        """ Get the none counter.
        """
        return self.MAX_NONE_CNT

    def set_none_cnt(self, none_cnt) -> None:
        """ Set the none counter.
        """
        self.MAX_NONE_CNT = none_cnt

    def get_prep_write_max(self) -> int:
        """ Get the Prepare Write Max.
        """
        return self.PREPARE_WRITE_REQUEST_NUMBER

    def set_prep_write_max(self, prep_write_max:int) -> None:
        """ Set the Prepare Write Max.
        """
        self.PREPARE_WRITE_REQUEST_NUMBER = prep_write_max

    def create_monitor(self, role: Central|Peripheral, use: str) -> PcapWriterMonitor:
        """Create, attach and start the monitoring session."""
        if use == "log" :
            monitor_main = PcapWriterMonitor(self.current_log_case+"/log.pcap")            # main pcap file
        elif use == "trace":
            monitor_main = PcapWriterMonitor(self.test_case_folder+"/trace.pcap")          # trace pcap file
        monitor_main.attach(role)
        monitor_main.start()
        return monitor_main

    def write_associated_pkts_number(self,monitor_main: PcapWriterMonitor, position: str) -> None:
        """Write the associated packets number corresponding to the main pcap file."""
        f = open(self.test_case_folder + "/associated_pkts_number.txt","a")
        if position == "start":
            f.write(str(monitor_main.packets_written+1))
        elif position == "end":
            f.write(" - "+str(monitor_main.packets_written))
        f.close()
        f.close()

    def write_trace(self,pdu: Packet, time_stamp: float) -> None:
        """Write the PDU in a text file."""
        f = open(self.test_case_folder + "/trace.txt","w")
        f.write("SENT ATT PDU =\n ")
        f.write(pdu[3].show(dump=True))
        f.write("\n")
        f.write("timestamp PDU = ")
        f.write(str(datetime.fromtimestamp(time_stamp))+"\n")
        f.write("\n")
        f.close()

    def write_error_unresponsive(self):
        """Write unresponsive device error."""
        f = open(self.current_log_case + "/error.txt","w")
        f.write(str(datetime.fromtimestamp(time.time()))+"\n")
        f.write("Device doesn't respond anymore (none_cnt > 10)")
        f.close()

    def restart(self, monitor_main: PcapWriterMonitor, monitor_trace: PcapWriterMonitor):
        """Detach, stop and close the monitoring session. Update the session variables."""
        monitor_main.detach()
        monitor_main.stop()
        monitor_main.close()
        if (monitor_trace != None):
            monitor_trace.detach()
            monitor_trace.stop()
            monitor_trace.close()
        self.session_cnt += 1
        self.none_cnt = 0
        self.case_cnt = 0


    def TreatError(self, error, post_url: str, monitor_main: PcapWriterMonitor, monitor_trace: PcapWriterMonitor, log_msg: str):
        """Process the occuring error."""
        print("\nError !!!: ", repr(error))
        requests.post(post_url, data=(log_msg + repr(error)).encode(encoding='utf-8'))

        try:
            f = open(self.current_log_case + "/error.txt","w")
            f.write(str(datetime.fromtimestamp(time.time()))+"\n")
            f.write(repr(error))
            f.close()
        except:
            f = open(self.previous_log_case + "/error.txt","a")
            f.write(str(datetime.fromtimestamp(time.time()))+"\n")
            f.write(repr(error))
            f.close()

        self.error_occured = True
        self.restart(monitor_main, monitor_trace)

    def run(self, central: Central, bt_addr: str, is_addr_random: bool, post_url: str, gatt_handle: list[int]):
        """Run the fuzzing scenario."""
        pass