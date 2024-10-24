from scapy.layers.bluetooth import *
from scapy.layers.bluetooth4LE import *

import os

from whad.ble import Peripheral
from whad.ble.profile import PrimaryService, Characteristic, GenericProfile, SecondaryService
from whad.ble.profile.attribute import UUID

from scenario import Scenario


class Scenario9Server(Scenario):
    """Scenario 9 Server side

    Secondary and Included services
    """
    def __init__(self):
        super().__init__()

    def run(self, periph: Peripheral, post_url: str, gatt_handle: list[int]):
        """Run the fuzzing scenario #4."""
        os.mkdir(self.current_log_case)
        monitor_main = self.create_monitor(periph,"log")

        periph.enable_synchronous(False)

        while periph.is_connected():

            pass

        #Disconnect
        print("Stop connection")
        self.restart(monitor_main,None)

class MyPeripheralScenario9(GenericProfile):

    device = PrimaryService(
        uuid=UUID(0x1800),

        device_name=Characteristic(
            uuid=UUID(0x2A00),
            permissions=['read', 'write'],
            notify=True,
            value=bytes("BLE_TEST_DEVICE", 'utf-8')
        ),
    )
    # create a secondary service
    secondary_service = SecondaryService(
        uuid=UUID(0x2300),
        test_charac = Characteristic(
            uuid=UUID(0x23ff),
            permissions = ['read'],
            notify=False,
            value=b'Test 1'
        )
    )
    # create a primary service
    primary_service = PrimaryService(
        uuid=UUID(0x1801),
        msg=Characteristic(
            uuid=UUID(0x2A01),
            permissions=['read'],
            notify=True,
            value=b'HelloWorld'
        ),
        guess=Characteristic(
            uuid=UUID('abcdabcd-0001-0001-0001-00010002000A'),
            permissions=['read', 'write'],
            notify=False,
            value=b'Guess the number!',
            description="Hello TEST"
        ),
        number=Characteristic(
            uuid=UUID('abcdabcd-0001-0001-0001-00010002000B'),
            permissions=['read'],
            notify=True,
            value=b'Default'
        ),
        inc_service = secondary_service
    )
    secondary_service.add_included_service(primary_service)
