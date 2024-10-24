from whad.ble import Central
from whad.ble import PeripheralClient, Peripheral
from whad.device import WhadDevice

from whad.ble.profile.advdata import AdvCompleteLocalName, AdvDataFieldList, AdvFlagsField

from scapy.layers.bluetooth import * 
from scapy.layers.bluetooth4LE import *

import rich_click as click

from utils import scenario_choice, MyPeripheral
from scenario.scenario4 import CustomGattScenario4
from scenario.scenario5 import CustomGattScenario5
from scenario.scenario9 import MyPeripheralScenario9

CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"], show_default=True)
POSSIBLE_SCENARIO = ["0","1","2","3","4","5","6","7","9"]
BLEMode = ["client" ,"server"]

click.rich_click.OPTION_GROUPS = {
    "ble_gatt_fuzzer": [
        {"name": "Global options", "options": ["--help"]},
        {
            "name": "Connection Options",
            "options": [
                "--bt_addr",
                "--is_addr_random",
                "--post_url",
                "--interface",
                "--gatt_handle",
                "--scenario",
                "--server",
                "--none_cnt",
                "--prep_write_max"
            ],
        },
    ]
}

# If no default value is provided, the default value is None.
@click.command(context_settings=CONTEXT_SETTINGS)
# connection options
@click.option(
    "-bt",
    "--bt_addr",
    type=str,
    help="Bluetooth address of the device."
)
@click.option(
    "-r",
    "--is_addr_random",
    type=bool,
    default=False,
    help="Is the given Bluetooth address random."
)
@click.option(
    "-u",
    "--post_url",
    type=str,
    default="https://ntfy.sh/test_ntfy_server",
    help="Notify address to use."
)
@click.option(
    "-i",
    "--interface",
    type=str,
    default="hci0",
    help="Interface to use.",
)
@click.option(
    "-g",
    "--gatt_handle",
    type=int,
    default=100,
    help="The last GATT handle of the device.",
)
@click.option(
    "-s",
    "--scenario",
    type=click.Choice(POSSIBLE_SCENARIO),
    default="0",
    help="The scenario to play.",
)
@click.option(
    "-nc",
    "--none_cnt",
    type=int,
    default=20,
    help="The max unreceived responses before triggering an error.",
)
@click.option(
    "-pwm",
    "--prep_write_max",
    type=int,
    default=100,
    help="Number of prepare write PDUs to send.",
)
# connection arguments
@click.argument("mode", type=click.Choice(BLEMode, case_sensitive=False))
def main(mode: str, bt_addr: str, is_addr_random: bool, post_url: str, interface: str, gatt_handle: int, scenario: str, none_cnt: int, prep_write_max: int):
    """Bluetooth Low Energy GATT Fuzzer based on multiple scenario."""

    print("\nThe current mode is:",mode)
    print("The current scenario is:",scenario)
    print("The current Notify address is:",post_url)
    print("The current used interface is:",interface)
    print("The last GATT handle is:",gatt_handle)

    client = False

    if mode == "client":
        client = True
        print("The Bluetooth address is:",bt_addr)
        if bt_addr is None:
            raise click.BadArgumentUsage(
                f"Missing option: client mode requires the following option to be set: \
                '--bt_addr'.")

    selected_scenario = scenario_choice(int(scenario), client)
    selected_scenario.set_none_cnt(none_cnt)
    selected_scenario.set_prep_write_max(prep_write_max)

    gatt_handle_range = range(1,int(gatt_handle))

    if client:
        central = Central(WhadDevice.create(interface))
        while True:
            selected_scenario.run(central, bt_addr, is_addr_random, post_url, gatt_handle_range)
    else:
        if int(scenario) == 9:
            my_profile = MyPeripheralScenario9()
        else:
            my_profile = MyPeripheral()
        if int(scenario) == 4:
            periph = Peripheral(WhadDevice.create(interface), profile=my_profile, public=True, gatt=CustomGattScenario4)
        elif int(scenario) == 5:
            periph = Peripheral(WhadDevice.create(interface), profile=my_profile, public=True, gatt=CustomGattScenario5)
        else:
            periph = PeripheralClient(WhadDevice.create(interface), profile=my_profile, public=True)
        periph.enable_peripheral_mode(adv_data=AdvDataFieldList(AdvCompleteLocalName(b'BLE_TEST'),AdvFlagsField()))
        while True:
            print("\nWaiting for connection...")
            periph.wait_connection()
            print("Connected !")
            selected_scenario.run(periph, post_url, gatt_handle_range)


if __name__ == "__main__":
    main()