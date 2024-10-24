from scapy.layers.bluetooth import *
from scapy.layers.bluetooth4LE import *

import os
import random

from whad.ble import Peripheral
from whad.ble.stack.att.constants import BleAttOpcode, BleAttErrorCode
from whad.ble.stack.gatt import GattServer, GattAttributeDataList, GattHandleUUIDItem

from scenario import Scenario

class Scenario5Server(Scenario):
    """Scenario 5 Server side

    Respond to FindInformationRequest with wrong Response
    """
    def __init__(self):
        super().__init__()

    def run(self, periph: Peripheral, post_url: str, gatt_handle: list[int]):
        """Run the fuzzing scenario #5."""
        os.mkdir(self.current_log_case)
        monitor_main = self.create_monitor(periph,"log")

        periph.enable_synchronous(False)

        while periph.is_connected():

            pass

        #Disconnect
        print("Stop connection")
        self.restart(monitor_main,None)

def txlock(f):
    def _wrapper(self, *args, **kwargs):
        self.lock_tx()
        result = f(self, *args, **kwargs)
        self.unlock_tx()
        return result
    return _wrapper

class CustomGattScenario5(GattServer):
    """Create a custom gatt layer."""
    def __init__(self, parent=None, layer_name=None, options={}):
        super().__init__(parent=parent, layer_name=layer_name, options=options)

    @txlock
    def on_find_info_request(self, request):
        """Find information request
        """
        # List attributes by type UUID, sorted by handles
        print("On Find Information Request")
        attrs = {}
        attrs_handles = []
        for attribute in self.server_model.find_objects_by_range(request.start, request.end):
            attrs[attribute.handle] = attribute
            attrs_handles.append(attribute.handle)

        attrs_handles.sort()

        # If we have at least one item to return
        if len(attrs_handles) > 0:

            # Get MTU
            mtu = self.get_layer('l2cap').get_local_mtu()

            # Get item size (UUID size + 2)
            uuid_size = len(attrs[attrs_handles[0]].type_uuid.packed)

            item_format = random.choices([1,2,random.randint(0,255)], weights=(30,30,40))[0]

            item_size = uuid_size + 2
            max_nb_items = int((mtu - 2) / item_size)

            # Create our datalist
            datalist = GattAttributeDataList(item_size)

            # Iterate over items while UUID size matches and data fits in MTU
            for i in range(max_nb_items):
                if i < len(attrs_handles):
                    handle = attrs_handles[i]
                    attr_obj = attrs[handle]
                    if len(attr_obj.type_uuid.packed) == uuid_size:
                        datalist.append(
                            GattHandleUUIDItem(
                                attr_obj.handle,
                                attr_obj.type_uuid
                            )
                        )
                else:
                    break

            # Once datalist created, send answer
            datalist_raw = datalist.to_bytes()
            self.att.send_data(custom_ATT_Find_Information_Response(format=item_format,handles=datalist_raw))
        else:
            self.error(
               BleAttOpcode.FIND_INFO_REQUEST,
               request.start,
               BleAttErrorCode.ATTRIBUTE_NOT_FOUND
            )

class custom_ATT_Find_Information_Response(Packet):
    name = "Find Information Response"
    fields_desc = [
        XByteField("format", 1),
        MultipleTypeField(
            [
                (PacketListField("handles", [], ATT_Handle),
                    lambda pkt: pkt.format != 1),
                (PacketListField("handles", [], ATT_Handle_UUID128),
                    lambda pkt: pkt.format == 2),
            ],
            StrFixedLenField("handles", "", length=0)
        )
    ]

bind_layers(ATT_Hdr, custom_ATT_Find_Information_Response, opcode=0x5)
