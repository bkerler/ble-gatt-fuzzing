from scapy.layers.bluetooth import *
from scapy.layers.bluetooth4LE import *

import os
from struct import pack
from random import shuffle

from whad.ble import Peripheral
from whad.ble.stack.att.constants import BleAttOpcode, BleAttErrorCode
from whad.ble.stack.gatt import GattServer, GattAttributeDataList, GattHandleUUIDItem
from whad.ble.stack.gatt.message import *
from whad.ble.profile.characteristic import Characteristic, CharacteristicDescriptor, CharacteristicValue
from whad.ble.profile.service import PrimaryService, SecondaryService, IncludeService

from scenario import Scenario


class Scenario8Server(Scenario):
    """Scenario 8 Server side

    Scenario dropped.
    Introduce inconsistencies in GATT server responses.
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

def txlock(f):
    def _wrapper(self, *args, **kwargs):
        self.lock_tx()
        result = f(self, *args, **kwargs)
        self.unlock_tx()
        return result
    return _wrapper

class CustomGattScenario8(GattServer):
    """Create a custom gatt layer."""
    def __init__(self, parent=None, layer_name=None, options={}):
        super().__init__(parent=parent, layer_name=layer_name, options=options)

    @txlock
    def on_find_info_request(self, request):
        """Find information request
        """
        # List attributes by type UUID, sorted by handles

        attrs = {}
        attrs_handles = []

        for attribute in self.server_model.find_objects_by_range(request.start, request.end):
            attrs[attribute.handle] = attribute
            attrs_handles.append(attribute.handle)

        print("on_find_info_request before shuffle(attrs_handles):", attrs_handles)
        shuffle(attrs_handles)
        print("on_find_info_request after shuffle(attrs_handles):", attrs_handles)

        # If we have at least one item to return
        if len(attrs_handles) > 0:

            # Get MTU
            mtu = self.get_layer('l2cap').get_local_mtu()

            # Get item size (UUID size + 2)
            uuid_size = len(attrs[attrs_handles[0]].type_uuid.packed)
            if uuid_size == 2:
                item_format = 1
            else:
                item_format = 2
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
            print("datalist_raw",datalist_raw)
            self.att.find_info_response(item_format, datalist_raw)
        else:
            self.error(
               BleAttOpcode.FIND_INFO_REQUEST,
               request.start,
               BleAttErrorCode.ATTRIBUTE_NOT_FOUND
            )

    @txlock
    def on_find_by_type_value_request(self, request: GattFindByTypeValueRequest):
        """ATT Find By Type Value Request callback

        :param GattFindByTypeValueRequest request: Request
        """
        # List attributes by type UUID, sorted by handles
        attrs = {}
        attrs_handles = []
        for attribute in self.server_model.find_objects_by_range(request.start, request.end):
            attrs[attribute.handle] = attribute
            attrs_handles.append(attribute.handle)
        print("on_find_by_type_value_request request.value",request.value)

        print("on_find_by_type_value_request before shuffle(attrs_handles):", attrs_handles)
        shuffle(attrs_handles)
        print("on_find_by_type_value_request after shuffle(attrs_handles):", attrs_handles)

        # Loop on attributes and return the attributes with a value that matches the request value
        matching_attrs = []
        for handle in attrs_handles:
            # Retrieve attribute based on handle
            attr = attrs[handle]

            # If attribute is a characteristic value or a descriptor, we make sure the characteristic
            # is readable before matching its value with the request value
            if isinstance(attr, CharacteristicValue) or isinstance(attr, CharacteristicDescriptor):
                if attr.characteristic.readable():
                    # Find characteristic end handle
                    if attr.value == request.value:
                        matching_attrs.append((handle, attr.characteristic.end_handle))
            else:
                # PrimaryService and SecondaryService are grouping types
                if isinstance(attr, PrimaryService) or isinstance(attr, SecondaryService):
                    if attr.value == request.value:
                        matching_attrs.append((handle, attr.end_handle))
                else:
                    if attr.value == request.value:
                        matching_attrs.append((handle, handle))

        # If we have found at least one attribute that matches the request, return a
        # FindByTypeValueResponse PDU
        if len(matching_attrs) > 0:
            # Build the response
            mtu = self.get_layer('l2cap').get_local_mtu()
            max_nb_items = int((mtu - 1) / 4)

            # Create our datalist
            handles_list = []

            # Iterate over items while UUID size matches and data fits in MTU
            for i in range(max_nb_items):
                if i < len(matching_attrs):
                    handle, end_handle = matching_attrs[i]
                    attr_obj = attrs[handle]
                    handles_list.append(
                        ATT_Handle(
                            handle=handle,
                            value=end_handle
                        )
                    )
                else:
                    break

            # Once datalist created, send answer
            print("handles_list:",handles_list)
            self.att.find_by_type_value_response(handles_list)
        else:
            # Attribute not found
            self.error(
               BleAttOpcode.FIND_BY_TYPE_VALUE_REQUEST,
               request.start,
               BleAttErrorCode.ATTRIBUTE_NOT_FOUND
            )

    @txlock
    def on_read_by_type_request(self, request: GattReadByTypeRequest):
        """Read attribute by type request
        """
        # List attributes by type UUID, sorted by handles
        attrs = {}
        attrs_handles = []
        for attribute in self.server_model.attr_by_type_uuid(UUID(request.type), request.start, request.end):
            attrs[attribute.handle] = attribute
            attrs_handles.append(attribute.handle)

        print("on_read_by_type_request before shuffle(attrs_handles):", attrs_handles)
        shuffle(attrs_handles)
        print("on_read_by_type_request after shuffle(attrs_handles):", attrs_handles)

        # If we have at least one item to return
        if len(attrs_handles) > 0:

            # Get MTU
            mtu = self.get_layer('l2cap').get_local_mtu()

            # If client is looking for characteristic declaration,
            # we compute the correct item size and maximum number
            # of items we can put in a response PDU
            #
            # In the case of a characteristic declaration, UUID could
            # be 16-bit or 128-bit long so we shall only put in the same
            # answer characteristics with same size UUIDs.

            if UUID(request.type) == UUID(0x2803):

                # Get item size (UUID size + 2)
                uuid_size = len(attrs[attrs_handles[0]].uuid.packed)
                item_size = uuid_size + 5
                max_nb_items = int((mtu - 2) / item_size)

                # Create our datalist
                datalist = GattAttributeDataList(item_size)
            elif UUID(request.type) == UUID(0x2802):

                # If client is looking for included services,
                # we compute the correct item size and maximum number
                # of items we can put in a response PDU
                #
                # In the case of an included service declaration, UUID could
                # be 16-bit or 128-bit long so we shall only put in the same
                # answer characteristics with same size UUIDs.

                # Get item size
                uuid_size = len(attrs[attrs_handles[0]].uuid.packed)
                item_size = uuid_size + 6
                max_nb_items = int((mtu - 2) / item_size)

                # Create our datalist
                datalist = GattAttributeDataList(item_size)
            else:
                max_nb_items = 0
                datalist = GattAttributeDataList(0)

            # Iterate over items while UUID size matches and data fits in MTU
            for i in range(max_nb_items):
                if i < len(attrs_handles):
                    handle = attrs_handles[i]
                    attr_obj = attrs[handle]
                    if len(attr_obj.uuid.packed) == uuid_size:
                        if isinstance(attrs[handle], Characteristic):
                            datalist.append(
                                GattAttributeValueItem(
                                    handle,
                                    pack(
                                        '<BH',
                                        attr_obj.properties,
                                        attr_obj.value_handle,
                                    ) + attr_obj.uuid.packed
                                )
                            )
                        elif isinstance(attrs[handle], IncludeService):
                            if attrs[handle].service_uuid.type == UUID.TYPE_16:
                                datalist.append(
                                    GattAttributeValueItem(
                                        handle,
                                        pack(
                                            '<HH',
                                            attr_obj.service_start_handle,
                                            attr_obj.service_end_handle,
                                        ) + attr_obj.service_uuid.packed
                                    )
                                )
                            else:
                                datalist.append(
                                    GattAttributeValueItem(
                                        handle,
                                        pack(
                                            '<HH',
                                            attr_obj.service_start_handle,
                                            attr_obj.service_end_handle,
                                        )
                                    )
                                )
                else:
                    break

            # Check that our result datalist does contain something
            if len(datalist) > 0:
                # Once datalist created, send answer
                datalist_raw = datalist.to_bytes()
                print("datalist_raw", datalist_raw)
                self.att.read_by_type_response(item_size, datalist_raw)
            else:
                # If not, send an error.
                self.error(
                    BleAttOpcode.READ_BY_TYPE_REQUEST,
                    request.start,
                    BleAttErrorCode.ATTRIBUTE_NOT_FOUND
                )
        else:
            self.error(
               BleAttOpcode.READ_BY_TYPE_REQUEST,
               request.start,
               BleAttErrorCode.ATTRIBUTE_NOT_FOUND
            )

    @txlock
    def on_read_by_group_type_request(self, request: GattReadByGroupTypeRequest):
        """Read by group type request

        List attribute with given type UUID from `start` handle to ̀`end` handle.
        """
        # List attributes by type UUID, sorted by handles
        attrs = {}
        attrs_handles = []
        for attribute in self.server_model.attr_by_type_uuid(UUID(request.type), request.start, request.end):
            attrs[attribute.handle] = attribute
            attrs_handles.append(attribute.handle)

        print("on_read_by_group_type_request before attrs_handles.sort(reverse=True):", attrs_handles)
        attrs_handles.sort(reverse=True)
        print("on_read_by_group_type_request after attrs_handles.sort(reverse=True):", attrs_handles)

        # If we have at least one item to return
        if len(attrs_handles) > 0:

            # Get MTU
            mtu = self.get_layer('l2cap').get_local_mtu()

            # Get item size (UUID size + 4)
            uuid_size = len(attrs[attrs_handles[0]].uuid.packed)
            item_size = uuid_size + 4
            max_nb_items = int((mtu - 2) / item_size)

            # Create our datalist
            datalist = GattAttributeDataList(item_size)

            # Iterate over items while UUID size matches and data fits in MTU
            for i in range(max_nb_items):
                if i < len(attrs_handles):
                    handle = attrs_handles[i]
                    end_handle = attrs[handle].end_handle
                    attr_uuid = attrs[handle].uuid
                    if len(attr_uuid.packed) == uuid_size:
                        datalist.append(
                            GattGroupTypeItem(handle, end_handle, attr_uuid.packed)
                        )
                else:
                    break

            # Once datalist created, send answer
            datalist_raw = datalist.to_bytes()
            print("datalist_raw:",datalist_raw)
            self.att.read_by_group_type_response(item_size, datalist_raw)
        else:
            self.error(
               BleAttOpcode.READ_BY_GROUP_TYPE_REQUEST,
               request.start,
               BleAttErrorCode.ATTRIBUTE_NOT_FOUND
            )
