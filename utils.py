from whad.ble.profile.attribute import UUID

from whad.ble.profile import PrimaryService, Characteristic, GenericProfile

from scenario import Scenario
from scenario.scenario0 import Scenario0
from scenario.scenario1 import Scenario1Client, Scenario1Server
from scenario.scenario2 import Scenario2Client, Scenario2Server
from scenario.scenario3 import Scenario3Client, Scenario3Server
from scenario.scenario4 import Scenario4Server
from scenario.scenario5 import Scenario5Server
from scenario.scenario6 import Scenario6Client, Scenario6Server
from scenario.scenario7 import Scenario7Client, Scenario7Server
from scenario.scenario9 import Scenario9Server

def scenario_choice(scenario_number: int, client: bool) -> Scenario:
    """Select the corresponding scenario.
    """
    match scenario_number:

        case 0:
            return Scenario0()
        case 1:
            if client:
                return Scenario1Client()
            else:
                return Scenario1Server()
        case 2:
            if client:
                return Scenario2Client()
            else:
                return Scenario2Server()
        case 3:
            if client:
                return Scenario3Client()
            else:
                return Scenario3Server()
        case 4:
            return Scenario4Server()
        case 5:
            return Scenario5Server()
        case 6:
            if client:
                return Scenario6Client()
            else:
                return Scenario6Server()
        case 7:
            if client:
                return Scenario7Client()
            else:
                return Scenario7Server()
        case 9:
            return Scenario9Server()

NAME = "BLE_TEST"

class MyPeripheral(GenericProfile):
    """Create a PrimaryService."""
    device = PrimaryService(
        uuid=UUID(0x1800),
        device_name=Characteristic(
            uuid=UUID(0x2A00),
            permissions=['read', 'write'],
            notify=True,
            value=bytes(NAME, 'utf-8'),
        ),
        msg1=Characteristic(
            uuid=UUID(0x2A01),
            permissions=['read',"write"],
            notify=True,
            value=b'HelloWorld',
            description = "This is a test"
        ),
        msg2=Characteristic(
            uuid=UUID(0x2A01),
            permissions=['read',"write"],
            notify=True,
            value=b'HelloWorld'
        ),
        msg3=Characteristic(
            uuid=UUID(0x2A03),
            permissions=['read'],
            notify=True,
            value=b'HelloWorld'
        ),
        msg4=Characteristic(
            uuid=UUID(0x2A04),
            permissions=['read'],
            notify=True,
            value=b'HelloWorld'
        ),
        msg5=Characteristic(
            uuid=UUID(0x2A05),
            permissions=['read',"write"],
            notify=True,
            value=b'HelloWorld'
        ),
        msg6=Characteristic(
            uuid=UUID(0x2A06),
            permissions=['read',"write"],
            notify=True,
            value=b'HelloWorld',
            description = "This is a test"
        ),
        msg7=Characteristic(
            uuid=UUID(0x2A07),
            permissions=['read',"write"],
            notify=True,
            value=b'HelloWorld',
            description = "This is a test"
        ),
        msg8=Characteristic(
            uuid=UUID(0x2A08),
            permissions=['read',"write"],
            notify=True,
            value=b'HelloWorld',
            description = "This is a test"
        ),
        msg9=Characteristic(
            uuid=UUID(0x2A09),
            permissions=['read',"write"],
            notify=True,
            value=b'HelloWorld',
            description = "This is a test"
        ),
    )
    # create a custom service
    custom = PrimaryService(
        uuid=UUID('abcdabcd-0001-0001-0001-000100020000'),
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
        number1=Characteristic(
            uuid=UUID('abcdabcd-0001-0001-0001-00010002000C'),
            permissions=['read'],
            notify=True,
            value=b'Default'
        ),
        number2=Characteristic(
            uuid=UUID('abcdabcd-0001-0001-0001-00010002000D'),
            permissions=['read'],
            notify=True,
            value=b'Default'
        ),
        number3=Characteristic(
            uuid=UUID('abcdabcd-0001-0001-0001-00010002000E'),
            permissions=['read'],
            notify=True,
            value=b'Default'
        ),
    )
