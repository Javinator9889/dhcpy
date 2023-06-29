from __future__ import annotations

from ipaddress import IPv4Address
from typing import TYPE_CHECKING, Any

from .options import (
    options,
    unsigned_unpack,
    short_unpack,
    mac_unpack,
    unsigned_pack,
    short_pack,
    mac_pack,
)
from .utils import GLOBAL_NETWORK, DataReader, DataWriter

if TYPE_CHECKING:
    from ipaddress import IPv4Network
    from typing import Tuple, Dict, Union, Iterable, Optional, Set, List, TypeVar

    from .settings import DHCPSettings

    T = TypeVar("T")


_DEFAULT_ADDRESS = GLOBAL_NETWORK, 0


class ReadBOOTPPacket:
    def __init__(self, data: bytes, address: Tuple[IPv4Address, int] = _DEFAULT_ADDRESS):
        self.data = data
        reader = DataReader(data)
        self.host = address[0]
        self.port = address[1]

        self.message_type = self.OP = reader.read_byte()
        self.hardware_type = self.HTYPE = reader.read_byte()
        self.hardware_address_length = self.HLEN = reader.read_byte()
        self.hops = self.HOPS = reader.read_byte()

        self.XID = self.transaction_id = unsigned_unpack(reader.read(4))

        self.seconds_elapsed = self.SECS = short_unpack(reader.read(2))
        self.bootp_flags = self.FLAGS = short_unpack(reader.read(2))

        self.client_ip_address = self.CIADDR = IPv4Address(reader.read(4))
        self.your_ip_address = self.YIADDR = IPv4Address(reader.read(4))
        self.next_server_ip_address = self.SIADDR = IPv4Address(reader.read(4))
        self.relay_agent_ip_address = self.GIADDR = IPv4Address(reader.read(4))

        self.client_mac_address = self.CHADDR = mac_unpack(
            reader.read(self.hardware_address_length)
        )
        reader.seek(236)
        self.magic_cookie = IPv4Address(reader.read(4))
        self.options: Dict[int, bytes] = {}
        self.named_options: Dict[str, Union[str, int, Iterable[str], bytes, IPv4Address, Iterable[IPv4Address], Iterable[Tuple[IPv4Network, IPv4Address]]]] = {}

        while not reader.exhausted:
            option = reader.read_byte()
            # padding
            if option == 0:
                continue
            # end
            if option == 255:
                break

            option_length = reader.read_byte()
            option_data = reader.read(option_length)
            self.options[option] = option_data
            if option in options:
                name, encoder, decoder = options[option]
                if encoder is not None:
                    option_data = encoder(option_data)
                if name:
                    setattr(self, name, option_data)
                    self.named_options[name] = option_data
            setattr(self, f"option_{option}", option_data)

    def __getitem__(self, key: Any) -> Optional[Any]:
        return getattr(self, key, None)

    def __contains__(self, key: Any) -> bool:
        return hasattr(self, key)

    @property
    def formatted_named_options(self) -> Iterable[str]:
        return (
            f"{name.replace(' ', '')}:{' ':>14}{value}"
            for name, value in sorted(self.named_options.items())
        )

    def __str__(self):
        return "\n".join(
            [
                f"Message Type:{' ':>14}{self.message_type}",
                f"Client MAC address:{' ':>14}{self.client_mac_address}",
                f"Client IP address:{' ':>14}{self.client_ip_address.compressed}",
                f"Your IP address:{' ':>14}{self.your_ip_address.compressed}",
                f"Next server IP address:{' ':>14}{self.next_server_ip_address.compressed}",
                *self.formatted_named_options,
            ]
        )

    if TYPE_CHECKING:
        def __getattr(self, attribute: str) -> T: ...
        def __setattr__(self, attribute: str, value: T) -> None: ...


class WriteBOOTPPacket:
    def __init__(self, dhcp: DHCPSettings):
        # 1: client -> server | 2: server -> client
        self.message_type: int = 2
        self.hardware_type: int = 1
        self.hardware_address_length: int = 6
        self.hops: int = 0
        self.transaction_id: Optional[int] = None
        self.seconds_elapsed: int = 0
        self.bootp_flags: int = 0  # unicast
        self.client_ip_address: IPv4Address = GLOBAL_NETWORK
        self.your_ip_address: IPv4Address = GLOBAL_NETWORK
        self.next_server_ip_address: IPv4Address = GLOBAL_NETWORK
        self.relay_agent_ip_address: IPv4Address = GLOBAL_NETWORK
        self.client_mac_address: Optional[str] = None
        self.magic_cookie: IPv4Address = IPv4Address("99.130.83.99")
        self.parameter_order: List[int] = []

        names: Set[str] = set()
        for i in range(256):
            if getattr(dhcp, f"option_{i}", None) is not None:
                names.add(f"option_{i}")

            if i in options and getattr(dhcp, options[i].name, None) is not None:
                names.add(options[i].name)

        for name in names:
            setattr(self, name, getattr(dhcp, name))

    @property
    def options(self) -> Iterable[int]:
        res = {
            option
            for option in self.parameter_order
            if option in options
            and hasattr(self, options[option].name)
            or hasattr(self, f"option_{option}")
        }
        res.update({
            index
            for index, option in options.items()
            if option.name and hasattr(self, option.name)
        })
        res.update({
            option
            for option in range(256)
            if hasattr(self, f"option_{option}")
        })

        return res

    def get_option(self, option: int) -> Optional[bytes]:
        value = None
        if option in options and hasattr(self, options[option].name):
            value = getattr(self, options[option].name)
        elif hasattr(self, f"option_{option}"):
            value = getattr(self, f"option_{option}")
        else:
            return None

        encoder = options[option].encoder
        if value is not None and encoder is not None:
            value = encoder(value)  # type: ignore

        return value  # type: ignore

    def to_bytes(self) -> bytes:
        if self.transaction_id is None:
            raise ValueError("The transaction ID is required")
        if self.client_mac_address is None:
            raise ValueError("The client mac address is required")

        writer = DataWriter(bytearray(236))
        writer.write_byte(self.message_type)
        writer.write_byte(self.hardware_type)
        writer.write_byte(self.hardware_address_length)
        writer.write_byte(self.hops)

        writer.write(unsigned_pack(self.transaction_id), 4)
        writer.write(short_pack(self.seconds_elapsed), 2)
        writer.write(short_pack(self.bootp_flags), 2)
        writer.write(self.client_ip_address.packed, 4)
        writer.write(self.your_ip_address.packed, 4)
        writer.write(self.next_server_ip_address.packed, 4)
        writer.write(self.relay_agent_ip_address.packed, 4)

        writer.write(mac_pack(self.client_mac_address), self.hardware_address_length)

        writer.extend(self.magic_cookie.packed)

        for option in self.options:
            value = self.get_option(option)
            if value is not None:
                writer.extend(bytes([option, len(value)]) + value)

        writer.extend(bytes([255]))
        return writer.to_bytes()

    def __str__(self):
        return str(ReadBOOTPPacket(self.to_bytes()))

    if TYPE_CHECKING:
        def __getattr(self, attribute: str) -> T: ...
        def __setattr__(self, attribute: str, value: T) -> None: ...
