from __future__ import annotations

from datetime import datetime
from functools import total_ordering
from ipaddress import IPv4Address
from typing import NamedTuple, TYPE_CHECKING

from pydantic import BaseModel  # pylint: disable=no-name-in-module

from .pattern import ALL
from .utils import GLOBAL_NETWORK

if TYPE_CHECKING:
    from typing import TypeVar, Union, Tuple
    from typing_extensions import Self

    from .packets import ReadBOOTPPacket
    from .pattern import SupportsEq

    T = TypeVar("T", bound=SupportsEq)


class Item(BaseModel):
    mac: str
    ip: IPv4Address
    hostname: str
    last_used: datetime

    def to_tuple(self) -> Tuple[str, IPv4Address, str, datetime]:
        return self.mac, self.ip, self.hostname, self.last_used

    if TYPE_CHECKING:
        def __hash__(self) -> int: ...

    class Config:
        frozen = True


class Pattern(NamedTuple):
    mac: Union[str, SupportsEq] = ALL
    ip: Union[IPv4Address, SupportsEq] = ALL
    hostname: Union[str, SupportsEq] = ALL
    last_used: Union[datetime, SupportsEq] = ALL


@total_ordering
class Host:
    def __init__(
        self, mac: str, ip: IPv4Address, hostname: str, last_used: datetime
    ) -> None:
        self.mac = mac.upper()
        self.ip = ip
        self.hostname = hostname
        self.last_used = last_used

    @classmethod
    def from_tuple(cls, data: Item) -> Self:
        return cls(**data.dict())

    @classmethod
    def from_packet(cls, packet: ReadBOOTPPacket) -> Self:
        return cls(
            packet.client_mac_address,
            getattr(packet, "requested_ip_address", packet.client_ip_address),
            getattr(packet, "host_name", ""),
            datetime.utcnow(),
        )

    def to_tuple(self) -> Item:
        return Item(mac=self.mac, ip=self.ip, hostname=self.hostname, last_used=self.last_used)

    def to_pattern(self) -> Pattern:
        return get_pattern(mac=self.mac, ip=self.ip)

    @property
    def has_valid_ip(self) -> bool:
        return self.ip != GLOBAL_NETWORK

    def __hash__(self) -> int:
        return hash(self.to_tuple())

    def __eq__(self, value: object) -> bool:
        if not isinstance(value, Host):
            return NotImplemented

        return self.to_tuple() == value.to_tuple()

    def __lt__(self, value: object) -> bool:
        if not isinstance(value, Host):
            return NotImplemented

        return (
            self.hostname.lower() < value.hostname.lower()
            and self.mac.lower() < value.mac.lower()
            and self.ip < value.ip
        )


def get_pattern(
    mac: T = ALL, ip: T = ALL, hostname: T = ALL, last_used: T = ALL
) -> Pattern:
    return Pattern(mac, ip, hostname, last_used)
