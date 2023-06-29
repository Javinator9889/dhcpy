from __future__ import annotations

from ipaddress import IPv4Network, IPv4Address
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any, Iterable
    from typing_extensions import Protocol

    class SupportsEq(Protocol):
        def __eq__(self, __value: Any, /) -> bool: ...


class _ALL:
    def __eq__(self, other: Any) -> bool:
        return True

    def __repr__(self) -> str:
        return type(self).__name__


class GREATER:
    def __init__(self, value: Any) -> None:
        self.value = value

    def __eq__(self, other: Any, /) -> bool:
        return type(self.value)(other) > self.value


class NETWORK:
    def __init__(self, network: Iterable[IPv4Network]):
        self.network = network

    def __eq__(self, other: Any, /) -> bool:
        if not isinstance(other, (IPv4Network, IPv4Address)):
            return False

        if isinstance(other, IPv4Network):
            return any(network == other for network in self.network)

        return any(other in network for network in self.network)


class CASEINSENSITIVE:
    def __init__(self, value: str) -> None:
        self.value = value.lower()

    def __eq__(self, other: Any, /) -> bool:
        if not isinstance(other, str):
            return False

        return self.value == other.lower()

ALL = _ALL()
