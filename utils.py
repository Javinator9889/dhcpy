from __future__ import annotations

import asyncio
import inspect
import sys

from contextlib import suppress
from datetime import timedelta
from ipaddress import IPv4Address

from typing import TYPE_CHECKING

import netifaces

if TYPE_CHECKING:
    from ipaddress import IPv4Network
    from typing import Any, Iterable, Iterator, Callable, Awaitable


GLOBAL_NETWORK = IPv4Address("0.0.0.0")

PY37 = sys.version_info == (3, 7)


class DataReader:
    def __init__(self, data: bytes) -> None:
        self.__data = data
        self.__index = 0

    def read_byte(self) -> int:
        if self.exhausted:
            raise IndexError(f"Data exhausted (reading from offset {self.__index})")

        res = self.__data[self.__index]
        self.__index += 1
        return res

    def read(self, length: int = 1) -> bytes:
        if self.__index + length > len(self.__data):
            raise IndexError(f"Cannot read {length} bytes from offset {self.__index}")

        res = self.__data[self.__index : self.__index + length]
        self.__index += length
        return res

    def reset(self) -> None:
        self.__index = 0

    def seek(self, offset: int) -> None:
        self.__index = offset

    @property
    def exhausted(self) -> bool:
        return self.__index >= len(self.__data)

    @property
    def remaining(self) -> int:
        return len(self.__data) - self.__index


class DataWriter:
    def __init__(self, data: bytearray) -> None:
        self.__data = data
        self.__index = 0

    def write_byte(self, byte: int) -> None:
        if self.exhausted:
            raise IndexError(f"Data exhausted (writing from offset {self.__index})")

        self.__data[self.__index] = byte
        self.__index += 1

    def write(self, bytes: bytes, length: int) -> None:
        if length != len(bytes):
            msg = "overflow" if length > len(bytes) else "underflow"
            raise ValueError(
                f"Bytes object length {len(bytes)} {msg} - expected {length}"
            )

        if self.__index + length > len(self.__data):
            raise IndexError(f"Cannot write {length} bytes from offset {self.__index}")

        self.__data[self.__index : self.__index + length] = bytes
        self.__index += length

    def extend(self, bytes: bytes) -> None:
        self.__data += bytes
        self.seek(len(self.__data))

    def reset(self) -> None:
        self.seek(0)

    def seek(self, offset: int) -> None:
        self.__index = offset

    @property
    def exhausted(self) -> bool:
        return self.__index >= len(self.__data)

    def to_bytes(self) -> bytes:
        return bytes(self.__data)


def available_addresses() -> Iterator[IPv4Address]:
    for iface in netifaces.interfaces():
        addresses = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in addresses:
            for link in addresses[netifaces.AF_INET]:
                yield IPv4Address(link["addr"])


def iterate_networks(networks: Iterable[IPv4Network]) -> Iterator[IPv4Address]:
    for network in networks:
        yield from network


async def run_with_delay(
    delay: timedelta | float | int,
    function: Callable[[], Any | Awaitable[Any]],
):
    with suppress(asyncio.CancelledError):
        if isinstance(delay, timedelta):
            delay = delay.total_seconds()

        await asyncio.sleep(delay)
        ret = function()
        if inspect.isawaitable(ret):
            await ret
