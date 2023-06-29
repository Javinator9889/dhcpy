from __future__ import annotations

from typing import TYPE_CHECKING

from .settings import DHCPSettings
from .database import CSVDatabase, HostDatabase
from .host import Host, Item, Pattern, get_pattern
from .options import Option, options
from .packets import ReadBOOTPPacket, WriteBOOTPPacket
from .server import DHCPServer
from .transaction import Transaction
from .utils import GLOBAL_NETWORK, DataReader, DataWriter, available_addresses, iterate_networks

if TYPE_CHECKING:
    from .database import Database


__all__ = (
    "CSVDatabase",
    "HostDatabase",
    "Host",
    "Item",
    "Pattern",
    "get_pattern",
    "Option",
    "options",
    "ReadBOOTPPacket",
    "WriteBOOTPPacket",
    "DHCPServer",
    "Transaction",
    "GLOBAL_NETWORK",
    "DHCPSettings",
    "DataReader",
    "DataWriter",
    "available_addresses",
    "iterate_networks",
)
