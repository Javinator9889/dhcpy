from __future__ import annotations

from datetime import timedelta
from ipaddress import IPv4Address, IPv4Network, summarize_address_range
from logging import Logger, getLogger
from pathlib import Path
from socket import gethostname
from typing import Optional, List, Tuple, TYPE_CHECKING

from pydantic import BaseSettings, root_validator

from .utils import iterate_networks

if TYPE_CHECKING:
    from typing import Dict, Any


class DHCPSettings(BaseSettings):
    interface: Optional[str] = None
    bind_address: IPv4Address = IPv4Address("0.0.0.0")
    broadcast_address: IPv4Address = IPv4Address("255.255.255.255")
    dns: List[IPv4Address] = []
    lease_time: timedelta = timedelta(seconds=300)
    leases_file: Path = Path("leases.csv")
    network: IPv4Network = IPv4Network("10.11.12.0/24")
    range_end: IPv4Address = IPv4Address("10.11.12.14")
    range_start: IPv4Address = IPv4Address("10.11.12.2")
    router: List[IPv4Address] = [IPv4Address("10.11.12.1")]
    transaction_length: timedelta = timedelta(seconds=40)
    rfc3442_classless_static_routes: Optional[List[Tuple[IPv4Network, IPv4Address]]] = None
    host_name: str = gethostname()
    log: Logger = getLogger(__name__)

    @root_validator
    @classmethod
    def validate_addresses(cls, values: Dict[str, Any]) -> Dict[str, Any]:
        network : IPv4Network = values["network"]
        range_start: IPv4Address = values["range_start"]
        range_end: IPv4Address = values["range_end"]

        networks = summarize_address_range(range_start, range_end)
        if any(ip not in network for ip in iterate_networks(networks)):
            raise TypeError(
                f"IP pool range {range_start} - {range_end} is outside "
                f'DHCP network "{network}"'
            )

        return values