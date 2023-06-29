from __future__ import annotations

import math
import struct

from base64 import b16encode, b16decode
from enum import IntEnum
from ipaddress import IPv4Address, IPv4Network
from typing import NamedTuple, TYPE_CHECKING

from .utils import DataReader

if TYPE_CHECKING:
    from typing import Tuple, Optional, Callable, List, Iterable, Union, Literal, Dict
    from typing_extensions import TypeAlias

    Decoder: TypeAlias = Union[
        Callable[[bytes], str],
        Callable[[bytes], int],
        Callable[[bytes], Iterable[str]],
        Callable[[bytes], IPv4Address],
        Callable[[bytes], Iterable[IPv4Address]],
        Callable[[bytes], Iterable[Tuple[IPv4Network, IPv4Address]]],
    ]
    Encoder: TypeAlias = Union[
        Callable[[str], bytes],
        Callable[[int], bytes],
        Callable[[Iterable[str]], bytes],
        Callable[[IPv4Address], bytes],
        Callable[[Iterable[IPv4Address]], bytes],
        Callable[[Iterable[Tuple[IPv4Network, IPv4Address]]], bytes],
    ]


class DHCPMessageTypes(IntEnum):
    DHCPDISCOVER = 1
    DHCPOFFER = 2
    DHCPREQUEST = 3
    DHCPDECLINE = 4
    DHCPACK = 5
    DHCPNAK = 6
    DHCPRELEASE = 7
    DHCPINFORM = 8


def int_minimum_bytes(value: int, byteorder: Literal["little", "big"] = "big") -> bytes:
    if value == 0:
        return b"\x00"

    length = math.ceil(math.log(value) / math.log(255))
    return value.to_bytes(length, byteorder)


def inet_ntoa(data: bytes) -> IPv4Address:
    return IPv4Address(data)


def inet_aton(address: IPv4Address) -> bytes:
    return address.packed


def inet_ntoaX(data: bytes) -> Iterable[IPv4Address]:
    return [inet_ntoa(data[i : i + 4]) for i in range(0, len(data), 4)]


def inet_atonX(addresses: Iterable[IPv4Address]) -> bytes:
    return b"".join(inet_aton(address) for address in addresses)


def inet_ntopdd(data: bytes) -> Iterable[Tuple[IPv4Network, IPv4Address]]:
    routes: List[Tuple[IPv4Network, IPv4Address]] = []
    reader = DataReader(data)
    while not reader.exhausted:
        prefix = reader.read_byte()
        octets = int((prefix + 7) / 8)
        raw_subnet = reader.read(octets)
        if len(raw_subnet) < 4:
            raw_subnet = raw_subnet.ljust(4, b"\x00")

        subnet = unsigned_unpack(raw_subnet)
        address = reader.read(4)

        routes.append((IPv4Network((subnet, prefix)), IPv4Address(address)))

    return routes


def inet_pddton(values: Iterable[Tuple[IPv4Network, IPv4Address]]) -> bytes:
    res: List[bytes] = []
    for network, address in values:
        res.append(network.prefixlen.to_bytes(1, "big"))
        octets = int((network.prefixlen + 7) / 8)
        res.append(network.network_address.packed[:octets])
        res.append(address.packed)

    return b"".join(res)


def unpack_single(data: bytes) -> int:
    return data[0]


def pack_single(data: int) -> bytes:
    return bytes([data])


def short_unpack(data: bytes) -> int:
    return (data[0] << 8) + data[1]


def short_pack(data: int) -> bytes:
    return bytes([data >> 8, data & 255])


def unsigned_unpack(data: bytes) -> int:
    return struct.unpack(">I", data)[0]


def unsigned_pack(data: int) -> bytes:
    return struct.pack(">I", data)


def decode(data: bytes) -> str:
    return data.decode("ascii")


def encode(data: str) -> bytes:
    return data.encode("ascii")


def dhcp_message_type(data: bytes) -> Union[str, int]:
    try:
        return DHCPMessageTypes(data[0]).name
    except ValueError:
        return data[0]


def type_to_dhcp(data: Union[str, int]) -> bytes:
    value = DHCPMessageTypes[data].value if isinstance(data, str) else data
    return bytes([value])


def mac_unpack(data: bytes) -> str:
    encoded = b16encode(data)
    return ":".join(decode(encoded[i : i + 2]) for i in range(0, 12, 2))


def mac_pack(data: str) -> bytes:
    return b16decode(encode(data.replace(":", "").replace("-", "")))


class Option(NamedTuple):
    name: str
    decoder: Optional[Decoder] = None
    encoder: Optional[Encoder] = None


options: Dict[int, Option] = {
    0: Option("pad"),
    1: Option("subnet_mask", inet_ntoa, inet_aton),
    2: Option("time_offset"),
    3: Option("router", inet_ntoaX, inet_atonX),
    4: Option("time_server", inet_ntoaX, inet_atonX),
    5: Option("name_server", inet_ntoaX, inet_atonX),
    6: Option("domain_name_server", inet_ntoaX, inet_atonX),
    7: Option("log_server", inet_ntoaX, inet_atonX),
    8: Option("cookie_server", inet_ntoaX, inet_atonX),
    9: Option("lpr_server", inet_ntoaX, inet_atonX),
    10: Option("impress_server", inet_ntoaX, inet_atonX),
    11: Option("resource_location_server", inet_ntoaX, inet_atonX),
    12: Option("host_name", decode, encode),
    13: Option("boot_file_size"),
    14: Option("merit_dump_file"),
    15: Option("domain_name"),
    16: Option("swap_server", inet_ntoa, inet_aton),
    17: Option("root_path"),
    18: Option("extensions_path"),
    19: Option("ip_forwarding_enabled", unpack_single, pack_single),
    20: Option("non_local_source_routing_enabled", unpack_single, pack_single),
    21: Option("policy_filer"),
    22: Option("maximum_datagram_reassembly_size", short_unpack, short_pack),
    23: Option("default_ip_time_to_live", unpack_single, pack_single),
    24: Option("path_mtu_aging_timeout"),
    25: Option("path_mtu_plateau_table"),
    26: Option("interface_mtu"),
    27: Option("all_subnets_are_local", unpack_single, pack_single),
    28: Option("broadcast_address", inet_ntoa, inet_aton),
    29: Option("perform_mask_discovery", unpack_single, pack_single),
    30: Option("mask_supplier"),
    31: Option("perform_router_discovery"),
    32: Option("router_solicitation_address", inet_ntoa, inet_aton),
    33: Option("static_route"),
    34: Option("trailer_encapsulation_option"),
    35: Option("arp_cache_timeout"),
    36: Option("ethernet_encapsulation"),
    37: Option("tcp_default_ttl"),
    38: Option("tcp_keep_alive_interval"),
    39: Option("tcp_keep_alive_garbage"),
    40: Option("network_information_service_domain"),
    41: Option("network_informtaion_servers", inet_ntoaX, inet_atonX),
    42: Option("network_time_protocol_servers", inet_ntoaX, inet_atonX),
    43: Option("vendor_specific_information"),
    44: Option("netbios_over_tcp_ip_name_server", inet_ntoaX, inet_atonX),
    45: Option("netbios_over_tcp_ip_datagram_distribution_server", inet_ntoaX, inet_atonX),
    46: Option("netbios_over_tcp_ip_node_type"),
    47: Option("netbios_over_tcp_ip_scope"),
    48: Option("x_window_system_font_server", inet_ntoaX, inet_atonX),
    49: Option("x_window_system_display_manager", inet_ntoaX, inet_atonX),
    50: Option("requested_ip_address", inet_ntoa, inet_aton),
    51: Option("ip_address_lease_time", unsigned_unpack, unsigned_pack),
    52: Option("option_overload"),
    53: Option("dhcp_message_type", dhcp_message_type, type_to_dhcp),  # type: ignore
    54: Option("server_identifier", inet_ntoa, inet_aton),
    55: Option("parameter_request_list", list, bytes),
    56: Option("message"),
    57: Option("maximum_dhcp_message_size", short_unpack, short_pack),
    58: Option("renewal_time_value"),
    59: Option("rebinding_time_value"),
    60: Option("vendor_class_identifier"),
    61: Option("client_identifier", mac_unpack, mac_pack),
    62: Option("tftp_server_name"),
    63: Option("boot_file_name"),
    64: Option("network_information_service_domain"),
    65: Option("network_information_servers", inet_ntoaX, inet_atonX),
    68: Option("mobile_ip_home_agent", inet_ntoaX, inet_atonX),
    69: Option("smtp_server", inet_ntoaX, inet_atonX),
    70: Option("pop_servers", inet_ntoaX, inet_atonX),
    71: Option("nntp_server", inet_ntoaX, inet_atonX),
    72: Option("default_www_server", inet_ntoaX, inet_atonX),
    73: Option("default_finger_server", inet_ntoaX, inet_atonX),
    74: Option("default_irc_server", inet_ntoaX, inet_atonX),
    75: Option("streettalk_server", inet_ntoaX, inet_atonX),
    76: Option("stda_server", inet_ntoaX, inet_atonX),
    121: Option("rfc3442_classless_static_routes", inet_ntopdd, inet_pddton),
}
