from __future__ import annotations

import sys

from asyncio import CancelledError, DatagramProtocol, Event, sleep, wait
from contextlib import asynccontextmanager, suppress
from datetime import datetime
from ipaddress import IPv4Address, summarize_address_range
from socket import (
    socket,
    SOCK_DGRAM,
    SOL_SOCKET,
    SO_REUSEADDR,
    SO_BROADCAST,
)

from typing import TYPE_CHECKING

from .transaction import Transaction
from .packets import ReadBOOTPPacket
from .pattern import CASEINSENSITIVE, NETWORK
from .host import Host, Pattern
from .database import HostDatabase, CSVDatabase
from .settings import DHCPSettings
from .utils import GLOBAL_NETWORK, iterate_networks, available_addresses, run_with_delay

if sys.platform != "win32":
    from socket import SO_BINDTODEVICE  # pylint: disable=ungrouped-imports
else:
    from os import getpid
    from socket import fromshare  # pylint: disable=ungrouped-imports

if TYPE_CHECKING:
    from asyncio import AbstractEventLoop, DatagramTransport, Task
    from typing import Optional, AsyncIterator, Union, Set, Dict
    from typing_extensions import TypeGuard, TypeAlias

    from .packets import WriteBOOTPPacket

    EllipsisType: TypeAlias = ellipsis  # pylint: disable=undefined-variable


@asynccontextmanager
async def broadcast(
    loop: AbstractEventLoop, local_addr: IPv4Address, local_port: int
) -> AsyncIterator[DatagramTransport]:
    transport: Optional[DatagramTransport] = None
    sock = socket(type=SOCK_DGRAM)
    sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    sock.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
    try:
        sock.bind((local_addr.compressed, local_port))
        transport, protocol = await loop.create_datagram_endpoint(DatagramProtocol, sock=sock)
        yield transport
    finally:
        if transport is not None:
            transport.close()
        else:
            sock.close()


class DHCPServer:
    def __init__(self, loop: AbstractEventLoop, settings: Union[DHCPSettings, EllipsisType] = ...):
        if settings is ...:
            settings = DHCPSettings()
        self.settings = settings
        self.log = settings.log
        self.log.debug("working with settings: %s", settings)
        self.main_network = settings.network
        self.networks = [*summarize_address_range(settings.range_start, settings.range_end)]
        self.interface = settings.interface
        self.bind_address = settings.bind_address
        self.broadcast_address = settings.broadcast_address
        self.transaction_length = settings.transaction_length
        self.router = settings.router
        self.lease_time = settings.lease_time
        self.dns = settings.dns
        self.leases_file = settings.leases_file

        self.loop = loop
        self.socket = socket(type=SOCK_DGRAM)
        self.hosts = HostDatabase(CSVDatabase(settings.leases_file, settings.log), settings.log)
        self.closed: Optional[Event] = None
        self.transactions: Set[Task[bool]] = set()
        self.leases: Dict[str, Task[None]] = {}

    def check_internal_state(self):
        if sys.platform == "win32":  # pragma: py-win32
            if self.bind_address == GLOBAL_NETWORK:
                self.log.warning(
                    "Listening to all traffic in Windows is discouraged! Please, specify "
                    "the interface's IP address instead"
                )
            if self.interface is not None:
                self.log.warning("Specifying the interface while in Windows makes no effect")
        else:
            if self.bind_address == GLOBAL_NETWORK and self.interface is None:
                self.log.warning(
                    "Listening to all traffic without specifying an interface is discouraged! "
                    "Please, specify the interface to listen at"
                )
            if self.bind_address != GLOBAL_NETWORK:
                self.log.warning(
                    "Configuring a non-global IP address for the DHCP server may not work "
                    'in all devices. Consider combining "bind_address" and "interface" settings'
                )

    def on_packet_received(self):
        transaction = Transaction(self)
        try:
            packet = ReadBOOTPPacket(*self.socket.recvfrom(4096))
        except OSError:
            # OSError: An operation was attempted on something that is not a socket
            pass
        else:
            task = self.loop.create_task(transaction.receive(packet))
            self.transactions.add(task)
            task.add_done_callback(self.transactions.discard)

    async def run(self) -> None:
        self.log.info("Starting DHCP server")
        self.check_internal_state()
        self.socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        self.socket.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
        if self.interface is not None and sys.platform != "win32":
            self.log.debug("binding DHCP socket to interface %s", self.interface)
            self.socket.setsockopt(SOL_SOCKET, SO_BINDTODEVICE, self.interface.encode("utf-8"))

        self.socket.bind((self.bind_address.compressed, 67))

        if sys.platform == "win32":  # pragma: py-win32
            sock_data = self.socket.share(getpid())
            self.socket = fromshare(sock_data)

        self.closed = Event()
        self.loop.add_reader(self.socket, self.on_packet_received)
        try:
            self.log.info(
                "DHCP server listening on %s port %d%s",
                self.bind_address,
                67,
                f" (interface {self.interface})" if self.interface is not None else "",
            )
            while not self.closed.is_set():
                await sleep(0.1)
        finally:
            self.log.debug("removing socket reader")
            self.loop.remove_reader(self.socket)
            self.socket.close()
            self.log.debug("closing %d pending transactions", len(self.transactions))
            for transaction in self.transactions:
                transaction.cancel()

            if len(self.transactions) > 0:
                self.log.debug("waiting for %d transactions to complete", len(self.transactions))
                await wait(self.transactions)

            self.log.debug("closing %d pending leases", len(self.leases))
            for lease in self.leases.values():
                lease.cancel()

            if len(self.leases) > 0:
                self.log.debug("waiting for %d leases to complete", len(self.leases))
                await wait(self.leases.values())

            self.log.debug("closed DHCP server")

    def close(self):
        if self.closed is None:
            raise RuntimeError("Cannot close a non-started DHCP server")

        if self.closed.is_set():
            return
        self.log.debug("closing DHCP server")
        self.closed.set()

    async def client_has_chosen(self, packet: ReadBOOTPPacket):
        self.log.debug("client chosen: %s", packet)
        host = Host.from_packet(packet)
        if not host.has_valid_ip:
            return

        await self.hosts.replace(host)

        prev_lease = self.leases.pop(host.mac, None)
        if prev_lease is not None:
            self.log.debug("client acquired a new lease, removing previous one (%s)", prev_lease)
            prev_lease.cancel()
            with suppress(CancelledError):
                await prev_lease

        lease_task = self.loop.create_task(
            run_with_delay(
                delay=getattr(packet, "ip_address_lease_time", self.lease_time),
                function=lambda: self.hosts.delete(host),
            ),
            name=host.mac,
        )
        self.leases[host.mac] = lease_task
        lease_task.add_done_callback(
            lambda task: task.cancelled()
            or self.log.debug("host %s got lease expired", host.mac)
            or self.leases.pop(host.mac, None)
        )

    def is_valid_client_address(
        self, address: Optional[Union[IPv4Address, str]]
    ) -> TypeGuard[IPv4Address]:
        if address is None:
            return False

        if not isinstance(address, IPv4Address):
            address = IPv4Address(address)

        return any(address in network for network in self.networks)

    async def get_ip_address(self, packet: ReadBOOTPPacket) -> IPv4Address:
        self.log.debug("getting IP address for packet: %s", packet)
        mac = packet.client_mac_address
        requested_ip: Optional[IPv4Address] = getattr(packet, "requested_ip_address", None)
        known_hosts = [host async for host in self.hosts.get(Pattern(mac=CASEINSENSITIVE(mac)))]
        assigned_addresses = {host.ip async for host in self.hosts.all()}
        ip: Optional[IPv4Address] = None
        # 1. Choose a known IP address
        for host in known_hosts:
            if self.is_valid_client_address(host.ip):
                self.log.debug(
                    "reusing already known IP address %s for packet %s", host.ip, packet
                )
                ip = host.ip
                break

        # 2. Choose a valid requested address
        if (
            ip is None
            and self.is_valid_client_address(requested_ip)
            and requested_ip not in assigned_addresses
        ):
            self.log.debug("using client-requested IP address %s", requested_ip)
            ip = requested_ip

        # 3. Choose a new, free IP address
        if ip is None:
            chosen = False
            network_hosts = [
                host async for host in self.hosts.get(Pattern(ip=NETWORK(self.networks)))
            ]
            for ip in iterate_networks(self.networks):
                if not any(host.ip == ip for host in network_hosts):
                    self.log.debug("assigning new, free IP address %s", ip)
                    chosen = True
                    break

            # 4. Reuse old valid IP address
            if not chosen:
                ip = sorted(network_hosts, key=lambda host: host.last_used)[0].ip
                if not self.is_valid_client_address(ip):
                    raise ValueError(
                        f'Re-used IP address "{ip.compressed}" is invalid in the current pool'
                    )
                self.log.debug("reusing old IP address %s", ip)

        assert ip is not None
        host = Host(mac, ip, getattr(packet, "host_name", ""), datetime.utcnow())
        if not any(host.ip == ip for host in known_hosts):
            self.log.debug("adding new host %s", host)
            await self.hosts.add(host)
        else:
            self.log.debug("replacing host %s", host)
            await self.hosts.replace(host)

        return ip

    async def broadcast(self, packet: WriteBOOTPPacket):
        self.log.debug("broadcasting packet %s", packet)
        broadcast_addr = self.broadcast_address.compressed, 68
        for address in available_addresses():
            self.log.debug(
                "sending packet to %s and broadcast %s", address, self.broadcast_address
            )
            packet.server_identifier = address
            address = IPv4Address(address)
            data = packet.to_bytes()
            async with broadcast(self.loop, address, 67) as dt:
                dt.sendto(data, (address.compressed, 67))
                dt.sendto(data, broadcast_addr)
