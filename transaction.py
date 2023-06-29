from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from .packets import ReadBOOTPPacket, WriteBOOTPPacket

if TYPE_CHECKING:
    from ..dhcp.server import DHCPServer


class Transaction:
    def __init__(self, server: DHCPServer) -> None:
        self.server = server
        self.packets = []
        self.done_time = datetime.utcnow() + server.transaction_length
        self.done = False
        self.log = server.log

    @property
    def is_done(self) -> bool:
        return self.done or self.done_time < datetime.utcnow()

    def close(self):
        self.done = True

    async def send_offer(self, packet: ReadBOOTPPacket):
        # https://tools.ietf.org/html/rfc2131
        self.log.debug("sending offer for packet %s", packet)
        offer = WriteBOOTPPacket(self.server.settings)
        offer.parameter_order = getattr(packet, "parameter_request_list", [])
        mac = packet.client_mac_address
        offer.your_ip_address = await self.server.get_ip_address(packet)
        offer.transaction_id = packet.transaction_id
        offer.relay_agent_ip_address = packet.relay_agent_ip_address
        offer.client_mac_address = mac
        offer.client_ip_address = packet.client_ip_address
        offer.bootp_flags = packet.bootp_flags
        offer.ip_address_lease_time = self.server.lease_time.seconds
        offer.dhcp_message_type = "DHCPOFFER"
        offer.client_identifier = mac
        offer.subnet_mask = self.server.main_network.netmask
        self.log.info("DHCPOFFER of %s to client %s", offer.your_ip_address, mac)
        await self.server.broadcast(offer)

    async def handle_dhcp_discover(self, packet: ReadBOOTPPacket):
        if not self.is_done:
            self.log.info("DHCPDISCOVER from client %s", packet.client_mac_address)
            await self.send_offer(packet)

    async def acknowledge(self, packet: ReadBOOTPPacket):
        self.log.debug("acknowledge packet %s", packet)
        ack = WriteBOOTPPacket(self.server.settings)
        ack.parameter_order = getattr(packet, "parameter_request_list", [])
        ack.transaction_id = packet.transaction_id
        ack.bootp_flags = packet.bootp_flags
        ack.relay_agent_ip_address = packet.relay_agent_ip_address
        mac = packet.client_mac_address
        ack.client_mac_address = mac
        ack.client_ip_address = packet.client_ip_address
        ack.your_ip_address = await self.server.get_ip_address(packet)
        ack.dhcp_message_type = "DHCPACK"
        ack.ip_address_lease_time = getattr(packet, "ip_address_lease_time", self.server.lease_time.seconds)
        ack.subnet_mask = getattr(packet, "subnet_mask", self.server.main_network.netmask)
        self.log.info("DHCPACK of %s to client %s", ack.your_ip_address, mac)
        await self.server.broadcast(ack)

    async def handle_dhcp_request(self, packet: ReadBOOTPPacket):
        if not self.is_done:
            self.log.info("DHCPREQUEST from client %s", packet.client_mac_address)
            await self.server.client_has_chosen(packet)
            await self.acknowledge(packet)
            self.close()

    async def handle_dhcp_inform(self, packet: ReadBOOTPPacket):
        self.log.debug("handling dhcp inform for packet %s", packet)
        self.log.info("DHCPINFO from client %s", packet.client_mac_address)
        self.close()
        await self.server.client_has_chosen(packet)

    async def receive(self, packet: ReadBOOTPPacket):
        if packet.message_type == 1:
            callables = {
                "DHCPDISCOVER": self.handle_dhcp_discover,
                "DHCPREQUEST": self.handle_dhcp_request,
                "DHCPINFORM": self.handle_dhcp_inform,
            }
            message_type = getattr(packet, "dhcp_message_type", None)
            self.log.debug("packet %s has message_type %s", packet, message_type)
            if message_type is None or message_type not in callables:
                return False
            await callables[message_type](packet)
            return True
        return False
