""" A Python DHCP server with pluggable lease backends """

import logging
import select
import ipaddress
import socket
import netifaces
from dhcp.utils import format_mac
from dhcp.packet import Packet, PacketType, PacketOption, Option, MessageType

logger = logging.getLogger("dhcp")

DHCP_LISTEN_PORT = 67


def lease_to_packet(lease, src_packet, message_type, sname):
    """ Generate a DHCP packet based on a `Lease` and the incomming
    packet that inspired the lease.
    """

    new = Packet()
    new.clone_from(src_packet)
    new.op = PacketType.BOOTREPLY
    new.yiaddr = lease.client_ip

    if lease.tftp_server:
        new.siaddr = ipaddress.IPv4Address(lease.tftp_server)

    new.options.append(Option(PacketOption.MESSAGE_TYPE, message_type))
    new.options.append(Option(PacketOption.SERVER_IDENT, sname))
    new.options += lease.options
    return new


class Server():
    """ A DHCP server """

    # pylint: disable=too-many-instance-attributes

    def __init__(self, backend, interface="*", server_name=None, authoritative=False):
        self.backend = backend
        self.interface = interface
        self.server_name = server_name or socket.gethostname()
        self.authoritative = authoritative

        self.ipaddrs = dict()
        self.subnets = dict()
        self.requests = {}
        self.handlers = {
            MessageType.DHCPDISCOVER: self.handle_discover,
            MessageType.DHCPREQUEST: self.handle_request,
            MessageType.DHCPRELEASE: self.handle_release,
        }

        self.setup_sockets()

    def serve(self):
        """ Start the server and process incomming requests """

        while True:
            rlist, _, _ = select.select(list(self.ipaddrs.keys()), [], [])
            if rlist:
                for sock in rlist:
                    data, address = sock.recvfrom(1024)
                    _, src_port = address

                    if src_port not in [67, 68]:
                        continue

                    packet = Packet()
                    packet.inaddr = self.ipaddrs[sock]
                    packet.unpack(data)

                    message_type = packet.find_option(
                        PacketOption.MESSAGE_TYPE
                    )
                    if not message_type:
                        logger.debug(
                            "Malformed packet: no MESSAGE_TYPE option"
                        )
                        continue

                    handler = self.handlers.get(message_type.value)
                    if handler:
                        handler(sock, packet)

    def handle_discover(self, sock, packet):
        """ Handle a DHCP Discover message """

        logger.info("%s: Received DISCOVER", format_mac(packet.chaddr))

        try:
            lease = self.backend.offer(packet)
        except Exception as ex:
            logger.error("Backend produced an error handling discover: %s", str(ex))
            lease = None

        if not lease:
            return

        if 66 in packet.requested_options and 67 in packet.requested_options:
            logger.info("Boot parameters requested")
            logger.info(packet.requested_options)
            logger.info("Booting client arch: %s", packet.client_arch)
            self.backend.boot_request(packet, lease)

        self.requests[packet.xid] = lease
        offer = lease_to_packet(
            lease, packet, MessageType.DHCPOFFER, self.ipaddrs[sock]
        )

        logger.info("%s: Sending OFFER of %s",
                    format_mac(packet.chaddr), str(lease.client_ip))
        offer.dump()
        self.send_packet(sock, offer)

    def handle_request(self, sock, packet):
        """ Handle a DHCP Request message """

        logger.info("%s: Received REQUEST", format_mac(packet.chaddr))
        offer = self.requests.pop(packet.xid, None)

        if offer is None:
            try:
                offer = self.backend.offer(packet)
            except Exception as ex:
                logger.error("Backend produced an error handling request: %s", str(ex))

        if self.authoritative and offer is None:
            nack = Packet()
            nack.clone_from(packet)
            nack.op = PacketType.BOOTREPLY
            nack.htype = packet.htype
            nack.yiaddr = 0
            nack.siaddr = 0
            nack.options.append(Option(PacketOption.MESSAGE_TYPE,
                                       MessageType.DHCPNAK))

            logger.info("%s: Sending NACK", format_mac(packet.chaddr))
            self.send_packet(sock, nack)
            return

        lease = self.backend.acknowledge(packet, offer)
        ack = lease_to_packet(lease, packet, MessageType.DHCPACK,
                              self.ipaddrs[sock])

        logger.info("%s: Sending ACK of %s",
                    format_mac(packet.chaddr), str(lease.client_ip))

        ack.dump()
        self.send_packet(sock, ack)

    def handle_release(self, packet):
        """ Handle a DHCP release message """
        self.backend.release(packet)

    def setup_sockets(self):
        """ Setup a socket for each interface to serve on """
        # pylint: disable=I1101

        def _make_sock(iface):
            try:
                addrs = netifaces.ifaddresses(iface)
            except ValueError:
                logger.error("Invalid interface %s", iface)
                return

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM,
                                 socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_BINDTODEVICE,
                str(iface + "\0").encode("utf-8"),
            )

            if netifaces.AF_INET in addrs:
                ipaddr = addrs[netifaces.AF_INET][0]["addr"]
                mask = addrs[netifaces.AF_INET][0]["netmask"]
                network = ipaddress.IPv4Network("%s/%s" % (ipaddr, mask),
                                                strict=False)
                self.ipaddrs[sock] = ipaddress.IPv4Address(ipaddr)
                self.subnets[sock] = network

            sock.bind(("", DHCP_LISTEN_PORT))

        if self.interface in ("", "*"):
            # Listen on all interfaces
            for iface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    _make_sock(iface)

        else:
            if isinstance(self.interface, (list, tuple)):
                for _i in self.interface:
                    _make_sock(_i)
            else:
                _make_sock(self.interface)

    @staticmethod
    def send_packet(sock, packet):
        """ Send packet to client """

        dst = "255.255.255.255"
        dport = 68

        if not packet.ciaddr.is_unspecified:
            dst = str(packet.ciaddr)

        if not packet.giaddr.is_unspecified:
            dst = str(packet.giaddr)
            dport = 67

        sock.sendto(packet.pack(), (dst, dport))
