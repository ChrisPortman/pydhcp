""" DHCP Packets """

import sys
import enum
import ipaddress
import socket
import struct
import logging
from dhcp.utils import first_or_default, format_mac


MAGIC_COOKIE = b"\x63\x82\x53\x63"
LOGGER = logging.getLogger(__name__)


class PacketType(enum.IntEnum):
    """DHCP packet types"""
    BOOTREQUEST = 1
    BOOTREPLY = 2


class PacketFlags(enum.IntEnum):
    """DHCP Packet Flags"""
    BROADCAST = 1 << 15


class HardwareAddressType(enum.IntEnum):
    """DHCP hardware address types"""
    ETHERNET = 1
    IEEE802 = 6


class MessageType(enum.IntEnum):
    """DHCP message types"""
    DHCPDISCOVER = 1
    DHCPOFFER = 2
    DHCPREQUEST = 3
    DHCPDECLINE = 4
    DHCPACK = 5
    DHCPNAK = 6
    DHCPRELEASE = 7
    DHCPINFORM = 8


class PacketOption(enum.IntEnum):
    """DHCP options"""
    SUBNET_MASK = 1
    ROUTER = 3
    TIME_SERVER = 4
    NAME_SERVER = 5
    DOMAIN_NAME_SERVER = 6
    LOG_SERVER = 7
    QUOTE_SERVER = 8
    LPR_SERVER = 9
    IMPRESS_SERVER = 10
    RESOURCE_LOCATION_SERVER = 11
    HOST_NAME = 12
    DOMAIN_NAME = 15
    ROOT_PATH = 17
    EXTENSIONS_PATH = 18
    BROADCAST = 28
    REQUESTED_IP = 50
    LEASE_TIME = 51
    MESSAGE_TYPE = 53
    SERVER_IDENT = 54
    PARAMETER_REQUEST_LIST = 55
    ERROR_MESSAGE = 56
    MAX_MESSAGE_SIZE = 57
    CLASS_IDENT = 60
    CLIENT_IDENT = 61
    TFTP_SERVER = 66
    TFTP_FILENAME = 67
    AGENT_INFORMATION_OPTION = 82
    CLIENT_ARCH_TYPE = 93
    CLIENT_NETWORK_INTERFACE_ID = 94
    CLIENT_MACHINE_IDENTIFIER = 97
    STATIC_ROUTES = 121
    WPAD_URL = 252


class Packet():
    """DCHP Packet"""

    # pylint: disable=too-many-instance-attributes

    @property
    def message_type(self):
        """ Return the message type option name """
        option = self.find_option(PacketOption.MESSAGE_TYPE)
        return option.identifier.name

    @property
    def receiving_ip(self):
        """ The IP address at which the packet was first received.
        returns the GIADDR if populated else the server IP receiving
        the packet.  Assists in determining the origin subnet of the client
        """
        if self.giaddr != ipaddress.ip_address("0.0.0.0"):
            return self.giaddr

        return self.inaddr

    @property
    def client_mac(self):
        """ Return the client mac in a readable form """
        return format_mac(self.chaddr)

    @property
    def client_hostname(self):
        """ Returns the client hostname if present otherwise None """
        hostname = self.find_option(PacketOption.HOST_NAME)
        return hostname.value if hostname else None

    @property
    def client_arch(self):
        """ Return the arch type of the client """

        arches = ["Intel x86PC", "NEC/PC98", "EFI Itanium", "DEC Alpha"
                  "Arc x86", "Intel Learn Client", "EFI IA32", "EFI BC"
                  "EFI Xscale", "EFI x86-64"]

        class_id = self.find_option(PacketOption.CLASS_IDENT)
        if class_id and len(class_id.value) == 32:
            arch_id = int(class_id.value.decode().split(":")[2])
            return arches[arch_id]

        return "unknown"

    @property
    def requested_options(self):
        """ Returns the requested options """
        options = self.find_option(PacketOption.PARAMETER_REQUEST_LIST)
        return options.value if options else []

    def __init__(self):
        self.op = None  # pylint: disable=C0103
        self.htype = HardwareAddressType.ETHERNET
        self.hlen = 6
        self.hops = 0
        self.secs = 0
        self.flags = PacketFlags.BROADCAST
        self.xid = None
        self.srciaddr = ipaddress.ip_address("0.0.0.0")
        self.inaddr = ipaddress.ip_address("0.0.0.0")
        self.ciaddr = ipaddress.ip_address("0.0.0.0")
        self.yiaddr = ipaddress.ip_address("0.0.0.0")
        self.siaddr = ipaddress.ip_address("0.0.0.0")
        self.giaddr = ipaddress.ip_address("0.0.0.0")
        self.chaddr = b"\x00\x00\x00\x00\x00\x00"
        self.cookie = MAGIC_COOKIE
        self.sname = ""
        self.file = ""
        self.options = []

    def clone_from(self, other):
        """Assign attributes from those of other"""
        self.htype = other.htype
        self.hlen = other.hlen
        self.hops = other.hops
        self.xid = other.xid
        self.secs = other.secs
        self.flags = other.flags
        self.chaddr = other.chaddr
        self.giaddr = other.giaddr
        self.ciaddr = other.ciaddr

        arch_type_opt = other.find_option(PacketOption.CLIENT_ARCH_TYPE)
        if arch_type_opt:
            self.options.append(arch_type_opt)

        client_machine_id_opt = other.find_option(PacketOption.CLIENT_MACHINE_IDENTIFIER)
        if client_machine_id_opt:
            self.options.append(client_machine_id_opt)

        client_network_interface_id_opt = other.find_option(
            PacketOption.CLIENT_NETWORK_INTERFACE_ID
        )

        if client_network_interface_id_opt:
            self.options.append(client_network_interface_id_opt)

    def response_from_lease(self, lease):
        """ Generate a response packet from lease """
        new = Packet()
        new.clone_from(self)
        new.op = PacketType.BOOTREPLY
        new.yiaddr = lease.client_ip

        if lease.tftp_server:
            new.siaddr = ipaddress.IPv4Address(lease.tftp_server)

        if lease.tftp_filename:
            new.file = lease.tftp_filename

        if self.find_option(PacketOption.MESSAGE_TYPE).value == MessageType.DHCPDISCOVER:
            new.options.append(Option(PacketOption.MESSAGE_TYPE, MessageType.DHCPOFFER))
        else:
            new.options.append(Option(PacketOption.MESSAGE_TYPE, MessageType.DHCPACK))

        new.options.append(Option(PacketOption.SERVER_IDENT, self.inaddr))
        new.options += lease.options
        return new

    def unpack(self, payload):
        """Unpack the wireline data into attributes"""
        self.op, self.htype, self.hlen, self.hops = struct.unpack_from("BBBB", payload, 0)
        self.xid = struct.unpack_from("!I", payload, 4)[0]
        self.secs, self.flags = struct.unpack_from("!HH", payload, 8)
        self.ciaddr = ipaddress.ip_address(struct.unpack_from("!I", payload, 12)[0])
        self.yiaddr = ipaddress.ip_address(struct.unpack_from("!I", payload, 16)[0])
        self.siaddr = ipaddress.ip_address(struct.unpack_from("!I", payload, 20)[0])
        self.giaddr = ipaddress.ip_address(struct.unpack_from("!I", payload, 24)[0])
        self.chaddr = struct.unpack_from("16s", payload, 28)[0][:self.hlen]
        self.sname = struct.unpack_from("64s", payload, 44)[0].decode("ascii").strip("\x00")
        self.file = struct.unpack_from("128s", payload, 108)[0].decode("ascii").strip("\x00")
        self.cookie = struct.unpack_from("4s", payload, 236)[0]

        self.op = PacketType(self.op)

        offset = 240
        while offset < len(payload):
            code = struct.unpack_from("B", payload, offset)[0]
            offset += 1

            if code == 0:
                continue

            if code == 255:
                break

            length = struct.unpack_from("B", payload, offset)[0]
            offset += 1
            value = struct.unpack_from("{0}s".format(length), payload, offset)[0]
            offset += length

            try:
                optid = PacketOption(code)
                self.options.append(Option(optid, packed=value))
            except ValueError:
                LOGGER.debug("Unknown DHCP option %s, skipped", str(code))
                continue

    def pack(self):
        """Pack the attributes into wireline data"""
        result = bytearray(bytes(240))
        struct.pack_into("BBBB", result, 0, int(self.op), self.htype, self.hlen, self.hops)
        struct.pack_into("!I", result, 4, self.xid)
        struct.pack_into("!H", result, 8, self.secs)
        struct.pack_into("!H", result, 10, self.flags)
        struct.pack_into("!II", result, 12, int(self.ciaddr), int(self.yiaddr))
        struct.pack_into("!II", result, 20, int(self.siaddr), int(self.giaddr))
        struct.pack_into("12s", result, 28, self.chaddr)
        struct.pack_into("64s", result, 44, self.sname.encode("ascii"))
        struct.pack_into("128s", result, 108, self.file.encode("ascii"))
        struct.pack_into("4s", result, 236, MAGIC_COOKIE)

        for i in self.options:
            packed = i.pack()
            result += struct.pack(
                "BB{0}s".format(len(packed)),
                int(i.identifier),
                len(packed),
                packed,
            )

        result += b"\xff"

        if len(result) < 300:
            result += b"\x00" * (300 - len(result))

        return result

    def dump(self, out=sys.stdout):
        """Print the packet attributes"""
        print("Op: {0}".format(self.op.name), file=out)
        print("Flags: {0}".format(self.flags), file=out)
        print("Client address: {0}".format(self.ciaddr), file=out)
        print("Your address: {0}".format(self.yiaddr), file=out)
        print("Server address: {0}".format(self.siaddr), file=out)
        print("Gateway address: {0}".format(self.giaddr), file=out)
        print(
            "Client hardware address: {0}".format(
                ":".join("%02x" % b for b in self.chaddr[:6])
            ),
            file=out
        )
        print("XID: {0}".format(self.xid), file=out)
        print("Sname: {0}".format(self.sname), file=out)
        print("Magic cookie: {0}".format(self.cookie), file=out)
        print("Options:", file=out)
        for _i in self.options:
            print("\t{0} = {1}".format(_i.identifier.name, _i.value), file=out)

    def find_option(self, opt):
        """Return a specific option"""
        return first_or_default(lambda x: x.identifier == opt, self.options)


class Option():
    """ DHCP Option"""

    # pylint: disable=too-many-return-statements

    def __init__(self, identifier, value=None, packed=None):
        self.identifier = identifier
        self.value = None

        if value is not None:
            self.value = value
            return

        if packed:
            self.unpack(packed)

    def __repr__(self):
        return "Option(identifier={}, value={})".format(str(self.identifier), str(self.value))

    @staticmethod
    def __pack_route(subnet, gateway):
        result = struct.pack("B", subnet.prefixlen)

        octets = int(subnet.prefixlen / 8)
        if subnet.prefixlen % 8:
            octets += 1
        result += subnet.network_address.packed[:octets]

        result += gateway.packed
        return result

    def unpack(self, value):  # noqa: C901
        """Unpack the option from wireline data"""
        if self.identifier in (
                PacketOption.ROUTER, PacketOption.REQUESTED_IP,
                PacketOption.SUBNET_MASK, PacketOption.SERVER_IDENT,
                PacketOption.BROADCAST,
        ):
            self.value = ipaddress.ip_address(value)
            return

        if self.identifier in (
                PacketOption.HOST_NAME, PacketOption.DOMAIN_NAME,
                PacketOption.TFTP_SERVER, PacketOption.WPAD_URL,
                PacketOption.TFTP_FILENAME, PacketOption.CLIENT_MACHINE_IDENTIFIER,
        ):
            self.value = value.decode("ascii")
            if self.identifier == PacketOption.HOST_NAME:
                self.value = self.value.strip(" \t\r\n\0")
            return

        if self.identifier == PacketOption.ERROR_MESSAGE:
            self.value = value.decode("utf-8")
            return

        if self.identifier in (
                PacketOption.DOMAIN_NAME_SERVER, PacketOption.LOG_SERVER,
                PacketOption.TIME_SERVER, PacketOption.QUOTE_SERVER,
                PacketOption.LPR_SERVER, PacketOption.IMPRESS_SERVER,
                PacketOption.RESOURCE_LOCATION_SERVER
        ):
            self.value = []
            for i, in struct.iter_unpack("I", value):
                self.value.append(ipaddress.ip_address(socket.ntohl(i)))

            return

        if self.identifier == PacketOption.MESSAGE_TYPE:
            self.value = MessageType(value[0])
            return

        if self.identifier == PacketOption.LEASE_TIME:
            self.value = struct.unpack("!I", value)[0]
            return

        if self.identifier == PacketOption.CLIENT_ARCH_TYPE:
            self.value = struct.unpack("!H", value)[0]
            return

        if self.identifier == PacketOption.PARAMETER_REQUEST_LIST:
            self.value = []
            for i, in struct.iter_unpack("B", value):
                try:
                    self.value.append(PacketOption(i))
                except ValueError:
                    continue

            return

        self.value = value

    def pack(self):  # noqa: C901
        """Pack the option into the wireline data"""
        if self.identifier in (
                PacketOption.ROUTER, PacketOption.REQUESTED_IP,
                PacketOption.SUBNET_MASK, PacketOption.SERVER_IDENT,
                PacketOption.BROADCAST
        ):
            return self.value.packed

        if self.identifier in (
                PacketOption.DOMAIN_NAME_SERVER, PacketOption.LOG_SERVER,
                PacketOption.TIME_SERVER, PacketOption.QUOTE_SERVER,
                PacketOption.LPR_SERVER, PacketOption.IMPRESS_SERVER,
                PacketOption.RESOURCE_LOCATION_SERVER
        ):
            return b"".join(i.packed for i in self.value)

        if self.identifier in (
                PacketOption.HOST_NAME, PacketOption.DOMAIN_NAME,
                PacketOption.WPAD_URL, PacketOption.TFTP_SERVER,
                PacketOption.TFTP_FILENAME, PacketOption.CLASS_IDENT,
                PacketOption.CLIENT_MACHINE_IDENTIFIER,
        ):
            return self.value.encode("ascii")

        if self.identifier == PacketOption.ERROR_MESSAGE:
            return self.value.encode("utf-8")

        if self.identifier == PacketOption.CLIENT_IDENT:
            return struct.pack("!B6s", 1, self.value)

        if self.identifier == PacketOption.MESSAGE_TYPE:
            return bytes([int(self.value)])

        if self.identifier == PacketOption.LEASE_TIME:
            return struct.pack("!I", self.value)

        if self.identifier == PacketOption.STATIC_ROUTES:
            return b"".join(self.__pack_route(s, g) for s, g in self.value)

        if self.identifier == PacketOption.PARAMETER_REQUEST_LIST:
            return b"".join(struct.pack("B", int(i)) for i in self.value)

        if self.identifier == PacketOption.CLIENT_ARCH_TYPE:
            return struct.pack("!H", self.value)

        if self.identifier == PacketOption.CLIENT_NETWORK_INTERFACE_ID:
            return self.value

        return None
