""" pcap parser """

import struct
import ipaddress

MAGIC_NUMBER = 0xa1b2c3d4
MAGIC_NUMBER_USEC = 0xa1b23c4d

GLOBAL_HEADER_LEN = 24
PACKET_HEADER_LEN = 16

def btoh(bytestr):
    return " ".join(["%02X" % b for b in bytestr])


class Layer(object):
    """ OSI Layer 2 - 4 """

    LAYOUT = []

    def parse(self, data):
        """ Parse data according to the layout """

        offset = 0

        for field in self.LAYOUT:
            name, sformat = field
            if sformat:
                struct_o = struct.Struct(sformat)
                value = struct_o.unpack_from(data, offset)[0]
                offset += struct_o.size
                setattr(self, name, value)

    def __repr__(self):
        return "{0}({1})".format(
            self.__class__.__name__,
            ", ".join(["{0}: {1}".format(k, btoh(v) if isinstance(v, bytes) else v) for k, v in self.__dict__.items()])
        )


class Pcap(Layer):
    """ PCAP object """

    LAYOUT = [
        ("magic_number", "I"),
        ("version_major", "H"),
        ("version_minor", "H"),
        ("timezone", "i"),
        ("sigfigs", "I"),
        ("snaplen", "I"),
        ("network", "I"),
    ]

    def __init__(self, path):
        self.path = path
        magic_number = None
        version_major = None
        version_minor = None
        timezone = None
        sigfigs = None
        snaplen = None
        network = None

        _usec_enabled = False

        with open(path, 'rb') as _h:
            self.parse(_h.read(GLOBAL_HEADER_LEN))

    def parse(self, data):
        """ Parse data according to the layout """

        super().parse(data)
        if self.magic_number not in (MAGIC_NUMBER, MAGIC_NUMBER_USEC):
            raise ValueError("Invalid PCAP file: Magic number is incorrect")

        if self.magic_number == MAGIC_NUMBER_USEC:
            self._usec_enabled = True

        fcs = struct.unpack_from(self.LAYOUT[-1][1], data, len(data) - 4)[0]
        setattr(self, "fcs", fcs)

    def packets(self):
        """ packet generator """

        with open(self.path, "rb") as _h:
            _h.read(GLOBAL_HEADER_LEN)

            while True:
                pkt = Packet(_h)
                yield pkt
                break


class Packet(Layer):
    """ A pcap packet """

    LAYOUT = [
        ("ts_sec", "I"),
        ("ts_usec", "I"),
        ("incl_len", "I"),
        ("orig_len", "I"),
    ]

    def __init__(self, ofile):
        self.ts_sec = None
        self.ts_usec = None
        self.incl_len = None
        self.orig_len = None
        self.data = None

        self.parse(ofile.read(PACKET_HEADER_LEN))
        self.data = Ethernet(ofile.read(self.incl_len))

    def parse(self, data):
        """ Parse data according to the layout """
        super().parse(data)


class Ethernet(Layer):
    """ Ethernet encapsulation decoder """

    LAYOUT = [
        ("destination_address", "6s"),
        ("source_address", "6s"),
        ("type", "2s"),
        ("fcs", None),
    ]

    def __init__(self, data):
        self.destination_address = None
        self.source_address = None
        self.type = None
        self.fcs = None
        self.data = None

        self.parse(data)

    def parse(self, data):
        """ Parse data according to the layout """
        super().parse(data)
        setattr(self, "fcs", struct.unpack_from("I", data, len(data) - 4)[0])

        if self.type == b"\x08\x00":
            self.data = InternetProtocolV4(data[14:-4])

class InternetProtocolV4(Layer):
    """ IPv4 encapsulation header """

    LAYOUT = [
        ("version", "!B"),
        ("ihl", None),
        ("dscp", "!B"),
        ("ecn", None),
        ("total_lenth", "!H"),
        ("identification", "!H"),
        ("flags", "!H"),
        ("fragment_offset", None),
        ("ttl", "!B"),
        ("protocol", "!B"),
        ("header_checksum", "!H"),
        ("source_address", "!I"),
        ("destination_address", "!I"),
        ("options", None),
    ]

    def __init__(self, data):
        self.version = None
        self.ihl = None      # Internet Header Length
        self.dscp = None     # Differentiated Services Code Point
        self.ecn = None      # Explicit Congestion Notification
        self.total_lenth = None
        self.identification = None
        self.flags = None
        self.fragment_offset = None
        self.ttl = None
        self.protocol = None  # 1 = ICMP, 6 = TCP, 17 = UDP
        self.header_checksum = None
        self.source_address = None
        self.destination_address = None
        self.options = None
        self.data = None

        self.parse(data)

    def parse(self, data):
        """ Parse data according to the layout """

        super().parse(data)
        self.ihl = self.version & 15
        self.version = self.version >> 4
        self.ecn = self.dscp & 3
        self.dscp = self.dscp >> 2
        self.fragment_offset = self.flags & 2 ** 13
        self.flags = self.flags >> 13

        if self.ihl > 5:
            option_bytes = (self.ihl - 5) * 4
            self.options = data[20:20 + option_bytes]

        self.source_address = ipaddress.ip_address(self.source_address)
        self.destination_address = ipaddress.ip_address(self.destination_address)

        if self.protocol == 17:
            self.data = UDP(data[self.ihl * 4:])


class UDP(Layer):
    """ UDP Protocol packet """

    LAYOUT = [
        ("source_port", "!H"),
        ("destination_port", "!H"),
        ("length", "!H"),
        ("checksum", "!H"),
    ]

    def __init__(self, data):
        self.source_port = None
        self.destination_port = None
        self.length = None
        self.checksum = None
        self.data = data[8:]

        self.parse(data)



