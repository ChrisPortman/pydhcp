""" PyTest the dhcp.packet module """

import os
import enum
import ipaddress

import pytest
from .pcap import Pcap
from scapy.all import rdpcap, DHCPOptions
from dhcp.packet import Packet


SAMPLE_DATA_DIR = os.path.join(
    os.path.dirname(os.path.realpath(__file__)),
    "samples",
)

SCAPY_DHCP_OPTIONS_MAP = {
    v if isinstance(v, str) else v.name: i for i, v in DHCPOptions.items()
}


@pytest.fixture
def load_from_pcap():
    """ Factory returns a funcion that reads in data from a pcap """
    def _load_from_pcap(msgtype, subtype=None, platform="centos"):
        filename = ".".join([p for p in [msgtype, subtype, platform, "pcap"] if p is not None])
        filepath = os.path.join(SAMPLE_DATA_DIR, filename)
        if os.path.isfile(filepath):
            return rdpcap(filepath)

        raise RuntimeError("No sample file: {0}".format(filepath))

    return _load_from_pcap


def test_discover_centos(load_from_pcap):
    """ Test ia decoded discover packet is valid compared to scapy's interpretation """

    pcappkt = load_from_pcap("discover", "selecting")[0]
    dhcp = pcappkt["BOOTP"]
    print(dhcp.show())

    options = {}
    for opt in dhcp["DHCP options"].options:
        if opt == "end":
            break
        options[opt[0]] = opt[1]

    packet = Packet()
    packet.unpack(bytes(dhcp))
    packet.dump()

    # raw field values
    assert packet.op == dhcp.op
    assert packet.htype == dhcp.htype
    assert packet.hlen == dhcp.hlen
    assert packet.hops == dhcp.hops
    assert packet.xid == dhcp.xid
    assert packet.secs == dhcp.secs
    assert packet.flags == dhcp.flags
    assert packet.ciaddr == ipaddress.ip_address(dhcp.ciaddr)
    assert packet.yiaddr == ipaddress.ip_address(dhcp.yiaddr)
    assert packet.siaddr == ipaddress.ip_address(dhcp.siaddr)
    assert packet.giaddr == ipaddress.ip_address(dhcp.giaddr)
    assert packet.chaddr == dhcp.chaddr[:packet.hlen]
    assert packet.sname == dhcp.sname.decode("ascii").strip("\x00")
    assert packet.file == dhcp.file.decode("ascii").strip("\x00")
    assert packet.cookie == dhcp.options  # b"c\x82Sc"

    for opt, val in options.items():
        packet_opt = packet.find_option(SCAPY_DHCP_OPTIONS_MAP[opt])
        assert packet_opt is not None

        packet_opt_val = packet_opt.value
        if isinstance(packet_opt_val, enum.IntEnum):
            packet_opt_val = packet_opt_val.value

        if isinstance(val, bytes):
            val = val.decode("ascii")

        if opt == "param_req_list":
            packet_opt_val = [e.value for e in packet_opt_val]
            print("{0}: {1} <= {2}".format(opt, str(packet_opt_val), str(val)))
            assert set(packet_opt_val) <= set(val)
        else:
            print("{0}: {1} == {2}".format(opt, str(packet_opt_val), str(val)))
            assert str(packet_opt_val) == str(val)
