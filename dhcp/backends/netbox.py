""" Netbox DHCP backend """

import os
import logging
import ipaddress

from dhcp.backends.base import DHCPBackend
from dhcp.lease import Lease

LOGGER = logging.getLogger(__name__)


class NetboxBackend(DHCPBackend):
    """ Manage DHCP leases from Netbox """

    NAME = "netbox"

    @property
    def client(self):
        """ Create and cache a netbox client on first use """

        if self._client:
            return self._client

        self._client = pynetbox.api(self.url, self.token)
        return self._client

    def __init__(self, url=None, token=None):
        self.url = url or os.getenv("NETBOX_URL", None)
        self.token = token or os.getenv("NETBOX_TOKEN", None)

        if not self.url and self.token:
            raise RuntimeError("url and token required for netbox backend")

        self._client = None

    def offer(self, packet):
        """ Generate an appropriate offer based on packet.  Return a dhcp.lease.Lease object """
        return self._find_lease(packet)

    def acknowledge(self, packet, offer):
        """ Acknowledge the request for the previously provided offer.  If the offer is for a
        dynamic address, set the expiry time accordingly.
        """

        return offer

    def release(self, packet):
        """ Action release request as per packet """

    def _find_lease(self, packet):
        return self._find_static_lease(packet)

    def _find_static_lease(self, packet):
        interface = self.client.dcim.interfaces.get(mac_address=packet.client_mac.upper()) or \
            self.client.virtualization.interfaces.get(mac_address=packet.client_mac.upper())
        if interface is None:
            return None

        device = interface.device if hasattr(interface, "device") else interface.virtual_machine
        if device is None:
            return None

        if hasattr(interface, "lag") and interface.lag is not None:
            # Link aggregation interface member
            interface = interface.lag

        prefix = self._find_prefix(packet.receiving_ip)
        if not prefix:
            LOGGER.warning("No prefix configured containing IP %s", packet.receiving_ip)
            return None

        ip_addresses = self.client.ipam.ip_addresses.filter(interface_id=interface.id)

        offer_ip = None
        for ip in ip_addresses:
            ip_interface = ipaddress.ip_interface(ip.address)
            if ip_interface.ip in ipaddress.ip_network(prefix.prefix):
                offer_ip = ip_interface
                break
        else:
            return None

        router_ip = list(offer_ip.network.hosts())[0]
        dns_server_ips = device.config_context.get("dns_servers", [])
        dns_server_ips = [ipaddress.ip_address(i) for i in dns_server_ips]
        dns_server_ips = dns_server_ips or [router_ip]

        lease = Lease(
            client_ip=offer_ip.ip,
            client_mask=offer_ip.network.netmask,
            router=router_ip,
            dns_addresses=dns_server_ips,
        )

        return lease

    def _find_prefix(self, ipaddr):
        """ Return the smallest prefix containing the ip address """
        ipaddr = str(ipaddr)
        prefixes = self.client.ipam.prefixes.filter(contains=ipaddr)
        if not prefixes:
            return None

        prefixes.sort(key=lambda p: int(p.prefix.split("/")[-1]))
        return prefixes[0]


try:
    import pynetbox
except ImportError as ex:
    NetboxBackend.DISABLED = str(ex)
