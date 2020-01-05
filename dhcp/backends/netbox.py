""" Netbox DHCP backend """

import os
import logging
import ipaddress

from dhcp.backends.base import DHCPBackend
from dhcp.lease import Lease
from dhcp.settings import SETTINGS

logger = logging.getLogger(__name__)


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
        self.url = url or SETTINGS.netbox_url or os.getenv("NETBOX_URL", None)
        self.token = token or SETTINGS.netbox_token or os.getenv("NETBOX_TOKEN", None)

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

    def boot_request(self, packet, lease):
        """ Add boot params to the supplied lease """

        device, _ = self._find_device_and_interface(packet)

        if not device.custom_fields.get("redeploy", False):
            return

        confirmation = device.custom_fields.get("confirm_redeploy", "")
        if confirmation != device.name:
            logger.warning("Redeploy set on device %s, but confirmation does not match: %s",
                           device.name, confirmation)
            return

        config_context = device.config_context
        boot_infra = device.config_context.get("boot_infrastructure", {})
        tftp_server = boot_infra.get("tftp_server", None)
        boot_filepath = None

        if packet.client_arch in ("Intel x86PC",):
            boot_filepath = boot_infra.get("pxe_boot_file", None)
        if packet.client_arch in ("EFI BC",):
            boot_filepath = boot_infra.get("uefi_boot_file", None)

        if tftp_server and boot_filepath:
            lease.tftp_server = tftp_server
            lease.tftp_filename = boot_filepath

        logger.info(lease)

    def _find_lease(self, packet):
        return self._find_static_lease(packet)

    def _find_static_lease(self, packet):
        device, interface = self._find_device_and_interface(packet)

        if interface is None:
            return None

        if device is None:
            return None

        if hasattr(interface, "lag") and interface.lag is not None:
            # Link aggregation interface member
            interface = interface.lag

        prefix = self._find_prefix(packet.receiving_ip)
        if not prefix:
            logger.warning("No prefix configured containing IP %s", packet.receiving_ip)
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

        router_ip = self.client.ipam.ip_addresses.filter(parent=str(prefix), tag="gateway") or None
        if router_ip:
            router_ip = ipaddress.IPv4Interface(router_ip[0]).ip

        dns_server_ips = device.config_context.get("dns_servers", [])
        dns_server_ips = [ipaddress.ip_address(i) for i in dns_server_ips]
        dns_server_ips = dns_server_ips or [router_ip]

        lease = Lease(
            client_ip=offer_ip.ip,
            client_mask=offer_ip.network.netmask,
        )
        if router_ip:
            lease.router = router_ip
        if dns_server_ips:
            lease.dns_addresses = dns_server_ips

        return lease

    def _find_device_and_interface(self, packet):
        interface = self.client.dcim.interfaces.get(mac_address=packet.client_mac.upper()) or \
            self.client.virtualization.interfaces.get(mac_address=packet.client_mac.upper())
        if interface is None:
            return None, None

        device = interface.device if hasattr(interface, "device") else interface.virtual_machine
        device.full_details()

        return device, interface

    def _find_prefix(self, ipaddr):
        """ Return the smallest prefix containing the ip address """
        ipaddr = str(ipaddr)
        prefixes = self.client.ipam.prefixes.filter(contains=ipaddr)
        if not prefixes:
            return None

        prefixes.sort(key=lambda p: int(p.prefix.split("/")[-1]))
        return prefixes[0]

    @classmethod
    def add_backend_args(cls):
        """ Add argparse arguments for this backend """
        group = SETTINGS.add_argument_group(title=cls.NAME, description=cls.__doc__)
        group.add_argument("--netbox-url", help="The Netbox instance URL")
        group.add_argument("--netbox-token", help="The netbox authentication token")


try:
    import pynetbox
    NetboxBackend.add_backend_args()
except ImportError as ex:
    NetboxBackend.DISABLED = str(ex)
