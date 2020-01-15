""" Netbox DHCP backend """

import os
import logging
import ipaddress
from datetime import datetime, timedelta, timezone

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

    def __init__(self, url=None, token=None, allow_unknown_devices=False, lease_time=None):
        self.url = url or SETTINGS.netbox_url or os.getenv("NETBOX_URL", None)
        self.token = token or SETTINGS.netbox_token or os.getenv("NETBOX_TOKEN", None)
        self.lease_time = lease_time or SETTINGS.lease_time or \
            int(os.getenv("PYDHCP_LEASE_TIME", "3600"))
        self.allow_unknown_devices = allow_unknown_devices or \
            SETTINGS.netbox_allow_unknown_devices or \
            os.getenv("NETBOX_ALLOW_UNKNOWN_DEVICES", "false").lower() == "true"

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

        if device is None:
            logger.warning(
                "Received boot request from unknown machine with MAC: %s",
                packet.client_mac.upper(),
            )
            return

        if not device.custom_fields.get("redeploy", False):
            return

        confirmation = device.custom_fields.get("confirm_redeploy", "")
        if confirmation != device.name:
            logger.warning("Redeploy set on device %s, but confirmation does not match: %s",
                           device.name, confirmation)
            return

        pydhcp_configuration = device.config_context.get("pydhcp_configuration", {})
        tftp_server = pydhcp_configuration.get("tftp_server", None)
        boot_filepath = None

        if packet.client_arch in ("Intel x86PC",):
            boot_filepath = pydhcp_configuration.get("pxe_boot_file", None)
        if packet.client_arch in ("EFI BC",):
            boot_filepath = pydhcp_configuration.get("uefi_boot_file", None)

        if tftp_server and boot_filepath:
            lease.tftp_server = tftp_server
            lease.tftp_filename = boot_filepath

        logger.info(lease)

    def _find_lease(self, packet):
        prefix = self._find_prefix(packet.receiving_ip)
        if not prefix:
            logger.warning("No prefix configured containing IP %s", packet.receiving_ip)
            return None

        device, interface = self._find_device_and_interface(packet)
        if device is None and not self.allow_unknown_devices:
            return None

        return self._find_static_lease(device, interface, prefix) or \
            self._find_dynamic_lease(packet, device, interface, prefix)

    def _find_static_lease(self, device, interface, prefix):
        if device is None or interface is None:
            return None

        if hasattr(interface, "lag") and interface.lag is not None:
            # Link aggregation interface member
            interface = interface.lag

        ip_addresses = self.client.ipam.ip_addresses.filter(interface_id=interface.id)

        offer_ip = None
        for ip in ip_addresses:
            if ip.status.value == 5:
                # this is a dynamic IP
                continue

            ip_interface = ipaddress.ip_interface(ip.address)
            if ip_interface.ip in ipaddress.ip_network(prefix.prefix):
                offer_ip = ip_interface
                break
        else:
            return None

        lease = Lease(
            client_ip=offer_ip.ip,
            client_mask=offer_ip.network.netmask,
        )

        self._add_network_settings_to_lease(lease, device, prefix)

        return lease

    def _find_dynamic_lease(self, packet, device, interface, prefix):
        """ Find a dynamic IP address for the the discover/request using the following process
        - If the interface is known, and it has a 'DHCP' tagged IP assigned, realocate the same
        IP and extend the lease period.
        - If the interface is known, select an available DHCP tagged IP address and allocate it
        to the interface.
        - If the interface is not known, select an available IP and allocate it via the IP comments

        In all cases, the details of the lease (mac, and expire time) will be recorded in the
        comments of the IP address.

        An IP is considered available for dynamic allocation when the following conditions are met:
            - The IP is tagged 'DHCP'
            - The comments are empty OR the comments contain an expire time value that is in
              the past.
        """

        def _make_lease(_allocated_ip):
            expire = (datetime.now(timezone.utc) + timedelta(seconds=self.lease_time)).isoformat()
            _allocated_ip.custom_fields["pydhcp_mac"] = packet.client_mac.upper()
            _allocated_ip.custom_fields["pydhcp_expire"] = expire
            _allocated_ip.interface = interface
            _allocated_ip.save()

            allocated_ip_iface = ipaddress.ip_interface(_allocated_ip.address)
            lease = Lease(
                client_ip=allocated_ip_iface.ip,
                client_mask=allocated_ip_iface.network.netmask,
            )

            self._add_network_settings_to_lease(lease, device, prefix)
            return lease

        allocated_ip = None

        # next check for the most recently allocated IP address allocated to the MAC address.
        ip_addresses = self.client.ipam.ip_addresses.filter(
            cf_pydhcp_mac=packet.client_mac.upper(),
            parent=prefix.prefix,
            status=5,
        )
        if ip_addresses:
            ip_addresses.sort(
                key=lambda i: i.custom_fields.get("pydhcp_expire", None) or "9999"
            )

            return _make_lease(ip_addresses[-1])

        # For the last checks we need all the relevant DHCP addresses
        dhcp_addresses = self.client.ipam.ip_addresses.filter(
            status=5,
            parent=prefix.prefix,
        )

        # next check for any ip address that has no allocated MAC
        unallocated = [i for i in dhcp_addresses if not i.custom_fields.get("pydhcp_mac", None)]
        if unallocated:
            unallocated.sort(key=lambda i: i.address)
            return _make_lease(unallocated[0])

        # next check for any ip address with an expired allocation
        expired = []
        for i in dhcp_addresses:
            if not i.custom_fields.get("pydhcp_expire", None):
                continue

            try:
                expire = datetime.fromisoformat(i.custom_fields["pydhcp_expire"])
                if datetime.now(timezone.utc) > expire:
                    expired.append(i)
            except Exception:
                pass

        if expired:
            expired.sort(key=lambda i: i.custom_fields["pydhcp_expire"])
            return _make_lease(expired[0])

        # If theres no allocated IP now, we dont have any to allocate
        return None

    def _add_network_settings_to_lease(self, lease, device, prefix):
        router_ip = self.client.ipam.ip_addresses.filter(parent=str(prefix), tag="gateway") or None
        if router_ip:
            router_ip = ipaddress.IPv4Interface(router_ip[0]).ip
            lease.router = router_ip

        if device is not None:
            pydhcp_configuration = device.config_context.get("pydhcp_configuration", {})
        elif prefix.site:
            site_config_contexts = self.client.extras.config_contexts.filter(site_id=prefix.site.id)
            for scc in site_config_contexts:
                pydhcp_configuration = scc.data.get("pydhcp_configuration", {})
                if pydhcp_configuration:
                    break

        dns_server_ips = pydhcp_configuration.get("dns_servers", [])
        dns_server_ips = [ipaddress.ip_address(i) for i in dns_server_ips]
        dns_server_ips = dns_server_ips or [router_ip]

        if dns_server_ips:
            lease.dns_addresses = dns_server_ips

    def _find_device_and_interface(self, packet):
        # The api to lookup virtual interfaces by mac appears to be broken, but we can get the
        # device directly with mac and then enumerate its interfaces to get the correct one.

        device = self.client.dcim.devices.get(mac_address=packet.client_mac.upper()) or \
            self.client.virtualization.virtual_machines.get(mac_address=packet.client_mac.upper())

        if device is None:
            return None, None

        if hasattr(device, "vcpus"):
            # virtual machine
            interfaces = self.client.virtualization.interfaces.filter(virtual_machine_id=device.id)
        else:
            interfaces = self.client.dcim.interfaces.filter(device_id=device.id)

        interface = None
        for _i in interfaces:
            if _i.mac_address.upper() == packet.client_mac.upper():
                interface = _i
                break

        return device, interface

    def _find_prefix(self, ipaddr):
        """ Return the smallest prefix containing the ip address """
        ipaddr = str(ipaddr)
        prefixes = self.client.ipam.prefixes.filter(contains=ipaddr)
        if not prefixes:
            return None

        prefixes.sort(key=lambda p: int(p.prefix.split("/")[-1]))
        return prefixes[0]

    def _find_dynamic_pool_ips(self, prefix):
        return self.client.ipam.ip_addresses.filter(parent=str(prefix), status=5)

    @classmethod
    def add_backend_args(cls):
        """ Add argparse arguments for this backend """
        group = SETTINGS.add_argument_group(title=cls.NAME, description=cls.__doc__)
        group.add_argument("--netbox-url", help="The Netbox instance URL")
        group.add_argument("--netbox-token", help="The netbox authentication token")
        group.add_argument("--netbox-allow-unknown-devices",
                           help="Allow dynamic leases for unknown devices",
                           action="store_true")


try:
    import pynetbox
    NetboxBackend.add_backend_args()
except ImportError as ex:
    NetboxBackend.DISABLED = str(ex)
