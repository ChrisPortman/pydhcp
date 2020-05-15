""" Netbox DHCP backend """

import os
import logging
import ipaddress
from datetime import datetime, timedelta, timezone

from dhcp.backends.base import DHCPBackend
from dhcp.lease import Lease
from dhcp.packet import PacketOption
from dhcp.settings import SETTINGS

logger = logging.getLogger(__name__)


def obj_or_dict_get(ctx, key, default=None):
    """Currently depending on the class of object holding the context, the context may be
    a dict or an object.
    """
    if isinstance(ctx, dict):
        return ctx.get(key, default)

    return getattr(ctx, key, default)


class DHCPIgnore(Exception):
    pass


class NetboxBackend(DHCPBackend):
    """ Manage DHCP leases from Netbox """

    NAME = "netbox"

    _API_VERSION = None
    _IPADDRESS_DHCP_STATUS = "dhcp"

    @property
    def client(self):
        """ Create and cache a netbox client on first use """

        if self._client:
            return self._client

        self._client = pynetbox.api(self.url, self.token)
        self._API_VERSION = (int(i) for i in self.client.version.split("."))

        _, minor = self._API_VERSION
        if minor < 7:
            self._IPADDRESS_DHCP_STATUS = 5

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

        nbip, prefix, device, _ = self._find_lease(packet)
        if not nbip:
            return None

        lease = self._nbip_to_lease(nbip)
        self._add_network_settings_to_lease(lease, device, prefix)

        # Reserve the lease for 10 secs pending the clients REQUEST
        self._allocate_dynamic_ip(packet, nbip, 10)

        return lease

    def acknowledge_selecting(self, packet, offer):
        """ Check if the offer was dynamic, if so set the full expiry """

        if not offer:
            return

        ip_address = self.client.ipam.ip_addresses.filter(
            address=str(offer.client_ip),
            cf_pydhcp_mac=packet.client_mac.upper(),
            status=self._IPADDRESS_DHCP_STATUS,
        )

        if ip_address:
            device, interface = self._find_device_and_interface(packet)
            self._allocate_dynamic_ip(packet, ip_address[0], self.lease_time, device, interface)

        return offer

    def acknowledge_renewing(self, packet, offer=None):
        """ Find the lease and extend """
        nbip, prefix, device, interface = self._find_lease(packet)
        if not nbip:
            return

        requested_ip = getattr(
            packet.find_option(PacketOption.REQUESTED_IP),
            "value", packet.ciaddr
        )
        if ipaddress.ip_interface(nbip.address).ip != requested_ip:
            logger.error("Resolved lease IP: %s, does not match requested IP: %s in renewal",
                         ipaddress.ip_interface(nbip.address).ip, requested_ip)
            return None

        lease = self._nbip_to_lease(nbip)
        self._add_network_settings_to_lease(lease, device, prefix)
        self._allocate_dynamic_ip(packet, nbip, self.lease_time, device, interface)

        return lease

    def acknowledge_rebinding(self, packet, offer=None):
        """ Find a lease, if it matches the requested return it else return none """
        return self.acknowledge_renewing(packet, offer)

    def acknowledge_init_reboot(self, packet, offer=None):
        """ Find a lease, if it matches the requested return it else return none """
        return self.acknowledge_renewing(packet, offer)

    def release(self, packet):
        """ Action release request as per packet.  Clear the expire but not the MAC so
        so that init-reboot works as intended
        """
        ip_address = self.client.ipam.ip_addresses.filter(
            address=str(packet.ciaddr),
            cf_pydhcp_mac=packet.client_mac.upper(),
            status=self._IPADDRESS_DHCP_STATUS,
        )

        if ip_address:
            ip_address = ip_address[0]
            ip_address.custom_fields["pydhcp_expire"] = None
            ip_address.interface = None
            ip_address.save()

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

        pydhcp_configuration = obj_or_dict_get(device.config_context, "pydhcp_configuration", {})
        tftp_server = obj_or_dict_get(pydhcp_configuration, "tftp_server", None)
        boot_filepath = None

        if packet.client_arch in ("Intel x86PC",):
            boot_filepath = obj_or_dict_get(pydhcp_configuration, "pxe_boot_file", None)
        if packet.client_arch in ("EFI BC", "EFI x86-64"):
            boot_filepath = obj_or_dict_get(pydhcp_configuration, "uefi_boot_file", None)

        if tftp_server and boot_filepath:
            lease.tftp_server = tftp_server
            lease.tftp_filename = boot_filepath

    def _find_lease(self, packet):
        prefix = self._find_origin_prefix(packet)
        if not prefix:
            return None, None, None, None

        device, interface = self._find_device_and_interface(packet)

        nbip = None
        try:
            nbip = self._find_static_lease(device, interface, prefix) or \
                self._find_dynamic_lease(packet, prefix)
        except DHCPIgnore:
            pass

        if nbip is None:
            return None, None, None, None

        return nbip, prefix, device, interface

    def _find_static_lease(self, device, interface, prefix):
        if device is None or interface is None:
            return None

        if hasattr(interface, "lag") and interface.lag is not None:
            # Link aggregation interface member we need to only service ONE
            # member else, it will hand the the same IP to both memebers if they
            # come up independantly (e.g. PXE)
            lag = interface.lag
            if interface.mac_address != lag.mac_address:
                raise DHCPIgnore()

            interface = lag

        ip_addresses = self.client.ipam.ip_addresses.filter(interface_id=interface.id)

        for ip in ip_addresses:
            if ip.status.value == self._IPADDRESS_DHCP_STATUS:
                # this is a dynamic IP
                continue

            ip_interface = ipaddress.ip_interface(ip.address)
            if ip_interface.ip in ipaddress.ip_network(prefix.prefix):
                return ip

        return None

    def _find_dynamic_lease(self, packet, prefix):
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

        # check for the most recently allocated IP address allocated to the MAC address.
        ip_addresses = self.client.ipam.ip_addresses.filter(
            cf_pydhcp_mac=packet.client_mac.upper(),
            parent=prefix.prefix,
            status=self._IPADDRESS_DHCP_STATUS,
        )
        if ip_addresses:
            ip_addresses.sort(
                key=lambda i: i.custom_fields.get("pydhcp_expire", None) or "9999"
            )

            return ip_addresses[-1]

        # For the last checks we need all the relevant DHCP addresses
        dhcp_addresses = self.client.ipam.ip_addresses.filter(
            status=self._IPADDRESS_DHCP_STATUS,
            parent=prefix.prefix,
        )

        # next check for any ip address that has no allocated MAC
        unallocated = [i for i in dhcp_addresses if not i.custom_fields.get("pydhcp_mac", None)]
        if unallocated:
            unallocated.sort(key=lambda i: i.address)
            return unallocated[0]

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
            return expired[0]

        # If theres no allocated IP now, we dont have any to allocate
        return None

    def _allocate_dynamic_ip(self, packet, ipaddr, expiry, device=None, interface=None):
        if not ipaddr:
            return

        if ipaddr.status.value != self._IPADDRESS_DHCP_STATUS:
            # Not a dynamic address
            return

        expire = (datetime.now(timezone.utc) + timedelta(seconds=expiry)).isoformat()
        ipaddr.custom_fields["pydhcp_mac"] = packet.client_mac.upper()
        ipaddr.custom_fields["pydhcp_expire"] = expire
        ipaddr.custom_fields["pydhcp_hostname"] = packet.client_hostname

        if interface:
            ipaddr.interface = interface
        ipaddr.save()

        if device:
            device.primary_ip4 = ipaddr
            device.save()

    def _nbip_to_lease(self, ipaddr):
        ipaddr = ipaddress.ip_interface(ipaddr.address)

        return Lease(
            client_ip=ipaddr.ip,
            client_mask=ipaddr.network.netmask,
            lifetime=self.lease_time,
        )

    def _add_network_settings_to_lease(self, lease, device, prefix):
        try:
            router_ip = self.client.ipam.ip_addresses.filter(parent=str(prefix), tag="gateway") or None
        except pynetbox.core.query.RequestError:
            # The api returns HTTP 400 if the gateway tag does not exist.
            router_ip = None

        if router_ip:
            router_ip = ipaddress.IPv4Interface(router_ip[0]).ip
            lease.router = router_ip

        if device is not None:
            pydhcp_configuration = obj_or_dict_get(
                device.config_context, "pydhcp_configuration", {}
            )
        elif prefix.site:
            site_config_contexts = self.client.extras.config_contexts.filter(site_id=prefix.site.id)
            for scc in site_config_contexts:
                pydhcp_configuration = obj_or_dict_get(scc.data, "pydhcp_configuration", {})
                if pydhcp_configuration:
                    break

        dns_server_ips = obj_or_dict_get(pydhcp_configuration, "dns_servers", [])
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
            if _i.mac_address and _i.mac_address.upper() == packet.client_mac.upper():
                interface = _i
                break

        return device, interface

    def _find_origin_prefix(self, packet):
        """ Return the smallest prefix containing the ip address """

        requested_ip = getattr(
            packet.find_option(PacketOption.REQUESTED_IP),
            "value", packet.ciaddr
        )

        if requested_ip.is_unspecified is False:
            # Return the prefix for the requested IP
            prefixes = self.client.ipam.prefixes.filter(contains=str(requested_ip))
        else:
            ipaddr = str(packet.receiving_ip)
            prefixes = self.client.ipam.prefixes.filter(contains=str(ipaddr))

        if not prefixes:
            logger.warning("No prefix configured containing IP %s", packet.receiving_ip)
            return None

        prefixes.sort(key=lambda p: int(p.prefix.split("/")[-1]))
        return prefixes[-1]

    def _find_dynamic_pool_ips(self, prefix):
        return self.client.ipam.ip_addresses.filter(
            parent=str(prefix), status=self._IPADDRESS_DHCP_STATUS
        )

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
