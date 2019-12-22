""" DHCP Leases """

import ipaddress
from datetime import datetime, timedelta
from dhcp.packet import Option, PacketOption


class Lease():
    """ DHCP Lease """

    # pylint: disable=too-many-instance-attributes

    def __init__(self, **kwargs):
        self.started_at = datetime.utcnow()
        self.client_mac = None
        self.client_ip = None
        self.client_mask = None
        self.lifetime = 86400
        self.router = None
        self.host_name = None
        self.domain_name = None
        self.dns_addresses = []
        self.dns_search = []
        self.static_routes = []
        self.active = False
        self.class_ident = None
        self.tftp_server = None
        self.tftp_filename = None

        for key, val in kwargs.items():
            setattr(self, key, val)

    def __getstate__(self):
        return {
            "client_mac": self.client_mac,
            "client_ip": str(self.client_ip),
            "client_mask": str(self.client_mask),
            "lifetime": self.lifetime,
            "router": str(self.router) if self.router else None,
            "dns_addresses": [str(i) for i in self.dns_addresses],
            "active": self.active
        }

    @property
    def client_interface(self):
        """ Return an IPv4Address instance """
        return ipaddress.ip_interface("{0}/{1}".format(self.client_ip, self.client_mask))

    @property
    def ends_at(self):
        """ Return the lease end time """
        return self.started_at + timedelta(seconds=self.lifetime)

    @property
    def options(self):
        """ Construct the options """
        yield Option(PacketOption.LEASE_TIME, self.lifetime)
        yield Option(PacketOption.SUBNET_MASK, self.client_mask)

        if self.router:
            yield Option(PacketOption.ROUTER, self.router)

        if self.dns_addresses:
            yield Option(PacketOption.DOMAIN_NAME_SERVER, self.dns_addresses)

        if self.static_routes:
            yield Option(PacketOption.STATIC_ROUTES, self.static_routes)

        if self.class_ident:
            yield Option(PacketOption.CLASS_IDENT, self.class_ident)

        if self.tftp_server:
            yield Option(PacketOption.TFTP_SERVER, self.tftp_server)

        if self.tftp_filename:
            yield Option(PacketOption.TFTP_FILENAME, self.tftp_filename)

    def __repr__(self):
        return (
            "Lease(started_at={}, client_mac={}, client_ip={}, client_mask={}, "
            "lifetime={}, router={}, host_name={}, domain_name={}, dns_addresses={}, "
            "dns_search={}, static_routes={}, active={}, class_ident={}, tftp_server={}, "
            "tftp_filename={})"
        ).format(
            self.started_at,
            self.client_mac,
            self.client_ip,
            self.client_mask,
            self.lifetime,
            self.router,
            self.host_name,
            self.domain_name,
            self.dns_addresses,
            self.dns_search,
            self.static_routes,
            self.active,
            self.class_ident,
            self.tftp_server,
            self.tftp_filename,
        )
