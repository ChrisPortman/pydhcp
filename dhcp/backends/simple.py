import os

import ipaddress

from dhcp.backends.base import DHCPBackend
from dhcp.lease import Lease
from dhcp.packet import PacketOption
from dhcp.settings import SETTINGS


class PtpBackend(DHCPBackend):
    """ Simple Point-to-Point DHCP backend """

    NAME = "ptp"

    DISABLED = False

    def __init__(self, gateway=None, client=None, dns1=None, dns2=None, lease_time=None):
        print(dir(SETTINGS))
        self.gateway = gateway or SETTINGS.ptp_gateway or os.getenv("PTP_SERVER_IP", None)
        self.client = client or SETTINGS.ptp_client or os.getenv("PTP_CLIENT_IP", None)
        self.dns1 = dns1 or SETTINGS.ptp_dns1 or os.getenv("PTP_DNS_IP1", None)
        self.dns2 = dns2 or SETTINGS.ptp_dns2 or os.getenv("PTP_DNS_IP2", None)
        # default 10 minutes
        self.lease_time = lease_time or SETTINGS.lease_time or os.getenv("LEASE_TIME", 60 * 10)

    def get_lease(self):
        ipaddr = ipaddress.ip_interface(self.client + '/32')
        return Lease(
            client_ip=ipaddr.ip,
            client_mask=ipaddr.network.netmask,
            lifetime=self.lease_time,
            static_routes=[(ipaddress.ip_network("0.0.0.0/0"), ipaddress.ip_interface(self.gateway).ip)],
        )

    def offer(self, packet):
        """ Generate an appropriate offer based on packet.  Return a dhcp.lease.Lease object """
        return self.get_lease()

    def acknowledge(self, packet, offer):
        """ Generate an ACKNOWLEGE response to a REQUEST """
        return self.get_lease()

    def acknowledge_selecting(self, packet, offer):
        """ Generate an ACKNOWLEGE response to a REQUEST from a client in SELECTING state """
        return self.acknowledge(packet, offer)

    def acknowledge_renewing(self, packet, offer):
        """ Generate an ACKNOWLEGE response to a REQUEST from a client in RENEWING state """
        return self.acknowledge(packet, offer)

    def acknowledge_rebinding(self, packet, offer):
        """ Generate an ACKNOWLEGE response to a REQUEST from a client in REBINDING state """
        return self.acknowledge(packet, offer)

    def acknowledge_init_reboot(self, packet, offer):
        """ Generate an ACKNOWLEGE response to a REQUEST from a client in INITREBOOT state """
        return self.acknowledge(packet, offer)

    def release(self, packet):
        """ We ignore any release, as we always give out the same lease """
        pass

    def boot_request(self, packet, lease):
        """ Add boot options to the lease """
        raise NotImplementedError()

    @classmethod
    def add_backend_args(cls):
        """ Add argparse arguments for this backend """
        group = SETTINGS.add_argument_group(title=cls.NAME, description=cls.__doc__)
        group.add_argument("--ptp-gateway", help="Point-to-Point address of the gateway")
        group.add_argument("--ptp-client", help="Point-to-Point address of the client")
        group.add_argument("--ptp-dns1", help="First DNS ip address")
        group.add_argument("--ptp-dns2", help="Second DNS ip address")

PtpBackend.add_backend_args()
