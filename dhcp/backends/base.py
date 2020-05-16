""" Base DHCP backend """

import sys
import logging

logger = logging.getLogger(__name__)

BACKENDS = {}


class DHCPBackendMeta(type):
    """ Register Backend classes in the library """

    def __new__(cls, clsname, bases, attrs):
        newclass = super().__new__(cls, clsname, bases, attrs)

        if newclass.__name__ != "DHCPBackend":
            if not hasattr(newclass, "NAME"):
                setattr(newclass, "NAME", newclass.__name__)

            BACKENDS[newclass.NAME] = newclass

        return newclass


class DHCPBackend(metaclass=DHCPBackendMeta):
    """ Base DHCP backend """

    DISABLED = False

    def offer(self, packet):
        """ Generate an offer in response to a DISCOVER """
        raise NotImplementedError()

    def acknowledge(self, packet, offer):
        """ Generate an ACKNOWLEGE response to a REQUEST """
        raise NotImplementedError()

    # Implementations MAY CHOOSE to implement specific behavior for some of the specific
    # client states that generate a DHCP request, non implemented states fall back to
    # the generic acknowledge.  If all are implemented there is no need to implement
    # acknowledge
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
        """ Process a release """
        raise NotImplementedError()

    def boot_request(self, packet, lease):
        """ Add boot options to the lease """


def get_backend(name):
    """ Retrive the enabled backend `name` """

    if name in BACKENDS:
        if BACKENDS[name].DISABLED:
            logger.error("Backend %s is DISABLED: %s", name,
                         BACKENDS[name].DISABLED)
            sys.exit(1)
        else:
            return BACKENDS[name]

    logger.error("Backend %s is unknown", name)
    sys.exit(1)
