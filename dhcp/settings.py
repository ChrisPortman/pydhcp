""" DHCP Server Settings """

import argparse

from dhcp.backends.base import BACKENDS

class _Settings():
    """ Pydhcp Settings """

    def __init__(self):
        """ Init a new settings instance """

        self.parser = argparse.ArgumentParser()

    def parse(self, args=None):
        """ Parse the cli arguments """
        self._add_common_args()
        args = self.parser.parse_args(args=args, namespace=self)

    def add_argument_group(self, title, description=None):
        """ Add a additional argument group to the parser and return the group """
        return self.parser.add_argument_group(title=title, description=description)

    def _add_common_args(self):
        backend_choices = [cls.NAME for cls in BACKENDS.values() if not cls.DISABLED]
        self.parser.add_argument("-i", "--interface", default="*", type=str,
                                 help=(
                                     "Name of interface to listen on, or '*' "
                                     "to listen on all. Default: *"
                                 ))
        self.parser.add_argument("-a", "--authoritative", action="store_true")
        self.parser.add_argument("-l", "--lease_time", default=None, type=int,
                                 help="Dynamic lease time in seconds")
        self.parser.add_argument("-b", "--backend",
                                 choices=backend_choices,
                                 required=True)
        self.parser.add_argument("--server-ident", default=None, type=str,
                                 help=(
                                     "Force the IP address the server presents "
                                     "as its own to clients.  This is helpful if "
                                     "the DHCP server is running in a Docker container "
                                     "or similar situation where the DHCP packets are "
                                     "being DNAT port forwarded to the DHCP server (not "
                                     "including real DHCP proxies)"
                                 ))


SETTINGS = _Settings()
