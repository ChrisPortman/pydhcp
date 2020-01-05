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
        self.parser.add_argument("-i", "--interface", default="*", type=str)
        self.parser.add_argument("-a", "--authoritative", action="store_true")
        self.parser.add_argument("-b", "--backend",
                                 choices=backend_choices,
                                 required=True)


SETTINGS = _Settings()
