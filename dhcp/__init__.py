""" PyDHCP """

import os
import sys
import logging

from dhcp.server import Server
from dhcp.backends import get_backend

LOGGER = logging.getLogger("dhcp")
LOGGER.setLevel(logging.INFO)
LOGGER.addHandler(
    logging.StreamHandler()
)


def run():
    """ Run dhcp """
    backend = None
    args = []

    if len(sys.argv) < 2:
        backend = os.getenv("PYDHCP_BACKEND", None)
    else:
        backend = sys.argv[1]
        if len(sys.argv) > 2:
            args = sys.argv[2:]

    if not backend:
        print("Usage: %s <backend_name> {[<backend_arg>]}" % sys.argv[0])
        sys.exit(1)

    backend = get_backend(backend)
    server = Server(backend=backend(*args))

    LOGGER.info("Starting DHCP server")
    server.serve()
    LOGGER.info("DHCP server stopped")


if __name__ == "__main__":
    run()
