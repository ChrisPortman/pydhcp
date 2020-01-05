""" PyDHCP """

import os
import sys
import logging

from dhcp.server import Server
from dhcp.backends import get_backend
from dhcp.settings import SETTINGS

logger = logging.getLogger("dhcp")
logger.setLevel(logging.INFO)
logger.addHandler(
    logging.StreamHandler()
)


def run():
    """ Run dhcp """
    SETTINGS.parse()

    backend = get_backend(SETTINGS.backend)
    server = Server(backend=backend())

    logger.info("Starting DHCP server")

    try:
        server.serve()
    except KeyboardInterrupt:
        pass
    except Exception as ex:
        logger.error("Error running DHCP server: %s", str(ex), exc_info=True)

    logger.info("DHCP server stopped")


if __name__ == "__main__":
    run()
