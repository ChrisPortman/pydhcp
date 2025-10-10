""" DHCP Backends """

# flake8: noqa: F401

from dhcp.backends.netbox import NetboxBackend
from dhcp.backends.base import get_backend
from dhcp.backends.simple import PtpBackend
