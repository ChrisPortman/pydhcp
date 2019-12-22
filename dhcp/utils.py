""" Helper functions"""

import binascii


def format_mac(mac):
    """Return formatted MAC"""
    return ":".join("{0:02x}".format(s) for s in mac)


def pack_mac(macstr):
    """Return binary MAC"""
    return binascii.unhexlify(macstr.replace(":", ""))


def first_or_default(find, iterable, default=None):
    """Return the first match in iterable, or the default if not found"""
    matches = list(filter(find, iterable))
    if matches:
        return matches[0]

    return default
