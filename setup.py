from setuptools import setup, find_packages

setup(
    name="pydhcp",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "netifaces>=0.10.0,<0.11.0",
    ],
    extras_require={
        "netbox": [
            "pynetbox>=4.0.0,<5.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "pydhcp = dhcp:run",
        ]
    },
)
