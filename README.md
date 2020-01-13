# PyDHCP

## Introduction

The PyDHCP package provides a DHCP server written in Python that is relatively easy to extend with custom backends for managing lease and IP allocation information.

## Installation

```
> git clone <this repo>
> cd pydhcp
> pip install .[desired backend]
```

Each backend will likely have its own dependancies which should be optionally installed if you want to use that specific backend.

## Usage

The basic usage provides for 3 command line arguments:
 * `-i|--interface`: specify `*` to listen on all interfaces, or specify one or more times with an interface name (e.g. "eth0") to listen on specific interfaces.
 * `-a|--authoritive`: boolean flag. Authoritative DHCP servers send a NAK to clients it does not wish to provide a lease to which will effectively stop DHCP on the client.  Non-authoritative servers will simply ignore the client leaving other DHCP servers free to respond.
 * `-b|--backend`: the name of the backend to use.  The selection of a backend will invoke the need for backend specific arguments.
 
E.g:
```
> dhcp -i * -a --backend=netbox <netbox arguments>
```
 
## Backends
 
### Netbox
 
The netbox backend will use a netbox instance to generate lease information.  Static leases are achieved by configuring a Device or Virtual Machine with a network interface that has the MAC address properly set and an IP address assigned.  If this is the case, PyDHCP will identify the interface by matching the MAC address with that of the incoming DISCOVER/REQUEST and provide the configured IP.

Dynamic leases are achievable by tagging IP addresses with `DHCP`.

#### Basic Setup Requirements

 * There must be a prefix defined containing any IP address you want PyDHCP to allocate.
 * The default gateway for any lease is determined by the IP address within the allocation's prefix that is tagged `Gateway`.
 * DNS servers for any lease is determined by looking up `config_context['pydhcp_configuration']['dns_servers']`.  The value must be a list of IP addresses.  When generating a lease for a MAC address that resolves to an Interface attached to a Device or Virtual Machine, the Configuration Context of the Device or Virtual Machine will be used.  In other cases, the configuration context for the site to which the Prefix is allocated will be used.

There are a number of values that are looked up via the configuration context data that netbox provides.  Configuration context is a hierachical process of applying configuration type data to objects whereby configuration data is overlayed in order of priority/scope to reach the final configuration as it applies to a specific object.  How to specifically structure the config data in your environment will depend on you circumstances, as long as the devices (and sites in some cases) have the required context rendered for them.  For more information on configuration contexts, see https://netbox.readthedocs.io/en/stable/additional-features/context-data/

#### Supporting Dynamic Leases
If you wish to support dynamic leases, the following custom fields will need to be setup in netbox and applied to `IPAM->IP Address` objects:
 * `pydhcp_mac`: text field used to store the MAC address to which the IP was last allocated. Set required=false, no default.
 * `pydhcp_expire`: used to store the expiry time of the lease. Set required=false, no default.
 
Note that these names for the custom fields are the internal names.  You may use whatever labels/descriptions for the fields suit your fancy.

To make an IP address available for dynamic assignment, create the prefix, and IP addresses and tag the IP addresses `DHCP`.

#### Supporting Automated Deployment (PXE Booting)

The netbox backend provides a process for supporting the automated deployment of Devices and Virtual Machines during the PXE boot phase of a device's boot sequence.  To this end, if the DISCOVER/REQUEST packet's include requests for boot related options, PyDHCP can populate the lease options with the IP of a TFTP service and the file to request from the TFTP server.  These additional fields are required to be available in the `pydhcp_configuration` section of a Device's configuration context:
 * `tftp_server`: the IP address of the TFTP server
 * `pxe_boot_file`: the path of the file to load via TFTP in the case of legacy, non UEFI based, bioses.  Required if supporting such systems.
 * `uefi_boot_file`: the path of the file to load via TFTP in the case of UEFI based boot processes.  Required if supporting such systems.



