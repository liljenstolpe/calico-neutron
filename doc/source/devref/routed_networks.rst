Routed Networks
===============

This document describes and proposes a type of Neutron network in
which connectivity between the VMs attached to that network is
provided by L3 routing.  This type of network provides full (subject
to security policy) IP connectivity between VMs in that and other
routed networks: v4 and v6, unicast and multicast; but it provides no
L2 capability, except as required for this IP connectivity, plus
correct operation of the ICMP, ARP and NDP protocols that exist to
support IP.  Therefore, this kind of network is suitable for VMs that
only communicate over IP.

Why would anyone want that?  Compared to the other kinds of networks
that provide connectivity at L2, its arguable benefits are that:

- it is conceptually simpler, in that VM data is transported in a
  uniform way between a VM and its compute host, between compute
  hosts, and between the data center network and the outside world,
  without any encapsulation changes anywhere

- as a practical consequence, it is easier to debug, using standard
  tools such as ping, traceroute, wireshark and tcpdump

- its scale is not limited in the way that VLAN-based and VXLAN-based
  networks are, by the practical diameter of the physical underlying
  L2 network.

Description on the Neutron API
------------------------------

A routed network is described on the Neutron API using a new provider
network type: TYPE_ROUTED = 'routed'.  The related physical network
and segmentation ID parameters are not meaningful and should be left
unspecified.

A routed network can be shared or private; this is indicated as usual
by presence or absence of the 'shared' flag.

Neutron router objects are not used with routed networks.  Subject to
security policy, there is automatically potential connectivity between
all ports on routed networks in the same address scope; and between
routed networks and the outside world.

Floating IPs are not used with routed networks.  Because of the
preceding connectivity point, it is practical to configure two routed
networks, one with DC-private (e.g. RFC 1918) IP addresses, and one
with a range of globally routable IP addresses.  Then, when launching
a VM, it can simply be attached to the latter if it requires inbound
connectivity from the Internet, and to the former if not.

Connectivity Implementation - Shared
------------------------------------

In the shared routed network case, everything happens in the default
namespace of the relevant compute hosts.  Standard Linux routing
routes VM data, with iptables used to implement the configured
security policy.

A VM is 'plugged' with a TAP device on the host that connects to the
VM's network stack.  The host end of the TAP is left unbridged and
without any IP addresses (except for link-local IPv6).  The host is
configured to respond to any ARP or NDP requests, through that TAP,
with its own MAC address; hence data arriving through the TAP is
always addressed at L2 to the host, and is passed to the Linux routing
layer.

For each local VM, the host programs a route to that VM's IP
address(es) through the relevant TAP device.  The host also runs a BGP
client (BIRD) so as to export those routes to other compute hosts.
The routing table on a compute host might therefore look like this:

.. code::

 user@host02:~$ route -n
 Kernel IP routing table
 Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
 0.0.0.0         172.18.203.1    0.0.0.0         UG    0      0        0 eth0
 10.65.0.21      172.18.203.126  255.255.255.255 UGH   0      0        0 eth0
 10.65.0.22      172.18.203.129  255.255.255.255 UGH   0      0        0 eth0
 10.65.0.23      172.18.203.129  255.255.255.255 UGH   0      0        0 eth0
 10.65.0.24      0.0.0.0         255.255.255.255 UH    0      0        0 tapa429fb36-04
 172.18.203.0    0.0.0.0         255.255.255.0   U     0      0        0 eth0

This shows one local VM on this host with IP address 10.65.0.24,
accessed via a TAP named tapa429fb36-04; and three VMs, with the .21,
.22 and .23 addresses, on two other hosts (172.18.203.126 and .129),
and hence with routes via those compute host addresses.

DHCP
----

DHCP service in this type of network can be provided by Dnsmasq using
its --bridge-interface option.  A patch with the necessary Neutron
DHCP agent modifications can be seen at
https://review.openstack.org/#/c/197578/.

Connectivity Implementation - Private
-------------------------------------

Full details here are still to be tied down, but broadly this is the
same as in the shared case except for the following points.

- For each private address scope, there is a corresponding non-default
  namespace on the host, in which the routing for that address scope
  is performed.

- The TAP devices for ports in a private address scope are moved into
  the corresponding namespace, on the host side.

- Some tunneling or overlay technology is used to connect those
  namespaces, between participating compute hosts.  Options here
  include 464XLAT and any of the tunneling technologies used in
  Neutron L2 network types.

Work Needed
-----------

For the shared case, the following work is needed for Neutron to
support routed networks.

- At the API-level, merge and document the idea of the 'routed'
  network type (as described above in this devref).

- Adapt the relevant components of the Neutron reference
  implementation as required in order to support the 'routed' type.  I
  believe that this means only the DHCP agent, and the work there is
  already underway as shown at
  https://review.openstack.org/#/c/197578/.

- Provide a mechanism driver and agent to implement the connectivity
  for a 'routed' network as described above.  This work is out-of-tree
  at https://github.com/Metaswitch/calico and is already fairly
  mature, although it will need some minor adaptation for how the
  in-tree pieces (above) end up.

Further implementation work will be needed for the private case, and
for IP multicast, but we propose to cover those in separate future
phases.  These are not expected to require any further API-level
changes or enhancements.

References
----------

 - https://review.openstack.org/#/c/197578/
 - https://github.com/Metaswitch/calico
 - http://www.projectcalico.org/
