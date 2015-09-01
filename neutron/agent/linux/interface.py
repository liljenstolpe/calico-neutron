# Copyright 2012 OpenStack Foundation
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import abc

import netaddr
from oslo_config import cfg
from oslo_log import log as logging
import six

from neutron.agent.common import ovs_lib
from neutron.agent.linux import ip_lib
from neutron.agent.linux import utils
from neutron.common import constants as n_const
from neutron.common import exceptions
from neutron.common import ipv6_utils
from neutron.i18n import _LE, _LI


LOG = logging.getLogger(__name__)

OPTS = [
    cfg.StrOpt('ovs_integration_bridge',
               default='br-int',
               help=_('Name of Open vSwitch bridge to use')),
    cfg.BoolOpt('ovs_use_veth',
                default=False,
                help=_('Uses veth for an interface or not')),
    cfg.IntOpt('network_device_mtu',
               help=_('MTU setting for device.')),
]


@six.add_metaclass(abc.ABCMeta)
class LinuxInterfaceDriver(object):

    # from linux IF_NAMESIZE
    DEV_NAME_LEN = 14
    DEV_NAME_PREFIX = n_const.TAP_DEVICE_PREFIX

    def __init__(self, conf):
        self.conf = conf
        if self.conf.network_device_mtu:
            self._validate_network_device_mtu()

    def _validate_network_device_mtu(self):
        if (ipv6_utils.is_enabled() and
            self.conf.network_device_mtu < n_const.IPV6_MIN_MTU):
            LOG.error(_LE("IPv6 protocol requires a minimum MTU of "
                          "%(min_mtu)s, while the configured value is "
                          "%(current_mtu)s"), {'min_mtu': n_const.IPV6_MIN_MTU,
                          'current_mtu': self.conf.network_device_mtu})
            raise SystemExit(1)

    @property
    def use_gateway_ips(self):
        """Whether to use gateway IPs instead of unique IP allocations.

        In each place where the DHCP agent runs, and for each subnet for
        which DHCP is handling out IP addresses, the DHCP port needs -
        at the Linux level - to have an IP address within that subnet.
        Generally this needs to be a unique Neutron-allocated IP
        address, because the subnet's underlying L2 domain is bridged
        across multiple compute hosts and network nodes, and for HA
        there may be multiple DHCP agents running on that same bridged
        L2 domain.

        However, if the DHCP ports - on multiple compute/network nodes
        but for the same network - are _not_ bridged to each other,
        they do not need each to have a unique IP address.  Instead
        they can all share the same address from the relevant subnet.
        This works, without creating any ambiguity, because those
        ports are not all present on the same L2 domain, and because
        no data within the network is ever sent to that address.
        (DHCP requests are broadcast, and it is the network's job to
        ensure that such a broadcast will reach at least one of the
        available DHCP servers.  DHCP responses will be sent _from_
        the DHCP port address.)

        In particular, in the networking-calico case, all DHCP ports
        can use the subnet's gateway IP address, and thereby
        completely avoid any unique IP address allocation.
        networking-calico uses BGP to populate a detailed routing
        table on each compute host, including for traffic between
        Neutron networks, and to and from the Internet, and the
        gateway IP address is not required for its usual Neutron
        purpose of reaching a virtual router.  So it can be used
        instead as the DHCP port address.

        When an operator deploys Neutron with an interface driver that
        makes use_gateway_ips True, they should also ensure that a
        gateway IP address is defined for each DHCP-enabled subnet,
        and that the gateway IP address doesn't change during the
        subnet's lifetime.
        """
        return False

    def init_l3(self, device_name, ip_cidrs, namespace=None,
                preserve_ips=[], gateway_ips=None,
                clean_connections=False):
        """Set the L3 settings for the interface using data from the port.

        ip_cidrs: list of 'X.X.X.X/YY' strings
        preserve_ips: list of ip cidrs that should not be removed from device
        gateway_ips: For gateway ports, list of external gateway ip addresses
        clean_connections: Boolean to indicate if we should cleanup connections
          associated to removed ips
        """
        device = ip_lib.IPDevice(device_name, namespace=namespace)

        # The LLA generated by the operating system is not known to
        # Neutron, so it would be deleted if we added it to the 'previous'
        # list here
        default_ipv6_lla = ip_lib.get_ipv6_lladdr(device.link.address)
        previous = {addr['cidr'] for addr in device.addr.list(
            filters=['permanent'])} - {default_ipv6_lla}

        # add new addresses
        for ip_cidr in ip_cidrs:

            net = netaddr.IPNetwork(ip_cidr)
            # Convert to compact IPv6 address because the return values of
            # "ip addr list" are compact.
            if net.version == 6:
                ip_cidr = str(net)
            if ip_cidr in previous:
                previous.remove(ip_cidr)
                continue

            device.addr.add(ip_cidr)

        # clean up any old addresses
        for ip_cidr in previous:
            if ip_cidr not in preserve_ips:
                if clean_connections:
                    device.delete_addr_and_conntrack_state(ip_cidr)
                else:
                    device.addr.delete(ip_cidr)

        for gateway_ip in gateway_ips or []:
            device.route.add_gateway(gateway_ip)

    def init_router_port(self,
                         device_name,
                         ip_cidrs,
                         namespace,
                         preserve_ips=None,
                         gateway_ips=None,
                         extra_subnets=None,
                         enable_ra_on_gw=False,
                         clean_connections=False):
        """Set the L3 settings for a router interface using data from the port.

        ip_cidrs: list of 'X.X.X.X/YY' strings
        preserve_ips: list of ip cidrs that should not be removed from device
        gateway_ips: For gateway ports, list of external gateway ip addresses
        enable_ra_on_gw: Boolean to indicate configuring acceptance of IPv6 RA
        clean_connections: Boolean to indicate if we should cleanup connections
          associated to removed ips
        extra_subnets: An iterable of cidrs to add as routes without address
        """
        LOG.debug("init_router_port: device_name(%s), namespace(%s)",
                  device_name, namespace)
        self.init_l3(device_name=device_name,
                     ip_cidrs=ip_cidrs,
                     namespace=namespace,
                     preserve_ips=preserve_ips or [],
                     gateway_ips=gateway_ips,
                     clean_connections=clean_connections)

        if enable_ra_on_gw:
            self.configure_ipv6_ra(namespace, device_name)

        device = ip_lib.IPDevice(device_name, namespace=namespace)

        # Manage on-link routes (routes without an associated address)
        new_onlink_routes = set(s['cidr'] for s in extra_subnets or [])
        existing_onlink_routes = set(
            device.route.list_onlink_routes(n_const.IP_VERSION_4) +
            device.route.list_onlink_routes(n_const.IP_VERSION_6))
        for route in new_onlink_routes - existing_onlink_routes:
            LOG.debug("adding onlink route(%s)", route)
            device.route.add_onlink_route(route)
        for route in existing_onlink_routes - new_onlink_routes:
            LOG.debug("deleting onlink route(%s)", route)
            device.route.delete_onlink_route(route)

    def add_ipv6_addr(self, device_name, v6addr, namespace, scope='global'):
        device = ip_lib.IPDevice(device_name,
                                 namespace=namespace)
        net = netaddr.IPNetwork(v6addr)
        device.addr.add(str(net), scope)

    def delete_ipv6_addr(self, device_name, v6addr, namespace):
        device = ip_lib.IPDevice(device_name,
                                 namespace=namespace)
        device.delete_addr_and_conntrack_state(v6addr)

    def delete_ipv6_addr_with_prefix(self, device_name, prefix, namespace):
        """Delete the first listed IPv6 address that falls within a given
        prefix.
        """
        device = ip_lib.IPDevice(device_name, namespace=namespace)
        net = netaddr.IPNetwork(prefix)
        for address in device.addr.list(scope='global', filters=['permanent']):
            ip_address = netaddr.IPNetwork(address['cidr'])
            if ip_address in net:
                device.delete_addr_and_conntrack_state(address['cidr'])
                break

    def get_ipv6_llas(self, device_name, namespace):
        device = ip_lib.IPDevice(device_name,
                                 namespace=namespace)

        return device.addr.list(scope='link', ip_version=6)

    def check_bridge_exists(self, bridge):
        if not ip_lib.device_exists(bridge):
            raise exceptions.BridgeDoesNotExist(bridge=bridge)

    def get_device_name(self, port):
        return (self.DEV_NAME_PREFIX + port.id)[:self.DEV_NAME_LEN]

    @staticmethod
    def configure_ipv6_ra(namespace, dev_name):
        """Configure acceptance of IPv6 route advertisements on an intf."""
        # Learn the default router's IP address via RAs
        ip_lib.IPWrapper(namespace=namespace).netns.execute(
            ['sysctl', '-w', 'net.ipv6.conf.%s.accept_ra=2' % dev_name])

    @abc.abstractmethod
    def plug_new(self, network_id, port_id, device_name, mac_address,
                 bridge=None, namespace=None, prefix=None):
        """Plug in the interface only for new devices that don't exist yet."""

    def plug(self, network_id, port_id, device_name, mac_address,
             bridge=None, namespace=None, prefix=None):
        if not ip_lib.device_exists(device_name,
                                    namespace=namespace):
            self.plug_new(network_id, port_id, device_name, mac_address,
                          bridge, namespace, prefix)
        else:
            LOG.info(_LI("Device %s already exists"), device_name)

    @abc.abstractmethod
    def unplug(self, device_name, bridge=None, namespace=None, prefix=None):
        """Unplug the interface."""

    @property
    def bridged(self):
        """Whether the DHCP port is bridged to the VM TAP interfaces.

        When the DHCP port is bridged to the TAP interfaces for the
        VMs for which it is providing DHCP service - as is the case
        for most Neutron network implementations - the DHCP server
        only needs to listen on the DHCP port, and will still receive
        DHCP requests from all the relevant VMs.

        If the DHCP port is not bridged to the relevant VM TAP
        interfaces, the DHCP server needs to listen explicitly on
        those TAP interfaces, and to treat those as aliases of the
        DHCP port where the IP subnet is defined.
        """
        return True


class NullDriver(LinuxInterfaceDriver):
    def plug_new(self, network_id, port_id, device_name, mac_address,
                 bridge=None, namespace=None, prefix=None):
        pass

    def unplug(self, device_name, bridge=None, namespace=None, prefix=None):
        pass


class OVSInterfaceDriver(LinuxInterfaceDriver):
    """Driver for creating an internal interface on an OVS bridge."""

    DEV_NAME_PREFIX = n_const.TAP_DEVICE_PREFIX

    def __init__(self, conf):
        super(OVSInterfaceDriver, self).__init__(conf)
        if self.conf.ovs_use_veth:
            self.DEV_NAME_PREFIX = 'ns-'

    def _get_tap_name(self, dev_name, prefix=None):
        if self.conf.ovs_use_veth:
            dev_name = dev_name.replace(prefix or self.DEV_NAME_PREFIX,
                                        n_const.TAP_DEVICE_PREFIX)
        return dev_name

    def _ovs_add_port(self, bridge, device_name, port_id, mac_address,
                      internal=True):
        attrs = [('external_ids', {'iface-id': port_id,
                                   'iface-status': 'active',
                                   'attached-mac': mac_address})]
        if internal:
            attrs.insert(0, ('type', 'internal'))

        ovs = ovs_lib.OVSBridge(bridge)
        ovs.replace_port(device_name, *attrs)

    def plug_new(self, network_id, port_id, device_name, mac_address,
                 bridge=None, namespace=None, prefix=None):
        """Plug in the interface."""
        if not bridge:
            bridge = self.conf.ovs_integration_bridge

        self.check_bridge_exists(bridge)

        ip = ip_lib.IPWrapper()
        tap_name = self._get_tap_name(device_name, prefix)

        if self.conf.ovs_use_veth:
            # Create ns_dev in a namespace if one is configured.
            root_dev, ns_dev = ip.add_veth(tap_name,
                                           device_name,
                                           namespace2=namespace)
        else:
            ns_dev = ip.device(device_name)

        internal = not self.conf.ovs_use_veth
        self._ovs_add_port(bridge, tap_name, port_id, mac_address,
                           internal=internal)

        ns_dev.link.set_address(mac_address)

        if self.conf.network_device_mtu:
            ns_dev.link.set_mtu(self.conf.network_device_mtu)
            if self.conf.ovs_use_veth:
                root_dev.link.set_mtu(self.conf.network_device_mtu)

        # Add an interface created by ovs to the namespace.
        if not self.conf.ovs_use_veth and namespace:
            namespace_obj = ip.ensure_namespace(namespace)
            namespace_obj.add_device_to_namespace(ns_dev)

        ns_dev.link.set_up()
        if self.conf.ovs_use_veth:
            root_dev.link.set_up()

    def unplug(self, device_name, bridge=None, namespace=None, prefix=None):
        """Unplug the interface."""
        if not bridge:
            bridge = self.conf.ovs_integration_bridge

        tap_name = self._get_tap_name(device_name, prefix)
        self.check_bridge_exists(bridge)
        ovs = ovs_lib.OVSBridge(bridge)

        try:
            ovs.delete_port(tap_name)
            if self.conf.ovs_use_veth:
                device = ip_lib.IPDevice(device_name, namespace=namespace)
                device.link.delete()
                LOG.debug("Unplugged interface '%s'", device_name)
        except RuntimeError:
            LOG.error(_LE("Failed unplugging interface '%s'"),
                      device_name)


class MidonetInterfaceDriver(LinuxInterfaceDriver):

    def plug_new(self, network_id, port_id, device_name, mac_address,
                 bridge=None, namespace=None, prefix=None):
        """This method is called by the Dhcp agent or by the L3 agent
        when a new network is created
        """
        ip = ip_lib.IPWrapper()
        tap_name = device_name.replace(prefix or n_const.TAP_DEVICE_PREFIX,
                                       n_const.TAP_DEVICE_PREFIX)

        # Create ns_dev in a namespace if one is configured.
        root_dev, ns_dev = ip.add_veth(tap_name, device_name,
                                       namespace2=namespace)

        ns_dev.link.set_address(mac_address)

        # Add an interface created by ovs to the namespace.
        namespace_obj = ip.ensure_namespace(namespace)
        namespace_obj.add_device_to_namespace(ns_dev)

        ns_dev.link.set_up()
        root_dev.link.set_up()

        cmd = ['mm-ctl', '--bind-port', port_id, device_name]
        utils.execute(cmd, run_as_root=True)

    def unplug(self, device_name, bridge=None, namespace=None, prefix=None):
        # the port will be deleted by the dhcp agent that will call the plugin
        device = ip_lib.IPDevice(device_name, namespace=namespace)
        try:
            device.link.delete()
        except RuntimeError:
            LOG.error(_LE("Failed unplugging interface '%s'"), device_name)
        LOG.debug("Unplugged interface '%s'", device_name)

        ip_lib.IPWrapper(namespace=namespace).garbage_collect_namespace()


class IVSInterfaceDriver(LinuxInterfaceDriver):
    """Driver for creating an internal interface on an IVS bridge."""

    DEV_NAME_PREFIX = n_const.TAP_DEVICE_PREFIX

    def __init__(self, conf):
        super(IVSInterfaceDriver, self).__init__(conf)
        self.DEV_NAME_PREFIX = 'ns-'

    def _get_tap_name(self, dev_name, prefix=None):
        dev_name = dev_name.replace(prefix or self.DEV_NAME_PREFIX,
                                    n_const.TAP_DEVICE_PREFIX)
        return dev_name

    def _ivs_add_port(self, device_name, port_id, mac_address):
        cmd = ['ivs-ctl', 'add-port', device_name]
        utils.execute(cmd, run_as_root=True)

    def plug_new(self, network_id, port_id, device_name, mac_address,
                 bridge=None, namespace=None, prefix=None):
        """Plug in the interface."""
        ip = ip_lib.IPWrapper()
        tap_name = self._get_tap_name(device_name, prefix)

        root_dev, ns_dev = ip.add_veth(tap_name, device_name)

        self._ivs_add_port(tap_name, port_id, mac_address)

        ns_dev = ip.device(device_name)
        ns_dev.link.set_address(mac_address)

        if self.conf.network_device_mtu:
            ns_dev.link.set_mtu(self.conf.network_device_mtu)
            root_dev.link.set_mtu(self.conf.network_device_mtu)

        if namespace:
            namespace_obj = ip.ensure_namespace(namespace)
            namespace_obj.add_device_to_namespace(ns_dev)

        ns_dev.link.set_up()
        root_dev.link.set_up()

    def unplug(self, device_name, bridge=None, namespace=None, prefix=None):
        """Unplug the interface."""
        tap_name = self._get_tap_name(device_name, prefix)
        try:
            cmd = ['ivs-ctl', 'del-port', tap_name]
            utils.execute(cmd, run_as_root=True)
            device = ip_lib.IPDevice(device_name, namespace=namespace)
            device.link.delete()
            LOG.debug("Unplugged interface '%s'", device_name)
        except RuntimeError:
            LOG.error(_LE("Failed unplugging interface '%s'"),
                      device_name)


class BridgeInterfaceDriver(LinuxInterfaceDriver):
    """Driver for creating bridge interfaces."""

    DEV_NAME_PREFIX = 'ns-'

    def plug_new(self, network_id, port_id, device_name, mac_address,
                 bridge=None, namespace=None, prefix=None):
        """Plugin the interface."""
        ip = ip_lib.IPWrapper()

        # Enable agent to define the prefix
        tap_name = device_name.replace(prefix or self.DEV_NAME_PREFIX,
                                       n_const.TAP_DEVICE_PREFIX)
        # Create ns_veth in a namespace if one is configured.
        root_veth, ns_veth = ip.add_veth(tap_name, device_name,
                                         namespace2=namespace)
        ns_veth.link.set_address(mac_address)

        if self.conf.network_device_mtu:
            root_veth.link.set_mtu(self.conf.network_device_mtu)
            ns_veth.link.set_mtu(self.conf.network_device_mtu)

        root_veth.link.set_up()
        ns_veth.link.set_up()

    def unplug(self, device_name, bridge=None, namespace=None, prefix=None):
        """Unplug the interface."""
        device = ip_lib.IPDevice(device_name, namespace=namespace)
        try:
            device.link.delete()
            LOG.debug("Unplugged interface '%s'", device_name)
        except RuntimeError:
            LOG.error(_LE("Failed unplugging interface '%s'"),
                      device_name)
