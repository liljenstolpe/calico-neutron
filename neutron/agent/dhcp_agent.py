# Copyright 2012 OpenStack Foundation
# Copyright 2015 Metaswitch Networks
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

import functools
import json
import mock
import netaddr
import os
import socket
import sys

import eventlet
eventlet.monkey_patch()

from oslo.config import cfg

from neutron.agent.common import config
from neutron.agent.linux import dhcp
from neutron.agent.linux import interface
from neutron.common import config as common_config
from neutron.common import exceptions
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron import manager
from neutron.openstack.common import importutils
from neutron.openstack.common import log as logging
from neutron.openstack.common import service
from neutron import service as neutron_service

from calico.datamodel_v1 import dir_for_host
from calico.etcdutils import EtcdWatcher
from calico.felix.futils import intern_dict

LOG = logging.getLogger(__name__)

# Intern JSON keys as we load them to reduce occupancy.
FIELDS_TO_INTERN = set([
    # Endpoint dicts.  It doesn't seem worth interning items like the MAC
    # address or TAP name, which are rarely (if ever) shared.
    "profile_id",
    "profile_ids",
    "state",
    "ipv4_gateway",
    "ipv6_gateway",

    # Rules dicts.
    "protocol",
    "src_tag",
    "dst_tag",
    "action",
])
json_decoder = json.JSONDecoder(
    object_hook=functools.partial(intern_dict,
                                  fields_to_intern=FIELDS_TO_INTERN)
)

NETWORK_ID = 'calico'


class DhcpAgent(manager.Manager):
    """
    DHCP agent.  Manages a DHCP driver (such as the dnsmasq wrapper).

    Architecture:

    - Watches Calico etcd database for endpoint information.
    - To avoid blocking the RPC queue while handling the messages,
      queues all updates to a worker thread.
    - The worker thread processes messages in turn, coalescing
      port updates into single calls to the driver's
      reload_allocations method.

    """
    OPTS = [
        cfg.StrOpt('dhcp_driver',
                   default='neutron.agent.linux.dhcp.Dnsmasq',
                   help=_("The driver used to manage the DHCP server.")),
        cfg.BoolOpt('enable_isolated_metadata', default=False,
                    help=_("Support Metadata requests on isolated networks.")),
        cfg.BoolOpt('enable_metadata_network', default=False,
                    help=_("Allows for serving metadata requests from a "
                           "dedicated network. Requires "
                           "enable_isolated_metadata = True")),
        cfg.StrOpt('metadata_proxy_socket',
                   default='$state_path/metadata_proxy',
                   help=_('Location of Metadata Proxy UNIX domain '
                          'socket')),
    ]

    def __init__(self, host=None):
        super(DhcpAgent, self).__init__(host=host)
        self.conf = cfg.CONF
        self.cache = NetworkCache()
        """Cache of the current state of the networks, owned by the
        worker thread."""
        self.root_helper = config.get_root_helper(self.conf)
        self.dhcp_driver_cls = importutils.import_class(self.conf.dhcp_driver)

        self.etcd = EtcdWatcher('localhost:4001',
                                dir_for_host(socket.gethostname()) + "/workload")
        self.etcd.register_path("/calico/v1/host/<hostname>/workload/<orchestrator>" +
                                "/<workload_id>/endpoint/<endpoint_id>",
                                on_set=self.on_endpoint_set,
                                on_del=self.on_endpoint_delete)

        # Work out if DHCP serving for bridged or routed VM interfaces.
        try:
            interface_driver = importutils.import_object(
                self.conf.interface_driver, self.conf)
            self.bridged = interface_driver.bridged()
        except Exception as e:
            msg = (_("Error importing interface driver '%(driver)s': "
                   "%(inner)s") % {'driver': self.conf.interface_driver,
                                   'inner': e})
            LOG.error(msg)
            raise SystemExit(msg)

        # create dhcp dir to store dhcp info
        dhcp_dir = os.path.dirname("/%s/dhcp/" % self.conf.state_path)
        if not os.path.isdir(dhcp_dir):
            os.makedirs(dhcp_dir, 0o755)
        self.dhcp_version = self.dhcp_driver_cls.check_version()
        self._populate_networks_cache()

    NETWORK_ID = 'calico'

    def on_endpoint_set(self, response, hostname, orchestrator,
                        workload_id, endpoint_id):
        """Handler for endpoint updates, passes the update to the splitter.

        Endpoint data is, for example:

        { 'state': 'active' or 'inactive',
          'name': port['interface_name'],
          'mac': port['mac_address'],
          'profile_ids': port['security_groups'],
          'ipv4_nets': ['10.28.0.2/32'],
          'ipv4_gateway': '10.28.0.1',
          'ipv6_nets': ['2001:db8:1::2/128'],
          'ipv6_gateway': '2001:db8:1::1' }

        Port properties needed by DHCP code are:

        { 'id': <unique ID>,
          'network_id': <network ID>,
          'device_owner': 'calico'?,
          'fixed_ips': [ { 'subnet_id': <subnet ID>, 'ip_address': '10.28.0.2' } ],
          'mac_address: <MAC address>,
          'extra_dhcp_opts': ... (optional) }

        Network properties are:

        { 'subnets': [ <subnet object> ],
          'id': <network ID>,
          'namespace': None,
          'ports: [ <port object> ],
          'tenant_id': ? }

        Subnet properties are:

        { 'enable_dhcp': True,
          'ip_version': 4 or 6,
          'cidr': '10.28.0.0/24',
          'dns_nameservers': [],
          'id': <subnet ID>,
          'gateway_ip': <gateway IP address>,
          'host_routes': [] }
        """
        # Get the global network object, creating it if it doesn't
        # already exist.
        net = self.cache.get_network_by_id(NETWORK_ID)
        if not net:
            net = dhcp.NetModel(False,
                                {"id": NETWORK_ID,
                                 "subnets": [],
                                 "ports": []})
            self.cache.put(net)

        # Get the endpoint data.
        endpoint = json_decoder.decode(response.value)

        # Set up subnet objects.
        subnets_changed = False
        fixed_ips = []
        for ip_version in [4, 6]:
            nets_key = 'ipv%s_nets' % ip_version
            gateway_key = 'ipv%s_gateway' % ip_version
            # FIXME: don't hardcode prefix length.
            subnet_suffix = '/24' if ip_version == 4 else '/80'

            if gateway_key in endpoint:
                # Construct the CIDR for this endpoint's IPv? subnet.
                cidr = netaddr.IPNetwork(endpoint[gateway_key] + subnet_suffix)

                # See if we already have this subnet.
                if [s for s in net.subnets if s.cidr == cidr]:
                    # Yes, no change needed to network object.
                    pass
                else:
                    # No, update the network object with a new subnet.
                    subnet = {'enable_dhcp': True,
                              'ip_version': ip_version,
                              'cidr': cidr,
                              'dns_nameservers': [],
                              'id': cidr,
                              'gateway_ip': endpoint[gateway_key],
                              'host_routes': []}
                    net = dhcp.NetModel(False,
                                        {"id": net.id,
                                         "subnets": net.subnets + [subnet],
                                         "ports": net.ports,
                                         "tenant_id": "calico"})
                    self.cache.put(net)
                    subnets_changed = True

                # Generate the fixed IPs for the endpoint on this subnet.
                fixed_ips += [ {'subnet_id': cidr,
                                'ip_address': n.split('/')[0]}
                               for n in endpoint[nets_key] ]
        LOG.info("net: %s", net)
        if subnets_changed:
            self.call_driver('restart', net)

        # Construct port equivalent of endpoint data.
        port = {'id': endpoint_id,
                'network_id': NETWORK_ID,
                'device_owner': 'calico',
                'fixed_ips': fixed_ips,
                'mac_address': endpoint['mac'],
                'extra_dhcp_opts': []}
        self.cache.put_port(dhcp.DictModel(port))
        LOG.info("port: %s", port)

        self.call_driver('reload_allocations', net)

    def on_endpoint_delete(self, response, hostname, orchestrator,
                           workload_id, endpoint_id):
        """Handler for endpoint deleted, passes the update to the splitter."""

        # Find the corresponding port in the DHCP agent's cache.
        port = self.cache.get_port_by_id(endpoint_id)
        if port:
            self.cache.remove_port(port)
            self.call_driver('reload_allocations', net)

    def after_start(self):
        self.run()
        LOG.info(_("DHCP agent started"))

    def run(self):
        """
        Starts the worker thread, which owns the driver.
        """
        eventlet.spawn(self.etcd.loop)

    def _populate_networks_cache(self):
        """Populate the networks cache when the DHCP-agent starts."""
        try:
            existing_networks = self.dhcp_driver_cls.existing_dhcp_networks(
                self.conf,
                self.root_helper
            )
            for net_id in existing_networks:
                net = dhcp.NetModel(self.bridged and
                                    self.conf.use_namespaces,
                                    {"id": net_id,
                                     "subnets": [],
                                     "ports": []})
                self.cache.put(net)
        except NotImplementedError:
            # just go ahead with an empty networks cache
            LOG.debug(
                _("The '%s' DHCP-driver does not support retrieving of a "
                  "list of existing networks"),
                self.conf.dhcp_driver
            )

    def call_driver(self, action, network, **action_kwargs):
        """Invoke an action on a DHCP driver instance."""
        LOG.debug(_('Calling driver for network: %(net)s action: %(action)s'),
                  {'net': network.id, 'action': action})
        try:
            # the Driver expects something that is duck typed similar to
            # the base models.
            driver = self.dhcp_driver_cls(self.conf,
                                          network,
                                          self.root_helper,
                                          self.dhcp_version,
                                          mock.Mock())

            getattr(driver, action)(**action_kwargs)
            return True
        except exceptions.Conflict:
            # No need to resync here, the agent will receive the event related
            # to a status update for the network
            LOG.warning(_('Unable to %(action)s dhcp for %(net_id)s: there is '
                          'a conflict with its current state; please check '
                          'that the network and/or its subnet(s) still exist.')
                        % {'net_id': network.id, 'action': action})
        except Exception as e:
            if (isinstance(e, n_rpc.RemoteError)
                and e.exc_type == 'NetworkNotFound'
                or isinstance(e, exceptions.NetworkNotFound)):
                LOG.warning(_("Network %s has been deleted."), network.id)
            else:
                LOG.exception(_('Unable to %(action)s dhcp for %(net_id)s.')
                              % {'net_id': network.id, 'action': action})


class NetworkCache(object):
    """Agent cache of the current network state."""
    def __init__(self):
        self.cache = {}
        self.subnet_lookup = {}
        self.port_lookup = {}

    def get_network_ids(self):
        return self.cache.keys()

    def get_network_by_id(self, network_id):
        return self.cache.get(network_id)

    def get_network_by_subnet_id(self, subnet_id):
        return self.cache.get(self.subnet_lookup.get(subnet_id))

    def get_network_by_port_id(self, port_id):
        return self.cache.get(self.port_lookup.get(port_id))

    def put(self, network):
        if network.id in self.cache:
            self.remove(self.cache[network.id])

        self.cache[network.id] = network

        for subnet in network.subnets:
            self.subnet_lookup[subnet.id] = network.id

        for port in network.ports:
            self.port_lookup[port.id] = network.id

    def remove(self, network):
        del self.cache[network.id]

        for subnet in network.subnets:
            del self.subnet_lookup[subnet.id]

        for port in network.ports:
            del self.port_lookup[port.id]

    def put_port(self, port):
        network = self.get_network_by_id(port.network_id)
        for index in range(len(network.ports)):
            if network.ports[index].id == port.id:
                network.ports[index] = port
                break
        else:
            network.ports.append(port)

        self.port_lookup[port.id] = network.id

    def remove_port(self, port):
        network = self.get_network_by_port_id(port.id)

        for index in range(len(network.ports)):
            if network.ports[index] == port:
                del network.ports[index]
                del self.port_lookup[port.id]
                break

    def get_port_by_id(self, port_id):
        network = self.get_network_by_port_id(port_id)
        if network:
            for port in network.ports:
                if port.id == port_id:
                    return port

    def get_state(self):
        net_ids = self.get_network_ids()
        num_nets = len(net_ids)
        num_subnets = 0
        num_ports = 0
        for net_id in net_ids:
            network = self.get_network_by_id(net_id)
            num_subnets += len(network.subnets)
            num_ports += len(network.ports)
        return {'networks': num_nets,
                'subnets': num_subnets,
                'ports': num_ports}


DhcpAgentWithStateReport = DhcpAgent


def register_options():
    cfg.CONF.register_opts(DhcpAgent.OPTS)
    config.register_interface_driver_opts_helper(cfg.CONF)
    config.register_use_namespaces_opts_helper(cfg.CONF)
    config.register_agent_state_opts_helper(cfg.CONF)
    config.register_root_helper(cfg.CONF)
    cfg.CONF.register_opts(dhcp.OPTS)
    cfg.CONF.register_opts(interface.OPTS)


def main():
    register_options()
    common_config.init(sys.argv[1:])
    config.setup_logging()
    server = neutron_service.Service.create(
        binary='neutron-dhcp-agent',
        topic=topics.DHCP_AGENT,
        report_interval=cfg.CONF.AGENT.report_interval,
        manager='neutron.agent.dhcp_agent.DhcpAgentWithStateReport')
    service.launch(server).wait()
