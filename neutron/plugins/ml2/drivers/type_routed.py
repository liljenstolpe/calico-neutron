# Copyright (c) 2013,2015 OpenStack Foundation
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

from oslo_log import log
import six

from neutron.common import exceptions as exc
from neutron.i18n import _LI
from neutron.plugins.common import constants as p_const
from neutron.plugins.ml2 import driver_api as api

LOG = log.getLogger(__name__)


class RoutedTypeDriver(api.TypeDriver):
    """Manage state for routed networks with ML2.

    The RoutedTypeDriver implements the 'routed' network_type.  Routed
    network segments provide IP-level connectivity between VMs that
    are attached to the same network.

    """

    def __init__(self):
        LOG.info(_LI("ML2 RoutedTypeDriver initialization complete"))

    def get_type(self):
        return p_const.TYPE_ROUTED

    def initialize(self):
        pass

    def is_partial_segment(self, segment):
        return False

    def validate_provider_segment(self, segment):
        for key, value in six.iteritems(segment):
            if value and key != api.NETWORK_TYPE:
                msg = _("%s prohibited for routed provider network") % key
                raise exc.InvalidInput(error_message=msg)

    def reserve_provider_segment(self, session, segment):
        # No resources to reserve
        return segment

    def allocate_tenant_segment(self, session):
        # Tenant routed networks are not yet supported.
        return

    def release_segment(self, session, segment):
        # No resources to release
        pass

    def get_mtu(self, physical_network=None):
        pass
