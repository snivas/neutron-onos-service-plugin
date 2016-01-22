# Copyright 2013 Mirantis Inc.
# All Rights Reserved
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
#
# @author: Ilya Shakhat, Mirantis Inc.
#

from neutronclient.i18n import _
from neutronclient.neutron import v2_0 as neutronV20


class Createflow(neutronV20.CreateCommand):
    """Create a vip."""

    resource = 'flows'

    def add_known_arguments(self, parser):
        parser.add_argument(
            'id', metavar='id',
            help=_('ID unique'))
        parser.add_argument(
            '--deviceid',
            help=_('Switch/Device ID.'))
        parser.add_argument(
            '--port',
            help=_('Target port'))
        parser.add_argument(
            '--ethType',
            help=_('Ethernet type'))

    def args2body(self, parsed_args):
        _tenant_id = neutronV20.find_resourceid_by_name_or_id(self.get_client(), 'tenant', parsed_args.tenant_id)
        body = {
            self.resource: {
                'tenant_id': _tenant_id
            },
        }
        neutronV20.update_dict(parsed_args, body[self.resource],['deviceid','port','ethType'])
        return body

