# Copyright 2012 Nachi Ueno, NTT MCL, Inc.
# All rights reserved.
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

from neutron.api import extensions
from neutron.api.v2 import attributes
from neutron.api.v2 import base
from neutron import manager
from neutron.api.v2 import resource_helper
from neutron.plugins.common import constants


EXT_PREFIX='/onosfp'
EXT_ALIAS='flow'
COLLECTION_NAME='%ss' % EXT_ALIAS

RESOURCE_ATTRIBUTE_MAP = {
    'flow': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True,
               'primary_key': True},
        'deviceid': {'allow_post': True,
                         'allow_put': False,
                         'is_visible': True,
                         'default': ''},
        'port': {'allow_post': True,
                         'allow_put': False,
                         'is_visible': True,
                         'default': ''},
        'ethtype': {'allow_post': True,
                         'allow_put': False,
                         'is_visible': True,
                         'default': ''}
    }
}


class Onosfp(extensions.ExtensionDescriptor):
#   path_prefix = "onosfp"
    @classmethod
    def get_name(cls):
        return "ONOS Flowprogramming"

    @classmethod
    def get_alias(cls):
        return 'onosfp'

    @classmethod
    def get_description(cls):
        return "Onos Flow programming"

    @classmethod
    def get_namespace(cls):
        return "ns:neutron:onosfp:v1"

    @classmethod
    def get_updated(cls):
        return "2012-07-20T10:00:00-00:00"
    
    @classmethod
    def get_resources(cls):
    # This method registers the URL and the dictionary  of
    # attributes on the neutron-server.
        exts = list()
#        plugin = manager.NeutronManager.get_plugin()
	plugin = manager.NeutronManager.get_service_plugins()['ONOSFP']
        resource_name = EXT_ALIAS
        collection_name= COLLECTION_NAME
        params = RESOURCE_ATTRIBUTE_MAP.get(resource_name)
        controller = base.create_resource(collection_name, resource_name,
                                              plugin, params, allow_bulk=False)
        ex = extensions.ResourceExtension(collection_name, controller,path_prefix=EXT_PREFIX)
        exts.append(ex)
        return exts

    def get_extended_resources(self, version):
        if version == "2.0":
            return RESOURCE_ATTRIBUTE_MAP
        else:
            return {}
