from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.common import constants
from oslo_log import log as logging
from neutron.services import service_base
from neutron.services.onosfp.driver.onos_driver import ONOSRestDriver 
from neutron.services.onosfp.db import onosfp_db as fpdb

LOG = logging.getLogger(__name__)

#service_base.ServicePluginBase
class OnosFPPlugin(service_base.ServicePluginBase, fpdb.Onosfp_db_mixin):
    supported_extension_aliases = ["onosfp"]

    def __init__(self):
        super(OnosFPPlugin, self).__init__()
	self.onosdriver = ONOSRestDriver()

#	pass

    def get_plugin_name(self):
        return "ONOS Flowprogramming"

    def get_plugin_type(self):
        return constants.ONOSFP

    def get_plugin_description(self):
        return ("ONOS Flow Progamming")

    def create_flow(self, context, flow):
	res = self.onosdriver.create_flow(context,flow)
	status=400
	resp={}
	try:
            data=res.get('body')
	    status=res.get('status')
        except:
            return {}
	if status in [200,201]:
		resp=super(OnosFPPlugin, self).create_db_flow(context, flow)
	return resp

    def create_flow_bulk(self, context, params):
        return {}

    def update_flow(self, context, id):
        # The id is the unique identifier to your entry, foxinsock is a
        # dictionary with values that needs to be updated with.
	pass
    def get_flow(self, context, id, fields):
        # The id is the unique identifier to your entry.
        # fields are the columns that you wish to display.
	pass
    def get_flows(self, context, filters, fields):
        # Note there is an extra 's'.
        # filters contains the column name with a value with which
        # you can return multiple row entries that matches the filter
        # fields are the columns that you wish to display.
	return {}
	#pass
    def delete_flow(self, context, id):
        # The id is the unique identifier that can be used to delete
        # the row entry of your database.
	pass
