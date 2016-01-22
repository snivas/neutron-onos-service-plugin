import sqlalchemy as sa
from sqlalchemy.ext.orderinglist import ordering_list
from sqlalchemy import orm
from sqlalchemy.orm import exc

#from neutron.db import db_base_plugin_v2 as base_db
from neutron.db import common_db_mixin as base_db
from neutron.db import model_base
from neutron.db import models_v2
from neutron.openstack.common import uuidutils
from neutron.plugins.common import constants as const
from datetime import datetime


class Flows(model_base.BASEV2, models_v2.HasId):
    """Represents the HostStatistics."""
    __tablename__ = 'onosflows'
    deviceid = sa.Column(sa.String(255))
    port = sa.Column(sa.String(255))
    ethtype = sa.Column(sa.String(255))
    extend_existing=True

class Onosfp_db_mixin( base_db.CommonDbMixin):

    def create_db_flow(self, context, params):
        flowparam = params['flow']	 
        with context.session.begin(subtransactions=True):
            data = Flows(id=uuidutils.generate_uuid(),
            deviceid= flowparam['deviceid'],
            port=flowparam['port'],
	    ethtype=flowparam['ethtype'])
            context.session.add(data)
        return self._make_createflow_response(data)

    def _make_createflow_response(self, flowparam):
        res = {'id': flowparam['id'],
                'deviceid':flowparam["deviceid"],
                'port':flowparam["port"],
                'ethtype': flowparam["ethtype"]
               }
        return self._fields(res, flowparam)


