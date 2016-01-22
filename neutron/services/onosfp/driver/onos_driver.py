import base64
import requests
import httplib2
from oslo.config import cfg
from oslo_log import log as logging
from oslo_serialization import jsonutils as json

LOG = logging.getLogger(__name__)
REST_URL_PREFIX = '/onos/v1/flows'

class ONOSRestDriver(object):
    def __init__(self):
        self.user = 'admin'
        self.passwd = 'admin'
        self.server = 'locanhost'
        self.port = '8181' 
        self.timeout = 3

    def rest_api(self, method, url, body=None, headers=None):
        url = REST_URL_PREFIX + url
        if body:
            body_data = json.dumps(body)
        else:
            body_data = ''

        try:
            url = "http://" + self.server + ":" + self.port + url
            #h = httplib2.Http(".cache")
            h = httplib2.Http()
            h.add_credentials(self.user, self.passwd)
            resp, resp_str = h.request(url, method,
                                       body=body_data,
                                       headers=headers)
            if resp.status in [200,201]:
                return {'status': resp.status,
                        'reason': resp.reason,
                        'body': json.loads(resp_str)}
        except Exception, e:
            print "Exception = ", e
 
    def create_flow(self, context, flowparams):
        LOG.debug("Create ONOS Flow------------------------------")
        deviceid = flowparams['flow']['deviceid']
        ethtype = flowparams['flow']['ethtype']
        port = flowparams['flow']['port']
        postbody = {'flow':{'isPermanent':'true', 'selector':{'criteria':[{'type': 'ETH_TYPE','ethType': ethtype}]}}},{'priority': 1,'deviceId': deviceid,'timeout': 10,'treatment':{'deferred': [],'instructions': [{'type': 'OUTPUT','port': port}]}}
        resp = self.rest_api('POST','/'+deviceid, body=postbody)
        return resp


