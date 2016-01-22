import base64
import requests
import httplib2
from oslo.config import cfg
from oslo_log import log as logging
from oslo_serialization import jsonutils as json

LOG = logging.getLogger(__name__)
REST_URL_PREFIX = '/sample.json'

class ONOSRestDriver(object):
    def __init__(self):
        self.user = 'admin'
        self.passwd = 'admin'
        self.server = 'localhost'
        self.port = '80' 
        self.timeout = 3

    def rest_api(self, method, url, body=None, headers=None):
        url = REST_URL_PREFIX + url
        if body:
            body_data = json.dumps(body)
        else:
            body_data = ''

        try:
            url = "http://" + self.server + ":" + self.port + url
            h = httplib2.Http()
            h.add_credentials("admin", "admin")
            resp, resp_str = h.request(url, method,
                                       body=body_data,
                                       headers=headers)
            if resp.status == 200:
                return {'status': resp.status,
                        'reason': resp.reason,
                        'body': json.loads(resp_str)}
        except Exception, e:
            print "Exception = ", e
 
    def create_flow(self, context, flowparams):
        LOG.debug(_("Create ONOS Flow"))
        body = self.rest_api('GET','')
        LOG.debug(_(body['status']))
        return body

