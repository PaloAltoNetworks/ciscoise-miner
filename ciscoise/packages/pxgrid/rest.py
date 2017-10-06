#
# Copyright (c) 2017 Palo Alto Networks, Inc. <techbizdev@paloaltonetworks.com>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

'''\
Python interface to the Cisco ISE pxGrid bulk download REST API.

Bulk downloads in XMPP-Grid occur out-of-band (over a different
connection and protocol than XMPP).  Cisco pxGrid uses a REST-like
API over HTTPS, which is undocumented.

For session download the endpoint is
/pxgrid/mnt/sd/getSessionListByTime.

Username and password authentication does not work using the password
provided by ISE, as the password that must be used in the HTTP
Authorization header appears to be an encoded version of the ISE
password.

The interface is specific to requirements for creating ip-sgt and
ip-user mappings on PAN-OS.

'''

from datetime import datetime
import inspect
import logging
import pprint
import xml.etree.ElementTree as etree
from io import StringIO

from . import DEBUG1, DEBUG2, DEBUG3

try:
    import requests
except ImportError:
    raise ValueError('Install requests library: '
                     'http://docs.python-requests.org/')

# https://github.com/shazow/urllib3/issues/655
# Requests treats None as forever
_None = object()


class PxgridRestRequest:
    def __init__(self, name=None):
        self.name = name
        # python-requests
        self.response = None
        self.status_code = None
        self.reason = None
        self.headers = None
        self.encoding = None
        self.content = None
        self.text = None
        #
        self.xml_root = None
        self.obj = None

    def raise_for_status(self):
        if self.response is not None:
            try:
                self.response.raise_for_status()
            except requests.exceptions.HTTPError as e:
                raise PxgridRestError(e)


class PxgridRestError(Exception):
    pass


class PxgridRest:
    def __init__(self,
                 hostname=None,
                 username=None,
                 password=None,
                 cert=None,
                 cert_password=None,  # XXX unused; no support in requests
                 verify=None,
                 timeout=_None):
        self._log = logging.getLogger(__name__).log
        self._log(DEBUG2, 'requests version: %s', requests.__version__)
        self.session = requests.Session()
        # XXX https://github.com/requests/requests/issues/3829
        self.session.trust_env = False
        if hostname is None:
            raise PxgridRestError('no hostname')
        if username is None:
            raise PxgridRestError('no username')

        self.session.headers.update({'user':
                                     '%s@xgrid.cisco.com' % username})
        if password is not None:
            self.session.auth = requests.auth.HTTPBasicAuth(username, password)
        elif cert is not None:
            self.session.cert = cert
        else:
            raise PxgridRestError('must provide password or cert')

        if verify is not None:
            self.session.verify = verify

        if not (logging.getLogger(__name__).getEffectiveLevel() in
                [DEBUG1, DEBUG2, DEBUG3]):
            requests.packages.urllib3.disable_warnings()

        self.timeout = timeout
        self.uri = 'https://' + hostname + ':8910'

    def _request(self,
                 url,
                 headers,
                 data):

        kwargs = {}
        if self.timeout is not _None:
            kwargs['timeout'] = self.timeout

        try:
            r = self.session.post(url=url,
                                  headers=headers,
                                  data=data,
                                  **kwargs)
        except (requests.exceptions.RequestException, ValueError) as e:
            raise PxgridRestError(e)

        return r

    def _set_attributes(self, r):
        x = PxgridRestRequest(inspect.stack()[1][3])
        # http://docs.python-requests.org/en/master/api/#requests.Response
        x.response = r
        x.status_code = r.status_code
        x.reason = r.reason
        x.headers = r.headers
        x.encoding = r.encoding
        self._log(DEBUG2, r.encoding)
        self._log(DEBUG2, r.request.headers)  # XXX authorization header
        self._log(DEBUG2, r.headers)
        x.content = r.content  # bytes
        x.text = r.text  # Unicode
        self._log(DEBUG3, r.text)
        try:
            x.xml_root = etree.fromstring(r.content)
        except etree.ParseError as e:
            self._log(DEBUG1, 'ElementTree.fromstring ParseError: %s', e)

        if x.xml_root is not None:
            self._log(DEBUG1, 'root tag: %s', x.xml_root.tag)

            self.namespaces = dict([
                elem for _, elem in etree.iterparse(
                    StringIO(x.text), events=['start-ns']
                )
            ])
            self._log(DEBUG2, 'namespaces: %s',
                      pprint.pformat(self.namespaces))
            used = ['ns2', 'ns3', 'ns4']
            if not all(k in self.namespaces for k in used):
                raise PxgridRestError('missing namespace(s): %s' %
                                      repr(set(used) -
                                           set(self.namespaces.keys())))

        return x

    def get_session_list(self,
                         start_time=None,
                         end_time=None):
        xml = '''\
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<ns2:getSessionListByTimeRequest
    xmlns:ns2="http://www.cisco.com/pxgrid/identity"
    xmlns:ns3="http://www.cisco.com/pxgrid"
    xmlns:ns4="http://www.cisco.com/pxgrid/net">
  <ns2:timeWindow>%s%s
  </ns2:timeWindow>
</ns2:getSessionListByTimeRequest>'''

        xml_begin = '''
    <ns3:begin>%s</ns3:begin>'''

        xml_end = '''
    <ns3:end>%s</ns3:end>'''

        def date_time(x):
            if isinstance(x, datetime):
                t = datetime.isoformat(x)
            else:
                t = x
            return t

        headers = {
            'accept': 'application/xml',
            'content-type': 'application/xml',
            }
        path = '/pxgrid/mnt/sd/getSessionListByTime'
        url = self.uri + path

        start = end = ''
        if start_time is not None:
            start = xml_begin % date_time(start_time)
        if end_time is not None:
            end = xml_end % date_time(end_time)

        data = xml % (start, end)
        self._log(DEBUG3, '%s', data)

        r = self._request(url=url, headers=headers, data=data)
        x = self._set_attributes(r)

        if x.xml_root is not None:
            rk = 'sessions'  # root key
            if x.xml_root.tag == '{%s}getSessionListByTimeResponse' % \
               self.namespaces['ns3']:
                x.obj = {}
                x.obj[rk] = []
                for elem in x.xml_root.findall('ns3:sessions/ns4:session',
                                               self.namespaces):
                    o = {}
                    xmap = {
                        'lastUpdateTime': 'ns2:lastUpdateTime',
                        'gid': 'ns2:gid',
                        'state': 'ns4:state',
                        'interface': 'ns4:interface',
                        'user': 'ns4:user',
                        'securityGroup': 'ns4:securityGroup',
                        }

                    for k in xmap.keys():
                        e = elem.find(xmap[k], self.namespaces)
                        if e is not None:
                            if k == 'user':
                                v = e.find('ns2:%s' % 'name', self.namespaces)
                                if v is not None:
                                    o[k] = v.text
                            elif k == 'interface':
                                v = e.find('ns4:macAddress', self.namespaces)
                                if v is not None:
                                    o['macAddress'] = v.text
                                v = e.find('ns4:%s/ns2:%s' %
                                           ('ipIntfID', 'ipAddress'),
                                           self.namespaces)
                                if v is not None:
                                    o['ipaddress'] = v.text
                            else:
                                o[k] = e.text

                    if o:
                        x.obj[rk].append(o)

                self._log(DEBUG2, pprint.pformat(x.obj))

        return x
