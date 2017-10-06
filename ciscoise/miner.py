#  Copyright 2017 Palo Alto Networks, Inc
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import ipaddress
import logging
import os
import yaml

from minemeld.ft.basepoller import BasePollerFT
import ciscoise.packages.pxgrid.rest as rest

LOG = logging.getLogger(__name__)
DEFAULT_ATTRIBUTE_PREFIX = 'ise_'


class PxgridRestSession(BasePollerFT):
    def configure(self):
        super(PxgridRestSession, self).configure()

        self.kwargs = {}
        for x in ['hostname', 'username', 'password',
                  'cert', 'verify',
                  'timeout', 'attribute_prefix']:
            if x == 'attribute_prefix':
                self.attribute_prefix = \
                    self.config.get(x, DEFAULT_ATTRIBUTE_PREFIX)
            else:
                self.kwargs[x] = self.config.get(x, None)

        self.side_config_path = self.config.get('side_config', None)
        if self.side_config_path is None:
            self.side_config_path = os.path.join(
                os.environ['MM_CONFIG_DIR'],
                '%s_side_config.yml' % self.name
            )

        self._load_side_config()

        d = self.kwargs.copy()
        if d['password']:
            d['password'] = '*' * 6
        LOG.debug('%s attribute_prefix: %s', d, self.attribute_prefix)

    def _load_side_config(self):
        try:
            with open(self.side_config_path, 'r') as f:
                sconfig = yaml.safe_load(f)

        except IOError as e:
            LOG.info('%s - No side config: %s', self.name, e)
            return

        if sconfig is None:
            LOG.info('%s - Empty side config: %s', self.name,
                     self.side_config_path)
            return

        for x in ['hostname', 'username', 'password',
                  'cert', 'verify',
                  'timeout', 'attribute_prefix']:
            v = sconfig.get(x, None)
            if v is not None:
                if x == 'attribute_prefix':
                    self.attribute_prefix = v
                else:
                    self.kwargs[x] = v

    @staticmethod
    def ip_version(x):
        try:
            x = unicode(x)
        except NameError:
            pass

        try:
            ip = ipaddress.ip_address(x)
        except ValueError as e:
            LOG.warning('%s: %s', x, e)
            return None

        if ip.version == 4:
            return 'IPv4'
        if ip.version == 6:
            return 'IPv6'

    def _process_item(self, item):
        x = item.copy()
        del x['ip']

        return [[item['ip'], x]]

    def _build_iterator(self, now):
        def indicators(obj):
            LOG.info('ISE sessions: %d', len(obj))
            # XXX
            if len(obj) < 10:
                LOG.debug('ISE sessions: %s', obj)
            for item in obj:
                try:
                    for x in ['state', 'ipaddress']:
                        if x not in item:
                            LOG.warning('no "%s" field: %s', x, item)
                            raise RuntimeWarning()
                except RuntimeWarning:
                    continue
                if item['state'] not in ['Authenticated', 'Started']:
                    continue
                x = {}
                x['ip'] = item['ipaddress']
                version = self.ip_version(item['ipaddress'])
                if version is None:
                    continue
                x['type'] = version
                if 'user' in item:
                    x[self.attribute_prefix + 'user'] = item['user']
                if 'securityGroup' in item:
                    x[self.attribute_prefix + 'sgt'] = item['securityGroup']
                yield x

        try:
            api = rest.PxgridRest(**self.kwargs)
            r = api.get_session_list()
            r.raise_for_status()
            if r.obj is None:
                x = 'no response object'
                raise rest.PxgridRestError(x)
            if 'sessions' not in r.obj:
                x = '"sessions" key not in response object'
                raise rest.PxgridRestError(x)
        except rest.PxgridRestError as e:
            x = '%s: poll not performed: %s' % (self.name, e)
            LOG.info('%s', x)
            raise RuntimeError(x)

        return indicators(r.obj['sessions'])

    def hup(self, source=None):
        LOG.info('%s - hup received, reload side config', self.name)
        self._load_side_config()
        super(PxgridRestSession, self).hup(source=source)

    @staticmethod
    def gc(name, config=None):
        basepoller.BasePollerFT.gc(name, config=config)

        side_config_path = None
        if config is not None:
            side_config_path = config.get('side_config', None)
        if side_config_path is None:
            side_config_path = os.path.join(
                os.environ['MM_CONFIG_DIR'],
                '{}_side_config.yml'.format(name)
            )

        try:
            os.remove(side_config_path)
        except:
            pass
