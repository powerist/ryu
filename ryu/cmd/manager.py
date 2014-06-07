#!/usr/bin/env python
#
# Copyright (C) 2011, 2012 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2011 Isaku Yamahata <yamahata at valinux co jp>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
import os
import sys

from oslo.config import cfg
from kazoo.client import KazooClient

SELF_DIR = os.path.abspath(os.path.dirname(__file__))
TOP_DIR = os.path.abspath(os.path.join(SELF_DIR,
                                       os.pardir,
                                       os.pardir))
sys.path.insert(0, TOP_DIR)
from ryu.lib import hub
from ryu import log
from ryu import version
from ryu.app import wsgi
from ryu.base.app_manager import AppManager
#from ryu import flags
#from ryu.controller import controller
#from ryu.topology import switches
#
# # TODO:
# #   Right now, we have our own patched copy of ovs python bindings
# #   Once our modification is upstreamed and widely deployed,
# #   use it
# #
# # NOTE: this modifies sys.path and thus affects the following imports.
# # eg. oslo.config.cfg.
# import ryu.contrib

log.early_init_log(logging.DEBUG)
hub.patch()

LOGGER = logging.getLogger(__name__)

CONF = cfg.CONF
CONF.register_cli_opts([
    cfg.ListOpt('app-lists', default=[],
                help='application module name to run'),
    cfg.MultiStrOpt('app', positional=True, default=[],
                    help='application module name to run')
])

CONF.import_opt('zookeeper_storage', 'ryu.app.inception_conf')
CONF.import_opt('zk_servers', 'ryu.app.inception_conf')
CONF.import_opt('zk_election', 'ryu.app.inception_conf')


def main():
    config_file = None
    try:
        config_file = '/usr/local/etc/ryu/ryu.conf'
        CONF(project='ryu', version='ryu-manager %s' % version,
             default_config_files=[config_file])
    except cfg.ConfigFilesNotFoundError:
        try:
            config_file = os.path.join(TOP_DIR, 'etc/ryu/inception.conf')
            CONF(project='ryu', version='ryu-manager %s' % version,
                 default_config_files=[config_file])
        except cfg.ConfigFilesNotFoundError:
            CONF(project='ryu', version='ryu-manager %s' % version)

    log.init_log()
    LOGGER.info('config_file=%s', config_file)

    # if using zookeeper backend storage, use it for leader election
    if CONF.zookeeper_storage:
        LOGGER.info('ZooKeeper servers=%s', CONF.zk_servers)
        zk = KazooClient(hosts=CONF.zk_servers, logger=LOGGER)
        zk.start()
        election = zk.Election(CONF.zk_election)
        LOGGER.info('Contending to be the leader...')
        election.run(real_main)
    # otherwise, directly run real main function
    else:
        real_main()

def real_main():
    LOGGER.info('I win leader election, Ryu controller start running')

    app_lists = CONF.app_lists + CONF.app
    # keep old behaivor, run ofp if no application is specified.
    if not app_lists:
        app_lists = ['ryu.controller.ofp_handler']

    app_mgr = AppManager.get_instance()
    app_mgr.load_apps(app_lists)
    contexts = app_mgr.create_contexts()
    services = []
    services.extend(app_mgr.instantiate_apps(**contexts))

    webapp = wsgi.start_service(app_mgr)
    if webapp:
        thr = hub.spawn(webapp)
        services.append(thr)

    try:
        hub.joinall(services)
    finally:
        app_mgr.close()


if __name__ == "__main__":
    main()
