import logging
import ipaddress
import threading
from .errors import *
import subprocess as sp
from .cyclic import ipgen
from .util import autodetect_address_pool, autodetect_interface

log = logging.getLogger('trevorproxy.interface')


class SubnetProxy:

    def __init__(self, subnet=None, interface=None, version=6, pool_netmask=16):

        self.lock = threading.Lock()

        pool_netmask = (pool_netmask if version == 6 else 128 - pool_netmask)

        # if no subnet is requested
        self.subnet = subnet
        if self.subnet is None:
            log.info(f'No subnet specified, detecting IPv{version} interfaces.')
            #self.subnet = autodetect_address_pool(version=version)
            if not self.subnet:
                raise SubnetProxyError('Failed to detect IP subnet')
            log.debug(f'Successfully detected subnet: {self.subnet}')
        else:
            self.subnet = ipaddress.ip_network(self.subnet)

        # if no interface is requested
        self.interface = interface
        if self.interface is None:
            log.info(f'No interface specified, detecting.')
            self.interface = autodetect_interface(version=version)
            if not self.interface:
                raise SubnetProxyError('Failed to detect interface')
            log.debug(f'Successfully detected interface: {self.interface}')
        
        self.ipgen = ipgen(self.subnet)


    def start(self):

        cmd = ['ip', 'route', 'add', 'local', str(self.subnet), 'dev', str(self.interface)]
        log.debug(' '.join(cmd))
        sp.run(cmd)


    def stop(self):

        cmd = ['ip', 'route', 'del', 'local', str(self.subnet), 'dev', str(self.interface)]
        log.debug(' '.join(cmd))
        sp.run(cmd)
