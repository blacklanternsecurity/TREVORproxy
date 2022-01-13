import os
import sh
import sys
import logging
from . import logger
from time import sleep
import subprocess as sp
from pathlib import Path
from .errors import SSHProxyError

log = logging.getLogger('trevorproxy.ssh')


class SSHProxy:

    def __init__(self, host, proxy_port, key=None, key_pass='', ssh_args={}):

        self.host = host
        self.proxy_port = proxy_port
        self.key = key
        self.key_pass = key_pass
        self.ssh_args = dict(ssh_args)
        # Enable SSH socks proxy
        self.ssh_args['D'] = str(proxy_port)
        # Disable the "Are you sure you want to continue connecting" prompt
        self.ssh_args['o'] = 'StrictHostKeychecking=no'
        if key:
            self.ssh_args['i'] = str(Path(key).absolute())
        self.sh = None
        self.command = ''
        self._ssh_stdout = ''
        self.running = False


    def start(self, wait=True, timeout=30):

        self.stop()
        log.info(f'Opening SSH connection to {self.host}')

        self._ssh_stdout = ''
        self._password_entered = False
        self.sh = sh.ssh(
            self.host,
            _out=self._enter_password,
            _out_bufsize=0,
            _tty_in=True,
            _unify_ttys=True,
            _long_sep=' ',
            _bg=True,
            _bg_exc=False,
            **self.ssh_args
        )
        self.command = b' '.join(self.sh.cmd).decode()
        log.debug(self.command)

        left = int(timeout)
        if wait:
            while not self.is_connected():
                left -= 1
                if left <= 0 or not self.sh.is_alive():
                    raise SSHProxyError(f'Failed to start SSHProxy {self}')
                else:
                    sleep(1)


    def stop(self):

        try:
            self.sh.process.terminate()
        except:
            try:
                self.sh.process.kill()
            except:
                pass


    def _enter_password(self, char, stdin):

        if self._password_entered or not char:
            # save on CPU
            sleep(.01)
        else:
            self._ssh_stdout += char
            if 'pass' in self._ssh_stdout and self._ssh_stdout.endswith(': '):
                stdin.put(f'{self.key_pass}\n')


    def is_connected(self):

        if self.sh is None:
            return False

        netstat = sp.run(['ss', '-ntlp'], stderr=sp.DEVNULL, stdout=sp.PIPE)
        if not f' 127.0.0.1:{self.proxy_port} ' in netstat.stdout.decode():
            log.debug(f'Waiting for {" ".join([x.decode() for x in self.sh.cmd])}')
            self.running = False
        else:
            self.running = True
            self._password_entered = True

        return self.running


    def __hash__(self):

        return hash(str(self))


    def __str__(self):

        return f'socks5://127.0.0.1:{self.proxy_port}'


    def __repr__(self):

        return str(self)



class IPTables:

    def __init__(self, proxies, address=None, proxy_port=None):

        if address is None:
            self.address = '127.0.0.1'
        else:
            self.address = str(address)
        if proxy_port is None:
            self.proxy_port = 1080
        else:
            self.proxy_port = int(proxy_port)

        self.proxies = [p for p in proxies if p is not None]
        self.args_pre = []
        if os.geteuid() != 0:
            self.args_pre = ['sudo']

        self.iptables_rules = []


    def start(self):

        log.debug('Creating iptables rules')

        current_ip = False
        for i,proxy in enumerate(self.proxies):
            if proxy is not None:
                iptables_add = ['iptables', '-A']
                iptables_main = ['OUTPUT', '-t', 'nat', '-d', f'{self.address}', '-o', 'lo', '-p', \
                    'tcp', '--dport', f'{self.proxy_port}', '-j', 'DNAT', '--to-destination', f'127.0.0.1:{proxy.proxy_port}']

                # if this isn't the last proxy
                if not i == len(self.proxies)-1:
                    iptables_main += ['-m', 'statistic', '--mode', 'nth', '--every', f'{len(self.proxies)-i}', '--packet', '0']

                self.iptables_rules.append(iptables_main)

                cmd = self.args_pre + iptables_add + iptables_main
                log.debug(' '.join(cmd))
                sp.run(cmd)


    def stop(self):

        log.debug('Cleaning up iptables rules')

        for rule in self.iptables_rules:
            iptables_del = ['iptables', '-D']
            cmd = self.args_pre + iptables_del + rule
            log.debug(' '.join(cmd))
            sp.run(cmd)



class SSHLoadBalancer:

    dependencies = ['ssh', 'ss', 'iptables', 'sudo']

    def __init__(self, hosts, key=None, key_pass=None, base_port=33482, current_ip=False, socks_server=False):

        self.args = dict()
        self.hosts = hosts
        self.key = key
        self.key_pass = key_pass
        self.base_port = base_port
        self.current_ip = current_ip
        self.proxies = dict()
        self.socks_server = socks_server

        for i,host in enumerate(hosts):
            proxy_port = self.base_port + i
            proxy = SSHProxy(host, proxy_port, key, key_pass, ssh_args=self.args)
            self.proxies[str(proxy)] = proxy

        if current_ip:
            self.proxies['None'] = None

        self.proxy_round_robin = list(self.proxies.values())
        self.round_robin_counter = 0

        self.iptables = IPTables(list(self.proxies.values()))


    def start(self, timeout=30):

        [p.start(wait=False) for p in self.proxies.values() if p is not None]            

        # wait for them all to start
        left = int(timeout)
        while not all([p.is_connected() for p in self.proxies.values() if p is not None]):
            left -= 1
            for p in self.proxies.values():
                if p is not None and (not p.sh.is_alive() or left <= 0):
                    raise SSHProxyError(f'Failed to start SSH proxy {p}: {p.command}')
            sleep(1)

        if self.socks_server:
            self.iptables.start()


    def stop(self):

        [proxy.stop() for proxy in self.proxies.values() if proxy is not None]
        if self.socks_server:
            self.iptables.stop()


    def __next__(self):
        '''
        Yields proxies in round-robin fashion forever
        Note that a proxy can be "None" if current_ip is specified
        '''

        proxy_num = self.round_robin_counter % len(self.proxies)
        proxy = self.proxy_round_robin[proxy_num]
        self.round_robin_counter += 1
        return proxy


    def __enter__(self):

        return self


    def __exit__(self, exc_type, exc_value, exc_traceback):

        debug.info('Shutting down proxies')
        self.stop()