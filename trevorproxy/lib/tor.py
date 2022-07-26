import sh
import logging
from time import sleep
import subprocess as sp
from pathlib import Path
from .util import sudo_run

log = logging.getLogger('trevorproxy.tor')


class IndividualTorProxy:
    def __init__(self, host='127.0.0.1', proxy_port=None, sh=None):
        self.host = host
        self.proxy_port = proxy_port
        self.sh = sh
        self.command = ''

    def stop(self):

        try:
            self.sh.process.terminate()
        except:
            try:
                self.sh.process.kill()
            except:
                pass

    
    def __hash__(self):

        return hash(str(self))


    def __str__(self):

        return f'socks5://127.0.0.1:{self.proxy_port}'


    def __repr__(self):

        return str(self)
class TorProxy:

    def __init__(self, ports):

        self.ports = ports


        self.sh = None
        self.command = ''
        self.proxies = dict()
        for port in ports:
            individual_proxy = IndividualTorProxy(proxy_port=port)
            self.proxies[str(individual_proxy)] = individual_proxy



    def start(self, wait=True, timeout=30):

        self.stop()
        with sh.sudo:
            arguments = []
            
            for port in self.ports:
                arguments.append("--SocksPort")
                arguments.append(f"127.0.0.1:{port}")
            self.sh = sh.tor(*arguments, _bg=True, _bg_exc=False,)
        
        
        


    def stop(self):

        try:
            self.sh.process.terminate()
        except:
            try:
                self.sh.process.kill()
            except:
                pass



    def __hash__(self):

        return hash(str(self))


    def __str__(self):

        return str([f'socks4://127.0.0.1:{proxy_port}' for proxy_port in self.ports])
    
    def get_iptables_input(self):

        return [(f'socks4://127.0.0.1:{proxy_port}', proxy_port) for proxy_port in self.ports]

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
                if not i == len(self.proxies) - 1:
                    iptables_main += ['-m', 'statistic', '--mode', 'nth', '--every', f'{len(self.proxies)-i}', '--packet', '0']
                self.iptables_rules.append(iptables_main)
                cmd = iptables_add + iptables_main
                sudo_run(cmd)
    def stop(self):

        log.debug('Cleaning up iptables rules')

        for rule in self.iptables_rules:
            iptables_del = ['iptables', '-D']
            cmd = iptables_del + rule
            sudo_run(cmd)



class TorLoadBalancer:

    dependencies = ['ss', 'iptables', 'sudo', 'tor']

    def __init__(self, base_port=33482, current_ip=False, socks_server=True):

        self.args = dict()
        self.base_port = base_port
        self.current_ip = current_ip
        self.proxies = dict()
        self.socks_server = socks_server
        proxy_ports = []
        for i in range(5):
            proxy_ports.append(self.base_port + i)
            
            #self.proxies[str(proxy)] = proxy
        
        self.main_proxy_class = TorProxy(proxy_ports)
        self.proxies = self.main_proxy_class.proxies

        


        self.proxy_round_robin = list(self.proxies.values())
        self.round_robin_counter = 0

        self.iptables = IPTables(list(self.proxies.values()))


    def start(self, timeout=30):

        self.main_proxy_class.start(wait=False)       

        # wait for them all to start
        left = int(timeout)
        log.info("Sleeping 5 seconds to make sure Tor is properly initialized")
        sleep(5)

        if self.socks_server:
            self.iptables.start()


    def stop(self):

        self.main_proxy_class.stop()
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

        log.info('Shutting down proxies')
        self.stop()