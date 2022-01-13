import json
import logging
import ipaddress
import subprocess as sp
from pathlib import Path
from getpass import getpass
from contextlib import suppress

log = logging.getLogger('trevorproxy.util')


def clean_pool_arg(arg):

    arg = str(arg)
    if '-' in arg:
        ip1, ip2 = [s.strip() for s in arg.split('-', 1)]
        subnets = range_to_cidrs(ip1, ip2)
    else:
        subnets = [ip_network(arg)]
    blacklist = get_blacklist()
    return exclude_hosts_from_subnets(subnets, blacklist)


def range_to_cidrs(ip1, ip2):

    ip1 = ipaddress.ip_address(ip1)
    ip2 = ipaddress.ip_address(ip2)
    ip1,ip2 = sorted([ip1, ip2])
    return ipaddress.summarize_address_range(ip1, ip2)


def get_blacklist():

    return get_neighbors().union(get_gateways())

def get_interfaces(globalonly=True):

    interfaces = {}
    with suppress(Exception):
        for i in json.loads(sp.run(['ip', '-j', 'a'], stdout=sp.PIPE, stderr=sp.DEVNULL).stdout):
            ifname = i.get('ifname', '')
            if not ifname:
                continue
            interface = {}
            for a in i.get('addr_info', []):
                address = a.get('local', '')
                netmask = a.get('prefixlen', '')
                scope = a.get('scope', '')
                if scope == 'global' or not globalonly:
                    interfaces[ifname] = f'{address}/{netmask}'
    return interfaces


def get_neighbors():

    neighbors = set()
    for neighbor in json.loads(sp.run(['ip', '-j', 'n'], stdout=sp.PIPE, stderr=sp.DEVNULL).stdout):
        dst = neighbor.get('dst', '')
        if dst:
            neighbors.add(ipaddress.ip_address(dst))
    return neighbors


def get_gateways():

    gateways = set()
    for route in json.loads(sp.run(['ip', '-j', 'r'], stdout=sp.PIPE, stderr=sp.DEVNULL).stdout):
        gateway = route.get('gateway', '')
        if gateway:
            gateways.add(ipaddress.ip_address(gateway))

    return gateways


def autodetect_interface(version=6):

    # return the first physical interface that's enabled and has a carrier
    for i in json.loads(sp.run(['ip', '-j', 'a'], stdout=sp.PIPE, stderr=sp.DEVNULL).stdout):
        if 'UP' in i['flags'] and not ('LOOPBACK' in i['flags'] or 'NO-CARRIER' in i['flags']):
            return i['ifname']

    return None


def autodetect_address_pool(version=6):

    blacklist = get_blacklist()
    for ifname,ipaddr in get_interfaces().items():
        print(f'{ifname}:{ipaddr}')
        net = ipaddress.ip_network(ipaddr, strict=False)
        excluded_hosts = set(blacklist)
        blacklist.add(net.network_address)
        blacklist.add(net.broadcast_address)
        if net.version == version:
            log.info(f'Detected subnet {net} on {ifname}')
            return exclude_hosts(net, excluded_hosts)

    return []


def exclude_hosts_from_subnets(subnets, hosts):

    new_subnets = []
    for subnet in subnets:
        new_subnets += exclude_hosts_from_subnet(subnet, hosts)

    if not new_subnets:
        return subnets

    return new_subnets


def exclude_hosts_from_subnet(subnet, hosts):

    new_subnets = [subnet]
    for host in hosts:
        new_subnets = exclude_host_from_subnets(new_subnets, host)

    return new_subnets


def exclude_host_from_subnets(subnets, host):

    new_subnets = []
    for subnet in subnets:
        new_subnets += exclude_host_from_subnet(subnet, host)

    return new_subnets


def exclude_host_from_subnet(subnet, host):
    if host in subnet:
        return list(subnet.address_exclude(ipaddress.ip_network(host)))
    else:
        return [subnet]


def get_ssh_key_passphrase(f=None):

    key_pass = ''
    if ssh_key_encrypted(f):
        while 1:
            key_pass = getpass('SSH key password (press enter if none): ')
            if check_ssh_key_passphrase(key_pass, f):
                break
            log.error(f'Incorrect SSH key passphrase')

    return key_pass


def ssh_key_encrypted(f=None):

    if f is None:
        f = Path.home() / '.ssh/id_rsa'

    with suppress(Exception):
        p = sp.run(['ssh-keygen', '-y', '-P', '', '-f', str(f)], stdout=sp.DEVNULL, stderr=sp.PIPE)
        if not 'incorrect' in p.stderr.decode():
            return False

    return True


def check_ssh_key_passphrase(passphrase, f=None):

    if f is None:
        f = Path.home() / '.ssh/id_rsa'

    cmd = ['ssh-keygen', '-y', '-P', str(passphrase), '-f', str(f)]
    with suppress(Exception):
        p = sp.run(
            cmd,
            stdout=sp.DEVNULL,
            stderr=sp.DEVNULL
        )
        return p.returncode == 0

    return True