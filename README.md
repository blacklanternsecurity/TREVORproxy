# TREVORproxy

By [@thetechr0mancer](https://twitter.com/thetechr0mancer)

[![License](https://img.shields.io/badge/license-GPLv3-blue.svg)](https://raw.githubusercontent.com/blacklanternsecurity/nmappalyzer/master/LICENSE)
[![Python Version](https://img.shields.io/badge/python-3.6+-blue)](https://www.python.org)

See the accompanying [**Blog Post**](https://github.com/blacklanternsecurity/TREVORspray/blob/trevorspray-v2/blogpost.md) for a fun rant and some cool demos!

A SOCKS proxy written in Python that randomizes your source IP address. Round-robin your evil packets through SSH tunnels or give them billions of unique source addresses!

![trevorproxy-diagram](https://user-images.githubusercontent.com/20261699/149545633-a2f14f3a-1abc-4f9a-b589-3a52385ba635.png)
TREVORproxy IPv6 Subnet Proxy Diagram

![ssh-proxy](https://user-images.githubusercontent.com/20261699/149403633-3b6259c4-6c13-4ae5-abe6-498024a155f5.gif)
TREVORproxy SSH Proxy Demo

![subnet-proxy](https://user-images.githubusercontent.com/20261699/142468206-4e9a46db-b18b-4969-8934-19d1f3837300.gif)
TREVORproxy Subnet Proxy Demo

## Common use cases
- WAF bypass
- Password spraying
- Web scraping

## How it works
TREVORproxy has two modes of operation: a **Subnet Proxy** and an **SSH Proxy**:
- **Subnet Proxy** mode uses the **AnyIP** feature of the Linux kernel to assign an entire subnet to your network interface, and give every connection a random source IP address from that subnet.
    - E.g. if your cloud provider gives you a `/64` IPv6 range, you can send your traffic from over **eighteen quintillion** (18,446,744,073,709,551,616) unique IP addresses.
- **SSH Proxy** mode combines `iptables` with SSH's SOCKS proxy feature (`ssh -D`) to round-robin packets through remote systems (cloud VMs, etc.)

NOTE: TREVORproxy is not intended as a DoS tool, as it does not "spoof" packets. It is a fully-functioning SOCKS proxy, meaning that it is designed to accept return traffic.

## Installation
~~~
$ pip install -U git+https://github.com/blacklanternsecurity/trevorproxy
~~~

## Example #1 - Send traffic from random addresses within an IPv6 subnet
- NOTE: In `subnet` mode, `trevorproxy` must be run as root
- NOTE: This must be a legitimate subnet, e.g. an IPv6 range allocated to you by your cloud provider.
~~~bash
# Start TREVORproxy
$ sudo trevorproxy subnet -s dead:beef::0/64 -i eth0
[DEBUG] ip route add local dead:beef::0/64 dev eth0
[INFO] Listening on socks5://127.0.0.1:1080

# Test SOCKS proxy
# Note that each request has a different source IP address
$ curl --proxy socks5://127.0.0.1:1080 -6 api64.ipify.org
dead:beef::74d0:b1be:3166:c934
$ curl --proxy socks5://127.0.0.1:1080 -6 api64.ipify.org
dead:beef::4927:1b4:8e5f:d44d
$ curl --proxy socks5://127.0.0.1:1080 -6 api64.ipify.org
dead:beef::2bb8:7b79:706e:cb7d
$ curl --proxy socks5://127.0.0.1:1080 -6 api64.ipify.org
dead:beef::7e13:abe3:dc24:5a00
~~~

## Example #2 - Send traffic through SSH tunnels
~~~bash
# Configure proxychains
$ cat /etc/proxychains.conf
...
socks5 127.0.0.1 1080
...

# Start TREVORproxy
$ trevorproxy ssh root@1.2.3.4 root@4.3.2.1
[DEBUG] Opening SSH connection to root@1.2.3.4
[DEBUG] /usr/bin/ssh root@1.2.3.4 -D 32482 -o StrictHostKeychecking=no
[DEBUG] Opening SSH connection to root@4.3.2.1
[DEBUG] /usr/bin/ssh root@4.3.2.1 -D 32483 -o StrictHostKeychecking=no
[DEBUG] Waiting for /usr/bin/ssh root@1.2.3.4 -D 32482 -o StrictHostKeychecking=no
[DEBUG] Waiting for /usr/bin/ssh root@4.3.2.1 -D 32483 -o StrictHostKeychecking=no
[DEBUG] Creating iptables rules
[DEBUG] iptables -A OUTPUT -t nat -d 127.0.0.1 -o lo -p tcp --dport 1080 -j DNAT --to-destination 127.0.0.1:32482 -m statistic --mode nth --every 2 --packet 0
[DEBUG] iptables -A OUTPUT -t nat -d 127.0.0.1 -o lo -p tcp --dport 1080 -j DNAT --to-destination 127.0.0.1:32483
[INFO] Listening on socks5://127.0.0.1:1080

# Test SOCKS proxy
$ proxychains curl ifconfig.me
1.2.3.4
$ proxychains curl ifconfig.me
4.3.2.1
$ proxychains curl ifconfig.me
1.2.3.4
$ proxychains curl ifconfig.me
4.3.2.1
~~~

## CLI Usage
~~~
$ trevorproxy --help
usage: trevorproxy [-h] [-p PORT] [-l LISTEN_ADDRESS] [-q] [-v] {interface,ssh} ...

Round-robin requests through multiple SSH tunnels via a single SOCKS server

positional arguments:
  {interface,ssh}       proxy type
    interface           send traffic from local interface
    ssh                 send traffic through SSH hosts

optional arguments:
  -h, --help            show this help message and exit
  -p PORT, --port PORT  Port for SOCKS server to listen on (default: 1080)
  -l LISTEN_ADDRESS, --listen-address LISTEN_ADDRESS
                        Listen address for SOCKS server (default: 127.0.0.1)
  -q, --quiet           Be quiet
  -v, -d, --verbose, --debug
                        Be verbose
~~~

## CLI Usage - Subnet Proxy
~~~
$ trevorproxy subnet --help
usage: trevorproxy subnet [-h] [-i INTERFACE] [-s SUBNET]

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        Interface to send packets on
  -s SUBNET, --subnet SUBNET
                        Subnet to send packets from
~~~

## CLI Usage - SSH Proxy
~~~
$ trevorproxy ssh --help
usage: trevorproxy ssh [-h] [-k KEY] [--base-port BASE_PORT] ssh_hosts [ssh_hosts ...]

positional arguments:
  ssh_hosts             Round-robin load-balance through these SSH hosts (user@host)

optional arguments:
  -h, --help            show this help message and exit
  -k KEY, --key KEY     Use this SSH key when connecting to proxy hosts
  --base-port BASE_PORT
                        Base listening port to use for SOCKS proxies (default: 32482)
~~~

![trevor](https://user-images.githubusercontent.com/20261699/92336575-27071380-f070-11ea-8dd4-5ba42c7d04b7.jpeg)

`#trevorforget`