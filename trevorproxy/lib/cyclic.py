'''
cyclic provides an inexpensive approach to iterating over an IP
space in a random(-ish) manner such that we connect to every host once in
a scan execution without having to keep track of the IPs that have been
scanned or need to be scanned and such that each scan has a different
ordering. We accomplish this by utilizing a cyclic multiplicative group
of integers modulo a prime and generating a new primitive root (generator)
for each scan.

We know that 3 is a generator of (Z mod 2^32 + 15 - {0}, *)
and that we have coverage over the entire address space because 2**32 + 15
is prime and ||(Z mod PRIME - {0}, *)|| == PRIME - 1. Therefore, we
just need to find a new generator (primitive root) of the cyclic group for
each scan that we perform.

Because generators map to generators over an isomorphism, we can efficiently
find random primitive roots of our mult. group by finding random generators
of the group (Zp-1, +) which is isomorphic to (Zp*, *). Specifically the
generators of (Zp-1, +) are { s | (s, p-1) == 1 } which implies that
the generators of (Zp*, *) are { d^s | (s, p-1) == 1 }. where d is a known
generator of the multiplicative group. We efficiently find
generators of the additive group by precalculating the psub1_f of
p - 1 and randomly checking random numbers against the psub1_f until
we find one that is coprime and map it into Zp*. Because
totient(totient(p)) ~= 10^9, this should take relatively few
iterations to find a new generator.
'''

import sys
import ipaddress
from random import randint


def ipgen(network='0.0.0.0/0', blacklist=None):

    if blacklist is None:
        blacklist = set()
    else:
        blacklist = set(blacklist)

    net = ipaddress.ip_network(str(network), strict=False)

    hostbits = net.max_prefixlen - net.prefixlen

    # if we have 32 or fewer host bits
    if hostbits <= 32:
        # do complicated math fuckery
        ip_generator = multiplicative_group_of_integers_modulo_prime(net)
    # otherwise
    else:
        # don't give a shit
        ip_generator = prig(net)

    for ip in ip_generator:
        if ip not in blacklist:
            yield ip


def prig(net):
    '''
    Pseudo Random IP Generator
    '''
    while 1:
        offset = int(net.network_address)
        random_int = randint(0, net.num_addresses-1)
        if net.version == 4:
            yield ipaddress.IPv4Address(offset + random_int)
        else:
            yield ipaddress.IPv6Address(offset + random_int)



def multiplicative_group_of_integers_modulo_prime(net):
    '''
    defaults to entire ipv4 internet
    raises ValueError if network string is invalid
    '''
    max_prefixlen = 32

    while 1:

        if net.prefixlen > net.max_prefixlen - 2:
            for i in net:
                yield i

        else:

            # precalculated values in the format:
            # mask: (prime, first_primitive_root, [factors of (prime-1)])
            calcd = {
                0:  (4294967311, 3, [2, 3, 5, 131, 364289]),
                1:  (2147483659, 2, [2, 3, 149, 2402107]),
                2:  (1073741827, 2, [2, 3, 59, 3033169]),
                3:  (536870923, 3, [2, 3, 7, 23, 555767]),
                4:  (268435459, 2, [2, 3, 19, 87211]),
                5:  (134217757, 5, [2, 3, 1242757]),
                6:  (67108879, 3, [2, 3, 1242757]),
                7:  (33554467, 2, [2, 3, 11, 56489]),
                8:  (16777259, 2, [2, 23, 103, 3541]),
                9:  (8388617, 3, [2, 17, 61681]),
                10: (4194319, 3, [2, 3, 699053]),
                11: (2097169, 47, [2, 3, 43691]),
                12: (1048583, 5, [2, 29, 101, 179]),
                13: (524309, 2, [2, 23, 41, 139]),
                14: (262147, 2, [2, 3, 43691]),
                15: (131101, 17, [2, 3, 5, 19, 23]),
                16: (65537, 3, [2]),
                17: (32771, 2, [2, 5, 29, 113]),
                18: (16411, 3, [2, 3, 5, 547]),
                19: (8209, 7, [2, 3, 19]),
                20: (4099, 2, [2, 3, 683]),
                21: (2053, 2, [2, 3, 19]),
                22: (1031, 14, [2, 5, 103]),
                23: (521, 3, [2, 5, 13]),
                24: (257, 3, [2]),
                25: (131, 2, [2, 5, 13]),
                26: (67, 2, [2, 3, 11]),
                27: (37, 2, [2, 3]),
                28: (17, 3, [2]),
                29: (11, 2, [2, 5]),
                30: (5, 2, [2])
            }

            prefixlen = net.prefixlen % max_prefixlen
            numhosts = net.num_addresses - 2 # subtract 2 for network/broadcast address
            offset = int(net.network_address)
            prime, first_root, prime_factors = calcd[prefixlen]
            phi = prime - 1

            # compute random primitive root
            rand_root = None
            while rand_root is None:
                c = randint(3, phi-1)
                # check if c is coprime with phi
                for i in prime_factors:
                    if i%c == 0 or c%i == 0:
                        break
                else:
                    rand_root = pow(first_root, c, prime)

            # compute random seed
            seed = randint(1, numhosts)

            # generator
            n = int(seed)
            while 1:
                y = n + offset
                if y <= (numhosts + offset):
                    if net.version == 4:
                        yield ipaddress.IPv4Address(y)
                    else:
                        yield ipaddress.IPv6Address(y)
                n = ((n*rand_root) % prime)
                if n == seed:
                    break
