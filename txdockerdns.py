#!/usr/bin/env python
import argparse
import socket
import sys

from twisted.internet import defer, task
from twisted.names import client, dns, error, server
from twisted.python import log


class DockerResolver(object):
    def query(self, query, timeout=None):
        return defer.fail(error.DomainError())


def upstream(s):
    if not s:
        raise ValueError('no servers specified')
    ret = []
    for server in s.split(','):
        server, _, port = server.partition(':')
        try:
            socket.inet_pton(socket.AF_INET, server)
        except socket.error:
            raise ValueError('%r is not a valid IP address' % (server,))
        port = int(port) if port else 53
        ret.append((server, port))
    return ret


def parse_args(args):
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-d', '--domain', default='docker',
        help='the domain from which to serve requests (default %(default)r)')
    parser.add_argument(
        '-s', '--socket', default='/var/run/docker.sock',
        help='the docker socket to query (default %(default)r)')
    parser.add_argument(
        '-u', '--udp-port', default=53, type=int,
        help='the port on which to serve UDP DNS (default %(default)s)')
    parser.add_argument(
        '-t', '--upstream', type=upstream,
        help='upstream DNS server(s) to query')
    return parser.parse_args(args)


def twisted_main(reactor, args):
    args = parse_args(args)
    log.startLogging(sys.stderr)

    print args

    clients = [DockerResolver()]
    if args.upstream:
        clients.append(client.Resolver(servers=args.upstream))

    factory = server.DNSServerFactory(clients=clients)
    protocol = dns.DNSDatagramProtocol(controller=factory)
    reactor.listenUDP(args.udp_port, protocol)
    return defer.Deferred()


def main():
    task.react(twisted_main, [sys.argv[1:]])
