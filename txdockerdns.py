import argparse
import json
import socket
import sys

from twisted.internet.error import ConnectionDone, ConnectionLost
from twisted.internet import defer, endpoints, protocol, task
from twisted.names import client, dns, error, server
from twisted.python import log
from twisted.web.client import Agent, ResponseDone, ResponseFailed
from twisted.web.http import PotentialDataLoss
from twisted.web.iweb import IAgentEndpointFactory
from zope.interface import implementer


@implementer(IAgentEndpointFactory)
class FixedAgentEndpointFactory(object):
    def __init__(self, endpoint):
        self._endpoint = endpoint

    def endpointForURI(self, uri):
        return self._endpoint


class UnexpectedHTTPCode(Exception):
    pass


def trap_http_status(response, allowed=frozenset([200])):
    if response.code not in allowed:
        raise UnexpectedHTTPCode(response.code, response.phrase)
    return response


def receive(response, receiver):
    response.deliverBody(receiver)
    return receiver.deferred


class DockerEventsReceiver(protocol.Protocol):
    def __init__(self, callback):
        self.callback = callback
        self.deferred = defer.Deferred(self._cancel)

    def _cancel(self, ign):
        self.transport.stopProducing()

    def dataReceived(self, chunk):
        # THIS IS BAD BAD BAD
        # Do not do this in real code. The reason this is being done at all is
        # because docker doesn't delimit events; each one is sent as an
        # individual HTTP chunk. The way that Agent works, dataReceived will be
        # called exactly once for every chunk received.
        j = json.loads(chunk)
        try:
            self.callback(j)
        except Exception:
            log.err(None, 'error calling %r' % (self.callback))

    def connectionLost(self, reason):
        self.deferred.errback(reason)


class StringReceiver(protocol.Protocol):
    def __init__(self):
        self.deferred = defer.Deferred()
        self._buffer = []

    def dataReceived(self, data):
        self._buffer.append(data)

    def connectionLost(self, reason):
        if ((reason.check(ResponseFailed) and any(exn.check(ConnectionDone, ConnectionLost)
                                                  for exn in reason.value.reasons))
                or reason.check(ResponseDone, PotentialDataLoss)):
            self.deferred.callback(''.join(self._buffer))
        else:
            self.deferred.errback(reason)


class DockerClient(object):
    def __init__(self, agent):
        self.agent = agent

    def request(self, path, method='GET'):
        return self.agent.request(method, 'docker://' + path)

    def run_events(self, callback):
        d = self.request('/events')
        d.addCallback(trap_http_status)
        d.addCallback(receive, DockerEventsReceiver(callback))
        return d


class DockerResolver(object):
    def __init__(self, domain, client):
        self.domain = domain
        self.client = client
        self.hosts_by_id = {}
        self.responsible_for = {}

    def got_event(self, ev):
        log.msg('processing %(status)s on container %(id)s' % ev)
        meth = getattr(self, 'event_%s' % (ev['status'],), None)
        if meth:
            meth(ev)

    def event_start(self, ev):
        self._add_record_for_container(ev['id'].encode())

    def _add_record_for_container(self, container_id):
        d = self.client.request('/containers/%s/json' % (container_id,))
        d.addCallback(trap_http_status)
        d.addCallback(receive, StringReceiver())
        d.addCallback(json.loads)
        d.addCallback(self._got_container)
        d.addErrback(
            log.err, 'error on adding a record for container %s' % (
                container_id,))

    def _got_container(self, container):
        _, _, name = container['Name'].partition('/')
        host = (name + '.' + self.domain).lower()
        ip = container['NetworkSettings']['IPAddress']
        reverse_ip = '.'.join(reversed(ip.split('.'))) + '.in-addr.arpa'
        self.responsible_for[host, dns.A] = dns.Record_A(ip)
        self.responsible_for[reverse_ip, dns.PTR] = dns.Record_PTR(host)
        self.hosts_by_id[container['Id']] = [
            (host, dns.A), (reverse_ip, dns.PTR)]

    event_restart = event_start

    def event_die(self, ev):
        for record in self.hosts_by_id.pop(ev['id'], ()):
            self.responsible_for.pop(record, None)

    event_stop = event_kill = event_die

    def fetch_running_containers(self):
        d = self.client.request('/containers/json')
        d.addCallback(trap_http_status)
        d.addCallback(receive, StringReceiver())
        d.addCallback(json.loads)
        d.addCallback(self._got_containers)
        d.addErrback(log.err, 'error fetching running containers')

    def _got_containers(self, containers):
        for container in containers:
            self._add_record_for_container(container['Id'].encode())

    def query(self, query, timeout=None):
        answers = []
        current_query = query
        while True:
            answer = self.responsible_for.get(
                (current_query.name.name.lower(), query.type))
            if answer is None:
                break
            answer_rr = dns.RRHeader(
                name=current_query.name.name, type=answer.TYPE, payload=answer,
                ttl=30)
            answers.append(answer_rr)
            if answer_rr.type != dns.CNAME:
                break
            current_query = answer

        if not answers:
            return defer.fail(error.DomainError())
        return defer.succeed((answers, [], []))


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


def dns_override(s):
    parts = s.split(',')
    host = parts[0]
    query_type = getattr(dns, parts[1])
    answer = parts[2]
    answer_type_name = parts[3] if len(parts) > 3 else parts[1]
    answer_type = getattr(dns, 'Record_' + answer_type_name)
    return (host, query_type), answer_type(answer)


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
    parser.add_argument(
        '-r', '--override', type=dns_override, default=[], action='append',
        help='DNS query overrides to make')
    return parser.parse_args(args)


def twisted_main(reactor, args):
    args = parse_args(args)
    log.startLogging(sys.stderr)

    docker_endpoint = endpoints.UNIXClientEndpoint(reactor, args.socket)
    agent = Agent.usingEndpointFactory(
        reactor, FixedAgentEndpointFactory(docker_endpoint))
    docker_client = DockerClient(agent)

    resolver = DockerResolver(args.domain, docker_client)
    for query, payload in args.override:
        resolver.responsible_for[query] = payload

    clients = [resolver]
    if args.upstream:
        clients.append(client.Resolver(servers=args.upstream))

    factory = server.DNSServerFactory(clients=clients)
    protocol = dns.DNSDatagramProtocol(controller=factory)
    reactor.listenUDP(args.udp_port, protocol)
    resolver.fetch_running_containers()
    return docker_client.run_events(resolver.got_event)


def main():
    task.react(twisted_main, [sys.argv[1:]])
