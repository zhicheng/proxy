import ssl
import struct
import socket
import logging
import fnmatch
import functools
import tornado.gen
import tornado.ioloop
import tornado.netutil
import tornado.options
import tornado.iostream
import tornado.tcpclient
import tornado.tcpserver
import tornado.autoreload

import geoip2.database
geoip = geoip2.database.Reader('GeoLite2-Country.mmdb')

class SOCKS5(object):
	VER = 5
	RSV = 0

	REP_SUCCESSED   = 0
	REP_SERVERFAIL  = 1
	REP_NOTALLOWED  = 2
	REP_NETWORKFAIL = 3
	REP_HOSTFAIL    = 4
	REP_CONNFAIL    = 5
	REP_TTLEXPIRED  = 6
	REP_NOTSUPPORTED = 7
	REP_ADDRESSERROR = 8

	METHOD_NOAUTH   = 0
	METHOD_GSSAPI   = 1
	METHOD_USERNAME = 2
	METHOD_NOACCEPT = 0xFF

	ATYP_IPV4       = 1
	ATYP_DOMAINNAME = 3
	ATYP_IPV6       = 4

	CMD_CONNECT = 1
	CMD_BIND    = 2
	CMD_UDP     = 3


class ProxyConnection(object):

	def __init__(self, client, address, server):
		self.address = address
		self.resolver = server.resolver

		self.handshake(client)

	def client_recv(self, data, finished=False):

		if len(data):
			try:
				self.remote.write(data)
			except Exception as e:
				finished = True

		if finished:
			self.remote.close()
			self.client.close()

	def remote_recv(self, data, finished=False):

		if len(data):
			try:
				self.client.write(data)
			except Exception as e:
				finished = True

		if finished:
			self.remote.close()
			self.client.close()

	@tornado.gen.coroutine
	def upstream(self, client, atyp, dstaddr, dstport):
		if atyp == SOCKS5.ATYP_IPV4:
			rule = tornado.options.options.default
			rule = tornado.options.options.country_rules.get(cc, rule)
			rule = tornado.options.options.hostname_rules.get(dstaddr, rule)
			ip   = dstaddr
		elif atyp == SOCKS5.ATYP_DOMAINNAME:
			rule = {}
			for pat, val in tornado.options.options.hostname_rules.iteritems():
				if fnmatch.fnmatch(dstaddr, pat):
					rule = val 
					break

			if rule.get('mode', 'pass') == 'pass':
				rule = tornado.options.options.default
				try:
					addr = yield self.resolver.resolve(dstaddr, dstport)
					ip = addr[0][1][0]
					cc = geoip.country(ip).country.iso_code
					if cc:
						cc = cc.lower()
					rule = tornado.options.options.country_rules.get(cc, rule)
				except Exception as e:
					logging.error(e)
					rule = tornado.options.options.default

		mode = rule.get('mode', 'pass').lower()
		host = rule.get('host', None)
		port = rule.get('port', None)

		if mode == 'pass':
			logging.info('pass  %s to %s' % (self.address, (dstaddr, dstport)))

			stream = yield tornado.tcpclient.TCPClient().connect(dstaddr, dstport)
			data  = struct.pack('!BBBB',
					SOCKS5.VER, SOCKS5.REP_SUCCESSED, SOCKS5.RSV, SOCKS5.ATYP_IPV4)
			data += socket.inet_aton(ip) + struct.pack('!H', dstport)
			client.write(data)
		elif mode == 'socks5' or mode == 'socks5s':
			logging.info('proxy %s to %s via %s' % (self.address, (dstaddr, dstport), (host, port)))

			if mode == 'socks5s':
				stream = yield tornado.tcpclient.TCPClient().connect(host, port,
						ssl_options=dict(cert_reqs=ssl.CERT_NONE))
			else:
				stream = yield tornado.tcpclient.TCPClient().connect(host, port)

			stream.write(struct.pack('BBB', SOCKS5.VER, 1, SOCKS5.METHOD_NOAUTH))
			data = yield stream.read_bytes(2)
			if data != struct.pack('BB', SOCKS5.VER, SOCKS5.METHOD_NOAUTH):
				raise Exception()

			request = struct.pack('!BBBB',
					SOCKS5.VER,
					SOCKS5.CMD_CONNECT,
					SOCKS5.RSV,
					atyp,
				)
			if atyp == SOCKS5.ATYP_IPV4:
				request += socket.inet_aton(dstaddr) + struct.pack('!H', dstport)
			elif atyp == SOCKS5.ATYP_DOMAINNAME:
				request += struct.pack('B', len(dstaddr)) + \
					   dstaddr + struct.pack('!H', dstport)
			stream.write(request)
		else:
			raise Exception()

		raise tornado.gen.Return(stream)

	@tornado.gen.coroutine
	def handshake(self, client):

		data = yield client.read_bytes(2)
		ver, nmethods = struct.unpack('BB', data)
		if ver != 5:
			client.write(
				'''HTTP/1.1 200 OK\r\n'''
				'''Content-Length: 10\r\n'''
				'''Server: nginx/2.0\r\n'''
				'''Content-Type: text/plain\r\n\r\n'''
				'''HelloWorld'''
			)
			client.close()
			return

		methods = yield client.read_bytes(nmethods)
		client.write(struct.pack('BB', SOCKS5.VER, SOCKS5.METHOD_NOAUTH))

		data = yield client.read_bytes(4)
		request = data

		ver, cmd, rsv, atyp = struct.unpack('BBBB', data)
		if atyp == SOCKS5.ATYP_IPV4:
			data = yield client.read_bytes(4)
			dstaddr = socket.inet_ntoa(data)

			data = yield client.read_bytes(2)
			dstport = struct.unpack('!H', data)[0]
		elif atyp == SOCKS5.ATYP_DOMAINNAME:
			data = yield client.read_bytes(1)
			dstaddr = yield client.read_bytes(struct.unpack('B', data)[0])

			data = yield client.read_bytes(2)
			dstport = struct.unpack('!H', data)[0]
		elif atyp == SOCKS5.ATYP_IPV6:
			client.write(
				struct.pack('!BBBBIH',
					SOCKS5.VER,
					SOCKS5.REP_ADDRESSERROR,
					SOCKS5.RSV,
					SOCKS5.ATYP_IPV4, 0, 0
				))
			client.close()
			return
		else:
			client.write(
				struct.pack('!BBBBIH',
					SOCKS5.VER,
					SOCKS5.REP_ADDRESSERROR,
					SOCKS5.RSV,
					SOCKS5.ATYP_IPV4, 0, 0
				))
			client.close()
			return

		remote = yield self.upstream(client, atyp, dstaddr, dstport)


		self.client = client
		self.remote = remote

		client_finish = functools.partial(self.client_recv, finished=True)
		client.read_until_close(client_finish, self.client_recv)

		remote_finish = functools.partial(self.remote_recv, finished=True)
		remote.read_until_close(remote_finish, self.remote_recv)

class ProxyServer(tornado.tcpserver.TCPServer):

	def handle_stream(self, stream, address):
		self.connection[address] = ProxyConnection(stream, address, server=self)

def main():
	tornado.options.define("workers", default=1)
	tornado.options.define("default", default={'mode': 'pass'})

	tornado.options.define("socks5_port",    default=8888)

	tornado.options.define("socks5s",      default=False)
	tornado.options.define("socks5s_port", default=8443)
	tornado.options.define("socks5s_key",  default="server.key")
	tornado.options.define("socks5s_crt",  default="server.crt")

	tornado.options.define("country_rules",  default={})
	tornado.options.define("hostname_rules", default={})

	tornado.options.define("config", default='rules.conf')

        tornado.options.parse_command_line()
        tornado.options.parse_config_file(tornado.options.options.config)

	socks5_sockets = tornado.netutil.bind_sockets(tornado.options.options.socks5_port)
	if tornado.options.options.socks5s_port:
		socks5s_sockets = tornado.netutil.bind_sockets(tornado.options.options.socks5s_port)
	tornado.process.fork_processes(tornado.options.options.workers)

	socks5_server = ProxyServer()
	socks5_server.connection = {}
	socks5_server.add_sockets(socks5_sockets)
	socks5_server.resolver = tornado.netutil.Resolver()

	if tornado.options.options.socks5s_port:
		ssl_options = {
			'keyfile': tornado.options.options.socks5s_key,
			'certfile': tornado.options.options.socks5s_crt,
		}
		socks5s_server = ProxyServer(ssl_options=ssl_options)
		socks5s_server.connection = {}
		socks5s_server.add_sockets(socks5s_sockets)
		socks5s_server.resolver = tornado.netutil.Resolver()

	tornado.netutil.Resolver.configure('tornado.netutil.ThreadedResolver', num_threads=10)

	tornado.autoreload.watch(tornado.options.options.config)
	tornado.autoreload.start()

	tornado.ioloop.IOLoop.current().start()

if __name__ == '__main__':
	main()
