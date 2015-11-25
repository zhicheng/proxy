import ssl
import struct
import socket
import random
import logging
import fnmatch
import ipaddress
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
		self.server   = server
		self.address  = address
		self.resolver = server.resolver

		self.handshake(client)

	def close_callback(self):
		if not self.client.closed():
			self.client.close()
		if not self.remote.closed():
			self.remote.close()

		if self.address in self.server.connection:
			del self.server.connection[self.address]

	@tornado.gen.coroutine
	def client_recv(self, data):
		if len(data):
			try:
				yield self.remote.write(data)
			except Exception as e:
				logging.error(e)

	@tornado.gen.coroutine
	def remote_recv(self, data):
		if len(data):
			try:
				yield self.client.write(data)
			except Exception as e:
				logging.error(e)

	@tornado.gen.coroutine
	def upstream(self, client, atyp, dstaddr, dstport):
		ip   = '0.0.0.0'
		rule = {}
		matched = False
		for pat, val in tornado.options.options.hostname_rules.iteritems():
			if fnmatch.fnmatch(dstaddr, pat):
				rule = val
				matched = True
				break
			elif atyp == SOCKS5.ATYP_IPV4 or atyp == SOCKS5.ATYP_IPV6:
				try:
					if ipaddress.ip_address(unicode(dstaddr)) in ipaddress.ip_network(unicode(pat)):
						rule = val
						matched = True
						break
				except Exception:
					pass

		if not matched:
			if atyp == SOCKS5.ATYP_IPV4:
				ip = dstaddr
			elif atyp == SOCKS5.ATYP_DOMAINNAME:
				try:
					addr = yield self.resolver.resolve(dstaddr, dstport)
					ip = addr[0][1][0]
				except Exception as e:
					ip = None
					logging.error(e)
					rule = tornado.options.options.default
			if ip != '0.0.0.0' and ip != None:
				rule = tornado.options.options.default
				cc = geoip.country(ip).country.iso_code
				if cc:
					cc = cc.lower()
				rule = tornado.options.options.country_rules.get(cc, rule)
		if isinstance(rule, (list, tuple)) and rule:
			rule = rule[random.randint(0, len(rule))-1]

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
		elif mode == 'reject':
			logging.info('Reject %s to %s' % (self.address, (dstaddr, dstport)))
			client.write(
				'''HTTP/1.1 502 Bad Gateway\r\n'''
				'''Content-Length: 73\r\n'''
				'''Server: nginx/2.0\r\n'''
				'''Content-Type: text/plain\r\n\r\n'''
			)
			client.close()
		elif mode == 'socks5' or mode == 'socks5s':
			logging.info('proxy %s to %s via %s' % (self.address, (dstaddr, dstport), (host, port)))

			if mode == 'socks5s':
				stream = yield tornado.tcpclient.TCPClient().connect(host, port,
						ssl_options=dict(cert_reqs=ssl.CERT_NONE))
			else:
				stream = yield tornado.tcpclient.TCPClient().connect(host, port)

			if rule.get('username', None):
				stream.write(
					struct.pack('BBBB',
						SOCKS5.VER,
						2,
						SOCKS5.METHOD_NOAUTH,
						SOCKS5.METHOD_USERNAME
					))
			else:
				stream.write(
					struct.pack('BBB',
						SOCKS5.VER,
						1,
						SOCKS5.METHOD_NOAUTH,
					))

			data = yield stream.read_bytes(2)
			ver, method = struct.unpack('BB', data)

			if method == SOCKS5.METHOD_USERNAME:
				data  = struct.pack('BB', 1, len(rule.get('username', '')))
				data += rule.get('username', '')
				data += struct.pack('B', len(rule.get('password', '')))
				data += rule.get('password', '')
				stream.write(data)
				data = yield stream.read_bytes(2)
				ver, status = struct.unpack('BB', data)
				if status != 0:
					stream.close()
					raise tornado.gen.Return(None)
			elif method == SOCKS5.METHOD_NOAUTH:
				pass
			else:
				raise tornado.gen.Return(None)

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
			raise tornado.gen.Return(None)

		raise tornado.gen.Return(stream)

	@tornado.gen.coroutine
	def handshake(self, client):

		data = yield client.read_bytes(2)
		ver, nmethods = struct.unpack('BB', data)
		if ver != SOCKS5.VER:
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
		if tornado.options.options.auth:
			if struct.pack('B', SOCKS5.METHOD_USERNAME) not in methods:
				client.write(struct.pack('BB', SOCKS5.VER, SOCKS5.METHOD_NOACCEPT))
				client.close()
				return

			client.write(struct.pack('BB', SOCKS5.VER, SOCKS5.METHOD_USERNAME))
			ver  = yield client.read_bytes(1)

			data   = yield client.read_bytes(1)
			ulen   = struct.unpack('B', data)[0]
			uname  = yield client.read_bytes(ulen)

			data   = yield client.read_bytes(1)
			plen   = struct.unpack('B', data)[0]
			passwd = yield client.read_bytes(plen)

			if tornado.options.options.auth.get(uname, None) == passwd:
				client.write(struct.pack('BB', 1, 0))
			else:
				client.write(struct.pack('BB', 1, 1))
				client.close()
				return
		else:
			client.write(struct.pack('BB', SOCKS5.VER, SOCKS5.METHOD_NOAUTH))

		data = yield client.read_bytes(4)

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

		try:
			remote = yield self.upstream(client, atyp, dstaddr, dstport)
		except Exception as e:
			remote = None

		if remote is None:
			client.close()
			return

		self.client = client
		self.remote = remote

		client.set_nodelay(True)
		remote.set_nodelay(True)

		client.read_until_close(streaming_callback=self.client_recv)
		remote.read_until_close(streaming_callback=self.remote_recv)

		client.set_close_callback(self.close_callback)
		remote.set_close_callback(self.close_callback)

class ProxyServer(tornado.tcpserver.TCPServer):

	def handle_stream(self, stream, address):
		self.connection[address] = ProxyConnection(stream, address, server=self)

def main():
	tornado.options.define("workers", default=1)
	tornado.options.define("auth",    default={})
	tornado.options.define("default", default=[{'mode': 'pass'}])

	tornado.options.define("socks5_port",  default=8888)
	tornado.options.define("socks5s_port", default=8443)
	tornado.options.define("socks5s_key",  default="server.key")
	tornado.options.define("socks5s_crt",  default="server.crt")

	tornado.options.define("country_rules",  default={})
	tornado.options.define("hostname_rules", default={})

	tornado.options.define("config", default='rules.conf')

        tornado.options.parse_command_line()
        tornado.options.parse_config_file(tornado.options.options.config)

	socks5_sockets = tornado.netutil.bind_sockets(tornado.options.options.socks5_port)
	for s in socks5_sockets:
		s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	if tornado.options.options.socks5s_port:
		socks5s_sockets = tornado.netutil.bind_sockets(tornado.options.options.socks5s_port)
		for s in socks5s_sockets:
			s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
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
