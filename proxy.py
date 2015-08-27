import ssl
import struct
import socket
import logging
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
	def upstream(self, addr, port, client, request, hostname=None):
		try:
			country = geoip.country(addr).country.iso_code.lower()
		except Exception as e:
			country = 'us'

		rule = tornado.options.options.default

		if country in tornado.options.options.country_rules:
			rule = tornado.options.options.country_rules.get(country)
		if hostname in tornado.options.options.hostname_rules:
			rule = tornado.options.options.hostname_rules.get(hostname)

		if rule.get('mode', 'pass') == 'pass':
			logging.info('pass  %s to %s %s' % (self.address, hostname, (addr, port)))

			stream = yield tornado.tcpclient.TCPClient().connect(addr, port)

			data  = struct.pack('!BBBB', 0x05, 0x00, 0x00, 0x01)
			data += socket.inet_aton(addr) + struct.pack('!H', port)
			client.write(data)
		elif rule.get('mode', 'pass').lower() == 'socks5':
			logging.info('proxy %s to %s %s via %s' % \
				(self.address, hostname, (addr, port), (rule.get('host'), rule.get('port'))))

			stream = yield tornado.tcpclient.TCPClient().connect(rule.get('host'), rule.get('port'))
			stream.write(struct.pack('BBB', 0x05, 0x01, 0x00))
			data = yield stream.read_bytes(2)
			if data != struct.pack('BB', 0x05, 0x00):
				raise Exception()

			stream.write(request)
			data = yield stream.read_bytes(4096, partial=True)
			client.write(data)
		elif rule.get('mode', 'pass').lower() == 'socks5s':
			logging.info('proxy %s to %s %s via %s' % \
				(self.address, hostname, (addr, port), (rule.get('host'), rule.get('port'))))

			stream = yield tornado.tcpclient.TCPClient().connect(
					rule.get('host'),
					rule.get('port'),
					ssl_options=dict(cert_reqs=ssl.CERT_NONE))
			yield stream.wait_for_handshake()
			stream.write(struct.pack('BBB', 0x05, 0x01, 0x00))
			data = yield stream.read_bytes(2)
			if data != struct.pack('BB', 0x05, 0x00):
				raise Exception()

			stream.write(request)
			data = yield stream.read_bytes(4096, partial=True)
			client.write(data)
		else:
			raise Exception()

		raise tornado.gen.Return(stream)

	@tornado.gen.coroutine
	def handshake(self, client):

		data = yield client.read_bytes(2)
		ver, nmethods = struct.unpack('BB', data)
		methods = yield client.read_bytes(nmethods)
		client.write(struct.pack('BB', 0x05, 0x00))

		data = yield client.read_bytes(4)
		request = data

		ver, cmd, rsv, atyp = struct.unpack('BBBB', data)
		if atyp == 0x01:
			data = yield client.read_bytes(4)
			host = socket.inet_ntoa(data)
			request += data
			addr = host

			data = yield client.read_bytes(2)
			request += data
			port = struct.unpack('!H', data)[0]
		elif atyp == 0x03:
			data = yield client.read_bytes(1)
			request += data
			data = yield client.read_bytes(struct.unpack('B', data)[0])
			request += data
			host = data

			data = yield client.read_bytes(2)
			request += data
			port = struct.unpack('!H', data)[0]

			rule = tornado.options.options.hostname_rules.get(host, {})
			if rule.get('mode', 'pass') == 'pass':
				try:
					addr = yield self.resolver.resolve(host, port)
					addr = addr[0][1][0]
				except Exception as e:
					logging.error(e)
					addr = ''
			else:
				addr = ''
		elif atyp == 0x04:
			client.write(struct.pack('!BBBBIH', 0x05, 0x07, 0x00, 0x01, 0, 0))
			client.close()
			return
		else:
			client.write(struct.pack('!BBBBIH', 0x05, 0x07, 0x00, 0x01, 0, 0))
			client.close()
			return

		remote = yield self.upstream(addr, port, client, request, host)


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

	tornado.options.define("tcp_port",    default=8888)

	tornado.options.define("ssl",         default=False)
	tornado.options.define("ssl_port",    default=8443)
	tornado.options.define("ssl_key",     default="server.key")
	tornado.options.define("ssl_crt",     default="server.crt")

	tornado.options.define("country_rules",  default={})
	tornado.options.define("hostname_rules", default={})

	tornado.options.define("config", default='rules.conf')

        tornado.options.parse_command_line()
        tornado.options.parse_config_file(tornado.options.options.config)

	tcp_sockets = tornado.netutil.bind_sockets(tornado.options.options.tcp_port)
	if tornado.options.options.ssl:
		ssl_sockets = tornado.netutil.bind_sockets(tornado.options.options.ssl_port)
	tornado.process.fork_processes(tornado.options.options.workers)

	tcp_server = ProxyServer()
	tcp_server.connection = {}
	tcp_server.add_sockets(tcp_sockets)
	tcp_server.resolver = tornado.netutil.Resolver()

	if tornado.options.options.ssl:
		"""
		ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
		ssl_ctx.load_cert_chain(
			tornado.options.options.ssl_crt,
			tornado.options.options.ssl_key
		)
		"""
		ssl_ctx = {
			'keyfile': tornado.options.options.ssl_key,
			'certfile': tornado.options.options.ssl_crt,
		}
		ssl_server = ProxyServer(ssl_options=ssl_ctx)
		ssl_server.connection = {}
		ssl_server.add_sockets(ssl_sockets)
		ssl_server.resolver = tornado.netutil.Resolver()

	tornado.netutil.Resolver.configure('tornado.netutil.ThreadedResolver', num_threads=10)

	tornado.autoreload.watch(tornado.options.options.config)
	tornado.autoreload.start()

	tornado.ioloop.IOLoop.current().start()

if __name__ == '__main__':
	main()
