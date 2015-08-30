# How to use

## Download code

	$ git clone https://github.com/zhicheng/proxy.git
	$ cd proxy

## Setup virtualenv and active virtualenv

	$ virtualenv env
	$ source env/bin/activate

## Install 3rdparty package

	$ pip install -r requirements.txt

## Change configure file

	$ cp rules.conf.default rules.conf

## run 

	$ ./proxy

# Configure


how many process use.

	workers = 8

local listen proxy port `socks5` for client use,`socks5s` may not work with your client but for remote upstream will work well.

	socks5_port  = 8888
	socks5s_port = 8443

`socks5s` ssl server key and crt,`socks5s` repr socks5 over ssl.`genkey.sh` can generate self-signed crt.

	socks5s_key  = 'server.key'
	socks5s_crt  = 'server.crt'

default rule set `mode` value

1. `pass` passthrough mode
2. `socks5` use `socks5` proxy upstream
3. `socks5s` same as above but ssl

	default = {'mode': 'socks5s', 'host': '127.0.0.1', 'port': 7443}


Authenticate for client,may not work with your client.

	auth = {
        	'username': 'password'
	}

country rule set

	country_rules = {
		'cn': {'mode': 'pass'},
	}

hostname rule set high priority, support wildcard match like `*.example.com` 

	hostname_rules = {
		'127.0.0.1': {'mode': 'pass'},
		'localhost': {'mode': 'pass'},
	}

# Best Practice

TODO
