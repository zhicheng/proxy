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

## Run 

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
4. `reject` do not proxy anything


```
default = {'mode': 'socks5s', 'host': '127.0.0.1', 'port': 7443}
```


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
		'192.168.0.0/16': {'mode': 'pass'},
		'10.0.0.0/8': {'mode': 'pass'},
		'172.16.0.0/12': {'mode': 'pass'},
	}

# Best Practice

TODO

# Bugs

* DNS Query will block and can be poisoning,current use hostname_rules avoiding make local domain query.
* Slow performance.

