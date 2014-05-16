#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# Filename: sjtu-inproxy.py

'''
    *major code is retrieved and modified from webvpn_proxy_via_stunnel.py by
    yqt.  
    http://script-holic.appspot.com/2013/04/22/SPDY%20proxy%E2%86%92HTTP%E4%BB%A3%E7%90%86/%E5%85%A8%E5%B1%80%E4%BB%A3%E7%90%86
'''

from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from httplib import HTTPResponse
from SocketServer import ThreadingMixIn
import socket, os, select
import threading
import base64

# Minimize Memory Usage
threading.stack_size(128*1024)

BufferSize = 8192

# local proxy
local_proxy_host = '' # bind all network types
local_proxy_port = 8090

# proxy host
proxy_host = 'inproxy.sjtu.edu.cn'
proxy_port = 80
proxy_user = 'your jAccount user name'
proxy_pass = 'your jAccount user secret'

auth = proxy_user + ':' + proxy_pass

class Handler(BaseHTTPRequestHandler):
    remote = None
    
    # Ignore Connection Failure
    def handle(self):
        try:
            BaseHTTPRequestHandler.handle(self)
        except socket.error: pass
    def finish(self):
        try:
            BaseHTTPRequestHandler.finish(self)
        except socket.error: pass
    
    # CONNECT Data Transfer
    def transfer(self, a, b):
        fdset = [a, b]
        while True:
            r,w,e = select.select(fdset, [], [])
            if a in r:
                data = a.recv(BufferSize)
                if not data: break
                b.sendall(data)
            if b in r:
                data = b.recv(BufferSize)
                if not data: break
                a.sendall(data)
    
    def proxy(self):
        if self.remote is None or self.lastHost != self.headers['Host']:
            self.remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.remote.connect((proxy_host, proxy_port))
        self.remote.sendall(self.requestline.encode('ascii') + b'\r\n')
        # Add auth inf.
        self.headers['Proxy-Authorization'] = 'Basic %s' % base64.b64encode(auth)
        #self.remote.sendall('Proxy-Authorization: Basic %s\r\n' % base64.b64encode(auth))
        headerstr = str(self.headers).replace('\r\n', '\n').replace('\n', '\r\n')
        self.remote.sendall(headerstr.encode('ascii') + b"\r\n")
        # Send Post data
        if self.command == 'POST':
            self.remote.sendall(self.rfile.read(int(self.headers['Content-Length'])))
        response = HTTPResponse(self.remote, method=self.command)
        response.begin()
        
        # Reply to the browser
        status = 'HTTP/1.1 ' + str(response.status) + ' ' + response.reason
        self.wfile.write(status.encode('ascii') + b'\r\n')
        hlist = []
        for line in response.msg.headers: # Fixed multiple values of a same name
            if 'TRANSFER-ENCODING' not in line.upper():
                hlist.append(line)
        self.wfile.write(''.join(hlist) + b'\r\n')
        
        if self.command == 'CONNECT' and response.status == 200:
            return self.transfer(self.remote, self.connection)
        else:
            while True:
                response_data = response.read(BufferSize)
                if not response_data: break
                self.wfile.write(response_data)
    
    do_POST = do_GET = do_CONNECT = proxy

class ThreadingHTTPServer(ThreadingMixIn, HTTPServer): 
    #address_family = socket.AF_INET6 # IPV6
    address_family = socket.AF_INET # IPV4

server_address = (local_proxy_host, local_proxy_port)
server = ThreadingHTTPServer(server_address, Handler)

print('Proxy over {}:{}\nPlease set your browser\'s or PAC\'s proxy to {}'.format(proxy_host, proxy_port, server_address))
try:
    server.serve_forever()
except:
    os._exit(1)
