#!/usr/bin/env python3

import base64
import http.server
import socketserver

PORT = 5000
DIRECTORY = 'webroot'

class HTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

    def do_GET(self):
        if self.path == '/userinfo':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            userinfo = self.headers.get('authorization').split('.')[1]
            userinfo += '=' * (-len(userinfo) % 4)
            userinfo = base64.urlsafe_b64decode(userinfo)
            self.wfile.write(userinfo)
        else:
            super().do_GET()

socketserver.TCPServer.allow_reuse_address = True
with socketserver.TCPServer(('', PORT), HTTPRequestHandler) as httpd:
    print('serving at port', PORT)
    httpd.serve_forever()
