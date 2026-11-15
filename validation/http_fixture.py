#!/usr/bin/env python3
"""Network reproduction of TestAPIAgentAppDerivedChecksWithoutManualURLsOrCredentials."""
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from urllib.parse import urlsplit,parse_qs
class Fixture(BaseHTTPRequestHandler):
 def do_GET(self):
  q=parse_qs(urlsplit(self.path).query).get('q',[''])[0]
  body='SQLSTATE[42000]' if q=="'" else q if q else 'safe response'
  self.send_response(200)
  self.send_header('Access-Control-Allow-Origin',self.headers.get('Origin',''))
  self.send_header('Access-Control-Allow-Credentials','true')
  self.send_header('Content-Type','text/html')
  self.send_header('Set-Cookie','sessionid=hidden; Path=/')
  self.send_header('Content-Length',str(len(body.encode())))
  self.end_headers();self.wfile.write(body.encode())
 def log_message(self,*args):pass
ThreadingHTTPServer(('127.0.0.1',18091),Fixture).serve_forever()
