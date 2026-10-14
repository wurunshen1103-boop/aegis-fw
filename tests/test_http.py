"""Real localhost HTTP integration; no credentials or paid provider calls."""
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import json
import os
import tempfile
import threading
import unittest
from unittest.mock import patch
from aegis_fw.core import canonical,proposal,Denied
from aegis_fw.models import Council,ENDPOINTS,post
from aegis_fw.store import Store
from test_core import events,policy

class HTTPTests(unittest.TestCase):
    def setUp(self):
        self.q=proposal(events(),policy());self.received=[];owner=self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_POST(self):
                body=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                owner.received.append((dict(self.headers),body))
                if self.path=='/redirect':
                    self.send_response(307);self.send_header('Location','/target');self.end_headers();return
                v=canonical(dict(decision='support',confidence=.99,evidence_ids=[x['id'] for x in owner.q['evidence']]))
                if self.path=='/anthropic':data={'content':[{'type':'text','text':v}]}
                elif self.path=='/ollama':data={'message':{'content':v}}
                else:data={'choices':[{'message':{'content':v}}]}
                payload=json.dumps(data).encode();self.send_response(200);self.send_header('Content-Length',str(len(payload)));self.end_headers();self.wfile.write(payload)
        self.server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
        self.addCleanup(self.server.server_close);self.addCleanup(self.server.shutdown)
        self.url='http://127.0.0.1:'+str(self.server.server_port)
    def test_all_four_http_protocols(self):
        with tempfile.TemporaryDirectory() as d,patch.dict(os.environ,TEST_API_KEY='dummy-test-key'):
            s=Store(d+'/db')
            try:
                for provider in ENDPOINTS:
                    c={'provider':provider,'model':'test-model','key_env':'TEST_API_KEY','max_output_tokens':512,
                       'input_usd_per_million':1,'output_usd_per_million':2}
                    cfg={'roles':{'classifier':c},'daily_usd':1,'daily_calls':10}
                    with patch.dict(ENDPOINTS,{provider:self.url+'/'+provider}):
                        self.assertEqual(Council(cfg,s).ask('classifier',self.q)['decision'],'support')
                self.assertEqual(len(self.received),4)
                self.assertEqual(self.received[1][0]['Anthropic-Version'],'2023-06-01')
                self.assertEqual(self.received[3][1]['keep_alive'],0)
            finally:s.db.close()
    def test_redirect_refused(self):
        with self.assertRaises(Denied):post(self.url+'/redirect',{'Content-Type':'application/json'},{})
        self.assertEqual(len(self.received),1)
