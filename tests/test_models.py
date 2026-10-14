import json
import os
import tempfile
import unittest
from unittest.mock import patch
from aegis_fw.core import Denied,canonical,proposal
from aegis_fw.models import Council,request_spec
from aegis_fw.store import Store
from test_core import events,policy,ROOT
class ModelTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.s=Store(self.tmp.name+'/db');self.addCleanup(self.s.db.close)
        self.cfg=json.loads((ROOT/'examples/models.json').read_text());self.cfg['enabled']=True;self.q=proposal(events(),policy());self.calls=[]
        self.env=patch.dict(os.environ,DEEPSEEK_API_KEY='test',OPENAI_API_KEY='test',ANTHROPIC_API_KEY='test');self.env.start();self.addCleanup(self.env.stop)
        self.uid=patch('os.geteuid',return_value=1000);self.uid.start();self.addCleanup(self.uid.stop)
    def transport(self,url,headers,body):
        self.calls.append((url,body));v=canonical(dict(decision='support',confidence=.99,evidence_ids=[e['id'] for e in self.q['evidence']]))
        if 'anthropic' in url:return {'content':[{'type':'text','text':v}]}
        if '11434' in url:return {'message':{'content':v}}
        return {'choices':[{'message':{'content':v}}]}
    def test_lazy_no_calls_disabled(self):
        self.cfg['enabled']=False;self.assertEqual(Council(self.cfg,self.s,self.transport).review(self.q)['status'],'disabled');self.assertEqual(self.calls,[])
    def test_layering_and_cache(self):
        c=Council(self.cfg,self.s,self.transport);self.assertEqual(c.review(self.q)['status'],'supported');self.assertEqual(c.review(self.q)['status'],'supported');self.assertEqual(len(self.calls),2)
    def test_high_independent_reviewer(self):
        self.q=proposal(events(severity=1),policy());self.assertEqual(Council(self.cfg,self.s,self.transport).review(self.q)['status'],'supported');self.assertEqual(len(self.calls),3)
    def test_same_provider_rejected(self):
        self.q=proposal(events(severity=1),policy());self.cfg['roles']['reviewer']['provider']=self.cfg['roles']['supervisor']['provider'];self.assertEqual(Council(self.cfg,self.s,self.transport).review(self.q)['status'],'unavailable');self.assertEqual(len(self.calls),0)
    def test_budget_before_call(self):
        self.cfg['daily_usd']=0;self.assertEqual(Council(self.cfg,self.s,self.transport).review(self.q)['status'],'unavailable');self.assertEqual(len(self.calls),0)
    def test_timeout_reserves_cost(self):
        def timeout(*args):raise TimeoutError('secret must not be logged')
        self.assertEqual(Council(self.cfg,self.s,timeout).review(self.q)['status'],'unavailable');self.assertGreater(self.s.db.execute('SELECT reserved FROM spend').fetchone()[0],0);self.assertNotIn('secret',str(list(self.s.db.execute('SELECT payload FROM audit'))))
    def test_ollama_cold_unload(self):
        url,headers,body=request_spec(dict(provider='ollama',model='local-test',max_output_tokens=512),'system','data');self.assertEqual(body['keep_alive'],0);self.assertFalse(body['stream']);self.assertNotIn('Authorization',headers)
    def test_output_injection_hold(self):
        def evil(*args):return {'choices':[{'message':{'content':'{"command":"sudo sh"}'}}]}
        self.assertEqual(Council(self.cfg,self.s,evil).review(self.q)['status'],'unavailable')
    def test_root_model_denied(self):
        with patch('os.geteuid',return_value=0),self.assertRaises(Denied):Council(self.cfg,self.s,self.transport).review(self.q)
    def test_audit_tamper(self):
        self.s.audit('x');self.s.verify_audit();self.s.db.execute('UPDATE audit SET payload=?',('tampered',));self.s.db.commit()
        with self.assertRaises(Denied):self.s.verify_audit()
    def test_call_cap(self):
        self.cfg['daily_calls']=1;self.assertEqual(Council(self.cfg,self.s,self.transport).review(self.q)['status'],'unavailable');self.assertEqual(len(self.calls),1)
    def test_opposition_stops_escalation(self):
        def oppose(url,headers,body):
            raw=self.transport(url,headers,body);v=json.loads(raw['choices'][0]['message']['content']);v['decision']='oppose';raw['choices'][0]['message']['content']=canonical(v);return raw
        self.assertEqual(Council(self.cfg,self.s,oppose).review(self.q)['status'],'hold');self.assertEqual(len(self.calls),1)
    def test_circuit_breaker_prevents_retry(self):
        def fail(*args):self.calls.append('failed');raise TimeoutError()
        c=Council(self.cfg,self.s,fail);c.review(self.q);c.review(self.q);self.assertEqual(len(self.calls),1)
