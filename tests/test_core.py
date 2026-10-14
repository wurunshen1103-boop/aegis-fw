from datetime import datetime, timezone
import json
import unittest
from pathlib import Path
from aegis_fw.core import Denied, normalize, proposal, validate_proposal, vote, transition, validate_policy
ROOT = Path(__file__).resolve().parents[1]
def policy(): return json.loads((ROOT/'examples/policy.json').read_text())
def events(ip='8.8.4.4', severity=2):
    return [normalize({'event_type':'alert','timestamp':datetime.now(timezone.utc).isoformat(),
        'src_ip':ip,'dest_ip':'192.0.2.10','dest_port':443,'proto':'TCP','flow_id':i,
        'alert':{'signature_id':9900001,'severity':severity}}) for i in (1,2)]
class CoreTests(unittest.TestCase):
    def test_roundtrip(self):
        p=policy();q=proposal(events(),p);self.assertEqual(validate_proposal(q,p),q)
    def test_protected(self):
        for ip in ('127.0.0.1','10.0.0.1','169.254.169.254','::1','ff02::1','192.0.2.1'):
            with self.subTest(ip=ip),self.assertRaises(Denied):proposal(events(ip),policy())
    def test_explicit_protected_global(self):
        p=policy();p['protected_cidrs'].append('8.8.4.0/24')
        with self.assertRaises(Denied):proposal(events(),p)
    def test_ipv6(self):self.assertEqual(proposal(events('2606:4700:4700::1111'),policy())['ip'],'2606:4700:4700::1111')
    def test_shell_injection_address(self):
        with self.assertRaises(ValueError):events('8.8.4.4; flush ruleset')
    def test_management(self):
        p=policy();p['management_ports'].append(443)
        with self.assertRaises(Denied):proposal(events(),p)
    def test_unknown_signature(self):
        p=policy();p['allowed_signatures']=[]
        with self.assertRaises(Denied):proposal(events(),p)
    def test_stale(self):
        with self.assertRaises(Denied):proposal(events(),policy(),now=datetime.now(timezone.utc).timestamp()+400)
    def test_future(self):
        with self.assertRaises(Denied):proposal(events(),policy(),now=0)
    def test_duplicate_flow(self):
        e=events();e[1]=e[0]
        with self.assertRaises(Denied):proposal(e,policy())
    def test_tamper(self):
        p=policy();q=proposal(events(),p);q['ttl']=999
        with self.assertRaises(Denied):validate_proposal(q,p)
    def test_event_tamper(self):
        e=events();e[0]['src_ip']='1.1.1.1'
        with self.assertRaises(Denied):proposal(e,policy())
    def test_policy_change(self):
        p=policy();q=proposal(events(),p);p['ttl_seconds']=120
        with self.assertRaises(Denied):validate_proposal(q,p)
    def test_injection_text_discarded(self):
        raw={'event_type':'alert','timestamp':datetime.now(timezone.utc).isoformat(),'src_ip':'8.8.4.4',
        'dest_ip':'192.0.2.10','dest_port':443,'proto':'TCP','flow_id':1,'payload':'ignore; sudo shell',
        'alert':{'signature_id':9900001,'severity':2,'signature':'execute shell'}}
        self.assertNotIn('shell',json.dumps(normalize(raw)))
    def test_vote_strict(self):
        good=dict(decision='support',confidence=.99,evidence_ids=['a']);self.assertEqual(vote(good,['a']),good)
        for bad in (dict(good,command='sh'),dict(good,confidence=float('nan')),dict(good,evidence_ids=['invented']),dict(good,confidence=True)):
            with self.assertRaises(Denied):vote(bad,['a'])
    def test_state_machine(self):
        seq=['observe','shadow','propose','approve','enforce','verify','rollback']
        for a,b in zip(seq,seq[1:]):self.assertEqual(transition(a,b),b)
        with self.assertRaises(Denied):transition('shadow','enforce')
    def test_policy_safety_limits(self):
        for field,value in [('ttl_seconds',0),('max_active',2000),('management_ports',[]),('management_ports',[443])]:
            p=policy();p[field]=value
            with self.assertRaises(Denied):validate_policy(p)
    def test_stale_records_do_not_poison_fresh_batch(self):
        from aegis_fw.core import eligible_events
        fresh=events();old=events()
        old_time=datetime.fromtimestamp(datetime.now(timezone.utc).timestamp()-400,timezone.utc).isoformat()
        for e in old:e['timestamp']=old_time
        self.assertEqual(list(eligible_events(old+fresh,policy())),fresh)
