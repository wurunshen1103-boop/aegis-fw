import copy
import time
import unittest
from aegis_fw.broker import Broker
from aegis_fw.core import Denied,digest,proposal
from aegis_fw.firewall import structure
from test_core import events,policy
class FakeNft:
    def __init__(self):
        self.data={'nftables':[{'table':{'family':'inet','name':'aegis_fw'}},{'set':{'family':'inet','table':'aegis_fw','name':'blocked4','type':'ipv4_addr','elem':[]}}]}
        self.live={};self.adds=0;self.fail_verify=False;self.conflict=False
    def table(self):return copy.deepcopy(self.data)
    def rules(self):return {'nftables':[]}
    def check_conflicts(self):
        if self.conflict:raise Denied('conflict')
        return self.rules()
    def verify_management(self,p):
        if not p['management_confirmed']:raise Denied('confirm management')
    def add(self,ip,ttl):self.live[ip]=time.time()+ttl;self.adds+=1
    def contains(self,ip):return not self.fail_verify and self.live.get(ip,0)>time.time()
    def remove(self,ip):self.live.pop(ip,None)
    def init_script(self,p,marker):return 'init'
    def transaction(self,script):pass
    def uninstall(self):self.live.clear()
class BrokerTests(unittest.TestCase):
    def setUp(self):
        self.p=policy();self.p.update(mode='enforce',management_confirmed=True);self.ev=events();self.q=proposal(self.ev,self.p)
        self.n=FakeNft();self.saved=[];self.logs=[]
        self.s=dict(fingerprint=structure(self.n.table()),policy_hash=digest(self.p),cases={},grants={},attempts=[])
        self.b=Broker(self.p,self.n,self.s,lambda x:self.saved.append(copy.deepcopy(x)),lambda *a,**kw:self.logs.append((a,kw)),lambda:self.ev)
    def test_manual_lifecycle(self):
        self.assertEqual(self.b.apply(self.q,self.q['id'])['state'],'verify');self.assertTrue(self.n.contains(self.q['ip']))
        self.assertEqual(self.b.rollback(self.q['id'])['state'],'rollback');self.assertFalse(self.n.contains(self.q['ip']))
    def test_idempotence_does_not_extend(self):
        a=self.b.apply(self.q,self.q['id']);b=self.b.apply(self.q,self.q['id']);self.assertEqual(a['expires'],b['expires']);self.assertEqual(self.n.adds,1)
    def test_no_approval(self):
        with self.assertRaises(Denied):self.b.apply(self.q)
        self.assertEqual(self.n.adds,0)
    def test_expired_grant(self):
        self.s['grants']['9900001']=time.time()-1
        with self.assertRaises(Denied):self.b.apply(self.q)
    def test_scoped_grant(self):
        body={'signature_id':9900001,'seconds':60,'policy_hash':digest(self.p)};self.b.grant(9900001,60,digest(body));self.assertEqual(self.b.apply(self.q)['state'],'verify')
    def test_high_risk_always_manual(self):
        self.ev=events(severity=1);q=proposal(self.ev,self.p);self.s['grants']['9900001']=time.time()+60
        with self.assertRaises(Denied):self.b.apply(q)
    def test_forged_evidence(self):
        self.b.evidence_reader=lambda:[]
        with self.assertRaises(Denied):self.b.apply(self.q,self.q['id'])
        self.assertEqual(self.n.adds,0)
    def test_drift(self):
        self.n.data['nftables'].append({'rule':{'expr':['unknown']}})
        with self.assertRaises(Denied):self.b.apply(self.q,self.q['id'])
    def test_manager_appears(self):
        self.n.conflict=True
        with self.assertRaises(Denied):self.b.apply(self.q,self.q['id'])
    def test_shadow_cannot_apply(self):
        self.p['mode']='shadow';q=proposal(self.ev,self.p)
        with self.assertRaises(Denied):self.b.apply(q,q['id'])
    def test_failure_rollback(self):
        self.n.fail_verify=True
        with self.assertRaises(Denied):self.b.apply(self.q,self.q['id'])
        self.assertEqual(self.n.live,{});self.assertEqual(self.s['cases'][self.q['id']]['state'],'rollback')
    def test_crash_recovery(self):
        self.s['cases'][self.q['id']]={'ip':self.q['ip'],'expires':time.time()+60,'state':'enforce'};self.n.add(self.q['ip'],60)
        self.assertEqual(self.b.apply(self.q,self.q['id'])['state'],'rollback')
    def test_hourly_limit(self):
        self.s['attempts']=[time.time()]*self.p['max_per_hour']
        with self.assertRaises(Denied):self.b.apply(self.q,self.q['id'])
    def test_active_limit(self):
        self.p['max_active']=1;self.s['policy_hash']=digest(self.p);q=proposal(self.ev,self.p)
        self.s['cases']['other']=dict(ip='1.1.1.1',expires=time.time()+60,state='verify')
        with self.assertRaises(Denied):self.b.apply(q,q['id'])
    def test_expiry(self):
        self.b.apply(self.q,self.q['id']);self.s['cases'][self.q['id']]['expires']=0;self.n.live.clear()
        self.assertEqual(self.b.reconcile()[self.q['id']]['state'],'expired')
    def test_fingerprint_ignores_elements(self):
        a=copy.deepcopy(self.n.data);a['nftables'][1]['set']['elem']=['8.8.4.4'];self.assertEqual(structure(a),structure(self.n.data))
    def test_auto_without_grants_no_write(self):
        self.assertEqual(self.b.automatic(),[]);self.assertEqual(self.n.adds,0)
    def test_auto_with_grant_and_replay(self):
        self.s['grants']['9900001']=time.time()+60
        self.assertEqual(self.b.automatic()[0]['state'],'verify');self.b.automatic();self.assertEqual(self.n.adds,1)
    def test_auto_high_held(self):
        self.ev=events(severity=1);self.s['grants']['9900001']=time.time()+60
        self.assertEqual(self.b.automatic(),[]);self.assertEqual(self.n.adds,0)
    def test_rollback_old_case_does_not_remove_new_block(self):
        old={'ip':self.q['ip'],'expires':0,'state':'verify'};self.s['cases']['old']=old
        self.b.apply(self.q,self.q['id']);self.b.rollback('old');self.assertTrue(self.n.contains(self.q['ip']))
    def test_foreign_table_not_adopted(self):
        self.s.clear();self.n.rules=lambda:self.n.table()
        with self.assertRaises(Denied):self.b.initialize(digest(self.p))
