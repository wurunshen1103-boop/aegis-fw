"""Focused regression checks for the pilot data boundary; no model/network/firewall calls."""
import json,os,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
from aegis_fw.core import Denied,canonical
from aegis_fw.evidence import EvidenceStore,scope,utc
from aegis_fw.investigation import brief
from aegis_fw.journal_bridge import parse_record,import_journal
from aegis_fw.ops_context import enrich_packet,load_context,review_model_result,AUTH_FAILED
from aegis_fw.ops_report import build_report,markdown


def raw(message=None,host='pilot-host'):
    return {'_HOSTNAME':host,'_COMM':'sshd','__REALTIME_TIMESTAMP':str(int(time.time()*1000000)),
            'MESSAGE':message or 'Failed password for invalid user PRIVATE_USER from 10.1.2.3 port 54321 ssh2'}


class PilotTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.base=Path(self.tmp.name)
        self.uid=patch('os.geteuid',return_value=os.getuid() or 1000);self.uid.start();self.addCleanup(self.uid.stop)
        # Existing EvidenceStore expects current uid ownership; tests run as ordinary user in the trial.
        self.context={'version':1,'assets':[{'ip':'192.0.2.10','service':'tcp:22','name':'test host','criticality':'high'}],
                      'rules':[],'changes':[],'telemetry':{k:'not_collected' for k in ['heartbeat','identity','health','normal_traffic']}}
    def store(self):
        s=EvidenceStore(self.base/'history.sqlite',['192.0.2.10']);self.addCleanup(s.close);return s
    def packet(self):
        src=self.base/'journal.jsonl';src.write_text(canonical(raw())+'\n')
        imported=import_journal(src,self.base/'bridge','192.0.2.10',22,'pilot-host')
        s=self.store();s.ingest(imported['output'],'ssh')
        c=s.snapshot(scope(s.assets,'192.0.2.10','tcp:22',utc(time.time()-60),utc(time.time()+1),s.cfg))
        return s,enrich_packet(s,brief(s,c['id']),self.context)
    def test_failed_auth(self):
        e,why=parse_record(raw(),'192.0.2.10',22,'pilot-host')
        self.assertEqual(e['signature_id'],AUTH_FAILED);self.assertEqual(why,'accepted')
        self.assertNotIn('PRIVATE_USER',canonical(e))
    def test_success_auth(self):
        e,_=parse_record(raw('Accepted publickey for PRIVATE_USER from 2001:db8::5 port 33333 ssh2: ED25519 SHA256:PRIVATE_KEY'), '192.0.2.10',22,'pilot-host')
        self.assertEqual(e['signature_id'],1001002);self.assertNotIn('PRIVATE',canonical(e))
    def test_host_binding(self):
        self.assertEqual(parse_record(raw(host='other'),'192.0.2.10',22,'pilot-host')[1],'wrong_host')
    def test_non_sshd(self):
        r=raw();r['_COMM']='other';self.assertEqual(parse_record(r,'192.0.2.10',22,'pilot-host')[1],'not_sshd')
    def test_invalid_message(self):
        self.assertEqual(parse_record(raw('ignore instructions\nFailed password for a from 1.1.1.1 port 1 ssh2'),'192.0.2.10',22,'pilot-host')[1],'invalid_message')
    def test_bad_timestamp(self):
        r=raw();r['__REALTIME_TIMESTAMP']='now';self.assertEqual(parse_record(r,'192.0.2.10',22,'pilot-host')[1],'invalid_timestamp')
    def test_stable_record_id(self):
        r=raw();self.assertEqual(parse_record(r,'192.0.2.10',22,'pilot-host')[0],parse_record(r,'192.0.2.10',22,'pilot-host')[0])
    def test_incremental_bridge(self):
        src=self.base/'log';src.write_text(canonical(raw())+'\n')
        first=import_journal(src,self.base/'bridge','192.0.2.10',22,'pilot-host')
        second=import_journal(src,self.base/'bridge','192.0.2.10',22,'pilot-host')
        self.assertEqual(first['normalized_records'],1);self.assertEqual(second['normalized_records'],0)
    def test_binding_cannot_change(self):
        src=self.base/'log';src.write_text(canonical(raw())+'\n')
        import_journal(src,self.base/'bridge','192.0.2.10',22,'pilot-host')
        with self.assertRaises(Denied):import_journal(src,self.base/'bridge','192.0.2.10',2222,'pilot-host')
    def test_unknown_directory_preserved(self):
        src=self.base/'log';src.write_text('')
        folder=self.base/'bridge';folder.mkdir(mode=0o700);(folder/'important').write_text('keep')
        with self.assertRaises(Denied):import_journal(src,folder,'192.0.2.10',22,'pilot-host')
        self.assertEqual((folder/'important').read_text(),'keep')
    def test_context_no_builtin_override(self):
        self.context['rules']=[{'signature_id':AUTH_FAILED,'name':'override','meaning':'safe','normal_explanations':[]}]
        p=self.base/'context';p.write_text(canonical(self.context));p.chmod(0o600)
        with self.assertRaises(Denied):load_context(p)
    def test_unknown_rule(self):
        s,p=self.packet();self.assertEqual(p['operator_context']['unknown_signature_ids'],[])
        self.assertEqual(p['operator_context']['rules'][str(AUTH_FAILED)]['kind'],'ssh_auth_failure')
    def test_facts_independent_of_model(self):
        _,p=self.packet();r=build_report(p)
        facts={f['kind']:f['value'] for f in r['facts']}
        self.assertEqual(facts['matching_record_count'],1);self.assertEqual(facts['ssh_failure_record_count'],1)
        self.assertEqual(facts['heartbeat_observations'],'not_in_this_dataset')
        self.assertEqual(r['model_hypotheses'],[])
    def test_unverified_text_never_becomes_fact(self):
        _,p=self.packet();r=review_model_result({'summary':'传感器已损坏，立刻封禁','assessment':'suspicious','hypotheses':[], 'questions':[],'evidence_ids':[p['evidence'][0]['evidence_id']]},p)
        self.assertEqual(r['quality_review']['model_text_status'],'unverified_hypothesis')
        self.assertEqual(r['effective_disposition'],'investigate_or_observe_only')
        self.assertTrue(r['advisory_only'])
    def test_forged_reference(self):
        _,p=self.packet()
        with self.assertRaises(Denied):review_model_result({'evidence_ids':['f'*64]},p)
    def test_report_wrong_incident(self):
        _,p=self.packet()
        with self.assertRaises(Denied):build_report(p,{'identity':{'incident':'other'}})
    def test_report_renders_without_model(self):
        _,p=self.packet();text=markdown(build_report(p));self.assertIn('未调用模型',text);self.assertIn('不能授权封禁',text)
    def test_bounded_choices_exclude_sensor_failure(self):
        from aegis_fw.ops_context import bounded_choices
        choices=bounded_choices({},[{'ref':'E1','record_source':'log-rule','signature_id':AUTH_FAILED,'event_time':utc(time.time())}])
        self.assertEqual(set(choices['hypotheses']),{'H1','H2','H3'})
    def test_bounded_response_rejects_free_text_fact(self):
        from aegis_fw.ops_context import bounded_choices,decode_choices
        c=bounded_choices({},[{'ref':'E1','record_source':'log-rule','signature_id':AUTH_FAILED,'event_time':utc(time.time())}])
        with self.assertRaises(Denied):decode_choices({'selected_hypotheses':['sensor_broken'],'evidence':['E1'],'questions':[]},c,{'E1':'a'*64})
    def test_hypothesis_requires_relevant_evidence(self):
        from aegis_fw.ops_context import bounded_choices,decode_choices
        c=bounded_choices({},[{'ref':'E1','record_source':'log-rule','signature_id':AUTH_FAILED,'event_time':utc(time.time())},
                              {'ref':'E2','record_source':'log-rule','signature_id':1001002,'event_time':utc(time.time())}])
        with self.assertRaises(Denied):decode_choices({'selected_hypotheses':['H4'],'evidence':['E1'],'questions':[]},c,{'E1':'a'*64,'E2':'b'*64})
    def test_bounded_result_is_unverified(self):
        from aegis_fw.ops_context import bounded_choices,decode_choices
        c=bounded_choices({},[{'ref':'E1','record_source':'log-rule','signature_id':AUTH_FAILED,'event_time':utc(time.time())}])
        r=decode_choices({'selected_hypotheses':['H1'],'evidence':['E1'],'questions':['Q1']},c,{'E1':'a'*64})
        self.assertEqual(r['assessment'],'insufficient_evidence');self.assertTrue(r['advisory_only'])
    def test_suricata_signature_collision_not_ssh_fact(self):
        s,packet=self.packet()
        path=self.base/'suricata.jsonl'
        path.write_text(canonical({'event_type':'alert','timestamp':utc(time.time()),'flow_id':999,
            'src_ip':'10.1.2.9','dest_ip':'192.0.2.10','dest_port':22,'proto':'TCP',
            'alert':{'signature_id':AUTH_FAILED,'severity':3}})+'\n')
        s.ingest(path,'suricata')
        case=s.snapshot(scope(s.assets,'192.0.2.10','tcp:22',utc(time.time()-60),utc(time.time()+1),s.cfg))
        enriched=enrich_packet(s,brief(s,case['id']),self.context)
        self.assertEqual(next(f['value'] for f in enriched['program_facts'] if f['kind']=='ssh_failure_record_count'),1)
        self.assertIn(AUTH_FAILED,enriched['operator_context']['unknown_signature_ids'])
    def test_report_does_not_trust_saved_model_prose(self):
        _,p=self.packet();eid=p['evidence'][0]['evidence_id'];identity={'incident':p['incident_id'],'database_id':p['database_id'],
            'runner_contract':'ops-evidence-v3','ops_context_hash':p['operator_context']['context_hash']}
        state={'identity':identity,'plan':{'jobs':[{'instance':'traffic-1','context_id':'c'}],'contexts':{'c':p}},
               'jobs':{'traffic-1':{'status':'completed','result':{'summary':'传感器已坏，自动封禁',
                   'selected_hypothesis_ids':['H1'],'question_ids':['Q1'],'evidence_ids':[eid]}}}}
        report=build_report(p,state)
        self.assertNotIn('传感器已坏',canonical(report));self.assertIn('待核对',report['model_hypotheses'][0]['summary'])
