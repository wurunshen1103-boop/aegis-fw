"""Operator context and deterministic facts. Model text is never a fact source."""
import ipaddress
from collections import Counter
import json
import os
from pathlib import Path
import stat
from .core import Denied, canonical, digest, integer
from .evidence import query_parts, timestamp, utc

AUTH_FAILED = 1001001
AUTH_ACCEPTED = 1001002
BUILTIN_RULES = {
    AUTH_FAILED: {'name': 'SSH authentication failed', 'meaning': 'A parsed sshd record reports an authentication failure; not proof of brute force or compromise.', 'normal_explanations': ['mistyped credentials', 'outdated automation credentials'], 'kind': 'ssh_auth_failure'},
    AUTH_ACCEPTED: {'name': 'SSH authentication accepted', 'meaning': 'A parsed sshd record reports accepted authentication; not proof that the login was authorized by the account owner.', 'normal_explanations': ['authorized administrator login'], 'kind': 'ssh_auth_success'},
}


def bounded_text(value, limit=512):
    if not isinstance(value, str) or not 1 <= len(value) <= limit or any(ord(c)<32 for c in value):
        raise Denied('invalid operator context text')
    return value


def load_context(path):
    path=Path(path)
    st=path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid not in (0,os.getuid()) or st.st_mode & 0o022:
        raise Denied('context must be a regular owner-controlled file, not group/world writable')
    if st.st_size>65536:raise Denied('operator context exceeds 64 KiB')
    data=json.loads(path.read_text())
    if not isinstance(data,dict) or set(data)!={'version','assets','rules','changes','telemetry'} or data['version']!=1:
        raise Denied('invalid operator context schema')
    if not isinstance(data['assets'],list) or not 1<=len(data['assets'])<=32:
        raise Denied('need 1..32 declared assets/services')
    seen=set()
    for a in data['assets']:
        if not isinstance(a,dict) or set(a)!={'ip','service','name','criticality'}:
            raise Denied('invalid asset fields')
        a['ip']=str(ipaddress.ip_address(a['ip']))
        service(a['service']);bounded_text(a['name'],80)
        if a['criticality'] not in ('low','medium','high','unknown'):raise Denied('invalid asset criticality')
        key=(a['ip'],a['service'])
        if key in seen:raise Denied('duplicate asset/service declaration')
        seen.add(key)
    if not isinstance(data['rules'],list) or len(data['rules'])>128:raise Denied('too many rule definitions')
    seen=set()
    for r in data['rules']:
        if not isinstance(r,dict) or set(r)!={'signature_id','name','meaning','normal_explanations'}:
            raise Denied('invalid rule definition')
        integer(r['signature_id'],1,2**32-1)
        if r['signature_id'] in BUILTIN_RULES or r['signature_id'] in seen:
            raise Denied('builtin/duplicate signature cannot be overridden')
        seen.add(r['signature_id'])
        bounded_text(r['name'],100);bounded_text(r['meaning'])
        if not isinstance(r['normal_explanations'],list) or len(r['normal_explanations'])>5:
            raise Denied('normal explanation limit exceeded')
        for text in r['normal_explanations']:bounded_text(text,256)
    if not isinstance(data['changes'],list) or len(data['changes'])>32:raise Denied('too many change windows')
    for c in data['changes']:
        if not isinstance(c,dict) or set(c)!={'id','asset','service','since','until','description'}:
            raise Denied('invalid change window')
        bounded_text(c['id'],64);bounded_text(c['description'])
        c['asset']=str(ipaddress.ip_address(c['asset']));service(c['service'])
        if not timestamp(c['since'])<timestamp(c['until']):raise Denied('invalid change window times')
    if not isinstance(data['telemetry'],dict) or set(data['telemetry'])!={'heartbeat','identity','health','normal_traffic'}:
        raise Denied('declare the four telemetry capabilities')
    if any(v not in ('not_collected','unknown','operator_reports_available') for v in data['telemetry'].values()):
        raise Denied('invalid telemetry availability declaration')
    return data


def service(text):
    if not isinstance(text,str):raise Denied('service must be tcp:PORT or udp:PORT')
    parts=text.split(':')
    if len(parts)!=2 or parts[0] not in ('tcp','udp') or not parts[1].isascii() or not parts[1].isdigit():
        raise Denied('service must be tcp:PORT or udp:PORT')
    integer(int(parts[1]),1,65535)
    return parts[0],int(parts[1])


def enrich_packet(store,packet,context=None):
    """Aggregate the exact snapshot, not only the truncated prompt sample."""
    data=json.loads(canonical(packet))
    data.pop('id',None)
    case=store.incident(packet['incident_id'])
    where,args=query_parts(case['scope'],case['watermark'])
    rules={str(k):dict(v,provenance='builtin adapter definition') for k,v in BUILTIN_RULES.items()}
    if context:
        for item in context['rules']:
            rules[str(item['signature_id'])]=dict(item,kind='network_alert',provenance='operator declaration')
    counts=Counter()
    for row in store.db.execute('SELECT signature,normalized FROM events WHERE '+where,args):
        counts[(json.loads(row['normalized'])['source'],row['signature'])]+=1
    used={};unknown=[]
    for (source,sid),count in counts.items():
        if str(sid) not in rules or (sid in BUILTIN_RULES and source!='log-rule'):
            unknown.append(sid)
        else:used[str(sid)]=rules[str(sid)]
    unknown=sorted(set(unknown))
    label=case['scope']['proto']+':'+str(case['scope']['port'])
    asset=next((a for a in context['assets'] if a['ip']==case['scope']['asset'] and a['service']==label),None) if context else None
    changes=[c for c in context['changes'] if c['asset']==case['scope']['asset'] and c['service']==label
             and timestamp(c['since'])<timestamp(case['scope']['until']) and timestamp(c['until'])>timestamp(case['scope']['since'])] if context else []
    telemetry=context['telemetry'] if context else {k:'unknown' for k in ('heartbeat','identity','health','normal_traffic')}
    stats=store.summary(case)
    facts=[{'id':'F1','kind':'matching_record_count','value':stats['events'],'statement':'调查范围内记录数；不是请求总量或攻击次数。'},
           {'id':'F2','kind':'distinct_source_ip_count','value':stats['sources'],'statement':'唯一源 IP 数量；不是攻击者或用户人数。'},
           {'id':'F3','kind':'late_collection_count','value':stats['late'],'statement':'采集时间晚于事件时间的记录数；不能单独证明传感器故障。'},
           {'id':'F4','kind':'heartbeat_observations','value':'not_in_this_dataset','statement':'本数据集没有心跳事件，无法判断传感器是否故障。'},
           {'id':'F5','kind':'business_health_observations','value':'not_in_this_dataset','statement':'本数据集没有业务健康指标，无法判断业务是否受损。'}]
    for sid,kind in [(AUTH_FAILED,'ssh_failure_record_count'),(AUTH_ACCEPTED,'ssh_accepted_record_count')]:
        n=counts.get(('log-rule',sid),0)
        if n:facts.append({'id':'F%d'%(len(facts)+1),'kind':kind,'value':n,'statement':BUILTIN_RULES[sid]['meaning']})
    data['program_facts']=facts
    data['operator_context']={'context_hash':digest(context) if context else None,'asset':asset,
        'rules':used,'unknown_signature_ids':unknown,'overlapping_declared_changes':changes,
        'declared_telemetry':telemetry,'trust':'operator declarations supply background, not proof that an event is harmless'}
    data['id']=digest(data)
    if len(canonical(data).encode())>store.cfg['context_max_bytes']:
        raise Denied('background plus evidence exceeds packet cap; narrow scope or context definitions')
    return data


def review_model_result(result,context):
    """Typed facts remain separate; no free-form statement is promoted by a vote."""
    reviewed=json.loads(canonical(result))
    known={e['evidence_id'] for e in context['evidence']}
    if any(e not in known for e in reviewed.get('evidence_ids',[])):
        raise Denied('model reference is outside its supplied context')
    issues=[{'code':'MODEL_TEXT_UNVERIFIED','message':'模型文字只作为待核对假设，引用存在并不证明推断成立。'}]
    if context.get('operator_context',{}).get('unknown_signature_ids'):
        issues.append({'code':'UNKNOWN_RULE','message':'存在尚无释义的规则编号，应补充规则背景。'})
    if not context.get('operator_context',{}).get('asset'):
        issues.append({'code':'MISSING_ASSET_CONTEXT','message':'缺少资产重要性和业务说明。'})
    if context.get('overview',{}).get('late',0):
        issues.append({'code':'LATE_IS_NOT_SENSOR_FAILURE','message':'迟到采集只描述时间差，传感器故障尚未证实。'})
    issues.extend([{'code':'NO_HEARTBEAT_EVIDENCE','message':'没有心跳证据，不能确认传感器故障。'},
                   {'code':'NO_BUSINESS_HEALTH_EVIDENCE','message':'没有业务健康证据，不能确认业务受损。'}])
    reviewed.update(quality_review={'status':'operator_review_required','fact_source':'deterministic program_facts only',
                    'model_text_status':'unverified_hypothesis','issues':issues},
                    effective_disposition='investigate_or_observe_only',advisory_only=True)
    return reviewed


HYPOTHESES={
    'H1':'凭据输入错误是一个待核对解释，尚未证实。',
    'H2':'自动化任务使用过期凭据是一个待核对解释，尚未证实。',
    'H3':'存在未经授权登录尝试的可能，需要账号和来源背景核对。',
    'H4':'日志记录了接受认证，但操作者是否获得授权仍需核对。',
    'H5':'部分记录与声明的维护窗口重叠，尚不能证明因果关系。',
    'H0':'当前材料不足以选择具体原因，需要补充证据。',
}
QUESTIONS={
    'Q1':'请账号负责人核对这些登录是否属于预期操作。',
    'Q2':'请核对自动化任务是否近期修改了凭据。',
    'Q3':'请核对规则释义与正常触发条件。',
    'Q4':'请补充同服务正常时段的记录作为比较背景。',
    'Q5':'如需判断服务故障，请提供独立健康检查和心跳证据。',
    'Q6':'请维护负责人确认具体操作与这些记录是否有关。',
    'Q7':'请复核报告是否把记录数量或缺失资料解释成了未经证实的原因。',
}


def bounded_choices(context,observations):
    eligibility={}
    failed=[o['ref'] for o in observations if o.get('record_source')=='log-rule' and o['signature_id']==AUTH_FAILED]
    accepted=[o['ref'] for o in observations if o.get('record_source')=='log-rule' and o['signature_id']==AUTH_ACCEPTED]
    for key in ('H1','H2','H3'):
        if failed:eligibility[key]=failed
    if accepted:eligibility['H4']=accepted
    changes=context.get('operator_context',{}).get('overlapping_declared_changes',[])
    overlap=[o['ref'] for o in observations if any(timestamp(c['since'])<=timestamp(o['event_time'])<timestamp(c['until']) for c in changes)]
    if overlap:eligibility['H5']=overlap
    if not eligibility:eligibility['H0']=[o['ref'] for o in observations]
    return {'hypotheses':{k:HYPOTHESES[k] for k in eligibility},'questions':QUESTIONS,
            'eligible_evidence':eligibility,'instruction':'Select at most 3 candidate hypotheses and 3 questions. Candidates are unverified, not attack verdicts. Cite eligible evidence for each selected candidate; use empty hypotheses to abstain.'}


def decode_choices(data,choices,refs):
    if not isinstance(data,dict) or set(data)!={'selected_hypotheses','evidence','questions'}:
        raise Denied('unexpected bounded model response')
    for key,allowed,limit in [('selected_hypotheses',choices['hypotheses'],3),('evidence',refs,8),('questions',choices['questions'],3)]:
        if not isinstance(data[key],list) or len(data[key])>limit or any(not isinstance(x,str) or x not in allowed for x in data[key]):
            raise Denied('unknown or excessive bounded choice')
        if len(set(data[key]))!=len(data[key]):raise Denied('duplicate bounded choice')
    for h in data['selected_hypotheses']:
        if not set(data['evidence']) & set(choices['eligible_evidence'][h]):
            raise Denied('candidate hypothesis lacks eligible cited evidence')
    return {'assessment':'insufficient_evidence',
            'summary':'已提出%d项待核对假设，尚不能据此确认攻击。'%len(data['selected_hypotheses']),
            'hypotheses':[choices['hypotheses'][h] for h in data['selected_hypotheses']],
            'questions':[choices['questions'][q] for q in data['questions']],
            'evidence_ids':[refs[e] for e in data['evidence']],
            'selected_hypothesis_ids':data['selected_hypotheses'],'question_ids':data['questions'],
            'output_contract':'bounded-ssh-hypotheses-v1','advisory_only':True}
