"""Evidence-first report. Only deterministic records populate the facts section."""
import json
from .core import Denied,digest
from .ops_context import review_model_result,bounded_choices,decode_choices


def build_report(packet,state=None):
    results=[]
    if state is not None:
        if state.get('identity',{}).get('incident')!=packet['incident_id'] or state['identity'].get('database_id')!=packet['database_id']:
            raise Denied('model run is bound to another investigation/database')
        if state['identity'].get('runner_contract')!='ops-evidence-v3':
            raise Denied('legacy open-text model runs require a new bounded investigation run')
        expected=packet.get('operator_context',{}).get('context_hash')
        if state['identity'].get('ops_context_hash')!=expected:
            raise Denied('model run used different operator background; do not merge mismatched analyses')
        for instance,item in state.get('jobs',{}).items():
            if item.get('status')!='completed':
                results.append({'instance':instance,'status':item.get('status','unknown')});continue
            job=next(j for j in state['plan']['jobs'] if j['instance']==instance)
            context=state['plan']['contexts'][job['context_id']]
            observations=[dict(ref=e['evidence_id'],record_source=e['observed']['source'],
                signature_id=e['observed']['signature_id'],event_time=e['event_time']) for e in packet['evidence']]
            choices=bounded_choices(packet,observations)
            stored=item['result']
            reconstructed=decode_choices({'selected_hypotheses':stored.get('selected_hypothesis_ids'),
                'questions':stored.get('question_ids'),'evidence':stored.get('evidence_ids')},
                choices,{e['evidence_id']:e['evidence_id'] for e in packet['evidence']})
            reviewed=review_model_result(reconstructed,packet)
            results.append({'instance':instance,'status':'unverified_model_hypothesis',
                            'summary':reviewed['summary'],'hypotheses':reviewed['hypotheses'],
                            'questions':reviewed['questions'],'evidence_ids':reviewed['evidence_ids'],
                            'quality_review':reviewed['quality_review']})
    report={'version':1,'incident':packet['incident_id'],'database_id':packet['database_id'],
            'context_id':packet['id'],'model_source_context_id':state['plan'].get('source_context_id') if state else None,'scope':packet['scope'],'facts':packet['program_facts'],
            'operator_declarations':packet['operator_context'],
            'coverage':packet['coverage'],'bounds':packet['bounds'],
            'unknowns':['是否属于真实攻击','账号使用是否获得授权','传感器是否故障','业务是否受损'],
            'model_hypotheses':results,'disposition':'人工核对；本报告不能授权封禁',
            'next_checks':['核对账号拥有者及预期运维活动','核对规则释义和调查范围',
                           '如需判断服务故障，另取健康检查与心跳证据'],
            'customer_validation':'not performed; this is a technical investigation artifact'}
    report['id']=digest(report)
    return report


def safe_text(value):
    text=str(value).replace('\n',' ').replace('\r',' ')
    for char in ('\\','`','*','_','[',']','|','#'):text=text.replace(char,'\\'+char)
    return text.replace('<','&lt;').replace('>','&gt;')


def markdown(report):
    s=report['scope']
    lines=['# 本地安全调查简报','', '**处置状态：'+report['disposition']+'。**','',
           '调查编号：`'+report['incident']+'`',
           '范围：`'+s['asset']+'` / `'+s['proto']+':'+str(s['port'])+'`，'+s['since']+' 至 '+s['until']+'。','',
           '## 程序核对的记录事实','',
           '| 项目 | 值 | 含义及限制 |','|---|---|---|']
    labels={'matching_record_count':'范围内记录数','distinct_source_ip_count':'唯一源 IP 数','late_collection_count':'迟到采集记录数',
        'heartbeat_observations':'心跳证据','business_health_observations':'业务健康证据','ssh_failure_record_count':'SSH 失败日志记录数','ssh_accepted_record_count':'SSH 接受认证日志记录数'}
    for fact in report['facts']:
        value='本数据集未采集' if fact['value']=='not_in_this_dataset' else fact['value']
        lines.append('| '+safe_text(labels.get(fact['kind'],fact['kind']))+' | '+safe_text(value)+' | '+safe_text(fact['statement'])+' |')
    lines+=['','这些统计描述已入库的记录，不证明日志源本身未被篡改，也不自动证明攻击存在。','',
            '## 运维人员提供的背景','',
            '背景来源为本地配置声明，不能单独证明某次活动正常。']
    bg=report['operator_declarations']
    if bg['asset']:lines.append('- 资产：'+safe_text(bg['asset']['name'])+'；重要性：'+safe_text(bg['asset']['criticality']))
    else:lines.append('- 尚未提供资产业务说明。')
    lines.append('- 没有释义的规则编号：'+safe_text(bg['unknown_signature_ids']))
    if not bg['overlapping_declared_changes']:lines.append('- 未提供重叠的维护窗口声明；不能据此认定没有维护活动。')
    for change in bg['overlapping_declared_changes']:
        lines.append('- 重叠的声明维护窗口：'+safe_text(change['id'])+' — '+safe_text(change['description']))
    lines+=['','## 仍然未知','']+['- '+x for x in report['unknowns']]
    lines+=['','## 模型假设 待人工核对','']
    if not report['model_hypotheses']:lines.append('未调用模型；以上事实和背景可单独用于核对。')
    for item in report['model_hypotheses']:
        lines.append('### '+safe_text(item['instance']))
        lines.append('')
        if item['status']!='unverified_model_hypothesis':
            lines.append('状态：'+safe_text(item['status']));continue
        lines.append('未核实的模型意见：'+safe_text(item['summary']))
        lines.append('')
        lines.extend('- 待核对：'+safe_text(h) for h in item['hypotheses'])
        lines.extend('- 补证问题：'+safe_text(q) for q in item['questions'])
        lines.append('- 引用：'+', '.join('`'+eid+'`' for eid in item['evidence_ids']))
        lines.append('- 审查提示：'+'；'.join(safe_text(i['message']) for i in item['quality_review']['issues']))
        lines.append('')
    lines+=['','## 下一步核对','']+['- '+x for x in report['next_checks']]
    lines+=['','覆盖完整性：'+safe_text(report['coverage']['completeness']),
            '材料截断：'+safe_text(report['bounds']['evidence_truncated']),
            '客户需求验证：尚未进行。','']
    return '\n'.join(lines)
