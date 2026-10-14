import hashlib
import ipaddress
import json
import math
import time
from datetime import datetime, timezone


class Denied(ValueError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def integer(value, low, high):
    if type(value) is not int or not low <= value <= high:
        raise Denied('integer outside allowed range')
    return value


def normalize(raw):
    """Only numeric/enum evidence crosses into policy or AI. Raw text is discarded."""
    if raw.get('event_type') == 'alert':
        alert = raw['alert']
        values = dict(source='suricata', src_ip=raw['src_ip'], dest_ip=raw['dest_ip'],
                      dest_port=raw.get('dest_port', 0), proto=raw['proto'].lower(),
                      signature_id=alert['signature_id'], severity=alert['severity'],
                      timestamp=raw['timestamp'], flow_id=str(raw['flow_id']))
    elif raw.get('source') == 'log-rule':
        values = {k: raw[k] for k in ('source', 'src_ip', 'dest_ip', 'dest_port', 'proto',
                                    'signature_id', 'severity', 'timestamp', 'flow_id')}
    else:
        raise Denied('unsupported event; only EVE alert or normalized log-rule')
    values['src_ip'] = str(ipaddress.ip_address(values['src_ip']))
    values['dest_ip'] = str(ipaddress.ip_address(values['dest_ip']))
    integer(values['dest_port'], 1, 65535)
    integer(values['signature_id'], 1, 2**32-1)
    integer(values['severity'], 1, 3)
    if values['proto'] not in ('tcp', 'udp'):
        raise Denied('only TCP/UDP events are actionable')
    flow = str(values['flow_id'])
    if not flow.isascii() or not flow.isdigit() or len(flow) > 20:
        raise Denied('flow_id must be at most 20 decimal digits')
    values['flow_id'] = flow
    ts = datetime.fromisoformat(values['timestamp'].replace('Z', '+00:00'))
    if ts.tzinfo is None:
        raise Denied('timestamp must include timezone')
    values['timestamp'] = ts.astimezone(timezone.utc).isoformat()
    values['id'] = digest(values)
    return values


def event_time(e):
    return datetime.fromisoformat(e['timestamp']).timestamp()


def validate_policy(p):
    if p.get('mode') not in ('observe', 'shadow', 'propose', 'enforce'):
        raise Denied('invalid mode')
    for key, lo, hi in [('ttl_seconds', 5, 3600), ('max_event_age', 10, 3600),
                        ('max_active', 1, 1000), ('max_per_hour', 1, 1000)]:
        integer(p[key], lo, hi)
    if not p['management_ports'] or 22 not in p['management_ports']:
        raise Denied('management ports must include 22')
    for port in p['management_ports']:
        integer(port, 1, 65535)
    if not p['protected_cidrs'] or not p['local_addresses']:
        raise Denied('explicit protected networks and local addresses required')
    for cidr in p['protected_cidrs']:
        ipaddress.ip_network(cidr)
    for addr in p['local_addresses']:
        ipaddress.ip_address(addr)
    if type(p.get('management_confirmed')) is not bool:
        raise Denied('management_confirmed must be boolean')
    for sid in p['allowed_signatures']:
        integer(sid, 1, 2**32-1)
    if not 0.9 <= p.get('confidence_threshold', 0.95) <= 1:
        raise Denied('confidence threshold must be >= .9')
    return p


def check_event(e, p, now=None):
    now = time.time() if now is None else now
    # Reconstruct from canonical fields; never trust an incoming id.
    check = dict(e, source='log-rule')
    n = normalize(check)
    n['source'] = e['source']
    n.pop('id')
    if digest(n) != e.get('id'):
        raise Denied('event digest mismatch')
    age = now - event_time(e)
    if age < -5 or age > p['max_event_age']:
        raise Denied('stale or future evidence')
    src = ipaddress.ip_address(e['src_ip'])
    if not src.is_global or src.is_multicast or src.is_unspecified:
        raise Denied('non-global source is protected')
    if any(src in ipaddress.ip_network(n) for n in p['protected_cidrs']):
        raise Denied('protected source')
    if e['src_ip'] in p['local_addresses'] or e['dest_ip'] not in p['local_addresses']:
        raise Denied('source/destination outside authorized inbound host scope')
    if e['dest_port'] in p['management_ports']:
        raise Denied('management traffic is never actionable')
    if e['signature_id'] not in p['allowed_signatures']:
        raise Denied('signature not explicitly allowlisted')


def proposal(events, p, now=None):
    if not events or len(events) > 32:
        raise Denied('need 1..32 evidence records')
    for e in events:
        check_event(e, p, now)
    keys = {(e['src_ip'], e['dest_ip'], e['dest_port'], e['proto'], e['signature_id']) for e in events}
    if len(keys) != 1:
        raise Denied('mixed evidence targets')
    # Repeated packet alerts in the same flow do not constitute independent evidence.
    if len({e['flow_id'] for e in events}) < 2 or len({e['id'] for e in events}) != len(events):
        raise Denied('at least two distinct flows required')
    e = events[0]
    body = dict(version=1, action='temporary-source-block', ip=e['src_ip'],
                ttl=p['ttl_seconds'], evidence=sorted(events, key=lambda x: x['id']),
                policy_hash=digest(p), risk='high' if any(x['severity'] == 1 for x in events) else 'medium')
    body['id'] = digest(body)
    return body


def validate_proposal(q, p, now=None):
    expected = proposal(q['evidence'], p, now)
    if canonical(expected) != canonical(q):
        raise Denied('proposal changed or not canonical')
    return q


TRANSITIONS = {
    'observe': {'shadow'}, 'shadow': {'propose'}, 'propose': {'approve', 'rejected'},
    'approve': {'enforce', 'rejected'}, 'enforce': {'verify', 'rollback'},
    'verify': {'rollback', 'expired'}, 'rollback': set(), 'expired': set(), 'rejected': set()
}


def transition(old, new):
    if new not in TRANSITIONS.get(old, set()):
        raise Denied('invalid transition: %s -> %s' % (old, new))
    return new


def vote(raw, ids):
    if set(raw) != {'decision', 'confidence', 'evidence_ids'}:
        raise Denied('model response has unknown/missing fields')
    if raw['decision'] not in ('support', 'abstain', 'oppose'):
        raise Denied('invalid model decision')
    c = raw['confidence']
    if type(c) not in (int, float) or not math.isfinite(c) or not 0 <= c <= 1:
        raise Denied('invalid model confidence')
    refs = raw['evidence_ids']
    if not isinstance(refs, list) or not refs or not all(type(x) is str for x in refs) or set(refs) != set(ids):
        raise Denied('model must cite exactly the supplied evidence')
    return raw


def eligible_events(events, p, now=None):
    """Discard stale/ineligible observations before grouping fresh evidence."""
    for e in events:
        try:
            check_event(e, p, now)
            yield e
        except (Denied, ValueError, KeyError, TypeError):
            continue
