"""Privileged narrow executor. No model imports, network clients, or arbitrary commands."""
import json
import os
import time
from .core import Denied, canonical, digest, eligible_events, integer, normalize, proposal, validate_proposal
from .firewall import TABLE, structure


class Broker:
    def __init__(self, policy, backend, state, save, audit, evidence_reader):
        self.p, self.nft, self.state = policy, backend, state
        self.save, self.audit, self.evidence_reader = save, audit, evidence_reader

    def owned(self):
        if not self.state.get('fingerprint') or structure(self.nft.table()) != self.state['fingerprint']:
            raise Denied('owned table missing/modified; refuse writes')
        if self.state.get('policy_hash') != digest(self.p):
            raise Denied('policy changed: uninstall owned table with old policy, then reinitialize')

    def initialize(self, confirmation):
        if confirmation != digest(self.p) or self.p['mode'] != 'enforce':
            raise Denied('explicit enforce mode and exact policy digest required')
        rules = self.nft.check_conflicts()
        self.nft.verify_management(self.p)
        if self.state.get('fingerprint'):
            self.owned()
            return 'already initialized'
        if any(x.get('table', {}).get('name') == TABLE for x in rules['nftables']):
            raise Denied('table name already exists; never adopt or overwrite it')
        self.audit('initialize_intent', policy=digest(self.p))
        self.nft.transaction(self.nft.init_script(self.p, 'aegis-fw-v1'))
        self.state.update(fingerprint=structure(self.nft.table()), policy_hash=digest(self.p),
                          cases={}, grants={}, attempts=[])
        self.save(self.state)
        self.audit('initialized', policy=digest(self.p))
        return 'initialized'

    def grant(self, sid, seconds, confirmation):
        self.owned()
        integer(sid, 1, 2**32-1)
        integer(seconds, 1, 3600)
        body = {'signature_id': sid, 'seconds': seconds, 'policy_hash': digest(self.p)}
        if confirmation != digest(body) or sid not in self.p['allowed_signatures']:
            raise Denied('exact per-signature grant confirmation required')
        self.audit('grant_intent', **body)
        self.state['grants'][str(sid)] = time.time()+seconds
        self.save(self.state)
        return body

    def apply(self, q, confirmation=None):
        now = time.time()
        validate_proposal(q, self.p, now)
        if self.p['mode'] != 'enforce':
            raise Denied('policy is not enforce')
        self.owned()
        self.nft.check_conflicts()
        self.nft.verify_management(self.p)
        prior = self.state['cases'].get(q['id'])
        if prior:
            # Never renew TTL on retry, even after expiry or a crash.
            if prior['state'] == 'enforce':
                self.rollback(q['id'])
                return {'state': 'rollback', 'recovered': True}
            return dict(prior, duplicate=True)
        for case, item in list(self.state['cases'].items()):
            if item['state'] == 'enforce':
                self.rollback(case)
        # Root re-reads trusted local evidence; caller-supplied records are not authority.
        available = {e['id']: e for e in self.evidence_reader()}
        if any(available.get(e['id']) != e for e in q['evidence']):
            raise Denied('proposal evidence not found in trusted local log')
        now = time.time()
        validate_proposal(q, self.p, now)
        sid = str(q['evidence'][0]['signature_id'])
        manual = confirmation == q['id']
        if not manual:
            if q['risk'] == 'high' or self.state['grants'].get(sid, 0) <= now:
                raise Denied('manual proposal approval required (high risk never autonomous)')
        cases = self.state['cases'].values()
        active = [x for x in cases if x['expires'] > now and x['state'] in ('enforce', 'verify')]
        if len(active) >= self.p['max_active'] or any(x['ip'] == q['ip'] for x in active):
            raise Denied('active limit or source already blocked; no TTL extension')
        attempts = [x for x in self.state['attempts'] if x > now-3600]
        if len(attempts) >= self.p['max_per_hour']:
            raise Denied('hourly action limit')
        self.audit('approve', case=q['id'], method='manual' if manual else 'scoped_grant')
        item = {'ip': q['ip'], 'expires': now+q['ttl'], 'state': 'enforce'}
        self.state['cases'][q['id']] = item
        self.state['attempts'] = attempts+[now]
        self.save(self.state)  # durable intent before touching kernel
        try:
            self.nft.add(q['ip'], q['ttl'])
            self.owned()
            if not self.nft.contains(q['ip']):
                raise Denied('post-apply verification failed')
            item['state'] = 'verify'
            self.save(self.state)
            self.audit('verify', case=q['id'], ip=q['ip'], expires=item['expires'])
            return item
        except BaseException:
            self.rollback(q['id'])
            raise

    def rollback(self, case):
        self.owned()
        item = self.state['cases'].get(case)
        if not item:
            raise Denied('unknown case')
        if item['state'] in ('rollback', 'expired'):
            return item
        if any(k != case and v['ip'] == item['ip'] and v['state'] in ('enforce', 'verify')
               and v['expires'] > time.time() for k, v in self.state['cases'].items()):
            item['state'] = 'expired'
            self.save(self.state)
            return item
        self.audit('rollback_intent', case=case)
        self.nft.remove(item['ip'])
        if self.nft.contains(item['ip']):
            raise Denied('rollback verification failed; kernel TTL remains backstop')
        item['state'] = 'rollback'
        self.save(self.state)
        self.audit('rollback', case=case)
        return item

    def reconcile(self):
        self.owned()
        for case, item in list(self.state['cases'].items()):
            if item['state'] == 'enforce':
                self.rollback(case)
            elif item['state'] == 'verify':
                present = self.nft.contains(item['ip'])
                if item['expires'] <= time.time():
                    if present:
                        self.rollback(case)
                    else:
                        item['state'] = 'expired'
                elif not present:
                    item['state'] = 'rollback'
                    self.audit('unexpected_element_loss', case=case)
        self.save(self.state)
        return self.state['cases']

    def automatic(self):
        """Deterministic no-AI path, only for individually authorized signatures."""
        self.owned()
        self.reconcile()
        batches = {}
        for e in eligible_events(self.evidence_reader(), self.p):
            if self.state['grants'].get(str(e['signature_id']), 0) <= time.time():
                continue
            key = (e['src_ip'], e['dest_ip'], e['dest_port'], e['proto'], e['signature_id'])
            batches.setdefault(key, {})[e['id']] = e
        results = []
        for records in batches.values():
            try:
                q = proposal(list(records.values())[-32:], self.p)
                results.append(self.apply(q))
            except Denied as exc:
                self.audit('automatic_hold', reason=str(exc))
        return results

    def uninstall(self, confirmation):
        self.owned()
        if confirmation != 'DELETE-OWNED-TABLE':
            raise Denied('exact uninstall confirmation required')
        self.audit('uninstall_intent')
        self.nft.uninstall()
        if any(x.get('table', {}).get('name') == TABLE for x in self.nft.rules()['nftables']):
            raise Denied('uninstall verification failed')
        self.state.clear()
        self.save(self.state)
        self.audit('uninstalled')
        return 'removed only inet aegis_fw; audit and configuration retained'
