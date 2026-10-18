"""Local, unprivileged historical evidence. Never a firewall authorization source."""
from contextlib import contextmanager
from datetime import datetime, timezone
import ipaddress
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import time
import uuid

from .core import Denied, canonical, digest, event_time, integer, normalize

APPLICATION_ID = 1095124805
SCHEMA_VERSION = 1
DEFAULTS = {
    'history_days': 30,
    'max_batch_records': 20000,
    'max_batch_bytes': 4194304,
    'max_line_bytes': 65536,
    'max_events': 200000,
    'max_incidents': 10000,
    'max_receipts': 50000,
    'max_checkpoints_per_incident': 100,
    'max_database_bytes': 536870912,
    'max_query_rows': 200,
    'max_sql_steps': 2000000,
    'future_tolerance_seconds': 5,
    'late_after_seconds': 300,
    'windows_seconds': [10, 60, 300, 3600, 86400, 604800, 2592000],
    'expected_sensors': [],
    'context_max_bytes': 32768,
    'instance_counts': {'traffic': 2, 'timeline': 1, 'business': 1, 'critic': 1, 'lead': 1},
    'max_instances': 8,
}


def utc(value):
    return datetime.fromtimestamp(value, timezone.utc).isoformat()


def timestamp(value):
    if type(value) in (int, float):
        # ISO strings are used at the CLI boundary; floats are internal only.
        number = float(value)
        if not 0 <= number <= 253402300799:
            raise Denied('timestamp outside supported range')
        return number
    if not isinstance(value, str) or len(value) > 40:
        raise Denied('ISO timestamp with timezone required')
    try:
        dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if dt.tzinfo is None:
            raise ValueError()
        return timestamp(dt.timestamp())
    except (ValueError, OverflowError):
        raise Denied('invalid timestamp')


def settings(raw=None):
    raw = {} if raw is None else raw
    if not isinstance(raw, dict) or set(raw)-set(DEFAULTS):
        raise Denied('unknown evidence configuration fields')
    cfg = dict(DEFAULTS, **raw)
    for name, low, high in (
        ('history_days', 1, 365), ('max_batch_records', 1, 20000),
        ('max_batch_bytes', 65536, 16777216), ('max_line_bytes', 1024, 65536),
        ('max_events', 1, 2000000), ('max_incidents', 1, 100000),
        ('max_receipts', 1, 100000), ('max_checkpoints_per_incident', 1, 10000), ('max_database_bytes', 1048576, 10737418240),
        ('max_query_rows', 1, 1000), ('max_sql_steps', 10000, 10000000),
        ('future_tolerance_seconds', 0, 60), ('late_after_seconds', 1, 86400),
        ('context_max_bytes', 8192, 131072), ('max_instances', 1, 16),
    ):
        integer(cfg[name], low, high)
    windows = cfg['windows_seconds']
    if not isinstance(windows, list) or not 1 <= len(windows) <= 12:
        raise Denied('need 1..12 analysis windows')
    for window in windows:
        integer(window, 1, cfg['history_days']*86400)
    cfg['windows_seconds'] = sorted(set(windows))
    if not isinstance(cfg['expected_sensors'], list) or len(cfg['expected_sensors']) > 32:
        raise Denied('too many expected sensors')
    cfg['expected_sensors'] = sorted(set(sensor_id(x) for x in cfg['expected_sensors']))
    roles = cfg['instance_counts']
    if not isinstance(roles, dict) or set(roles) != {'traffic', 'timeline', 'business', 'critic', 'lead'}:
        raise Denied('fixed investigation roles required')
    for count in roles.values():
        integer(count, 1, 4)
    if roles['lead'] != 1 or sum(roles.values()) > cfg['max_instances']:
        raise Denied('one lead and bounded total instance count required')
    return cfg


def sensor_id(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', value):
        raise Denied('sensor ID must be 1..64 ASCII letters, digits, underscore or hyphen')
    return value


def scope(assets, asset, service, since, until, cfg, source_ip=None):
    asset = str(ipaddress.ip_address(asset))
    if asset not in assets:
        raise Denied('asset is not in this host policy local_addresses')
    if not isinstance(service, str) or not re.fullmatch(r'(tcp|udp):[0-9]{1,5}', service):
        raise Denied('service must be tcp:PORT or udp:PORT')
    proto, port = service.split(':')
    port = integer(int(port), 1, 65535)
    start, end = timestamp(since), timestamp(until)
    if not start < end or end-start > cfg['history_days']*86400 or end > time.time()+cfg['future_tolerance_seconds']:
        raise Denied('invalid or excessive investigation time range')
    source_ip = str(ipaddress.ip_address(source_ip)) if source_ip else None
    return dict(asset=asset, proto=proto, port=port, since=utc(start), until=utc(end), source_ip=source_ip)


def query_parts(s, watermark):
    sql = 'asset=? AND proto=? AND port=? AND event_time>=? AND event_time<? AND seq<=?'
    args = [s['asset'], s['proto'], s['port'], timestamp(s['since']), timestamp(s['until']), watermark]
    if s['source_ip']:
        sql += ' AND src_ip=?'
        args.append(s['source_ip'])
    return sql, args


class EvidenceStore:
    """Separate schema/identity prevents opening an observer or privileged audit DB."""
    def __init__(self, path, assets, cfg=None):
        if hasattr(os, 'geteuid') and os.geteuid() == 0:
            raise Denied('historical evidence commands must run without root')
        self.cfg = settings(cfg)
        self.assets = {str(ipaddress.ip_address(a)) for a in assets}
        path = Path(path).absolute()
        parent = path.parent
        st = parent.lstat()
        if stat.S_ISLNK(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o022:
            raise Denied('evidence DB needs a user-owned directory not writable by others')
        for suffix in ('', '-wal', '-shm', '-journal'):
            item = Path(str(path)+suffix)
            if item.exists() or item.is_symlink():
                st = item.lstat()
                if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077:
                    raise Denied('evidence DB and sidecars must be private regular files owned by this user')
        new = not path.exists()
        if new:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
        self.path = path
        self.db = sqlite3.connect(str(path), timeout=10)
        self.db.row_factory = sqlite3.Row
        app = self.db.execute('PRAGMA application_id').fetchone()[0]
        version = self.db.execute('PRAGMA user_version').fetchone()[0]
        tables = self.db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        if (not new and (app != APPLICATION_ID or version != SCHEMA_VERSION)) or (new and tables):
            self.db.close()
            raise Denied('not an Aegis historical evidence database; refusing to adopt/migrate it')
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('PRAGMA foreign_keys=ON')
        if new:
            self.db.executescript('''
            CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE events(
              seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT UNIQUE NOT NULL,
              sensor TEXT NOT NULL, event_time REAL NOT NULL, received_time REAL NOT NULL,
              asset TEXT NOT NULL, proto TEXT NOT NULL, port INTEGER NOT NULL,
              src_ip TEXT NOT NULL, signature INTEGER NOT NULL, severity INTEGER NOT NULL,
              flow TEXT NOT NULL, late INTEGER NOT NULL, normalized TEXT NOT NULL,
              origin TEXT NOT NULL, offset INTEGER NOT NULL, length INTEGER NOT NULL,
              line_hash TEXT NOT NULL);
            CREATE INDEX events_scope ON events(asset,proto,port,event_time,seq);
            CREATE INDEX events_source ON events(src_ip,event_time);
            CREATE TABLE sensors(id TEXT PRIMARY KEY, path TEXT NOT NULL, device INTEGER NOT NULL,
              inode INTEGER NOT NULL, offset INTEGER NOT NULL, last_received REAL NOT NULL);
            CREATE TABLE receipts(id TEXT PRIMARY KEY, sensor TEXT NOT NULL, received_time REAL NOT NULL,
              body TEXT NOT NULL);
            CREATE TABLE incidents(id TEXT PRIMARY KEY, parent TEXT, created REAL NOT NULL,
              watermark INTEGER NOT NULL, scope TEXT NOT NULL, coverage TEXT NOT NULL,
              FOREIGN KEY(parent) REFERENCES incidents(id));
            CREATE TABLE checkpoints(id TEXT PRIMARY KEY, incident TEXT NOT NULL, created REAL NOT NULL,
              body TEXT NOT NULL, FOREIGN KEY(incident) REFERENCES incidents(id));
            CREATE TABLE journal(seq INTEGER PRIMARY KEY, payload TEXT NOT NULL, hash TEXT NOT NULL);
            ''')
            with self.db:
                self.db.execute('INSERT INTO meta VALUES (?,?)', ('database_id', uuid.uuid4().hex))
                self.db.execute('PRAGMA application_id=%d' % APPLICATION_ID)
                self.db.execute('PRAGMA user_version=%d' % SCHEMA_VERSION)
        self.database_id = self.db.execute("SELECT value FROM meta WHERE key='database_id'").fetchone()[0]
        self.db.set_progress_handler(lambda: 1, self.cfg['max_sql_steps'])

    def close(self):
        self.db.close()

    @contextmanager
    def transaction(self):
        self.db.execute('BEGIN IMMEDIATE')
        try:
            yield
            self.db.commit()
        except BaseException:
            self.db.rollback()
            raise

    def journal(self, kind, details):
        previous = self.db.execute('SELECT hash FROM journal ORDER BY seq DESC LIMIT 1').fetchone()
        body = canonical(dict(time=utc(time.time()), kind=kind, details=details,
                              previous=previous[0] if previous else ''))
        self.db.execute('INSERT INTO journal(payload,hash) VALUES (?,?)', (body, digest(body)))

    def verify_journal(self):
        previous, count = '', 0
        for row in self.db.execute('SELECT payload,hash FROM journal ORDER BY seq'):
            if digest(row['payload']) != row['hash'] or json.loads(row['payload'])['previous'] != previous:
                raise Denied('historical journal chain broken')
            previous, count = row['hash'], count+1
        return dict(records=count, head=previous, protection='local consistency; not tamper-proof against owner/root')

    def check_disk_budget(self):
        used_bytes = sum(p.stat().st_size for p in (self.path, Path(str(self.path)+'-wal')) if p.exists())
        if used_bytes >= self.cfg['max_database_bytes']:
            raise Denied('evidence disk budget reached; no automatic eviction')

    def ingest(self, filename, sensor):
        sensor = sensor_id(sensor)
        path = Path(filename).absolute()
        if path.is_symlink():
            raise Denied('input must not be a symlink')
        path = path.resolve(strict=True)
        self.check_disk_budget()
        received = time.time()
        receipt = dict(id=uuid.uuid4().hex, sensor=sensor, received_time=utc(received), inserted=0,
                       duplicates=0, ignored=0, rejected=0, late=0, outside_history=0, future=0,
                       out_of_scope=0, continuity_warning=None, incomplete_tail=False, batch_limited=False)
        with self.transaction():
            if self.db.execute('SELECT count(*) FROM receipts').fetchone()[0] >= self.cfg['max_receipts']:
                raise Denied('collection receipt limit reached; archive before collecting more')
            if (self.db.execute('SELECT count(*) FROM sensors').fetchone()[0] >= 128 and
                    not self.db.execute('SELECT 1 FROM sensors WHERE id=?',(sensor,)).fetchone()):
                raise Denied('sensor inventory limit reached')
            count = self.db.execute('SELECT count(*) FROM events').fetchone()[0]
            if count >= self.cfg['max_events']:
                raise Denied('event budget reached; preserve/archive evidence before collecting more')
            fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
            with os.fdopen(fd, 'rb') as f:
                st = os.fstat(f.fileno())
                if not stat.S_ISREG(st.st_mode):
                    raise Denied('input must be a regular file')
                cursor = self.db.execute('SELECT * FROM sensors WHERE id=?', (sensor,)).fetchone()
                offset = 0
                if cursor:
                    if cursor['path'] != str(path):
                        raise Denied('sensor ID is pinned to its original path; use a new sensor ID')
                    if (cursor['device'], cursor['inode']) != (st.st_dev, st.st_ino):
                        receipt['continuity_warning'] = 'rotation; uncollected old-file data may be missing'
                    elif st.st_size < cursor['offset']:
                        receipt['continuity_warning'] = 'truncation; prior stream continuity is unknown'
                    else:
                        offset = cursor['offset']
                f.seek(offset)
                read_bytes, scanned = 0, 0
                while scanned < self.cfg['max_batch_records']:
                    start = f.tell()
                    line = f.readline(self.cfg['max_line_bytes']+1)
                    if not line:
                        break
                    if len(line) > self.cfg['max_line_bytes']:
                        raise Denied('oversized log line; batch rolled back and cursor retained')
                    if read_bytes+len(line) > self.cfg['max_batch_bytes']:
                        f.seek(start); receipt['batch_limited'] = True; break
                    if not line.endswith(b'\n'):
                        f.seek(start); receipt['incomplete_tail'] = True; break
                    scanned += 1; read_bytes += len(line)
                    try:
                        raw = json.loads(line)
                        if not isinstance(raw, dict):
                            raise ValueError()
                        if raw.get('event_type') != 'alert' and raw.get('source') != 'log-rule':
                            receipt['ignored'] += 1; continue
                        e = normalize(raw)
                        t = event_time(e)
                    except (ValueError, TypeError, KeyError, AttributeError, OverflowError):
                        receipt['rejected'] += 1; continue
                    if e['dest_ip'] not in self.assets:
                        receipt['out_of_scope'] += 1; continue
                    if t > received+self.cfg['future_tolerance_seconds']:
                        receipt['future'] += 1; continue
                    if t < received-self.cfg['history_days']*86400:
                        receipt['outside_history'] += 1; continue
                    if count+receipt['inserted'] >= self.cfg['max_events']:
                        f.seek(start); receipt['batch_limited'] = True; break
                    eid = digest({'sensor': sensor, 'event': e})
                    late = int(received-t > self.cfg['late_after_seconds'])
                    result = self.db.execute('''INSERT OR IGNORE INTO events
                      (id,sensor,event_time,received_time,asset,proto,port,src_ip,signature,severity,
                       flow,late,normalized,origin,offset,length,line_hash)
                      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                      (eid,sensor,t,received,e['dest_ip'],e['proto'],e['dest_port'],e['src_ip'],
                       e['signature_id'],e['severity'],e['flow_id'],late,canonical(e),str(path),
                       start,len(line),hashlib.sha256(line).hexdigest()))
                    if result.rowcount:
                        receipt['inserted'] += 1; receipt['late'] += late
                    else:
                        receipt['duplicates'] += 1
                offset = f.tell()
                receipt.update(offset=offset, records_scanned=scanned, bytes_read=read_bytes,
                               backlog_bytes=max(0,st.st_size-offset))
                receipt['batch_limited'] = receipt['batch_limited'] or offset < st.st_size and not receipt['incomplete_tail']
                self.db.execute('INSERT OR REPLACE INTO sensors VALUES (?,?,?,?,?,?)',
                                (sensor,str(path),st.st_dev,st.st_ino,offset,received))
            self.db.execute('INSERT INTO receipts VALUES (?,?,?,?)',
                            (receipt['id'],sensor,received,canonical(receipt)))
            self.journal('collect', receipt)
        return receipt

    def coverage(self):
        known = [dict(x) for x in self.db.execute('SELECT id,last_received FROM sensors ORDER BY id LIMIT 128')]
        receipts = [json.loads(x[0]) for x in self.db.execute('SELECT body FROM receipts ORDER BY received_time DESC LIMIT 20')]
        return dict(expected_sensors=self.cfg['expected_sensors'],
                    missing_expected_sensors=sorted(set(self.cfg['expected_sensors'])-{x['id'] for x in known}),
                    sensors=[dict(id=x['id'], last_collection=utc(x['last_received'])) for x in known],
                    recent_receipts=receipts, completeness='unknown: no sensor heartbeat or loss attestation',
                    trust='observer evidence only; sensor labels are not authenticated identities')

    def snapshot(self, s, parent=None):
        self.check_disk_budget()
        s = scope(self.assets,s['asset'],s['proto']+':'+str(s['port']),s['since'],s['until'],self.cfg,s.get('source_ip'))
        with self.transaction():
            if self.db.execute('SELECT count(*) FROM incidents').fetchone()[0] >= self.cfg['max_incidents']:
                raise Denied('investigation snapshot limit reached')
            watermark = self.db.execute('SELECT coalesce(max(seq),0) FROM events').fetchone()[0]
            case = dict(id=uuid.uuid4().hex,parent=parent,created=utc(time.time()),watermark=watermark,
                        scope=s,coverage=self.coverage(),database_id=self.database_id)
            self.db.execute('INSERT INTO incidents VALUES (?,?,?,?,?,?)',
                            (case['id'],parent,timestamp(case['created']),watermark,canonical(s),canonical(case['coverage'])))
            self.journal('snapshot', dict(id=case['id'],parent=parent,watermark=watermark,scope=s))
        return case

    def incident(self, case_id):
        row = self.db.execute('SELECT * FROM incidents WHERE id=?', (case_id,)).fetchone()
        if not row:
            raise Denied('unknown investigation snapshot')
        s = json.loads(row['scope'])
        scope(self.assets,s['asset'],s['proto']+':'+str(s['port']),s['since'],s['until'],self.cfg,s.get('source_ip'))
        return dict(id=row['id'],parent=row['parent'],created=utc(row['created']),watermark=row['watermark'],
                    scope=s,coverage=json.loads(row['coverage']),database_id=self.database_id)

    def summary(self, case):
        where, args = query_parts(case['scope'], case['watermark'])
        row = self.db.execute('''SELECT count(*) events,count(DISTINCT src_ip) sources,
           count(DISTINCT signature) signatures,count(DISTINCT sensor) sensors,
           coalesce(sum(severity=1),0) high_severity,coalesce(sum(late),0) late,
           min(event_time) first,max(event_time) last FROM events WHERE '''+where,args).fetchone()
        return {k: (utc(row[k]) if row[k] is not None and k in ('first','last') else row[k]) for k in row.keys()}

    def records(self, case, limit=None):
        limit = self.cfg['max_query_rows'] if limit is None else integer(limit,1,self.cfg['max_query_rows'])
        where,args = query_parts(case['scope'],case['watermark'])
        rows = self.db.execute('SELECT * FROM events WHERE '+where+' ORDER BY event_time DESC,seq DESC LIMIT ?',args+[limit]).fetchall()
        result=[]
        for row in rows:
            result.append(dict(evidence_id=row['id'],event_time=utc(row['event_time']),
                               received_time=utc(row['received_time']),sensor=row['sensor'],
                               late=bool(row['late']),observed=json.loads(row['normalized'])))
        return dict(records=result,order='event_time descending',limit=limit,
                    truncated=self.summary(case)['events']>len(result))

    def windows(self, case):
        result=[]
        end = timestamp(case['scope']['until'])
        start = timestamp(case['scope']['since'])
        for seconds in self.cfg['windows_seconds']:
            actual_start=max(start,end-seconds)
            subset=dict(case,scope=dict(case['scope'],since=utc(actual_start)))
            result.append(dict(requested_seconds=seconds,since=utc(actual_start),until=utc(end),
                               clipped_to_case=actual_start>end-seconds,stats=self.summary(subset)))
        return result

    def series(self, case, seconds=60, limit=200):
        integer(seconds,1,self.cfg['history_days']*86400)
        integer(limit,1,self.cfg['max_query_rows'])
        where,args = query_parts(case['scope'],case['watermark'])
        total = self.db.execute('SELECT count(DISTINCT CAST(event_time/? AS INTEGER)) FROM events WHERE '+where,[seconds]+args).fetchone()[0]
        rows=self.db.execute('''SELECT CAST(event_time/? AS INTEGER)*? bucket,count(*) events,
           count(DISTINCT src_ip) sources,coalesce(sum(severity=1),0) high_severity
           FROM events WHERE '''+where+' GROUP BY bucket ORDER BY bucket DESC LIMIT ?',
           [seconds,seconds]+args+[limit]).fetchall()
        return dict(bucket_seconds=seconds,buckets=[dict(since=utc(r['bucket']),events=r['events'],
                    sources=r['sources'],high_severity=r['high_severity']) for r in rows],
                    order='newest first',truncated=total>len(rows),
                    absent_buckets='unknown observation coverage, not proven zero traffic')

    def show(self, evidence_id):
        row=self.db.execute('SELECT * FROM events WHERE id=?',(evidence_id,)).fetchone()
        if not row or row['asset'] not in self.assets:
            raise Denied('unknown or out-of-scope evidence')
        return dict(evidence_id=row['id'],observed=json.loads(row['normalized']),
                    event_time=utc(row['event_time']),received_time=utc(row['received_time']),
                    provenance=dict(sensor=row['sensor'],path=row['origin'],offset=row['offset'],
                                    length=row['length'],line_digest=row['line_hash'],
                                    digest_scheme='sha256(raw_line_bytes_including_newline)',
                                    warning='original file may have rotated; no raw payload is retained here'))
