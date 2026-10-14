#!/usr/bin/env python3
"""Remove only unchanged, manifest-listed software; retain policy/audit/evidence."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


def main():
    if os.geteuid()!=0 or sys.argv[1:]!=['--confirm-remove-software']:
        raise SystemExit('Requires root and --confirm-remove-software; remove owned table first.')
    r=subprocess.run(['/usr/sbin/nft','-j','list','ruleset'],capture_output=True,text=True)
    if r.returncode:raise SystemExit('Cannot inspect rules; refusing software removal')
    if any(x.get('table',{}).get('name')=='aegis_fw' for x in json.loads(r.stdout)['nftables']):
        raise SystemExit('Owned table still exists; run admin uninstall first')
    for name in ('aegis-fw-auto.service','aegis-fw-auto.timer'):
        if (Path('/etc/systemd/system')/name).exists():
            raise SystemExit('Stop/disable timer and remove only its reviewed unit files first')
    root=Path('/opt/aegis-fw');manifestpath=root/'manifest.json'
    manifest=json.loads(manifestpath.read_text())
    allowed={Path(x) for x in manifest}
    actual={p for p in root.rglob('*') if p.is_file() or p.is_symlink()}
    if actual!={p for p in allowed if root in p.parents}|{manifestpath}:
        raise SystemExit('Unknown/missing software files; retain everything for manual review')
    expected_dirs={root}
    for p in allowed:
        if root in p.parents:
            expected_dirs.update(parent for parent in p.parents if parent==root or root in parent.parents)
    actual_dirs={root}|{p for p in root.rglob('*') if p.is_dir()}
    if actual_dirs!=expected_dirs:
        raise SystemExit('Unknown directories; retain everything for manual review')
    for p in allowed:
        if root not in p.parents and p not in (Path('/usr/local/bin/aegis-fw'),Path('/usr/local/bin/aegis-fw-admin')):
            raise SystemExit('Manifest contains unexpected path')
        if p.is_symlink() or hashlib.sha256(p.read_bytes()).hexdigest()!=manifest[str(p)]:
            raise SystemExit('Changed software file; retain everything: '+str(p))
    for p in allowed:p.unlink()
    manifestpath.unlink()
    for p in sorted((p for p in root.rglob('*') if p.is_dir()),key=lambda p:len(p.parts),reverse=True):p.rmdir()
    root.rmdir()
    print('Software removed; /etc/aegis-fw and /var/lib/aegis-fw retained for audit/recovery.')
if __name__=='__main__':main()
