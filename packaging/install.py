#!/usr/bin/env python3
"""Offline installer. Does not invoke nft, systemctl, sudo, pip, or the network."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import sys


def main():
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise SystemExit('Use sudo /usr/bin/python3 -I packaging/install.py on Debian/Ubuntu after review.')
    source=Path(__file__).resolve().parents[1]
    targets=[Path('/opt/aegis-fw'),Path('/etc/aegis-fw'),Path('/var/lib/aegis-fw'),
             Path('/usr/local/bin/aegis-fw'),Path('/usr/local/bin/aegis-fw-admin')]
    for p in targets:
        if p.exists() or p.is_symlink():raise SystemExit('Refuse to overwrite existing path: '+str(p))
        for parent in p.parents:
            if parent.exists():
                st=parent.lstat()
                if stat.S_ISLNK(st.st_mode) or st.st_uid!=0 or st.st_mode&0o022:
                    raise SystemExit('Untrusted parent: '+str(parent))
    os.umask(0o022)
    root=targets[0];root.mkdir(mode=0o755)
    package=root/'lib'/'aegis_fw';package.mkdir(parents=True)
    for p in (source/'aegis_fw').glob('*.py'):
        if p.is_symlink():raise SystemExit('Refuse source symlink')
        shutil.copyfile(p,package/p.name)
    (root/'entry.py').write_text('import sys\nsys.dont_write_bytecode=True\nsys.path.insert(0,"/opt/aegis-fw/lib")\nmode=sys.argv.pop(1)\nif mode=="admin":\n from aegis_fw.admin import main\nelse:\n from aegis_fw.cli import main\nmain()\n')
    for name,mode in [('aegis-fw','worker'),('aegis-fw-admin','admin')]:
        p=Path('/usr/local/bin')/name
        p.write_text('#!/bin/sh\nexec /usr/bin/python3 -I /opt/aegis-fw/entry.py '+mode+' "$@"\n');p.chmod(0o755)
    targets[1].mkdir(mode=0o755);targets[2].mkdir(mode=0o700)
    shutil.copyfile(source/'examples/policy.json',targets[1]/'policy.json')
    shutil.copyfile(source/'packaging/uninstall.py',root/'uninstall.py')
    for name in ('LICENSE','README.md'):shutil.copyfile(source/name,root/name)
    files=[p for p in root.rglob('*') if p.is_file()]+targets[3:]
    manifest={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
    (root/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print('Installed without firewall changes. Policy remains shadow. No services enabled.')
    print('Configure /etc/aegis-fw/policy.json before any explicit live authorization.')

if __name__=='__main__':main()
