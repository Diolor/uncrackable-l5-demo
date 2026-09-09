#!/usr/bin/env python3
"""Local signing custody helper. Never prints private material or overwrites a key."""
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
PRIVATE = Path.home() / '.android' / 'uncrackable-l5-release'
CONFIG = PRIVATE / 'signing.json'
JDK = Path('/Applications/Android Studio.app/Contents/jbr/Contents/Home/bin')

def run(*args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)

if len(sys.argv) != 2 or sys.argv[1] not in ('create', 'build'):
    raise SystemExit('Usage: scripts/release-signing.py create|build')
os.umask(0o077)
if sys.argv[1] == 'create':
    PRIVATE.mkdir(parents=True, exist_ok=False, mode=0o700)
    env = dict(os.environ,
        UNCRACKABLE_KEYSTORE=str(PRIVATE / 'release.jks'),
        UNCRACKABLE_KEYSTORE_PASSWORD=secrets.token_urlsafe(48),
        UNCRACKABLE_KEY_PASSWORD=secrets.token_urlsafe(48),
        UNCRACKABLE_KEY_ALIAS='uncrackable-l5')
    # Store recovery credentials before generation; an interrupted run never regenerates silently.
    CONFIG.write_text(json.dumps({k: v for k, v in env.items() if k.startswith('UNCRACKABLE_')}, indent=2))
    run(str(JDK / 'keytool'), '-genkeypair', '-keystore', env['UNCRACKABLE_KEYSTORE'],
        '-storetype', 'JKS', '-alias', env['UNCRACKABLE_KEY_ALIAS'],
        '-storepass:env', 'UNCRACKABLE_KEYSTORE_PASSWORD', '-keypass:env', 'UNCRACKABLE_KEY_PASSWORD',
        '-keyalg', 'RSA', '-keysize', '4096', '-sigalg', 'SHA256withRSA', '-validity', '10950',
        '-dname', 'CN=UnCrackable L5 Release', env=env, stdout=subprocess.DEVNULL)
    der = run(str(JDK / 'keytool'), '-exportcert', '-keystore', env['UNCRACKABLE_KEYSTORE'],
        '-alias', env['UNCRACKABLE_KEY_ALIAS'], '-storepass:env', 'UNCRACKABLE_KEYSTORE_PASSWORD',
        env=env, stdout=subprocess.PIPE).stdout
    import base64
    body = base64.b64encode(der).decode()
    public = ROOT / 'release'
    public.mkdir(exist_ok=True)
    (public / 'signing-certificate.pem').write_text('-----BEGIN CERTIFICATE-----\n' +
        '\n'.join(body[i:i+64] for i in range(0, len(body), 64)) + '\n-----END CERTIFICATE-----\n')
    (public / 'signer-sha256.txt').write_text(hashlib.sha256(der).hexdigest() + '\n')
    print('Created private signing material in', PRIVATE)
    print('Public certificate SHA-256:', hashlib.sha256(der).hexdigest())
else:
    env = dict(os.environ, **json.loads(CONFIG.read_text()))
    run(str(ROOT / 'gradlew'), ':app:assembleRelease',
        '--no-daemon', cwd=ROOT, env=env)
