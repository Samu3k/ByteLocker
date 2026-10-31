"""Public package metadata only. Never reads vaults, profiles or signing keys."""
import argparse, hashlib, json, re, zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath

parser=argparse.ArgumentParser()
parser.add_argument('--artifact',required=True);parser.add_argument('--version',required=True)
parser.add_argument('--build',required=True,type=int);parser.add_argument('--platform',required=True,choices=['windows-x64','android-arm64'])
args=parser.parse_args()
if not re.fullmatch(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',args.version) or not 1<=args.build<=2147483647: raise SystemExit('Invalid version')
file=Path(args.artifact)
name=f'ByteLocker-Windows-{args.version}.zip' if args.platform=='windows-x64' else f'ByteLocker-{args.version}-android-arm64.apk'
if file.name!=name or not 1<=file.stat().st_size<=128*1024*1024: raise SystemExit('Unexpected artifact')
files=[];seen=set();total=0
if args.platform=='windows-x64':
    with zipfile.ZipFile(file) as archive:
        for entry in archive.infolist():
            if entry.is_dir(): continue
            path=entry.filename
            if path.lower() in seen or '\\' in path or path.startswith('/') or any(part in ('','.', '..') or part.endswith(('.', ' ')) or re.search(r'[\x00-\x1f:<>"|?*]',part) or re.fullmatch(r'(?:CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])(?:\..*)?',part,re.I) for part in path.split('/')): raise SystemExit('Unsafe package path')
            seen.add(path.lower());total+=entry.file_size
            if entry.file_size>128*1024*1024 or total>512*1024*1024 or len(seen)>10000: raise SystemExit('Package too large')
            files.append({'path':path,'size':entry.file_size,'sha256':hashlib.sha256(archive.read(entry)).hexdigest()})
    if not {'.bytelocker-install.json','bytelocker.exe','bytelockerupdater.exe'}<=seen: raise SystemExit('Updater or inventory missing')
payload={'schema':1,'version':args.version,'build':args.build,'platform':args.platform,
 'url':f'https://github.com/Samu3k/ByteLocker/releases/download/v{args.version}/{name}',
 'sha256':hashlib.sha256(file.read_bytes()).hexdigest(),'size':file.stat().st_size,
 'expires':(datetime.now(timezone.utc)+timedelta(days=180)).isoformat().replace('+00:00','Z'),'files':files}
print(json.dumps(payload,separators=(',',':'),ensure_ascii=True))
