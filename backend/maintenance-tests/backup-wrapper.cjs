// Run with Node and a POSIX shell. Docker and the tool are mocked: no server,
// root filesystem, cron, real backup or live container is touched.
const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),assert=require('node:assert/strict'),{spawnSync}=require('node:child_process');
const shell=process.env.BYTELOCKER_TEST_SHELL||'/bin/sh';
const posixTools=process.platform==='win32'?path.dirname(shell).replaceAll('\\','/').replace(/^([A-Za-z]):/,(_,drive)=>'/'+drive.toLowerCase()):'/usr/bin:/bin';
const original=fs.readFileSync(path.join(__dirname,'../../maintenance/backup.sh'),'utf8').replace(/\r\n/g,'\n');
for(const mode of ['normal','snapshot-fail','backup-fail','verify-fail']){
 const fixture=fs.mkdtempSync(path.join(os.tmpdir(),'bytelocker-wrapper-'));
 try{
  const project=path.join(fixture,'project'),bin=path.join(fixture,'bin'),maintenance=path.join(project,'maintenance');fs.mkdirSync(maintenance,{recursive:true});fs.mkdirSync(bin);
  function write(file,text){fs.writeFileSync(file,text,{mode:0o700});}
  const injected=original.replace('PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',`PATH='${posixTools}'\nFIXTURE=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)\nexport FIXTURE\nPATH="$FIXTURE/bin:${posixTools}"`).replace('backup_dir=/DATA/Backups/bytelocker','backup_dir="$FIXTURE/backups"').replace('lock_dir=/run/bytelocker-maintenance','lock_dir="$FIXTURE/locks"');
  write(path.join(maintenance,'backup.sh'),injected);
  write(path.join(bin,'id'),'#!/bin/sh\necho 0\n');
  write(path.join(bin,'flock'),'#!/bin/sh\nexit 0\n');
  write(path.join(bin,'chmod'),'#!/bin/sh\nexit 0\n');
  write(path.join(bin,'seq'),'#!/bin/sh\necho 1\n');
  write(path.join(bin,'sha256sum'),'#!/bin/sh\necho test-digest\n');
  write(path.join(bin,'docker'),`#!/bin/sh
printf '%s\\n' "$*" >> "$FIXTURE/events"
case "$1" in
compose) echo test-container ;;
run) [ "$FAIL_MODE" != snapshot-fail ] || exit 1
 for argument in "$@"; do destination="$argument"; done
 name=$(basename "$destination")
 mkdir -p "$FIXTURE/project/data/$name"
 touch "$FIXTURE/project/data/$name/passwordmanager.db" "$FIXTURE/project/data/$name/instance.keys"
 ;;
inspect) case "$3" in
 *State.Running*) if [ -f "$FIXTURE/running" ]; then cat "$FIXTURE/running"; else echo true; fi ;;
 *State.ExitCode*) echo 0 ;;
 *State.Health.Status*) echo healthy ;;
 *Image*) echo sha256:local-only ;;
 *gmail-app-password*) echo "$FIXTURE/project/secrets/gmail-app-password" ;;
 *) echo "$FIXTURE/project/data" ;;
 esac ;;
*) exit 99 ;;
esac
`);
  write(path.join(maintenance,'bytelocker-maintenance'),`#!/bin/sh
echo "tool $1" >> "$FIXTURE/events"
case "$1:$FAIL_MODE" in backup:backup-fail|verify:verify-fail) exit 1;; esac
if [ "$1" = backup ]; then touch "$5"; fi
exit 0
`);
  const result=spawnSync(shell,[path.join(maintenance,'backup.sh').replaceAll('\\','/')],{env:{...process.env,FAIL_MODE:mode},encoding:'utf8',timeout:15000});
  if(result.error)throw result.error;
  assert.equal(result.status,mode==='normal'?0:1,`${mode}: ${result.stderr} ${result.stdout}`);
  const events=fs.readFileSync(path.join(fixture,'events'),'utf8');
  assert.equal(events.split('\n').filter(s=>s.startsWith('stop ')||s.startsWith('start ')).length,0,`${mode}: backend must remain running`);
  assert(events.includes('--network none'));
  assert(events.includes('--user 10001:10001'));
  assert(!events.includes('cloudflared'));
  if(mode==='normal')assert(events.includes('tool verify'));
  console.log(`${mode}: passed`);
 }finally{fs.rmSync(fixture,{recursive:true,force:true});}
}
