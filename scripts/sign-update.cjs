#!/usr/bin/env node
'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),{spawnSync}=require('node:child_process');
function main(){
 const root=path.resolve(__dirname,'..'),[artifact,version,build,platform,output]=process.argv.slice(2);
 if(!artifact||!version||!build||!['windows-x64','android-arm64'].includes(platform)||!output)throw Error('Usage: node scripts/sign-update.cjs artifact version build platform output');
 const keyPath=process.env.BYTELOCKER_UPDATE_SIGNING_KEY;if(!keyPath)throw Error('Set BYTELOCKER_UPDATE_SIGNING_KEY to the private signing-key file outside Git');
 const key=crypto.createPrivateKey(fs.readFileSync(keyPath));if(key.asymmetricKeyType!=='ed25519')throw Error('Expected Ed25519 signing key');
 const der=crypto.createPublicKey(key).export({format:'der',type:'spki'}),pub=der.subarray(der.length-32).toString('base64');
 const source=fs.readFileSync(path.join(root,'client/lib/updates/update_key.dart'),'utf8');if(!source.includes("'"+pub+"'"))throw Error('Signing key does not match the app verification key');
 if(!fs.readFileSync(path.join(root,'client/windows/updater/key.go'),'utf8').includes('"'+pub+'"'))throw Error('Windows updater verification key mismatch');
 const result=spawnSync(process.env.BYTELOCKER_PYTHON||'python',[path.join(__dirname,'create-update-payload.py'),'--artifact',path.resolve(artifact),'--version',version,'--build',build,'--platform',platform],{encoding:'utf8',maxBuffer:8*1024*1024,windowsHide:true});
 if(result.status!==0)throw Error('Cannot generate verified package metadata');
 const payload=Buffer.from(JSON.stringify(JSON.parse(result.stdout)));
 const signature=crypto.sign(null,payload,key);
 const envelope=JSON.stringify({schema:1,payload:payload.toString('base64'),signature:signature.toString('base64')})+'\n';
 fs.mkdirSync(path.dirname(path.resolve(output)),{recursive:true});fs.writeFileSync(output,envelope);
 console.log(JSON.stringify({signed:true,platform,version,build:Number(build)}));
}
try{main()}catch(error){console.error(error.message);process.exitCode=1}
