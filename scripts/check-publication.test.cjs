const {test}=require('node:test');
const assert=require('node:assert/strict');
const {inspect}=require('./check-publication.cjs');
const check=(file,body='')=>inspect(file,Buffer.from(body));
test('private files are refused even if someone force-adds them',()=>{
 for(const file of ['.env','backend/data/passwordmanager.db','data/instance.keys','secrets/gmail-app-password','client/android/local.properties','client/windows/flutter/ephemeral/generated_config.cmake','app.apk','app.exe','signing.jks','backup.tar.gz']) assert(check(file).length>0,file);
 assert.deepEqual(check('.env.example','PM_SMTP_USERNAME=\n'),[]);
 assert(check('.env.example','PM_SMTP_USERNAME=operator@unit-test.invalid').includes('configured-mail-in-example'));
});
test('personal server and token patterns are refused without retaining values',()=>{
 const tunnel=['https://','unit-test-only','.trycloudflare.com'].join('');
 assert(check('client/lib/app.dart',tunnel).includes('personal-tunnel-url'));
 assert(check('README.md',tunnel).includes('personal-tunnel-url'));
 const token=['gh','p_','x'.repeat(36)].join('');
 assert(check('client/lib/app.dart',token).includes('credential-pattern'));
 const key=['-----BEGIN ','PRIVATE KEY-----'].join('');
 assert(check('settings.txt',key).includes('private-key'));
 assert(check('config.txt','C:'+'\\Users\\unit-test\\project').includes('personal-machine-path'));
});
test('documented endpoints, synthetic fixtures and public certificates are allowed',()=>{
 assert.deepEqual(check('client/lib/client.dart','/api/v1/config\nhttps://vault.example.com'),[]);
 assert.deepEqual(check('docs/install.md','https://your-tunnel.trycloudflare.com'),[]);
 assert.deepEqual(check('client/test/fixtures/passkey.json','{"private_key":"synthetic-DER-fixture"}'),[]);
 assert.deepEqual(check('client/android/app/src/main/assets/privileged_apps.json','{"cert_fingerprint_sha256":"AA:BB"}'),[]);
 assert.deepEqual(check('client/assets/brand/bytelocker.png'),[]);
});
