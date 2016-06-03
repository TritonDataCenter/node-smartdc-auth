// Copyright 2015 Joyent, Inc.  All rights reserved.

var test = require('tape').test;

var temp = require('temp');
var fs = require('fs');
var path = require('path');
var sshpk = require('sshpk');
var vasync = require('vasync');
var auth = require('../lib/index');

/* automatically clean up temp dir at exit */
temp.track();

var testDir = __dirname;
var tmpDir;
var ID_RSA_FP = 'SHA256:29GY+6bxcBkcNNUzTnEcTdTv1W3d3PN/OxyplcYSoX4';
var ID_RSA2_FP = 'SHA256:FWEns/VvPZdbSPtoVDUlUpewdP/LgC/4+l/V42Oltpw';
var ID_DSA_FP = 'SHA256:WI2QyT/UuJ4LaPylGynx244f6k+xqVHYOyxg1cfnL0I';

function copyAsset(name, dst, cb) {
    var rd = fs.createReadStream(path.join(testDir, name));
    var wr = fs.createWriteStream(path.join(tmpDir, dst));
    wr.on('close', cb);
    rd.pipe(wr);
}

test('setup', function (t) {
    temp.mkdir('smartdc-auth.fs-keys.test', function (err, tmp) {
        t.error(err);
        tmpDir = tmp;
        fs.mkdirSync(path.join(tmpDir, '.ssh'));

        vasync.parallel({
            funcs: [
                copyAsset.bind(this, 'id_rsa',
                    path.join('.ssh', 'id_rsa')),
                copyAsset.bind(this, 'id_rsa.pub',
                    path.join('.ssh', 'id_rsa.pub')),
                copyAsset.bind(this, 'id_dsa',
                    path.join('.ssh', 'id_dsa'))
            ]
        }, function (err, res) {
            t.error(err);
            process.env['HOME'] = tmpDir;
            delete process.env['SSH_AUTH_SOCK'];
            delete process.env['SSH_AGENT_PID'];
            t.end();
        });
    });
});

test('loadSSHKey full pair', function (t) {
    auth.loadSSHKey(ID_RSA_FP, function (err, key, keyFiles) {
        t.error(err);
        t.equal(key.type, 'rsa');
        t.equal(key.size, 1024);
        t.equal(key.comment, path.join(tmpDir, '.ssh', 'id_rsa'));
        t.end();
    });
});

test('loadSSHKey public only', function (t) {
    fs.unlinkSync(path.join(tmpDir, '.ssh', 'id_rsa'));
    auth.loadSSHKey(ID_RSA_FP, function (err) {
        t.ok(err);
        t.ok(err instanceof auth.KeyNotFoundError);
        t.end();
    });
});

test('keyring cannot sign', function (t) {
    var kr = new auth.KeyRing({ plugins: ['homedir'] });
    var fp = sshpk.parseFingerprint(ID_RSA_FP);
    kr.findSigningKeyPair(fp, function (err, kp) {
        t.ok(err);
        kr.find(fp, function (err2, kps) {
            t.error(err2);
            t.strictEqual(kps.length, 1);
            t.ok(!kps[0].canSign());
            t.end();
        });
    });
});

test('loadSSHKey private only rsa', function (t) {
    fs.unlinkSync(path.join(tmpDir, '.ssh', 'id_rsa.pub'));
    copyAsset('id_rsa', path.join('.ssh', 'id_rsa'), function () {
        auth.loadSSHKey(ID_RSA_FP, function (err) {
            t.error(err);
            t.end();
        });
    });
});

test('loadSSHKey private only dsa', function (t) {
    auth.loadSSHKey(ID_DSA_FP, function (err, key) {
        t.error(err);
        t.equal(key.type, 'dsa');
        t.equal(key.size, 1024);
        t.end();
    });
});

test('keyring basic', function (t) {
    var kr = new auth.KeyRing({ plugins: ['homedir'] });
    var fp = sshpk.parseFingerprint(ID_DSA_FP);
    kr.findSigningKeyPair(fp, function (err, kp) {
        t.error(err);
        t.ok(kp.canSign());
        t.ok(!kp.isLocked());
        t.end();
    });
});

test('setup encrypted', function (t) {
    vasync.parallel({
        funcs: [
            copyAsset.bind(this, 'id_rsa2', path.join('.ssh', 'id_rsa2')),
            copyAsset.bind(this, 'id_rsa2.pub', path.join('.ssh', 'id_rsa2.pub'))
        ]
    }, function (err, res) {
        t.error(err);
        t.end();
    });
});

test('keyring unlock', function (t) {
    var kr = new auth.KeyRing({ plugins: ['homedir'] });
    var fp = sshpk.parseFingerprint(ID_RSA2_FP);
    kr.findSigningKeyPair(fp, function (err, kp) {
        t.error(err);
        t.ok(kp.isLocked());
        kp.unlock('asdfasdf');
        t.ok(!kp.isLocked());
        t.ok(fp.matches(kp.getPrivateKey()));
        t.end();
    });
});

test('file plugin', function (t) {
    var kr = new auth.KeyRing({ plugins: [] });
    var fp = sshpk.parseFingerprint(ID_DSA_FP);
    kr.addPlugin('file', { keyPath: path.join(testDir, 'id_dsa') });
    kr.findSigningKeyPair(fp, function (err, kp) {
        t.error(err);
        t.ok(kp.canSign());
        t.ok(!kp.isLocked());
        t.end();
    });
});

test('loadSSHKey enc-private full pair', function (t) {
    auth.loadSSHKey(ID_RSA2_FP, function (err) {
        t.ok(err);
        t.notStrictEqual(err.toString().indexOf('encrypted'), -1);
        t.end();
    });
});

test('loadSSHKey enc-private private only', function (t) {
    fs.unlinkSync(path.join(tmpDir, '.ssh', 'id_rsa2.pub'));
    auth.loadSSHKey(ID_RSA2_FP, function (err) {
        t.ok(err);
        t.end();
    });
});

test('loadSSHKey enc-private other key', function (t) {
    auth.loadSSHKey(ID_RSA_FP, function (err, key) {
        t.error(err);
        t.end();
    });
})

test('teardown', function (t) {
    temp.cleanup(function () {
        t.end();
    });
});
