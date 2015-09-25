// Copyright 2015 Joyent, Inc.  All rights reserved.

var test = require('tape').test;

var temp = require('temp');
var fs = require('fs');
var path = require('path');
var sshpk = require('sshpk');
var vasync = require('vasync');
var auth = require('../lib/index');
var crypto = require('crypto');

/* automatically clean up temp dir at exit */
temp.track();

var testDir = __dirname;
var tmpDir;
var ID_RSA_FP = 'SHA256:29GY+6bxcBkcNNUzTnEcTdTv1W3d3PN/OxyplcYSoX4';
var ID_RSA_MD5 = 'fa:56:a1:6b:cc:04:97:fe:e2:98:54:c4:2e:0d:26:c6';
var ID_RSA2_FP = 'SHA256:FWEns/VvPZdbSPtoVDUlUpewdP/LgC/4+l/V42Oltpw';
var ID_DSA_FP = 'SHA256:WI2QyT/UuJ4LaPylGynx244f6k+xqVHYOyxg1cfnL0I';
var ID_DSA_MD5 = 'a6:e6:68:d3:28:2b:0a:a0:12:54:da:c4:c0:22:8d:ba';

var SIG_RSA_SHA256 = 'KX1okEE5wWjgrDYM35z9sO49WRk/DeZy7QeSNCFdOsn45BO6rVOIH5v' +
    'V7WD25/VWyGCiN86Pml/Eulhx3Xx4ZUEHHc18K0BAKU5CSu/jCRI0dEFt4q1bXCyM7aK' +
    'FlAXpk7CJIM0Gx91CJEXcZFuUddngoqljyt9hu4dpMhrjVFA=';

var SIG_RSA_SHA1 = 'parChQDdkj8wFY75IUW/W7KN9q5FFTPYfcAf+W7PmN8yxnRJB884NHYNT' +
    'hl/TjZB2s0vt+kkfX3nldi54heTKbDKFwCOoDmVWQ2oE2ZrJPPFiUHReUAIRvwD0V/q7' +
    '4c/DiRR6My7FEa8Szce27DBrjBmrMvMcmd7/jDbhaGusy4=';

function copyAsset(name, dst, cb) {
    var rd = fs.createReadStream(path.join(testDir, name));
    var wr = fs.createWriteStream(path.join(tmpDir, dst));
    wr.on('close', cb);
    rd.pipe(wr);
}

test('setup fs only', function (t) {
    temp.mkdir('smartdc-auth.signers.test', function (err, tmp) {
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
                    path.join('.ssh', 'id_dsa')),
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

test('basic cliSigner rsa', function (t) {
    var sign = auth.cliSigner({
        keyId: ID_RSA_FP,
        user: 'foo'
    });
    t.ok(sign);
    sign('foobar', function (err, sigData) {
        t.error(err);
        t.strictEqual(sigData.keyId, ID_RSA_MD5);
        t.strictEqual(sigData.user, 'foo');
        t.strictEqual(sigData.signature, SIG_RSA_SHA256);
        t.end();
    });
});

test('basic cliSigner dsa', function (t) {
    var sign = auth.cliSigner({
        keyId: ID_DSA_FP,
        user: 'foo'
    });
    t.ok(sign);
    sign('foobar', function (err, sigData) {
        t.error(err);
        t.strictEqual(sigData.keyId, ID_DSA_MD5);
        t.strictEqual(sigData.algorithm, 'dsa-sha1');
        t.strictEqual(sigData.user, 'foo');

        var v = crypto.createVerify('DSA-SHA1');
        v.update('foobar');
        var keyData = fs.readFileSync(path.join(testDir, 'id_dsa.pub'));
        var key = sshpk.parseKey(keyData, 'ssh');
        t.ok(v.verify(key.toBuffer('pem'), sigData.signature, 'base64'));

        t.end();
    });
});

test('basic cliSigner with algorithm and subuser', function (t) {
    var sign = auth.cliSigner({
        keyId: ID_RSA_MD5,
        user: 'foo',
        algorithm: 'RSA-SHA1',
        subuser: 'bar'
    });
    t.ok(sign);
    sign('foobar', function (err, sigData) {
        t.error(err);
        t.strictEqual(sigData.keyId, ID_RSA_MD5);
        t.strictEqual(sigData.user, 'foo');
        t.strictEqual(sigData.subuser, 'bar');
        t.strictEqual(sigData.signature, SIG_RSA_SHA1);
        t.end();
    });
});

test('cliSigner unknown fp', function (t) {
    var sign = auth.cliSigner({
        keyId: ID_RSA2_FP,
        user: 'foo'
    });
    t.ok(sign);
    sign('foobar', function (err, sigData) {
        t.ok(err);
        t.ok(err instanceof auth.KeyNotFoundError);
        t.end();
    });
});

test('cliSigner invalid fp', function (t) {
    t.throws(function () {
        var sign = auth.cliSigner({
            keyId: '!!!!',
            user: 'foo'
        });
    }, sshpk.FingerprintFormatError);
    t.throws(function () {
        var sign = auth.cliSigner({
            keyId: ID_RSA_MD5 + 'aaaaa',
            user: 'foo'
        });
    }, sshpk.FingerprintFormatError);
    t.end();
});

test('teardown', function (t) {
    temp.cleanup(function () {
        t.end();
    });
});
