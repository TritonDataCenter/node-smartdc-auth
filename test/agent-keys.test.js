// Copyright 2015 Joyent, Inc.  All rights reserved.

var test = require('tape').test;

var Agent = require('./ssh-agent-ctl');
var sshpk = require('sshpk');
var vasync = require('vasync');
var path = require('path');
var fs = require('fs');
var crypto = require('crypto');
var auth = require('../lib/index');
var temp = require('temp');
var spawn = require('child_process').spawn;

var ID_RSA_FP = 'SHA256:29GY+6bxcBkcNNUzTnEcTdTv1W3d3PN/OxyplcYSoX4';
var ID_RSA_MD5 = 'fa:56:a1:6b:cc:04:97:fe:e2:98:54:c4:2e:0d:26:c6';
var ID_DSA_FP = 'SHA256:WI2QyT/UuJ4LaPylGynx244f6k+xqVHYOyxg1cfnL0I';
var ID_DSA_MD5 = 'a6:e6:68:d3:28:2b:0a:a0:12:54:da:c4:c0:22:8d:ba';
var ID_ECDSA_FP = 'SHA256:ezilZp/ZHJuMF8i9jyMGuxRdFCu4rzGYLQmfSOhrolE';
var ID_ECDSA_MD5 = '00:74:32:ae:0a:24:3c:7a:e7:07:b8:ee:91:c4:c7:27';

var SIG_RSA_SHA1 = 'parChQDdkj8wFY75IUW/W7KN9q5FFTPYfcAf+W7PmN8yxnRJB884NHYNT' +
    'hl/TjZB2s0vt+kkfX3nldi54heTKbDKFwCOoDmVWQ2oE2ZrJPPFiUHReUAIRvwD0V/q7' +
    '4c/DiRR6My7FEa8Szce27DBrjBmrMvMcmd7/jDbhaGusy4=';

/* automatically clean up temp dir at exit */
temp.track();

var agent;
var testDir = __dirname;
var tmpDir;

test('setup', function (t) {
    delete (process.env['SSH_AGENT_PID']);
    delete (process.env['SSH_AUTH_SOCK']);
    t.end();
});

test('agentsigner throws with no agent', function (t) {
    t.throws(function () {
        var sign = auth.sshAgentSigner({
            keyId: ID_RSA_FP,
            user: 'foo'
        });
    });
    t.end();
});

test('agent setup', function (t) {
    agent = new Agent();
    agent.on('open', function () {
        agent.importEnv();
        t.end();
    });
    agent.on('error', function (err) {
        console.log(err);
        agent = undefined;
        t.end();
    });
});

test('agentsigner with empty agent', function (t) {
    t.ok(agent);
    var sign = auth.sshAgentSigner({
        keyId: ID_RSA_FP,
        user: 'foo'
    });
    t.ok(sign);
    sign('foobar', function (err, sigData) {
        t.ok(err);
        t.ok(err instanceof auth.KeyNotFoundError);
        t.end();
    });
});

test('agentsigner rsa', function (t) {
    t.ok(agent);
    agent.addKey(path.join(testDir, 'id_rsa'), function (err) {
        t.error(err);

        var sign = auth.sshAgentSigner({
            keyId: ID_RSA_FP,
            user: 'foo'
        });
        t.ok(sign);
        sign('foobar', function (err, sigData) {
            t.error(err);
            t.strictEqual(sigData.keyId, ID_RSA_MD5);
            t.strictEqual(sigData.algorithm, 'rsa-sha1');
            t.strictEqual(sigData.user, 'foo');
            t.strictEqual(sigData.signature, SIG_RSA_SHA1);
            t.end();
        });
    });
});

test('agentsigner dsa', function (t) {
    t.ok(agent);
    agent.addKey(path.join(testDir, 'id_dsa'), function (err) {
        t.error(err);

        var sign = auth.sshAgentSigner({
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
            var keyData = fs.readFileSync(path.join(testDir, 'id_dsa.pem'));
            t.ok(v.verify(keyData, sigData.signature, 'base64'));

            t.end();
        });
    });
});

test('agentsigner ecdsa + buffer', function (t) {
    t.ok(agent);
    agent.addKey(path.join(testDir, 'id_ecdsa'), function (err) {
        t.error(err);

        var sign = auth.sshAgentSigner({
            keyId: ID_ECDSA_FP,
            user: 'foo'
        });
        t.ok(sign);
        var buf = crypto.randomBytes(32);
        sign(buf, function (err, sigData) {
            t.error(err);
            t.strictEqual(sigData.keyId, ID_ECDSA_MD5);
            t.strictEqual(sigData.algorithm, 'ecdsa-sha256');
            t.strictEqual(sigData.user, 'foo');

            var v = crypto.createVerify('sha256');
            v.update(buf);
            var keyData = fs.readFileSync(path.join(testDir, 'id_ecdsa.pem'));
            t.ok(v.verify(keyData, sigData.signature, 'base64'));

            t.end();
        });
    });
});

test('clisigner with only agent', function (t) {
    delete (process.env['HOME']);
    delete (process.env['USERPROFILE']);
    t.ok(agent);
    var sign = auth.cliSigner({
        keyId: ID_RSA_FP,
        user: 'foo'
    });
    t.ok(sign);
    sign('foobar', function (err, sigData) {
        t.error(err);
        t.strictEqual(sigData.keyId, ID_RSA_MD5);
        t.strictEqual(sigData.algorithm, 'rsa-sha1');
        t.strictEqual(sigData.user, 'foo');
        t.strictEqual(sigData.signature, SIG_RSA_SHA1);
        t.end();
    });
});

var bulkKeys = [];

test('generate 40 keys (for TOOLS-1214)', function (t) {
    t.ok(agent);
    temp.mkdir('smartdc-auth.agent-keys.test', function (err, tmp) {
        t.error(err);
        tmpDir = tmp;

        process.env['HOME'] = tmpDir;
        fs.mkdirSync(path.join(tmpDir, '.ssh'));

        var inputs = [];
        for (var i = 1; i <= 40; ++i)
            inputs.push(i);

        vasync.forEachParallel({
            func: genKey,
            inputs: inputs
        }, function (err) {
            t.error(err);
            t.end();
        });

        function genKey(n, cb) {
            var fn = path.join(tmpDir, 'id_rsa_' + n);
            var kid = spawn('ssh-keygen', [
                '-f', fn, '-t', 'rsa', '-N', '', '-b', '1024', '-q']);
            var errBuf = '';
            kid.stderr.on('data', function (chunk) {
                errBuf += chunk.toString();
            });
            kid.on('close', function(rc) {
                if (rc !== 0) {
                    cb(new Error('ssh-keygen failed: ' + errBuf.trim()));
                    return;
                }
                fs.readFile(fn + '.pub', function (err, data) {
                    if (err) {
                        cb(err);
                        return;
                    }

                    bulkKeys.push(sshpk.parseKey(data, 'ssh'));
                    agent.addKey(fn, cb);
                });
            });
        }
    });
});

test('cliSigner using agent with lots of keys (TOOLS-1214)', function (t) {
    t.ok(agent);
    var sign = auth.cliSigner({
        keyId: bulkKeys[2].fingerprint('sha256').toString(),
        user: 'foo'
    });
    t.ok(sign);
    sign('foobar', function (err, sigData) {
        t.error(err);
        t.strictEqual(sigData.keyId,
            bulkKeys[2].fingerprint('md5').toString('hex'));
        t.strictEqual(sigData.user, 'foo');
        t.strictEqual(sigData.algorithm, 'rsa-sha1');
        var v = bulkKeys[2].createVerify('sha1');
        v.update('foobar');
        t.ok(v.verify(sigData.signature, 'base64'));
        t.end();
    });
});

test('agent teardown', function (t) {
    t.ok(agent);
    agent.close(function () {
        temp.cleanup(function () {
            t.end();
        });
    });
});
