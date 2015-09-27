// Copyright (c) 2015, Joyent, Inc. All rights reserved.

var crypto = require('crypto');
var EventEmitter = require('events').EventEmitter;
var fs = require('fs');
var path = require('path');
var util = require('util');

var assert = require('assert-plus');
var clone = require('clone');
var SSHAgentClient = require('sshpk-agent').Client;
var once = require('once');
var vasync = require('vasync');
var sshpk = require('sshpk');

function KeyNotFoundError(fp, srcs) {
    assert.string(fp, 'fingerprint');
    assert.arrayOfString(srcs, 'sources');
    if (Error.captureStackTrace)
        Error.captureStackTrace(this, KeyNotFoundError);
    this.name = 'KeyNotFoundError';
    this.fingerprint = fp;
    this.sources = srcs;
    this.message = 'SSH key with fingerprint "' + fp + '" could not be ' +
        'located in ' + srcs.join(' or ');
}
util.inherits(KeyNotFoundError, Error);
KeyNotFoundError.join = function (errs) {
    assert.arrayOfObject(errs, 'errors');
    var fp = errs[0].fingerprint;
    var srcs = errs[0].sources;
    for (var i = 1; i < errs.length; ++i) {
        assert.ok(errs[i] instanceof KeyNotFoundError);
        assert.strictEqual(errs[i].fingerprint, fp);
        srcs = srcs.concat(errs[i].sources);
    }
    return (new KeyNotFoundError(fp, srcs));
};

function SignatureCache(opts) {
    assert.optionalObject(opts, 'options');
    opts = opts || {};
    assert.optionalNumber(opts.expiry, 'options.expiry');

    this.expiry = opts.expiry || 10000;
    this.pending = new EventEmitter();
    this.pending.table = {};
    this.table = {};
    this.list = [];
}

SignatureCache.prototype.get = function get(k, cb) {
    assert.string(k, 'key');
    assert.func(cb, 'callback');

    cb = once(cb);

    var found = false;
    var self = this;

    function cachedResponse() {
        var val = self.table[k].value;
        cb(val.err, val.value);
    }

    if (this.table[k]) {
        found = true;
        process.nextTick(cachedResponse);
    } else if (this.pending.table[k]) {
        found = true;
        this.pending.once(k, cachedResponse);
    }

    return (found);
};


SignatureCache.prototype.put = function put(k, v) {
    assert.string(k, 'key');
    assert.ok(v, 'value');

    this.table[k] = {
        time: new Date().getTime(),
        value: v
    };

    if (this.pending.table[k])
        delete this.pending.table[k];

    this.pending.emit(k, v);
    this.purge();
};


SignatureCache.prototype.purge = function purge() {
    var list = [];
    var now = new Date().getTime();
    var self = this;

    Object.keys(this.table).forEach(function (k) {
        if (self.table[k].time + self.expiry < now)
            list.push(k);
    });

    list.forEach(function (k) {
        if (self.table[k])
            delete self.table[k];
    });
};


SignatureCache.prototype.toString = function toString() {
    var fmt = '[object SignatureCache<pending=%j, table=%j>]';
    return (util.format(fmt, this.pending.table, this.table));
};


function createCacheKey(opts) {
    assert.object(opts, 'options');
    assert.object(opts.key, 'options.key');
    assert.string(opts.data, 'options.data');

    return (opts.key.comment + '|' + opts.data);
}

function canonicalKeyId(key) {
    assert.object(key, 'key');
    return (key.fingerprint('md5').toString('hex'));
}

function loadSSHKey(fp, cb) {
    if (typeof (fp) === 'string')
        fp = sshpk.parseFingerprint(fp);
    assert.object(fp, 'fingerprint');
    assert.ok(fp instanceof sshpk.Fingerprint,
        'fingerprint instanceof sshpk.Fingerprint');
    assert.func(cb, 'callback');

    cb = once(cb);

    var p;

    if (process.platform === 'win32') {
        p = process.env.USERPROFILE;
    } else {
        p = process.env.HOME;
    }

    if (!p) {
        cb(new Error('cannot find HOME dir (HOME/USERPROFILE is not set)'));
        return;
    }

    p = path.join(p, '.ssh');

    fs.readdir(p, function (err, files) {
        if (err) {
            cb(err);
            return;
        }

        var keyFiles = [];
        (files || []).forEach(function (f) {
            /* If we have a .pub file and a matching private key */
            var m = f.match(/(.+)\.pub$/);
            if (m && files.indexOf(m[1]) !== -1) {
                keyFiles.push({public: f, private: m[1]});
                return;
            }
            /*
             * If the name contains id_ (but doesn't end with .pub) and there
             * is no matching public key
             */
            var m2 = f.match(/(^|[^a-zA-Z])id_/);
            if (!m && m2 && files.indexOf(f + '.pub') === -1) {
                keyFiles.push({private: f});
                return;
            }
        });

        /*
         * When we have both a public and private key file, read in the
         * .pub file first to do the fingerprint match. If that succeeds,
         * read in and validate that the private key file matches it.
         *
         * This also ensures we fail early and give a sensible error if,
         * e.g. the specified key is password-protected.
         */
        function readPublicKey(keyFile, kcb) {
            var fname = path.join(p, keyFile.public);
            fs.readFile(fname, 'ascii', function (kerr, blob) {
                if (kerr) {
                    kcb(kerr);
                    return;
                }

                try {
                    var key = sshpk.parseKey(blob, 'ssh', fname);
                } catch (e) {
                    kcb(e);
                    return;
                }

                if (fp.matches(key)) {
                    /*
                     * At this point, readPrivateKey has to succeed. If it
                     * doesn't, its error should go all the way to the user
                     * rather than a KeyNotFoundError (we did find the key,
                     * but something is wrong with it)
                     */
                    readPrivateKey(keyFile, function (pkerr, pk) {
                        cb(pkerr, pk);
                        kcb(null, pk);
                    });
                } else {
                    kcb(new KeyNotFoundError(fp.toString(), [fname]));
                }
            });
        }

        function readPrivateKey(keyFile, kcb) {
            var fname = path.join(p, keyFile.private);
            fs.readFile(fname, 'ascii', function (kerr, blob) {
                if (kerr) {
                    kcb(kerr);
                    return;
                }

                try {
                    var key = sshpk.parsePrivateKey(blob, 'pem', fname);
                } catch (e) {
                    kcb(e);
                    return;
                }

                /*
                 * NOTE: we call cb() here (which has been once()'d above)
                 * directly if we find a match. The actual forEachParallel cb
                 * only calls cb() in case nothing succeeds.
                 */
                if (fp.matches(key)) {
                    cb(null, key);
                    kcb(null, key);
                } else {
                    kcb(new KeyNotFoundError(fp.toString(), [fname]));
                }
            });
        }

        function processKey(keyFile, kcb) {
            /*
             * Stat the file first to ensure we don't read from any sockets
             * or crazy huge files that ended up in $HOME/.ssh (it happens)
             */
            var fname;
            if (keyFile.public) {
                fname = path.join(p, keyFile.public);
                fs.stat(fname, function (serr, stats) {
                    if (serr) {
                        kcb(serr);
                        return;
                    }
                    if (stats.isFile() && stats.size < 65536) {
                        readPublicKey(keyFile, kcb);
                    } else {
                        kcb(new Error(fname + ' is not a regular file, or ' +
                            'size is too big to be an SSH public key.'));
                    }
                });
            } else {
                fname = path.join(p, keyFile.private);
                fs.stat(fname, function (serr, stats) {
                    if (serr) {
                        kcb(serr);
                        return;
                    }
                    if (stats.isFile() && stats.size < 131072) {
                        readPrivateKey(keyFile, kcb);
                    } else {
                        kcb(new Error(fname + ' is not a regular file, or ' +
                            'size is too big to be an SSH private key.'));
                    }
                });
            }
        }

        var opts = {
            inputs: keyFiles,
            func: processKey
        };
        vasync.forEachParallel(opts, function (errs, res) {
            /* Only handle the not found case, see above. */
            if (res.successes.length === 0) {
                var msg = 'dir ' + p;
                if (errs) {
                    var fatals = [];
                    res.operations.forEach(function (op) {
                        if (op.err && !(op.err instanceof KeyNotFoundError))
                            fatals.push(op.err.name + ': ' +
                                op.err.message);
                    });
                    if (fatals.length > 0)
                        msg += ' [warnings: ' + fatals.join(' ; ') + ']';
                }
                cb(new KeyNotFoundError(fp.toString(), [msg]));
                return;
            }
        });
    });
}


function rfc3986(str) {
    return (encodeURIComponent(str)
            .replace(/[!'()]/g, escape)
            /* JSSTYLED */
            .replace(/\*/g, '%2A'));
}


function sshAgentGetKey(client, fp, cb) {
    assert.object(client, 'sshAgentClient');
    if (typeof (fp) === 'string')
        fp = sshpk.parseFingerprint(fp);
    assert.object(fp, 'fingerprint');
    assert.ok(fp instanceof sshpk.Fingerprint,
        'fingerprint instanceof sshpk.Fingerprint');
    assert.func(cb, 'callback');

    var cache = client._signCache;
    var _key = 'requestIdentities ' + fp.toString();
    if (cache.get(_key, cb))
        return;

    client.listKeys(function (err, keys) {
        var _val = {
            err: null,
            value: null
        };

        if (err) {
            _val.err = err;
        } else {
            var key;
            for (var i = 0; i < keys.length; ++i) {
                if (fp.matches(keys[i])) {
                    key = keys[i];
                    break;
                }
            }

            if (!key) {
                _val.err = new KeyNotFoundError(fp.toString(), ['ssh-agent (' +
                    keys.length + ' keys)']);
            } else {
                _val.value = key;
            }
        }

        cache.put(_key, _val);
        cb(_val.err, _val.value);
    });
}

function createSSHAgent(agentOpts) {
    assert.optionalObject(agentOpts, 'agentOpts');

    /*
     * Return an error rather than throwing, so if our caller wants to ignore
     * an issue with agent setup (eg no socket to connect to), they can do that
     * without also ignoring a programmer error in SignatureCache (like a
     * failed assertion).
     */
    try {
        var agent = new SSHAgentClient(agentOpts);
    } catch (e) {
        assert.ok(e instanceof Error);
        return (e);
    }

    agent._signCache = new SignatureCache();
    return (agent);
}

function sshAgentSign(client, key, data, cb) {
    assert.object(client, 'sshAgentClient');
    assert.object(client._signCache, 'sshAgentClient');
    assert.object(key, 'key');
    assert.buffer(data, 'data');
    assert.func(cb, 'callback');

    var cache = client._signCache;

    var _key = createCacheKey({
        key: key,
        data: data.toString()
    });

    if (cache.get(_key, cb))
        return;

    client.sign(key, data, function (err, sig) {
        var _val = {};

        if (err) {
            _val.err = err;
            cb(err);
        } else {
            _val.err = null;

            _val.value = {
                algorithm: key.type + '-' + sig.hashAlgorithm,
                signature: sig.toString('asn1')
            };

            cb(null, _val.value);
        }

        cache.put(_key, _val);
    });
}

function defaultSignAlgorithm(key) {
    switch (key.type) {
    case 'rsa':
        return ('RSA-SHA256');
    case 'dsa':
        return ('DSA-SHA1');
    case 'ecdsa':
        /* NOTE: lowercase, because node-crypto is speshul */
        return ('ecdsa-SHA1');
    default:
        throw (new Error('Unsupported key type: ' + key.type));
    }
}

// ---- API

function privateKeySigner(options) {
    assert.object(options, 'options');
    assert.optionalString(options.algorithm, 'options.algorithm');
    assert.optionalString(options.keyId, 'options.keyId');
    assert.string(options.key, 'options.key');
    assert.string(options.user, 'options.user');
    assert.optionalString(options.subuser, 'options.subuser');

    var key = sshpk.parseKey(options.key, 'pem');
    if (options.keyId) {
        var fp = sshpk.parseFingerprint(options.keyId);
        assert.ok(fp.matches(key), 'keyId does not match the given key');
    }
    var keyId = canonicalKeyId(key);

    var algorithm = options.algorithm;

    if (algorithm === undefined)
        algorithm = defaultSignAlgorithm(key);
    else
        algorithm = algorithm.toUpperCase();

    var opts = clone(options);

    function sign(str, cb) {
        assert.string(str, 'str');
        assert.func(cb, 'callback');

        var signer = crypto.createSign(algorithm.
            replace(/^ecdsa/, 'ecdsa-with'));
        signer.update(str);
        var res = {
            algorithm: sign.algorithm.toLowerCase(),
            keyId: keyId,
            signature: signer.sign(opts.key, 'base64'),
            user: opts.user,
            subuser: opts.subuser
        };

        cb(null, res);
    }

    sign.algorithm = algorithm.toLowerCase();
    sign.keyId = keyId;
    sign.user = options.user;
    sign.subuser = options.subuser;
    sign.getKey = function (cb) {
        cb(null, key);
    };

    return (sign);
}


function sshAgentSigner(options) {
    assert.object(options, 'options');
    assert.string(options.keyId, 'options.keyId');
    assert.string(options.user, 'options.user');
    assert.optionalObject(options.sshAgentOpts, 'options.sshAgentOpts');
    assert.optionalString(options.subuser, 'options.subuser');

    var agentOrErr = createSSHAgent(options.sshAgentOpts);
    /* An agent signer is useless without an agent, so throw */
    if (agentOrErr instanceof Error)
        throw (agentOrErr);

    var agent = agentOrErr;

    var fp = sshpk.parseFingerprint(options.keyId);

    function sign(str, cb) {
        assert.string(str, 'string');
        assert.func(cb, 'callback');

        sshAgentGetKey(agent, fp, function (err, key) {
            if (err) {
                cb(err);
                return;
            }

            var data = new Buffer(str);
            sshAgentSign(agent, key, data, function (err2, res) {
                if (err2) {
                    cb(err2);
                } else {
                    res.keyId = canonicalKeyId(key);
                    res.user = options.user;
                    res.subuser = options.subuser;
                    sign.algorithm = res.algorithm;
                    sign.keyId = res.keyId;
                    cb(null, res);
                }
            });
        });
    }

    sign.keyId = options.keyId;
    sign.user = options.user;
    sign.subuser = options.subuser;
    sign.getKey = function (cb) {
        sshAgentGetKey(agent, fp, function (err, key) {
            if (key)
                sign.algorithm = key.type + '-sha1';
            cb(err, key);
        });
    };

    return (sign);
}


function cliSigner(options) {
    assert.object(options, 'options');

    assert.string(options.keyId, 'options.keyId');
    assert.string(options.user, 'options.user');
    assert.optionalString(options.subuser, 'options.subuser');
    assert.optionalString(options.algorithm, 'options.algorithm');
    assert.optionalObject(options.sshAgentOpts, 'options.sshAgentOpts');

    var alg = options.algorithm;
    var algParts = alg ? alg.toLowerCase().split('-') : [];

    var initOpts = new EventEmitter();
    initOpts.setMaxListeners(Infinity);
    var fp = sshpk.parseFingerprint(options.keyId);
    var user = options.user;

    var agentOrErr = createSSHAgent(options.sshAgentOpts);
    /* It's ok if we got an error, we can look at files instead */
    if (!(agentOrErr instanceof Error))
        initOpts.agent = agentOrErr;

    // This pipeline is to perform setup ahead of time; we don't want to
    // recheck the agent, or reload private keys, etc., if we're in a nested
    // case, like mfind. We use 'initOpts' as a node hack, where we tack
    // what we need on it, but use it as an "lock" if this function is
    // invoked _before_ the setup work is done.
    vasync.pipeline({
        funcs: [
            function checkAgentForKey(opts, cb) {
                if (!opts.agent) {
                    cb();
                    return;
                }

                var a = opts.agent;
                sshAgentGetKey(a, fp, function (err, key) {
                    if (err && err instanceof KeyNotFoundError)
                        opts.agentErr = err;

                    if (!err) {
                        opts.key = key;
                        opts.alg = opts.algorithm = key.type + '-sha1';
                    }

                    cb();
                });

            },

            function loadKey(opts, cb) {
                if (opts.key) {
                    cb();
                    return;
                }

                loadSSHKey(fp, function (err, key) {
                    if (err && err instanceof KeyNotFoundError && opts.agentErr)
                        err = KeyNotFoundError.join([opts.agentErr, err]);

                    if (err) {
                        cb(err);
                        return;
                    }

                    if (alg) {
                        var wantAlg = alg.split('-')[0].toLowerCase();
                        if (wantAlg !== key.type) {
                            cb(new Error(wantAlg + ' signing requested; ' +
                                key.type + ' key loaded'));
                            return;
                        }
                    }

                    if (!alg)
                        alg = defaultSignAlgorithm(key);
                    opts.alg = opts.algorithm = alg;
                    opts.key = key;
                    cb();
                });
            }
        ],
        arg: initOpts
    }, function (err) {
        if (err) {
            initOpts.error = err;
            initOpts.emit('error', err);
            return;
        }

        sign.algorithm = initOpts.alg.toLowerCase();

        initOpts.ready = true;
        initOpts.emit('ready');
    });

    function waitForReady(opts, cb) {
        cb = once(cb);

        if (initOpts.ready) {
            cb();
            return;
        } else if (initOpts.error) {
            cb(initOpts.error);
            return;
        }

        initOpts.once('ready', cb);
        initOpts.once('error', cb);
    }

    function sign(str, callback) {
        assert.string(str, 'string');
        assert.func(callback, 'callback');

        callback = once(callback);

        var arg = {};
        vasync.pipeline({
            funcs: [
                waitForReady,

                function agentSign(opts, cb) {
                    if (!initOpts.agent || !initOpts.key ||
                        initOpts.key instanceof sshpk.PrivateKey)
                    {
                        cb();
                        return;
                    }

                    var a = initOpts.agent;
                    var d = new Buffer(str);
                    var k = initOpts.key;
                    sshAgentSign(a, k, d, function (e, s) {
                        if (e) {
                            cb(e);
                            return;
                        }

                        s.keyId = canonicalKeyId(k);
                        s.user = options.user;
                        s.subuser = options.subuser;
                        opts.res = s;
                        cb();
                    });
                },

                function signWithPrivateKey(opts, cb) {
                    if (opts.res) {
                        cb();
                        return;
                    }


                    var k = initOpts.key;
                    if (algParts[0] && algParts[0] !== k.type) {
                        cb(new Error('Requested algorithm ' + alg + ' is ' +
                            'not supported with a key of type ' + k.type));
                        return;
                    }
                    var s = k.createSign(algParts[1]);
                    s.update(str);
                    var sig = s.sign();
                    opts.res = {
                        algorithm: k.type + '-' + sig.hashAlgorithm,
                        keyId: canonicalKeyId(k),
                        signature: sig.toString(),
                        user: user,
                        subuser: options.subuser
                    };

                    cb();
                }
            ],
            arg: arg
        }, function (err) {
            if (err) {
                callback(err);
            } else {
                sign.algorithm = arg.res.algorithm.toLowerCase();
                sign.keyId = arg.res.keyId;
                sign.user = user;
                sign.subuser = options.subuser;
                callback(null, arg.res);
            }
        });
    }

    function getKey(cb) {
        waitForReady({}, function (err) {
            if (err)
                return cb(err);
            return cb(null, initOpts.key);
        });
    }

    sign.getKey = getKey;

    return (sign);
}


/**
 * Creates a presigned URL.
 *
 * Invoke with a signing callback (like other client APIs) and the keys/et al
 * needed to actually form a valid presigned request.
 *
 * Parameters:
 * - host, keyId, user: see other client APIs
 * - sign: needs to have a .getKey() (all the provided signers in smartdc-auth
 *         are fine)
 * - path: path to the Manta object to sign
 * - query: optional HTTP query parameters to include on the URL
 * - expires: the expire time of the URL, in seconds since the Unix epoch
 * - manta: set to true if using sub-users with Manta
 */
function signUrl(opts, cb) {
    assert.object(opts, 'options');
    assert.optionalNumber(opts.expires, 'options.expires');
    assert.string(opts.host, 'options.host,');
    assert.string(opts.keyId, 'options.keyId');
    assert.string(opts.user, 'options.user');
    assert.string(opts.path, 'options.path');
    assert.optionalObject(opts.query, 'options.query');
    assert.optionalArrayOfString(opts.role, 'options.role');
    assert.optionalArrayOfString(opts['role-tag'], 'options[\'role-tag\']');
    assert.optionalString(opts.subuser, 'opts.subuser');
    assert.func(opts.sign, 'options.sign');
    assert.func(opts.sign.getKey, 'options.sign.getKey');
    assert.func(cb, 'callback');
    assert.optionalBool(opts.manta, 'options.manta');

    if (opts.manta && opts.subuser !== undefined)
        opts.user = opts.user + '/' + opts.subuser;
    else if (opts.subuser !== undefined)
        opts.user = opts.user + '/user/' + opts.subuser;

    if (opts.method !== undefined) {
        if (Array.isArray(opts.method)) {
            assert.ok(opts.method.length >= 1);
            opts.method.forEach(function (m) {
                assert.string(m, 'options.method');
            });
        } else {
            assert.string(opts.method, 'options.method');
            opts.method = [opts.method];
        }
    } else {
        opts.method = ['GET', 'HEAD'];
    }
    opts.method.sort();
    var method = opts.method.join(',');

    var q = clone(opts.query || {});
    q.expires = (opts.expires ||
                 Math.floor(((Date.now() + (1000 * 300))/1000)));

    if (opts.role)
        q.role = opts.role.join(',');

    if (opts['role-tag'])
        q['role-tag'] = opts['role-tag'].join(',');

    if (opts.method.length > 1)
        q.method = method;

    opts.sign.getKey(function (err, key) {
        if (err) {
            cb(err);
            return;
        }

        var fp = canonicalKeyId(key);
        q.keyId = '/' + opts.user + '/keys/' + fp;
        q.algorithm = (opts.algorithm || opts.sign.algorithm).toUpperCase();

        var line =
            method + '\n' +
            opts.host + '\n' +
            opts.path + '\n';
        var str = Object.keys(q).sort(function (a, b) {
            return (a.localeCompare(b));
        }).map(function (k) {
            return (rfc3986(k) + '=' + rfc3986(q[k]));
        }).join('&');
        line += str;

        if (opts.log)
            opts.log.debug('signUrl: signing -->\n%s', line);

        opts.sign(line, function onSignature(serr, obj) {
            if (serr) {
                cb(serr);
            } else {
                var u = opts.path + '?' +
                    str +
                    '&signature=' + rfc3986(obj.signature);
                cb(null, u);
            }
        });
    });
}


// ---- Exports

module.exports = {
    cliSigner: cliSigner,
    privateKeySigner: privateKeySigner,
    sshAgentSigner: sshAgentSigner,
    loadSSHKey: loadSSHKey,
    signUrl: signUrl,
    KeyNotFoundError: KeyNotFoundError
};
