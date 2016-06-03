# Joyent Authentication Library

Utility functions to sign http requests to Joyent Triton and Manta services.
This library is meant to be used internally by other libraries and tools as in
the [`triton`](https://github.com/joyent/node-triton) and
[Manta](https://github.com/joyent/node-manta) repositories.

If you only want to use one of these libraries to make requests to a Joyent
service, you should not need to use this library directly at all.

Its API can be used independently, though, to search for and list the available
SSH keys on the system (used by `triton profile create`, for example):

```js
var mod_sdcauth = require('smartdc-auth');

var keyRing = new mod_sdcauth.KeyRing();
keyRing.list(function (err, keyMap) {
    if (err) {
        /* ... handle err ... */
        return;
    }
    /* The keyMap is an object that maps keyId => [keyPair] */
    var keyIds = Object.keys(keyMap);
    keyIds.forEach(function (keyId) {
        var keys = keyMap[keyId];
        console.log('%s:', keyId);
        keys.forEach(function (keyPair) {
            var key = keyPair.getPublicKey();
            console.log('  %s (%d bit): %s',
              key.type, key.size, key.comment);
            if (keyPair.isLocked())
                console.log('    !! password protected');
        });
    });
});
```

This might produce the output:

```
05:6c:c8:0c:83:6c:1e:9a:81:26:fb:52:8e:03:3c:33:
  ecdsa (256 bit): foobar@my-mbp.local
    !! password protected
2c:be:e8:b1:32:02:31:cd:10:89:f9:96:95:db:11:0c:
  rsa (2048 bit): foobar@my-mbp.local
81:ad:d5:57:e5:6f:7d:a2:93:79:56:af:d7:c0:38:51:
  ecdsa (256 bit): foobar@my-mbp.local
```

It can also be used to implement your own `http-signature` HTTPS client that
uses the same logic that the `triton` and `manta` tools do to locate SSH keys:

```js
var mod_sdcauth = require('smartdc-auth');
var mod_sshpk = require('sshpk');
var mod_https = require('https');

var fp = mod_sshpk.parseFingerprint(process.env.TRITON_KEY_ID);

var keyRing = new mod_sdcauth.KeyRing();
keyRing.findSigningKeyPair(fp, function (err, keyPair) {
    var signer = keyPair.createRequestSigner({
        user: process.env.TRITON_ACCOUNT
    });
    var opts = {
        host: 'localhost',
        port: 8443, path: '/', method: 'GET',
        headers: {}
    };
    signer.writeTarget(opts.method, opts.path);
    opts.headers.date = signer.writeDateHeader();
    signer.sign(function (err, authz) {
        opts.headers.authorization = authz;
        var req = https.request(opts);
        /* ... */
        req.end();
    });
});
```

## Overview

Authentication to Triton CloudAPI and Manta is built on top of Joyent's
[http-signature](https://github.com/joyent/node-http-signature) specification.
All requests to the APIs require an HTTP Authorization header where the scheme is
`Signature`.  Full details are available in the `http-signature` specification,
but a simple form is:

    Authorization: Signature keyId="/:login/keys/:md5_fingerprint",algorithm="rsa-sha256" $base64_signature

The `keyId` field varies in structure when making requests with RBAC subusers,
particularly when doing so in requests made to Manta. In the API reference
below, the term `keyId` generally refers specifically to the MD5 fingerprint of
the key in hex format, as used in the field.

Note that this MD5 fingerprint is used only to choose the existing full key on
file at the server end out of the ones for the given user and is not used for
authentication itself (so the weak hash is not a serious problem).

This library handles the complete process of finding SSH keys based on user
preferences or input, all the way to generating the contents of the
`Authorization` header ready for you to use.

The general idea is to create a `KeyRing`, then search it for the particular key
pair you want to use. Then you can call methods on the `KeyPair` instance like
`createRequestSigner()` to sign an HTTP request. You can also access metadata
about the key pair.

## API: KeyRing

### `new mod_sdcauth.KeyRing([options])`

Create a new SDC keyring. KeyRing instances use a list of plugins in order to
locate keys on the local system - via the filesystem, via the SSH agent, or any
other mechanism.

Parameters

- `options`: an Object containing properties:
  - `plugins`: an Array of Strings, names of plugins to enable

Any additional keys set in the `options` object will be passed through to
plugins as options for their processing.

Available plugins:
- `agent`: Gets keys from the OpenSSH agent. Options:
  - `sshAgentOpts`: an Object, options to be passed to `mod_sshpk_agent.Client`
- `homedir`: Gets keys from a directory on the filesystem. Options:
  - `keyDir`: a String, path to look in for keys, defaults to `$HOME/.ssh`
- `file`: Gets a key from a particular path on disk. Options:
  - `keyPath`: a String, path to the private key file

### `KeyRing#addPlugin(pluginName[, options])`

Adds a plugin to the KeyRing after construction. This is particularly useful
with the `file` plugin.

Parameters

- `pluginName`: a String, name of the plugin to load. One of `agent`, `homedir`
                or `file`
- `options`: an optional Object, options to pass to the plugin. See the
             documentation above for the class constructor for details.

### `KeyRing#list(cb)`

Lists all available keys in all plugins, organised by their Key ID.

Parameters

- `cb`: a Function `(err, keyPairs)` with parameters:
  - `err`: an Error or `null`
  - `keyPairs`: an Object, keys: String key IDs, values: Array of instances of
    `KeyPair`

### `KeyRing#find(fingerprint, cb)`

Searches active plugins for an SSH key matching the given fingerprint. Calls
`cb` with an array of `KeyPair` instances that match, ordered arbitrarily.

Parameters:
 - `fingerprint`: an `sshpk.Fingerprint`
 - `cb`: a Function `(err, keyPairs)`, with parameters:
   - `err`: an Error or `null`
   - `keyPairs`: an Array of `KeyPair` instances

### `KeyRing#findSigningKeyPair(fingerprint, cb)`

Searches active plugins for an SSH key matching the given fingerprint. Chooses
the best available signing key of those available (preferably unlocked) and
calls `cb` with this single `KeyPair` instance.

Parameters:
 - `fingerprint`: an `sshpk.Fingerprint`
 - `cb`: a Function `(err, keyPair)`, with parameters:
   - `err`: an Error or `null`
   - `keyPair`: a `KeyPair` instance

## KeyPair

### `KeyPair.fromPrivateKey(privKey)`

Constructs a KeyPair unrelated to any keychain, based directly on a given
private key. This is mostly useful for compatibility purposes.

Parameters:
 - `privKey`: an `sshpk.PrivateKey`

### `KeyPair#plugin`

String, name of the plugin through which this KeyPair was found.

### `KeyPair#source`

String (may be `undefined`), human-readable name of the source that the KeyPair
came from when discovered (e.g. for a plugin that searches the filesystem, this
could be the path to the key file).

### `KeyPair#comment`

String, comment that was stored with the key, if any.

### `KeyPair#canSign()`

Returns Boolean `true` if this key pair is complete (has a private and public
key) and can be used for signing. Note that this returns `true` for locked
keys.

### `KeyPair#isLocked()`

Returns Boolean `true` if this key pair is locked and may be unlocked using
the `unlock()` method.

### `KeyPair#unlock(passphrase)`

Unlocks an encrypted key pair, allowing it to be used for signing and the
`getPrivateKey()` method to be called.

Parameters:
 - `passphrase`: a String, passphrase for decryption

### `KeyPair#getKeyId()`

Returns the String key ID for this key pair. This is specifically the key ID
as used in HTTP signature auth for SDC and Manta. Currently this is a
hex-format MD5 fingerprint of the key, but this may change in future.

### `KeyPair#getPublicKey()`

Returns the `sshpk.Key` object representing this pair's public key.

### `KeyPair#getPrivateKey()`

Returns the `sshpk.PrivateKey` object representing this pair's private key. If
unavailable, this method will throw an `Error`.

### `KeyPair#createRequestSigner(options)`

Creates an `http-signature` `RequestSigner` object for signing an HTTP request
using this key pair's private key.

Parameters:
 - `options`, an Object with keys:
   - `user`, a String, the Triton or Manta account to authenticate as. Note that
                       this field is named `user` even though it normally refers
                       to an *account*, for historical reasons.
   - `subuser`, an optional String, subuser of the account to authenticate as
   - `mantaSubUser`, an optional Boolean, if `true` use Manta-style subuser
                     syntax

### `KeyPair#createSign(options)`

Creates a `sign()` function (matching the legacy `smartdc-auth` API) for
signing arbitrary data with this key pair's private key.

Parameters:
 - `options`, an Object with keys:
   - `user`, a String, the Triton or Manta account to authenticate as. Note that
                       this field is named `user` even though it normally refers
                       to an *account*, for historical reasons.
   - `subuser`, an optional String, subuser of the account to authenticate as
   - `mantaSubUser`, an optional Boolean, if `true` use Manta-style subuser
                     syntax
   - `algorithm`, an optional String, the signing algorithm to use

## Legacy request signers

Older SDC and Manta client libraries expose a bit more of the innards of key
location and management, and require direct use of this library.

The legacy signer function API is provided for compatibility with users of these
older client libraries. Note that you don't need to use this API for new
software that still wants to be able to use an older client library (you can
just use the `createSign()` method on a `KeyPair`, above).

These functions take options and return a "signer function" which is provided as
the `sign` parameter to other libraries.

### `privateKeySigner(options);`

A basic signer which signs using a given PEM (PKCS#1) format private key only.
Ideal for simple use cases where the key is stored in a file on the filesystem
ready for use.

- `options`: an Object containing properties:
  - `key`: a String, PEM-format (PKCS#1) private key, for any supported algorithm
  - `user`: a String, SDC login name to be used in the full keyId, above
  - `subuser`: an optional String, SDC subuser login name
  - `keyId`: optional String, the fingerprint of the `key` (not the same as the
             full keyId given to the server). Ignored unless it does not match
             the given `key`, then an Error will be thrown.

### `sshAgentSigner(options);`

Signs requests using a key that is stored in the OpenSSH agent. Opens and manages
a connection to the current session's agent during operation.

- `options`: an Object containing properties:
  - `keyId`: a String, fingerprint of the key to retrieve from the agent
  - `user`: a String, SDC login name to be used
  - `subuser`: an optional String, SDC subuser login name
  - `sshAgentOpts`: an optional Object, any additional options to pass through
                    to the SSHAgent constructor (eg `timeout`)

### `cliSigner(options);`

Signs requests using a key located either in the OpenSSH agent, or found in
the filesystem under `$HOME/.ssh` (or its equivalent on your platform).

This is generally intended for use with CLI utilities (eg the `sdc-listmachines`
tool and family), hence the name.

- `options`: an Object containing properties:
  - `keyId`: a String, fingerprint of the key to retrieve or find
  - `user`: a String, SDC login name to be used
  - `subuser`: an optional String, SDC subuser login name
  - `sshAgentOpts`: an optional Object, any additional options to pass through
                    to the SSHAgent constructor (eg `timeout`)
  - `algorithm`: DEPRECATED, an optional String, the signing algorithm to use.
                 If this does not match up with the algorithm of the key (once
                 it is located), an Error will be thrown.

(The `algorithm` option is deprecated as its backwards-compatible behaviour is
to apply only to keys that were found on disk, not in the SSH agent. If you have
a compelling use case for a replacement for this option in future, please open
an issue on this repo).

The `keyId` fingerprint does not necessarily need to be the exact format
(hex MD5) as sent to the server -- it can be in any fingerprint format supported
by the [`sshpk`](https://github.com/arekinath/node-sshpk) library.

As of version 2.0.0, an invalid fingerprint (one that can never match any key,
because, for example, it contains invalid characters) will produce an exception
immediately rather than returning a `sign` function.

Note that the `cliSigner` and `sshAgentSigner` are not suitable for server
applications, or any other system where the performance degradation necessary
to interact with SSH is not acceptable; put another way, you should only use
it for interactive tooling, such as the CLI that ships with node-smartdc.

## License

MIT.

## Bugs

See <https://github.com/joyent/node-smartdc-auth/issues>.
