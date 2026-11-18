/**
 * Vault encryption.
 *
 * Entries are "v": 2, ML-KEM-768 + X25519 (X-Wing, draft-connolly-cfrg-xwing-kem).
 *   Each service gets its own X-Wing key pair, derived on the OnlyKey from the
 *   label "vault:<service>". The private half never leaves the device.
 *   - Store: the page asks the OnlyKey for that service's public key (no
 *     press), encapsulates to it here, and turns the 32-byte shared secret
 *     into an AES-256-GCM key with HKDF-SHA256. The entry keeps the 1120-byte
 *     KEM ciphertext next to the AES-GCM ciphertext.
 *   - Read: the KEM ciphertext goes to the OnlyKey, which decapsulates it
 *     (both the ML-KEM and the X25519 halves) after you confirm on the device,
 *     and hands back the shared secret; the same HKDF gives the AES key.
 *   The AES key is non-extractable, and the service name is bound in as
 *   AES-GCM additional data, so a blob moved to another service fails.
 * *
 * Plain CommonJS with no bundler-only imports, so the test kit can require it
 * under Node. X-Wing encapsulation (age_pqc.js) is passed in by the caller.
 */
"use strict";

var LABEL_PREFIX = "vault:";
var XWING_CT = 1120;
var XWING_PK = 1216;

var enc = new TextEncoder();
var V2_SALT = enc.encode("onlykey-vault-v2");
var V2_INFO_PREFIX = "xwing-mlkem768-x25519|";
var V2_AAD_PREFIX = "onlykey-vault-v2|";

function labelFor(serviceId) {
    return LABEL_PREFIX + serviceId;
}

function toB64(bytes) {
    var s = "";
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s);
}

function fromB64(b64) {
    return Uint8Array.from(atob(b64), function(c) { return c.charCodeAt(0); });
}

function toBytes(secret) {
    if (secret instanceof Uint8Array) return secret;
    if (Array.isArray(secret)) return new Uint8Array(secret);
    var s = String(secret);
    if (/^[0-9a-fA-F]+$/.test(s) && s.length % 2 === 0) {
        var out = new Uint8Array(s.length / 2);
        for (var i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
        return out;
    }
    return enc.encode(s);
}

async function hkdfAesKey(ikm, salt, info) {
    var base = await crypto.subtle.importKey("raw", ikm, { name: "HKDF" }, false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
        { name: "HKDF", hash: "SHA-256", salt: salt, info: info },
        base,
        { name: "AES-GCM", length: 256 },
        false, // NON-EXTRACTABLE
        ["encrypt", "decrypt"]
    );
}

function v2Key(sharedSecret, serviceId) {
    return hkdfAesKey(sharedSecret, V2_SALT, enc.encode(V2_INFO_PREFIX + labelFor(serviceId)));
}

function aadFor(entry) {
    return enc.encode(V2_AAD_PREFIX + entry.serviceId);
}

async function seal(aesKey, plaintext, aad) {
    var nonce = crypto.getRandomValues(new Uint8Array(12));
    var params = { name: "AES-GCM", iv: nonce, additionalData: aad };
    var ct = new Uint8Array(await crypto.subtle.encrypt(params, aesKey, enc.encode(plaintext)));
    var out = new Uint8Array(12 + ct.length);
    out.set(nonce);
    out.set(ct, 12);
    return toB64(out);
}

async function open(aesKey, b64, aad) {
    var raw = fromB64(b64);
    if (raw.length < 28) throw new Error("Blob too short");
    var params = { name: "AES-GCM", iv: raw.slice(0, 12), additionalData: aad };
    var pt = await crypto.subtle.decrypt(params, aesKey, raw.slice(12));
    return new TextDecoder().decode(pt);
}

function callback(fn) {
    return new Promise(function(resolve, reject) {
        fn(function(err, value) {
            if (err) reject(new Error(String(err && err.message ? err.message : err)));
            else resolve(value);
        });
    });
}

/**
 * ok      - the onlykey3rd() api object (derive_xwing_recipient/_decap)
 * agePqc  - age_pqc.js (xwingEncapsHost)
 */
function create(ok, agePqc) {

    function recipient(serviceId) {
        return callback(function(cb) { ok.derive_xwing_recipient(labelFor(serviceId), cb); })
            .then(function(r) {
                r = toBytes(r);
                if (r.length !== XWING_PK) {
                    throw new Error("X-Wing public key must be " + XWING_PK + " bytes, got " + r.length);
                }
                return r;
            });
    }

    function decap(serviceId, kemCt) {
        return callback(function(cb) { ok.derive_xwing_decap(labelFor(serviceId), kemCt, cb); })
            .then(toBytes);
    }

    /** A fresh v2 key for a service: no press. Returns { kem, aesKey }. */
    async function newKey(serviceId) {
        var pk = await recipient(serviceId);
        var e = agePqc.xwingEncapsHost(pk);
        var ss = toBytes(e.sharedSecret);
        try {
            return { kem: toB64(toBytes(e.ciphertext)), aesKey: await v2Key(ss, serviceId) };
        } finally {
            ss.fill(0);
        }
    }

    /** The AES key for an existing entry: device confirmation required. */
    async function keyFor(entry) {
        if (entry.v !== 2) throw new Error("Unsupported vault entry version " + entry.v);
        var kemCt = fromB64(entry.kem);
        if (kemCt.length !== XWING_CT) {
            throw new Error("X-Wing ciphertext must be " + XWING_CT + " bytes, got " + kemCt.length);
        }
        var ss = await decap(entry.serviceId, kemCt);
        try { return await v2Key(ss, entry.serviceId); } finally { ss.fill(0); }
    }

    /** Encrypt a secret for a service under a key from newKey(). */
    async function sealEntry(serviceId, plaintext, key) {
        var entry = { v: 2, serviceId: serviceId, kem: key.kem };
        entry.encrypted = await seal(key.aesKey, plaintext, aadFor(entry));
        return entry;
    }

    function openEntry(entry, aesKey) {
        return open(aesKey, entry.encrypted, aadFor(entry));
    }

    return {
        newKey: newKey,
        keyFor: keyFor,
        sealEntry: sealEntry,
        openEntry: openEntry
    };
}

/** Tag a cached key with the entry it opens: each key is only good for one KEM ciphertext. */
function cacheTag(entry) {
    return entry.kem;
}

/** The text "Copy blob" puts on the clipboard. */
function blobOf(entry) {
    return JSON.stringify({ v: 2, serviceId: entry.serviceId, kem: entry.kem, encrypted: entry.encrypted });
}

/** Import check: an entry this page can open. */
function isValidEntry(entry) {
    if (!entry || typeof entry.serviceId !== "string" || !entry.serviceId || typeof entry.encrypted !== "string") {
        return false;
    }
    if (entry.v !== 2 || typeof entry.kem !== "string") return false;
    try { return fromB64(entry.kem).length === XWING_CT; } catch (e) { return false; }
}

module.exports = {
    create: create,
    cacheTag: cacheTag,
    blobOf: blobOf,
    isValidEntry: isValidEntry,
    labelFor: labelFor,
    XWING_CT: XWING_CT
};
