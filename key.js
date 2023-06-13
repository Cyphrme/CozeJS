"use strict";

import * as CTK from './cryptokey.js';
import * as Can from './canon.js';
import * as Coze from './coze.js';
import * as Alg from './alg.js';
import {
	isEmpty
} from './coze.js';

export {
	NewKey,
	Correct,
	Valid,
	Thumbprint,
	Revoke,
	IsRevoked,

	// RecalcX,

	TmbCanon,
}

/**
@typedef {import('./typedefs.js').Tmb}  Tmb
@typedef {import('./typedefs.js').Alg}  Alg
@typedef {import('./typedefs.js').Use}  Use
@typedef {import('./typedefs.js').Sig}  Sig
@typedef {import('./typedefs.js').Key}  Key
 */

// Coze key Thumbprint Canons.
const TmbCanon = ["alg", "x"];

/**
NewKey returns a new Coze key.
If no alg is given, the returned key will be an 'ES256' key.
@param   {Alg}     [alg=ES256] - Alg of the key to generate. (e.g. "ES256")
@returns {Key}
 */
async function NewKey(alg) {
	if (isEmpty(alg)) {
		alg = Alg.Algs.ES256;
	}
	if (Alg.Genus(alg) == Alg.GenAlgs.ECDSA) {
		var keyPair = await CTK.CryptoKey.New(alg);
	} else {
		throw new Error("Coze.NewKey: only ECDSA algs are currently supported.");
	}

	let k = await CTK.CryptoKey.ToCozeKey(keyPair.privateKey);
	k.iat = Math.floor(Date.now() / 1000); // To get Unix from js, divide by 1000.
	k.tmb = await Thumbprint(k);
	k.kid = "My Cyphr.me Key.";

	return k;
}

/**
Thumbprint calculates and returns a B64 Coze key thumbprint. Fails on empty
'alg' or 'x'.
@param   {Key}   cozeKey
@returns {Tmb}
@throws  {error}
 */
async function Thumbprint(cozeKey) {
	if (isEmpty(cozeKey.alg) || isEmpty(cozeKey.x)) {
		throw new Error("Coze.Thumbprint: alg or x is empty.");
	}
	return Can.CanonicalHash64(cozeKey, await Alg.HashAlg(cozeKey.alg), TmbCanon);
};

/**
Valid returns true only for a valid private Coze key.
@param   {Key}      privateCozeKey  Private Coze key.
@returns {boolean}
 */
async function Valid(privateCozeKey) {
	if (isEmpty(privateCozeKey.d)) {
		console.error("Coze key missing `d`");
		return false;
	}
	try {
		let msg = `7AtyaCHO2BAG06z0W1tOQlZFWbhxGgqej4k9-HWP3DE-zshRbrE-69DIfgY704_FDYez7h_rEI1WQVKhv5Hd5Q`;
		let sig = await Coze.SignPay(msg, privateCozeKey);
		return Coze.VerifyPay(msg, privateCozeKey, sig);
	} catch (e) {
		//console.debug("Valid error: " + e);
		return false;
	}
}

/**
Correct checks for the correct construction of a Coze key, but may return
true on cryptographically invalid public keys.  Key must have `alg` and at
least one of `tmb`, `x`, and `d`. Using input information, if it is possible
to definitively know the given key is incorrect, Correct returns false, but
if it's plausible it's correct, Correct returns true. Correct answers the
question: "Is the given Coze key reasonable using the information provided?".
Correct is useful for sanity checking public keys without signed messages,
sanity checking `tmb` only keys, and validating private keys. Use function
"Verify" instead for verifying public keys when a signed message is
available. Correct is considered an advanced function. Please understand it
thoroughly before use.

Correct:

1. Checks the length of `x` and/or `tmb` against `alg`.
2. If `x` and `tmb` are present, verifies correct `tmb`.
3. If `d` is present, verifies correct `tmb` and `x` if present, and verifies
the key by verifying a generated signature.
@param   {Key}     ck
@returns {boolean}
 */
async function Correct(ck) {
	if (typeof ck !== "object") {
		console.error("Correct: CozeKey must be passed in as an object.");
		return false;
	}

	if (isEmpty(ck.alg)) {
		console.error("Correct: Alg must be set");
		return false;
	}

	let p = Alg.Params(ck.alg);

	let isTmbEmpty = isEmpty(ck.tmb);
	let isXEmpty = isEmpty(ck.x);
	let isDEmpty = isEmpty(ck.d);

	if (isTmbEmpty && isXEmpty && isDEmpty) {
		console.error("Correct: At least one of [x, tmb, d] must be set");
		return false;
	}

	// tmb only key
	if (isXEmpty && isDEmpty) {
		if (isTmbEmpty || ck.tmb.length !== p.HashSizeB64) {
			console.error("Correct: Incorrect `tmb` size: ", ck.tmb.length);
			return false;
		}
		return true;
	}

	// d is not set
	if (!isXEmpty && ck.x.length !== p.XSizeB64) {
		console.error("Correct: Incorrect x size: ", ck.x.length);
		return false;
	}

	// We currently do not support recalculating `x`, as subtle does not provide
	// the necessary API for computing the points from the private component.
	// https://developer.mozilla.org/en-US/docs/Web/API/Crypto/subtle
	//
	// See RecalcX docs below
	//
	// If d and (x and/or tmb) is given, recompute from d and compare:
	// let x = RecalcX(ck);

	// If tmb is set, recompute and compare.
	if (!isTmbEmpty && !isXEmpty) {
		let t = await Thumbprint(ck);
		if (ck.tmb !== t) {
			console.error("Correct: Incorrect given `tmb`: ", ck.tmb);
			return false;
		}
	}

	// If private key, validate by signing and verifying.
	// `x` must also be populated, for cryptokey, since we do not have RecalcX().
	if (!isDEmpty && !isXEmpty) {
		let cryptoKey = await CTK.CryptoKey.FromCozeKey(ck);
		let mldBuffer = await Coze.SToArrayBuffer("Test Signing")
		let sig = await CTK.CryptoKey.SignBuffer(cryptoKey, mldBuffer);
		let pubKey = await CTK.CryptoKey.FromCozeKey(ck, true);
		let result = await CTK.CryptoKey.VerifyArrayBuffer(ck.alg, pubKey, mldBuffer, sig);

		if (!result) {
			console.error("Correct: private key invalid.");
			return false;
		}
	}

	return true;
};


// TODO Support RecalcX if crypto.subtle provides necessary API for computing
// https://stackoverflow.com/questions/72151096/how-to-derive-public-key-from-private-key-using-webcryptoapi/72153942#72153942
//
// scalar/jacobian/affinity from private component.
// Alternatively, use noble.
// function RecalcX(ck) {
// 	let x;
// 	switch (ck.alg) {
// 		case "ES256":
// 		case "ES384":
// 		case "ES512":
// 			break;
// 		default:
// 			x = null;
// 	}

// 	return x;
// }


/**
Revoke generates a self revoke message and sets the input key as revoked.
'rvk' will be set on given cozeKey.
@param   {Key}       cozeKey  Private Coze key.
@param   {string}    [msg]    Optional, human readable non programmatic reason for revoking the key.
@returns {Coze}               Signed revoke Coze.
@throws  {error}              Fails if cryptoKeyPrivate is nil or invalid.
 */
async function Revoke(cozeKey, msg) {
	if (isEmpty(cozeKey)) {
		throw new Error("CozeKey.Revoke: Private key not set.  Cannot sign message");
	}

	var coze = {};
	coze.pay = {};
	if (!isEmpty(msg)) { // Optional revoke message. 
		coze.pay.msg = msg;
	}
	coze.pay.rvk = Math.round((Date.now() / 1000)); // Javascript's Date converted to Unix time.

	// SignCoze does not allow revoked keys to sign messages.  Temporarily remove
	// key.revoke and then set back afterward, otherwise set key with new revoke. 
	let prevRvk = cozeKey.rvk;
	delete cozeKey.rvk;
	coze = await Coze.Sign(coze, cozeKey);
	if (prevRvk !== undefined) {
		cozeKey.rvk = prevRvk;
	} else {
		cozeKey.rvk = coze.pay.rvk;
	}

	return coze
};

/**
IsRevoked returns true if a key or a coze is marked as revoked. `rvk` should
be an integer Unix timestamp, however this function also checks for the
string "true" as well as the bool `true`.

Messages self-revoking keys must have `rvk` with an integer value greater
than 0.  
@param   {Key|Coze}       cozeKey  Coze key or coze object.
@param   {string}         [msg]    Optional reason for revoking the key.
@returns {boolean}
 */
function IsRevoked(cozeKey) {
	if (isEmpty(cozeKey.rvk) || !(parseInt(cozeKey.rvk) > 0)) {
		return false;
	}
	return true;
};