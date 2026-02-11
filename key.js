"use strict";

import * as Can from './canon.js'; // import as "Can".
import * as Enum from './alg.js';
import {
	isEmpty,
} from './coze.js';

export {
	NewKey,
	Thumbprint,
	Valid,
	Correct,
	Revoke,
	IsRevoked,

	KeyCanon,
}

/**
@typedef {import('./typedef.js').Alg}   Alg
@typedef {import('./typedef.js').B64}   B64
@typedef {import('./typedef.js').Key}   Key
@typedef {import('./typedef.js').Coz}   Coz
@typedef {import('./typedef.js').Can}   Can
 */

// KeyCanon is the canonical form of a Coz key.
const KeyCanon = ["alg", "pub"];

/**
NewKey returns a new Coz key.
If no alg is given, the returned key will be an 'ES256' key.
@param   {Alg}     [alg=ES256] - Alg of the key to generate. (e.g. "ES256")
@param   {string}  [tag]       - Key identifier, readable label.
@returns {Key}
 */
async function NewKey(alg, tag) {
	if (isEmpty(alg)) {
		alg = Enum.Algs.ES256;
	}
	if (Enum.Genus(alg) == Enum.GenAlgs.ECDSA) {
		var keyPair = await CTK.CryptoKey.New(alg);
	} else {
		throw new Error("Coz.NewKey: only ECDSA algs are currently supported.");
	}

	let k = await CTK.CryptoKey.CryptoKeyToCozKey(keyPair.privateKey);
	k.now = Math.floor(Date.now() / 1000); // To get Unix from js, divide by 1000.
	k.tmb = await Thumbprint(k);
	if (!isEmpty(tag)) {
		k.tag = tag;
	} else {
		k.tag = "My Cyphr.me Key.";
	}

	return k;
};

import * as CTK from './cryptokey.js';

/**
Thumbprint calculates a thumbprint from the given Coz key.
@param  {Key}    cozKey  Coz key with `alg` and `pub` minimally populated.
@returns {B64}   Thumbprint
@throws  {error}
 */
async function Thumbprint(cozKey) {
	if (isEmpty(cozKey.pub)) {
		throw new Error("Thumbprint: Coz key pub must be set.");
	}
	return Can.CanonicalHash64(cozKey, Enum.HashAlg(cozKey.alg), KeyCanon);
}

/**
Valid returns true only for a valid private Coz key.
@param   {Key}      privateCozKey  Private Coz key.
@returns {boolean}
 */
async function Valid(privateCozKey) {
	if (isEmpty(privateCozKey.prv)) {
		console.error("Coz key missing `prv`");
		return false;
	}
	try {
		let Coze = await import('./coze.js');
		let msg = `7AtyaCHO2BAG06z0W1tOQlZFWbhxGgqej4k9-HWP3DE-zshRbrE-69DIfgY704_FDYez7h_rEI1WQVKhv5Hd5Q`;
		let sig = await Coze.SignPayRaw(msg, privateCozKey);
		return Coze.VerifyPay(msg, privateCozKey, sig);
	} catch (e) {
		//console.debug("Valid error: " + e);
		return false;
	}
}

/**
Correct checks for the correct construction of a Coz key, but may return
true on cryptographically invalid public keys.  Key must have `alg` and at
least one of `tmb`, `pub`, and `prv`. Using input information, if it is possible
to definitively know the given key is incorrect, Correct returns false, but
if it's plausible it's correct, Correct returns true. Correct answers the
question: "Is the given Coz key reasonable using the information provided?".
Correct is useful for sanity checking public keys without signed messages,
sanity checking `tmb` only keys, and validating private keys. Use function
"Verify" instead for verifying public keys when a signed message is
available. Correct is considered an advanced function. Please understand it
thoroughly before use.

Correct:

1. Checks the length of `pub` and/or `tmb` against `alg`.
2. If `pub` and `tmb` are present, verifies correct `tmb`.
3. If `prv` is present, verifies correct `tmb` and `pub` if present, and verifies
the key by verifying a generated signature.
@param   {Key}     ck
@returns {boolean}
 */
async function Correct(ck) {
	if (typeof ck !== "object") {
		console.error("Correct: CozKey must be passed in as an object.");
		return false;
	}

	if (isEmpty(ck.alg)) {
		console.error("Correct: Alg must be set");
		return false;
	}

	let p = Enum.Params(ck.alg);

	let isTmbEmpty = isEmpty(ck.tmb);
	let isPubEmpty = isEmpty(ck.pub);
	let isPrvEmpty = isEmpty(ck.prv);

	if (isTmbEmpty && isPubEmpty && isPrvEmpty) {
		console.error("Correct: At least one of [pub, tmb, prv] must be set");
		return false;
	}

	// tmb only key
	if (isPubEmpty && isPrvEmpty) {
		if (isTmbEmpty || ck.tmb.length !== p.HashSizeB64) {
			console.error("Correct: Incorrect `tmb` size: ", ck.tmb.length);
			return false;
		}
		return true;
	}

	// prv is not set
	if (!isPubEmpty && ck.pub.length !== p.PubSizeB64) {
		console.error("Correct: Incorrect pub size: ", ck.pub.length);
		return false;
	}

	// We currently do not support recalculating `pub`, as subtle does not provide
	// the necessary API for computing the points from the private component.
	// https://developer.mozilla.org/en-US/docs/Web/API/Crypto/subtle
	//
	// See RecalcX docs below
	//
	// If prv and (pub and/or tmb) is given, recompute from prv and compare:
	// let pub = RecalcX(ck);

	// If tmb is set, recompute and compare.
	if (!isTmbEmpty && !isPubEmpty) {
		let t = await Thumbprint(ck);
		if (ck.tmb !== t) {
			console.error("Correct: Incorrect given `tmb`: ", ck.tmb);
			return false;
		}
	}

	// If private key, validate by signing and verifying.
	// `pub` must also be populated, for cryptokey, since we do not have RecalcX().
	if (!isPrvEmpty && !isPubEmpty) {
		let Coze = await import('./coze.js');
		let cryptoKey = await CTK.CryptoKey.FromCozKey(ck);
		let mldBuffer = await Coze.SToArrayBuffer("Test Signing")
		let sig = await CTK.CryptoKey.SignBuffer(cryptoKey, mldBuffer);
		let pubKey = await CTK.CryptoKey.FromCozKey(ck, true);
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
//	let x;
//	switch (ck.alg) {
//		case "ES256":
//		case "ES384":
//		case "ES512":
//			break;
//		default:
//			x = null;
//	}

//	return x;
// }


/**
Revoke generates a self revoke message and sets the input key as revoked.
'rvk' will be set on given cozKey.
@param   {Key}       cozKey  Private Coz key.
@param   {string}    [msg]   Optional, human readable non programmatic reason for revoking the key.
@returns {Coz}               Signed revoke Coz.
@throws  {error}             Fails if cryptoKeyPrivate is nil or invalid.
 */
async function Revoke(cozKey, msg) {
	if (isEmpty(cozKey)) {
		throw new Error("CozKey.Revoke: Private key not set.  Cannot sign message");
	}

	let Coze = await import('./coze.js');

	var coz = {};
	coz.pay = {};
	if (!isEmpty(msg)) { // Optional revoke message. 
		coz.pay.msg = msg;
	}
	coz.pay.rvk = Math.round((Date.now() / 1000)); // Javascript's Date converted to Unix time.

	// Enforce revoke message max size to prevent DoS.
	if (Coze.RVK_MAX_SIZE > 0) {
		let paySize = JSON.stringify(coz.pay).length;
		if (paySize > Coze.RVK_MAX_SIZE) {
			throw new Error(`Revoke: revoke message size ${paySize} exceeds RVK_MAX_SIZE ${Coze.RVK_MAX_SIZE}`);
		}
	}

	// Sign does not allow revoked keys to sign messages.  Temporarily remove
	// key.rvk and then set back afterward, otherwise set key with new revoke.
	let prevRvk = cozKey.rvk;
	delete cozKey.rvk;
	coz = await Coze.Sign(coz, cozKey);
	if (prevRvk !== undefined) {
		cozKey.rvk = prevRvk;
	} else {
		cozKey.rvk = coz.pay.rvk;
	}

	return coz
};

/**
IsRevoked returns true if the given Key is marked as revoked.
@param   {Key}     cozKey
@returns {boolean}
*/
function IsRevoked(cozKey) {
	if (!isEmpty(cozKey.rvk) && cozKey.rvk > 0) {
		return true;
	}
	return false;
}