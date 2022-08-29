"use strict";

import * as CTK from './cryptokey.js';
import * as Can from './canon.js';
import * as Coze from './coze.js';
import * as Alg from './alg.js';
import {
	isEmpty
} from './coze.js';

export {
	NewCozeKey,
	Correct,
	Valid,
	Thumbprint,
	Revoke,
	IsRevoked,

	// RecalcX,

	TmbCanon,
}

/**
 * @typedef {import('./coze.js').B64}  B64
 * @typedef {import('./coze.js').Alg}  Alg
 * @typedef {import('./coze.js').Use}  Use
 * @typedef {import('./coze.js').Sig}  Sig
 * @typedef {import('./coze.js').Time} Time
 */

/**
 * CozeKey holds a cryptographic key, with the minimum required fields for the 
 * given `alg`.
 *
 * -alg: Cryptographic signing or encryption algorithm - e.g. "ES256"
 * 
 * -kid: Human readable, non programmatic, key identifier - e.g. "Test Key"
 * 
 * -iat: Unix time key was created. e.g. 1624472390
 * 
 * -tmb: Key thumbprint e.g. "cLj8vsYtMBwYkzoFVZHBZo6SNL8wSdCIjCKAwXNuhOk"
 * 
 * -d:   ECDSA private "d" component in b64ut. Required for ECDSA private Coze keys.
 * e.g. "bNstg4_H3m3SlROufwRSEgibLrBuRq9114OvdapcpVA"
 * 
 * -x:   ECDSA public "x" component in b64ut. Required for ECDSA public Coze keys.
 * e.g. "2nTOaFVm2QLxmUO_SjgyscVHBtvHEfo2rq65MvgNRjORojq39Haq9rXNxvXxwba_Xj0F5vZibJR3isBdOWbo5g"
 * @typedef  {Object} CozeKey
 * @property {Alg}    alg
 * @property {String} kid
 * @property {Time}   iat
 * @property {B64}    tmb
 * @property {B64}    [d]
 * @property {B64}    [x]
 */

/**
 * PrivateCozeKey is a Coze key containing any private components.
 * @typedef  {CozeKey} PrivateCozeKey
 */

/**
 * PublicCozeKey is a Coze key containing no private components and required public components.
 * @typedef  {CozeKey} PublicCozeKey
 **/

// Coze key Thumbprint Canons.
const TmbCanon = ["alg", "x"];

/**
 * NewCozeKey returns a new Coze key. 
 * 
 * @param   {Alg}     [alg=ES256] - Alg of the key to generate. (e.g. "ES256")
 * @returns {CozeKey}             - Coze key in Javascript object format
 */
async function NewCozeKey(alg) {
	if (isEmpty(alg)) {
		alg = "ES256"
	}
	if (Alg.Genus(alg) == "ECDSA") {
		var keyPair = await CTK.CryptoKey.New(alg);
	} else {
		throw new Error("CozeKey.NewCozeKey: only ECDSA algs are currently supported.");
	}

	let CozeKey = await CTK.CryptoKey.ToCozeKey(keyPair.privateKey);
	CozeKey.iat = Math.floor(Date.now() / 1000); // To get Unix from js, divide by 1000.
	CozeKey.tmb = await Thumbprint(CozeKey);
	CozeKey.kid = "My Cyphr.me Key.";

	return CozeKey;
}

/**
 * Thumbprint generates Coze key thumbprint.
 *
 * @param   {CozeKey} cozeKey - Javascript object Coze key.
 * @returns {tmb}             - B64 thumbprint.
 * @throws  {Error}           - Fails on empty alg or x.
 */
async function Thumbprint(cozeKey) {
	if (isEmpty(cozeKey.alg) || isEmpty(cozeKey.x)) {
		throw new Error("CozeKey.Thumbprint: alg or x is empty.");
	}
	return Can.CanonicalHash64(cozeKey, await Alg.HashAlg(cozeKey.alg), TmbCanon);
};

/**
 * Valid validates a private Coze key.  See notes on `Correct`.
 *
 * @param   {CozeKey} privateCozeKey  Private Coze key.
 * @returns {Boolean}                 Valid.
 */
async function Valid(privateCozeKey) {
	if (isEmpty(privateCozeKey.d)) {
		console.error("Coze key missing `d`");
		return false;
	}
	try {
		let msg = `7AtyaCHO2BAG06z0W1tOQlZFWbhxGgqej4k9-HWP3DE-zshRbrE-69DIfgY704_FDYez7h_rEI1WQVKhv5Hd5Q`;
		let sig = await Coze.Sign(msg, privateCozeKey);
		return await Coze.Verify(msg, privateCozeKey, sig);
	} catch (e) {
		console.error(e);
	}
	return false;
}

/**
 * Correct checks for the correct construction of a Coze key, but may return
 * true on cryptographically invalid public keys.  Key must have `alg` and at
 * least one of `tmb`, `x`, and `d`. Using input information, if it is possible
 * to definitively know the given key is incorrect, Correct returns false, but
 * if it's plausible it's correct, Correct returns true. Correct answers the
 * question: "Is the given Coze key reasonable using the information provided?".
 * Correct is useful for sanity checking public keys without signed messages,
 * sanity checking `tmb` only keys, and validating private keys. Use function
 * "Verify" instead for verifying public keys when a signed message is
 * available. Correct is considered an advanced function. Please understand it
 * thoroughly before use.
 * 
 * Correct:
 * 
 * 1. Checks the length of `x` and/or `tmb` against `alg`.
 * 2. If `x` and `tmb` are present, verifies correct `tmb`.
 * 3. If `d` is present, verifies correct `tmb` and `x` if present, and verifies
 * the key by verifying a generated signature.
 * 
 * @param   {CozeKey} ck         Object. Coze key. 
 * @returns {Boolean}
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
		if (isTmbEmpty || ck.tmb.length !== p.B64.HashSize) {
			console.error("Correct: Incorrect `tmb` size: ", ck.tmb.length);
			return false;
		}
		return true;
	}

	// d is not set
	if (!isXEmpty && ck.x.length !== p.B64.XSize) {
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

	// // Sanity check - No keys from the future allowed.
	// if (ck.iat > Math.round((Date.now() / 1000))) {
	// 	console.error("Correct: cannot have iat greater than present time");
	// }


	// If private key, validate by signing and verifying.
	// `x` must also be populated, for cryptokey, since we do not have RecalcX().
	if (!isDEmpty && !isXEmpty) {
		let cryptoKey = await CTK.CryptoKey.FromCozeKey(ck);
		let mldBuffer = await Coze.SToArrayBuffer("Test Signing")
		let sig = await CTK.CryptoKey.SignBuffer(cryptoKey, mldBuffer);
		let pubKey = await CTK.CryptoKey.FromCozeKey(ck, true);
		let result = await CTK.CryptoKey.VerifyArrayBuffer(pubKey, mldBuffer, sig);

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
 * Revoke generates a self revoke message and sets the input key as revoked.
 * Returns the signed Coze.
 * Fails if cryptoKeyPrivate is nil or invalid.
 * 
 * @param   {CozeKey}   cozeKey  Private Coze key.
 * @param   {String}    [msg]    Optional, human readable non programmatic reason for revoking the key.
 * @returns {Coze}
 * @throws  {Error}
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
	coze = await Coze.SignCoze(coze, cozeKey);
	if (prevRvk !== undefined) {
		cozeKey.rvk = prevRvk;
	} else {
		cozeKey.rvk = coze.pay.rvk;
	}

	return coze
};

/**
 * IsRevoked returns true if a key or a coze is marked as revoked. `rvk` should
 * be an integer Unix timestamp, however this function also checks for the
 * string "true" as well as the bool `true`.
 *
 * Messages self-revoking keys must have `rvk` with an integer value greater
 * than 0.  
 *
 * @param   {CozeKey|Coze}   cozeKey  Coze key or coze          
 * @param   {String}         [msg]    Optional reason for revoking the key.    
 * @returns {boolean}                 Revoked or not. 
 */
function IsRevoked(cozeKey) {
	if (isEmpty(cozeKey.rvk) || !(parseInt(cozeKey.rvk) > 0)) {
		return false;
	}
	return true;
};