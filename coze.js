"use strict";

import * as Can from './canon.js'; // import as "Can" since func "Canon" will conflict in `coze.join.js`.
import * as Enum from './alg.js';
import * as CZK from './key.js';
import * as CTK from './cryptokey.js';
import * as Coze from './coze.js';

export {
	PayCanon,
	Sign,
	SignCoze,
	SignCozeRaw,
	Verify,
	VerifyCoze,
	VerifyCozeArray,
	Meta,

	// Base conversion
	SToArrayBuffer,
	B64uToArrayBuffer,
	B64utToUint8Array,
	ArrayBufferTo64ut,

	// Helpers
	isEmpty,
	isBool,
}

/**
 * @typedef {import('./key.js').Key}      Key
 * @typedef {import('./alg.js').Alg}      Alg
 * @typedef {import('./canon.js').Canon}  Canon
 */

////  Basic Coze Types

/**
 * Coze b64ut (RFC 4648 base64 url truncated)
 * @typedef  {String} B64
 */

/**
 * A not-hashed message to be signed.
 @typedef  {String} Message
 */

/**
 * A digest.
 @typedef  {B64}    Digest
 */

/**
 * A signature.
 @typedef  {B64}    Sig
 */

/**
 * Unix time.
 @typedef  {Number} Time
 */


/**
 * Pay contains the standard `Coze.Pay` fields.
 * 
 * - alg:    Algorithm.            E.g. "ES256".
 * - iat:    Unix time of signing. E.g. 1623132000.
 * - tmb:    Signing thumbprint    E.g. cLj8vsYtMBwYkzoFVZHBZo6SNL8wSdCIjCKAwXNuhOk
 * - typ:    Type.                 E.g. "cyphr.me/msg/create".
 * @typedef  {Object} Pay
 * @property {Alg}    alg
 * @property {Time}   iat
 * @property {B64}    tmb
 * @property {String} typ
 */

/**
 * Coze is a signed coze object.  See docs for more about `coze`.
 * 
 * - pay:   The `pay`.  See docs on Pay for more.
 * - sig:   The B64 signature.
 * - cad:   Canonical digest of `pay`.  E.g.  LSgWE4vEfyxJZUTFaRaB2JdEclORdZcm4UVH9D8vVto
 * - can:   The canon fields of pay.    E.g.  ["alg", "iat", "msg", "tmb", "typ"]
 * - czd:   "Coze digest" over `{"cad":...,"sig":...}`.
 * - key:   Coze Key used to sign `coze`.
 * @typedef  {Object}  Coze
 * @property {Pay}     pay
 * @property {Sig}     sig
 * @property {Digest}  [cad]
 * @property {Array}   [can]
 * @property {Digest}  [czd]
 * @property {Key}     [key]
 */

/**
 * VerifiedArray - Used when verifying array of cozies.
 * 
 * - VerifiedAll:    Indicates if whole array was verified. False on error or if
 *                   anything was not verified.
 * - VerifiedCount:  Number of objects verified.
 * - FailedCount:    Number of objects that failed verification.
 * - FailedCoze:     Objects that failed verification.
 * @typedef  {Object}  VerifiedArray
 * @property {Boolean} VerifiedAll
 * @property {Number}  VerifiedCount
 * @property {Number}  FailedCount
 * @property {Coze[]}  FailedCoze
 */

// PayCanon is the standard coze.pay fields.
const PayCanon = ["alg", "iat", "tmb", "typ"];

/**
 * Sign signs message with private Coze key and returns b64ut sig.
 * Returns empty on invalid.
 * 
 * @param   {Message}       message    Message string.
 * @param   {Key}           cozeKey    Private coze key.
 * @returns {Sig}
 * @throws  {Error}
 */
async function Sign(message, cozeKey) {
	return CTK.CryptoKey.SignBufferB64(
		await CTK.CryptoKey.FromCozeKey(cozeKey),
		await SToArrayBuffer(message)
	);
}

/**
 * SignCoze signs in place coze.pay with a private Coze key. Returns the same,
 * but updated, coze.  Errors on mismatch `alg` or `tmb`.  If empty, `alg` and
 * `tmb` are populated. `iat` set to current time.
 *
 * SignCoze, SignCozeRaw, VerifyCoze, and VerifyCozeArray assumes that object
 * has no duplicate fields since this is disallowed in Javascript.
 * 
 * Returns the same coze that was given.
 * 
 * Fails on invalid key, parse error, mismatch fields.
 * 
 * @param   {Coze}      coze       Object coze.
 * @param   {Key}       cozeKey    A private coze key.
 * @param   {Canon}     [canon]    Array for canonical keys.
 * @returns {Coze}
 * @throws  {Error}
 */
async function SignCoze(coze, cozeKey, canon) {
	if (CZK.IsRevoked(cozeKey)) {
		throw new Error("Coze: Cannot sign with revoked key.");
	}
	if (isEmpty(coze.pay.alg)) {
		coze.pay.alg = cozeKey.alg;
	}
	if (isEmpty(coze.pay.tmb)) {
		coze.pay.tmb = await CZK.Thumbprint(cozeKey);
	}
	if (coze.pay.alg !== cozeKey.alg) {
		throw new Error("SignCoze: Coze key alg mismatch with coze.pay.alg.");
	}
	if (coze.pay.tmb !== cozeKey.tmb) {
		throw new Error("SignCoze: Coze key tmb mismatch with coze.pay.tmb.");
	}

	coze.pay.iat = Math.round((Date.now() / 1000)); // Javascript's Date converted to Unix time.

	if (!isEmpty(canon)) {
		coze.pay = await Can.Canonical(coze.pay, canon);
	}

	coze.sig = await Sign(await JSON.stringify(coze.pay), cozeKey);
	return coze;
}


/**
 * SignCozeRaw signs in place coze.pay with a private Coze key, but unlike
 * SignCoze, does not set `alg`, `tmb` or `iat`. Returns the same, but updated,
 * coze. Errors on mismatch `alg` or `tmb`.
 *
 * @param   {Coze}      coze       Object coze.
 * @param   {Key}       cozeKey    A private coze key.
 * @param   {Canon}     [canon]    Array for canonical keys.
 * @returns {Coze}
 * @throws  {Error}
 */
async function SignCozeRaw(coze, cozeKey, canon) {
	if (CZK.IsRevoked(cozeKey)) {
		throw new Error("SignCozeRaw: Cannot sign with revoked key.");
	}
	if (!isEmpty(coze.pay.alg) && coze.pay.alg !== cozeKey.alg) {
		throw new Error("SignCozeRaw: Coze key alg mismatch with coze.pay.alg.");
	}
	if (!isEmpty(coze.pay.tmb) && coze.pay.tmb !== cozeKey.tmb) {
		throw new Error("SignCozeRaw: Coze key tmb mismatch with coze.pay.tmb.");
	}

	if (!isEmpty(canon)) {
		coze.pay = await Can.Canonical(coze.pay, canon);
	}
	coze.sig = await Sign(await JSON.stringify(coze.pay), cozeKey);
	return coze;
}

/**
 * Verify verifies a `pay` with `sig` and returns whether or not the message is
 * verified. Verify does no Coze checks.  If checks are needed, use
 * VerifyCoze();
 *
 * @param  {Message}   message    Message string.
 * @param  {Key}       cozekey    Coze key for validation.
 * @param  {Sig}       sig        Signature.
 * @return {Boolean}
 * @throws {Error}
 */
async function Verify(message, cozekey, sig) {
	return CTK.CryptoKey.VerifyMsg(
		await CTK.CryptoKey.FromCozeKey(cozekey, true),
		message,
		sig,
	);
};

/**
 * VerifyCoze returns a whether or not the Coze is valid. coze.sig must be set.
 * If set, pay.alg and pay.tmb must match with cozeKey.
 * 
 * @param  {Coze}     coze         Coze with signed pay.
 * @param  {Key}      [cozeKey]    Public Coze key for verification.
 * @param  {Sig}      [sig]        Signature.
 * @return {Boolean}
 * @throws {Error}
 */
async function VerifyCoze(coze, cozeKey) {
	if (!isEmpty(coze.pay.alg) && coze.pay.alg !== cozeKey.alg) {
		throw new Error("Coze: Coze key alg mismatch with coze.pay.alg.");
	}
	if (!isEmpty(coze.pay.tmb) && coze.pay.tmb !== cozeKey.tmb) {
		throw new Error("Coze: Coze key tmb mismatch with coze.pay.tmb.");
	}
	return Verify(JSON.stringify(coze.pay), cozeKey, coze.sig);
}

/**
 * VerifyCozeArray verifies an array of `coze`s and returns a single
 * "VerifiedArray" object.
 *
 * @param  {coze[]}           coze       - Array of Coze objects.
 * @param  {Key}              cozeKey    - Javascript object.  Coze Key.
 * @return {VerifiedArray}
 * @throws {Error}
 */
async function VerifyCozeArray(coze, cozeKey) {
	if (!Array.isArray(coze)) {
		return VerifyCoze(coze, cozeKey)
	}

	/** @type {VerifiedArray} */
	var verifiedObj = {
		VerifiedAll: false,
		VerifiedCount: 0,
		FailedCount: 0,
		FailedCoze: [],
	};

	let copy = [...coze]; // Copy so original isn't modified.
	for (let c of copy) {
		if (!isEmpty(c.coze)) { // "coze" encapsulated?
			c = c.coze;
		}

		let valid = await VerifyCoze(c, cozeKey);
		if (valid) {
			verifiedObj.VerifiedCount++;
		} else {
			verifiedObj.FailedCount++;
			verifiedObj.FailedCoze.push(c);
		}
	}

	if (verifiedObj.FailedCount == 0) {
		verifiedObj.VerifiedAll = true;
	}

	return verifiedObj;
};


/**
 * Meta recalculates and sets [can, cad, czd] for given `coze`. Coze.Pay, and
 * Coze.Sig must be set, and either Coze.Pay.Alg or parameter alg must be set.
 * Meta does no cryptographic verification.
 * Fails on JSON parse exception.
 * Returns {pay, key, iat, can, cad, czd, tmb, sig}.
 *
 * @param  {Coze}      coze     coze.
 * @param  {Alg}       [alg]    coze.pay.alg takes precedence.
 * @throws {Error} 
 * @return {Coze}
 */
async function Meta(coze, alg) {
	if (!isEmpty(coze.pay.alg)) {
		alg = Enum.HashAlg(coze.pay.alg);
	} else {
		alg = Enum.HashAlg(alg);
	}

	coze.can = await Can.Canon(coze.pay);
	coze.cad = await Can.CanonicalHash64(coze.pay, alg);
	coze.czd = await Can.CanonicalHash64({
		cad: coze.cad,
		sig: coze.sig
	}, alg);
	return coze;
}


///////////////////////////////////
// Base Conversion
///////////////////////////////////

/**
 * Converts a string to an ArrayBuffer.
 *
 * @param  {String}        string
 * @return {ArrayBuffer}
 */
async function SToArrayBuffer(string) {
	var enc = new TextEncoder(); // Suppose to be always in UTF-8
	return enc.encode(string).buffer;
}

/**
 * B64uToArrayBuffer takes a b64u (truncated or not truncated) string and
 * decodes it to an ArrayBuffer.
 * 
 * @param   {B64}          string 
 * @returns {ArrayBuffer}
 */
function B64uToArrayBuffer(string) {
	// atob doesn't care about the padding character '='
	return Uint8Array.from(atob(string.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0)).buffer;
};

/**
 * B64utToUint8Array takes a b64ut string and decodes it back into a string.
 * 
 * @param   {B64}          string 
 * @returns {Uint8Array}
 */
function B64utToUint8Array(string) {
	// atob doesn't care about the padding character '='
	return Uint8Array.from(atob(string.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
};


/**
 * ArrayBufferTo64ut Array buffer to base64url.
 * 
 * @param   {ArrayBuffer} buffer  Arbitrary bytes. UTF-16 is Javascript native.
 * @returns {B64}                 b64ut encoded string.
 */
function ArrayBufferTo64ut(buffer) {
	var string = String.fromCharCode.apply(null, new Uint8Array(buffer));
	return btoa(string).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}


///////////////////////////////////
// Helpers - Taken from Cyphr.me
///////////////////////////////////

/**
 * isEmpty is a helper function to determine if thing is empty. 
 * 
 * Objects are empty if they have no keys. (Returns len === 0 of object keys.)
 *
 * Functions are considered always not empty. 
 * 
 * NaN returns true.  (NaN === NaN is always false, as NaN is never equal to
 * anything. NaN is the only JavaScript value unequal to itself.)
 *
 * Don't use on HTMl elements. For HTML elements, use the !== equality check
 * (element !== null).
 *
 * Cannot use CryptoKey with this function since (len === 0) always. 
 *
 * @param   {any}     thing    Thing you wish was empty.
 * @returns {Boolean}
 */
function isEmpty(thing) {
	if (typeof thing === 'function') {
		return false;
	}

	if (thing === Object(thing)) {
		if (Object.keys(thing).length === 0) {
			return true;
		}
		return false;
	}

	if (!isBool(thing)) {
		return true;
	}
	return false
};


/**
 * Helper function to determine boolean.  
 *
 * Javascript, instead of considering everything false except a few key words,
 * decided everything is true instead of a few key words.  Why?  Because
 * Javascript.  This function inverts that assumption, so that everything can be
 * considered false unless true. 
 *
 * @param   {any}      bool   Thing that you wish was a boolean.  
 * @returns {Boolean}
 */
function isBool(bool) {
	if (
		bool === false ||
		bool === "false" ||
		bool === undefined ||
		bool === "undefined" ||
		bool === "" ||
		bool === 0 ||
		bool === "0" ||
		bool === null ||
		bool === "null" ||
		bool === "NaN" ||
		Number.isNaN(bool) ||
		bool === Object(bool) // isObject
	) {
		return false;
	}
	return true;
};