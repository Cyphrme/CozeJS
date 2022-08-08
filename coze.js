"use strict";

import * as Can from './canon.js'; // import as "Can" since func "Canon" will conflict in `coze.join.js`.
import * as Enum from './alg.js';
import * as CZK from './cozekey.js';
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
@typedef {import('./cozekey.js').CozeKey} CozeKey
@typedef {import('./alg.js').Alg}         Alg
@typedef {import('./canon.js').Canon}     Canon

Basic Coze Types
@typedef  {String} B64       - Coze b64ut (RFC 4648 base64 url truncated)
@typedef  {String} Message   - A not-hashed message to be signed.
@typedef  {B64}    Digest    - A digest.
@typedef  {B64}    Sig       - A signature.
@typedef  {Number} Time      - Unix time.

Pay contains the standard `Coze.Pay` fields.
@typedef  {Object} Pay
@property {Alg}    alg  - Algorithm             e.g. "ES256".
@property {Time}   iat  - Unix time of signing. e.g. 1623132000.
@property {B64}    tmb  - Signing thumbprint    e.g. cLj8vsYtMBwYkzoFVZHBZo6SNL8wSdCIjCKAwXNuhOk
@property {String} typ  - Type.                 e.g. "cyphr.me/msg/create".

Coze is a signed coze object.  See docs for more about `coze`.
@typedef  {Object}  Coze
@property {Pay}     pay    - The `pay`.  See Pay.
@property {Sig}     sig    - The B64 signature.
@property {Digest}  [cad]  - Canonical digest of `pay`.     e.g.  LSgWE4vEfyxJZUTFaRaB2JdEclORdZcm4UVH9D8vVto
@property {Array}   [can]  - The canon fields of pay.       e.g.  ["alg", "iat", "msg", "tmb", "typ"]
@property {Digest}  [czd]  - "Coze digest".                 Have over `{"cad":...,"sig":...}`
@property {CozeKey} [key]  - Coze Key used to sign `coze`.

VerifiedArray - Used when verifying array of cozies.  
@typedef  {Object}  VerifiedArray
@property {boolean} VerifiedAll   - Indicates if whole array was verified.  False on error or if anything was not verified.
@property {number}  VerifiedCount - Number of objects verified.
@property {number}  FailedCount   - Number of objects that failed verification.
@property {Coze[]}  FailedCoze    - Objects that failed verification.
*/

// PayCanon is the standard coze.pay fields.
const PayCanon = ["alg", "iat", "tmb", "typ"];

/**
 * Sign signs message with private Coze key and returns b64ut sig.
 * 
 * @param   {Message}       message    Message string.
 * @param   {CozeKey}       cozeKey    Private coze key.
 * @returns {Sig}                      b64ut `sig`.  Empty on invalid.
 * @throws  {Error}                    Invalid key/parse error.
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
 * @param   {Coze}      coze       Object coze.
 * @param   {CozeKey}   cozeKey    A private coze key.
 * @param   {Canon}     [canon]    Array for canonical keys. [Optional]
 * @returns {Coze}                 The same coze as input.
 * @throws  {Error}                Invalid key, parse error, mismatch fields.
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
 * @param   {CozeKey}   cozeKey    A private coze key.
 * @param   {Canon}     [canon]    Array for canonical keys. [Optional]
 * @returns {Coze}                 The same coze as input.
 * @throws  {Error}                Invalid key, parse error, mismatch fields.
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
 * Verify verifies a `pay` with `sig` and returns a boolean.  Verify does no
 * Coze checks.  If checks are needed, use VerifyCoze();
 *
 * @param  {Message}   message    Message string.
 * @param  {CozeKey}   cozekey    Coze key for validation.
 * @param  {Sig}       sig        Signature.
 * @return {boolean}              Whether or not message is verified.
 * @throws {Error}                Invalid key/parse error.
 */
async function Verify(message, cozekey, sig) {
	return CTK.CryptoKey.VerifyMsg(
		await CTK.CryptoKey.FromCozeKey(cozekey, true),
		message,
		sig,
	);
};

/**
 * VerifyCoze returns a boolean.  coze.sig must be set.  If set, pay.alg and
 * pay.tmb must match with cozeKey.
 * 
 * @param  {Coze}     coze         Coze.
 * @param  {CozeKey}  [cozeKey]    Coze key for validation.
 * @param  {Sig}      [sig]        String.
 * @return {boolean}               Valid or not
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
 * VerifyCozeArray verifies an array of `coze`s and returns a single "VerifiedArray" object.
 *
 * @param  {coze[]}           coze       - Array of Coze objects.
 * @param  {CozeKey}          cozeKey    - Javascript object.  CozeKey.
 * @return {VerifiedArray}
 * @throws {Error}
 */
async function VerifyCozeArray(coze, cozeKey) {
	if (!Array.isArray(coze)) {
		return VerifyCoze(coze, cozeKey)
	}

	/** @type {VerifiedArray} verifiedObj */
	var verifiedObj = {
		VerifiedAll: false,
		VerifiedCount: 0,
		FailedCount: 0,
		FailedCoze: [],
	};

	let copy = [...coze]; // Copy so original isn't modified.

	for (let i = 0; i < copy.length; i++) {
		let c = copy[i];
		if (!isEmpty(c.coze)) { // "coze" encapsulated?
			c = c.coze;
		}

		let valid = await VerifyCoze(c, cozeKey);
		if (valid) {
			verifiedObj.VerifiedCount++;
		} else {
			verifiedObj.FailedCount++;
			verifiedObj.FailedCoze.push(copy);
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
 *
 * @param  {Coze}      coze          coze.
 * @param  {alg}       [alg]         Optional alg.  pay.alg takes precedence over parameter.   
 * @throws {Error}                   JSON parse exception or other Error.  
 * @return {Coze}                    {pay, key, iat, can, cad, czd, tmb, sig}
 * 
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
 * @param  {string}        string
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
 * @param   {ArrayBuffer} buffer  ArrayBuffer. Arbitrary bytes. UTF-16 is Javascript native.
 * @returns {b64ut}               String. b64ut encoded string.
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
 * @returns {boolean}          Boolean.
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
 * @returns {boolean}         An actual boolean.  
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