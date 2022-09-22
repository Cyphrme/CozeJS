"use strict";

import * as Can from './canon.js'; // import as "Can" since func "Canon" will conflict in `coze.join.js`.
import * as Enum from './alg.js';
import * as CZK from './key.js';
import * as CTK from './cryptokey.js';

export {
	PayCanon,
	Sign,
	SignCoze,
	SignCozeRaw,
	Verify,
	VerifyCoze,
	// VerifyCozeArray,
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
 * @typedef {import('./typedefs.js').Key}            Key
 * @typedef {import('./typedefs.js').Alg}            Alg
 * @typedef {import('./typedefs.js').Msg}            Msg
 * @typedef {import('./typedefs.js').Coze}           Coze
 * @typedef {import('./typedefs.js').Sig}            Sig
 * @typedef {import('./typedefs.js').Canon}          Canon
 * @typedef {import('./typedefs.js').Meta}           Meta
 * @typedef {import('./typedefs.js').VerifiedArray}  VerifiedArray
 */

// PayCanon is the standard coze.pay fields.
const PayCanon = ["alg", "iat", "tmb", "typ"];

/**
 * Sign signs message with private Coze key and returns b64ut sig.
 * 
 * @param   {Msg}       message
 * @param   {Key}       cozeKey
 * @returns {Sig}
 * @throws  {Error}     Error, SyntaxError, DOMException, TypeError
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
 * @param   {Coze}      coze       Object coze.
 * @param   {Key}       cozeKey    A private coze key.
 * @param   {Canon}     [canon]    Array for canonical keys.
 * @returns {Coze}                 Coze that may have been modified from given.
 * @throws  {Error}                Fails on invalid key, parse error, mismatch fields.
 */
async function SignCoze(coze, cozeKey, canon) {
	if (CZK.IsRevoked(cozeKey)) {
		throw new Error("SignCoze: Cannot sign with revoked key.");
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
 * SignCoze, does not set `alg`, `tmb` or `iat`.
 *
 * @param   {Coze}      coze       Object coze.
 * @param   {Key}       cozeKey    A private coze key.
 * @param   {Canon}     [canon]    Array for canonical keys.
 * @returns {Coze}                 Coze with new `sig` and canonicalized `pay`.
 * @throws  {Error}                Fails on mismatch `alg` or `tmb`.
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
 * @param  {Msg}       message    Message string.
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
		throw new Error("VerifyCoze: Coze key alg mismatch with coze.pay.alg.");
	}
	if (!isEmpty(coze.pay.tmb) && coze.pay.tmb !== cozeKey.tmb) {
		throw new Error("VerifyCoze: Coze key tmb mismatch with coze.pay.tmb.");
	}
	return Verify(JSON.stringify(coze.pay), cozeKey, coze.sig);
}

/**
 * Meta recalculates and sets [can, cad, czd] for given `coze`. Coze.Pay, and
 * Coze.Sig must be set, and either Coze.Pay.Alg or parameter alg must be set.
 * Meta does no cryptographic verification.
 *
 * @param  {Coze}      coze     coze.
 * @param  {Alg}       [alg]    coze.pay.alg takes precedence.
 * @return {Meta}               Meta Coze (sets fields [can, cad, czd]).
 * @throws {Error}              Fails on JSON parse exception.
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
	return new TextEncoder().encode(string).buffer; // Suppose to be always in UTF-8
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
 * ArrayBufferTo64ut returns a b64 string from an Array buffer.
 * 
 * @param   {ArrayBuffer} buffer  Arbitrary bytes. UTF-16 is Javascript native.
 * @returns {B64}
 */
function ArrayBufferTo64ut(buffer) {
	return btoa(String.fromCharCode.apply(null, new Uint8Array(buffer))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
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