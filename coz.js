"use strict";

import * as Can from './canon.js'; // import as "Can" since func "Canon" will conflict in `coz.join.js`.
import * as Enum from './alg.js';
import * as CZK from './key.js';
import * as CTK from './cryptokey.js';

export {
	Sign,
	SignPayRaw,
	SignCozRaw,
	Verify,
	VerifyPay,
	Meta,

	// Base conversion
	SToArrayBuffer,
	B64uToArrayBuffer,
	B64ToUint8Array,
	ArrayBufferTo64ut,

	// Helpers
	isEmpty,

	PayCanon,
	MaxSafeTimestamp,
	validateTimestamp,
	RVK_MAX_SIZE,
}

/**
@typedef {import('./typedef.js').Alg}            Alg
@typedef {import('./typedef.js').B64}            B64
@typedef {import('./typedef.js').Coz}            Coz
@typedef {import('./typedef.js').Pay}            Pay
@typedef {import('./typedef.js').Sig}            Sig
@typedef {import('./typedef.js').Key}            Key
@typedef {import('./typedef.js').Can}            Can
@typedef {import('./typedef.js').Meta}           Meta
@typedef {import('./typedef.js').VerifiedArray}  VerifiedArray
 */

// PayCanon is the standard coz.pay fields.
const PayCanon = ["alg", "now", "tmb", "typ"];


/**
Sign signs in place coz.pay.  It populates/replaces alg and tmb using
the given private Coz key and populates/updates now if non-zero. Returns the
same, but updated, coz.  The optional canon is used to canonicalize pay before
signing.  If needing a coz without alg, tmb, or now, use SignCozRaw.  

Sign, SignCozRaw, and Verify assumes that object has no duplicate
fields since this is disallowed in Javascript.
@param   {Coz}       coz        Object coz.
@param   {Key}       cozKey     A private coz key.
@param   {Can}       [canon]    Array for canonical keys.
@returns {Coz}                  Coz that may have been modified from given.
@throws  {error}                Fails on invalid key, parse error, mismatch fields.
 */
async function Sign(coz, cozKey, canon) {
	if (CZK.IsRevoked(cozKey)) {
		throw new Error("Sign: Cannot sign with revoked key.");
	}

	coz.pay.alg = cozKey.alg;
	coz.pay.tmb = await CZK.Thumbprint(cozKey);
	// If now is non-zero, update it to the current time.
	if (!isEmpty(coz.pay.now)) {
		coz.pay.now = Math.round((Date.now() / 1000)); // Javascript's Date converted to Unix time.
	}

	if (!isEmpty(canon)) {
		coz.pay = await Can.Canonical(coz.pay, canon);
	}

	coz.sig = await SignPayRaw(JSON.stringify(coz.pay), cozKey);
	return coz;
}



/**
SignPayRaw signs message with private Coz key and returns b64ut sig.
@param   {Pay}       pay      ay. e.g. `{"alg"...}` May also be any message.  
@param   {Key}       cozKey
@returns {Sig}
@throws  {error}     Error, SyntaxError, DOMException, TypeError
 */
async function SignPayRaw(pay, cozKey) {
	return CTK.CryptoKey.SignBufferB64(
		await CTK.CryptoKey.FromCozKey(cozKey),
		await SToArrayBuffer(pay)
	);
}



/**
SignCozRaw signs in place coz.pay with a private Coz key, but unlike
Sign, does not set `alg`, `tmb` or `now`. The optional canon is used to
canonicalize pay before signing. 
@param   {Coz}       coz        Object coz.
@param   {Key}       cozKey     A private coz key.
@param   {Can}     [canon]    Array for canonical keys.
@returns {Coz}                  Coz with new `sig` and canonicalized `pay`.
@throws  {error}                Fails on rvk or mismatch `alg` or `tmb`.
 */
async function SignCozRaw(coz, cozKey, canon) {
	if (CZK.IsRevoked(cozKey)) {
		throw new Error("SignCozRaw: Cannot sign with revoked key.");
	}
	if (!isEmpty(coz.pay.alg) && coz.pay.alg !== cozKey.alg) {
		throw new Error("SignCozRaw: Coz key alg mismatch with coz.pay.alg.");
	}
	if (!isEmpty(coz.pay.tmb) && coz.pay.tmb !== cozKey.tmb) {
		throw new Error("SignCozRaw: Coz key tmb mismatch with coz.pay.tmb.");
	}

	if (!isEmpty(canon)) {
		coz.pay = await Can.Canonical(coz.pay, canon);
	}
	coz.sig = await SignPayRaw(JSON.stringify(coz.pay), cozKey);
	return coz;
}



/**
Verify returns a whether or not the Coz is valid. coz.sig must be set.
If set, pay.alg and pay.tmb must match with cozKey.
@param  {Coz}      coz          Coz with signed pay. e.g. `{"pay":..., "sig":...}`
@param  {Key}      [cozKey]     Public Coz key for verification.
@param  {Sig}      [sig]        Signature.
@return {boolean}
@throws {error}
 */
async function Verify(coz, cozKey) {
	if (!isEmpty(coz.pay.alg) && coz.pay.alg !== cozKey.alg) {
		throw new Error("Verify: Coz key alg mismatch with coz.pay.alg.");
	}
	if (!isEmpty(coz.pay.tmb) && coz.pay.tmb !== cozKey.tmb) {
		throw new Error("Verify: Coz key tmb mismatch with coz.pay.tmb.");
	}
	// Enforce revoke message max size to prevent DoS.
	if (!isEmpty(coz.pay.rvk) && coz.pay.rvk > 0 && RVK_MAX_SIZE > 0) {
		let paySize = JSON.stringify(coz.pay).length;
		if (paySize > RVK_MAX_SIZE) {
			throw new Error(`Verify: revoke message size ${paySize} exceeds RVK_MAX_SIZE ${RVK_MAX_SIZE}`);
		}
	}
	return VerifyPay(JSON.stringify(coz.pay), cozKey, coz.sig);
}


/**
VerifyPay verifies a `pay` with `sig` and returns whether or not the message is
verified. Verify does no Coz checks.  If checks are needed, use
Verify(); 
@param  {Pay}       pay        pay. e.g. `{"alg"...}`  May also be any message.  
@param  {Key}       cozKey     Coz key for validation.
@param  {Sig}       sig        Signature.
@return {boolean}
@throws {error}
 */
async function VerifyPay(pay, cozKey, sig) {
	return CTK.CryptoKey.VerifyMsg(
		cozKey.alg,
		await CTK.CryptoKey.FromCozKey(cozKey, true),
		pay,
		sig,
	);
};



/**
Meta calculates a Meta object with the fields [alg,now,tmb,typ,can,cad,sig,czd]
derived from the given coz. Meta always calculates `can`, `cad`, if populated
from pay [alg,now,tmb,typ] are copied, and calculates `czd` if `sig` is set. Pay
must be set even if it is an empty object. Either Coz.Pay.Alg or parameter alg
must be set. If Coz.Sig is populated, `czd` is set. The empty coz (A coz with
an empty pay but sig is set) is legitimate input for Meta.  

Errors when
1. Pay doesn't exist. 
2. No alg is given (both coz.pay.alg and alg are empty).
3. Pay.Alg doesn't match parameter alg if both are set.

Meta does no cryptographic verification.
@param  {Coz}      coz      coz.
@param  {Alg}       [alg]    coz.pay.alg takes precedence.
@return {Meta}               Meta object [alg,now,tmb,typ,can,cad,sig,czd].
@throws {error}              
 */
async function Meta(coz, alg) {
	if (isEmpty(coz.pay)) {
		throw new Error("Meta: coz.pay must exist.")
	}
	let meta = {}

	// Alg check section. Assumes later call to CanonicalHas64() errors on bad or empty alg.  
	if (isEmpty(alg)) {
		if (isEmpty(coz.pay.alg)) {
			throw new Error("Meta: either coz.pay.alg or parameter alg must be set.")
		}
		meta.alg = coz.pay.alg
	} else {
		meta.alg = alg
	}
	if (!isEmpty(coz.pay.alg) && meta.alg !== coz.pay.alg) {
		throw new Error(`Meta: coz.pay.alg (${coz.pay.alg}) and parameter alg (${alg}) do not match. `)
	}

	if (!isEmpty(coz.pay.now)) {
		meta.now = coz.pay.now
	}
	if (!isEmpty(coz.pay.tmb)) {
		meta.tmb = coz.pay.tmb
	}
	if (!isEmpty(coz.pay.typ)) {
		meta.typ = coz.pay.typ
	}

	meta.can = await Can.Canon(coz.pay)
	meta.cad = await Can.CanonicalHash64(coz.pay, Enum.HashAlg(meta.alg));
	if (!isEmpty(coz.sig)) {
		meta.sig = coz.sig
		meta.czd = await Can.CanonicalHash64({
			cad: meta.cad,
			sig: meta.sig
		}, Enum.HashAlg(meta.alg));
	}

	return meta;
}


///////////////////////////////////
// Base Conversion
///////////////////////////////////

/**
Converts a string (UTF-8) to an ArrayBuffer.
@param  {string}        string
@return {ArrayBuffer}
 */
async function SToArrayBuffer(string) {
	return new TextEncoder().encode(string).buffer; // Suppose to be always in UTF-8
}

/**
B64uToArrayBuffer takes a b64 (truncated or not truncated, padded or not
padded) UTF-8 string and decodes it to an ArrayBuffer.
@param   {B64}          string 
@returns {ArrayBuffer}
 */
function B64uToArrayBuffer(string) {
	return B64ToUint8Array(string).buffer;
};

/**
B64ToUint8Array takes a b64 string (truncated or not truncated, padded or not
padded) and decodes it back into a string.
@param   {B64}          string 
@returns {Uint8Array}
 */
function B64ToUint8Array(string) {
	// Make sure that the encoding is canonical.  See issue "Enforce Canonical
	// Base64 encoding" https://github.com/Cyphrme/Coz/issues/18. Alternatively
	// to this method, we could write our own encoder as Mozilla suggests.
	// https://developer.mozilla.org/en-US/docs/Glossary/Base64#solution_1_%E2%80%93_escaping_the_string_before_encoding_it
	string = string.replace(/-/g, '+').replace(/_/g, '/')

	let reencode = btoa(atob(string)).replace(/=/g, '')
	if (reencode !== string) {
		throw new Error('Non-canonical base64 string');
	}

	// atob doesn't care about the padding character '=', but does not like URI
	// encoding.  
	return Uint8Array.from(atob(string), c => c.charCodeAt(0));
};

/**
ArrayBufferTo64ut returns a b64 string from an Array buffer.
@param   {ArrayBuffer} buffer  Arbitrary bytes. UTF-16 is Javascript native.
@returns {B64}
 */
function ArrayBufferTo64ut(buffer) {
	return btoa(String.fromCharCode.apply(null, new Uint8Array(buffer))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}


///////////////////////////////////
// Helpers - Taken from Cyphr.me
///////////////////////////////////

/**
isEmpty is a helper function to determine if thing is empty. 

Functions are considered always not empty. 

Arrays: Only if an array has no elements it is empty.  isEmpty does not check
element contents.  (For item contents, do: `isEmpty(array[0])`)

Objects are empty if they have no keys. (Returns len === 0 of object keys.)

NaN returns true.  (NaN === NaN is always false, as NaN is never equal to
anything. NaN is the only JavaScript value unequal to itself.)

Don't use on HTMl elements. For HTML elements, use the !== equality check
(element !== null). TODO fix this

Cannot use CryptoKey with this function since (len === 0) always. 
@param   {any}     thing    Thing you wish was empty.  
@returns {boolean}          Boolean.  
*/
function isEmpty(thing) {
	if (typeof thing === 'function') {
		return false
	}

	if (Array.isArray(thing)) {
		if (thing.length == 0) {
			return true
		}
	}

	if (thing === Object(thing)) {
		if (Object.keys(thing).length === 0) {
			return true
		}
		return false
	}

	if (!isBool(thing)) {
		return true
	}
	return false
}


/**
isBool is a helper function to determine boolean.  

Javascript, instead of considering everything false except a few key words,
decided everything is true instead of a few key words.  Why?  Because
Javascript.  This function inverts that assumption, so that everything can be
considered false unless true. 
@param   {any}      bool   Thing that you wish was a boolean.  
@returns {boolean}         An actual boolean.
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
		return false
	}
	return true
}


// MaxSafeTimestamp is the maximum valid timestamp value: 2^53 - 1.
const MaxSafeTimestamp = 9007199254740991;

// RVK_MAX_SIZE is the maximum allowed payload size in bytes for revoke
// messages.  Prevents DoS via oversized revoke payloads.  Set to 0 to
// disable.  Default is 2048 bytes.  Matches Go's coz.RVK_MAX_SIZE.
let RVK_MAX_SIZE = 2048;


/**
validateTimestamp checks whether a timestamp is within the allowed range
[0, 2^53 - 1].  Throws if invalid.  Matches Go's Timestamp.Valid().
@param   {number}  t  Timestamp value.
@throws  {Error}      If t is outside the valid range.
 */
function validateTimestamp(t) {
	if (t < 0 || t > MaxSafeTimestamp) {
		throw new Error(`validateTimestamp: value ${t} is invalid. Must be between 0 and ${MaxSafeTimestamp} inclusive`);
	}
}