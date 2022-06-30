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
@typedef {import('./alg.js').Alg}     Alg
@typedef {import('./canon.js').Canon} Canon

Basic Coze Types
@typedef  {String} B64       - Coze b64ut (RFC 4648 base64 url truncated)
@typedef  {String} Message   - A not-hashed message to be signed. 
@typedef  {B64}    Digest    - A digest in b64ut.
@typedef  {B64}    Sig       - The signature.   
@typedef  {Number} Time      - The Unix time.

Pay contains the standard `Coze.Pay` fields.  
@typedef  {Object} Pay  
@property {Alg}    alg  - Algorithm -           e.g. "ES256".
@property {Time}   iat  - Unix time of signing. e.g. 1623132000.
@property {Hex}    tmb  - Signing thumbprint    e.g. cLj8vsYtMBwYkzoFVZHBZo6SNL8wSdCIjCKAwXNuhOk
@property {String} typ  - Type.                 e.g. "cyphr.me/msg/create".

Coze is a signed coze object.  See docs for more about `coze`.
@typedef  {Object}  Coze    
@property {Pay}     pay    - The `pay`.  See Pay.  
@property {Sig}     sig    - The Hex signature.  
@property {B64}     [cad]  - Canonical digest of `pay`.     e.g. LSgWE4vEfyxJZUTFaRaB2JdEclORdZcm4UVH9D8vVto
@property {Array}   [can]  - The canon fields of pay.       e.g.  ["alg", "iat", "msg", "tmb", "typ"]
@property {B64}     [czd]  - Coze digest.
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
 * @param   {String}        message    message object/string.
 * @param   {CozeKey}       cozeKey    Private coze key.        
 * @returns {B64}                      b64ut `sig`.  Empty on invalid. 
 * @throws  error                      invalid key/parse error.  
 */
async function Sign(message, cozeKey) {
	let cryptokey = await CTK.CryptoKey.FromCozeKey(cozeKey);
	return CTK.CryptoKey.SignBufferB64(
		cryptokey,
		await SToArrayBuffer(message)
	);
}

/**
 * SignCoze signs in place coze.pay with a private Coze key. Returns the same,
 * but updated, coze.
 * 
 * `pay` will be updated with values for:
 * 1. `alg` based on key.
 * 2. `iat` to now.
 * 3. `tmb` recalculated from key.
 *
 * @param   {Coze}      coze       Object coze or string coze
 * @param   {CozeKey}   cozeKey    A private coze key.        
 * @param   {Array}     [canon]    Array for canonical keys. [Optional]
 * @returns {coze}                 The same coze as input.
 * @throws  error                  invalid key/parse error.  
 */
async function SignCoze(coze, cozeKey, canon) {
	if (CZK.IsRevoked(cozeKey)) {
		throw new Error("Coze: Cannot sign with revoked key.");
	}

	coze.pay.alg = cozeKey.alg;
	coze.pay.iat = Math.round((Date.now() / 1000)); // Javascript's Date converted to Unix time.
	coze.pay.tmb = await CZK.Thumbprint(cozeKey);


	if (!isEmpty(canon)) {
		coze.pay = await Can.Canonical(coze.pay, canon);
	}
	let pay = await JSON.stringify(coze.pay);
	console.log(pay);
	coze.sig = await Sign(pay, cozeKey);
	return coze;
}




/**
 * Verify verifies a `pay` with `sig` and returns a boolean.
 *
 * @param  {String}   message    Message
 * @param  {CozeKey}  cozekey    Coze key for message validation. 
 * @param  {Sig}      sig        Signature.   
 * @return {boolean}             invalid key/parse error. 
 * @throws error
 */
async function Verify(message, cozekey, sig) {
	let cryptoKey = await CTK.CryptoKey.FromCozeKey(cozekey, true);
	// console.log(message, cozekey, sig, cryptoKey);
	return CTK.CryptoKey.VerifyMsg(
		cryptoKey,
		message,
		sig,
	);
};

/**
 * VerifyCoze returns a boolean.  Parameter `coze` must have `coze.pay` and
 * optionally `coze.sig` and `coze.key`.
 *
 * If parameters `pubkey` or `sig` are set they will respectively overwrite
 * `coze.key` and `coze.sig`.
 * @param  {Coze}     coze         `coze` with optional `key` and/or `sig` set.  
 * @param  {CozeKey}  [cozeKey]    CozeKey to use to validate the coze message. 
 * @param  {Sig}      [sig]        String.  Hex sig.   
 * @return {boolean}               Valid or not
 * @throws error
 */
async function VerifyCoze(coze, cozeKey) {
	if (coze.pay.tmb !== cozeKey.tmb) {
		throw new Error("Coze.VerifyCoze: pay.tmb does not match key.tmb.");
	}
	let pay = await JSON.stringify(coze.pay);
	return Verify(pay, cozeKey, coze.sig);
}





/**
 * VerifyCozeArray verifies an array of `coze`s and returns a single "VerifiedArray" object.
 *
 * @param  {coze[]}           coze       - Javascript object.  Coze Javascript Object or string.   
 * @param  {CozeKey}        [pubkey] - Javascript object.  CozeKey.   
 * @return {VerifiedArray}
 * @throws error
 */
async function VerifyCozeArray(coze, CozeKeyPublic) {
	if (!Array.isArray(coze)) {
		return VerifyCoze(coze, CozeKeyPublic)
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

		let valid = await VerifyCoze(c, CozeKeyPublic);
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
Meta recalculates [can, cad, czd], for a given `coze`. Coze.Pay,
Coze.Pay.Alg, and Coze.Sig must be set.  Meta does no cryptographic
verification.
 *
 * The input `coze` must always have the field `pay` set.
 *
 * Input variable `coze` may or may not be encapsulated in a `coze` JSON name.
 * If the field `coze` does not appear in the first level of input `coze` object
 * it is assume that parameter `coze` is a coze object.
 *
 * The input must also have `coze.key` or parameter "pubkey" and `coze.sig` or
 * parameter "sig".  If both the parameter and the respective coze component is
 * populated (`coze.key` and `pubkey` or `coze.sig` and `sig`) the parameters
 * (pubkey, sig) will overwrite coze components (`coze.key`, `coze.sig`).  If
 * neither are given an error is thrown. 
 *
 * @param  {coze}      coze          coze.   
 * @throws {Error}                   JSON parse exception or other Error.  
 * @return {Meta}                    {pay, key, iat, can, cad, czd, tmb, sig}
 * 
 */
async function Meta(coze) {
	// console.log(coze, pubkey, sig); // debugging
	// Old, probably move to the sign verify page.
	// 	if (Array.isArray(coze)) { // Don't attempt for arrays.
	// 		throw new Error("Coze.Meta: Coze cannot be array.");
	// 	}
	// 	let c = {};
	// 	if (typeof coze == "string") {
	// 		c = JSON.parse(coze); // May throw error
	// 	} else {
	// 		c = {
	// 			...coze
	// 		}; // Copy of original.
	// 	}

	// 	// Is `coze` "coze" encapsulated?  If so, unencapsulate.
	// 	if (!isEmpty(c.coze)) {
	// 		c = c.coze;
	// 	}

	// 	/** @type {Meta} meta */
	// 	var meta = {};
	// 	meta.pay = c.pay;
	// 	if (isEmpty(meta.pay)) {
	// 		throw new Error("Coze.Meta: A pay is not set.");
	// 	}

	// 	// If set, pubkey overwrites key. 
	// 	if (!isEmpty(pubkey)) {
	// 		meta.key = await CZK.ToPublicCozeKey(pubkey); // sanitizes and recalcs tmb
	// 	} else {
	// 		meta.key = await CZK.ToPublicCozeKey(c.key); // sanitizes and recalcs tmb
	// 	}
	// 	if (isEmpty(meta.key)) {
	// 		throw new Error("Coze.Meta: A public key is not set.");
	// 	}
	// console.log(meta.pay.tmb !== meta.key.tmb);

	// 	if (meta.pay.tmb !== meta.key.tmb) {
	// 		throw new Error("Coze.Meta: `pay.tmb` does not match `key.tmb`.");
	// 	}

	// 	if (!isEmpty(sig)) {
	// 		meta.sig = sig;
	// 	} else {
	// 		meta.sig = c.sig;
	// 	}
	// 	if (isEmpty(meta.sig)) {
	// 		throw new Error("Coze.Meta: A sig is not set.");
	// 	}


	coze.can = await Can.Canon(coze.pay);

	// TODO serialize don't call cannon hash
	// Calculate cad
	coze.cad = await Coze.ArrayBufferTo64ut(await Can.CanonicalHash(coze.pay, Enum.HashAlg(coze.pay.alg)));

	// Calculate czd
	let czdIn = await Coze.SToArrayBuffer('{"cad":"' + coze.cad + '","sig":"' + coze.sig + '"}');
	coze.czd = await Coze.ArrayBufferTo64ut(await crypto.subtle.digest(Enum.HashAlg(coze.pay.alg), czdIn));
	return coze;
}



///////////////////////////////////
// Base Conversion
///////////////////////////////////
/**
 * Converts a string to an ArrayBuffer.   
 *
 * @param  {string}        String.
 * @return {ArrayBuffer}
 */
 async function SToArrayBuffer(string) {
	var enc = new TextEncoder(); // Suppose to be always in UTF-8
	return enc.encode(string).buffer;
}

/**
 * B64uToArrayBuffer takes a b64u (truncated or not truncated) string and decodes it to an ArrayBuffer. 
 * 
 * @param   {B64} string 
 * @returns {ArrayBuffer}
 */
 function B64uToArrayBuffer(string) {
	// atob doesn't care about the padding character '='
	return Uint8Array.from(atob(string.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0)).buffer;
};

/**
 * B64utToUint8Array takes a b64ut string and decodes it back into a string.
 * 
 * @param   {B64} string 
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
// Helpers
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