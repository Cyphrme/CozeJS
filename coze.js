"use strict";

import * as Can from './canon.js'; // import as "Can" since func "Canon" will conflict in `coze.join.js`. 
import * as Enum from './coze_enum.js';
import * as CZK from './coze_key.js';
import * as CTK from './cryptokey.js';
import * as BSCNV from './base_convert.js';

export {
	Sign,
	SignCy,

	Verify,
	VerifyCy,
	VerifyCyArray,

	GetCyParts,

	HeadCanon,
	MsgCanon,

	// Helpers
	isEmpty,
	isBool,
}

// HeadCanon is the minimum required fields for a valid signed cy.head.
// MsgCanon is the canon for the "msg" cy.  
const HeadCanon = ["alg", "iat", "tmb", "typ"];
const MsgCanon = ["alg", "iat", "msg", "tmb", "typ"];

/**
@typedef {import('./coze_key.js').CozeKey} CozeKey
@typedef {import('./coze_enum.js').Alg}    Alg

Basic Coze Types
@typedef  {String} Hex   - Coze Hex. Hex is upper case and always left padded. 
@typedef  {Hex}    Sig   - The signature.   
@typedef  {number} Time  - The Unix time.

head is the minimum `cy.head` object.  `cy.head` or just `head` may have
more fields, but a signed coze should minimally have these.  
@typedef  {Object} head  
@property {Alg}    alg  - Cryptographic signing or encryption algorithm - e.g. "ES256".
@property {Time}   iat  - Unix time message was signed or encrypted. e.g. 1624472390.
@property {Hex}    tmb  - Signing thumbprint digest e.g. 0148F4CD9093C9CBE3E8BF78D3E6C9B824F11DD2F29E2B1A630DD1CE1E176CDD.
@property {String} typ  - Coze object type.  e.g. "cyphr.me/msg/create".

cy is a signed or encrypted coze object.  See docs for more about `cy`.
@typedef  {Object}  cy    
@property {head}    head   - The `head`.  See head.  
@property {Sig}     sig    - The Hex signature.  
@property {Hex}     [cad]  - The canon digest, which is the digest of the canon fields of head.  `cad` may be implicit and not appear in a `cy`.  e.g. ADE8A110C0DC90CAA509CC20213DDF75D6FD5C9920079C79AB6FB15240FFE0A9
@property {Array}   [can]  - The canon fields of head.  `can` may be implicit and not appear in a `cy`. e.g.  ["alg", "iat", "msg", "tmb", "typ"]
@property {CozeKey} [key]  - Public Coze Key used in signing the `cy`.   `key` may be implicit, by `cy.head.tmb`, and not appear in a `cy`.
*/

/**
 * Sign signs a given `head` with a given private Coze key and returns Hex sig.
 * `head` will be updated with correct values for:
 * 1. `alg` based on key.
 * 2. `iat` to now.
 * 3. `tmb` recalculated from key.
 * @param   {head}    head       `head` object/string.
 * @param   {CozeKey} cozeKey    Private coze key.        
 * @param   {Array}   [canon]    Canon. [Optional]      
 * @returns {Hex}                Hex `sig`.  Empty on invalid. 
 * @throws  error                invalid key/parse error.  
 */
async function Sign(head, cozeKey, canon) {
	head = await sanitize(head, cozeKey, canon);
	return sign(head, cozeKey);
}

/**
 * SignCy signs `cy.head` with a given private Coze key and returns a new `cy`
 * with `sig` and canonicalized `head` populated.  
 *
 * Why does sSignCy() exist when Sign() already exists?  SignCy returns a
 * canonicalized `cy` while Sign() only returns a signature.  If that's not
 * needed, use `Sign()`: `cy.sig = Sign(cy.head, cozeKey);`
 *
 * @param   {Cy}        cy         Object cy or string cy
 * @param   {CozeKey}   cozeKey    A private coze key.        
 * @param   {Array}     [canon]    Array for canonical keys. [Optional]      
 * @returns {cy}                   Cy.  Empty on invalid. 
 * @throws  error                  invalid key/parse error.  
 */
async function SignCy(cy, cozeKey, canon) {
	// Written like this, instead of calling just Sign(), because although JS
	// objects are pass by reference, the order of keys does not change without
	// resetting object (For example, `function reset(obj){obj={};}` does not
	// reset `obj` because JS is "pass by sharing" and not true pass by reference
	// for objects.)
	let outCy = {};
	outCy.head = await sanitize(cy.head, cozeKey, canon);
	outCy.sig = await sign(outCy.head, cozeKey);
	return outCy;
}

/**
 * sanitize canonicalized head and sets:
 * 1. `alg` based on key.
 * 2. `iat` to now.
 * 3. `tmb` recalculated from key.
 * @param   {head|string}   head       `head` object/string.
 * @param   {CozeKey}       cozeKey    Private coze key.        
 * @param   {Array}         [canon]    Canon. [Optional]      
 * @returns {Hex}                      Hex `sig`.  Empty on invalid. 
 * @throws  error                      invalid key/parse error.  
 */
async function sanitize(head, cozeKey, canon) {
	if (isEmpty(cozeKey)) {
		throw new Error("Coze: Key not set. ");
	}
	if (CZK.IsRevoked(cozeKey)) {
		throw new Error("Coze: Cannot sign with revoked key.");
	}
	head.alg = cozeKey.alg;
	head.tmb = await CZK.Thumbprint(cozeKey);
	head.iat = Math.round((Date.now() / 1000)); // Javascript's Date converted to Unix time.
	return Can.Canon(head, canon); // Guarantees order.
}

/**
 * sign signs a given `obj` with a given private Coze key and returns Hex sig.
 * @param   {Object}   obj       `head` object/string.
 * @param   {CozeKey}  cozeKey    Private coze key.          
 * @returns {Hex}                 Hex `sig`.  Empty on invalid. 
 * @throws  error                 invalid key/parse error.  
 */
async function sign(obj, cozeKey) {
	return CTK.CryptoKey.SignBufferToHex(
		await CTK.CryptoKey.FromCozeKey(cozeKey),
		await BSCNV.SToArrayBuffer(JSON.stringify(obj))
	);
}


/**
 * Verify verifies a `head` with `sig` and returns a boolean.
 *
 * @param  {head}     head       head
 * @param  {CozeKey}  cozekey    CozeKey to use to validate the coze message. 
 * @param  {Sig}      sig        Hex sig.   
 * @return {boolean}             invalid key/parse error. 
 * @throws error
 */
async function Verify(head, cozekey, sig) {
	return CTK.CryptoKey.VerifyABMsgSig(
		await CTK.CryptoKey.FromCozeKeyToPublic(cozekey),
		await BSCNV.SToArrayBuffer(await Can.Canons(head)),
		await BSCNV.HexToArrayBuffer(sig)
	);
};

/**
 * VerifyCy returns a boolean.  Parameter `cy` must have `cy.head` and
 * optionally `cy.sig` and `cy.key`.
 *
 * If parameters `pubkey` or `sig` are set they will respectively overwrite
 * `cy.key` and `cy.sig`.
 * @param  {cy}       cy           `cy` with optional `key` and/or `sig` set.  
 * @param  {CozeKey}  [cozekey]    CozeKey to use to validate the coze message. 
 * @param  {Sig}      [sig]        String.  Hex sig.   
 * @return {boolean}               Valid or not
 * @throws error
 */
async function VerifyCy(cy, pubkey, sig) {
	let p = await GetCyParts(cy, pubkey, sig);

	if (p.head.tmb !== p.key.tmb) {
		throw new Error("Coze.VerifyCy: head.tmb does not match key.tmb.");
	}

	return CTK.CryptoKey.VerifyABMsgSig(
		await CTK.CryptoKey.FromCozeKeyToPublic(p.key),
		await BSCNV.SToArrayBuffer(await Can.Canons(p.head, p.can)),
		await BSCNV.HexToArrayBuffer(p.sig));
};

/**
 * @typedef  {object}  VerifiedArray
 * @property {boolean} VerifiedAll   - Indicates if whole array was verified.  False if anything was not verified or on error.
 * @property {number}  VerifiedCount - Number of objects verified.  
 * @property {number}  FailedCount   - Number of objects that failed verification.  
 * @property {cy[]}    FailedObjs    - Objects that failed verification.
 */

/**
 * VerifyCyArray verifies an array of `cy`s and returns a single "VerifiedArray" object.
 *
 * @param  {cy[]}           cy       - Javascript object.  Coze Javascript Object or string.   
 * @param  {CozeKey}        [pubkey] - Javascript object.  CozeKey.   
 * @return {VerifiedArray}
 * @throws error
 */
async function VerifyCyArray(cy, CozeKeyPublic) {
	if (!Array.isArray(cy)) {
		return VerifyCy(cy, CozeKeyPublic)
	}

	var verifiedObj = {
		VerifiedAll: false,
		VerifiedCount: 0,
		FailedCount: 0,
		FailedObjs: [],
	};

	let copy = [...cy]; // Array copy so original isn't modified. 

	for (let i = 0; i < copy.length; i++) {
		let c = copy[i];
		if (!isEmpty(c.cy)) { // Is message "cy" encapsulated?
			c = c.cy;
		}

		let valid = await VerifyCy(c, CozeKeyPublic);
		if (valid) {
			verifiedObj.VerifiedCount++;
		} else {
			verifiedObj.FailedCount++;
			verifiedObj.FailedObjs.push(copy);
		}
	}

	if (verifiedObj.FailedCount == 0) {
		verifiedObj.VerifiedAll = true;
	}

	return verifiedObj;
};

/**
 * signObj canonicalizes, signs the object, and returns a Hex signature.It may
 * produce invalid Coze that's cryptographically valid.  Performs canon,
 * signing, and returns the Hex of the signature.  The hashing algorithm is
 * defined by the CozeKey.
 *
 * Formerly CHSH, (Canonical Hash Sign Hex).
 *
 * Don't use this function unless you know what you are doing. 
 *
 * @param   {Object|string}  obj       Object to be canonicalized and signed.
 * @param   {CozeKey}        cozeKey   CozeKey object used for signing *and hashing* the Array Buffer. 
 * @param   {Array}          [canon]   Array for canonical keys. [Optional]
 * @returns {Hex}                      Hex of the digest.
 * @throws  {SyntaxError}              JSON parse exception.
 */
async function signObj(obj, cozeKey, canon) {
	if (typeof obj == "string") {
		obj = JSON.parse(obj); // May throw error
	}
	return CTK.CryptoKey.SignBufferToHex(
		await CTK.CryptoKey.FromCozeKey(cozeKey),
		await BSCNV.SToArrayBuffer(await Can.Canons(obj, canon))
	);
};



/**
 * CyParts 
 * 
 * @typedef  {Object}  CyParts
 * @property {head}    head - Coze `head` with `alg`, `iat`, and `tmb` set. 
 * @property {CozeKey} key  - CozeKey.
 * @property {sig}     sig  - Hex sig.  
 * @property {Array}   can  - Array Canon.  e.g. ["alg","x"]
 * @property {Hex}     cad  - "Canon digest" 
 * @property {Hex}     cyd  - "Cy digest" 
 */

/**
 * GetCyParts accepts a `cy`, calculates `cad`, `can`, `cyd` and `tmb`, and
 * returns a CyParts object.
 *
 * The input `cy` must always have the field `head` set.
 * 
 * `cy` may or may not be encapsulated in a `cy` key.  If the field `cy` does
 * not appear in the first level of input `cy` object it is assume that
 * parameter `cy` is a cy object.
 * 
 * The input must also have `cy.key` or parameter "pubkey" and `cy.sig` or
 * parameter "sig".  If both the parameter and the respective cy component is
 * populated (`cy.key` and `pubkey` or `cy.sig` and `sig`) the parameters
 * (pubkey, sig) will overwrite cy components (`cy.key`, `cy.sig`).  If neither
 * are given an error is thrown. 
 *
 * @param  {(cy|string)} cy        Object or string. May be cy or cy.head.   
 * @param  {CozeKey}     [pubkey]  CozeKey that was used to sign the coze message.  
 * @param  {sig}         [sig]     Hex sig.
 * @throws {Error}                 JSON parse exception or other Error.  
 * @return {CyParts}               {head, key, iat, can, cad, cyd, tmb, sig}
 * 
 */
async function GetCyParts(cy, pubkey, sig) {
	// console.log(cy, pubkey, sig); // debugging
	if (Array.isArray(cy)) { // Don't attempt for arrays.
		throw new Error("Coze.GetCyParts: Cy cannot be array.");
	}
	let c = {};
	if (typeof cy == "string") {
		c = JSON.parse(cy); // May throw error
	} else {
		c = {
			...cy
		}; // Copy of original.
	}

	// Is `cy` encapsulated?  If so, unencapsulate.
	if (!isEmpty(c.cy)) {
		c = c.cy;
	}

	/** @type {CyParts} cyp */
	var cyp = {};
	cyp.head = c.head;
	if (isEmpty(cyp.head)) {
		throw new Error("Coze.GetCyParts: A head is not set.");
	}

	// if set, pubkey overwrites key. 
	if (!isEmpty(pubkey)) {
		cyp.key = await CZK.ToPublicCozeKey(pubkey); // sanitizes and recalcs tmb
	} else {
		cyp.key = await CZK.ToPublicCozeKey(c.key); // sanitizes and recalcs tmb
	}
	if (isEmpty(cyp.key)) {
		throw new Error("Coze.GetCyParts: A public key is not set.");
	}
	if (cyp.head.tmb !== cyp.key.tmb) {
		throw new Error("Coze.GetCyParts: `head.tmb` does not match `key.tmb`.");
	}

	if (!isEmpty(sig)) {
		cyp.sig = sig;
	}else{
		cyp.sig = c.sig;
	}
	if (isEmpty(cyp.sig)) {
		throw new Error("Coze.GetCyParts: A sig is not set.");
	}

	// If can is empty, recalculate `can` based on current head. 
	if (isEmpty(c.can)) {
		cyp.can = await Can.GenCanon(cyp.head);
	} else {
		cyp.can = c.can;
	}

	// Calculate cad
	cyp.cad = await BSCNV.ArrayBufferToHex(await Can.CH(c.head, Enum.HashAlg(c.head.alg), c.can));

	// Calculate cyd
	let cydIn = '{"cad":"' + cyp.cad + '","sig":"' + cyp.sig + '"}';
	let cydab = await crypto.subtle.digest(Enum.HashAlg(cyp.head.alg), await BSCNV.SToArrayBuffer(cydIn));
	cyp.cyd = await BSCNV.ArrayBufferToHex(cydab);

	return cyp;
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