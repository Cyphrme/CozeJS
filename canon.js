"use strict";

import * as Coze from './coze.js';
import {
	isEmpty
} from './coze.js';

export {
	Canon,
	Canonical,
	CanonicalS,
	CanonicalHash,
	CanonicalHash64,
}

/**
 * @typedef  {Array|Object} Canon - An array or object representing a canon.  If object, only the first level keys are used as canon. 
 * @typedef  {import('./coze.js').Digest} Digest
 * @typedef  {import('./alg.js').Hash}    Hash
 */


/**
 * Canon returns the canon from first level object keys.  
 * 
 * @param   {Object}          obj      Object to create the canon from.
 * @returns {Array<String>}            Array. 
 */
function Canon(obj) {
	return Object.keys(obj);
}

/**
 * Canon canonicalizes the first level of "object" into the form of "can".
 *
 * @param   {Object}  object    Object to be canonicalized.
 * @param   {Canon}   [can]     Array|Object. Array|Object canon.
 * @returns {Object}            Object. Canonicalized object.
 * @throws  {Error}             Error. Fails on invalid Canons.
 */
async function Canonical(object, can) {
	if (isEmpty(can)) {
		return;
	}

	let obj = {};
	for (const e of can) {
		obj[e] = object[e];
	}
	return obj;
};


/**
 * Returns whether or not the Canon has duplicate fields.
 *
 * @param   {Canon}    can     Array|Object. Array|Object canon.
 * @returns {Boolean}          Boolean. Whether or not there are duplicates.
 */
function HasDuplicates(can) {
	let result = [];
	for (let v of can) {
		if (result.includes(v)) {
			return true;
		}
		result.push(v);
	}
	return false;
}

/**
 * Canonical canonicalizes obj and returns a JSON string.
 *
 * @param   {Object}   obj         Object being canonicalized.
 * @param   {Canon}    [canon]     Array.  Optional canon.[Optional]
 * @returns {string}               String.
 */
async function CanonicalS(obj, can) {
	return JSON.stringify(await Canonical(obj, can));
};

/**
 * CanonicalHash put input into canonical form and returns digest.
 *
 * @param   {Object}        input     Object being canonicalized.
 * @param   {Hash}          hash      String. Must be SubtleCrypto.digest() compatible. (i.e. 'SHA-256') [Optional]
 * @param   {Canon}         [canon]   Array. for canonical keys. [Optional]
 * @returns {ArrayBuffer}             ArrayBuffer. of the digest.
 * @throws  {Error}                   Error if hash is not given.
 */
async function CanonicalHash(input, hash, can) {
	if (isEmpty(hash)) {
		throw "Hash is not given";
	}

	return await crypto.subtle.digest(hash, await Coze.SToArrayBuffer(await CanonicalS(input, can)));
}

/**
 * CanonicalHash64 returns the b64ut of the digest. See docs on Canonical.
 *
 * @param   {Object|String}  obj         Object being canonicalized.
 * @param   {Hash}           [hash]      Subtle crypto compatible digest that's being used.  (i.e. 'SHA-256') [Optional]
 * @param   {Canon}          [canon]     Array for canonical keys. [Optional]
 * @returns {Digest}                     B64 Digest.
 */
async function CanonicalHash64(obj, hash, can) {
	return await Coze.ArrayBufferTo64ut(await CanonicalHash(obj, hash, can));
}