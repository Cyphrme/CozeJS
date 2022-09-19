"use strict";

import {
	isEmpty,
	SToArrayBuffer,
	ArrayBufferTo64ut
} from './coze.js';

export {
	Canon,
	Canonical,
	CanonicalS,
	CanonicalHash,
	CanonicalHash64,
}

/**
 * @typedef {import('./typedefs.js').Digest}  Digest
 * @typedef {import('./typedefs.js').Hash}    Hash
 * @typedef {import('./typedefs.js').Canon}   Canon
 */

/**
 * Canon returns the canon from first level object keys.
 * 
 * @param   {Object} obj      Object to create the canon from.
 * @returns {Canon}
 */
function Canon(obj) {
	return Object.keys(obj);
}

/**
 * Canon canonicalizes the first level of "object" into the form of "can".
 * 
 * @param   {Object}  object    Object to be canonicalized.
 * @param   {Canon}   [can]     Array|Object canon.
 * @returns {Object}            Canonicalized object.
 * @throws  {Error}             Fails on invalid canon.
 */
async function Canonical(object, can) {
	if (isEmpty(can)) {
		return object;
	}

	let obj = {};
	for (const e of can) {
		obj[e] = object[e];
	}
	return obj;
}

/**
 * Returns whether or not the Canon has duplicate fields.
 *
 * @param   {Canon}    can
 * @returns {Boolean}
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
 * CanonicalS canonicalizes obj and returns a JSON string.
 *
 * @param   {Object}   obj
 * @param   {Canon}    [canon]
 * @returns {String}
 */
async function CanonicalS(obj, can) {
	return JSON.stringify(await Canonical(obj, can));
}

/**
 * CanonicalHash puts input into canonical form and returns the array buffer of
 * the digest.
 *
 * @param   {Object}        input     Object being canonicalized.
 * @param   {Hash}          hash      Must be SubtleCrypto.digest() compatible (i.e. 'SHA-256').
 * @param   {Canon}         [canon]   Array for canonical keys.
 * @returns {ArrayBuffer}             ArrayBuffer of the digest.
 * @throws  {Error}                   Fails if hash is not given.
 */
async function CanonicalHash(input, hash, can) {
	if (isEmpty(hash)) {
		throw new Error("Hash is not given");
	}
	return await crypto.subtle.digest(hash, await SToArrayBuffer(await CanonicalS(input, can)));
}

/**
 * CanonicalHash64 returns the b64ut digest. See docs on Canonical.
 *
 * @param   {Object|String}  obj         Object being canonicalized.
 * @param   {Hash}           [hash]      Subtle crypto compatible digest that's being used (i.e. 'SHA-256').
 * @param   {Canon}          [canon]     Array for canonical keys.
 * @returns {Digest}                     B64 encoded string of digest.
 */
async function CanonicalHash64(obj, hash, can) {
	return await ArrayBufferTo64ut(await CanonicalHash(obj, hash, can));
}