"use strict";

import * as Coze from './coze.js';

export {
	Canon,
	Canonical,
	CanonicalS,
	CanonicalHash,
	CanonicalHash64,
}

/**
 * @typedef {import('./coze.js').Digest} Digest
 * @typedef {import('./alg.js').Hash} Hash
 */

/**
 * An array or object representing a canon.
 * If object, only the first level keys are used as canon.
 * @typedef  {Array|Object} Canon
 */

/**
 * Canon returns the canon from first level object keys.
 * 
 * @param   {Object}          obj      Object to create the canon from.
 * @returns {Array<String>}
 */
function Canon(obj) {
	return Object.keys(obj);
}

/**
 * Canon canonicalizes the first level of "object" into the form of "can".
 * Returns the canonicalized object.
 * Fails on invalid canon.
 *
 * @param   {Object}  object    Object to be canonicalized.
 * @param   {Canon}   [can]     Array|Object canon.
 * @returns {Object}
 * @throws  {Error}
 */
async function Canonical(object, can) {
	if (Coze.isEmpty(can)) {
		return;
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
 * @param   {Canon}    can     Array|Object canon.
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
 * Canonical canonicalizes obj and returns a JSON string.
 *
 * @param   {Object}   obj         Object being canonicalized.
 * @param   {Canon}    [canon]     Optional canon.
 * @returns {String}
 */
async function CanonicalS(obj, can) {
	return JSON.stringify(await Canonical(obj, can));
}

/**
 * CanonicalHash put input into canonical form and returns the array buffer of
 * the digest.
 * Fails if hash is not given.
 *
 * @param   {Object}        input     Object being canonicalized.
 * @param   {Hash}          hash      Must be SubtleCrypto.digest() compatible (i.e. 'SHA-256').
 * @param   {Canon}         [canon]   Array for canonical keys.
 * @returns {ArrayBuffer}
 * @throws  {Error}
 */
async function CanonicalHash(input, hash, can) {
	if (Coze.isEmpty(hash)) {
		throw "Hash is not given";
	}
	return await crypto.subtle.digest(hash, await Coze.SToArrayBuffer(await CanonicalS(input, can)));
}

/**
 * CanonicalHash64 returns the b64ut digest. See docs on Canonical.
 *
 * @param   {Object|String}  obj         Object being canonicalized.
 * @param   {Hash}           [hash]      Subtle crypto compatible digest that's being used (i.e. 'SHA-256').
 * @param   {Canon}          [canon]     Array for canonical keys.
 * @returns {Digest}
 */
async function CanonicalHash64(obj, hash, can) {
	return await Coze.ArrayBufferTo64ut(await CanonicalHash(obj, hash, can));
}