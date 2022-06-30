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
 * // TODO logic for optional canon.
 * Canon canonicalizes the first level of "object" into the form of "can". If
 * "can" is empty, the canon is generated from "object"'s first level fields.
 *
 * If input "can" is an object the first level object keys will be used as the
 * canon.
 * 
 * @param   {Object}         object    Object to be canonicalized.   
 * @param   {Canon}          [can]     Array|Object. Array|Object canon. 
 * @returns {Object}                   Object. Canonicalized object.
 */
async function Canonical(object, can) {
	let c = [];
	if (typeof can === 'object') {
		c = Object.keys(can);
	}

	// Is canon empty?  Use current object keys. 
	if (!can || can.length === 0) {
		c = Object.keys(object);
	} else {
		c = can;
	}

	let obj = {};
	for (const e of c) {
		obj[e] = object[e];
	}

	return obj
};

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
 * @param   {Object|String} input              Object being canonicalized.
 * @param   {HashAlg}       [digest=SHA-256]   String. Must be SubtleCrypto.digest() compatible.  (i.e. 'SHA-256') [Optional]
 * @param   {Canon}         [canon]            Array. for canonical keys. [Optional]
 * @returns {ArrayBuffer}                      ArrayBuffer. of the digest.  
 */
async function CanonicalHash(input, digest, can) {
	if (isEmpty(digest)) {
		digest = 'SHA-256';
	}
	if (typeof input == "string") {
		input = JSON.parse(input);
	}

	let ab = await Coze.SToArrayBuffer(await CanonicalS(input, can))
	return await crypto.subtle.digest(digest, ab);
}

/**
 * CanonicalHash64 returns the b64ut of the digest.  See docs on Canonical.
 *
 * @param {Object|String} obj           Object being canonicalized.
 * @param {String}        [digest]      Subtle crypto compatible digest that's being used.  (i.e. 'SHA-256') [Optional]
 * @param {Canon}         [canon]       Array for canonical keys. [Optional]
 * @param {String}                      Hex (string) of the digest.  
 */
async function CanonicalHash64(obj, digest, can) {
	let ab = await CanonicalHash(obj, digest, can);
	return await Coze.ArrayBufferTo64ut(ab);
}