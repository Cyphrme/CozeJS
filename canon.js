"use strict";

import * as BSCNV from './base_convert.js';
import {isEmpty} from './coze.js';

export {
	Canon,
	Canons,
	GenCanon,
	CH,
	CHH,
}

/**
* @typedef  {Array|Object} Canon - An array or object representing a canon.  If object, only the first level keys are used as canon.  
*/

/**
 * Canon canonicalizes the first level of "object" into the form of "can". If
 * "can" is empty, the canon is generated from "object"'s first level fields.
 *
 * If input "can" is an object the first level object keys will be used as the
 * canon.
 * 
 * @param   {Object}         object    Object to be canonicalized.   
 * @param   {Array|Object}   [can]     Array|Object. Array|Object canon. 
 * @returns {Object}                   Object. Canonicalized object.
 */
async function Canon(object, can) {
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

	c.sort(); // Sorts in place.  

	let obj = {};
	for (const e of c) {
		obj[e] = object[e];
	}

	return obj
};

/**
 * Canons canonicalizes obj and returns a JSON string. 
 *
 * @param   {Object}   obj         Object being canonicalized.
 * @param   {Array}    [canon]     Array.  Optional canon.[Optional]
 * @returns {string}               String.
 */
 async function Canons(obj, can) {
	return JSON.stringify(await Canon(obj, can));
};


/**
 * GenCanon returns the sorted array canon from the first level object keys.  
 * 
 * @param   {Object} obj           Object to create the canon from.   
 * @returns {Array}                Array. Canon of object.
 */
function GenCanon(obj) {
	let can = Object.keys(obj);
	can.sort(); // Sorts in place
	return can;
}


/**
 * CH, CanonicalHash, returns an array buffer of a digest.  See docs on Canons.
 *
 * @param   {Object|String} obj                Object. being canonicalized.
 * @param   {string}        [digest=SHA-256]   String. Must be SubtleCrypto.digest() compatible.  (i.e. 'SHA-256') [Optional]
 * @param   {array}         [canon]            Array. for canonical keys. [Optional]
 * @returns {ArrayBuffer}                      ArrayBuffer. of the digest.  
 */
async function CH(obj, digest, can) {
	if (typeof obj == "string") {
		obj = JSON.parse(obj);
	}

	let string = await Canons(obj, can);
	if (isEmpty(digest)) {
		digest = 'SHA-256';
	}
	let ab = await BSCNV.SToArrayBuffer(string)
	ab = await crypto.subtle.digest(digest, ab);
	return ab;
}

/**
 * CHH, CanonicalHashHex, returns the hex of the digest.  See docs on Canonical.
 *
 * @param {Object|String} obj           Object being canonicalized.
 * @param {String}        [digest]      Subtle crypto compatible digest that's being used.  (i.e. 'SHA-256') [Optional]
 * @param {Array}         [canon]       Array for canonical keys. [Optional]
 * @param {String}                      Hex (string) of the digest.  
 */
async function CHH(obj, digest, can) {
	let ab = await CH(obj, digest, can);
	let hex = await BSCNV.ArrayBufferToHex(ab);

	return hex;
}
