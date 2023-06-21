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
@typedef {import('./typedef.js').Hsh}     Hsh
@typedef {import('./typedef.js').Dig}     Dig
@typedef {import('./typedef.js').Can}     Can
 */

/**
Canon returns the canon from first level object keys.
@param   {object} obj      Object to create the canon from.
@returns {Can}
 */
function Canon(obj) {
	return Object.keys(obj);
}

/**
Canon canonicalizes the first level of "object" into the form of "can". 

Can may be an array or object.  If object, only the first level keys are used as
canon.  If given cannon is array, array is converted to object for field
deduplication.
@param   {object}         object    Object to be canonicalized.
@param   {Can|object}     [can]     Array|Object canon.
@returns {object}                   Canonicalized object.
@throws  {error}                    Fails on invalid canon.
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
CanonicalS canonicalizes obj and returns a JSON string.
@param   {object}   obj
@param   {Can}      [can]
@returns {string}
@throws  {error}
 */
async function CanonicalS(obj, can) {
	return JSON.stringify(await Canonical(obj, can));
}

/**
CanonicalHash puts input into canonical form and returns the array buffer of
the digest.
@param   {object}        input     Object being canonicalized.
@param   {Hsh}           hash      Must be SubtleCrypto.digest() compatible (i.e. 'SHA-256').
@param   {Can}           [can]     Array for canonical keys.
@returns {ArrayBuffer}             ArrayBuffer of the digest.
@throws  {error}                   Fails if hash is not given or invalid for SubtleCrypto.digest().
 */
async function CanonicalHash(input, hash, can) {
	if (isEmpty(hash)) {
		throw new Error("Hash is not given");
	}
	return await crypto.subtle.digest(hash, await SToArrayBuffer(await CanonicalS(input, can)));
}

/**
CanonicalHash64 wraps CanonicalHash to return b64ut digest. 
@param   {object}         obj
@param   {Hsh}            hash
@param   {Can}            [canon]
@returns {Dig}
@throws  {error}
 */
async function CanonicalHash64(obj, hash, can) {
	return await ArrayBufferTo64ut(await CanonicalHash(obj, hash, can));
}