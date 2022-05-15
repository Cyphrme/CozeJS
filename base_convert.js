// base_convert.js is taken from https://github.com/zamicol/BaseConverter and
// Cyphr.me's `base_convert.js`.
//
// Since base conversion is tightly coupled to Coze, instead of importing an
// external project/repo, this file is copied directly into this project.
// However, most of these functions are not exported into the Coze module since
// Coze isn't about base conversion.  See `join.js` for selected exported
// functions that are useful when interacting with Coze.   
//
// If you need general base conversion, see Cyphr.me's `base_convert.js` or
// `convert.zamicol.com`.  
"use strict";

// Needed in Coze:
export {
	// Hex
	ArrayBufferToHex,
	HexToArrayBuffer,
	SToArrayBuffer,

	// RFC base 64s
	HexTob64ut,
	B64ToHex,
}

/**
 * @typedef {import('./coze.js').Hex}  Hex
 * 
 * Unsafe base64 truncated isn't a thing.  If needed, use b64ut instead. 
 * @typedef {String} ub64     - Unsafe base 64.  Includes padding. 
 * @typedef {String} b64u     - base 64 url.  Includes padding. 
 * @typedef {String} b64ut    - base 64 url truncated.  Excludes padding. 
 * @typedef {String} Base64   - Cyphr.me Base64.  
 **/

/**
 * Converts a string to an ArrayBuffer.   
 *
 * @param  {string}        String.
 * @return {ArrayBuffer}
 */
async function SToArrayBuffer(string) {
	var enc = new TextEncoder(); // Suppose to be always in UTF-8
	let uint8array = enc.encode(string);
	let ab = uint8array.buffer;

	// Alternatively: (untested) 
	// var len = string.length;
	// var bytes = new Uint8Array(len);
	// for (var i = 0; i < len; i++) {
	// 	bytes[i] = string.charCodeAt(i);
	// }
	// let b = await bytes.buffer;

	return ab;
}

/**
 * Converts an ArrayBuffer to a UTF-8 string.   
 *
 * @param  {string} string
 * @return {string}
 */
async function ArrayBufferToS(ab) {
	var enc = new TextDecoder("utf-8");
	let s = await enc.decode(ab);
	return s;
}

/**
 * HexTob64ut is hex to "RFC 4648 URL Safe Truncated".  
 * 
 * Taken from https://github.com/LinusU/hex-to-array-buffer  MIT license
 * 
 * @param   {Hex}         hex    String. Hex representation.
 * @returns {ArrayBuffer}        ArrayBuffer. 
 */
async function HexToArrayBuffer(hex) {
	if (typeof hex !== 'string') {
		throw new TypeError('base_convert.HexToArrayBuffer: Expected input to be a string')
	}

	if ((hex.length % 2) !== 0) {
		throw new RangeError('base_convert.HexToArrayBuffer: Expected string to be an even number of characters')
	}

	var view = new Uint8Array(hex.length / 2)

	for (var i = 0; i < hex.length; i += 2) {
		view[i / 2] = parseInt(hex.substring(i, i + 2), 16)
	}

	return view.buffer
}


/**
 * ArrayBufferToHex accepts an ArrayBuffer and returns  Hex.
 * Taken from https://stackoverflow.com/a/50767210/1923095
 * 
 * @param   {ArrayBuffer} buffer       ArrayBuffer.
 * @returns {Hex}          hex         String. Hex representation.
 */
async function ArrayBufferToHex(buffer) {
	return [...new Uint8Array(buffer)].map(x => x.toString(16).padStart(2, "0")).join('').toUpperCase();

	// Alternatively:
	// let hashArray = Array.from(new Uint8Array(digest)); // convert buffer to byte array
	// let hexHash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}



////////////////////////////////////////////////////
////////////////////////////////////////////////////
// RFC 4648 "base64"s
////////////////////////////////////////////////////
////////////////////////////////////////////////////
// Encodings have two features:
// 1. An alphabet.
// 2. A conversion method.  
//
// RFC 4648 "base64" is a bucket convert encoding method with a specific alphabet.  
// 
// There are several base 64's that we use in two classes:
//   1. Unsafe base64.  We call it `ub64`.
//   2. URL Safe base64 (base64 url).  We call it `b64u` or `base64url`.
//   3. base64 url safe truncated.  We call it `b64ut`. Padding character "="
//      removed.  
//   4. Unsafe base64 truncated isn't a thing.  Why?  Use b64ut instead.  
//   5. Base64, with an upper case "B", has a different alphabet and uses the
//      iterative divide by radix conversion method and is not a bucket
//      conversion method.  (Cyphr.me defined, not RFC 4648 defined.)  NOT IN
//      THIS file. 
//
// NOTE: RFC 4648 uses the lower case "base64" to refer to it's encoding method.
// The casing and spacing is important!  The generic "base 64" with a space is
// used to refer to any encoding system that has a 64 character alphabet.  
//
// Why do we need work with the "Unsafe Base 64" (ub64)?
//
// JOSE's b64ut is truncated with padding removed.  Javascript's `atob` is the
// only efficient way in Javascript to work with some of these methods even
// though it's not used directly for JOSE.  The only way to access CryptoKey in
// Javascript is via JOSE keys.  See notes on CryptoKey.  


/**
 * B64ToHex is "RFC 4648 base64 URL Safe Truncated" to Hex.  
 * 
 * @param   {b64ut} b64ut   String. b64ut.
 * @returns {Hex}           String. Hex.  
 */
 function B64ToHex(b64ut) {
	let ub64 = URISafeToUnsafe(b64ut)
	const raw = atob(ub64);
	let result = '';
	for (let i = 0; i < raw.length; i++) {
		const hex = raw.charCodeAt(i).toString(16).toUpperCase();
		result += (hex.length === 2 ? hex : '0' + hex);
	}
	return result;
}

/**
 * HexTob64ut is hHx to "RFC 4648 base64 URL Safe Truncated".  
 * 
 * @param   {Hex}    hex    String. Hex.
 * @returns {b64ut}         String. b64ut.
 */
async function HexTob64ut(hex) {
	let ab = await HexToArrayBuffer(hex);
	let b64ut = await ArrayBufferTo64ut(ab);
	return b64ut;
}

/**
 * URISafeToUnsafe base64 url truncated to unsafe base64 (NOT JOSE compatible)
 * // TODO add padding back. 
 * 
 * @param   {b64ut} b64ut String. RFC 4648 base64 url safe truncated.
 * @returns {ub64}        String. RFC 4648 unsafe base64.
 */
function URISafeToUnsafe(ub64) {
	// Replace + and / with - and _
	return ub64.replace(/-/g, '+').replace(/_/g, '/');
}

/**
 * ArrayBufferTo64ut Array buffer to base64url.
 * 
 * @param   {ArrayBuffer} buffer  ArrayBuffer. Arbitrary bytes. UTF-16 is Javascript native.
 * @returns {b64ut}               String. b64ut encoded string.
 */
function ArrayBufferTo64ut(buffer) {
	var string = String.fromCharCode.apply(null, new Uint8Array(buffer));
	return base64t(URIUnsafeToSafe(btoa(string)));
}


/**
 * URIUnsafeToSafe converts any URI unsafe string to URI safe.  
 * 
 * @param   {string} ub64t 
 * @returns {string} b64ut 
 */
 function URIUnsafeToSafe(ub64) {
	return ub64.replace(/\+/g, '-').replace(/\//g, '_');
};

/**
 * base64t removes base64 padding if applicable.   
 * 
 * @param   {string} base64 
 * @returns {string} base64t
 */
 function base64t(base64){
	return base64.replace(/=/g, '');
}