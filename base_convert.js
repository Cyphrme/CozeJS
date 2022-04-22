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
	HexTob64UT,
	B64UTToHex,
}

// // Not used in Coze:
// export {
// 	AB,
// 	BaseConvert,
// 	ToUTF8Array,
// 	ArrayBufferToS,
// 	SToB64UT,
// 	B64UTToS,
// 	SToUB64,
// 	UB64ToS,
// 	U64To64UT,
// 	B64UTToUb64,
// 	ArrayBufferTo64UT,
// 	JSONto64UT,
// }

/**
 * @typedef {import('./coze.js').Hex}  Hex
 * 
 * Unsafe base64 truncated isn't a thing.  If needed, use b64ut instead. 
 * @typedef {String} ub64     - Unsafe base 64.  Includes padding. 
 * @typedef {String} b64u     - base 64 url.  Includes padding. 
 * @typedef {String} b64ut    - base 64 url truncated.  Excludes padding. 
 * @typedef {String} Base64   - Cyphr.me Base64.  
 **/

const Base16 = "0123456789ABCDEF";
const Base16Lower = "0123456789abcdef";

// Base64Unsafe are the RFC 4648, non-url safe base 64 characters. 
const Base64Unsafe = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
// base64Urlis RFC 4648 URL safe base 64 characters.  We think this should have been named "base64Uri"
const Base64Url = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";


// Defined Alphabets.  AB = "alphabets"
var AB = {
	Base16: Base16,
	Base16Lower: Base16Lower,
	Base64Unsafe: Base64Unsafe,
	Base64Url: Base64Url,
}


// BaseConvert converts a given string with a given encoding alphabet
// into another base with another given encoding alphabet.  
//
// Base/radix is assumed from alphabet sizes. 
//
function BaseConvert(string, inputAlphabet, outputAlphabet) {
	const add = (x, y, base) => {
		let z = [];
		const n = Math.max(x.length, y.length);
		let carry = 0;
		let i = 0;
		while (i < n || carry) {
			const xi = i < x.length ? x[i] : 0;
			const yi = i < y.length ? y[i] : 0;
			const zi = carry + xi + yi;
			z.push(zi % base);
			carry = Math.floor(zi / base);
			i++;
		}
		return z;
	}

	const multiplyByNumber = (num, power, base) => {
		if (num < 0) return null;
		if (num == 0) return [];

		let result = [];
		while (true) {
			num & 1 && (result = add(result, power, base));
			num = num >> 1;
			if (num === 0) break;
			power = add(power, power, base);
		}

		return result;
	}

	// decodeInput finds the position of each character in alphabet, thus
	// decoding the input string into a useful array.  
	const decodeInput = (string) => {
		const digits = string.split('');
		let arr = [];
		for (let i = digits.length - 1; i >= 0; i--) {
			const n = inputAlphabet.indexOf(digits[i])
			// Continue even if character is not found (possibly a padding character.)
			// if (n == -1) return null;
			if (n == -1) continue;
			arr.push(n);
		}
		return arr;
	}

	const fromBase = inputAlphabet.length;
	const toBase = outputAlphabet.length;
	const digits = decodeInput(string);
	if (digits === null) return null;


	// Get an array of what each position of character should be. 
	let outArray = [];
	let power = [1];
	for (let i = 0; i < digits.length; i++) {
		outArray = add(outArray, multiplyByNumber(digits[i], power, toBase), toBase);
		power = multiplyByNumber(fromBase, power, toBase);
	}

	// Finally, decode array into characters.  
	let out = '';
	for (let i = outArray.length - 1; i >= 0; i--) {
		out += outputAlphabet[outArray[i]];
	}

	return out;
};



/**
 * ToUTF8Array accepts a string and returns the utf8 encoding of the string.
 * 
 * @param {string} str         str that is being converted to UTF8
 * @returns {number[]} utf8    utf8 is the number array returned from the input string.
 */
function ToUTF8Array(str) {
	var utf8 = [];
	for (var i = 0; i < str.length; i++) {
		var charcode = str.charCodeAt(i);
		if (charcode < 0x80) utf8.push(charcode);
		else if (charcode < 0x800) {
			utf8.push(0xc0 | (charcode >> 6),
				0x80 | (charcode & 0x3f));
		} else if (charcode < 0xd800 || charcode >= 0xe000) {
			utf8.push(0xe0 | (charcode >> 12),
				0x80 | ((charcode >> 6) & 0x3f),
				0x80 | (charcode & 0x3f));
		}
		// surrogate pair
		else {
			i++;
			// UTF-16 encodes 0x10000-0x10FFFF by
			// subtracting 0x10000 and splitting the
			// 20 bits of 0x0-0xFFFFF into two halves
			charcode = 0x10000 + (((charcode & 0x3ff) << 10) |
				(str.charCodeAt(i) & 0x3ff));
			utf8.push(0xf0 | (charcode >> 18),
				0x80 | ((charcode >> 12) & 0x3f),
				0x80 | ((charcode >> 6) & 0x3f),
				0x80 | (charcode & 0x3f));
		}
	}
	return utf8;
};

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
 * HexTob64UT is hex to "RFC 4648 URL Safe Truncated".  
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
 * B64UTToHex is "RFC 4648 base64 URL Safe Truncated" to Hex.  
 * 
 * @param   {b64ut} b64ut   String. b64ut.
 * @returns {Hex}           String. Hex.  
 */
 function B64UTToHex(b64ut) {
	let ub64 = B64UTToUb64(b64ut)
	const raw = atob(ub64);
	let result = '';
	for (let i = 0; i < raw.length; i++) {
		const hex = raw.charCodeAt(i).toString(16).toUpperCase();
		result += (hex.length === 2 ? hex : '0' + hex);
	}
	return result;
}

/**
 * HexTob64UT is hHx to "RFC 4648 base64 URL Safe Truncated".  
 * 
 * @param   {Hex}    hex    String. Hex.
 * @returns {b64ut}         String. b64ut.
 */
async function HexTob64UT(hex) {
	let ab = await HexToArrayBuffer(hex);
	let b64ut = await ArrayBufferTo64UT(ab);
	return b64ut;
}

/**
 * Takes a string and encodes it into b64ut.
 * 
 * @param   {string} string 
 * @returns {b64u}
 */
function SToB64UT(string) {
	return btoa(string).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/**
 * Takes a base64url string and decodes it back into a string.
 * "base64url To String"
 * 
 * @param   {b64u}   String. 
 * @returns {string} String.
 */
function B64UTToS(string) {
	// atob doesn't care about the padding character '='
	return atob(string.replace(/-/g, '+').replace(/_/g, '/'));
}

/**
 * Takes a string and encodes it into a unsafe base64 string.
 * "String to Unsafe base64"
 * 
 * @param   {string} string   String.
 * @returns {ub64}            String. Unsafe base64 
 */
function SToUB64(string) {
	return btoa(string);
}

/**
 * Takes an unsafe base64 string and decodes it back into a string.
 * "Unsafe base64 to String"
 * 
 * @param   {ub64}   string  String.  Unsafe base64 string.
 * @returns {string}
 */
function UB64ToS(string) {
	return atob(string);
}

/**
 * Unsafe base64 to base64 url truncated. (JOSE compatible.)
 * 
 * @param   {ub64}   ub64   String. ub64.
 * @returns {b64ut}  b64ut  String. 
 */
function U64To64UT(ub64) {
	return U64To64U(ub64).replace(/=/g, '');
}

/**
 * Unsafebase64 to base64url. (NOT JOSE compatible)
 * 
 * @param   {ub64} ub64 String. ub64.
 * @returns {b64u}      String. base64url.
 */
function U64To64U(ub64) {
	// Replace + and / with - and _.
	return ub64.replace(/\+/g, '-').replace(/\//g, '_');
}


/**
 * B64UTToUb64 base64 url truncated to unsafe base64 (NOT JOSE compatible)
 * // TODO add padding back. 
 * 
 * @param   {b64ut} b64ut String. RFC 4648 base64 url safe truncated.
 * @returns {ub64}        String. RFC 4648 unsafe base64.
 */
function B64UTToUb64(ub64) {
	// Replace + and / with - and _
	return ub64.replace(/-/g, '+').replace(/_/g, '/');
}

/**
 * ArrayBufferTo64UT Array buffer to base64url.
 * 
 * @param   {ArrayBuffer} buffer  ArrayBuffer. Arbitrary bytes. UTF-16 is Javascript native.
 * @returns {b64ut}               String. b64ut encoded string.
 */
function ArrayBufferTo64UT(buffer) {
	var string = String.fromCharCode.apply(null, new Uint8Array(buffer));
	return U64To64UT(btoa(string));
}

/**
 * JSONto64UT serializes a JSON object and converts it to a  b64ut string. 
 * @param  {Object} json    Object. JSON.
 * @return {b64ut}          String. b64ut. 
 */
function JSONto64UT(json) {
	return U64To64UT(btoa(JSON.stringify(json)));
}