"use strict";

import * as Coze from './coze.js';
import * as Alg from './alg.js';
import * as CZK from './key.js';
import {
	isEmpty
} from './coze.js';


export {
	CryptoKey,
	SigToLowS,
	IsSigLowS,
};

/**
 * @typedef {import('./typedefs.js').B64}      B64
 * @typedef {import('./typedefs.js').Alg}      Alg
 * @typedef {import('./typedefs.js').Sig}      Sig
 * @typedef {import('./typedefs.js').Hsh}      Hsh
 * @typedef {import('./typedefs.js').Key}      Key
 * @typedef {import('./typedefs.js').Crv}      Crv
 * @typedef {import('./typedefs.js').Msg}      Msg
 */


var CryptoKey = {
	/**
	 * New returns a ECDSA CryptoKeyPair. 
	 * https://developer.mozilla.org/en-US/docs/Web/API/CryptoKeyPair
	 * 
	 * @param  {Alg}           [alg=ES256] - Alg of the key to generate. (e.g. "ES256")
	 * @return {CryptoKeyPair}
	 * @throws {error}         Error, SyntaxError, DOMException, TypeError
	 */
	New: async function(alg) {
		if (isEmpty(alg)) {
			alg = Alg.Algs.ES256;
		}
		// Javascript only supports ECDSA, and doesn't support ES192 or ES224.  See
		// https://developer.mozilla.org/en-US/docs/Web/API/EcdsaParams
		switch (alg) {
			case Alg.Algs.ES256:
			case Alg.Algs.ES384:
			case Alg.Algs.ES512:
				return await window.crypto.subtle.generateKey({
						name: Alg.GenAlgs.ECDSA,
						namedCurve: Alg.Curve(alg)
					},
					true,
					["sign", "verify"]
				);
			default:
				throw new Error("CryptoKey.New: Unsupported key algorithm:" + alg);
		}
	},

	/**
	 * FromCozeKey takes a Coze Key and returns a Javascript CryptoKey.  Only
	 * supports ECDSA since Crypto.subtle only supports ECDSA. 
	 * https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/importKey#JSON_Web_Key
	 * 
	 * Throws error on invalid keys.
	 * 
	 * @param   {Key}        cozeKey          Coze key.
	 * @param   {boolean}    [public=false]   Return only a public key.
	 * @returns {CryptoKey}
	 * @throws  {error}                Error, SyntaxError, DOMException, TypeError
	 */
	FromCozeKey: async function(cozeKey, onlyPublic) {
		if (Alg.Genus(cozeKey.alg) != Alg.GenAlgs.ECDSA) {
			throw new Error("CryptoKey.FromCozeKey: unsupported CryptoKey algorithm: " + cozeKey.alg);
		}

		// Create a new JWK that can be used to create and "import" a CryptoKey
		var jwk = {};
		jwk.use = Alg.Uses.Sig;
		jwk.crv = Alg.Curve(cozeKey.alg);
		jwk.kty = Alg.FamAlgs.EC;

		let half = Alg.XSize(cozeKey.alg) / 2;
		let xyab = await Coze.B64ToUint8Array(cozeKey.x);
		jwk.x = await Coze.ArrayBufferTo64ut(xyab.slice(0, half));
		jwk.y = await Coze.ArrayBufferTo64ut(xyab.slice(half));

		// Public CryptoKey "crypto.subtle.importKey" needs key use to be "verify"
		// even though this doesn't exist in JWK RFC or IANA registry. (2021/05/12)
		// Gawd help us.  Private CryptoKey needs key `use` to be "sign".
		if (isEmpty(cozeKey.d) || onlyPublic) {
			var signOrVerify = "verify";
		} else {
			signOrVerify = "sign";
			jwk.d = cozeKey.d;
		}

		return await crypto.subtle.importKey(
			"jwk",
			jwk, {
				name: Alg.GenAlgs.ECDSA,
				namedCurve: jwk.crv,
			},
			true,
			[signOrVerify]
		);
	},

	/**
	 * ToPublic accepts a Javascript CryptoKey and modifies the key to remove
	 * any private components.
	 *
	 * @param   {CryptoKey} cryptoKey
	 * @returns {void}
	 */
	ToPublic: async function(cryptoKey) {
		delete cryptoKey.d; // Remove private `d` from the key.
		// Only ["verify"] is a valid `key_ops` value for a public CryptoKey.
		// `key_ops` must be an array.
		cryptoKey.key_ops = ["verify"];
	},

	/**
	 * CryptoKeyToCozeKey returns a Coze Key from Javascript's "CryptoKey" type.
	 * (https://developer.mozilla.org/en-US/docs/Web/API/CryptoKey) Coze keys are
	 * similiar to JOSE JWK's but has a few significant differences.
	 * See the Coze docs for more on these differences.
	 * 
	 * - Coze Byte-to-string values are always b64ut, "RFC 4648 base64 URI Safe
	 * Truncated".
	 * - Coze keys also use the field `alg` to denote everything about the key:
	 * it's use, hashing algorithm, curve, family, signature size, private
	 * component size, public component size, etc...
	 * - A Coze key's Thumbprint's hashing algorithm must always be in alignment
	 * with the alg.  This is unlike JOSE which appears to use SHA-256 even for
	 * keys that don't use that algorithm.
	 * 
	 * This function currently only supports ECDSA (ES256. ES384, ES512) as
	 * crypto.subtle only supports these ECDSA algorithms. From Cryptokey,
	 * `exported` key output should is in the following form:
	 * 
	 * {
	 * "crv": "P-256",
	 * "d": "GwJgQIcbB29IfWO46QZwansE5XVVOg_CfafcpGk3K9I",
	 * "key_ops": [
	 * "sign",
	 * "verify"
	 * ],
	 * "kty": "EC",
	 * "x": "bMgUwXPLFR5WPERFIdUR8f6J9znFlM4fL-TaYr7YNSo",
	 * "y": "vuU0bE-JafF1zEW_MbL-oaO0eGltDeMHIfc_bxkdCHU",
	 * "use": "sig"
	 * }
	 * 
	 * Some aspects of the Javascript exported key are in conflict with JOSE. The
	 * `delete`s below are for reference of how out of alignment the Javascript
	 * representation is from JOSE.  If for some reason a JOSE representation is
	 * required, the deletes are suggested.
	 * 
	 * `delete exported.key_ops;`
	 * 
	 * According to RFC 7517 Section 4.3, "use" is mutually exclusive with
	 * key_ops.
	 * 
	 * `delete exported["ext"];`
	 * 
	 * `ext` is define by the Web Cryptography API and does not appear in the
	 * core JOSE RFC's.  It stands for "extractable".  Since the key is already
	 * "extracted" we don't care, and we're not going to burden downstream with
	 * it.  However, this may need to be added again later if the key is further
	 * manipulated by SubtleCrypto. 
	 * 
	 * Coze does not use "crv", "kty", or "use" and instead relies solely on
	 * "alg". Since alg is not given, it's assumed from `crv` while `kty`is
	 * ignored.
	 * 
	 * Why are we exporting to JWK?
	 * 1. There's no access to the key fields without exporting. (The
	 * browser hides the information from Javascript.)
	 * 2. The exporting formats are limited.  
	 * 3. Can't export to "raw" because "raw" appears to only work on public
	 * keys.  This may be a private key.
	 * 
	 * @param   {CryptoKey}   cryptoKey 
	 * @returns {Key}
	 * @throws  {error}
	 */
	ToCozeKey: async function(cryptoKey) {
		let exported = await window.crypto.subtle.exportKey(
			"jwk",
			cryptoKey
		);

		var czk = {};
		czk.alg = await CryptoKey.algFromCrv(exported.crv);
		// Concatenate x and y, but concatenation is done at the byte level, so:
		// unencode, concatenated, and encoded. 
		let xui8 = Coze.B64ToUint8Array(exported.x);
		let yui8 = Coze.B64ToUint8Array(exported.y);
		var xyui8 = new Uint8Array([
			...xui8,
			...yui8,
		]);
		czk.x = Coze.ArrayBufferTo64ut(xyui8.buffer);

		// Only private ECDSA keys have `d`.
		if (exported.hasOwnProperty('d')) {
			czk.d = exported.d;
		}

		czk.tmb = await CZK.Thumbprint(czk);
		// console.log("exported: " + JSON.stringify(exported), "Coze Key: " + JSON.stringify(czk)); // Debugging
		return czk;
	},

	/**
	 * Uses a Javascript `CryptoKey` to sign a array buffer.  Returns array buffer
	 * bytes of the signature. Returns empty buffer on error.
	 *
	 * The signing algorithm's hashing algorithm is used for the digest of the
	 * payload.  
	 * 
	 * Coze uses UTF-8.
	 *
	 * https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/importKey#JSON_Web_Key
	 * https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/ArrayBuffer
	 * 
	 * @param   {CryptoKey}      cryptoKey
	 * @param   {ArrayBuffer}    payloadBuffer
	 * @returns {ArrayBuffer}
	 * @throws  {error}
	 */
	SignBuffer: async function(cryptoKey, arrayBuffer) {
		let alg = await CryptoKey.algFromCrv(cryptoKey.algorithm.namedCurve);
		let sig = await window.crypto.subtle.sign({
				name: Alg.GenAlgs.ECDSA,
				hash: {
					name: Alg.HashAlg(alg)
				},
			},
			cryptoKey,
			arrayBuffer
		);

		sig = sigToLowSArrayBuffer(alg, sig);
		return sig;
	},


	/**
	 * SignBufferB64 signs a buffer with a CryptoKey and returns the b64ut
	 * signature. The input is hashed before it's signed.
	 * Coze uses UTF-8.
	 *
	 * @param   {CryptoKey}   cryptoKey       Private CryptoKey
	 * @param   {ArrayBuffer} arrayBuffer     ArrayBuffer to sign.
	 * @returns {B64}
	 */
	SignBufferB64: async function(cryptoKey, arrayBuffer) {
		return await Coze.ArrayBufferTo64ut(await CryptoKey.SignBuffer(cryptoKey, arrayBuffer));
	},

	/**
	 * SignString signs a string and returns the b64ut signature.
	 * Coze uses UTF-8.
	 * 
	 * @param   {CryptoKey} cryptoKey      Private key used for signing.
	 * @param   {string}    utf8           String to sign.
	 * @returns {B64}
	 */
	SignString: async function(cryptoKey, utf8) {
		return await CryptoKey.SignBufferB64(cryptoKey, await Coze.SToArrayBuffer(utf8));
	},

	/**
	 * VerifyArrayBuffer verifies an ArrayBuffer msg with an ArrayBuffer sig and
	 * Javascript CryptoKey.
	 * Returns whether or not message is verified by the given key and signature.
	 * 
	 * @param   {Alg}         alg
	 * @param   {CryptoKey}   cryptoKey           Javascript CryptoKey.
	 * @param   {ArrayBuffer} sig                 Signature.
	 * @param   {ArrayBuffer} msg                 Message.
	 * @returns {boolean}
	 */
	VerifyArrayBuffer: async function(alg, cryptoKey, msg, sig) {
		// Currently, Coze_js is only ECDSA.  For ECDSA, only accept low-S
		// signatures.  
		if (!(await IsSigLowS(alg, sig))) {
			return false;
		}

		// Guarantee key is not private to appease Javascript 😔:
		await CryptoKey.ToPublic(cryptoKey);
		return await window.crypto.subtle.verify({
				name: Alg.GenAlgs.ECDSA,
				hash: {
					name: await CryptoKey.GetSignHashAlgoFromCryptoKey(cryptoKey)
				},
			},
			cryptoKey,
			sig,
			msg);
	},

	/**
	 * VerifyMsg uses a public key to verify a string msg with a b64ut sig.
	 * Returns whether or not the signature is valid.
	 * 
	 * @param   {Alg}        alg
	 * @param   {CryptoKey}  cryptoKey         Javascript CryptoKey.
	 * @param   {Msg}        msg               String that was signed.
	 * @param   {Sig}        sig               B64 signature.
	 * @returns {boolean}
	 */
	VerifyMsg: async function(alg, cryptoKey, msg, sig) {
		return CryptoKey.VerifyArrayBuffer(alg, cryptoKey, await Coze.SToArrayBuffer(msg), await Coze.B64uToArrayBuffer(sig));
	},

	/**
	 * GetSignHashAlgoFromCryptoKey gets the signing hashing algorithm from the
	 * CryptoKey.
	 * Returns the name of the hashing algorithm. E.g. "SHA-256".
	 *
	 * Javascript's CryptoKey explicitly requires a signing hashing algorithm, but
	 * the CryptoKey itself may not explicitly contain that information. For
	 * example, a ES256 key will have the curve (P-256) and the general key type
	 * (ECDSA), but the hashing algo is not explicitly stated (SHA-256), nor is
	 * the algorithm explicitly stated (ES256).
	 *
	 * However, for some CryptoKeys, the hashing algorithm is explicitly stated.
	 * For example, "RsaHashedKeyGenParams" has the field "hash" which explicitly
	 * denotes what hashing algorithm was used.  As of 2021/05/26,
	 * "EcKeyGenParams" has no such field, so it must be assumed that certain
	 * hashing algorithms are paired with certain curves.
	 *
	 * The purpose of this function is to return the correct hashing digest for
	 * all CryptoKeys regardless of their form.
	 * 
	 * @param   {CryptoKey} CryptoKey  CryptoKey Javascript object.
	 * @returns {Hsh}
	 * @throws  {error}                Fails if alg is not supported.
	 */
	GetSignHashAlgoFromCryptoKey: async function(cryptoKey) {
		return Alg.HashAlg(await CryptoKey.algFromCrv(cryptoKey.algorithm.namedCurve));
	},

	/**
	 * algFromCrv returns a SEAlg from the given curve.
	 * Fails if curve is not supported.
	 * 
	 * @param   {Crv}     src    Curve type. E.g. "P-256".
	 * @returns {Alg}
	 * @throws  {error}
	 */
	algFromCrv: async function(crv) {
		switch (crv) {
			case Alg.Curves.P224:
				var alg = Alg.Algs.ES224;
				break;
			case Alg.Curves.P256:
				alg = Alg.Algs.ES256
				break;
			case Alg.Curves.P384:
				alg = Alg.Algs.ES384;
				break;
			case Alg.Curves.P521: // P-521 is not ES512/SHA-512.  The curve != the alg/hash. 
				alg = Alg.Algs.ES512;
				break;
			default:
				throw new Error("CryptoKey.ToCozeKey: Unsupported key algorithm.");
		}
		return alg;
	}
}; // End CryptoKey



/** Checks if S is a "low-S".  See the Coze docs on "Low-S"
 *
 * @param   {Alg}        alg
 * @param   {BigInt}     s
 * @returns {BigInt}
 * @throws  {error}
 */
function IsLowS(alg, s) {
	if (typeof s !== "bigint") {
		throw new Error("IsLowS: s is not of type bigint");
	}
	return Alg.CurveHalfOrder(alg) > s;
}

/** Makes sure that s is a "low-S".  See the Coze docs on "Low-S" and the Go
 * package's "ToLowS" function.  
 *
 * @param   {Alg}       alg
 * @param   {BigInt}    s
 * @returns {BigInt}
 * @throws  {error}
 */
function toLowS(alg, s) {
	if (typeof s !== "bigint") {
		throw new Error("toLowS: s is not of type bigint");
	}
	if (!IsLowS(alg, s)) {
		return Alg.CurveOrder(alg) - s;
	}
	return s
}

/** Makes sure that S in sig is a "low-S" and converts if needed.  See the Coze
 * docs on "low-S"
 * 
 * @param   {Alg}      alg
 * @param   {Sig}      sig
 * @returns {Sig}
 * @throws  {error}
 */
async function SigToLowS(alg, sig) {
	let ab = await Coze.B64uToArrayBuffer(sig);
	let lowSSigAB = await sigToLowSArrayBuffer(alg, ab);
	 return Coze.ArrayBufferTo64ut(lowSSigAB);
}

/** SigIsLowS checks if S in sig is a "low-S".  See the Coze docs on "low-S"
 * 
 * @param   {Alg}      alg
 * @param   {Sig}      sig
 * @returns {boolean}
 * @throws  {error}
 */
async function IsSigLowS(alg, sig) {
	let bigIntS = await sigToS(alg, sig);
	return IsLowS(alg, bigIntS);
}

/**
 * Returns S from sig.  
 * @param   {Alg}            alg    Return only a public key.
 * @param   {ArrayBuffer}    sig    Sig ArrayBuffer from subtle crypto
 * @returns {BigInt}
 * @throws  {error}         Error, SyntaxError, DOMException, TypeError
 */
function sigToS(alg, sig) {
	let half = Alg.SigSize(alg) / 2;
	let s = sig.slice(half);
	return arrayBufferToBigInt(s);
}


/**
 * 
 * @param   {Alg}            alg    Return only a public key.
 * @param   {ArrayBuffer}    sig    Sig ArrayBuffer from subtle crypto
 * @returns {ArrayBuffer}
 * @throws  {error}         Error, SyntaxError, DOMException, TypeError
 */
async function sigToLowSArrayBuffer(alg, sig) {
	let half = Alg.SigSize(alg) / 2;
	let r = sig.slice(0, half);
	let s = sig.slice(half);
	let bigIntS = arrayBufferToBigInt(s);
	let bigIntNormS = toLowS(alg, bigIntS);
	// console.log("sig in:", sig);
	// console.log("r:", r);
	// console.log("s:", s);
	// console.log("s hex:", bigIntS.toString(16).toUpperCase());
	// console.log("IsLowS: ", IsLowS(alg, bigIntS));
	// console.log("Before toLowS", bigIntS)
	// console.log("After toLowS", bigIntNormS)
	let normS = bigIntToArrayBuffer(Alg.SigSize(alg) / 2, bigIntNormS);


	// Add two ArrayBuffers, but it's Javascript so it's hard.  😔 This is just
	// doing `sig = r + normS`;
	var tmp = new Uint8Array(r.byteLength + normS.byteLength);
	tmp.set(new Uint8Array(r), 0);
	tmp.set(new Uint8Array(normS), r.byteLength);
	sig = tmp.buffer;
	return sig
}

/** Converts a Big Endian ArrayBuffer to BigInt.  
 * 
 * @param   {ArrayBuffer}         buffer
 * @returns {BigInt}         
 */
function arrayBufferToBigInt(buffer) {
	let result = 0n;
	let a = new Uint8Array(buffer)
	for (let i = 0; i < a.length; i++) {
		result = (result << 8n) + BigInt(a[i]);
	}
	return result;
}

/** Converts a BigInt to a Big Endian ArrayBuffer.  
 * 
 * @param   {size}         int    // Number of bytes to pad the ArrayBuffer 
 * @param   {Bigint}       bigInt 
 * @returns {ArrayBuffer}  buffer
 */
function bigIntToArrayBuffer(size, bigInt) {
	const buffer = new ArrayBuffer(size);
	const view = new DataView(buffer);

	do {
		size--;
		view.setUint8(size, Number(bigInt & BigInt(0xff)));
		bigInt >>= 8n;
	} while (size > 0);
	return buffer;
}