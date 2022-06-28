"use strict";

import * as BSCNV from './base_convert.js';
import * as Alg from './alg.js';
import * as CozeKey from './cozekey.js';
import {
	isEmpty
} from './coze.js';

export {
	CryptoKey,
};

var CryptoKey = {
	/**
	 * New returns a ECDSA CryptoKeyPair. 
	 * https://developer.mozilla.org/en-US/docs/Web/API/CryptoKeyPair
	 * @param  {Alg}           [alg=ES256] - Alg of the key to generate.  (e.g. "ES256")
	 * @return {CryptoKeyPair}             - CryptoKeyPair
	 * @throws 
	 */
	New: async function(alg) {
		if (isEmpty(alg)) {
			alg = "ES256"
		}
		// Javascript only supports ECDSA, and doesn't support ES192 or ES224.  See
		// https://developer.mozilla.org/en-US/docs/Web/API/EcdsaParams
		if (Alg.Genus(alg) !== "ECDSA" || alg == "ES224" || alg == "ES192") {
			throw new Error("CryptoKey.New: Unsupported key algorithm:" + alg);
		}

		let keyPair = await window.crypto.subtle.generateKey({
				name: "ECDSA",
				namedCurve: Alg.Curve(alg)
			},
			true,
			["sign", "verify"]
		);
		return keyPair;
	},


	/**
	 * FromCozeKey takes a Coze Key and returns a Javascript CryptoKey.  Only
	 * supports ECDSA since Crypto.subtle only supports ECDSA. 
	 * https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/importKey#JSON_Web_Key 
	 * @param   {CozeKey}    cozeKey     Coze key.
	 * @param   {Boolean}    [public=false]    Return only a public key.
	 * @returns {CryptoKey}              Javascript CryptoKey
	 * @throws
	 */
	FromCozeKey: async function(cozeKey, onlyPublic) {
		if (Alg.Genus(cozeKey.alg) != "ECDSA") {
			throw new Error("CryptoKey.FromCozeKey: unsupported CryptoKey algorithm: " + cozeKey.alg);
		}

		// Create a new JWK that can be used to create and "import" a CryptoKey
		var jwk = {};
		jwk.use = "sig";
		jwk.crv = Alg.Curve(cozeKey.alg);
		jwk.kty = "EC";

		let half = Alg.XSize(cozeKey.alg) / 2;
		let xyab = await BSCNV.B64utToUint8Array(cozeKey.x);
		let xab = xyab.slice(0, half)
		let yab = xyab.slice(half)
		jwk.x = await BSCNV.ArrayBufferTo64ut(xab);
		jwk.y = await BSCNV.ArrayBufferTo64ut(yab);
		
		// Public CryptoKey "crypto.subtle.importKey" needs key use to be "verify"
		// even though this doesn't exist in JWK RFC or IANA registry. (2021/05/12)
		// Gawd help us.  Private CryptoKey needs key `use` to be "sign".
		if (isEmpty(cozeKey.d) || onlyPublic) {
			var signOrVerify = "verify";
		} else {
			signOrVerify = "sign";
			jwk.d = cozeKey.d;
		}

		var cryptoKey = await crypto.subtle.importKey(
			"jwk",
			jwk, {
				name: "ECDSA",
				namedCurve: jwk.crv,
			},
			true,
			[signOrVerify]
		);

		return cryptoKey;
	},


	/**
	 * ToPublic accepts a Javascript CryptoKey and returns a public
	 * Javascript CryptoKey.  
	 *
	 * @param   {CryptoKey} cryptoKey   CryptoKey
	 * @returns {CryptoKey}             Public Javascript CryptoKey
	 */
	ToPublic: async function(cryptoKey) {
		delete cryptoKey.d; // Remove private `d` from the key.  
		// Only ["verify"] is a valid `key_ops` value for a public CryptoKey.
		// `key_ops` must be an array.
		cryptoKey.key_ops = ["verify"];
	},

	/**
 CryptoKeyToCozeKey returns a Coze Key from Javascript's "CryptoKey" type.
 (https://developer.mozilla.org/en-US/docs/Web/API/CryptoKey) Coze keys are
 similiar to JOSE JWK's but has a few significant differences. See the Coze docs
 for more on these differences.  

 - Coze Byte-to-string values are always b64ut, "RFC 4648 base64 URI Safe
    Truncated".
 - Coze keys also use the field `alg` to denote everything about the key:
    it's use, hashing algorithm, curve, family, signature size, private
    component size, public component size, etc...
 - A Coze key's Thumbprint's hashing algorithm must always be in alignment
    with the alg.  This is unlike JOSE which appears to use SHA-256 even for
    keys that don't use that algorithm.  
 
 This function currently only supports ECDSA (ES256. ES384, ES512) as
 crypto.subtle only supports these ECDSA algorithms. From Cryptokey, `exported`
 key output should is in the following form.  

{
	"crv": "P-256",
	"d": "GwJgQIcbB29IfWO46QZwansE5XVVOg_CfafcpGk3K9I",
	"key_ops": [
		"sign",
		"verify"
	],
	"kty": "EC",
	"x": "bMgUwXPLFR5WPERFIdUR8f6J9znFlM4fL-TaYr7YNSo",
	"y": "vuU0bE-JafF1zEW_MbL-oaO0eGltDeMHIfc_bxkdCHU",
	"use": "sig"
}
		
Some aspects of the Javascript exported key are in conflict with JOSE.  The
`delete`s below are for reference of how out of alignment the Javascript
representation is from JOSE.  If for some reason a JOSE representation is
required, the deletes are suggested.  

`delete exported.key_ops;`

According to RFC 7517 Section 4.3, "use" is mutually exclusive with
key_ops. 

`delete exported["ext"];`

`ext` is define by the Web Cryptography API and does not appear in the
core JOSE RFC's.  It stands for "extractable".  Since the key is already
"extracted" we don't care, and we're not going to burden downstream with
it.  However, this may need to be added again later if the key is further
manipulated by SubtleCrypto. 

Coze does not use "crv", "kty", or "use" and instead relies solely on
"alg". Since alg is not given, it's assumed from `crv` while `kty`is
ignored.

Why are we exporting to JWK?

1. There's no access to the key fields without exporting.  (The
		browser hides the information from Javascript.)
2. The exporting formats are limited.  
3. Can't export to "raw" because "raw" appears to only work on public
		keys.  This may be a private key. 
	 * @param   {CryptoKey}   cryptoKey 
	 * @returns {CozeKey}     Coze key.
	 * @throws 
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
		let xui8 = BSCNV.B64utToUint8Array(exported.x);
		let yui8 = BSCNV.B64utToUint8Array(exported.y);
		var xyui8 = new Uint8Array([
			...xui8,
			...yui8,
		]);
		czk.x = BSCNV.ArrayBufferTo64ut(xyui8.buffer);

		// Only private ECDSA keys have `d`.
		if (exported.hasOwnProperty('d')) {
			czk.d = exported.d;
		}

		czk.tmb = await CozeKey.Thumbprint(czk);
		// console.log("exported: " + JSON.stringify(exported), "Coze Key: " + JSON.stringify(czk)); // Debugging
		return czk;
	},

	/**
	 * Uses a Javascript `CryptoKey` to sign a array buffer.  Returns array buffer
	 * bytes.  
	 *
	 * The signing algorithm's hashing algorithm is used for the digest of the
	 * payload.  
	 * 
	 * Coze uses UTF-8 bytes for strings.  
	 *
	 * https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/importKey#JSON_Web_Key
	 * https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/ArrayBuffer
	 * 
	 * @param   {CryptoKey}      cryptoKey          
	 * @param   {ArrayBuffer}    payloadBuffer     
	 * @returns {ArrayBuffer}    ArrayBuffer of sig
	 */
	SignBuffer: async function(cryptoKey, arrayBuffer) {
		let hashAlg = await CryptoKey.GetSignHashAlgoFromCryptoKey(cryptoKey);

		let signature = await window.crypto.subtle.sign({
				name: "ECDSA",
				hash: {
					name: hashAlg
				},
			},
			cryptoKey,
			arrayBuffer
		);

		return signature; // Array Buffer
	},

	/**
	 * SignBufferB64 signs a buffer with a CryptoKey and returns Hex. The input is
	 * hashed before it's signed.
	 *
	 * @param   {CryptoKey}   cryptoKey       Private CryptoKey
	 * @param   {ArrayBuffer} arrayBuffer     ArrayBuffer to sign. 
	 * @returns {string}      B64             B64
	 */
	SignBufferB64: async function(cryptoKey, arrayBuffer) {
		return await BSCNV.ArrayBufferTo64ut(await CryptoKey.SignBuffer(cryptoKey, arrayBuffer));
	},

	/**
	 * SignString signs a string and returns Hex of
	 *  the signature.  Coze uses UTF8 bytes for strings.  
	 * @param {CryptoKey} cryptoKey      CryptoKey. Private key used for signing.
	 * @param {string}    utf8           String. String to sign. 
	 * @returns {string}  hex.           String. Hex as string.
	 */
	SignString: async function(cryptoKey, utf8) {
		return await CryptoKey.SignBufferB64(cryptoKey, await BSCNV.SToArrayBuffer(utf8));
	},

	/**
	 * VerifyArrayBuffer verifies an ArrayBuffer msg with an ArrayBuffer sig and
	 * Javascript CryptoKey.
	 * @param   {CryptoKey}   cryptoKey           Javascript CryptoKey.
	 * @param   {ArrayBuffer} sig                 ArrayBuffer. Signature.
	 * @param   {ArrayBuffer} msg                 ArrayBuffer. Message.
	 * @returns {boolean}                         Boolean. Verified or not.
	 */
	VerifyArrayBuffer: async function(cryptoKey, msg, sig) {
		// Guarantee key is not private to appease Javascript:		
		await CryptoKey.ToPublic(cryptoKey);
		let hash = await CryptoKey.GetSignHashAlgoFromCryptoKey(cryptoKey);
		// console.log(cryptoKey, sig, msg, hash);
		return await window.crypto.subtle.verify({
				name: "ECDSA",
				hash: {
					name: hash
				},
			},
			cryptoKey,
			sig,
			msg);
	},

	/**
	 * VerifyMsg uses a public key to verify a string msg with a b64ut sig.
	 * 
	 * @param   {CryptoKey}  cryptoKey         Javascript CryptoKey. 
	 * @param   {string}     msg               String that was signed.  
	 * @param   {Sig}        sig               B64 signature.  
	 * @returns {boolean}                      Boolean. If signature is valid.  
	 */
	VerifyMsg: async function(cryptoKey, msg, sig) {
		let msgab = await BSCNV.SToArrayBuffer(msg);
		let sigab = await BSCNV.B64utToArrayBuffer(sig);
		return CryptoKey.VerifyArrayBuffer(cryptoKey, msgab, sigab);
	},

	/**
	 * GetSignHashAlgoFromCryptoKey gets the signing hashing algorithm from the
	 * CryptoKey.  
	 *
	 * Javascript's CryptoKey explicitly requires a signing hashing algorithm, but
	 * the CryptoKey itself may not explicitly contain that information. For
	 * example, a ES256 key will have the curve (P-256) and the general key type
	 * (ECDSA), but the hashing algo is not explicitly stated (SHA-256), nor is
	 * the algorithm explicitly stated (ES256)
	 *
	 * However, for some CryptoKeys, the hashing algorithm is explicitly stated.
	 * For example, "RsaHashedKeyGenParams" has the field "hash" which explicitly
	 * denotes what hashing algorithm was used.  As of 2021/05/26,
	 * "EcKeyGenParams" has no such field, so it must be assumed that certain
	 * hashing algorithms are paired with certain curves.  
	 *
	 * The purpose of this function is to return the correct hashing digest for
	 * all CryptoKeys regardless of their form.  
	 * @param   {CryptoKey} CryptoKey          
	 * @returns {String}    Hash       String. Name of hashing algorithm e.g. "SHA-256".
	 */
	GetSignHashAlgoFromCryptoKey: async function(cryptoKey) {
		// let exported = await window.crypto.subtle.exportKey(
		// 	"jwk",
		// 	cryptoKey
		// );
		// console.log(cryptoKey.algorithm.namedCurve);
		return Alg.HashAlg(await CryptoKey.algFromCrv(cryptoKey.algorithm.namedCurve));
	},


	algFromCrv: async function(crv) {
		switch (crv) {
			case "P-224":
				var alg = "ES224";
				break;
			case "P-256":
				alg = "ES256";
				break;
			case "P-384":
				alg = "ES384";
				break;
			case "P-521": // P-521 is not ES512/SHA-512.  The curve != the alg/hash. 
				alg = "ES512";
				break;
			default:
				throw new Error("CryptoKey.ToCozeKey: Unsupported key algorithm.");
		}
		return alg;
	}
}; // End CryptoKey