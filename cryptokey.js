"use strict";

import * as BSCNV from './base_convert.js';
import * as Enum from './coze_enum.js';
import * as CozeKey from './coze_key.js';
import {isEmpty} from './coze.js';

export {
	CryptoKey,
};

var CryptoKey = {
	/**
	 * New returns a ECDSA CryptoKeyPair.
	 * 
	 * https://developer.mozilla.org/en-US/docs/Web/API/CryptoKeyPair
	 *
	 * @param  {Alg}           [alg=ES256] - Alg of the key to generate.  (e.g. "ES256")
	 * @return {CryptoKeyPair}             - CryptoKeyPair
	 * @throws 
	 */
	New: async function(alg) {
		if (isEmpty(alg)) {
			alg = "ES256"
		}

		// Javascript only supports ECDSA, and apparently doesn't support ES192 or
		// ES224.  See https://developer.mozilla.org/en-US/docs/Web/API/EcdsaParams
		if (Enum.Genus(alg) !== "ECDSA" || alg == "ES224" || alg == "ES192") {
			throw new Error("CryptoKey.New: Unsupported key algorithm.");
		}

		//generateKey returns a CryptoKeyPair
		let keyPair = await window.crypto.subtle.generateKey({
				name: "ECDSA",
				namedCurve: Enum.Curve(alg)
			},
			true,
			["sign", "verify"]
		);
		return keyPair;
	},


	/**
	 * ToCryptoKey takes a Coze Key and returns a Javascript CryptoKey.  Only
	 * supports ECDSA since Crypto.subtle only supports ECDSA. 
	 * 
	 * https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/importKey#JSON_Web_Key 
	 *
	 * @param   {CozeKey}    cozeKey     Javascript object Coze key. 
	 * @returns {CryptoKey}              Javascript CryptoKey
	 * @throws
	 */
	FromCozeKey: async function(cozeKey) {
		if (Enum.Genus(cozeKey.alg) != "ECDSA") {
			throw new Error("CryptoKey.FromCozeKey: unsupported CryptoKey algorithm: " + cozeKey.alg);
		}

		// Create a new JWK that can be used to create and "import" a CryptoKey
		var jwk = {};
		jwk.use = "sig";
		//jwk.key_ops = ["sign", "verify"]; // Don't appear to need this anymore in Chrome.  
		jwk.x = await BSCNV.HexTob64UT(cozeKey.x);
		jwk.y = await BSCNV.HexTob64UT(cozeKey.y);
		jwk.crv = Enum.Curve(cozeKey.alg);
		jwk.kty = "EC";

		// Public CryptoKey "crypto.subtle.importKey" needs key use to be "verify"
		// even though this doesn't exist in JWK RFC or IANA registry. (2021/05/12)
		// Gawd help us.  Private CryptoKey needs key `use` to be "sign".
		if (isEmpty(cozeKey.d)) {
			var signOrVerify = "verify";
		} else {
			signOrVerify = "sign";
			jwk.d = await BSCNV.HexTob64UT(cozeKey.d);
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
	 * FromCozeKeyToPublic takes a Coze Key and returns a public Javascript
	 * CryptoKey. Only supports ECDSA.  
	 *
	 * @param   {CozeKey}   cozeKey      Javascript object Coze key. 
	 * @returns {CryptoKey}              Javascript CryptoKey
	 * @throws
	 */
	FromCozeKeyToPublic: async function(cozeKey) {
		let nck = {
			...cozeKey
		}; // Copy of original. 
		delete nck.d; // Delete private components
		return CryptoKey.FromCozeKey(nck);
	},


	/**
	 * ToPublic accepts a Javascript CryptoKey and returns a public
	 * Javascript CryptoKey.  
	 *
	 * @param   {CryptoKey} CryptoKey   CryptoKey
	 * @returns {CryptoKey}             Public Javascript CryptoKey
	 */
	ToPublic: async function(CryptoKey) {
		// Javascript objects are "pass by reference" and not pass by
		// value.  One way to copy is by stringify and parses the object. 
		//
		// let npk = JSON.stringify(privateKey); npk = JSON.parse(npk); 
		//
		// Alternatively, the `{...obj}` syntax copies.  
		let npk = {
			...CryptoKey
		};

		// Remove the private component `d` from the key.  
		delete npk.d;

		// Only ["verify"] is a valid `key_ops` value for a public CryptoKey.
		// `key_ops` must be an array.
		npk.key_ops = ["verify"];
		return npk;
	},

	/**
	 * CryptoKeyToCozeKey returns a Coze Key from Javascript's "CryptoKey" type.  
	 * 
	 * https://developer.mozilla.org/en-US/docs/Web/API/CryptoKey
	 * 
	 * Coze keys are like JOSE JWK's but has a few significant differences. 
	 * 
	 * - Byte-to-string values in Coze are always Hex and never "RFC 4648 base64 URL
	 *    Safe Truncated".
	 * - Coze keys also use the field `alg` to denote everything about the key: it's
	 *    use, hashing algorithm, curve, family, etc...
	 * - The Thumbprint's hashing algorithms must always be in alignment with the
	 *    algorithm and is not defined universally across the standard.  
	 * 
	 * See the Coze docs for mor on these differences.  
	 * 
	 * This function currently only supports ECDSA (ES256. ES384, ES512) as
	 * crypto.subtle only supports these ECDSA algorithms.
	 * 
	 * @param   {CryptoKey}   CryptoKey 
	 * @returns {CozeKey}     Coze key.
	 * @throws 
	 */
	ToCozeKey: async function(CryptoKey) {
		// Why are we exporting to JWK?
		//
		// 1. There's no access to the key information without exporting.  (The
		//    browser hides the information from Javascript.)
		// 2. The exporting formats are limited.  
		// 3. We can't export to "raw" because "raw" appears to only work on public
		//    keys.  This is a private key. 
		let exported = await window.crypto.subtle.exportKey(
			"jwk",
			CryptoKey
		);

		// From Cryptokey, `exported` key output should is in the following form.  
		//
		// {
		// 	"crv": "P-256",
		// 	"d": "GwJgQIcbB29IfWO46QZwansE5XVVOg_CfafcpGk3K9I",
		// 	"key_ops": [
		// 		"sign",
		// 		"verify"
		// 	],
		// 	"kty": "EC",
		// 	"x": "bMgUwXPLFR5WPERFIdUR8f6J9znFlM4fL-TaYr7YNSo",
		// 	"y": "vuU0bE-JafF1zEW_MbL-oaO0eGltDeMHIfc_bxkdCHU",
		// 	"use": "sig"
		// }
		//
		// Some aspects of the exported key are in conflict with JOSE.  The `delete`s
		// below are for reference of how out of alignment the Javascript
		// representation is from JOSE.  If for some reason a JOSE representation is
		// required, the deletes are suggested.  
		//
		// `delete exported.key_ops;`
		//
		// According to RFC 7517 Section 4.3, "use" is mutually exclusive with
		// key_ops. 
		//
		// `delete exported["ext"];`
		// 
		// `ext` is define by the Web Cryptography API and does not appear in the
		// core JOSE RFC's.  It stands for "extractable".  Since the key is already
		// "extracted" we don't care, and we're not going to burden downstream with
		// it.  However, this may need to be added again later if the key is further
		// manipulated by SubtleCrypto. 
		//
		// Coze does not use "crv", "kty", or "use" and instead relies solely on
		// "alg". Since alg is not given, it's assumed from `crv` while `kty`is
		// ignored. `use` is also currently ignored since Coze does not currently
		// support encryption. 

		var cz = {}; // A new empty coze key.

		if (exported.kty != "EC") {
			throw new Error("CryptoKey.ToCozeKey: Unsupported key algorithm.");
		}

		switch (exported.crv) {
			case "P-256":
				cz.alg = "ES256";
				break;
			case "P-384":
				cz.alg = "ES384";
				break;
			case "P-521": // P-521 is not ES512/SHA-512.  The curve != the alg/hash. 
				cz.alg = "ES512";
				break;
			default:
				throw new Error("CryptoKey.ToCozeKey: Unsupported key algorithm.");
		}
		// console.log("exported: " + JSON.stringify(exported)); // Debugging

		// Key components for a ECDSA keys. 
		// Convert "RFC 4648 base64 URL Safe Truncated" to Hex.  
		// ECDSA and Ed have x
		cz.x = BSCNV.B64UTToHex(exported.x);

		// Only private ECDSA keys have `d`.
		if (exported.hasOwnProperty('d')) {
			cz.d = BSCNV.B64UTToHex(exported.d);
		}

		// In case of future support: Ed does not have `y` and only uses `x`.  
		if (exported.hasOwnProperty('y')) {
			cz.y = BSCNV.B64UTToHex(exported.y);
		}

		cz.tmb = await CozeKey.Thumbprint(cz);

		return cz;
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
		let digest = await CryptoKey.GetSignHashAlgoFromCryptoKey(cryptoKey);

		let signature = await window.crypto.subtle.sign({
				name: "ECDSA",
				hash: {
					name: digest
				},
			},
			cryptoKey,
			arrayBuffer
		);

		return signature; // Array Buffer
	},

	/**
	 * SignBufferToHex signs a buffer with a CryptoKey and returns Hex.
	 * 
	 * The input (arrayBuffer) is hashed before it's signed.
	 * 
	 * @param {CryptoKey}   cryptoKey       Private CryptoKey
	 * @param {ArrayBuffer} arrayBuffer     ArrayBuffer to sign. 
	 * @returns {string}    Hex             Hex as string.
	 */
	SignBufferToHex: async function(cryptoKey, arrayBuffer) {
		let ab = await CryptoKey.SignBuffer(cryptoKey, arrayBuffer);
		let sig = await BSCNV.ArrayBufferToHex(ab);

		return sig;
	},

	/**
	 * SignString signs a string and returns Hex of
	 *  the signature.  Coze uses UTF8 bytes for strings.  
	 * @param {CryptoKey} cryptoKey      CryptoKey. Private key used for signing.
	 * @param {string}    utf8           String. String to sign. 
	 * @returns {string}  hex.           String. Hex as string.
	 */
	SignString: async function(cryptoKey, utf8) {
		let buffer = await BSCNV.SToArrayBuffer(utf8);
		let hexSig = await CryptoKey.SignBufferToHex(cryptoKey, buffer)
		return hexSig;
	},

	/**
	 * VerifyABMsgSig verifies an ArrayBuffer msg with an ArrayBuffer sig.
	 *
	 * Note: For Coze messages, signature is over the digest of of `head`. If
	 * verifying Coze messages, the message must be the UTF-8 bytes of the
	 * message, not the digest, because Javascript hashes msg.  
	 * 
	 * If Javascript ever allowed private keys, this function should support that
	 * as well.  Currently private keys don't appear to be compatible.  
	 *
	 * @param   {CryptoKey}   publicCryptoKey     CryptoKey. Public CryptoKey. 
	 * @param   {ArrayBuffer} sig                 ArrayBuffer. Signature.  
	 * @param   {ArrayBuffer} msg                 ArrayBuffer. Message.   
	 * @returns {boolean}                         Boolean. Verified or not.  
	 */
	 VerifyABMsgSig: async function(publicCryptoKey, msg, sig) {
		//console.log({publicCryptoKey, sig, msg});
		let hash = await CryptoKey.GetSignHashAlgoFromCryptoKey(publicCryptoKey);
		let verified = await window.crypto.subtle.verify({
				name: "ECDSA",
				hash: {
					name: hash
				},
			},
			publicCryptoKey,
			sig,
			msg);

		return verified;
	},

	/**
	 * VerifyMsgHexSig verifies a msg string with a Hex sig.
	 * 
	 * Private keys are currently incompatible due to Javascript design.  
	 * 
	 * @param   {CryptoKey}  publicCryptoKey   Public Javascript CryptoKey. 
	 * @param   {string}     hexSig            String. Signature in hex.  
	 * @param   {string}     msg               String that was signed.  
	 * @returns {boolean}                      Boolean. If signature is valid.  
	 */
	 VerifyMsgHexSig: async function(publicCryptoKey, msg, hexSig) {
		hexSig = await BSCNV.HexToArrayBuffer(hexSig);
		msg = await BSCNV.SToArrayBuffer(msg);
		return CryptoKey.VerifyABMsgSig(publicCryptoKey, msg, hexSig);
	},

	/**
	 * GetSignHashAlgoFromCryptoKey gets the signing hashing algorithm from the
	 * CryptoKey.  
	 *
	 * Javascript's CryptoKey explicitly requires a signing hashing algorithm, but
	 * the CryptoKey itself may not explicitly contain that information. 
	 *
	 * For example, a ES256 key will have the curve (P-256) and the general key
	 * type (ECDSA), but the hashing algo is not explicitly stated (SHA-256). 
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
	 * @returns {String}    digest       String. Name of digest, i.e. SHA-256.
	 */
	GetSignHashAlgoFromCryptoKey: async function(cryptoKey) {
		let cz = await CryptoKey.ToCozeKey(cryptoKey);
		let alg = await Enum.HashAlg(cz.alg);
		return alg;
	},


}; // End CryptoKey