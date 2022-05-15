"use strict";

import * as CTK from './cryptokey.js';
import * as Coze from './coze.js';
import * as Can from './canon.js';
import * as BSCNV from './base_convert.js';
import * as Enum from './coze_enum.js';
import {isEmpty} from './coze.js';

export {
	NewCozeKey,
	ToPublicCozeKey,

	VerifyMsg,

	Correct,
	Normal,
	Valid,

	Thumbprint,

	Revoke,
	IsRevoked,

	ECDSATmbCanon,
	EdDSATmbCanon,
}


/**
 * @typedef {import('./coze.js').Hex}  Hex
 * @typedef {import('./coze.js').Alg}  Alg
 * @typedef {import('./coze.js').Use}  Use
 * @typedef {import('./coze.js').Sig}  Sig
 * @typedef {import('./coze.js').Time} Time
 * 
 * Coze key
 * @typedef  {Object} CozeKey
 * @property {Alg}    alg - Cryptographic signing or encryption algorithm - e.g. "ES256"
 * @property {String} kid - Human readable, non programmatic, key identifier - e.g. "Test Key"
 * @property {Time}   iat - Unix time key was created. e.g. 1624472390
 * @property {Hex}    tmb - Key thumbprint e.g. "0148F4CD9093C9CBE3E8BF78D3E6C9B824F11DD2F29E2B1A630DD1CE1E176CDD"
 * @property {Hex}    [d] - ECDSA private "d" component in Hex.  Required for ECDSA private Coze keys.  e.g. "30C76C9EC4286DADEB0E1EBFF546A1B4A57DB4571412F953E053FB689D286C3C"
 * @property {Hex}    [x] - ECDSA public "x" component in Hex.  Required for ECDSA public Coze keys.    e.g. "827ECBA80BE7421DD71A6C2819ABC1D988450EBB802B972AE22292FA0D538B6B"
 * @property {Hex}    [y] - ECDSA public "y" component in Hex.  Required for ECDSA public Coze keys.    e.g. "8D45880FC2C9FD1DBBF28ED4CB973CD8D1CB4F93F422B1B90AC1DA4ED13CA9EC"
 * 
 * @typedef  {CozeKey} PrivateCozeKey - A Coze key containing any private components.  
 * @typedef  {CozeKey} PublicCozeKey  - A Coze key containing no private components and required public components.  
 */

// Coze key Thumbprint Canons.
const ECDSATmbCanon = ["alg", "x", "y"];
const EdDSATmbCanon = ["alg", "x"];

/**
 * NewCozeKey returns a new Coze key. 
 * 
 * @param   {Alg}     [alg=ES256] - Alg of the key to generate. (e.g. "ES256")
 * @returns {CozeKey}             - Coze key in Javascript object format
 */
async function NewCozeKey(alg) {
	if (isEmpty(alg)) {
		alg = "ES256"
	}
	if (Enum.Genus(alg) == "ECDSA") {
		var keyPair = await CTK.CryptoKey.New(alg);
	} else {
		throw new Error("CozeKey.NewCozeKey: only ECDSA algs are currently supported.");
	}

	let CozeKey = await CTK.CryptoKey.ToCozeKey(keyPair.privateKey)

	CozeKey.iat = Math.floor(Date.now() / 1000);// To get Unix from js, divide by 1000.  
	CozeKey.tmb = await Thumbprint(CozeKey);
	CozeKey.kid = "My Cyphr.me Key.";

	return CozeKey;
}


/**
 * Verify verifies a message using the given Coze key.
 * 
 * @param   {CozeKey}  cozeKey   - Alg of the key to generate. (e.g. "ES256")
 * @param   {String}   msg       - Message to Verify
 * @param   {Hex}      sig       - Signature of message
 * @returns {Boolean}            - If the message is verified.
 */
async function VerifyMsg(cozeKey, msg, sig) {
	let msgBuff = await BSCNV.SToArrayBuffer(msg)
	let sigBuff = await BSCNV.SToArrayBuffer(sig)
	let pubKey = await CTK.CryptoKey.FromCozeKeyToPublic(cozeKey);
	return await CTK.CryptoKey.VerifyABMsgSig(pubKey, msgBuff, sigBuff);
}

/**
 * Thumbprint generates Coze key thumbprint.  Currently only supports ECDSA and
 * Ed25519. 
 *
 * @param   {CozeKey} cozeKey - Javascript object Coze key. 
 * @returns {tmb}             - Hex thumbprint string
 * @throws 
 */
async function Thumbprint(cozeKey) {
	if (isEmpty(cozeKey.alg)) {
		throw new Error("CozeKey.Thumbprint: alg is empty.");
	}

	if (Enum.Genus(cozeKey.alg) != "ECDSA" && cozeKey.alg != "Ed25519") {
		throw new Error("CozeKey.Thumbprint: unsupported alg.");
	}

	if (isEmpty(cozeKey.x)) {
		throw new Error("CozeKey.Thumbprint: x is empty.");
	}

	if (Enum.Genus(cozeKey.alg) == "ECDSA" && isEmpty(cozeKey.y)) {
		throw new Error("CozeKey.Thumbprint: y is empty.");
	}

	let can = {};
	if (Enum.Genus(cozeKey.alg) == "ECDSA") {
		can = ECDSATmbCanon;
	}
	if (Enum.Genus(cozeKey.alg) == "EdDSA") {
		can = EdDSATmbCanon;
	}

	let hashAlg = await Enum.HashAlg(cozeKey.alg)
	return Can.CHH(cozeKey, hashAlg, can);
};

/**
 * Valid validates a private Coze key.  See notes on `Correct`.
 *
 * @param   {CozeKey}    privateCozeKey  Private Coze key. 
 * @returns {boolean}                    Valid.   
 */
async function Valid(privateCozeKey) {
	try {
		if (isEmpty(privateCozeKey.d)) {
			throw "Private Coze key is missing private component 'd'";
		}
		let b = await Correct(privateCozeKey); // Throws, so `await` keyword is needed must be on two lines. 
		return b;
	} catch (e) {
		// ignore.
	}
	return false;
}

/**
 * Correct checks for the correct construction of a Coze key.  Always returns
 * true if no error.

 * Correct:
 * 1. Ensures required headers exist.
 * 2. Checks if the length of public components are correct.
 * 3. If the key is private (containing private components) generates and verifies a
 *    signature, thus verifying the private key.
 *
 * Correct may return "true" on cryptographically invalid public keys since
 * public keys cannot (necessarily) be validated without verifying a signed
 * message. Use function "Verify" for public keys with a signed message.  Use
 * function "Correct" to check for the correct construction of a public key.  
 *
 * @param   {CozeKey}    cozeKey  Object. Coze key. 
 * @returns {boolean}             Boolean. Always returns true unless error.   
 * @throws                        
 */
async function Correct(cozeKey) {
	let required = [
		'alg',
		'iat',
		'tmb',
		'x',
	]

	for (let element of required) {
		if (!(element in cozeKey)) {
			throw new Error("CozeKey.Correct: No '" + element + "' in Coze key");
		}
	}

	// Sanity check - No keys from the future allowed.
	if (cozeKey.iat > Math.round((Date.now() / 1000))) {
		throw new Error("CozeKey.Correct: cannot have iat greater than present time");
	}

	if (cozeKey.alg == "Ed25519") {
		if (cozeKey.x.length < 64) { // Ed25519's public key is 32 bytes (64 in Hex)
			throw new Error("CozeKey.Correct: x is too short.  Has length: " + cozeKey.x.length);
		}
	}

	if (Enum.Genus(cozeKey.alg) == "ECDSA") {
		// Hex is twice the size of bytes.  
		let size = (Enum.HashSize(Enum.HashAlg(cozeKey.alg))) * 2;
		if (cozeKey.x.length < size) {
			throw new Error("CozeKey.Correct: x is too short.  Has length: " + cozeKey.x.length);
		}
		if (cozeKey.y.length < size) { // y is required for ECDSA
			throw new Error("CozeKey.Correct: y is too short.  Has length: " + cozeKey.y.length);
		}
	}

	// Recalculate the tmb and compare
	let tmb = await Thumbprint(cozeKey);
	if (tmb != cozeKey.tmb) {
		throw new Error("CozeKey.Correct: tmb does not match: " + tmb);
	}

	// If private key, validate by signing and verifying.
	if (!isEmpty(cozeKey.d)) {
		// console.log("Signing for private key. ");
		let mld = "Test Signing";
		let cryptoKey = await CTK.CryptoKey.FromCozeKey(cozeKey);
		let mldBuffer = await BSCNV.SToArrayBuffer(mld)
		let sig = await CTK.CryptoKey.SignBuffer(cryptoKey, mldBuffer);
		let pubKey = await CTK.CryptoKey.FromCozeKeyToPublic(cozeKey);
		let result = await CTK.CryptoKey.VerifyABMsgSig(pubKey, mldBuffer, sig);

		if (result !== true) {
			throw new Error("CozeKey.Correct: private key invalid.");
		}
	}

	return true;
};

/**
 * Normal returns a normalized Coze key with "alg","iat","tmb',"x", and
 * if present, "kid", and "y".
 *
 * Truncates `kid` at 50 characters and throws on oversized `iat`.
 *
 * @param   {CozeKey}    cozeKey  Coze key. 
 * @returns {CozeKey}             Normalized Coze key.  
 * @throws                        
 */
async function Normal(cozeKey) {
	var nck = {};
	nck.alg = cozeKey.alg;
	if (cozeKey.iat > 9007199254740991) { // max safe Javascript integer.
		throw "Coze.Normal: `iat` too large"
	}
	nck.iat = cozeKey.iat;
	if (!isEmpty(cozeKey.kid)) {
		nck.kid = cozeKey.kid.substring(0, 50); // `kid` soft limit of 50
	}
	nck.x = cozeKey.x;
	if (Enum.Genus(cozeKey.alg) == "ECDSA") { 	// y is required for ECDSA
		nck.y = cozeKey.y;
	}

	if (!Correct(nck)) {
		throw new Error("CozeKey.Normal: Coze key not correct");
	}
	return nck
}

/**
 * ToPublicCozeKey takes a public or private Coze key and returns a normalized
 * public Coze key. Since this takes a "public or private" Coze key, this
 * function can act as "public key sanitization".
 *
 * Only supports ECDSA/EdDSA at the moment.  
 * 
 * @param   {CozeKey} cozeKey  - Javascript object Coze key (public or private). 
 * @returns {PublicCozeKey}    - Coze key that contains no private components.  
 * @throws
 */
async function ToPublicCozeKey(cozeKey) {
	let nck = {};
	nck.alg = cozeKey.alg;
	nck.iat = cozeKey.iat;
	if (!isEmpty(cozeKey.kid)) {
		nck.kid = cozeKey.kid;
	}
	nck.x = cozeKey.x;

	switch (Enum.Genus(nck.alg)) {
		case "ECDSA":
			nck.y = cozeKey.y;
			break;
		case "EdDSA":
			break;
		default:
			throw new Error("CozeKey.ToPublicCozeKey: Unsupported key algorithm (alg):" + nck.alg);
	}

	nck.tmb = await Thumbprint(nck);

	// Return object in order.  
	nck = await Can.Canon(nck);
	return nck;
}


/**
 * Revoke generates a self revoke message.  This includes from previous
 * previously revoked keys.  This function only generates a message and does not
 * manipulate the Coze key's `rvk` value.  Currently, a key's `rvk` must be
 * manually set. 
 *
 * @param   {CozeKey}   cozeKey            Private Coze key.
 * @param   {String}    [msg]              Optional, human readable non programmatic reason for revoking the key.
 * @returns {cy}                           Cy returned from signing the message.
 * @throws  error                          if cryptoKeyPrivate is nil or invalid.
 */
async function Revoke(cozeKey, msg) {
	if (isEmpty(cozeKey)) {
		throw new Error("CozeKey.Revoke: Private key not set.  Cannot sign message");
	}

	if (isEmpty(cozeKey.tmb)) {
		cozeKey.tmb = await CZK.Thumbprint(cozeKey);
	}

	var cy = {};
	cy.head = {};
	if (!isEmpty(msg)) { // Optional revoke message. 
		cy.head.msg = msg;
	}
	cy.head.rvk = Math.round((Date.now() / 1000)); // Javascript's Date converted to Unix time.
	cy.head.typ = "cyphr.me/key/revoke";

	// SignCy does not allow revoked keys to sign messages.  Temporarily remove
	// key.revoke and then set back afterward.
	let prevRvk = cozeKey.rvk;
	delete cozeKey.rvk;
	cy = await Coze.SignCy(cy, cozeKey);
	if (prevRvk !== undefined) {
		cozeKey.rvk = prevRvk;
	}

	return cy
};

/**
 * IsRevoked returns true if a key is marked as revoked. `rvk` should be an
 * integer Unix timestamp, however this function also checks for the string
 * "true" as well as the bool `true`.
 *
 * Messages self-revoking keys must have `rvk` with an integer value greater
 * than 0.  
 *
 * @param   {CozeKey}   cozeKey      Private Coze key.          
 * @param   {String}    [msg]        Optional reason for revoking the key.    
 * @returns {boolean}                Revoked or not. 
 */
function IsRevoked(cozeKey) {
	if (isEmpty(cozeKey.rvk)) {
		return false;
	}

	if (parseInt(cozeKey.rvk) > 0 || cozeKey.rvk === true || cozeKey.rvk.toLowerCase() === "true") {
		return true;
	}

	return false;
};