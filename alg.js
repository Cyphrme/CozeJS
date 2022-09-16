"use strict";

// For more documentation and notes, see the main Coze README.

export {
	Params,
	Curve,
	Family,
	Genus,
	HashAlg,
	HashSize,
	SigSize,
	XSize,
	DSize,
	Use,
}

/**
 * @typedef {import('./typedefs.js').Alg}     Alg
 * @typedef {import('./typedefs.js').Params}  Params
 * @typedef {import('./typedefs.js').Params}  Genus
 * @typedef {import('./typedefs.js').Family}  Family
 * @typedef {import('./typedefs.js').Hash}    Hash
 * @typedef {import('./typedefs.js').Curve}   Curve
 * @typedef {import('./typedefs.js').Use}     Use
 */

/**
 * Param reports all relevant values for a given `alg`.
 * Returns Params object with populated values for relevant fields.
 * All functions definied in this file will fail/error when given an
 * unsupported algorithm.
 * 
 * Go Coze returns 0 on errors, should cozejs do the same?
 * 
 * @param   {Alg}      alg
 * @returns {Params}
 * @throws  {Error}
 */
function Params(alg) {
	/** @type {Params} */
	let p = {
		Name: alg,
		B64: {},
	};
	p.Genus = Genus(alg);
	p.Family = Family(alg);
	p.Hash = HashAlg(alg);
	p.HashSize = HashSize(alg);
	p.B64.HashSize = Math.ceil(4 * p.HashSize / 3);
	p.Use = Use(alg);

	// SigAlg parameters
	try {
		p.SigSize = SigSize(alg);
		p.XSize = XSize(alg);
		p.DSize = DSize(alg);
		p.Curve = Curve(alg);

		p.B64.SigSize = Math.ceil(4 * p.SigSize / 3);
		p.B64.XSize = Math.ceil(4 * p.XSize / 3);
		p.B64.DSize = Math.ceil(4 * p.DSize / 3);
	} catch (e) {
		// ignore error
	}

	return p;
}

/**
 * Genus returns the genus for an alg (ECDSA, EdDSA, SHA-2, SHA-3).
 * See notes on the Go implementation of Coze for more on genus.
 *
 * @param   {Alg} alg
 * @returns {Genus}
 * @throws  {Error}
 */
function Genus(alg) {
	switch (alg) {
		case "ES224":
		case "ES256":
		case "ES384":
		case "ES512":
			return "ECDSA";
		case "Ed25519":
		case "Ed25519ph":
		case "Ed448":
			return "EdDSA";
		case "SHA-224":
		case "SHA-256":
		case "SHA-384":
		case "SHA-512":
			return "SHA2";
		case "SHA3-224":
		case "SHA3-256":
		case "SHA3-384":
		case "SHA3-512":
		case "SHAKE128":
		case "SHAKE256":
			return "SHA3";
		default:
			throw new Error("alg.Genus: unsupported algorithm: " + alg);
	}
}

/**
 * Family returns the family for an alg (EC and SHA).
 * See notes on the Go implementation of Coze for more on family.
 *
 * @param   {Alg}     alg
 * @returns {Family}
 * @throws  {Error}
 */
function Family(alg) {
	switch (alg) {
		case "ES224":
		case "ES256":
		case "ES384":
		case "ES512":
		case "Ed25519":
		case "Ed25519ph":
		case "Ed448":
			return "EC";
		case "SHA-224":
		case "SHA-256":
		case "SHA-384":
		case "SHA-512":
		case "SHA3-224":
		case "SHA3-256":
		case "SHA3-384":
		case "SHA3-512":
		case "SHAKE128":
		case "SHAKE256":
			return "SHA";
		default:
			throw new Error("alg.Family:  unsupported algorithm: " + alg);
	}
}

/**
 * Hash returns the hashing algorithm for the given algorithm.  A hash alg can
 * return itself.
 * See notes on the Go implementation of Coze for more.
 *
 * @param   {Alg}   alg 
 * @returns {Hash}
 * @throws  {Error}
 */
function HashAlg(alg) {
	switch (alg) {
		case "SHA-224":
		case "ES224":
			return "SHA-224";
		case "SHA-256":
		case "ES256":
			return "SHA-256";
		case "SHA-384":
		case "ES384":
			return "SHA-384";
		case "SHA-512":
		case "ES512": // P-521 is not ES512/SHA-512.  The curve != the alg/hash.
		case "Ed25519":
		case "Ed25519ph":
			return "SHA-512";
		case "SHAKE128":
			return "SHAKE128";
		case "SHAKE256":
		case "Ed448":
			return "SHAKE256";
		case "SHA3-224":
			return "SHA3-224";
		case "SHA3-256":
			return "SHA3-256";
		case "SHA3-384":
			return "SHA3-384";
		case "SHA3-512":
			return "SHA3-512";
		default:
			throw new Error("alg.HashAlg:  unsupported algorithm: " + alg);
	}
}

/**
 * HashSize returns the hashing algorithm size for the given algorithm in bytes
 * E.g. 32.
 * 
 * SHAKE128 has 128 bits of pre-collision resistance and a capacity of 256,
 * although it has arbitrary output size. SHAKE256 has 256 bits of pre-collision
 * resistance and a capacity of 512, although it has arbitrary output size.
 * 
 * See notes on the Go implementation of Coze for more.
 * 
 * @param   {Alg}     alg
 * @returns {Number}
 * @throws  {Error}
 */
function HashSize(alg) {
	switch (HashAlg(alg)) {
		case "SHA-224":
		case "SHA3-224":
			return 28;
		case "SHA-256":
		case "SHA3-256":
		case "SHAKE128":
			return 32;
		case "SHA-384":
		case "SHA3-384":
			return 48;
		case "SHA-512":
		case "SHA3-512":
		case "SHAKE256":
			return 64;
		default:
			throw new Error("alg.HashSize: unsupported algorithm: " + alg);
	}
}

/**
 * SigSize returns the signature size for the given algorithm in bytes.
 * 
 * Curve P-521 uses 521 bits.  This is then padded up the the nearest byte (528)
 * for R and S. 132 = (528*2)/8
 * 
 * See notes on the Go implementation of Coze for more
 * 
 * @param   {Alg}      alg
 * @returns {Number}
 * @throws  {Error}
 */
function SigSize(alg) {
	switch (alg) {
		case "ES224":
			return 56
		case "ES256":
		case "Ed25519":
		case "Ed25519ph":
			return 64
		case "ES384":
			return 96
		case "Ed448":
			return 114
		case "ES512":
			return 132
		default:
			throw new Error("alg.SigSize: unsupported algorithm: " + alg);
	}
}

/**
 * XSize returns the signature size for the given signature algorithm in bytes.
 * E.g. 64.
 * 
 * ES512 uses Curve P-521 that's 521 bits is padded up the the nearest byte
 * (528) for R and S. (528*2)/8 = 132.
 *
 * See notes on the Go implementation of Coze for more.
 * 
 * @param   {Alg}     alg
 * @returns {Number}
 * @throws  {Error}
 */
function XSize(alg) {
	switch (alg) {
		case "Ed25519":
		case "Ed25519ph":
			return 32
		case "ES224":
			return 56
		case "Ed448":
			return 57
		case "ES256":
			return 64
		case "ES384":
			return 96
		case "ES512":
			return 132 // X and Y are 66 bytes (Rounded up for P521)
		default:
			throw new Error("alg.XSize: unsupported algorithm: " + alg);
	}
}

/**
 * DSize returns the signature size for the given signature algorithm in bytes.
 * E.g. 64.
 * 
 * ES512 uses Curve P-521 that's 521 bits is padded up the the nearest byte
 * (528). (528)/8 = 66.
 *
 * See notes on the Go implementation of Coze for more
 * 
 * @param   {Alg}     alg
 * @returns {Number}
 * @throws  {Error}
 */
function DSize(alg) {
	switch (alg) {
		case "ES224":
			return 28
		case "ES256":
		case "Ed25519":
		case "Ed25519ph":
			return 32
		case "ES384":
			return 48
		case "Ed448":
			return 57
		case "ES512":
			return 66
		default:
			throw new Error("alg.DSize: unsupported algorithm: " + alg);
	}
}

/**
 * Curve returns the curve algorithm for the given signature algorithm.
 * E.g. "P-256".
 * 
 * See notes on the Go implementation of Coze for more.
 *
 * @param   {Alg}    alg 
 * @returns {Curve}
 * @throws  {Error}
 */
function Curve(alg) {
	switch (alg) {
		case "ES224":
			return "P-224";
		case "ES256":
			return "P-256";
		case "ES384":
			return "P-384";
		case "ES512": // P-521 is not ES512/SHA-512.  The curve != the alg/hash.
			return "P-521";
		case "Ed25519":
		case "Ed25519ph":
			return "Curve25519";
		case "Ed448":
			return "Curve448";
		default:
			throw new Error("alg.Curve: unsupported algorithm: " + alg);
	}
}

/**
 * Use returns the use for the given algorithm.  Only "sig", "enc", and "dig"
 * are currently valid.
 * Encryption ("enc") is currently not supported in Coze.
 * 
 * See notes on the Go implementation of Coze for more.
 * 
 * @param   {Alg}     alg 
 * @returns {Use}
 * @throws  {Error}
 */
function Use(alg) {
	switch (Genus(alg)) {
		case "EdDSA":
		case "ECDSA":
			return "sig";
		case "SHA2":
		case "SHA3":
			return "dig";
		default:
			throw new Error("alg.Use: unsupported algorithm: " + alg);
	}
}