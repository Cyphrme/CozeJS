"use strict";

export {
	Params,
	Curve,
	Family,
	Genus,
	HashAlg,
	HashSize,
	SigSize,
	Use,
}

// See notes on the Go implementation of Coze for more on Alg, Genus, Family,
// HashAlg, CurveAlg, and  Use.

/** 
* @typedef  {String} Alg     - Coze.Alg.  Alg is the algorithm string, e.g. "ES256" 
* @typedef  {String} Genus   - Genus is the genus string,              e.g. "SHA2", "ECDSA".
* @typedef  {String} Family  - Family is the family string,            e.g. "SHA", "EC".
* @typedef  {String} Hash    - Hash is the hashing algorithm string.   e.g. "SHA-256".
* @typedef  {String} Curve   - Curve is the elliptic curve string,     e.g. "P-256".
* @typedef  {String} Use     - Use is the algorithm use string,        e.g. "sig" or "enc"
/*

/** 
* Params holds all relevant values for an `alg`. If values are not applicable
  for a particular `alg`, values may be populated with the zero value, e.g.
  for the hash alg "SHA-256" Curve's value is 0.
* @typedef  {Object}  Params
* @property {string}  Name      - Name is the string representation of alg
* @property {Genus}   Genus     - Genus is the genus string,                    e.g. "SHA2", "ECDSA".
* @property {Family}  Family    - Family is the family string,                  e.g. "SHA", "EC".
* @property {Hash}    Hash      - Hash is the hashing algorithm string.         e.g. "SHA-256".
* @property {number}  HashSize  - HashSize is the size/length of the digest.    e.g. 32 for "SHA-256".
* @property {number}  SigSize   - SigSize is the size/length of the signature.  e.g. 64 for "ES256".
* @property {Curve}   Curve     - Curve is the elliptic curve string,           e.g. "P-256".
* @property {Use}     Use       - Use is the algorithm use string,
/*

/**
 * Params reports all relevant values for a given `alg`.
 * @param {string} alg  String. Alg is the string representation of a coze.Alg
 * @returns {Params}    Params object with populated values for relevant fields
*/
 function Params(alg) {
	/** @type {Params} */
	let p = {Name:alg};
	p.Genus = Genus(alg);
	p.Family = Family(alg);
	p.Hash = HashAlg(alg);
	p.HashSize = HashSize(alg);

	try {
		p.Curve = Curve(alg);
	} catch (e) {
		// ignore error
	}
	try {
		p.Use = Use(alg);
		p.SigSize = SigSize(alg);
	} catch (e) {
		// ignore error
	}
	return p;
}

/**
 * Genus returns the genus for an alg (ECDSA, EdDSA, SHA-2, SHA-3).
 * See notes on the Go implementation of Coze for more on genus.
 * @param   {Alg}     alg 
 * @returns {Use}
 * @throws error
 */
function Genus(alg) {
	switch (alg) {
		case "ES224":
		case "ES256":
		case "ES384":
		case "ES512":
			return "ECDSA";
		case "Ed25519":
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
			throw new Error("coze_enum.Genus: unsupported algorithm for genus");
	}
}

/**
 * Family returns the family for an alg (EC and SHA).
 * See notes on the Go implementation of Coze for more on family.
 * @param   {Alg}     alg 
 * @returns {Family}
 * @throws error
 */
function Family(alg) {
	switch (alg) {
		case "ES224":
		case "ES256":
		case "ES384":
		case "ES512":
		case "Ed25519":
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
			throw new Error("coze_enum.Family: unsupported algorithm for family");
	}
}

/**
 * Hash returns the hashing algorithm for the given algorithm.  
 * See notes on the Go implementation of Coze for more.
 * @param   {Alg}   alg 
 * @returns {Hash}  Hash Alg as a string, e.g. "SHA-256".
 * @throws error
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
			throw new Error("coze_enum.HashAlg: unsupported algorithm for HashAlg");
	}
}

/**
 * HashSize returns the hashing algorithm for the given algorithm.  
 * 
 * SHAKE128 has 128 bits of pre-collision resistance and a capacity of 256,
 * although it has arbitrary output size. SHAKE256 has 256 bits of pre-collision
 * resistance and a capacity of 512, although it has arbitrary output size.
 * 
 * See notes on the Go implementation of Coze for more
 * @param   {Alg}     alg - alg string
 * @returns {Number}  size of the hash alg in bytes.  (e.g. 32)
 * @throws error
 */
function HashSize(alg) {
	// If given alg that is not a hash, attempt to retrieve the hash alg
	let ha = HashAlg(alg);
	if (ha != alg) {
		alg = ha;
	}
	switch (alg) {
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
			throw new Error("coze_enum.HashSize: unsupported algorithm for hash size");
	}
}

/**
 * SigSize returns the signature size for the given algorithm.  
 * 
 * Curve P-521 uses 521 bits.  This is then padded up the the nearest byte (528)
 * for R and S. 132 = (528*2)/8
 * 
 * See notes on the Go implementation of Coze for more
 * @param   {Alg}     alg - Sig alg string, e.g. "ES256"
 * @returns {Number}  size of the sig alg in bytes.  (e.g. 64)
 * @throws error
 */
 function SigSize(alg) {
	switch (alg) {
		case "ES224":
			return 56
		case "ES256":
		case "Ed25519":
			return 64
		case "ES384":
			return 96
		case "Ed448":
			return 114
		case "ES512":
			return 132
		default:
			throw new Error("coze_enum.SigSize: unsupported algorithm for sig size");
	}
}

/**
 * Curve returns the curve algorithm for the given algorithm.  
 * 
 * See notes on the Go implementation of Coze for more
 * @param   {Alg}    alg 
 * @returns {Curve}  The curve alg as a string, e.g. "SHA-256".
 * @throws error
 */
function Curve(alg) {
	switch (alg) {
		case "ES256":
			return "P-256";
		case "ES384":
			return "P-384";
		case "ES512": // P-521 is not ES512/SHA-512.  The curve != the alg/hash. 
			return "P-521";
		case "Ed25519":
			return "Curve25519";
		case "Ed448":
			return "Curve448";
		default:
			throw new Error("coze_enum.Curve: unsupported algorithm for curve");
	}
}

/**
 * Use returns the use for the given algorithm.  Only "sig" or "enc" are
 * currently valid, and Coze currently only uses "sig".
 * 
 * See notes on the Go implementation of Coze for more
 * @param   {Alg}     alg 
 * @returns {Use}     The string "sig" or "enc"
 * @throws error
 */
function Use(alg) {
	switch (alg) {
		case "ES256":
		case "ES384":
		case "ES512":
		case "Ed25519":
		case "Ed448":
			return "sig";
		default:
			throw new Error("coze_enum.Use: unsupported algorithm for use");
	}
}