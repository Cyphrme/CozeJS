"use strict";

// For more documentation and notes, see the main Coze README.

export {
	Algs,
	FamAlgs,
	GenAlgs,
	Curves,
	Uses,

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
	CurveOrder,
	CurveHalfOrder,
}

/**
@typedef {import('./typedefs.js').Params}  Params
@typedef {import('./typedefs.js').Alg}     Alg
@typedef {import('./typedefs.js').Hsh}     Hsh
@typedef {import('./typedefs.js').Gen}     Gen
@typedef {import('./typedefs.js').Fam}     Fam
@typedef {import('./typedefs.js').Crv}     Crv
@typedef {import('./typedefs.js').Use}     Use
*/

/**
Algs holds all of the supported Coze algorithms.
*/
const Algs = {
	UnknownAlg: "UnknownAlg",
	ES224: "ES224",
	ES256: "ES256",
	ES384: "ES384",
	ES512: "ES512",
	Ed25519: "Ed25519",
	Ed25519ph: "Ed25519ph",
	Ed448: "Ed448",
	SHA224: "SHA-224",
	SHA256: "SHA-256",
	SHA384: "SHA-384",
	SHA512: "SHA-512",
	SHA3224: "SHA3-224",
	SHA3256: "SHA3-256",
	SHA3384: "SHA3-384",
	SHA3512: "SHA3-512",
	SHAKE128: "SHAKE128",
	SHAKE256: "SHAKE256",
};

/**
FamAlgs holds all of the supported Coze Family algorithms.
*/
const FamAlgs = {
	EC: "EC",
	SHA: "SHA",
	RSA: "RSA",
};

/**
GenAlgs holds all of the supported Coze Genus algorithms.
*/
const GenAlgs = {
	ECDSA: "ECDSA",
	EdDSA: "EdDSA",
	SHA2: "SHA2",
	SHA3: "SHA3",
};

/**
Curves holds all of the supported Coze curve algorithms.
*/
const Curves = {
	P224: "P-224",
	P256: "P-256",
	P384: "P-384",
	P521: "P-521",
	Curve25519: "Curve25519",
	Curve448: "Curve448",
};

/**
Uses holds all of the supported Coze uses.
*/
const Uses = {
	Sig: "sig",
	Enc: "enc",
	Hsh: "hsh",
};

/**
Param reports all relevant values for a given `alg`.
Returns Params object with populated values for relevant fields.
All functions defined in this file will throw an error when given an
unsupported algorithm.
@param   {Alg}      alg
@returns {Params}
@throws  {error}
*/
function Params(alg) {
	/** @type {Params} */
	let p = {};
	p.Name = alg;
	p.Genus = Genus(alg);
	p.Family = Family(alg);
	p.Use = Use(alg);
	p.Hash = HashAlg(alg);
	p.HashSize = HashSize(alg);
	p.HashSizeB64 = Math.ceil(4 * p.HashSize / 3);

	// SigAlg parameters
	try {
		p.XSize = XSize(alg);
		p.XSizeB64 = Math.ceil(4 * p.XSize / 3);
		p.DSize = DSize(alg);
		p.DSizeB64 = Math.ceil(4 * p.DSize / 3);
		p.Curve = Curve(alg);
		p.SigSize = SigSize(alg);
		p.SigSizeB64 = Math.ceil(4 * p.SigSize / 3);
	} catch (e) {
		// ignore error
	}

	return p;
}

/**
Genus returns the genus for an alg (ECDSA, EdDSA, SHA-2, SHA-3).
See notes on the Go implementation of Coze for more on genus.
@param   {Alg}   alg
@returns {Gen}
@throws  {error}
*/
function Genus(alg) {
	switch (alg) {
		case Algs.ES224:
		case Algs.ES256:
		case Algs.ES384:
		case Algs.ES512:
			return GenAlgs.ECDSA;
		case Algs.Ed25519:
		case Algs.Ed25519ph:
		case Algs.Ed448:
			return GenAlgs.EdDSA;
		case Algs.SHA224:
		case Algs.SHA256:
		case Algs.SHA384:
		case Algs.SHA512:
			return GenAlgs.SHA2;
		case Algs.SHA3224:
		case Algs.SHA3256:
		case Algs.SHA3384:
		case Algs.SHA3512:
		case Algs.SHAKE128:
		case Algs.SHAKE256:
			return GenAlgs.SHA3;
		default:
			throw new Error("alg.Genus: unsupported algorithm: " + alg);
	}
}

/**
Family returns the family for an alg (EC and SHA).
See notes on the Go implementation of Coze for more on family.
@param   {Alg}     alg
@returns {Fam}
@throws  {error}
*/
function Family(alg) {
	switch (alg) {
		case Algs.ES224:
		case Algs.ES256:
		case Algs.ES384:
		case Algs.ES512:
		case Algs.Ed25519:
		case Algs.Ed25519ph:
		case Algs.Ed448:
			return FamAlgs.EC;
		case Algs.SHA224:
		case Algs.SHA256:
		case Algs.SHA384:
		case Algs.SHA512:
		case Algs.SHA3224:
		case Algs.SHA3256:
		case Algs.SHA3384:
		case Algs.SHA3512:
		case Algs.SHAKE128:
		case Algs.SHAKE256:
			return FamAlgs.SHA
		default:
			throw new Error("alg.Family:  unsupported algorithm: " + alg);
	}
}

/**
Hash returns the hashing algorithm for the given algorithm.  A hash alg can
return itself.
See notes on the Go implementation of Coze for more.
@param   {Alg}   alg 
@returns {Hsh}
@throws  {error}
*/
function HashAlg(alg) {
	switch (alg) {
		case Algs.ES224:
		case Algs.SHA224:
			return Algs.SHA224;
		case Algs.SHA256:
		case Algs.ES256:
			return Algs.SHA256;
		case Algs.SHA384:
		case Algs.ES384:
			return Algs.SHA384;
		case Algs.SHA512:
		case Algs.ES512: // P-521 is not ES512/SHA-512.  The curve != the alg/hash.
		case Algs.Ed25519:
		case Algs.Ed25519ph:
			return Algs.SHA512;
		case Algs.SHAKE128:
			return Algs.SHAKE128
		case Algs.SHAKE256:
		case Algs.Ed448:
			return Algs.SHAKE256
		case Algs.SHA3224:
			return Algs.SHA3224
		case Algs.SHA3256:
			return Algs.SHA3256
		case Algs.SHA3384:
			return Algs.SHA3384
		case Algs.SHA3512:
			return Algs.SHA3512
		default:
			throw new Error("alg.HashAlg:  unsupported algorithm: " + alg);
	}
}

/**
HashSize returns the hashing algorithm size for the given algorithm in bytes
E.g. 32.

SHAKE128 has 128 bits of pre-collision resistance and a capacity of 256,
although it has arbitrary output size. SHAKE256 has 256 bits of pre-collision
resistance and a capacity of 512, although it has arbitrary output size.

See notes on the Go implementation of Coze for more.
@param   {Alg}     alg
@returns {number}
@throws  {error}
*/
function HashSize(alg) {
	switch (HashAlg(alg)) {
		case Algs.SHA224:
		case Algs.SHA3224:
			return 28;
		case Algs.SHA256:
		case Algs.SHA3256:
		case Algs.SHAKE128:
			return 32;
		case Algs.SHA384:
		case Algs.SHA3384:
			return 48;
		case Algs.SHA512:
		case Algs.SHA3512:
		case Algs.SHAKE256:
			return 64;
		default:
			throw new Error("alg.HashSize: unsupported algorithm: " + alg);
	}
}

/**
SigSize returns the signature size for the given algorithm in bytes.

Curve P-521 uses 521 bits.  This is then padded up the the nearest byte (528)
for R and S. 132 = (528*2)/8

See notes on the Go implementation of Coze for more.
@param   {Alg}      alg
@returns {number}
@throws  {error}
*/
function SigSize(alg) {
	switch (alg) {
		case Algs.ES224:
			return 56
		case Algs.ES256:
		case Algs.Ed25519:
		case Algs.Ed25519ph:
			return 64
		case Algs.ES384:
			return 96
		case Algs.Ed448:
			return 114
		case Algs.ES512:
			return 132
		default:
			throw new Error("alg.SigSize: unsupported algorithm: " + alg);
	}
}

/**
XSize returns the signature size for the given signature algorithm in bytes.
E.g. 64.

ES512 uses Curve P-521 that's 521 bits is padded up the the nearest byte
(528) for R and S. (528*2)/8 = 132.

See notes on the Go implementation of Coze for more.
@param   {Alg}     alg
@returns {number}
@throws  {error}
*/
function XSize(alg) {
	switch (alg) {
		case Algs.Ed25519:
		case Algs.Ed25519ph:
			return 32
		case Algs.ES224:
			return 56
		case Algs.Ed448:
			return 57
		case Algs.ES256:
			return 64
		case Algs.ES384:
			return 96
		case Algs.ES512:
			return 132 // X and Y are 66 bytes (Rounded up for P521)
		default:
			throw new Error("alg.XSize: unsupported algorithm: " + alg);
	}
}

/**
DSize returns the signature size for the given signature algorithm in bytes.
E.g. 64.

ES512 uses Curve P-521 that's 521 bits is padded up the the nearest byte
(528). (528)/8 = 66.

See notes on the Go implementation of Coze for more.
@param   {Alg}     alg
@returns {number}
@throws  {error}
*/
function DSize(alg) {
	switch (alg) {
		case Algs.ES224:
			return 28
		case Algs.ES256:
		case Algs.Ed25519:
		case Algs.Ed25519ph:
			return 32
		case Algs.ES384:
			return 48
		case Algs.Ed448:
			return 57
		case Algs.ES512:
			return 66
		default:
			throw new Error("alg.DSize: unsupported algorithm: " + alg);
	}
}

/**
Curve returns the curve algorithm for the given signature algorithm.
E.g. "P-256".

See notes on the Go implementation of Coze for more.
@param   {Alg}    alg 
@returns {Crv}
@throws  {error}
*/
function Curve(alg) {
	switch (alg) {
		default:
			throw new Error("alg.Curve: unsupported algorithm: " + alg);
		case Algs.ES224:
			return Curves.P224;
		case Algs.ES256:
			return Curves.P256;
		case Algs.ES384:
			return Curves.P384;
		case Algs.ES512: // P-521 is not ES512/SHA-512.  The curve != the alg/hash.
			return Curves.P521;
		case Algs.Ed25519:
		case Algs.Ed25519ph:
			return Curves.Curve25519;
		case Algs.Ed448:
			return Curves.Curve448;
	}
}

/**
Use returns the use for the given algorithm.  Only "sig", "enc", and "dig"
are currently valid.
Encryption ("enc") is currently not supported in Coze.

See notes on the Go implementation of Coze for more.
@param   {Alg}     alg 
@returns {Use}
@throws  {error}
*/
function Use(alg) {
	switch (Genus(alg)) {
		default:
			throw new Error("alg.Use: unsupported algorithm: " + alg);
		case GenAlgs.EdDSA:
		case GenAlgs.ECDSA:
			return Uses.Sig;
		case GenAlgs.SHA2:
		case GenAlgs.SHA3:
			return Uses.Hsh;
	}
}

const order = { 
	"ES224" : BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D"),
	"ES256" : BigInt("0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"),
	"ES384" : BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973"),
	"ES512" : BigInt("0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409"),
}

const halfOrder = { 
	"ES224" : order["ES224"] >> BigInt(1),
	"ES256" : order["ES256"] >> BigInt(1),
	"ES384" : order["ES384"] >> BigInt(1),
	"ES512" : order["ES512"] >> BigInt(1),
}

/**
Curve Order returns the Curve's order.  
@param   {Alg}     Alg 
@returns {BigInt}
@throws  {error}
*/
function CurveOrder(alg) {
	switch (alg) {
		default:
			throw new Error("CurveOrder: unsupported curve: " + alg);
		case  "ES224": case "ES256": case "ES384": case "ES512":
			return order[alg];
	}
}

/** 
Curve Order returns the Curve's order halved.  
@param   {Alg}     Alg 
@returns {BigInt}
@throws  {error}
*/
function CurveHalfOrder(alg) {
	switch (alg) {
		default:
			throw new Error("CurveHalfOrder: unsupported curve: " + alg);
	 case  "ES224": case "ES256": case "ES384": case "ES512":
			return halfOrder[alg];
	}
}
