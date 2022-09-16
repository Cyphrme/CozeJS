"use strict";

// Typedefs will not be exported without this keyword present.
export {}

/**
 * Alg is a declarative abstraction for cryptographic functions for Coze.
 * For more on Alg, see the main Coze README:
 * https://github.com/Cyphrme/Coze#readme
 * Alg is the algorithm being used. E.g. "ES256".
 * @typedef  {String} Alg
 */

/**
 * Genus is the genus for an Alg (Level 1). E.g. "SHA2", "ECDSA".
 * @typedef  {String} Genus
 */

/**
 * Family is the family for an Alg (Level 2). E.g. "SHA", "EC".
 * @typedef  {String} Family
 */

/**
 * Hash is the hashing algorithm. E.g. "SHA-256".
 * @typedef  {String} Hash
 */

/**
 * Curve is the (elliptic) curve used for Alg. E.g. "P-256".
 * @typedef  {String} Curve
 */

/**
 * Use is the use for Alg. E.g. "sig", "enc", "dig".
 * @typedef  {String} Use
 */

/** 
 * Params holds all relevant values for an `alg`. If values are not applicable
 * for a particular `alg`, values may be populated with the zero value, e.g.
 * for the hash alg "SHA-256" Curve's value is 0.
 * 
 * -Name:     Alg string Name.
 * -Genus:    Genus                              E.g. "SHA2", "ECDSA".
 * -Family:   Family                             E.g. "SHA", "EC".
 * -Hash:     Hash is the hashing algorithm.     E.g. "SHA-256".
 * -HashSize: Size in bytes of the digest.       E.g. 32 for "SHA-256".
 * -SigSize:  Size in bytes of the signature.    E.g. 64 for "ES256".
 * -XSize:    Size in bytes of `x`.              E.g. "64" for ES256
 * -DSize:    Size in bytes of `d`.              E.g. "32" for ES256
 * -Curve:    Curve is the elliptic curve.       E.g. "P-256".
 * -Use:      Algorithm use.                     E.g. "sig".
* @typedef  {Object}  Params
* @property {string}  Name 
* @property {Genus}   Genus
* @property {Family}  Family
* @property {Hash}    Hash 
* @property {Number}  HashSize
* @property {Number}  SigSize
* @property {Number}  XSize
* @property {Number}  DSize
* @property {Curve}   Curve
* @property {Use}     Use
* @property {B64P}    B64
/*

/**
 * B64 is a Params object for Base64ut encoding.
 * @typedef {Params} B64P
 */

/**
 * An array or object representing a canon.
 * If object, only the first level keys are used as canon.
 * @typedef  {Array|Object} Canon
 */

////  Basic Coze Types

/**
 * Coze b64ut (RFC 4648 base64 url truncated)
 * @typedef  {String} B64
 */

/**
 * A not-hashed message to be signed.
 @typedef {String} Message
 */

/**
 * A digest.
 @typedef  {B64} Digest
 */

/**
 * A signature.
 @typedef {B64} Sig
 */

/**
 * Unix time.
 @typedef {Number} Time
 */

/**
 * Pay contains the standard `Coze.Pay` fields.
 * 
 * - alg:    Algorithm.            E.g. "ES256".
 * - iat:    Unix time of signing. E.g. 1623132000.
 * - tmb:    Signing thumbprint    E.g. cLj8vsYtMBwYkzoFVZHBZo6SNL8wSdCIjCKAwXNuhOk
 * - typ:    Type.                 E.g. "cyphr.me/msg/create".
 * @typedef  {Object} Pay
 * @property {Alg}    alg
 * @property {Time}   iat
 * @property {B64}    tmb
 * @property {String} typ
 */

/**
 * Coze is a signed coze object.  See docs for more about `coze`.
 * 
 * - pay:   The `pay`.  See docs on Pay for more.
 * - sig:   The B64 signature.
 * - cad:   Canonical digest of `pay`.  E.g.  LSgWE4vEfyxJZUTFaRaB2JdEclORdZcm4UVH9D8vVto
 * - can:   The canon fields of pay.    E.g.  ["alg", "iat", "msg", "tmb", "typ"]
 * - czd:   "Coze digest" over `{"cad":...,"sig":...}`.
 * - key:   Coze Key used to sign `coze`.
 * @typedef  {Object}  Coze
 * @property {Pay}     pay
 * @property {Sig}     sig
 * @property {Digest}  [cad]
 * @property {Array}   [can]
 * @property {Digest}  [czd]
 * @property {Key}     [key]
 */

/**
 * VerifiedArray - Used when verifying array of cozies.
 * 
 * - VerifiedAll:    Indicates if whole array was verified. False on error or if
 *                   anything was not verified.
 * - VerifiedCount:  Number of objects verified.
 * - FailedCount:    Number of objects that failed verification.
 * - FailedCoze:     Objects that failed verification.
 * @typedef  {Object}  VerifiedArray
 * @property {Boolean} VerifiedAll
 * @property {Number}  VerifiedCount
 * @property {Number}  FailedCount
 * @property {Coze[]}  FailedCoze
 */

/**
 * Key holds a cryptographic key, with the minimum required fields for the 
 * given `alg`.
 *
 * -alg: Cryptographic signing or encryption algorithm - e.g. "ES256"
 * 
 * -kid: Human readable, non programmatic, key identifier - e.g. "Test Key"
 * 
 * -iat: Unix time key was created. e.g. 1624472390
 * 
 * -tmb: Key thumbprint e.g. "cLj8vsYtMBwYkzoFVZHBZo6SNL8wSdCIjCKAwXNuhOk"
 * 
 * -d:   ECDSA private "d" component in b64ut. Required for ECDSA private Coze keys.
 * e.g. "bNstg4_H3m3SlROufwRSEgibLrBuRq9114OvdapcpVA"
 * 
 * -x:   ECDSA public "x" component in b64ut. Required for ECDSA public Coze keys.
 * e.g. "2nTOaFVm2QLxmUO_SjgyscVHBtvHEfo2rq65MvgNRjORojq39Haq9rXNxvXxwba_Xj0F5vZibJR3isBdOWbo5g"
 * @typedef  {Object} Key
 * @property {Alg}    alg
 * @property {String} kid
 * @property {Time}   iat
 * @property {B64}    tmb
 * @property {B64}    [d]
 * @property {B64}    [x]
 */

/**
 * PrivateCozeKey is a Coze key containing any private components.
 * @typedef  {Key} PrivateCozeKey
 */

/**
 * PublicCozeKey is a Coze key containing no private components and required public components.
 * @typedef  {Key} PublicCozeKey
 **/

/** 
 * Meta holds metadata for a Coze object.
 * [pay, key, iat, can, cad, czd, tmb, sig]
 * The optional fields in a Coze are all present in a Meta. 
 * @typedef  {Coze}  Meta
 */