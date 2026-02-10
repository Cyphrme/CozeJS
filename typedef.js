"use strict";

// Typedefs are not exported without `export` keyword present.
export { }

/**
General Notes See the Go implementation (Cyphrme/Coz) for full Coz
documentation.  

Alg is a declarative abstraction for cryptographic functions for Coz. For more
on Alg, see the main Coz README, and the Go implementation, `alg.go`:
https://github.com/Cyphrme/Coz#readme

`can` is defined as type string[] and not type object.  Some canon related
functions may permit a canon as type object and those functions should
explicitly document that usage. For those functions, if Can is object, only the
first level keys should be used and nested keys should be ignored.  

In Coz, the message is always a "pay".  "pay" is then hashed and the resulting
digest is signed.  
*/


/**
@typedef {string}     B64    b64ut (RFC 4648 base64 url truncated)
@typedef {B64}        Dig    A digest encoded as b64ut.

@typedef {string}     Alg    Algorithm in use, e.g. "ES256".
@typedef {number}     Now    Unix time, e.g. 1623132000.
@typedef {Dig}        Tmb    Thumbprint, e.g. "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg"
@typedef {string}     Typ    Type,  e.g. "cyphr.me/msg"

@typedef {B64}        Sig    A cryptographic signature, e.g. "Jl8Kt4nznAf0LGgO5yn_9HkGdY3ulvjg-NyRGzlmJzhncbTkFFn9jrwIwGoRAQYhjc88wmwFNH5u_rO56USo_w"

@typedef {string}     Tag    Non-programmatic key identifier, e.g. "Zami's Majuscule Key."

@typedef {string[]}   Can    Canon, e.g. ["alg","now","msg","tmb","typ"].  
@typedef {Dig}        Cad    "Canonical digest" of `pay`, e.g. "Ie3xL77AsiCcb4r0pbnZJqMcfSBqg5Lk0npNJyJ9BC4"
@typedef {Dig}        Czd    "Coz digest" of `coz`, e.g. "TnRe4DRuGJlw280u3pGhMDOIYM7ii7J8_PhNuSScsIU"

@typedef {string}     Msg    A not-hashed, non-digest, "raw" message, e.g. `{"msg":"Coz Rocks","alg":"ES256","now":1623132000,"tmb":"U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg","typ":"cyphr.me/msg"}`

@typedef {Key}        SK     Private Coz key, an object containing private component `prv`.
@typedef {Key}        PK     Public Coz key, an object containing `pub` and not containing `prv`.

@typedef {string}     Gen    Gen is the genus for an Alg (Level 1), e.g. "SHA2", "ECDSA".
@typedef {string}     Fam    Fam is the family for an Alg (Level 2), e.g. "SHA", "EC".
@typedef {string}     Hsh    Hsh is a hashing algorithm that results in a digest, e.g. "SHA-256".
@typedef {string}     Crv    Crv is the (elliptic) curve used for Alg, e.g. "P-256".
@typedef {string}     Use    Use is the use for Alg, e.g. "sig", "enc", "dig".
*/

/**
 * Metadata object. [pay, key, now, can, cad, czd, tmb, sig]
@typedef {object}  Meta  
@property {Alg}    alg
@property {Now}    [now]
@property {B64}    [tmb]
@property {string} [typ]
@property {Can}    can
@property {Cad}    cad
@property {Sig}    [sig]
@property {Czd}    [czd]
*/


/**
Coz is a signed coz object.  See Go implementation docs (Cyphrme/Coz).

- pay:   The `pay`.  See docs on Pay for more.
- sig:   The B64 signature.
- cad:   Canonical digest of `pay`.  E.g.  LSgWE4vEfyxJZUTFaRaB2JdEclORdZcm4UVH9D8vVto
- can:   The canon of pay.    E.g.  ["alg", "now", "msg", "tmb", "typ"]
- czd:   "Coz digest" over `{"cad":...,"sig":...}`.
- key:   Coz Key used to sign `coz`.
@typedef  {object}  Coz
@property {Pay}     pay
@property {Sig}     sig
@property {Cad}     [cad]
@property {Can}     [can]
@property {Czd}     [czd]
@property {Key}     [key]
*/


/**
Pay contains the standard `Coz.Pay` fields.  See Go implementation docs (Cyphrme/Coz).

- alg:    Algorithm.            E.g. "ES256".
- now:    Unix time of signing. E.g. 1623132000.
- tmb:    Signing thumbprint    E.g. U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg
- typ:    Type.                 E.g. "cyphr.me/msg/create".
- msg:    Message payload.      E.g. "Coz is a cryptographic JSON messaging specification."
- dig:    Digest of external content. E.g. "LSgWE4v..."
- rvk:    Key revocation time.  E.g. 1623132000.  Only for revoke messages.
@typedef  {object} Pay
@property {Alg}    alg
@property {Now}    now
@property {Tmb}    tmb
@property {Typ}    typ
@property {string} [msg]
@property {Dig}    [dig]
@property {Now}    [rvk]
*/


/**
Key holds a cryptographic key, with the minimum required fields for the 
given `alg`. See Go implementation docs (Cyphrme/Coz).
 *
-alg: Cryptographic signing or encryption algorithm - e.g. "ES256"

-tag: Human readable, non programmatic, key identifier - e.g. "Test Key"

-now: Unix time key was created. e.g. 1624472390

-tmb: Key thumbprint e.g. "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg"

-prv:  ECDSA private component in b64ut. Required for ECDSA private Coz keys.
e.g. "bNstg4_H3m3SlROufwRSEgibLrBuRq9114OvdapcpVA"

-pub:  ECDSA public component in b64ut. Required for ECDSA public Coz keys.
e.g. "2nTOaFVm2QLxmUO_SjgyscVHBtvHEfo2rq65MvgNRjORojq39Haq9rXNxvXxwba_Xj0F5vZibJR3isBdOWbo5g"
@typedef  {object} Key
@property {Alg}    alg
@property {Tag}    tag
@property {Now}    now
@property {B64}    tmb
@property {B64}    [prv]
@property {B64}    [pub]
*/


/** 
Params holds all relevant values for an `alg`. If values are not applicable
for a particular `alg`, values may be populated with the zero value, e.g.
for the hash alg "SHA-256" Curve's value is "" and PubSize is 0.

-Name:       Alg string Name.
-Genus:      Genus                              E.g. "SHA2", "ECDSA".
-Family:     Family                             E.g. "SHA", "EC".
-Hash:       Hash is the hashing algorithm.     E.g. "SHA-256".
-HashSize:   Size in bytes of the digest.       E.g. 32 for "SHA-256".
-SigSize:    Size in bytes of the signature.    E.g. 64 for "ES256".
-PubSize:    Size in bytes of `pub`.            E.g. "64" for ES256
-PrvSize:    Size in bytes of `prv`.            E.g. "32" for ES256
-Curve:      Curve is the elliptic curve.       E.g. "P-256".
-Use:        Algorithm use.                     E.g. "sig".
@typedef  {object}    Params
@property {string}    Name
@property {Gen}       Genus
@property {Fam}       Family
@property {Use}       Use
@property {Dig}       Hash
@property {number}    HashSize
@property {number}    HashSizeB64
@property {number}    PubSize
@property {number}    PubSizeB64
@property {number}    PrvSize
@property {number}    PrvSizeB64
@property {Crv}       Curve
@property {number}    SigSize
@property {number}    SigSizeB64
*/
