"use strict";

import * as Can from './canon.js'; // import as "Can".
import * as Enum from './alg.js';
import {
	isEmpty,
} from './coze.js';

export {
	NewKey,
	Thumbprint,
	Valid,
	Correct,
	Revoke,
	IsRevoked,

	KeyCanon,
}

/**
@typedef {import('./typedef.js').Alg}   Alg
@typedef {import('./typedef.js').B64}   B64
@typedef {import('./typedef.js').Key}   Key
@typedef {import('./typedef.js').Coz}   Coz
@typedef {import('./typedef.js').Can}   Can
 */

// KeyCanon is the canonical form of a Coz key.
const KeyCanon = ["alg", "pub"];

/**
NewKey generates a new Coz key with given alg, `tmb`, `now`, and `tag`.  
`tag` is optional. 
@param   {Alg}      alg       Algorithm to use for key generation.
@param   {string}   [tag]     Key identifier, readable label.
@returns {Key}
@throws  {error}     Error, SyntaxError, DOMException, TypeError
 */
async function NewKey(alg, tag) {
	let cozKey = await CTK.CryptoKey.ToCozKey(
		(await CTK.CryptoKey.New(alg)).privateKey
	);
	if (!isEmpty(tag)) {
		cozKey.tag = tag;
	}
	return cozKey;
};

import * as CTK from './cryptokey.js';

/**
Thumbprint calculates a thumbprint from the given Coz key.
@param  {Key}    cozKey  Coz key with `alg` and `pub` minimally populated.
@returns {B64}   Thumbprint
@throws  {error}
 */
async function Thumbprint(cozKey) {
	if (isEmpty(cozKey.pub)) {
		throw new Error("Thumbprint: Coz key pub must be set.");
	}
	return Can.CanonicalHash64(cozKey, Enum.HashAlg(cozKey.alg), KeyCanon);
}


/**
Valid validates a private Coz key by signing a message and verifying the
resulting signature with the key's public component.

Valid always returns false on public-only keys.  Use function "Verify" for
verification with a signed message.  See also function Correct.
@param  {Key}        cozKey  A Private Coz Key.
@return {boolean}    
 */
async function Valid(cozKey) {
	if (isEmpty(cozKey.prv)) {
		console.error("Coz key missing `prv`");
		return false;
	}
	try {
		let Coze = await import('./coze.js');
		let msg = `7AtyaCHO2BAG06z0W1tOQlZFWbhxGgqej4k9-HWP3DE-zshRbrE-69DIfgY704_FDYez7h_rEI1WQVKhv5Hd5Q`;
		let sig = await Coze.SignPay(msg, cozKey);
		return Coze.VerifyPay(msg, cozKey, sig);
	} catch (e) {
		//console.debug("Valid error: " + e);
		return false;
	}
}


/**
Correct checks for the correct construction of a Coz key.  Key must have at
least one of [`tmb`, `pub`, `prv`] and `alg` set.  
@param  {Key}     cozKey
@return {boolean}
@throws {error}
 */
async function Correct(cozKey) {
	// Check sizes
	if (!isEmpty(cozKey.pub) && cozKey.pub.length > 0) {
		// Verify tmb matches
		if (!isEmpty(cozKey.tmb)) {
			let tmb = await Thumbprint(cozKey);
			if (tmb !== cozKey.tmb) {
				throw new Error("Correct: Incorrect tmb");
			}
		}
	}

	// validate by signing and verifying only when both pub and prv are present.
	// SubtleCrypto cannot derive pub from prv, so we can only validate when pub
	// is also available.
	if (!isEmpty(cozKey.prv) && !isEmpty(cozKey.pub)) {
		if (!await Valid(cozKey)) {
			throw new Error("Correct: key is invalid");
		}
	}

	if (isEmpty(cozKey.pub) && isEmpty(cozKey.prv)) {
		// tmb only key - verify length
		if (!isEmpty(cozKey.tmb)) {
			return true;
		}
		throw new Error("Correct: at least one of [pub, tmb, prv] must be set");
	}

	return true;
}


/**
Revoke creates a self-revoke message from a given private Coz key.
@param   {Key}       cozKey       A private Coz key.
@param   {string}    [msg]        An optional message.
@returns {Coz}                    A signed Coz with revoke message.
@throws  {error}
 */
async function Revoke(cozKey, msg) {
	let Coze = await import('./coze.js');

	let coz = {
		pay: {
			alg: cozKey.alg,
			now: Math.round((Date.now() / 1000)),
			rvk: Math.round((Date.now() / 1000)),
			tmb: await Thumbprint(cozKey),
			typ: "cyphr.me/key/revoke",
		}
	};
	if (!isEmpty(msg)) {
		coz.pay.msg = msg;
	}

	coz.sig = await Coze.SignPay(JSON.stringify(coz.pay), cozKey);

	// Set rvk on the key itself.
	cozKey.rvk = coz.pay.rvk;
	return coz;
};


/**
IsRevoked returns true if the given Key is marked as revoked.
@param   {Key}     cozKey
@returns {boolean}
*/
function IsRevoked(cozKey) {
	if (!isEmpty(cozKey.rvk) && cozKey.rvk > 0) {
		return true;
	}
	return false;
}