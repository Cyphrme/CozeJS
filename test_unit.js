"use strict";

// Tests are run from `test_run.js` so that module imports don't run. Javascript
// (dumbly) executes code that isn't imported by other modules, meaning
// `document.addEventListener` is executed despite not being imported.  

import * as Coze from './coze.min.js';

export {
	TestBrowserJS
};

/**
 * @typedef {import('./test.js').Test} Test
 * @typedef {import('./test.js').Tests} Tests
 * @typedef {import('./test.js').TestsToRun} TestsToRun
 * @typedef {import('./test.js').TestGUIOptions} TestGUIOptions
 * @typedef {import('./test.js').TestBrowserJS} TestBrowserJS
 */

/**@type {Test} */
let t_Param = {
	"name": "Param",
	"func": test_Param,
	"golden": `
{"Name":"ES224","B64":{"HashSize":38,"SigSize":75,"XSize":75,"DSize":38},"Genus":"ECDSA","Family":"EC","Hash":"SHA-224","HashSize":28,"Curve":"P-224","Use":"sig","SigSize":56,"XSize":56,"DSize":28}
{"Name":"ES256","B64":{"HashSize":43,"SigSize":86,"XSize":86,"DSize":43},"Genus":"ECDSA","Family":"EC","Hash":"SHA-256","HashSize":32,"Curve":"P-256","Use":"sig","SigSize":64,"XSize":64,"DSize":32}
{"Name":"ES384","B64":{"HashSize":64,"SigSize":128,"XSize":128,"DSize":64},"Genus":"ECDSA","Family":"EC","Hash":"SHA-384","HashSize":48,"Curve":"P-384","Use":"sig","SigSize":96,"XSize":96,"DSize":48}
{"Name":"ES512","B64":{"HashSize":86,"SigSize":176,"XSize":176,"DSize":88},"Genus":"ECDSA","Family":"EC","Hash":"SHA-512","HashSize":64,"Curve":"P-521","Use":"sig","SigSize":132,"XSize":132,"DSize":66}
{"Name":"Ed25519","B64":{"HashSize":86,"SigSize":86,"XSize":43,"DSize":43},"Genus":"EdDSA","Family":"EC","Hash":"SHA-512","HashSize":64,"Curve":"Curve25519","Use":"sig","SigSize":64,"XSize":32,"DSize":32}
{"Name":"Ed25519ph","B64":{"HashSize":86,"SigSize":86,"XSize":43,"DSize":43},"Genus":"EdDSA","Family":"EC","Hash":"SHA-512","HashSize":64,"Curve":"Curve25519","Use":"sig","SigSize":64,"XSize":32,"DSize":32}
{"Name":"Ed448","B64":{"HashSize":86,"SigSize":152,"XSize":76,"DSize":76},"Genus":"EdDSA","Family":"EC","Hash":"SHAKE256","HashSize":64,"Curve":"Curve448","Use":"sig","SigSize":114,"XSize":57,"DSize":57}
{"Name":"SHA-224","B64":{"HashSize":38},"Genus":"SHA2","Family":"SHA","Hash":"SHA-224","HashSize":28}
{"Name":"SHA-256","B64":{"HashSize":43},"Genus":"SHA2","Family":"SHA","Hash":"SHA-256","HashSize":32}
{"Name":"SHA-384","B64":{"HashSize":64},"Genus":"SHA2","Family":"SHA","Hash":"SHA-384","HashSize":48}
{"Name":"SHA-512","B64":{"HashSize":86},"Genus":"SHA2","Family":"SHA","Hash":"SHA-512","HashSize":64}
{"Name":"SHA3-224","B64":{"HashSize":38},"Genus":"SHA3","Family":"SHA","Hash":"SHA3-224","HashSize":28}
{"Name":"SHA3-256","B64":{"HashSize":43},"Genus":"SHA3","Family":"SHA","Hash":"SHA3-256","HashSize":32}
{"Name":"SHA3-384","B64":{"HashSize":64},"Genus":"SHA3","Family":"SHA","Hash":"SHA3-384","HashSize":48}
{"Name":"SHA3-512","B64":{"HashSize":86},"Genus":"SHA3","Family":"SHA","Hash":"SHA3-512","HashSize":64}
{"Name":"SHAKE128","B64":{"HashSize":43},"Genus":"SHA3","Family":"SHA","Hash":"SHAKE128","HashSize":32}
{"Name":"SHAKE256","B64":{"HashSize":86},"Genus":"SHA3","Family":"SHA","Hash":"SHAKE256","HashSize":64}
`
};

let t_Canon = {
	"name": "Canon",
	"func": test_Canon,
	"golden": '{"Action":{"POST":"cyphr.me/api/v1/image"},"Hello World":"!","Image":"6gt3OmYBEDHODQ9SUc8q2momInw6GR9GT_AVN2DTZ5U","hello":"world!"}'
};
let t_CanonRepeat = {
	"name": "Canon Repeat Fields",
	"func": test_Canon_repeat,
	"golden": '{"a":"a","b":"b","c":"c"}'
};
let t_Sign = {
	"name": "Sign",
	"func": test_Sign,
	"golden": true,
};
let t_SignCoze = {
	"name": "SignCoze",
	"func": test_SignCoze,
	"golden": true,
};
let t_Valid = {
	"name": "Valid",
	"func": test_Valid,
	"golden": true,
};
let t_Revoke = {
	"name": "Revoke",
	"func": test_Revoke,
	"golden": true,
};
let t_CryptoKeySign = {
	"name": "CryptoKey",
	"func": test_CryptoKeySign,
	"golden": true
};
let t_Correct = {
	"name": "Correct",
	"func": test_CozeKeyCorrect,
	"golden": true
};
let t_CanonicalHash = {
	"name": "CanonicalHash",
	"func": test_CanonicalHashB64,
	"golden": true
};
let t_Thumbprint = {
	"name": "Thumbprint",
	"func": test_Thumbprint,
	"golden": true
};



////////////////////////////////////////////////////////////////////////////////
//////////////////////    Testing Variables    /////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

// x": "2nTOaFVm2QLxmUO_SjgyscVHBtvHEfo2rq65MvgNRjM"
// "y": "kaI6t_R2qva1zcb18cG2v149Beb2YmyUd4rAXTlm6OY"
let GoldenGoodCozeKey = {
	"alg": "ES256",
	"iat": 1623132000,
	"kid": "Zami's Majuscule Key.",
	"d": "bNstg4_H3m3SlROufwRSEgibLrBuRq9114OvdapcpVA",
	"tmb": "cLj8vsYtMBwYkzoFVZHBZo6SNL8wSdCIjCKAwXNuhOk",
	"x": "2nTOaFVm2QLxmUO_SjgyscVHBtvHEfo2rq65MvgNRjORojq39Haq9rXNxvXxwba_Xj0F5vZibJR3isBdOWbo5g"
}


let GoldenBadCozeKey = {
	"alg": "ES256",
	"iat": 1623132000,
	"kid": "Zami's Majuscule Key.",
	"d": "bNstg4_H3m3SlROufwRSEgibLrBuRq9114OvdapcpVE", // Ending A to E (one bit off) A-D are encoded as the same
	"tmb": "cLj8vsYtMBwYkzoFVZHBZo6SNL8wSdCIjCKAwXNuhOk",
	"x": "2nTOaFVm2QLxmUO_SjgyscVHBtvHEfo2rq65MvgNRjORojq39Haq9rXNxvXxwba_Xj0F5vZibJR3isBdOWbo5g"
}

let Algs = ["ES256", "ES384", "ES512"];

////////////////////
// Tests
////////////////////

// Tests "Alg.Param".
async function test_Param() {
	let algs = ["ES224", "ES256", "ES384", "ES512", "Ed25519", "Ed25519ph", "Ed448", "SHA-224", "SHA-256", "SHA-384", "SHA-512", "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512", "SHAKE128", "SHAKE256"];
	let results = "";
	for (let i = 0; i < algs.length; i++) {
		results += JSON.stringify(Coze.Params(algs[i])) + "\n";
	}
	return results;
};

// test_Canon tests CanonicalS(). Checks for UTF-8 order, removal of
// whitespace (outside of values), and has trailing commas.  
//
// Javascript JSON normalization: Escapes special characters, object keys that
// are not strings are converted to strings, and other normalizations that are
// outside the scope of these tests.
async function test_Canon() {
	// "Image" should go after "Hello".
	// "hello" should go after "Image".
	let object = {
		"Action": {
			"POST": "cyphr.me/api/v1/image"
		},
		"hello": "world!",
		"Image": "6gt3OmYBEDHODQ9SUc8q2momInw6GR9GT_AVN2DTZ5U",
		"Hello World": "!",
	};
	let canon = ["Action", "Hello World", "Image", "hello"];
	return Coze.CanonicalS(object, canon);
};


// Tests the behavior of calling Canon with duplicate fields, as well as with
// non-duplicate fields.
// TODO FIXME
async function test_Canon_repeat() {
	let object = {
		"c": "c",
		"b": "b",
		"b": "B",
		"a": "a",
		// Repeated fields
		"c": "c",
		"b": "b",
		// Not in Canon fields
		"A": "a",
	};

	let badCanon = ["a", "b", "c", "c", "b", "a"];
	let can;
	try {
		// Test for proper failure on Canonical with duplicate fields in Canon.
		can = await Coze.CanonicalS(object, badCanon);
	} catch (e) {
		if (e.message !== "Canonical: Canon cannot have duplicate fields.") {
			throw new Error(e);
		}
	}
	let goodCanon = ["a", "b", "c"];
	can = await Coze.CanonicalS(object, goodCanon);
	return can;
};

// test_CanonicalHash tests CanonicalHashB64, for all currently supported
// hashing algorithms.
async function test_CanonicalHashB64() {
	let canon = ["Action", "Image", "hello"];
	let algs = ["SHA-256", "SHA-384", "SHA-512"];

	let results = [];
	let golden = ["BmJKvEbaefBhlK6g3XcGNQlrkBySYEbHsgswdWKQlnY", "5CiH8RJmXFDFOBPsyPbeoD2NzFJiwqXlwJPJ-BEbpZ0X_TnHqvBXG7FOkNyeDNxf", "BJ_rBAFi5WAxVMpqPhrpTgvCC6XkTwfrdSitYHGSUkiP-MHznu21LEjjJLlBNu1PpSNvUYH2TIMDCx4CCBPf7g"];

	for (let alg of algs) {
		let object = {
			"alg": alg,
			"hello": "world!",
			"Image": "6gt3OmYBEDHODQ9SUc8q2momInw6GR9GT_AVN2DTZ5U",
		};
		results.push(await Coze.CanonicalHash64(object, alg, canon));
	}
	for (let gold in golden) {
		if (golden[gold] != results[gold]) {
			return false;
		}
	}
	return true;
};


// test_Sign
// Tests each support alg.
// 1.) Coze.NewCozeKey
// 2.) Coze.Sign
// 3.) Coze.Verify
async function test_Sign() {
	for (const alg of Algs) {
		let cozeKey = await Coze.NewCozeKey(alg);
		let pay = `{"msg":"Test Message"}`;
		let sig = await Coze.Sign(pay, cozeKey);

		if ((await Coze.Verify(pay, cozeKey, sig)) !== true) {
			console.error("Failed on alg: " + alg)
			return false
		}
	}
	return true;
};

// test_SignCoze
// Tests each support alg.  
// 1.) Coze.NewCozeKey
// 2.) Coze.SignCoze
// 3.) Coze.VerifyCoze
async function test_SignCoze() {
	for (const alg of Algs) {
		let cozeKey = await Coze.NewCozeKey(alg);
		let coze = await Coze.SignCoze({
				"pay": {
					"msg": "Test Message",
					"iat": 3,
				}
			},
			cozeKey
		);
		if (true !== await Coze.VerifyCoze(coze, cozeKey)) {
			return false
		}
	}
	return true;
};

// test_Thumbprint tests generating a thumbprint for a known `tmb`.
async function test_Thumbprint() {
	let t = await Coze.Thumbprint(GoldenGoodCozeKey);
	if (t !== GoldenGoodCozeKey.tmb) {
		console.error("Thumbprint does not match: Calculated: " + t);
		return false;
	}
	return true;
}

// Tests Tests "Coze.Thumbprint" and "Coze.Valid"
async function test_Valid() {
	if (!await Coze.Valid(GoldenGoodCozeKey)) {
		return false;
	}
	if (await Coze.Valid(GoldenBadCozeKey)) {
		return false;
	}
	return true;
};


// test_Revoke test will test signing a message with a Coze Key, and validating
// the coze that is generated.
async function test_Revoke() {
	let coze = await Coze.Revoke(GoldenGoodCozeKey, "Test revoke.");
	if (!(await Coze.VerifyCoze(coze, GoldenGoodCozeKey)) || !Coze.IsRevoked(GoldenGoodCozeKey)) {
		return false;
	}
	return true;
}

// test_CozeKeyCorrect will test correctness for various keys with different
// algorithms when calling Correct().
async function test_CozeKeyCorrect() {
	// Bad Key results vary from GO, as we have slightly weaker logic in Correct,
	// since we do not have the API capabilities for recalculating `x`, and can
	// not perform as many checks that require x to be present, as GO.
	let goldenMap = [
		[false, true, true, false, true, true], // Bad Key (second result is false in GO)
		[true, true, true, true, true, true], // Good key
		[true, true, true, true, true, true], // ES256
		[true, true, true, true, true, true], // ES384
		[true, true, true, true, true, true], // ES512
	];
	let keys = [GoldenBadCozeKey, GoldenGoodCozeKey];
	for (let alg of Algs) {
		keys.push(await Coze.NewCozeKey(alg));
	}

	// On failure, correct is throwing errors, so instead of having to wrap each
	// call to Correct in a try, we can use this wrapper function.
	let isCorrect = async (k) => {
		try {
			if (await Coze.Correct(k)) {
				return true;
			}
			return false;
		} catch (error) {
			// console.error(error);
			return false;
		}
	};

	for (let key in keys) {
		// Make a copy
		let k = {
			...keys[key]
		};
		var results = [];

		// Key with with [alg,d,tmb,x]
		results.push(await isCorrect(k));

		// A key with [alg,tmb,d]
		k.x = null;
		results.push(await isCorrect(k));

		// Key with [alg,d].
		k.tmb = null;
		results.push(await isCorrect(k));

		// A key with [alg,x,d].
		k.x = keys[key].x;
		results.push(await isCorrect(k));

		// A key with [alg,x,tmb]
		k.d = null;
		k.tmb = keys[key].tmb;
		results.push(await isCorrect(k));

		// Key with [alg,tmb]
		k.x = null;
		results.push(await isCorrect(k));

		if (results.length !== 6) {
			return false;
		}

		let golden = goldenMap[parseInt(key)];
		for (let v in golden) {
			if (results[v] !== golden[v]) {
				console.error("Unexpected results: ", k, "Expected: ", golden, "Received: ", results);
				return false;
			}
		}
	}

	return true;
}


/////////////////////////////////////
// CryptoKey Tests
/////////////////////////////////////

// test_CryptoKeySign() {
// Tests
// 1.) New Coze Key
// 2.) Coze Key to Cryptokey.
// 3.) CryptoKey.SignString
// 4.) CryptoKey.FromCozeKey 
// 5.) CryptoKey.VerifyMsgHexSig
async function test_CryptoKeySign() {
	let msg = "Test Message";
	let abMsg = await Coze.SToArrayBuffer(msg);

	for (const alg of Algs) {
		let cozeKey = await Coze.NewCozeKey(alg);
		let cryptoKey = await Coze.CryptoKey.FromCozeKey(cozeKey);

		// Sign string
		let sig = await Coze.CryptoKey.SignString(cryptoKey, msg);
		let pcc = await Coze.CryptoKey.FromCozeKey(cozeKey, true);
		let result = await Coze.CryptoKey.VerifyMsg(pcc, msg, sig);
		if (result !== true) {
			return false
		}

		// Sign array buffer
		sig = await Coze.CryptoKey.SignBuffer(cryptoKey, abMsg);
		result = await Coze.CryptoKey.VerifyArrayBuffer(pcc, abMsg, sig);
		if (result !== true) {
			return false
		}
	}
	return true;
};

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
///////////////////////  Interface to browsertestjs package  ///////////////////
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////


/**
 * TestsToRun must be declared at the bottom of the file, as the variables
 * cannot be accessed before initialization.
 * 
 * @type {TestsToRun}
 **/
let TestsToRun = [
	t_Param,
	t_Canon,
	t_CanonRepeat,
	t_Sign,
	t_SignCoze,
	t_Valid,
	t_Revoke,
	t_CanonicalHash,
	t_Thumbprint,
	t_Correct,
	t_CryptoKeySign,
];


/** @type {TestGUIOptions} **/
let TestGUIOptions = {
	footer: `<div class="mt-4">
	<a href="/"><img src="coze_logo_zami_white_450x273.png" alt="Browser Test JS"></a>

	<p><a class="account_keys text-center" href="https://github.com/cyphrme/coze"> Coze Github</a></p>
	<p><a class="account_keys text-center" href="https://github.com/cyphrme/cozejs"> Coze js Github</a></p>
	<p><a href="https://cyphr.me/coze_verifier">Cyphr.me Coze Verifier</a></p>
	<div class="level-item has-text-centered text-muted footer_logo mt-5">

		<a href="https://cyphr.me">Sponsored by: <img src="cyphrme_long.png"></a>

		<p class="mt-3">Coze is released under The 3-Clause BSD License. <br>

"Cyphr.me" is a trademark of Cypherpunk, LLC. The Cyphr.me logo is all rights reserved Cypherpunk, LLC and may not be used without permission.
		</p>
</div>`,
	stylesheet: {
		href: "cyphrme_bootstrap.min.css"
	},
	main_image: "coze_logo_zami_white_450x273.png",
};

/** @type {TestBrowserJS} **/
let TestBrowserJS = {
	TestsToRun,
	TestGUIOptions
};