"use strict";

// Unit tests are ran using the `browsertestjs` directory/package.

import * as Coze from './coze_all.min.js';

export {
	// For `browsertestjs`
	TestBrowserJS,
};

/**
 * @typedef {import('./browsertestjs/test.js').Test}            Test
 * @typedef {import('./browsertestjs/test.js').Tests}           Tests
 * @typedef {import('./browsertestjs/test.js').TestsToRun}      TestsToRun
 * @typedef {import('./browsertestjs/test.js').TestGUIOptions}  TestGUIOptions
 * @typedef {import('./browsertestjs/test.js').TestBrowserJS}   TestBrowserJS
 */

/**@type {Test} */
let t_Verify = {
	"name": "VerifyCoze",
	"func": test_Verify,
	"golden": true,
};
let t_VerifyArray = {
	"name": "VerifyCozeArray",
	"func": test_VerifyArray,
	"golden": true
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
let t_CryptoKeySign = {
	"name": "CryptoKey",
	"func": test_CryptoKeySign,
	"golden": true
};
let t_Valid = {
	"name": "Valid",
	"func": test_Valid,
	"golden": true,
};
let t_Correct = {
	"name": "Correct",
	"func": test_CozeKeyCorrect,
	"golden": true
};
let t_Revoke = {
	"name": "Revoke",
	"func": test_Revoke,
	"golden": true,
};
let t_Thumbprint = {
	"name": "Thumbprint",
	"func": test_Thumbprint,
	"golden": true
};

let t_Param = {
	"name": "Param",
	"func": test_Param,
	"golden": `
{"Name":"ES224","Genus":"ECDSA","Family":"EC","Use":"sig","Hash":"SHA-224","HashSize":28,"HashSizeB64":38,"XSize":56,"XSizeB64":75,"DSize":28,"DSizeB64":38,"Curve":"P-224","SigSize":56,"SigSizeB64":75}
{"Name":"ES256","Genus":"ECDSA","Family":"EC","Use":"sig","Hash":"SHA-256","HashSize":32,"HashSizeB64":43,"XSize":64,"XSizeB64":86,"DSize":32,"DSizeB64":43,"Curve":"P-256","SigSize":64,"SigSizeB64":86}
{"Name":"ES384","Genus":"ECDSA","Family":"EC","Use":"sig","Hash":"SHA-384","HashSize":48,"HashSizeB64":64,"XSize":96,"XSizeB64":128,"DSize":48,"DSizeB64":64,"Curve":"P-384","SigSize":96,"SigSizeB64":128}
{"Name":"ES512","Genus":"ECDSA","Family":"EC","Use":"sig","Hash":"SHA-512","HashSize":64,"HashSizeB64":86,"XSize":132,"XSizeB64":176,"DSize":66,"DSizeB64":88,"Curve":"P-521","SigSize":132,"SigSizeB64":176}
{"Name":"Ed25519","Genus":"EdDSA","Family":"EC","Use":"sig","Hash":"SHA-512","HashSize":64,"HashSizeB64":86,"XSize":32,"XSizeB64":43,"DSize":32,"DSizeB64":43,"Curve":"Curve25519","SigSize":64,"SigSizeB64":86}
{"Name":"Ed25519ph","Genus":"EdDSA","Family":"EC","Use":"sig","Hash":"SHA-512","HashSize":64,"HashSizeB64":86,"XSize":32,"XSizeB64":43,"DSize":32,"DSizeB64":43,"Curve":"Curve25519","SigSize":64,"SigSizeB64":86}
{"Name":"Ed448","Genus":"EdDSA","Family":"EC","Use":"sig","Hash":"SHAKE256","HashSize":64,"HashSizeB64":86,"XSize":57,"XSizeB64":76,"DSize":57,"DSizeB64":76,"Curve":"Curve448","SigSize":114,"SigSizeB64":152}
{"Name":"SHA-224","Genus":"SHA2","Family":"SHA","Use":"hsh","Hash":"SHA-224","HashSize":28,"HashSizeB64":38}
{"Name":"SHA-256","Genus":"SHA2","Family":"SHA","Use":"hsh","Hash":"SHA-256","HashSize":32,"HashSizeB64":43}
{"Name":"SHA-384","Genus":"SHA2","Family":"SHA","Use":"hsh","Hash":"SHA-384","HashSize":48,"HashSizeB64":64}
{"Name":"SHA-512","Genus":"SHA2","Family":"SHA","Use":"hsh","Hash":"SHA-512","HashSize":64,"HashSizeB64":86}
{"Name":"SHA3-224","Genus":"SHA3","Family":"SHA","Use":"hsh","Hash":"SHA3-224","HashSize":28,"HashSizeB64":38}
{"Name":"SHA3-256","Genus":"SHA3","Family":"SHA","Use":"hsh","Hash":"SHA3-256","HashSize":32,"HashSizeB64":43}
{"Name":"SHA3-384","Genus":"SHA3","Family":"SHA","Use":"hsh","Hash":"SHA3-384","HashSize":48,"HashSizeB64":64}
{"Name":"SHA3-512","Genus":"SHA3","Family":"SHA","Use":"hsh","Hash":"SHA3-512","HashSize":64,"HashSizeB64":86}
{"Name":"SHAKE128","Genus":"SHA3","Family":"SHA","Use":"hsh","Hash":"SHAKE128","HashSize":32,"HashSizeB64":43}
{"Name":"SHAKE256","Genus":"SHA3","Family":"SHA","Use":"hsh","Hash":"SHAKE256","HashSize":64,"HashSizeB64":86}
`
};
let t_CanonicalHash = {
	"name": "CanonicalHash",
	"func": test_CanonicalHashB64,
	"golden": true
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
let t_Duplicate = {
	"name": "Duplicate",
	"func": test_Duplicate,
	"golden": true
};
let t_LowS = {
	"name": "LowS",
	"func": test_LowS,
	"golden": true
};
let t_B64Canonical = {
	"name": "t_B64Canonical",
	"func": test_B64Canonical,
	"golden": true
}

////////////////////////////////////////////////////////////////////////////////
//////////////////////    Testing Variables    /////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

// x": "2nTOaFVm2QLxmUO_SjgyscVHBtvHEfo2rq65MvgNRjM"
// "y": "kaI6t_R2qva1zcb18cG2v149Beb2YmyUd4rAXTlm6OY"
let GoldenCozeKey = {
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

let GoldenCoze = {
	"pay": {
		"msg": "Coze Rocks",
		"alg": "ES256",
		"iat": 1623132000,
		"tmb": "cLj8vsYtMBwYkzoFVZHBZo6SNL8wSdCIjCKAwXNuhOk",
		"typ": "cyphr.me/msg"
	},
	"sig": "Jl8Kt4nznAf0LGgO5yn_9HkGdY3ulvjg-NyRGzlmJzhncbTkFFn9jrwIwGoRAQYhjc88wmwFNH5u_rO56USo_w"
}

let GoldenCozeBad = {
	"pay": {
		"msg": "Coze Rocks",
		"alg": "ES256",
		"iat": 1623132000,
		"tmb": "cLj8vsYtMBwYkzoFVZHBZo6SNL8wSdCIjCKAwXNuhOk",
		"typ": "cyphr.me/msg"
	},
	"sig": "Jl8Kt4nznAf0LGgO5yn_9HkGdY3ulvjg-NyRGzlmJzhncbTkFFn9jrwIwGoRAQYhjc88wmwFNH5u_rO56USo_g"// bad signature, last byte is off by one bit.  
}

let Algs = ["ES256", "ES384", "ES512"];

////////////////////
// Tests
////////////////////

async function test_Verify() {
	let v = await Coze.VerifyCoze(GoldenCoze, GoldenCozeKey)
	console.log(v)
	if (v !== true) {
		return false
	}
	v = await Coze.VerifyCoze(GoldenCozeBad, GoldenCozeKey)
	if (v !== false) {
		return false
	}

	return true
}

// Tests VerifyCozeArray().
async function test_VerifyArray() {
	let cozeKey = await Coze.NewKey(Coze.Algs.ES256);
	let cozies = [await Coze.SignCoze({
				"pay": {
					"msg": "First",
					"iat": 1,
				}
			},
			cozeKey
		),
		await Coze.SignCoze({
				"pay": {
					"msg": "Second",
					"iat": 2,
				}
			},
			cozeKey
		),
		await Coze.SignCoze({
				"pay": {
					"msg": "Third",
					"iat": 3,
				}
			},
			cozeKey
		),
	];
	let v = await Coze.VerifyCozeArray(cozies, cozeKey);
	if (v.FailedCount !== 0 || v.FailedCozies.length > 0 || !v.VerifiedAll || v.VerifiedCount !== 3) {
		return false;
	}
	return true;
}


// test_Sign
// Tests each support alg.
// 1.) Coze.NewKey
// 2.) Coze.Sign
// 3.) Coze.Verify
async function test_Sign() {
	for (const alg of Algs) {
		let cozeKey = await Coze.NewKey(alg);
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
// 1.) Coze.NewKey
// 2.) Coze.SignCoze
// 3.) Coze.VerifyCoze
async function test_SignCoze() {
	for (const alg of Algs) {
		let cozeKey = await Coze.NewKey(alg);
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
	let t = await Coze.Thumbprint(GoldenCozeKey);
	if (t !== GoldenCozeKey.tmb) {
		console.error("Thumbprint does not match: Calculated: " + t);
		return false;
	}
	return true;
}


// Tests "Alg.Param".
async function test_Param() {
	let algs = ["ES224", "ES256", "ES384", "ES512", "Ed25519", "Ed25519ph", "Ed448", "SHA-224", "SHA-256", "SHA-384", "SHA-512", "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512", "SHAKE128", "SHAKE256"];
	let results = "";
	for (let alg of algs) {
		results += JSON.stringify(Coze.Params(alg)) + "\n";
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

	try {
		// Test for proper failure on Canonical with duplicate fields in Canon.
		let badCanon = ["a", "b", "c", "c", "b", "a"];
		await Coze.CanonicalS(object, badCanon);
	} catch (e) {
		if (e.message !== "Canonical: Canon cannot have duplicate fields.") {
			throw new Error(e);
		}
	}
	let goodCanon = ["a", "b", "c"];
	return await Coze.CanonicalS(object, goodCanon);
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


// test_Duplicate tests duplicate object names in `coze` and `pay`.
async function test_Duplicate() {
	// In ES5, should fail since it's in strict mode.  In ES6, it seems to be
	// last-value-wins.
	// https://github.com/json5/json5-spec/issues/38#issuecomment-1224158640
	// https://262.ecma-international.org/5.1/#sec-C
	// > It is a SyntaxError if strict mode code contains an ObjectLiteral with more
	// > than one definition of any data property (11.1.5).
	//
	// Solution via minification:
	// https://www.anycodings.com/1questions/3635977/js-check-json-for-duplicate-keys-prior-to-loading

	// Prints if in strict mode.  
	var mode = (eval("var __temp = null"), (typeof __temp === "undefined")) ? "strict" : "non-strict";
	if (mode !== "strict") {
		return false;
	};

	let tc = {
		"bob": "bob",
		"bob": "bob2"
	};
	if (JSON.stringify(tc) !== `{"bob":"bob2"}`) {
		return false;
	}

	// JSON parsing uses last-value-wins.  Will not fail. 
	tc = JSON.parse(`{"bob":"bob","bob":"bob2"}`);
	if (JSON.stringify(tc) !== `{"bob":"bob2"}`) {
		return false;
	}

	return true;
}


// Tests Tests "Coze.Thumbprint" and "Coze.Valid"
async function test_Valid() {
	if (!await Coze.Valid(GoldenCozeKey)) {
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
	let coze = await Coze.Revoke(GoldenCozeKey, "Test revoke.");
	if (!(await Coze.VerifyCoze(coze, GoldenCozeKey)) || !Coze.IsRevoked(GoldenCozeKey)) {
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
	let keys = [GoldenBadCozeKey, GoldenCozeKey];
	for (let alg of Algs) {
		keys.push(await Coze.NewKey(alg));
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

// test_CryptoKeySign contains tests for `cryptokey.js`.
// Tests
// 1.) Coze.NewKey
// 2.) CryptoKey.New (called from new coze key)
// 3.) CryptoKey.FromCozeKey
// 4.) CryptoKey.SignString
// 5.) CryptoKey.VerifyMsg
// 6.) CryptoKey.SignBuffer
// 7.) CryptoKey.VerifyArrayBuffer
// 8.) CryptoKey.GetSignHashAlgoFromCryptoKey (calls `algFromCrv`)
//
// `SignBuffer` cannot be tested for throwing an error, since we cannot
// create an invalid cryptokey. The test will fail at `FromCozeKey`.
async function test_CryptoKeySign() {
	let msg = "Test Message";
	let abMsg = await Coze.SToArrayBuffer(msg);
	let results = [];

	for (const alg of Algs) {
		let cozeKey = await Coze.NewKey(alg);
		let cryptoKey = await Coze.CryptoKey.FromCozeKey(cozeKey);

		// Sign string
		let sig = await Coze.CryptoKey.SignString(cryptoKey, msg);
		let pcc = await Coze.CryptoKey.FromCozeKey(cozeKey, true);
		let result = await Coze.CryptoKey.VerifyMsg(alg, pcc, msg, sig);
		if (result !== true) {
			return false
		}

		// Sign array buffer
		sig = await Coze.CryptoKey.SignBuffer(cryptoKey, abMsg);
		result = await Coze.CryptoKey.VerifyArrayBuffer(alg, pcc, abMsg, sig);
		if (result !== true) {
			return false
		}
		results.push(await Coze.CryptoKey.GetSignHashAlgoFromCryptoKey(cryptoKey));
	}
	if (JSON.stringify(results) !== JSON.stringify([Coze.Algs.SHA256, Coze.Algs.SHA384, Coze.Algs.SHA512])) {
		return false;
	}

	// Importing an invalid key from `subtle` will throw a DOMException error:
	// `DOMException: The imported EC key is invalid`
	let e = null;
	try {
		await Coze.CryptoKey.FromCozeKey(GoldenBadCozeKey);
	} catch (error) {
		e = error;
	}
	if (e === null) {
		return false;
	}

	return true;
};



async function test_LowS() {
	// All cozies should be low-S
	for (const alg of Algs) {
		let cozeKey = await Coze.NewKey(alg);
		let pay = `{"msg":"Test Message"}`;
		let sig = await Coze.Sign(pay, cozeKey);

		if ((await Coze.Verify(pay, cozeKey, sig)) !== true) {
			console.error("Failed on alg: " + alg)
			return false
		}
	}

	// Make sure high-S cozies will not verify.  
	let highSCozies = [
		'{"pay":{},"sig":"9iesKUSV7L1-xz5yd3A94vCkKLmdOAnrcPXTU3_qeKSuk4RMG7Qz0KyubpATy0XA_fXrcdaxJTvXg6saaQQcVQ"}',
		'{"pay":{"msg":"Coze Rocks","alg":"ES256","iat":1623132000,"tmb":"cLj8vsYtMBwYkzoFVZHBZo6SNL8wSdCIjCKAwXNuhOk","typ":"cyphr.me/msg"},"sig":"mVw8N6ZncWcObVGvnwUMRIC6m2fbX3Sr1LlHMbj_tZ3ji1rNL-00pVaB12_fmlK3d_BVDipNQUsaRyIlGJudtg"}',
		'{"pay":{"msg":"Coze Rocks","alg":"ES256","iat":1623132000,"tmb":"cLj8vsYtMBwYkzoFVZHBZo6SNL8wSdCIjCKAwXNuhOk","typ":"cyphr.me/msg"},"sig":"cn6KNl4VQlk5MzmhYFVyyJoTOU57O5Bq-8r-yXXR6Ojfs0-6LFGd8j1Y6wiJAQrGpWj_RptsiEg49v95FsVWMQ"}',
		'{"pay":{"msg":"Coze Rocks","alg":"ES256","iat":1623132000,"tmb":"cLj8vsYtMBwYkzoFVZHBZo6SNL8wSdCIjCKAwXNuhOk","typ":"cyphr.me/msg"},"sig":"9KvWfOSIZUjW8Ie0jbdVdu9UlIP4TT4MXz3YyNW3fCTWXHnO1MPROwcXvfNZN_icOvMAK3vfsr2w-CeBozS81w"}',
	]

	for (let c of highSCozies) {
		let coze = JSON.parse(c);

		let v = await Coze.VerifyCoze(coze, GoldenCozeKey);
		if (v) {
			return ("High-S Should not be valid. ");
		}

		coze.sig = await Coze.SigToLowS("ES256", coze.sig);
		v = await Coze.VerifyCoze(coze, GoldenCozeKey);
		if (!v) {
			return ("High-S to low-S should be valid. ");
		}

	}

	return true;
}

// Demonstrates Javascript's behavior for non-canonical base 64 encoding.
// Enforcing canonical only stop malleability.  See
// https://github.com/Cyphrme/Coze/issues/18. The last three characters of
// example `tmb` is `hOk`, but `hOl` also decodes to the same byte value (in
// Hex, `84E9`) even though they are different UTF-8 values. Tool for decoding
// [hOk](https://convert.zamicol.com/#?inAlph=base64&in=hOk&outAlph=Hex) and
// [hOl](https://convert.zamicol.com/#?inAlph=base64&in=hOl&outAlph=Hex).
//
// As an added concern, Go's base64 ignores new line and carriage return.
// Thankfully, JSON unmarshal does not, making Coze's interpretation of base 64
// non-malleable since Coze is JSON.
async function test_B64Canonical() {
	let ab1 = Coze.B64uToArrayBuffer("hOk") // correct

	let failed = false
	try {
		let ab2 = Coze.B64uToArrayBuffer("hOl") // non-canonical
	} catch (e) {
		failed = true;
	}
	if (failed != true) {
		return false
	}

	let nonCanonicalCozeSig = {
		"pay": {
			"msg": "Coze Rocks",
			"alg": "ES256",
			"iat": 1623132000,
			"tmb": "cLj8vsYtMBwYkzoFVZHBZo6SNL8wSdCIjCKAwXNuhOk",
			"typ": "cyphr.me/msg"
		},
		"sig": "Jl8Kt4nznAf0LGgO5yn_9HkGdY3ulvjg-NyRGzlmJzhncbTkFFn9jrwIwGoRAQYhjc88wmwFNH5u_rO56USo_x" // Non canonical sig (last "x" should be a "w")
	}
	failed = false
	try {
		failed = await Coze.VerifyCoze(nonCanonicalCozeSig, GoldenCozeKey)
	} catch (e) {
		failed = true
	}
	if (failed != true) {
		return false
	}

	let nonCanonicalCozeTmb = {
		"pay": {
			"msg": "Coze Rocks",
			"alg": "ES256",
			"iat": 1623132000,
			"tmb": "cLj8vsYtMBwYkzoFVZHBZo6SNL8wSdCIjCKAwXNuhOl", // Non canonical tmb (last "l" should be a "k")
			"typ": "cyphr.me/msg"
		},
		"sig": "Jl8Kt4nznAf0LGgO5yn_9HkGdY3ulvjg-NyRGzlmJzhncbTkFFn9jrwIwGoRAQYhjc88wmwFNH5u_rO56USo_w"
	}
	failed = false
	try {
		failed = await Coze.VerifyCoze(nonCanonicalCozeTmb, GoldenCozeKey)
	} catch (e) {
		failed = true
	}
	if (failed != true) {
		return false
	}
	return true;

}

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
	t_Verify,
	t_VerifyArray,
	t_Sign,
	t_SignCoze,
	t_CryptoKeySign,
	t_Valid,
	t_Correct,
	t_Revoke,
	t_Thumbprint,
	t_Param,
	t_Canon,
	t_CanonRepeat,
	t_CanonicalHash,
	t_Duplicate,
	t_LowS,
	t_B64Canonical,
];


/** @type {TestGUIOptions} **/
let TestGUIOptions = {
	footer: `<div class="mt-4">
	<a href="/"><img src="../coze_logo_zami_white_450x273.png" alt="Browser Test JS"></a>

	<p><a class="account_keys text-center" href="https://github.com/cyphrme/coze"> Coze Github</a></p>
	<p><a class="account_keys text-center" href="https://github.com/cyphrme/cozejs"> Coze js Github</a></p>
	<p><a href="https://cyphr.me/coze">Cyphr.me Coze Verifier</a></p>
	<div class="level-item has-text-centered text-muted footer_logo mt-5">

		<a href="https://cyphr.me">Sponsored by: <img src="../cyphrme_long_500x135.png"></a>

		<p class="mt-3">Coze is released under The 3-Clause BSD License. <br>

"Cyphr.me" is a trademark of Cypherpunk, LLC. The Cyphr.me logo is all rights reserved Cypherpunk, LLC and may not be used without permission.
		</p>
</div>`,
	stylesheet: {
		href: "../cyphrme_bootstrap.min.css"
	},
	main_image: "../coze_logo_zami_white_450x273.png",
};

/** @type {TestBrowserJS} **/
let TestBrowserJS = {
	TestsToRun,
	TestGUIOptions
};