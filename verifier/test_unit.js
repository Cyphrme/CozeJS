"use strict";

// Unit tests are ran using the `browsertestjs` directory/package.

import * as Coze from './coze_all.min.js';

export {
	TestBrowserJS, // Export "TestBrowserJS" is expected by `browsertestjs`
};

/**
@typedef {import('./browsertestjs/test.js').Test}            Test
@typedef {import('./browsertestjs/test.js').Tests}           Tests
@typedef {import('./browsertestjs/test.js').TestsToRun}      TestsToRun
@typedef {import('./browsertestjs/test.js').TestGUIOptions}  TestGUIOptions
@typedef {import('./browsertestjs/test.js').TestBrowserJS}   TestBrowserJS
*/

/**@type {Test} */
let t_Sign = {
	"name": "Sign",
	"func": test_Sign,
	"golden": true,
};
let t_SignPay = {
	"name": "Sign Pay",
	"func": test_SignPay,
	"golden": true,
};
let t_SignPayRaw = {
	"name": "Sign Pay Raw",
	"func": test_SignPayRaw,
	"golden": true,
};
let t_ValidateTimestamp = {
	"name": "Validate Timestamp",
	"func": test_ValidateTimestamp,
	"golden": true,
};
let t_RVKMaxSize = {
	"name": "RVK Max Size",
	"func": test_RVKMaxSize,
	"golden": true,
};
let t_Verify = {
	"name": "Verify",
	"func": test_Verify,
	"golden": true,
};
let t_VerifyArray = {
	"name": "VerifyArray",
	"func": test_VerifyArray,
	"golden": true
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
	"func": test_CozKeyCorrect,
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
{"Name":"ES224","Genus":"ECDSA","Family":"EC","Use":"sig","Hash":"SHA-224","HashSize":28,"HashSizeB64":38,"PubSize":56,"PubSizeB64":75,"PrvSize":28,"PrvSizeB64":38,"Curve":"P-224","SigSize":56,"SigSizeB64":75}
{"Name":"ES256","Genus":"ECDSA","Family":"EC","Use":"sig","Hash":"SHA-256","HashSize":32,"HashSizeB64":43,"PubSize":64,"PubSizeB64":86,"PrvSize":32,"PrvSizeB64":43,"Curve":"P-256","SigSize":64,"SigSizeB64":86}
{"Name":"ES384","Genus":"ECDSA","Family":"EC","Use":"sig","Hash":"SHA-384","HashSize":48,"HashSizeB64":64,"PubSize":96,"PubSizeB64":128,"PrvSize":48,"PrvSizeB64":64,"Curve":"P-384","SigSize":96,"SigSizeB64":128}
{"Name":"ES512","Genus":"ECDSA","Family":"EC","Use":"sig","Hash":"SHA-512","HashSize":64,"HashSizeB64":86,"PubSize":132,"PubSizeB64":176,"PrvSize":66,"PrvSizeB64":88,"Curve":"P-521","SigSize":132,"SigSizeB64":176}
{"Name":"Ed25519","Genus":"EdDSA","Family":"EC","Use":"sig","Hash":"SHA-512","HashSize":64,"HashSizeB64":86,"PubSize":32,"PubSizeB64":43,"PrvSize":32,"PrvSizeB64":43,"Curve":"Curve25519","SigSize":64,"SigSizeB64":86}
{"Name":"Ed25519ph","Genus":"EdDSA","Family":"EC","Use":"sig","Hash":"SHA-512","HashSize":64,"HashSizeB64":86,"PubSize":32,"PubSizeB64":43,"PrvSize":32,"PrvSizeB64":43,"Curve":"Curve25519","SigSize":64,"SigSizeB64":86}
{"Name":"Ed448","Genus":"EdDSA","Family":"EC","Use":"sig","Hash":"SHAKE256","HashSize":64,"HashSizeB64":86,"PubSize":57,"PubSizeB64":76,"PrvSize":57,"PrvSizeB64":76,"Curve":"Curve448","SigSize":114,"SigSizeB64":152}
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
let t_Meta = {
	"name": "Meta",
	"func": test_Meta,
	"golden": true
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
	"name": "B64 Canonical",
	"func": test_B64Canonical,
	"golden": true
}

////////////////////
// Testing Variables
////////////////////

// Golden Coz Key — matches Go reference (Cyphrme/Coz key_test.go GoldenKey).
// pub is the concatenation of JWK x||y:
// "x": "2nTOaFVm2QLxmUO_SjgyscVHBtvHEfo2rq65MvgNRjM"
// "y": "kaI6t_R2qva1zcb18cG2v149Beb2YmyUd4rAXTlm6OY"
let GoldenCozKey = {
	"alg": "ES256",
	"now": 1623132000,
	"tag": "Zami's Majuscule Key.",
	"prv": "bNstg4_H3m3SlROufwRSEgibLrBuRq9114OvdapcpVA",
	"tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
	"pub": "2nTOaFVm2QLxmUO_SjgyscVHBtvHEfo2rq65MvgNRjORojq39Haq9rXNxvXxwba_Xj0F5vZibJR3isBdOWbo5g"
}


let GoldenBadCozKey = {
	"alg": "ES256",
	"now": 1623132000,
	"tag": "Zami's Majuscule Key.",
	"prv": "bNstg4_H3m3SlROufwRSEgibLrBuRq9114OvdapcpVE", // Ending A to E (one bit off) A-D are encoded as the same
	"tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
	"pub": "2nTOaFVm2QLxmUO_SjgyscVHBtvHEfo2rq65MvgNRjORojq39Haq9rXNxvXxwba_Xj0F5vZibJR3isBdOWbo5g"
}

// Golden Coz — matches Go reference (Cyphrme/Coz key_test.go GoldenCoz).
let GoldenCoz = {
	"pay": {
		"msg": "Coz is a cryptographic JSON messaging specification.",
		"alg": "ES256",
		"now": 1623132000,
		"tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
		"typ": "cyphr.me/msg/create"
	},
	"sig": "OJ4_timgp-wxpLF3hllrbe55wdjhzGOLgRYsGO1BmIMYbo4VKAdgZHnYyIU907ZTJkVr8B81A2K8U4nQA6ONEg"
}

let GoldenCozBad = {
	"pay": {
		"msg": "Coz is a cryptographic JSON messaging specification.",
		"alg": "ES256",
		"now": 1623132000,
		"tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
		"typ": "cyphr.me/msg/create"
	},
	"sig": "OJ4_timgp-wxpLF3hllrbe55wdjhzGOLgRYsGO1BmIMYbo4VKAdgZHnYyIU907ZTJkVr8B81A2K8U4nQA6ONEw" // bad signature, last byte is off by one bit.
}

let Algs = ["ES256", "ES384", "ES512"];

////////////////////
// Tests
////////////////////

// test_Sign
// Tests each supported alg.
// 1.) Coze.NewKey
// 2.) Coze.Sign
// 3.) Coze.Verify
async function test_Sign() {
	for (const alg of Algs) {
		let cozKey = await Coze.NewKey(alg);
		let coz = await Coze.Sign({
			"pay": {
				"msg": "Test Message",
				"now": 3,
			}
		},
			cozKey
		);
		if (true !== await Coze.Verify(coz, cozKey)) {
			return false
		}
	}
	return true;
};


// test_SignPay
// Tests each supported alg.
// 1.) Coze.NewKey
// 2.) Coze.SignPay
// 3.) Coze.VerifyPay
async function test_SignPay() {
	for (const alg of Algs) {
		let cozKey = await Coze.NewKey(alg);
		let pay = `{"msg":"Test Message"}`;
		let sig = await Coze.SignPay(pay, cozKey);

		if ((await Coze.VerifyPay(pay, cozKey, sig)) !== true) {
			console.error("Failed on alg: " + alg)
			return false
		}
	}
	return true;
};


// test_SignPayRaw
// Signs with SignPayRaw (no field modification) and verifies the result.
async function test_SignPayRaw() {
	for (const alg of Algs) {
		let cozKey = await Coze.NewKey(alg);
		let coz = {
			"pay": {
				"msg": "Test Message",
				"alg": cozKey.alg,
				"tmb": cozKey.tmb,
			}
		};
		let signed = await Coze.SignPayRaw(coz, cozKey);
		if (true !== await Coze.Verify(signed, cozKey)) {
			console.error("SignPayRaw: Failed verification on alg: " + alg);
			return false;
		}
		// Verify that now was NOT set (SignPayRaw must not touch fields).
		if (signed.pay.now !== undefined) {
			console.error("SignPayRaw: now was set but should not have been. alg: " + alg);
			return false;
		}
	}
	return true;
};


// test_ValidateTimestamp
// Tests that validateTimestamp accepts valid values and rejects invalid ones.
async function test_ValidateTimestamp() {
	// Valid values — should not throw.
	let validValues = [0, 1, 1623132000, 9007199254740991];
	for (let v of validValues) {
		try {
			Coze.validateTimestamp(v);
		} catch (e) {
			console.error("validateTimestamp: Rejected valid value: " + v);
			return false;
		}
	}

	// Invalid values — should throw.
	let invalidValues = [-1, -100, 9007199254740992, Number.MAX_SAFE_INTEGER + 2];
	for (let v of invalidValues) {
		try {
			Coze.validateTimestamp(v);
			console.error("validateTimestamp: Accepted invalid value: " + v);
			return false;
		} catch (e) {
			// Expected.
		}
	}

	// Verify MaxSafeTimestamp is exported and correct.
	if (Coze.MaxSafeTimestamp !== 9007199254740991) {
		console.error("MaxSafeTimestamp: Incorrect value: " + Coze.MaxSafeTimestamp);
		return false;
	}

	return true;
};

async function test_Verify() {
	let v = await Coze.Verify(GoldenCoz, GoldenCozKey)
	if (v !== true) {
		console.error(`Coz test: Failed on Verify: Coz: ${GoldenCoz}, Key: ${GoldenCozKey}`)
		return false
	}
	v = await Coze.Verify(GoldenCozBad, GoldenCozKey)
	if (v !== false) {
		return false
	}

	return true
}

// Tests VerifyCozArray().
async function test_VerifyArray() {
	let cozKey = await Coze.NewKey(Coze.Algs.ES256);
	let cozies = [await Coze.Sign({
		"pay": {
			"msg": "First",
			"now": 1,
		}
	},
		cozKey
	),
	await Coze.Sign({
		"pay": {
			"msg": "Second",
			"now": 2,
		}
	},
		cozKey
	),
	await Coze.Sign({
		"pay": {
			"msg": "Third",
			"now": 3,
		}
	},
		cozKey
	),
	];
	let v = await Coze.VerifyCozArray(cozies, cozKey);
	if (v.FailedCount !== 0 || v.FailedCozies.length > 0 || !v.VerifiedAll || v.VerifiedCount !== 3) {
		return false;
	}
	return true;
}




// test_Thumbprint tests generating a thumbprint for a known `tmb`.
async function test_Thumbprint() {
	let t = await Coze.Thumbprint(GoldenCozKey);
	if (t !== GoldenCozKey.tmb) {
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


// This test should closely resemble the Go implementation test
// `ExampleCoz_MetaWithAlg`
async function test_Meta() {
	let meta = JSON.stringify(await Coze.Meta(GoldenCoz))
	let goldenMeta = `{"alg":"ES256","now":1623132000,"tmb":"U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg","typ":"cyphr.me/msg/create","can":["msg","alg","now","tmb","typ"],"cad":"XzrXMGnY0QFwAKkr43Hh-Ku3yUS8NVE0BdzSlMLSuTU","sig":"OJ4_timgp-wxpLF3hllrbe55wdjhzGOLgRYsGO1BmIMYbo4VKAdgZHnYyIU907ZTJkVr8B81A2K8U4nQA6ONEg","czd":"xrYMu87EXes58PnEACcDW1t0jF2ez4FCN-njTF0MHNo"}`
	if (meta != goldenMeta) {
		throw new Error("meta and goldenMeta not equal")
	}

	// No coz.pay.alg but parameter alg given.
	meta = JSON.stringify(await Coze.Meta(JSON.parse(`{
    "pay": {
        "msg": "Coz is a cryptographic JSON messaging specification.",
        "now": 1623132000,
        "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
        "typ": "cyphr.me/msg/create"
    },
    "sig": "37R-VP0BaR31_vjtOgdZP7lpanTMdQy07xz83o_I7mFMMt2BdoZwdXOAn0dxtKpPrhPPNxBTe-O12ifeiCnONQ"
}`), "ES256"))
	goldenMeta = `{"alg":"ES256","now":1623132000,"tmb":"U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg","typ":"cyphr.me/msg/create","can":["msg","now","tmb","typ"],"cad":"BZxsmjnmvPrvEQHZ6Ux0IR1QPFRhpjSmkpAjKvUMtfc","sig":"37R-VP0BaR31_vjtOgdZP7lpanTMdQy07xz83o_I7mFMMt2BdoZwdXOAn0dxtKpPrhPPNxBTe-O12ifeiCnONQ","czd":"NShGQ0KdJ4Bnx6TlXyKCaYG-4Q_Pxf3IK61_lLG0VxE"}`
	if (meta != goldenMeta) {
		throw new Error("meta and goldenMeta not equal")
	}

	// No coz.pay.alg but parameter alg given. No coz.sig so coz.sig must not be
	// populated and coz.czd not calculated. 
	meta = JSON.stringify(await Coze.Meta(JSON.parse(`{
    "pay": {
        "msg": "Coz is a cryptographic JSON messaging specification.",
        "now": 1623132000,
        "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
        "typ": "cyphr.me/msg/create"
    }
}`), "ES256"))
	goldenMeta = `{"alg":"ES256","now":1623132000,"tmb":"U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg","typ":"cyphr.me/msg/create","can":["msg","now","tmb","typ"],"cad":"BZxsmjnmvPrvEQHZ6Ux0IR1QPFRhpjSmkpAjKvUMtfc"}`
	if (meta != goldenMeta) {
		throw new Error("meta and goldenMeta not equal")
	}

	// Meta with mismatched alg must fail
	let errored = false
	try {
		meta = JSON.stringify(await Coze.Meta(GoldenCoz, "ES512"))
	} catch (e) {
		errored = true
	}
	if (errored == false) {
		throw new Error("Coze.Meta must fail if coz.pay.alg is mismatched with alg. ")
	}

	// Meta with no alg must fail.  
	errored = false
	try {
		meta = await Coze.Meta(JSON.parse(`{
	"pay": {
			"msg": "Coz is a cryptographic JSON messaging specification.",
			"now": 1623132000,
			"tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
			"typ": "cyphr.me/msg/create"
	},
	"sig": "37R-VP0BaR31_vjtOgdZP7lpanTMdQy07xz83o_I7mFMMt2BdoZwdXOAn0dxtKpPrhPPNxBTe-O12ifeiCnONQ"
}`))
	} catch (e) {
		errored = true
	}
	if (errored == false) {
		throw new Error("Coze.Meta must fail if coz.pay.alg is unpopulated and alg is not provided.")
	}

	return true
}

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


// test_Duplicate tests duplicate object names in `coz` and `pay`.
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


// Tests "Coze.Thumbprint" and "Coze.Valid"
async function test_Valid() {
	if (!await Coze.Valid(GoldenCozKey)) {
		return false;
	}
	if (await Coze.Valid(GoldenBadCozKey)) {
		return false;
	}
	return true;
};


// test_Revoke test will test signing a message with a Coz Key, and validating
// the coz that is generated.
async function test_Revoke() {
	let coz = await Coze.Revoke(GoldenCozKey, "Test revoke.");
	if (!(await Coze.Verify(coz, GoldenCozKey)) || !Coze.IsRevoked(GoldenCozKey)) {
		return false;
	}
	return true;
}


// test_RVKMaxSize tests RVK_MAX_SIZE enforcement at both creation and
// verification.  Uses a fresh key to avoid rvk state from test_Revoke.
async function test_RVKMaxSize() {
	let key = await Coze.NewKey("ES256");

	// 1. Normal revoke with short message — should succeed.
	let coz = await Coze.Revoke(key, "Short revoke.");
	if (!(await Coze.Verify(coz, key))) {
		console.error("RVKMaxSize: Normal revoke failed verification.");
		return false;
	}

	// 2. Oversized revoke message — Revoke() should throw.
	let bigMsg = "x".repeat(3000);
	let key2 = await Coze.NewKey("ES256");
	try {
		await Coze.Revoke(key2, bigMsg);
		console.error("RVKMaxSize: Revoke() accepted oversized message.");
		return false;
	} catch (e) {
		if (!e.message.includes("RVK_MAX_SIZE")) {
			console.error("RVKMaxSize: Unexpected error: " + e.message);
			return false;
		}
	}

	// 3. Verify() rejects oversized revoke payload.
	//    Construct a coz with rvk > 0 and oversized pay manually.
	let key3 = await Coze.NewKey("ES256");
	let fakeCoz = {
		"pay": {
			"alg": key3.alg,
			"tmb": key3.tmb,
			"rvk": Math.round(Date.now() / 1000),
			"msg": "y".repeat(3000),
		},
		"sig": "AAAA" // Invalid sig, but RVK_MAX_SIZE check is before sig verify.
	};
	try {
		await Coze.Verify(fakeCoz, key3);
		console.error("RVKMaxSize: Verify() accepted oversized revoke payload.");
		return false;
	} catch (e) {
		if (!e.message.includes("RVK_MAX_SIZE")) {
			console.error("RVKMaxSize: Unexpected Verify error: " + e.message);
			return false;
		}
	}

	return true;
}

// test_CozKeyCorrect will test correctness for various keys with different
// algorithms when calling Correct().
async function test_CozKeyCorrect() {
	// Bad Key results vary from GO, as we have slightly weaker logic in Correct,
	// since we do not have the API capabilities for recalculating `pub`, and can
	// not perform as many checks that require pub to be present, as GO.
	let goldenMap = [
		[false, true, true, false, true, true], // Bad Key (second result is false in GO)
		[true, true, true, true, true, true], // Good key
		[true, true, true, true, true, true], // ES256
		[true, true, true, true, true, true], // ES384
		[true, true, true, true, true, true], // ES512
	];
	let keys = [GoldenBadCozKey, GoldenCozKey];
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

		// Key with with [alg,prv,tmb,pub]
		results.push(await isCorrect(k));

		// A key with [alg,tmb,prv]
		k.pub = null;
		results.push(await isCorrect(k));

		// Key with [alg,prv].
		k.tmb = null;
		results.push(await isCorrect(k));

		// A key with [alg,pub,prv].
		k.pub = keys[key].pub;
		results.push(await isCorrect(k));

		// A key with [alg,pub,tmb]
		k.prv = null;
		k.tmb = keys[key].tmb;
		results.push(await isCorrect(k));

		// Key with [alg,tmb]
		k.pub = null;
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
// 2.) CryptoKey.New (called from new coz key)
// 3.) CryptoKey.FromCozKey
// 4.) CryptoKey.SignString
// 5.) CryptoKey.VerifyMsg
// 6.) CryptoKey.SignBuffer
// 7.) CryptoKey.VerifyArrayBuffer
// 8.) CryptoKey.GetSignHashAlgoFromCryptoKey (calls `algFromCrv`)
// 9.) Importing a bad key.  
//
// `SignBuffer` cannot be tested for throwing an error, since we cannot
// create an invalid cryptokey. The test will fail at `FromCozKey`.
async function test_CryptoKeySign() {
	let msg = "Test Message";
	let abMsg = await Coze.SToArrayBuffer(msg);
	let testGSHAFCK = [];

	for (const alg of Algs) {
		let cozKey = await Coze.NewKey(alg);
		let cryptoKey = await Coze.CryptoKey.FromCozKey(cozKey);

		// Sign string
		let sig = await Coze.CryptoKey.SignString(cryptoKey, msg);
		let pcc = await Coze.CryptoKey.FromCozKey(cozKey, true);
		let result = await Coze.CryptoKey.VerifyMsg(alg, pcc, msg, sig);
		if (result !== true) {
			return false
		}

		// Sign array buffer
		sig = await Coze.CryptoKey.SignBuffer(cryptoKey, abMsg);
		result = await Coze.CryptoKey.VerifyArrayBuffer(alg, pcc, abMsg, sig);
		if (result !== true) {
			console.log(`Test failed on ${alg}`);
			return false
		}
		testGSHAFCK.push(await Coze.CryptoKey.GetSignHashAlgoFromCryptoKey(cryptoKey));
	}
	console.log(testGSHAFCK);
	if (JSON.stringify(testGSHAFCK) !== JSON.stringify([Coze.Algs.SHA256, Coze.Algs.SHA384, Coze.Algs.SHA512])) {
		return false;
	}

	// Importing an invalid key from `subtle` should throw a DOMException error:
	// `DOMException: The imported EC key is invalid` However, it does only on
	// Chrome and not on Firefox (2023/07/14).  Firefox finally errors on signing.  
	let e = null;
	try {
		// Should error here, but right now (2023/07/14) only Chrome errors here. 
		let ck = await Coze.CryptoKey.FromCozKey(GoldenBadCozKey);

		// Firefox does not appear to error on bad private keys until signing.  
		console.log("Import should have errored for this key:", ck);

		// Sign array buffer.  The following should throw an error everywhere (Chrome/Firefox)
		let _ = await Coze.CryptoKey.VerifyArrayBuffer(ck.alg, pcc, abMsg, await Coze.CryptoKey.SignBuffer(ck, abMsg));
		return false // Should never get to this line.  
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
		let cozKey = await Coze.NewKey(alg);
		let pay = `{"msg":"Test Message"}`;
		let sig = await Coze.SignPay(pay, cozKey);

		if ((await Coze.VerifyPay(pay, cozKey, sig)) !== true) {
			console.error("Failed on alg: " + alg)
			return false
		}
	}

	// Make sure high-S cozies will not verify.
	// These vectors use the new tmb from Go reference ExampleECDSAToLowSSig.
	let highSCozies = [
		'{"pay":{},"sig":"nN7tddth3aiSHaEh0WfhFzXFSSWuAfB7wdS_fUAc9kai2fBx9jXY8j-MWDZW-5Pm4AsX7ed5UQ9MAStNOMNa8g"}',
		'{"pay":{"msg":"Coz is a cryptographic JSON messaging specification.","alg":"ES256","now":1623132000,"tmb":"U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg","typ":"cyphr.me/msg"},"sig":"fGNQ_xCWAlvSjuNZdh6Suam7_O7-LdoKmC8LAjPawRv7XciadwUmLXGom6StDQKpY5ue0gXuLz3xk-_jhaq_tg"}',
	]

	for (let c of highSCozies) {
		let coz = JSON.parse(c);

		let v = await Coze.Verify(coz, GoldenCozKey);
		if (v) {
			return ("High-S Should not be valid. ");
		}

		coz.sig = await Coze.SigToLowS("ES256", coz.sig);
		v = await Coze.Verify(coz, GoldenCozKey);
		if (!v) {
			return ("High-S to low-S should be valid. ");
		}

	}

	return true;
}

// Demonstrates Javascript's behavior for non-canonical base 64 encoding.
// Enforcing canonical only stop malleability.  See
// https://github.com/Cyphrme/Coz/issues/18. The last three characters of
// example `tmb` is `Aqg`, but `Aqh` also decodes to the same byte value (in
// Hex) even though they are different UTF-8 values. Tool for decoding
// [Aqg](https://convert.zamicol.com/#?inAlph=base64&in=Aqg&outAlph=Hex) and
// [Aqh](https://convert.zamicol.com/#?inAlph=base64&in=Aqh&outAlph=Hex).
//
// As an added concern, Go's base64 ignores new line and carriage return.
// Thankfully, JSON unmarshal does not, making Coz's interpretation of base 64
// non-malleable since Coz is JSON.
async function test_B64Canonical() {
	let ab1 = Coze.B64uToArrayBuffer("Aqg") // correct

	let failed = false
	try {
		let ab2 = Coze.B64uToArrayBuffer("Aqh") // non-canonical
	} catch (e) {
		failed = true;
	}
	if (failed != true) {
		return false
	}

	let nonCanonicalCozSig = {
		"pay": {
			"msg": "Coz is a cryptographic JSON messaging specification.",
			"alg": "ES256",
			"now": 1623132000,
			"tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
			"typ": "cyphr.me/msg/create"
		},
		"sig": "OJ4_timgp-wxpLF3hllrbe55wdjhzGOLgRYsGO1BmIMYbo4VKAdgZHnYyIU907ZTJkVr8B81A2K8U4nQA6ONEx" // Non canonical sig (last "x" should be a "g")
	}
	failed = false
	try {
		failed = await Coze.Verify(nonCanonicalCozSig, GoldenCozKey)
	} catch (e) {
		failed = true
	}
	if (failed != true) {
		return false
	}

	let nonCanonicalCozTmb = {
		"pay": {
			"msg": "Coz is a cryptographic JSON messaging specification.",
			"alg": "ES256",
			"now": 1623132000,
			"tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqh", // Non canonical tmb (last "h" should be a "g")
			"typ": "cyphr.me/msg/create"
		},
		"sig": "OJ4_timgp-wxpLF3hllrbe55wdjhzGOLgRYsGO1BmIMYbo4VKAdgZHnYyIU907ZTJkVr8B81A2K8U4nQA6ONEg"
	}
	failed = false
	try {
		failed = await Coze.Verify(nonCanonicalCozTmb, GoldenCozKey)
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
TestsToRun must be declared at the bottom of the file, as the variables
cannot be accessed before initialization.
@type {TestsToRun}
**/
let TestsToRun = [
	t_Verify,
	t_VerifyArray,
	t_Sign,
	t_SignPay,
	t_SignPayRaw,
	t_ValidateTimestamp,
	t_RVKMaxSize,
	t_CryptoKeySign,
	t_Valid,
	t_Correct,
	t_Revoke,
	t_Thumbprint,
	t_Param,
	t_Meta,
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

	<p><a class="account_keys text-center" href="https://github.com/cyphrme/coz"> Coz Github</a></p>
	<p><a class="account_keys text-center" href="https://github.com/cyphrme/cozejs"> CozJs Github</a></p>
	<p><a href="https://cyphr.me/coz">Cyphr.me Coz Verifier</a></p>
	<div class="level-item has-text-centered text-muted footer_logo mt-5">

		<a href="https://cyphr.me">Sponsored by: <img src="../cyphrme_long_500x135.png"></a>

		<p class="mt-3">Coz is released under The 3-Clause BSD License. <br>

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