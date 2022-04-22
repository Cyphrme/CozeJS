"use strict";

// Tests are run from `test_run.js` so that module imports don't run. Javascript
// (dumbly) executes code that isn't imported by other modules, meaning
// `document.addEventListener` is executed despite not being imported.  

import * as Coze from '../coze.min.js';


export {
	t_Canon,
	t_Sign,
	t_SignCy,
	t_Valid,
	t_Revoke,
	t_CryptoKeySign,
	t_AlgParams,
}

/**
@typedef {import('./test.js').test} test
*/

/**@type {test} */
let t_Canon = {
	"name": "Canon",
	"func": test_Canon,
	"golden": '{"Action":{"POST":"cyphr.me/api/v1/image"},"Hello World":"!","Image":"EA0B773A66011031CE0D0F5251CF2ADA6A26227C3A191F464FF0153760D36795","hello":"world!"}'
};
let t_Sign = {
	"name": "Sign",
	"func": test_Sign,
	"golden":true,
};
let t_SignCy = {
	"name": "SignCy",
	"func": test_SignCy,
	"golden":true,
};
let t_Valid = {
	"name": "Valid",
	"func": test_Valid,
	"golden": true,
};
let t_Revoke = {
	"name": "Revoking a key",
	"func": test_Revoke,
	"golden": true,
};
let t_CryptoKeySign = {
	"name": "CryptoKey",
	"func": test_CryptoKeySign,
	"golden": true
};
let t_AlgParams = {
	"name": "Params",
	"func": test_AlgParams,
	"golden": '{"Name":"ES224","Genus":"ECDSA","Family":"EC","Hash":"SHA-224","HashSize":28},{"Name":"ES256","Genus":"ECDSA","Family":"EC","Hash":"SHA-256","HashSize":32,"Curve":"P-256","Use":"sig","SigSize":64},{"Name":"ES384","Genus":"ECDSA","Family":"EC","Hash":"SHA-384","HashSize":48,"Curve":"P-384","Use":"sig","SigSize":96},{"Name":"ES512","Genus":"ECDSA","Family":"EC","Hash":"SHA-512","HashSize":64,"Curve":"P-521","Use":"sig","SigSize":132},{"Name":"Ed25519","Genus":"EdDSA","Family":"EC","Hash":"SHA-512","HashSize":64,"Curve":"Curve25519","Use":"sig","SigSize":64},{"Name":"Ed448","Genus":"EdDSA","Family":"EC","Hash":"SHAKE256","HashSize":64,"Curve":"Curve448","Use":"sig","SigSize":114},{"Name":"SHA-224","Genus":"SHA2","Family":"SHA","Hash":"SHA-224","HashSize":28},{"Name":"SHA-256","Genus":"SHA2","Family":"SHA","Hash":"SHA-256","HashSize":32},{"Name":"SHA-384","Genus":"SHA2","Family":"SHA","Hash":"SHA-384","HashSize":48},{"Name":"SHA-512","Genus":"SHA2","Family":"SHA","Hash":"SHA-512","HashSize":64},{"Name":"SHA3-224","Genus":"SHA3","Family":"SHA","Hash":"SHA3-224","HashSize":28},{"Name":"SHA3-256","Genus":"SHA3","Family":"SHA","Hash":"SHA3-256","HashSize":32},{"Name":"SHA3-384","Genus":"SHA3","Family":"SHA","Hash":"SHA3-384","HashSize":48},{"Name":"SHA3-512","Genus":"SHA3","Family":"SHA","Hash":"SHA3-512","HashSize":64}'
};
////////////////////////////////////////////////////////////////////////////////
//////////////////////    Testing Variables    /////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

let GoodCozeKey = {
	"alg": "ES256",
	"d": "30C76C9EC4286DADEB0E1EBFF546A1B4A57DB4571412F953E053FB689D286C3C",
	"x": "827ECBA80BE7421DD71A6C2819ABC1D988450EBB802B972AE22292FA0D538B6B",
	"y": "8D45880FC2C9FD1DBBF28ED4CB973CD8D1CB4F93F422B1B90AC1DA4ED13CA9EC",
	"tmb": "C124EBF0E79A8CC38576558723D9546E8DAE4F1D6BF9BCC7B402775128BD64F5",
	"iat": 1623132000,
	"kid": "Test Key"
}

let BadCozeKey = {
	"alg": "ES256",
	"d": "30C76C9EC4286DADEB0E1EBFF546A1B4A57DB4571412F953E053FB689D286C3C",
	"x": "827ECBA80BE7421DD71A6C2819ABC1D988450EBB802B972AE22292FA0D538B6BAA", // Extra "AA" at the end
	"y": "8D45880FC2C9FD1DBBF28ED4CB973CD8D1CB4F93F422B1B90AC1DA4ED13CA9EC",
	"tmb": "C124EBF0E79A8CC38576558723D9546E8DAE4F1D6BF9BCC7B402775128BD64F5",
	"iat": 1623132000,
	"kid": "Test Key Bad."
}

let Algs = ["ES256", "ES384", "ES512"];

////////////////////
// Tests
////////////////////

// test_Canon tests Canon() and Canons(). Checks for utf-8 order, removal of
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
		"Image": "EA0B773A66011031CE0D0F5251CF2ADA6A26227C3A191F464FF0153760D36795",
		"Hello World": "!", 
	};
	return Coze.Canons(object); // Canons() calls Canon()
};

// test_Sign
// Tests each support alg.  
// 1.) Coze.NewCozeKey
// 2.) Coze.SignCy
// 3.) Coze.VerifyCy
async function test_Sign() {
	for (const alg of Algs){
		let cozeKey = await Coze.NewCozeKey(alg);
		let head = {"msg":"Test Message"};
		let sig = await Coze.Sign(head, cozeKey);
		let valid = await Coze.Verify(head, cozeKey, sig);
		if (valid !== true){
			return false
		}
	}
	return true;
};

// test_SignCy
// Tests each support alg.  
// 1.) Coze.NewCozeKey
// 2.) Coze.SignCy
// 3.) Coze.VerifyCy
async function test_SignCy() {
	for (const alg of Algs){
		let cozeKey = await Coze.NewCozeKey(alg);
		// SignCy should set `iat, alg, tmb` and canonicalize head correctly.  
		let signedCy = await Coze.SignCy(
			{"head":{"msg":"Test Message","iat":3,"tmb":"test"}},
			cozeKey
		);
		if (true !== await Coze.VerifyCy(signedCy, cozeKey)){
			return false
		}
		// signedCy also canonicalizes. Check canonicalization.
		let hs = JSON.stringify(await Coze.Canon(signedCy.head));
		let cyhs = JSON.stringify(signedCy.head);
		if (hs !== cyhs){
			throw new Error("Canonicalization is incorrect");
		}
	}
	return true;
};



// Tests Tests "Coze.Thumbprint" and "Coze.Valid"
async function test_Valid() {
	let t = await Coze.Thumbprint(GoodCozeKey);
	if (t !== GoodCozeKey.tmb) {
		console.error("Thumbprint does not match: Calculated: " + t);
		return false;
	}

	let validGood = await Coze.Valid(GoodCozeKey); // Should pass
	var validBad = await Coze.Valid(BadCozeKey); // Should Fail
	if (validGood == true && validBad == false) {
		return true;
	}
	return false;
};


// Tests "Alg.Params".
async function test_AlgParams() {
	let algs = ["ES224","ES256","ES384","ES512","Ed25519","Ed448","SHA-224","SHA-256","SHA-384","SHA-512","SHA3-224","SHA3-256","SHA3-384","SHA3-512"];
	let results = [];
	for (let i=0; i<algs.length; i++) {
		results.push(JSON.stringify(Coze.Params(algs[i])));
	}
	return results;
};


// test_Revoke test will test signing a message with a Coze Key, and validating
// the cy that is generated.
async function test_Revoke() {
	let goldenMessage = "Testing revoking a key.";
	let cy = await Coze.Revoke(GoodCozeKey, goldenMessage);
	let valid = await Coze.VerifyCy(cy, GoodCozeKey);

	if (!valid) {
		return false;
	}

	let gck = {
		...GoodCozeKey
	}

	// True conditions
	gck.rvk = 3;
	if (Coze.IsRevoked(gck) !== true) {
		return false;
	}
	gck.rvk = "true";
	if (Coze.IsRevoked(gck) !== true) {
		return false;
	}
	gck.rvk = true;
	if (Coze.IsRevoked(gck) !== true) {
		return false;
	}

	// False conditions
	gck.rvk = 0;
	if (Coze.IsRevoked(gck) !== false) {
		return false;
	}
	gck.rvk = false;
	if (Coze.IsRevoked(gck) !== false) {
		return false;
	}
	gck.rvk = "false";
	if (Coze.IsRevoked(gck) !== false) {
		return false;
	}

	return true;
};


/////////////////////////////////////
// CryptoKey Tests
/////////////////////////////////////

// test_CryptoKeySign() {
// Tests
// 1.) New Coze Key
// 2.) Coze Key to Cryptokey.
// 3.) CryptoKey.SignString
// 4.) CryptoKey.FromCozeKeyToPublic 
// 5.) CryptoKey.VerifyMsgHexSig
async function test_CryptoKeySign() {
	let msg = "Test Message";
	let abMsg = await Coze.SToArrayBuffer(msg);

	for (const alg of Algs){
		let cozeKey = await Coze.NewCozeKey(alg);
		let cryptoKey = await Coze.CryptoKey.FromCozeKey(cozeKey);

		// Sign string
		let sig = await Coze.CryptoKey.SignString(cryptoKey, msg);
		let pcc = await Coze.CryptoKey.FromCozeKeyToPublic(cozeKey);
		let result = await Coze.CryptoKey.VerifyMsgHexSig(pcc, msg, sig);
		if (result !== true){return false}

		// Sign array buffer
		sig = await Coze.CryptoKey.SignBuffer(cryptoKey, abMsg);
		result = await Coze.CryptoKey.VerifyABMsgSig(pcc, abMsg, sig);
		if (result !== true){return false}
	}
	return true;
};

