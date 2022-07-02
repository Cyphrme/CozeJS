"use strict";

// Tests are run from `test_run.js` so that module imports don't run. Javascript
// (dumbly) executes code that isn't imported by other modules, meaning
// `document.addEventListener` is executed despite not being imported.  

import * as Coze from '../coze.min.js';


export {
	t_Param,
	t_Canon,
	t_Sign,
	t_SignCoze,
	t_Valid,
	t_Revoke,
	t_CryptoKeySign,
}

/**
@typedef {import('./test.js').test} test
*/

/**@type {test} */
let t_Param = {
	"name": "Param",
	"func": test_Param,
	"golden": `
{"Name":"ES224","Genus":"ECDSA","Family":"EC","Hash":"SHA-224","HashSize":28,"Curve":"P-224","Use":"sig","SigSize":56,"XSize":56,"DSize":28}
{"Name":"ES256","Genus":"ECDSA","Family":"EC","Hash":"SHA-256","HashSize":32,"Curve":"P-256","Use":"sig","SigSize":64,"XSize":64,"DSize":32}
{"Name":"ES384","Genus":"ECDSA","Family":"EC","Hash":"SHA-384","HashSize":48,"Curve":"P-384","Use":"sig","SigSize":96,"XSize":96,"DSize":48}
{"Name":"ES512","Genus":"ECDSA","Family":"EC","Hash":"SHA-512","HashSize":64,"Curve":"P-521","Use":"sig","SigSize":132,"XSize":132,"DSize":66}
{"Name":"Ed25519","Genus":"EdDSA","Family":"EC","Hash":"SHA-512","HashSize":64,"Curve":"Curve25519","Use":"sig","SigSize":64,"XSize":32,"DSize":32}
{"Name":"Ed25519ph","Genus":"EdDSA","Family":"EC","Hash":"SHA-512","HashSize":64,"Curve":"Curve25519","Use":"sig","SigSize":64,"XSize":32,"DSize":32}
{"Name":"Ed448","Genus":"EdDSA","Family":"EC","Hash":"SHAKE256","HashSize":64,"Curve":"Curve448","Use":"sig","SigSize":114,"XSize":57,"DSize":57}
{"Name":"SHA-224","Genus":"SHA2","Family":"SHA","Hash":"SHA-224","HashSize":28}
{"Name":"SHA-256","Genus":"SHA2","Family":"SHA","Hash":"SHA-256","HashSize":32}
{"Name":"SHA-384","Genus":"SHA2","Family":"SHA","Hash":"SHA-384","HashSize":48}
{"Name":"SHA-512","Genus":"SHA2","Family":"SHA","Hash":"SHA-512","HashSize":64}
{"Name":"SHA3-224","Genus":"SHA3","Family":"SHA","Hash":"SHA3-224","HashSize":28}
{"Name":"SHA3-256","Genus":"SHA3","Family":"SHA","Hash":"SHA3-256","HashSize":32}
{"Name":"SHA3-384","Genus":"SHA3","Family":"SHA","Hash":"SHA3-384","HashSize":48}
{"Name":"SHA3-512","Genus":"SHA3","Family":"SHA","Hash":"SHA3-512","HashSize":64}
{"Name":"SHAKE128","Genus":"SHA3","Family":"SHA","Hash":"SHAKE128","HashSize":32}
{"Name":"SHAKE256","Genus":"SHA3","Family":"SHA","Hash":"SHAKE256","HashSize":64}
`};

let t_Canon = {
	"name": "Canon",
	"func": test_Canon,
	"golden": '{"Action":{"POST":"cyphr.me/api/v1/image"},"Hello World":"!","Image":"EA0B773A66011031CE0D0F5251CF2ADA6A26227C3A191F464FF0153760D36795","hello":"world!"}'
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

////////////////////////////////////////////////////////////////////////////////
//////////////////////    Testing Variables    /////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
// x": "2nTOaFVm2QLxmUO_SjgyscVHBtvHEfo2rq65MvgNRjM"
// "y": "kaI6t_R2qva1zcb18cG2v149Beb2YmyUd4rAXTlm6OY"
let GoodCozeKey = {
	"alg": "ES256",
	"iat": 1623132000,
	"kid": "Zami's Majuscule Key.",
	"d": "bNstg4_H3m3SlROufwRSEgibLrBuRq9114OvdapcpVA",
	"tmb": "cLj8vsYtMBwYkzoFVZHBZo6SNL8wSdCIjCKAwXNuhOk",
	"x": "2nTOaFVm2QLxmUO_SjgyscVHBtvHEfo2rq65MvgNRjORojq39Haq9rXNxvXxwba_Xj0F5vZibJR3isBdOWbo5g"
}


let BadCozeKey = {
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




// test_Canon tests CanonicalS(). Checks for utf-8 order, removal of
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
	let canon = ["Action", "Hello World", "Image", "hello"]
	return Coze.CanonicalS(object, canon);
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
		// SignCoze sets/updates `iat, alg, tmb`.  
		let coze = await Coze.SignCoze({
				"pay": {
					"msg": "Test Message",
					"iat": 3,
					"tmb": "test"
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

// TODO test thumbprint:
// let t = await Coze.Thumbprint(GoodCozeKey);
// if (t !== GoodCozeKey.tmb) {
// 	console.error("Thumbprint does not match: Calculated: " + t);
// 	return false;
// }

// Tests Tests "Coze.Thumbprint" and "Coze.Valid"
async function test_Valid() {
	if (!await Coze.Valid(GoodCozeKey)) {
		return false;
	}
	if (await Coze.Valid(BadCozeKey)) {
		return false;
	}
	return true;
};


// test_Revoke test will test signing a message with a Coze Key, and validating
// the coze that is generated.
async function test_Revoke() {
	let coze = await Coze.Revoke(GoodCozeKey, "Test revoke.");
	console.log(Coze.IsRevoked(GoodCozeKey));
	if (!(await Coze.VerifyCoze(coze, GoodCozeKey)) || !Coze.IsRevoked(GoodCozeKey)) {
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