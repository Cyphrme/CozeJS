"use strict";

import * as Coze from './coze.min.js';
var InputMsg;
var InputKey;
var OutMsg;
var AlgSelect;
var RvkMsg;

// Metas
var MetaAlg;
var MetaTmb;
var MetaIat;
var MetaIats;
var MetaTyp;
var MetaCan;
var MetaCad;
var MetaSig;
var MetaCzd;

// DOM load
document.addEventListener('DOMContentLoaded', () => {
	if (window.location.hostname === "localhost"){
		// Fix for local deving.  Change from `cyphr.me/coze_verifier` to
		// `localhost/coze_verifier` 
		document.getElementById('VerifierLink').href = "/coze_verifier";
	}

	InputMsg = document.getElementById('InputMsg');
	InputKey = document.getElementById('InputKey');
	OutMsg = document.getElementById('OutMsg');
	AlgSelect = document.getElementById('AlgSelect');
	RvkMsg = document.getElementById('RvkMsg');

	// Meta
	MetaAlg = document.querySelector("#MetaAlg");
	MetaTmb = document.querySelector("#MetaTmb");
	MetaIat = document.querySelector("#MetaIat");
	MetaIats = document.querySelector("#MetaIats");
	MetaTyp = document.querySelector("#MetaTyp");
	MetaCan = document.querySelector("#MetaCan");
	MetaCad = document.querySelector("#MetaCad");
	MetaSig = document.querySelector("#MetaSig");
	MetaCzd = document.querySelector("#MetaCzd");

	// Set event listeners for buttons.
	document.getElementById('VerifyBtn').addEventListener('click', Verify);
	document.getElementById('SignBtn').addEventListener('click', Sign);
	document.getElementById('GenRandKeyBtn').addEventListener('click', GenKey);
	document.getElementById('ClearBtn').addEventListener('click', ClearAll);
	document.getElementById('CopyBtn').addEventListener('click', Copy);
});

function Copy(){
    // Select the text.
    var selection = window.getSelection();
    var range = document.createRange();
    range.selectNodeContents(OutMsg);
    selection.removeAllRanges();
    selection.addRange(range);
    //Add to clipboard.
    document.execCommand('copy');
}




async function Verify() {
	Reset();
	console.log(InputMsg.value, InputKey.value);

	try {
		var coze = JSON.parse(InputMsg.value);
	} catch (e) {
		OutMsg.innerText = "❌ Error parsing coze - " + e;
		return;
	}

	try {
		var key = JSON.parse(InputKey.value);
		var verified = await Coze.VerifyCoze(coze, key);

		if (Coze.IsRevoked(key)) {
			RvkMsg.innerText = "⚠️ Key is revoked since " + new Date(key.rvk * 1000).toLocaleString()
		}

		if (verified) {
			OutMsg.innerText = "✅ Verified";
			Meta(coze, key);
			return;
		}
	} catch (e) {}
	// Still show meta on Coze even if key is bad or signature failed.  Generate
	// key with alg from select for contextual cozies (such as the empty coze).  
	let AlgFromSelectKey = {
		alg: AlgSelect.value
	};
	Meta(coze, AlgFromSelectKey);
}

async function Sign() {
	Reset();
	console.log(InputMsg.value, InputKey.value);

	try {
		var cozeKey = JSON.parse(InputKey.value);
	} catch (e) {
		console.log();
		OutMsg.innerText = "❌ Error parsing key - " + e;
		return;
	}

	try {
		var coze = JSON.parse(InputMsg.value);
	} catch (e) {
		// Assume string on JSON parse error. 
		let pay = {
			msg: InputMsg.value,
			alg: cozeKey.alg,
			iat: Math.floor(Date.now() / 1000), // To get Unix time from js time, divide by 1000. 
			tmb: cozeKey.tmb,
			typ: "cyphr.me/msg/create"
		};

		coze = {
			pay: pay
		};
	}

	// Set the correct tmb if present in pay.  
	if (('tmb' in coze)) {
		coze.pay.tmb = cozeKey.tmb
	}

	// Set the correct alg if present in pay.  
	if (('alg' in coze)) {
		coze.pay.alg = cozeKey.alg
	}

	// Update iat if present in pay.  
	if (('iat' in coze)) {
		coze.pay.iat = Math.round((Date.now() / 1000)); // Javascript's Date converted to Unix time.
	}


	try {
		var newCoze = await Coze.SignCozeRaw(coze, cozeKey);
	} catch (e) {
		console.log();
		OutMsg.innerText = "❌ Error: " + e;
		return;
	}

	console.log(newCoze);


	OutMsg.textContent = JSON.stringify(newCoze, null, "  ");


	Meta(newCoze, cozeKey);
}


async function GenKey() {
	Reset();
	try {
		var newKey = await Coze.NewKey(AlgSelect.value);
	} catch (e) {
		console.log();
		OutMsg.innerText = "❌ Error: " + e;
	}

	InputKey.value = JSON.stringify(newKey, null, " ");
	console.log(newKey);
}

function ClearAll() {
	InputKey.value = "";
	InputMsg.value = "";
	Reset();
}

function Reset() {
	OutMsg.innerText = "❌ Invalid";
	RvkMsg.innerText = "";

	// Meta
	MetaAlg.textContent = "";
	MetaIat.textContent = "";
	MetaIats.textContent = "";
	MetaTmb.textContent = "";
	MetaTyp.textContent = "";
	MetaCan.textContent = "";
	MetaCad.textContent = "";
	MetaSig.textContent = "";
	MetaCzd.textContent = "";
}


async function Meta(coze, key) {
	console.log(coze, key);

	// Set fields for meta.  May be empty on "contextual" cozies.
	if (!('alg' in coze.pay) && ('alg' in key)) {
		coze = await Coze.Meta(coze, key.alg);
	} else {
		coze = await Coze.Meta(coze);
	}

	if (!('alg' in coze.pay) && ('alg' in key)) {
		console.log(coze);
		coze.pay.alg = key.alg
	}

	if (!('tmb' in coze.pay) && ('tmb' in key)) {
		coze.pay.tmb = key.tmb
	}

	MetaAlg.textContent = coze.pay.alg;
	if (('iat' in coze.pay)) {
		MetaIat.textContent = coze.pay.iat;
		MetaIats.textContent = "(" + new Date(coze.pay.iat * 1000).toLocaleString() + ")";
	}
	MetaTmb.textContent = coze.pay.tmb;
	MetaTyp.textContent = coze.pay.typ;
	MetaCan.textContent = JSON.stringify(coze.can);
	MetaCad.textContent = coze.cad;
	MetaSig.textContent = coze.sig;
	MetaCzd.textContent = coze.czd;
}