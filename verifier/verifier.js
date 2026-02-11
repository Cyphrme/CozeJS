"use strict";

import * as Coz from './coze.min.js';
var InputMsg;
var InputKey;
var OutMsg;
var AlgSelect;
var RvkMsg;

// Metas
var MetaAlg;
var MetaTmb;
var MetaNow;
var MetaNows;
var MetaTyp;
var MetaCan;
var MetaCad;
var MetaSig;
var MetaCzd;

// DOM load
document.addEventListener('DOMContentLoaded', () => {
	if (window.location.hostname === "localhost") {
		// Fix for local deving.  Change from `cyphr.me/coze` to
		// `localhost/coze` 
		document.getElementById('VerifierLink').href = "/coze";
	}

	InputMsg = document.getElementById('InputMsg');
	InputKey = document.getElementById('InputKey');
	OutMsg = document.getElementById('OutMsg');
	AlgSelect = document.getElementById('AlgSelect');
	RvkMsg = document.getElementById('RvkMsg');

	// Meta
	MetaAlg = document.querySelector("#MetaAlg");
	MetaTmb = document.querySelector("#MetaTmb");
	MetaNow = document.querySelector("#MetaNow");
	MetaNows = document.querySelector("#MetaNows");
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

function Copy() {
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
		var coz = JSON.parse(InputMsg.value);
	} catch (e) {
		OutMsg.innerText = "❌ Error parsing coz - " + e;
		return;
	}

	try {
		var key = JSON.parse(InputKey.value);
		var verified = await Coz.Verify(coz, key);

		if (Coz.IsRevoked(key)) {
			RvkMsg.innerText = "⚠️ Key is revoked since " + new Date(key.rvk * 1000).toLocaleString()
		}

		if (verified) {
			OutMsg.innerText = "✅ Verified";
			Meta(coz, key);
			return;
		}
	} catch (e) { }
	// Still show meta on Coz even if key is bad or signature failed.  Generate
	// key with alg from select for contextual cozies (such as the empty coz).  
	let AlgFromSelectKey = {
		alg: AlgSelect.value
	};
	Meta(coz, AlgFromSelectKey);
}

async function Sign() {
	Reset();
	console.log(InputMsg.value, InputKey.value);

	try {
		var cozKey = JSON.parse(InputKey.value);
	} catch (e) {
		console.log();
		OutMsg.innerText = "❌ Error parsing key - " + e;
		return;
	}

	try {
		var coz = JSON.parse(InputMsg.value);
	} catch (e) {
		// Assume string on JSON parse error. 
		let pay = {
			msg: InputMsg.value,
			alg: cozKey.alg,
			now: Math.floor(Date.now() / 1000), // To get Unix time from js time, divide by 1000. 
			tmb: cozKey.tmb,
			typ: "cyphr.me/msg/create"
		};

		coz = {
			pay: pay
		};
	}

	// Set the correct tmb if present in pay.  
	if (('tmb' in coz)) {
		coz.pay.tmb = cozKey.tmb
	}

	// Set the correct alg if present in pay.  
	if (('alg' in coz)) {
		coz.pay.alg = cozKey.alg
	}

	// Update now if present in pay.  
	if (('now' in coz)) {
		coz.pay.now = Math.round((Date.now() / 1000)); // Javascript's Date converted to Unix time.
	}


	try {
		var newCoz = await Coz.SignCozRaw(coz, cozKey);
	} catch (e) {
		console.log();
		OutMsg.innerText = "❌ Error: " + e;
		return;
	}

	console.log(newCoz);


	OutMsg.textContent = JSON.stringify(newCoz, null, "  ");


	Meta(newCoz, cozKey);
}


async function GenKey() {
	Reset();
	try {
		var newKey = await Coz.NewKey(AlgSelect.value);
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
	MetaNow.textContent = "";
	MetaNows.textContent = "";
	MetaTmb.textContent = "";
	MetaTyp.textContent = "";
	MetaCan.textContent = "";
	MetaCad.textContent = "";
	MetaSig.textContent = "";
	MetaCzd.textContent = "";
}


async function Meta(coz, key) {
	console.log(coz, key);
	let meta = {}

	// Set fields for meta.  May be empty on "contextual" cozies.
	if ('alg' in key) {
		meta = await Coz.Meta(coz, key.alg);
	} else {
		meta = await Coz.Meta(coz);
	}

	console.log(meta)

	MetaAlg.textContent = meta.alg;
	if (('now' in meta)) {
		MetaNow.textContent = meta.now;
		MetaNows.textContent = "(" + new Date(meta.now * 1000).toLocaleString() + ")";
	}
	MetaTmb.textContent = meta.tmb;
	MetaTyp.textContent = meta.typ;
	MetaCan.textContent = JSON.stringify(meta.can);
	MetaCad.textContent = meta.cad;
	MetaSig.textContent = meta.sig;
	MetaCzd.textContent = meta.czd;
}