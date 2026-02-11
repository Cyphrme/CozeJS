"use strict";

import {
	isEmpty,
	Verify
} from '../coz.js';

export {
	VerifyCozArray
}
/**
@typedef {import('../typedef.js').Coz}  Coz
*/

/**
VerifiedArray - Used when verifying array of coz objects.

- VerifiedAll:     Indicates if whole array was verified. False on error or
				   if anything was not verified.
- VerifiedCount:   Number of objects verified.
- FailedCount:     Number of objects that failed verification.
- FailedCozies:    Objects that failed verification.
- FailedPositions: Position in input array of all failed cozies.  
@typedef  {object}    VerifiedCozArray
@property {boolean}   VerifiedAll
@property {number}    VerifiedCount
@property {number}    FailedCount
@property {Coz[]}    FailedCozies
@property {Number[]}  FailedPositions
*/

/**
VerifyCozArray verifies an array of coz objects and returns a single
"VerifiedArray" object.  If a coz has a key, it is ignored, the given
cozKey is always used.  Assumes that object has no duplicate fields since
this is disallowed in Javascript.
@param  {coz[]}           coz        Array of Coz objects.
@param  {Key}              cozKey     Javascript object. Coz Key.
@return {VerifiedArray}
@throws {error}
*/
async function VerifyCozArray(coz, cozKey) {
	if (!Array.isArray(coz)) {
		return Verify(coz, cozKey)
	}

	/** @type {VerifiedCozArray} */
	var v = {
		VerifiedAll: false,
		VerifiedCount: 0,
		FailedCount: 0,
		FailedCozies: [],
		FailedPosition: [],
	};

	let i = 0;
	let copy = [...coz]; // Copy so original isn't modified.
	for (let c of copy) {

		if (!isEmpty(c.coz)) { // "coz" encapsulated?
			c = c.coz;
		}

		let valid = await Verify(c, cozKey);
		if (valid) {
			v.VerifiedCount++;
		} else {
			v.FailedCount++;
			v.FailedCozies.push(c);
			v.FailedPosition.push(i);
		}
		i++;
	}

	if (v.FailedCount == 0 && v.VerifiedCount > 1) {
		v.VerifiedAll = true;
	}

	return v;
};