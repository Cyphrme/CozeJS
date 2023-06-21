"use strict";

import {
	isEmpty,
	Verify
} from '../coze.js';

export {
	VerifyCozeArray
}
/**
@typedef {import('../typedef.js').Coze}  Coze
*/

/**
VerifiedArray - Used when verifying array of cozies.

- VerifiedAll:     Indicates if whole array was verified. False on error or
                   if anything was not verified.
- VerifiedCount:   Number of objects verified.
- FailedCount:     Number of objects that failed verification.
- FailedCozies:    Objects that failed verification.
- FailedPositions: Position in input array of all failed cozies.  
@typedef  {object}    VerifiedCozeArray
@property {boolean}   VerifiedAll
@property {number}    VerifiedCount
@property {number}    FailedCount
@property {Coze[]}    FailedCozies
@property {Number[]}  FailedPositions
*/

/**
VerifyCozeArray verifies an array of `coze`s and returns a single
"VerifiedArray" object.  If a coze has a key, it is ignored, the given
cozeKey is always used.  Assumes that object has no duplicate fields since
this is disallowed in Javascript.
@param  {coze[]}           coze       Array of Coze objects.
@param  {Key}              cozeKey    Javascript object. Coze Key.
@return {VerifiedArray}
@throws {error}
*/
async function VerifyCozeArray(coze, cozeKey) {
	if (!Array.isArray(coze)) {
		return Verify(coze, cozeKey)
	}

	/** @type {VerifiedCozeArray} */
	var v = {
		VerifiedAll: false,
		VerifiedCount: 0,
		FailedCount: 0,
		FailedCozies: [],
		FailedPosition:[],
	};

	let i = 0;
	let copy = [...coze]; // Copy so original isn't modified.
	for (let c of copy) {

		if (!isEmpty(c.coze)) { // "coze" encapsulated?
			c = c.coze;
		}

		let valid = await Verify(c, cozeKey);
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