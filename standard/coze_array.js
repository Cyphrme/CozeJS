"use strict";

import {
	isEmpty,
	VerifyCoze
} from '../coze.js';

export {
	VerifyCozeArray
}
/**
 * @typedef {import('../typedefs.js').Coze}  Coze
 */

/**
 * VerifiedArray - Used when verifying array of cozies.
 * 
 * - VerifiedAll:    Indicates if whole array was verified. False on error or if
 *                   anything was not verified.
 * - VerifiedCount:  Number of objects verified.
 * - FailedCount:    Number of objects that failed verification.
 * - FailedCoze:     Objects that failed verification.
 * @typedef  {Object}  VerifiedArray
 * @property {Boolean} VerifiedAll
 * @property {Number}  VerifiedCount
 * @property {Number}  FailedCount
 * @property {Coze[]}  FailedCoze
 */

/**
 * VerifyCozeArray verifies an array of `coze`s and returns a single
 * "VerifiedArray" object.
 *
 * @param  {coze[]}           coze       Array of Coze objects.
 * @param  {Key}              cozeKey    Javascript object. Coze Key.
 * @return {VerifiedArray}
 * @throws {Error}
 */
async function VerifyCozeArray(coze, cozeKey) {
	if (!Array.isArray(coze)) {
		return VerifyCoze(coze, cozeKey)
	}

	/** @type {VerifiedArray} */
	var verifiedObj = {
		VerifiedAll: false,
		VerifiedCount: 0,
		FailedCount: 0,
		FailedCoze: [],
	};

	let copy = [...coze]; // Copy so original isn't modified.
	for (let c of copy) {
		if (!isEmpty(c.coze)) { // "coze" encapsulated?
			c = c.coze;
		}

		let valid = await VerifyCoze(c, cozeKey);
		if (valid) {
			verifiedObj.VerifiedCount++;
		} else {
			verifiedObj.FailedCount++;
			verifiedObj.FailedCoze.push(c);
		}
	}

	if (verifiedObj.FailedCount == 0) {
		verifiedObj.VerifiedAll = true;
	}

	return verifiedObj;
};