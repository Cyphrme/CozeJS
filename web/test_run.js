"use strict";

import {Run} from './test.js';
import * as tests from './test_unit.js';

// Calls tests to be ran, after the DOM has been loaded.
document.addEventListener('DOMContentLoaded', () => {
	Run(testsToRun);
});

/** @type {tests} **/
let testsToRun = [
	tests.t_Canon,
	tests.t_Sign,
	tests.t_SignCy,
	tests.t_Valid,
	tests.t_Revoke,
	tests.t_CryptoKeySign,
	tests.t_AlgParams,
];