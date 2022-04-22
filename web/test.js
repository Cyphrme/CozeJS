"use strict";

export{
	Run,
}

/**
 * test defines a test to be run.  
 * @typedef  {Object}    test  
 * @property {String}    name    - Name of the test to display to the user.  
 * @property {Function}  func    - Test function to execute.  
 * @property {String}    golden  - Correct return value for the test.  
 * 
 * @typedef  {Array<test>} tests - Tests to be run.  
 */

let totalTestsToRun = 0;
let totalTestsRan = 0;
let testPastCount = 0;
let testFailCount = 0;

// Template for displaying test results in the GUI. Must be cloned.
const jsResultTemplate = document.getElementById('js_test_results');


/**
 * tests will run all of the tests in the 'testsToRun' array.
 * @param   {tests} tests
 * @returns {void}
 */
async function Run(tests) {
	console.log("Starting Coze Javascript Tests.");
	totalTestsToRun = Object.entries(tests).length;
	let values = Object.values(tests);
	for (let i = 0; i < totalTestsToRun; i++) {
		var test = {};
		test.name = values[i].name;
		test.golden = values[i].golden;
		try {
			test.result = await values[i].func();
		} catch (err) {
			console.error(err);
			test.result = err;
		}
		appendResult(test);
	}
	stats();
};


/**
 * stats displays statistics about the tests that are being run, out to the
 * screen. It will show the tests that ran, and which passed and failed.
 *
 * @returns {void}          Displays the stats on the page.
 */
async function stats() {
	document.getElementById("totalTestsToRun").innerText = totalTestsToRun;
	document.getElementById("totalTestsRan").innerText = totalTestsRan;
	document.getElementById("testPastCount").innerText = testPastCount;
	document.getElementById("testFailCount").innerText = testFailCount;

	document.getElementById("testsRunning").hidden = true;
	if (testFailCount == 0) {
		document.getElementById("testsPassed").hidden = false;
	} else {
		document.getElementById("testsFailed").hidden = false;
	}
};


/**
 * appendResults appends the results to the div on the page.
 *
 * @param {Object} obj            The object that holds the name of the test,
 *                                function, expected result, and actual results.
 * @returns {void}
 */
function appendResult(obj) {
	let clone = jsResultTemplate.content.cloneNode(true);
	let test = "" + obj.name + "\: ";
	let res;
	let expected;
	if (obj.result != obj.golden) {
		console.error("❌ Failed.  Expected: " + obj.golden + " Got: " + obj.result);
		test += "❌ Failed";
		clone.querySelector('div').classList.add("text-danger")
		res = "Results: " + obj.result;
		expected = "Expected: " + obj.golden;

		testFailCount++;
	} else {
		// Test Passed
		// console.debug("Test passsed");
		clone.querySelector('div').classList.add("text-success")
		test += "✅ Passed";
		testPastCount++;
	}
	totalTestsRan++;

	clone.querySelector('.test').textContent = test;
	clone.querySelector('.result').textContent = res;
	clone.querySelector('.expected').textContent = expected;

	document.getElementById("testsResultsList").append(clone);
};
