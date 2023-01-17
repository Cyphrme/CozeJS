#### ⚠️ COZE IS IN ALPHA.  USE AT YOUR OWN RISK ⚠️

![Coze](verifier/coze_logo_zami_white_450x273.png)

For Coze, please see the README in the [Main Coze Project.](https://github.com/Cyphrme/Coze)

For your project use `coze.min.js`.


## Simple Coze Verifier
The simple verifier is self-contained in `/verifier`.

- [Cyphr.me   hosted Power  Coze Verifier](https://cyphr.me/coze_verifier)
- [Cyphr.me   hosted Simple Coze Verifier](https://cyphr.me/coze_verifier_simple/coze.html)
- [Github.com hosted Simple Coze Verifier](https://cyphrme.github.io/Cozejs/verifier/coze.html)


# Developing CozeJS
## How to Build
##### Install esbuild

If using Go, esbuild can be installed with the following.

```
go install github.com/evanw/esbuild/cmd/esbuild@v0.15.8
```

[Alternatively, see esbuild's installation instructions][1]

##### Create the Coze distribution file. 

(See [join.js](join.js) for more instructions)
```
esbuild join.js --bundle --format=esm --minify --outfile=coze.min.js
cp coze.min.js verifier/coze.min.js
```

## Testing
Coze uses <a href="https://github.com/Cyphrme/BrowserTestJS">BrowserTestJS</a>
for running unit tests in the browser. The test can run as a [Github
page.](https://cyphrme.github.io/Cozejs/verifier/browsertest/browsertest.html)

For local development, use the Go server. 

```sh
cd verifier/browsertest
go run server.go
```

Then go to `https://localhost:8082`.


# Coze Javascript Gotchas
- ⚠️ Javascript is not constant time.  Until there's something available
	with constant time guarantees, like [constant time
	WASM](https://cseweb.ucsd.edu/~dstefan/pubs/renner:2018:ct-wasm.pdf), this
	library will be vulnerable to timing attacks as this problem is inherent to Javascript.
- Duplicate detection is outside the scope of Cozejs because Cozejs uses
	Javascript objects which always have unique fields.  Also, no JSON parsing is
	done inside of Cozejs, which uses last-value-wins. - Objects in ES6 defined
	with duplicate fields uses last-value-wins.  
	- See notes on `test_Duplicate`.

- ES224 is not supported.  Even though [FIPS
	186](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf) defines
	curves P-224, the [W3C recommendation omits
	it](https://www.w3.org/TR/WebCryptoAPI/#dfn-EcKeyGenParams) and thus is not
	implemented in Javascript.  The Javascript version of Coze will probably only
	support ES256, ES384, and ES512.  

- The W3C Web Cryptography API recommendation also omits Ed25519, so an external
	package that implements the Ed25519 primitive is used.  The upcoming update
	[FIPS 186-5 section 7.8](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5-draft.pdf)
	specifies Ed25519 support. Hopefully this will motivate Javascript to include
	Ed25519.  Also, [Paul has implemented Ed25519ph](
	https://github.com/paulmillr/noble-ed25519/issues/63).
 
- Javascript's `SubtleCrypto.sign(algorithm, key, data)` always hashes a message
	before signing while Go's ECDSA expects a digest to sign. This means that in
	Javascript messages must be passed for signing, while in Go only a digest is
	needed.




----------------------------------------------------------------------
# Attribution, Trademark notice, and License
Coze and CozeJS is released under The 3-Clause BSD License. 

"Cyphr.me" is a trademark of Cypherpunk, LLC. The Cyphr.me logo is all rights
reserved Cypherpunk, LLC and may not be used without permission.



[1]:https://esbuild.github.io/getting-started/#build-from-source