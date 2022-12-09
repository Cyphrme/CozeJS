# ⚠️ COZE IS IN ALPHA.  USE AT YOUR OWN RISK ⚠️

![Coze](test/coze_logo_zami_white_450x273.png)

Please see the README in the [Go project.](https://github.com/Cyphrme/Coze)

For your project use `coze.min.js`.


# Coze Javascript Gotchas
- Javascript is not constant time.  Until there's something available with
  constant time guarantees, like [constant time
  WASM](https://cseweb.ucsd.edu/~dstefan/pubs/renner:2018:ct-wasm.pdf), this
  library will be vulnerable to timing attacks.

- Duplicate detection is outside the scope of Cozejs because Cozejs uses
  Javascript objects which always have unique fields.  Also, no JSON parsing is
  done inside of Cozejs, which uses last-value-wins. 
	- Objects in ES6 defined with duplicate fields uses last-value-wins.  
	- See notes on `test_Duplicate`.

- ES224 is not supported.  Even though [FIPS
  186](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf) defines
  curves P-224, the [W3C recommendation omits
  it](https://www.w3.org/TR/WebCryptoAPI/#dfn-EcKeyGenParams) and thus is not
  implemented in Javascript.  The Javascript version of Coze will probably only
  support ES256, ES384, and ES512.  

- The W3C Web Cryptography API recommendation also omits Ed25519, so an external
  package that implements the Ed25519 primitive is used.  The upcoming update
  FIPS 186-5 specifies Ed25519 support.
  (https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5-draft.pdf, section
  7.8) Hopefully this will motivate Javascript to include Ed25519.  Also, we're
  hoping Paul will implement it soon:
  https://github.com/paulmillr/noble-ed25519/issues/63


#### Javascript vs Go crypto.
Javascript's `SubtleCrypto.sign(algorithm, key, data)` always hashes a message
before signing while Go's ECDSA expects a digest to sign. This means that in
Javascript messages must be passed for signing, while in Go only a digest is
needed.  

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
```


## Testing
Coze uses BrowserTestJS for running unit tests in the browser.

The test also runs as a [Github pages](https://cyphrme.github.io/Cozejs/browsertestjs/test.html)

### Go server

```sh
cd /test/browsertestjs
go run server.go
```

Then go to:

```url
https://localhost:8082/
```

The Go server runs over HTTPS on port 8082.  HTTPS is vital since some
Javascript, in our case especially cryptographic functions, are only available
over HTTPS ("secure contexts").  

If the git submodule is causing issues, use `--force`:

```
git submodule add --force git@github.com:Cyphrme/BrowserTestJS.git browsertestjs
```


#### Why use a Go server?
Static HTML files cannot call external Javascript modules when loading static
files (arbitrary browser/standard limitation):

> ES6 modules are subject to same-origin policy. This means that you cannot
import them from the file system or cross-origin without a CORS header (which
cannot be set for local files).

See https://stackoverflow.com/questions/46992463/es6-module-support-in-chrome-62-chrome-canary-64-does-not-work-locally-cors-er?rq=1

That leaves two options:

1. Run a HTTPS server.
2. Inline all Javascript modules into a single file.  

A Go server requires only a few lines of code and adds a single dependency (Go
itself).  Since main Coze is in Go, that's a reasonable tradeoff.


Alternatively, inlining all Javascript into a single `js.min` file might be
feasible in a single page, static HTML file.  This isn't implemented, but this
is how it would be done using esbuild:

```sh
esbuild join_test.js --bundle --format=esm --minify --sourcemap=inline  --outfile=test.coze.min.js
esbuild join_test.js --bundle --format=esm  --outfile=test.coze.min.js
```

Then dump the results in a `<script>` section of `browsertestjs/test.html`



## TODOS:
- `iat`, `alg`, and common `Meta` for arrays ([]coze).
  - If a field is different in any array, it becomes blank.  Fields that are the
   same for every element are populated.

- Single page "offline" verifier:
		Probably just use: 
		https://github.com/gildas-lormeau/SingleFile

- Support other hash algos that are supported in Go. Go has API support for more
		algos that are not natively supported in JS right now, such as: SHA-224,
		SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE128, SHAKE256.








----------------------------------------------------------------------
# Attribution, Trademark notice, and License
Coze and CozeJS is released under The 3-Clause BSD License. 

"Cyphr.me" is a trademark of Cypherpunk, LLC. The Cyphr.me logo is all rights
reserved Cypherpunk, LLC and may not be used without permission.



[1]:https://esbuild.github.io/getting-started/#build-from-source