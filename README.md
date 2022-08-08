# ⚠️ COZE IS IN ALPHA.  USE AT YOUR OWN RISK ⚠️

![Coze](web/coze_logo_zami_white_450x273.png)
# Coze js

Please see the README in the [Go project.](https://github.com/Cyphrme/Coze)

For your project use `coze.min.js`.

# Testing:
See `web` directory.  

# Javascript Gotchas
- Javascript is not constant time.  Until there's something available with
constant time guarantees, like [constant time
WASM](https://cseweb.ucsd.edu/~dstefan/pubs/renner:2018:ct-wasm.pdf), this
library will be vulnerable to timing attacks.

- Even though [FIPS
186](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf) defines curves
P-224, the [W3C recommendation omits
it](https://www.w3.org/TR/WebCryptoAPI/#dfn-EcKeyGenParams) and thus is not
implemented in Javascript.  The Javascript version of Coze will
probably only support ES256, ES384, and ES512 and not support ES224.  

- The W3C Web Cryptography API recommendation also omits Ed25519, so an external
package that implements the Ed25519 primitive is used.  The upcoming
update FIPS 186-5 specifies Ed25519 support.
(https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5-draft.pdf, section 7.8)
Hopefully this will motivate Javascript to include Ed25519.  Also, we're hoping
Paul will implement it soon:
https://github.com/paulmillr/noble-ed25519/issues/63

# TODOS:
- `iat`, `alg`, and common `Meta` for arrays ([]coze).
  - If a field is different in any array, it becomes blank.  Fields that are the
   same for every element are populated.

- Single page "offline" verifier:
		Probably just use: 
		https://github.com/gildas-lormeau/SingleFile

- Support other hash algos that are supported in Go. Go has API support for more
		algos that are not natively supported in JS right now, such as: SHA-224,
		SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE128, SHAKE256.

# Developing Coze js
## How to Build
1. Install esbuild.
2. Run the commands below. 

If using Go, esbuild can be installed with the following. Otherwise see
esbuild's instructions.  
```
git clone --depth 1 --branch v0.13.14 https://github.com/evanw/esbuild.git
cd esbuild
go build ./cmd/esbuild
```

Create the Coze distribution file.
```

esbuild join.js --bundle --format=esm --minify --outfile=coze.min.js
```

When developing we find the human readable join file useful.

```
esbuild join.js --bundle --format=esm --outfile=coze.join.js
```



----------------------------------------------------------------------
# Attribution, Trademark notice, and License
Coze and Coze js is released under The 3-Clause BSD License. 

"Cyphr.me" is a trademark of Cypherpunk, LLC. The Cyphr.me logo is all rights
reserved Cypherpunk, LLC and may not be used without permission.