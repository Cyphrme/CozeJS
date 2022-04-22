![Coze](web/coze_logo_zami_white_450x273.png)
# Coze js

Please see the Coze README in the [Go project's readme.](https://github.com/Cyphrme/Coze)

For your project use `coze.min.js`.


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

If developing we find the human readable join file useful.

```
esbuild join.js --bundle --format=esm --outfile=coze.join.js
```

# Testing:
See `web` directory.  

# Javascript Gotchas

Even though FIPS 186
(https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf) defines curves
P-192 and P-224, the W3C recommendation ignores them
(https://www.w3.org/TR/WebCryptoAPI/#dfn-EcKeyGenParams) and thus are not
implemented in Javascript.  Because of this the Javascript version of Coze will
probably only support ES256, ES384, and ES512 and not support ES192 and ES224.  

The W3C Web Cryptography API recommendation also omits Ed25519.  Because of this
an external package that implements the Ed25519 primitive is used.  The upcoming
update FIPS 186-5 specifies Ed25519 support.
(https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5-draft.pdf)  Hopefully
this will motivate Javascript to include Ed25519.  

# TODOS:
- Implement UTF-8 sorting. (Javascript is UTF-16)

- `iat`, `alg`, and common parts for `GetCyParts` on arrays ([]cy).
  - If a field is different in any array, it becomes blank.  Fields that are the
   same for every element are populated.

- Single page "offline" verifier:
		Probably just use: 
		https://github.com/gildas-lormeau/SingleFile