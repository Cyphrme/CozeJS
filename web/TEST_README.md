
![Coze](coze_logo_zami_white_450x273.png)
# Coze js Test Readme


## Go server

```sh
cd $CYPHRME/web/dist/js/coze/web
go run server.go
```

Then go to:

```url
https://localhost:8082/
```

The Go server runs over HTTPS on port 8082.  HTTPS is vital since some
Javascript, in our case especially cryptographic functions, are only available
over HTTPS ("secure contexts").  


## Huh?
Static HTML files cannot call external Javascript modules when loading static
files.  That's what we have to work with.  

> ES6 modules are subject to same-origin policy. This means that you cannot import
them from the file system or cross-origin without a CORS header (which cannot be
set for local files).

See https://stackoverflow.com/questions/46992463/es6-module-support-in-chrome-62-chrome-canary-64-does-not-work-locally-cors-er?rq=1

That leaves two options:

1. Run a HTTPS server.
2. Inline all Javascript modules into a single file.  

For Go the server option requires only a few lines of code and only Go as a
dependency.  Since main Coze is in Go, that's a reasonable tradeoff.





## No Go, inline Javascript modules.  
Alternatively, inlining all Javascript into a single `js.min` file might be
feasible in a single page, static HTML file.  

```sh
esbuild join_test.js --bundle --format=esm --minify --sourcemap=inline  --outfile=test.coze.min.js
esbuild join_test.js --bundle --format=esm  --outfile=test.coze.min.js
```

Then dump the results in a `<script>` section of `web/test.html`
