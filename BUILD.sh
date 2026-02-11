#!/usr/bin/env bash
#
# See https://github.com/zamicol/watch for automation.

# Coz Core
(
cd $COZEJS 
esbuild join.js --bundle --format=esm --platform=browser --minify --sourcemap --outfile=coz.min.js
# Copy for verifier app
cp coz.min.js     verifier/coz.min.js
cp coz.min.js.map verifier/coz.min.js.map
)

# Coz all 
(
cd $COZEJS/all; 
esbuild join_all.js --bundle --format=esm --platform=browser --minify --sourcemap --outfile=coz_all.min.js;
# Copy for testing
cp coz_all.min.js     ../verifier/coz_all.min.js
cp coz_all.min.js.map ../verifier/coz_all.min.js.map
)

# Coz standard
(
cd $COZEJS/standard; 
esbuild join_standard.js --bundle --format=esm --platform=browser --minify --sourcemap --outfile=coz_standard.min.js
)