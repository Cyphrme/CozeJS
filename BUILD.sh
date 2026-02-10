#!/usr/bin/env bash
#
# See https://github.com/zamicol/watch for automation.

# Coz Core
(
cd $COZEJS 
esbuild join.js --bundle --format=esm --platform=browser --minify --sourcemap --outfile=coze.min.js
)

# Coz all 
(
cd $COZEJS/all; 
esbuild join_all.js --bundle --format=esm --platform=browser --minify --sourcemap --outfile=coze_all.min.js;
# Copy for testing
cp coze_all.min.js     ../verifier/coze_all.min.js
cp coze_all.min.js.map ../verifier/coze_all.min.js.map
)

# Coz standard
(
cd $COZEJS/standard; 
esbuild join_standard.js --bundle --format=esm --platform=browser --minify --sourcemap --outfile=coze_standard.min.js
)