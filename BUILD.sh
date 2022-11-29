#!/usr/bin/env bash
#
# See https://github.com/zamicol/watch for automation.

# Coze Core
(cd $COZEJS; esbuild join.js --bundle --format=esm --platform=browser --minify --sourcemap --outfile=coze.min.js)

# Coze all 
(cd $COZEJS/all; 
esbuild join_all.js --bundle --format=esm --platform=browser --minify --sourcemap --outfile=coze_all.min.js;
# Copy it for testing
cp coze_all.min.js ../test/coze_all.min.js)

# Coze standard
(cd $COZEJS/standard; esbuild join_standard.js --bundle --format=esm --platform=browser --minify --sourcemap --outfile=coze_standard.min.js)