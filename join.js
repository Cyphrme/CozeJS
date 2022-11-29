// Coze Core
// `join.js` instructs esbuild to join all Coze core files into one file.
//
// From ESBuild for multiple files:
//
// > Note that bundling is different than file concatenation. Passing esbuild
// multiple input files with bundling enabled will create multiple separate
// bundles instead of joining the input files together. To join a set of files
// together with esbuild, import them all into a single entry point file and
// bundle just that one file with esbuild.
//
// For production, use the following:
// ```
// esbuild join.js      --bundle --format=esm --minify --sourcemap         --outfile=coze.min.js
// ```
//
// For single file, human readable/debuggable Javascript. 
// ```
// esbuild join.js      --bundle --format=esm                              --outfile=coze.join.js  
// ```
//
export * from './canon.js';
export * from './alg.js';
export * from './coze.js';
export * from './key.js';
export * from './cryptokey.js';