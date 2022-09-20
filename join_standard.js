// Coze Standard
// `join_standard.js` instructs esbuild to join all Coze standard files into one
// file.
// ```
// esbuild join_standard.js   --bundle --format=esm --minify --sourcemap --outfile=coze_standard.min.js
// ```
export * from './standard/coze_array.js';