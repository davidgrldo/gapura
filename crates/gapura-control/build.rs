// `rust-embed` 8.12 emits no `cargo:rerun-if-changed` for the folder it embeds, and this crate
// has no other build script to supply one. Cargo's fingerprint for `gapura-control` therefore
// never includes `web/dist`, so editing or adding files there — exactly what `npm run build`
// does — leaves the crate looking unchanged to Cargo: a rebuild recompiles nothing and the old
// embedded assets ship silently. Declaring the directory here is what makes "build the
// console, then rebuild the binary" actually pick up the new build.
fn main() {
    println!("cargo:rerun-if-changed=../../web/dist");
}
