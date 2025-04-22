use std::env;

fn main() {
    let arch = env::var("CARGO_CFG_TARGET_ARCH").expect("No target arch");
    if arch == "wasm32" {
        let src_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
        println!("cargo:rustc-link-lib=static=ipcrypt2");
        println!("cargo:rustc-link-search=native={}/wasm-libs", src_dir);
        return;
    }
    cc::Build::new()
        .opt_level(3)
        .flag_if_supported("-Wno-unused-command-line-argument")
        .flag_if_supported("-Wno-unknown-pragmas")
        .flag_if_supported("-mtune=native")
        .flag_if_supported("-maes")
        .flag_if_supported("-mcrypto")
        .flag_if_supported("-mneon")
        .flag_if_supported("-maes")
        .include("src/ipcrypt2src//include")
        .file("src/ipcrypt2/src/ipcrypt2.c")
        .compile("ipcrypt2");
}
