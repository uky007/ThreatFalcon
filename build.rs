fn main() {
    println!("cargo:rerun-if-changed=native/macos_es.c");
    println!("cargo:rerun-if-changed=native/macos_es.h");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        // Compile against the selected Apple SDK: never reproduce es_message_t's
        // versioned unions or Objective-C blocks ABI in Rust.
        cc::Build::new()
            .file("native/macos_es.c")
            .flag("-fblocks")
            .flag("-std=c11")
            .warnings_into_errors(true)
            .compile("threatfalcon_macos_es");
        println!("cargo:rustc-link-lib=EndpointSecurity");
        println!("cargo:rustc-link-lib=bsm");
    }
}
