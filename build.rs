extern crate bindgen;

use std::env;
use std::path::PathBuf;

fn main() {
    let current_dir = env::current_dir()
        .unwrap()
        .into_os_string()
        .into_string()
        .unwrap();
    println!("cargo:rustc-link-lib=yubihsm");

    let bindings = bindgen::Builder::default()
        .header(format!("{}/extern/include/yubihsm.h", current_dir))
        .whitelist_type("yh_.*")
        .whitelist_function("yh_.*")
        .whitelist_var("YH_.*")
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings.write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
