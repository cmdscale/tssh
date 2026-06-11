// Copyright (C) 2026 Stephan Naumann
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

use std::env;
use std::path::{Path, PathBuf};

use xxhash_rust::xxh3::xxh3_64;

// This is not cross compile compatible nor should one rely on the directory structure of cargo
// However the alternatives would be
// 1. Rely on external build tools (not wanted)
// 2. Use bindeps: https://rust-lang.github.io/rfcs/3028-cargo-binary-dependencies.html (however
//    this is in nightly only)
//
fn main() {
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set");
    let mut target_dir = PathBuf::from(out_dir.clone());

    target_dir.pop();
    target_dir.pop();
    target_dir.pop();

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let profile = env::var("PROFILE").unwrap_or_default();

    let lib_filename = match target_os.as_str() {
        "windows" => "tssh_pkcs11_lib.dll", //TODO:
        "macos" => "libtssh_pkcs11.dylib",
        _ => "libtssh_pkcs11.so",
    };

    //depending on where it is cargo build is called from
    //the pkcs11 is a regular build target or just a dependency located in deps

    let lib_path_primary = target_dir.join(lib_filename);
    let lib_path_deps = target_dir.join("deps").join(lib_filename);

    target_dir.pop();
    target_dir.pop();
    target_dir.push(profile);

    let target_lib_path_primary = target_dir.join(lib_filename);
    let target_lib_path_deps = target_dir.join("deps").join(lib_filename);

    let lib_path_used = if lib_path_primary.exists() {
        eprintln!("found in primary");
        lib_path_primary
    } else if lib_path_deps.exists() {
        eprintln!("found in deps");
        lib_path_deps
    } else if target_lib_path_deps.exists() {
        eprintln!("found in deps");
        target_lib_path_deps
    } else if target_lib_path_primary.exists() {
        eprintln!("found in deps");
        target_lib_path_primary
    } else {
        panic!(
            "Could not find {}. Looked in: \n1. {} \n2. {} \n3. {} \n4.{}",
            lib_filename,
            lib_path_primary.display(),
            lib_path_deps.display(),
            target_lib_path_primary.display(),
            target_lib_path_deps.display()
        );
    };

    println!(
        "cargo:rustc-env=TSSH_CDYLIB_PATH={}",
        lib_path_used.display()
    );

    let lib_bytes = std::fs::read(lib_path_used).expect("can't read lib");

    let hash = xxh3_64(&lib_bytes);

    let dest_path = Path::new(&out_dir).join("checksum.rs");

    let code = format!("pub const TSSH_LIB_CHECK_SUM: u64 = {};\n", hash);

    std::fs::write(&dest_path, code).expect("could not write checksum code");

    println!("cargo:rerun-if-changed=build.rs");
}
