use std::env;
use std::path::PathBuf;

fn main() {
    // Check if Firedancer submodule exists
    let firedancer_path = PathBuf::from("firedancer");

    if !firedancer_path.exists() {
        panic!("Firedancer submodule not found. Run: git submodule update --init --recursive");
    }

    // Build Firedancer
    build_firedancer();

    // Tell cargo to rerun if firedancer changes
    println!("cargo:rerun-if-changed=firedancer/src/ballet/ed25519");
    println!("cargo:rerun-if-changed=firedancer/src/ballet/sha512");
}

fn build_firedancer() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let firedancer_dir = manifest_dir.join("firedancer");
    let build_dir = manifest_dir.join("build");

    // Create build directory
    std::fs::create_dir_all(&build_dir).ok();

    // Paths to Firedancer source files
    let ed25519_src = firedancer_dir.join("src/ballet/ed25519");
    let sha512_src = firedancer_dir.join("src/ballet/sha512");
    let sha256_src = firedancer_dir.join("src/ballet/sha256");
    let hex_src = firedancer_dir.join("src/ballet/hex");

    // Check if source directories exist
    if !ed25519_src.exists() || !sha512_src.exists() {
        panic!(
            "Firedancer source directories not found. Ensure submodule is properly initialized."
        );
    }

    // Detect CPU features for optimal implementation selection
    let target = env::var("TARGET").unwrap();
    let use_avx512 = env::var("CARGO_CFG_TARGET_FEATURE")
        .unwrap_or_default()
        .contains("avx512");

    // Compile the necessary Firedancer C files
    let mut build = cc::Build::new();

    // Add stub implementations for logging functions
    build.file(manifest_dir.join("src/fd_stubs.c"));

    // Core ed25519 implementation files
    build
        .file(ed25519_src.join("fd_ed25519_user.c"))
        .file(ed25519_src.join("fd_curve25519_scalar.c"))
        .file(ed25519_src.join("fd_x25519.c"))
        .file(ed25519_src.join("fd_ristretto255.c"));

    // Select curve25519 implementation based on CPU features
    if use_avx512 && ed25519_src.join("avx512").exists() {
        println!("cargo:warning=Using AVX-512 implementation");
        build
            .file(ed25519_src.join("avx512/fd_curve25519.c"))
            .file(ed25519_src.join("avx512/fd_curve25519_secure.c"))
            .file(ed25519_src.join("avx512/fd_f25519.c"))
            .file(ed25519_src.join("avx512/fd_r43x6.c"))
            .file(ed25519_src.join("avx512/fd_r43x6_ge.c"));
    } else {
        // Use reference implementation
        build
            .file(ed25519_src.join("fd_curve25519.c"))
            .file(ed25519_src.join("fd_curve25519_secure.c"))
            .file(ed25519_src.join("fd_f25519.c"))
            .file(ed25519_src.join("fd_curve25519_tables.c"));
    }

    // Add SHA-512 implementation
    build.file(sha512_src.join("fd_sha512.c"));

    // Add SHA-256 if available
    if sha256_src.join("fd_sha256.c").exists() {
        build.file(sha256_src.join("fd_sha256.c"));
    }

    // Add hex if available
    if hex_src.join("fd_hex.c").exists() {
        build.file(hex_src.join("fd_hex.c"));
    }

    // Set include paths
    build
        .include(firedancer_dir.join("src"))
        .include(firedancer_dir.join("src/ballet"))
        .include(firedancer_dir.join("src/ballet/ed25519"))
        .include(firedancer_dir.join("src/ballet/sha512"))
        .include(firedancer_dir.join("src/ballet/sha256"))
        .include(firedancer_dir.join("src/ballet/hex"))
        .include(firedancer_dir.join("src/util"));

    // Set compiler flags
    build
        .flag("-std=c17")
        .flag("-O3")
        .flag("-fPIC")
        .flag("-Wno-unused-function")
        .flag("-Wno-unused-variable")
        .flag("-Wno-incompatible-pointer-types");

    // Add platform-specific flags
    if target.contains("darwin") {
        build.flag("-Wno-unused-command-line-argument");
    }

    // Try to use native CPU features, but don't fail if not available
    if !use_avx512 {
        build.flag_if_supported("-march=native");
    }

    build.compile("firedancer_ed25519");

    // Tell cargo where to find the library
    println!("cargo:rustc-link-lib=static=firedancer_ed25519");
    println!(
        "cargo:rustc-link-search=native={}",
        env::var("OUT_DIR").unwrap()
    );
}
