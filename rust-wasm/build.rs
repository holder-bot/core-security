fn main() {
    // Generate a unique build timestamp
    let now = chrono::Utc::now();
    let build_timestamp = format!("{}-{:04x}", 
        now.format("%Y%m%d-%H%M%S"),
        (now.timestamp() as u32) & 0xFFFF
    );
    
    // Write to environment variable for use in src/lib.rs
    println!("cargo:rustc-env=BUILD_TIMESTAMP={}", build_timestamp);
    
    // Also tell cargo to rerun this build script if it changes
    println!("cargo:rerun-if-changed=build.rs");
}