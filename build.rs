use std::env;
use std::process::Command;

fn main() {
    // Only enforce environment checks natively on Windows host configuration
    if std::env::consts::OS == "windows" {
        check_perl_installed();
        check_msvc_installed();
    }
}

fn check_perl_installed() {
    println!("cargo:rerun-if-env-changed=PATH");
    
    match Command::new("perl").arg("-v").output() {
        Ok(out) if out.status.success() => {
            // Perl successfully executed
        }
        _ => {
            panic!("Perl is required to build vendored OpenSSL. Install Strawberry Perl.");
        }
    }
}

fn check_msvc_installed() {
    // Only enforce MSVC check if the target requires MSVC
    if let Ok(target_env) = env::var("CARGO_CFG_TARGET_ENV") {
        if target_env != "msvc" {
            return; // Not MSVC targeted (e.g. GNU)
        }
    }

    // `vswhere.exe` is natively available on Windows machines with any modern VS Build Tools
    let vswhere_path = r"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe";
    let output = Command::new(vswhere_path)
        .arg("-latest")
        .arg("-products")
        .arg("*")
        .arg("-requires")
        .arg("Microsoft.VisualStudio.Component.VC.Tools.x86.x64")
        .output();

    match output {
        Ok(out) if out.status.success() && !out.stdout.is_empty() => {
            // MSVC environment and toolchain successfully located natively
        }
        _ => {
            // If vswhere fails or returns nothing, we panic early before reaching C compilation
            panic!("MSVC toolchain (Visual Studio Build Tools) is required on Windows. Please install the C++ build tools.");
        }
    }
}
