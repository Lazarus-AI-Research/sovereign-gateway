//! Build script for the bundled Preact + TSX admin UI.
//!
//! With the `console` feature on, this bundles `frontend/src/main.tsx` into a
//! single ES module at `$OUT_DIR/app.js`, which `src/ui.rs` embeds via
//! `include_str!`. It uses the `rolldown` bundler as a **build-dependency** — it
//! runs here at build time and is never part of the runtime binary.
//!
//! With the feature off (the default) this is a no-op: `src/ui.rs` is compiled
//! out, nothing needs `app.js`, and `rolldown`/`oxc` never enter the graph —
//! which is what lets the workspace build on the pinned stable toolchain.
//!
//! Preact is vendored under `frontend/src/vendor/`, so the bundle is hermetic:
//! no `npm`, no `node_modules`, no network. JSX is the classic runtime (pragma
//! `h`/`Fragment`), configured via `frontend/tsconfig.json`.

#[cfg(feature = "console")]
fn main() {
    use std::path::PathBuf;

    use rolldown::{Bundler, BundlerOptions, InputItem, OutputFormat, RawMinifyOptions, TsConfig};

    let crate_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let frontend = crate_dir.join("frontend");
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());

    // Rebuild the bundle whenever the TSX sources or tsconfig change.
    println!("cargo:rerun-if-changed={}", frontend.join("src").display());
    println!("cargo:rerun-if-changed={}", frontend.join("tsconfig.json").display());

    let options = BundlerOptions {
        input: Some(vec![InputItem {
            name: Some("app".to_string()),
            import: "./src/main.tsx".to_string(),
        }]),
        cwd: Some(frontend.clone()),
        file: Some(out_dir.join("app.js").to_string_lossy().to_string()),
        format: Some(OutputFormat::Esm),
        minify: Some(RawMinifyOptions::Bool(true)),
        // JSX (classic, pragma `h`/`Fragment`) is read from this tsconfig.
        tsconfig: Some(TsConfig::Manual(frontend.join("tsconfig.json"))),
        ..Default::default()
    };

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime");

    rt.block_on(async move {
        let mut bundler = Bundler::new(options).expect("init rolldown bundler");
        if let Err(e) = bundler.write().await {
            panic!("rolldown failed to bundle the admin UI: {e:?}");
        }
    });
}

#[cfg(not(feature = "console"))]
fn main() {}
