// Bundle the exact source/build recipe so installed binaries can build the same
// version's isolated Linux runtime, without requiring a checkout or trusting HEAD.
use std::{env, fs, path::Path};
fn main() {
    let root = env::var("CARGO_MANIFEST_DIR").unwrap();
    let mut files = vec![
        "Cargo.toml".to_string(),
        "Cargo.lock".into(),
        "Dockerfile".into(),
        "LICENSE".into(),
        "scope.example.yaml".into(),
        "scripts/install-tools.sh".into(),
    ];
    fn visit(root: &Path, dir: &Path, files: &mut Vec<String>) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                visit(root, &path, files);
            } else if path.extension().is_some_and(|e| e == "rs") {
                files.push(
                    path.strip_prefix(root)
                        .unwrap()
                        .to_string_lossy()
                        .replace('\\', "/"),
                );
            }
        }
    }
    visit(Path::new(&root), &Path::new(&root).join("src"), &mut files);
    files.sort();
    let mut code = String::from("pub const BUILD_FILES: &[(&str, &[u8])] = &[\n");
    for file in files {
        println!("cargo:rerun-if-changed={file}");
        code.push_str(&format!(
            "({file:?}, include_bytes!({:?})),\n",
            Path::new(&root).join(&file)
        ));
    }
    code.push_str("];\n");
    fs::write(
        Path::new(&env::var("OUT_DIR").unwrap()).join("build_files.rs"),
        code,
    )
    .unwrap();
    println!("cargo:rerun-if-changed=src");
}
