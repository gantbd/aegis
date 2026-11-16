#[test]
fn semantic_core_retains_no_runtime_dependencies() {
    let output = std::process::Command::new("cargo")
        .args([
            "tree",
            "--offline",
            "--locked",
            "-p",
            "aegis-authority",
            "--edges",
            "normal",
            "--prefix",
            "none",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let tree = String::from_utf8(output.stdout).unwrap();
    assert_eq!(
        tree.lines().count(),
        1,
        "unexpected semantic-core dependency"
    );
}
