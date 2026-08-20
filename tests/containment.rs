use std::{fs, path::Path};

#[test]
fn network_runtime_contains_no_process_launch_api() {
    let forbidden = [
        "std::process::Command",
        "tokio::process::Command",
        "libc::system",
        "CreateProcess",
        "ShellExecute",
    ];
    for file in rust_files(Path::new("src")) {
        let source = fs::read_to_string(&file).unwrap();
        for pattern in forbidden {
            assert!(
                !source.contains(pattern),
                "runtime source {} contains forbidden process API {pattern}",
                file.display()
            );
        }
    }
}

#[test]
fn network_runtime_contains_no_outbound_connect_call() {
    for file in rust_files(Path::new("src")) {
        let source = fs::read_to_string(&file).unwrap();
        assert!(
            !source.contains("TcpStream::connect"),
            "runtime source {} contains an outbound TCP connector",
            file.display()
        );
    }
}

fn rust_files(root: &Path) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    let mut pending = vec![root.to_owned()];
    while let Some(path) = pending.pop() {
        for entry in fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().and_then(|value| value.to_str()) == Some("rs") {
                files.push(path);
            }
        }
    }
    files
}
