fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_dir = "proto";
    let files = [
        "presidium.proto",
    ];

    let proto_paths: Vec<std::path::PathBuf> = files
        .iter()
        .map(|f| std::path::Path::new(proto_dir).join(f))
        .collect();

    let mut config = prost_build::Config::new();
    config
        .bytes(["."])
        .type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]")
        .compile_protos(&proto_paths, &[proto_dir])?;

    Ok(())
}