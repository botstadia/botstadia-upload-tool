//! Writing a bundle ZIP and reading one's manifest before upload, with no
//! session host: the manifest format comes from `botstadia-interface`, the
//! ZIP from `zip`. The ZIP is byte for byte the session host's (a test in the
//! CLI holds them together), so a bundle made here has the digest
//! `botstadia bundle` gives the same files.
//!
//! This is only a sanity check before encrypting. Verification inside an
//! enclave decides whether a bundle is sound (TRUST.md#bundle-encryption).

use std::io::{Cursor, Read};

use anyhow::{Context, Result, bail};
use botstadia_interface::bundle::{
    self as format, COMPONENT, MANIFEST, MAX_BUNDLE_BYTES, Manifest,
};

/// The most a manifest may be: far more than any real one.
const MAX_MANIFEST_BYTES: u64 = 64 * 1024;

/// The manifest of a bundle ZIP, checked as far as it can be without opening
/// the component: the manifest itself, safe entry names, only the files the
/// manifest names, and every one of them there.
pub fn read_manifest(zip: &[u8]) -> Result<Manifest> {
    if zip.starts_with(b"\0asm") {
        bail!(
            "a bundle to upload needs its manifest (`botstadia build` or `botstadia bundle` writes it)"
        );
    }
    if zip.len() as u64 > MAX_BUNDLE_BYTES {
        bail!(
            "the bundle is {} bytes, over the {MAX_BUNDLE_BYTES}-byte limit",
            zip.len()
        );
    }
    let mut archive = zip::ZipArchive::new(Cursor::new(zip)).context("reading the bundle ZIP")?;
    let mut names = Vec::new();
    let mut text = None;
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index)?;
        if entry.is_dir() {
            continue;
        }
        let name = entry.name()?.to_string();
        if name.starts_with('/') || name.split('/').any(|part| part == ".." || part.is_empty()) {
            bail!("the bundle has an unsafe path `{name}`");
        }
        if names.contains(&name) {
            bail!("the bundle holds `{name}` twice");
        }
        if name == MANIFEST {
            let mut bytes = Vec::new();
            entry
                .by_ref()
                .take(MAX_MANIFEST_BYTES + 1)
                .read_to_end(&mut bytes)?;
            if bytes.len() as u64 > MAX_MANIFEST_BYTES {
                bail!("botstadia.toml is over {MAX_MANIFEST_BYTES} bytes");
            }
            text = Some(String::from_utf8(bytes).context("botstadia.toml isn't UTF-8")?);
        }
        names.push(name);
    }
    let text = text.ok_or_else(|| {
        anyhow::anyhow!(
            "a bundle to upload needs its manifest (`botstadia build` or `botstadia bundle` writes it)"
        )
    })?;
    let manifest = Manifest::from_toml(&text).map_err(anyhow::Error::msg)?;
    let problems = manifest.problems();
    if !problems.is_empty() {
        bail!("botstadia.toml: {}", problems.join("; "));
    }
    for name in &names {
        if !format::entry_allowed(&manifest, name) {
            bail!("the bundle holds `{name}`, which its manifest doesn't name");
        }
    }
    if !names.iter().any(|n| n == COMPONENT) {
        bail!("the bundle has no component.wasm");
    }
    for model in &manifest.models {
        if !names.contains(&model.path) {
            bail!(
                "the manifest names {}, which isn't in the bundle",
                model.path
            );
        }
    }
    Ok(manifest)
}

/// A bundle's deterministic ZIP: its manifest, its component and its models
/// (in the manifest's order, at the manifest's paths), entries in name order,
/// a fixed time and mode, deflate at level 6. `models` pairs each manifest
/// model entry with its bytes.
pub fn write(manifest: &Manifest, component: &[u8], models: &[Vec<u8>]) -> Result<Vec<u8>> {
    use std::io::Write;
    if models.len() != manifest.models.len() {
        bail!(
            "{} models for the manifest's {}",
            models.len(),
            manifest.models.len()
        );
    }
    let problems = manifest.problems();
    if !problems.is_empty() {
        bail!("botstadia.toml: {}", problems.join("; "));
    }
    let mut files: Vec<(String, Vec<u8>)> = vec![
        (MANIFEST.to_string(), manifest.to_toml().into_bytes()),
        (COMPONENT.to_string(), component.to_vec()),
    ];
    for (entry, bytes) in manifest.models.iter().zip(models) {
        files.push((entry.path.clone(), bytes.clone()));
    }
    files.sort_by(|a, b| a.0.cmp(&b.0));
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .compression_level(Some(6))
        .last_modified_time(zip::DateTime::default())
        .unix_permissions(0o644);
    for (name, bytes) in files {
        writer.start_file(name, options)?;
        writer.write_all(&bytes)?;
    }
    Ok(writer.finish()?.into_inner())
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use botstadia_interface::bundle::{BotKind, ModelEntry};

    use super::*;

    fn zip_of(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        for (name, bytes) in files {
            out.start_file(*name, options).unwrap();
            out.write_all(bytes).unwrap();
        }
        out.finish().unwrap().into_inner()
    }

    #[test]
    fn reads_a_sound_bundle_and_refuses_a_broken_one() {
        let mut manifest = Manifest::new("dance-off", 1, BotKind::Policy);
        manifest.models.push(ModelEntry {
            name: "policy".into(),
            path: "artifacts/policy.onnx".into(),
        });
        let toml = manifest.to_toml();
        let sound = zip_of(&[
            (MANIFEST, toml.as_bytes()),
            (COMPONENT, b"\0asm"),
            ("artifacts/policy.onnx", b"onnx"),
        ]);
        assert_eq!(read_manifest(&sound).unwrap(), manifest);

        let missing_model = zip_of(&[(MANIFEST, toml.as_bytes()), (COMPONENT, b"\0asm")]);
        let err = read_manifest(&missing_model).unwrap_err().to_string();
        assert!(err.contains("isn't in the bundle"), "{err}");

        let extra = zip_of(&[
            (MANIFEST, toml.as_bytes()),
            (COMPONENT, b"\0asm"),
            ("artifacts/policy.onnx", b"onnx"),
            ("notes.txt", b"hi"),
        ]);
        let err = read_manifest(&extra).unwrap_err().to_string();
        assert!(err.contains("doesn't name"), "{err}");

        let bare = read_manifest(b"\0asm\x01\0\0\0").unwrap_err().to_string();
        assert!(bare.contains("needs its manifest"), "{bare}");

        let no_manifest = zip_of(&[(COMPONENT, b"\0asm")]);
        let err = read_manifest(&no_manifest).unwrap_err().to_string();
        assert!(err.contains("needs its manifest"), "{err}");
    }
}
