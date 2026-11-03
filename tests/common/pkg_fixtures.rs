//! Small package files built in memory, for tests of `ak pkg`. They hold just what the
//! helper and the server read.

use std::io::Write;
use std::path::{Path, PathBuf};

/// A `.tar.gz` of (path, content).
pub fn tar_gz(path: &Path, entries: &[(&str, &[u8])]) -> PathBuf {
    let file = std::fs::File::create(path).expect("create archive");
    let gz = flate2::write::GzEncoder::new(file, flate2::Compression::fast());
    let mut tar = tar::Builder::new(gz);
    for (name, content) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, name, *content)
            .expect("append");
    }
    tar.into_inner().expect("tar").finish().expect("gzip");
    path.to_path_buf()
}

/// A stored `.zip` of (path, content), which needs no compression library.
#[allow(dead_code)]
pub fn zip(path: &Path, entries: &[(&str, &[u8])]) -> PathBuf {
    let mut out: Vec<u8> = Vec::new();
    let mut central: Vec<u8> = Vec::new();
    for (name, content) in entries {
        let crc = crc32(content);
        let offset = out.len() as u32;
        let size = content.len() as u32;
        let common = |buf: &mut Vec<u8>| {
            buf.extend_from_slice(&20u16.to_le_bytes()); // version needed
            buf.extend_from_slice(&0u16.to_le_bytes()); // flags
            buf.extend_from_slice(&0u16.to_le_bytes()); // stored
            buf.extend_from_slice(&0u16.to_le_bytes()); // time
            buf.extend_from_slice(&0x21u16.to_le_bytes()); // date
            buf.extend_from_slice(&crc.to_le_bytes());
            buf.extend_from_slice(&size.to_le_bytes());
            buf.extend_from_slice(&size.to_le_bytes());
            buf.extend_from_slice(&(name.len() as u16).to_le_bytes());
            buf.extend_from_slice(&0u16.to_le_bytes()); // extra
        };
        out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        common(&mut out);
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(content);
        central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes()); // version made by
        common(&mut central);
        central.extend_from_slice(&[0u8; 10]); // comment, disk, attributes
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name.as_bytes());
    }
    let central_at = out.len() as u32;
    out.extend_from_slice(&central);
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&[0u8; 4]);
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(central.len() as u32).to_le_bytes());
    out.extend_from_slice(&central_at.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    let mut file = std::fs::File::create(path).expect("create zip");
    file.write_all(&out).expect("write zip");
    path.to_path_buf()
}

#[allow(dead_code)]
fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

pub fn crate_file(dir: &Path, name: &str, version: &str, extra_manifest: &str) -> PathBuf {
    let manifest = format!(
        "[package]\nname = \"{name}\"\nversion = \"{version}\"\nlicense = \"MIT\"\n{extra_manifest}"
    );
    tar_gz(
        &dir.join(format!("{name}-{version}.crate")),
        &[
            (&format!("{name}-{version}/Cargo.toml"), manifest.as_bytes()),
            (&format!("{name}-{version}/src/lib.rs"), b"// empty\n"),
        ],
    )
}

pub fn npm_tarball(dir: &Path, name: &str, version: &str) -> PathBuf {
    let manifest = format!("{{\"name\":\"{name}\",\"version\":\"{version}\"}}");
    let short = name.rsplit('/').next().unwrap_or(name);
    tar_gz(
        &dir.join(format!("{short}-{version}.tgz")),
        &[
            ("package/package.json", manifest.as_bytes()),
            ("package/index.js", b"module.exports = 1\n"),
        ],
    )
}

#[allow(dead_code)]
pub fn helm_chart(dir: &Path, name: &str, version: &str) -> PathBuf {
    let chart = format!("apiVersion: v2\nname: {name}\nversion: {version}\n");
    tar_gz(
        &dir.join(format!("{name}-{version}.tgz")),
        &[(&format!("{name}/Chart.yaml"), chart.as_bytes())],
    )
}

#[allow(dead_code)]
pub fn sdist(dir: &Path, name: &str, version: &str) -> PathBuf {
    let info = format!("Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n");
    tar_gz(
        &dir.join(format!("{name}-{version}.tar.gz")),
        &[(&format!("{name}-{version}/PKG-INFO"), info.as_bytes())],
    )
}

#[allow(dead_code)]
pub fn nupkg(dir: &Path, id: &str, version: &str) -> PathBuf {
    let nuspec = format!(
        "<?xml version=\"1.0\"?><package><metadata><id>{id}</id><version>{version}</version>\
         <authors>a</authors><description>d</description></metadata></package>"
    );
    zip(
        &dir.join(format!("{id}.{version}.nupkg")),
        &[(&format!("{id}.nuspec"), nuspec.as_bytes())],
    )
}
