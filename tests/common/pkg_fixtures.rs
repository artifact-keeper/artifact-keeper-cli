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

/// A `.deb`: an `ar` of a version, a control tarball and a data tarball.
#[allow(dead_code)]
pub fn deb(dir: &Path, name: &str, version: &str) -> PathBuf {
    let control = format!(
        "Package: {name}\nVersion: {version}\nArchitecture: all\nMaintainer: t <t@example.com>\n\
         Description: demo\n"
    );
    let control_tar = dir.join("control.tar.gz");
    tar_gz(&control_tar, &[("./control", control.as_bytes())]);
    let data_tar = dir.join("data.tar.gz");
    tar_gz(&data_tar, &[("./usr/share/demo/value", b"41\n")]);
    let members: [(&str, Vec<u8>); 3] = [
        ("debian-binary", b"2.0\n".to_vec()),
        (
            "control.tar.gz",
            std::fs::read(&control_tar).expect("control"),
        ),
        ("data.tar.gz", std::fs::read(&data_tar).expect("data")),
    ];
    let mut out = b"!<arch>\n".to_vec();
    for (member, content) in members {
        let header = format!(
            "{member:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
            0,
            0,
            0,
            "100644",
            content.len()
        );
        out.extend_from_slice(header.as_bytes());
        out.extend_from_slice(&content);
        if content.len() % 2 == 1 {
            out.push(b'\n');
        }
    }
    let path = dir.join(format!("{name}_{version}_all.deb"));
    std::fs::write(&path, out).expect("write deb");
    path
}

/// An `.apk`, or a pacman package with `.pkg.tar.gz`: a `.PKGINFO` and one file.
#[allow(dead_code)]
pub fn pkginfo_package(path: &Path, name: &str, version: &str, arch: &str) -> PathBuf {
    let info = format!(
        "pkgname = {name}\npkgver = {version}\npkgdesc = demo\nurl = https://example.com\n\
         arch = {arch}\nsize = 3\nlicense = MIT\n"
    );
    tar_gz(
        path,
        &[
            (".PKGINFO", info.as_bytes()),
            ("usr/share/demo/value", b"41\n"),
        ],
    )
}

/// A plain `.tar` of (path, content), as a Hex package is.
#[allow(dead_code)]
pub fn tar(path: &Path, entries: &[(&str, &[u8])]) -> PathBuf {
    let file = std::fs::File::create(path).expect("create archive");
    let mut tar = tar::Builder::new(file);
    for (name, content) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, name, *content)
            .expect("append");
    }
    tar.finish().expect("tar");
    path.to_path_buf()
}

/// A `.gem`: a tar holding a gzipped gemspec and a data tarball.
#[allow(dead_code)]
pub fn gem(dir: &Path, name: &str, version: &str) -> PathBuf {
    let spec = format!(
        "--- !ruby/object:Gem::Specification\nname: {name}\nversion: !ruby/object:Gem::Version\n  \
         version: {version}\nplatform: ruby\nauthors:\n- t\nsummary: demo\nlicenses:\n- MIT\n\
         dependencies: []\nrequire_paths:\n- lib\n"
    );
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gz.write_all(spec.as_bytes()).expect("gzip");
    let metadata = gz.finish().expect("gzip");
    let data = dir.join("data.tar.gz");
    tar_gz(&data, &[("lib/x.rb", b"\n")]);
    let data = std::fs::read(data).expect("data");
    tar(
        &dir.join(format!("{name}-{version}.gem")),
        &[("metadata.gz", &metadata), ("data.tar.gz", &data)],
    )
}

/// A Hex package: a tar of a version, a checksum, the metadata and the contents.
#[allow(dead_code)]
pub fn hex_package(dir: &Path, name: &str, version: &str) -> PathBuf {
    use sha2::{Digest, Sha256};
    let metadata = format!(
        "{{<<\"name\">>,<<\"{name}\">>}}.\n{{<<\"version\">>,<<\"{version}\">>}}.\n\
         {{<<\"app\">>,<<\"{name}\">>}}.\n"
    );
    let contents_path = dir.join("contents.tar.gz");
    tar_gz(&contents_path, &[("lib/a.ex", b"\n")]);
    let contents = std::fs::read(contents_path).expect("contents");
    let mut hash = Sha256::new();
    hash.update(b"3");
    hash.update(metadata.as_bytes());
    hash.update(&contents);
    let checksum = hex::encode_upper(hash.finalize());
    tar(
        &dir.join(format!("{name}-{version}.tar")),
        &[
            ("VERSION", b"3"),
            ("CHECKSUM", checksum.as_bytes()),
            ("metadata.config", metadata.as_bytes()),
            ("contents.tar.gz", &contents),
        ],
    )
}
