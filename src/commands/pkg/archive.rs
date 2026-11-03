//! Reading a file out of a package archive, for the formats whose request has to say
//! what's in the package. Nothing here unpacks to disk.

use std::io::Read;
use std::path::Path;

use flate2::read::GzDecoder;
use miette::Result;

use crate::error::AkError;

/// Larger than any manifest. A crafted archive can't make us hold more than this.
const MAX_ENTRY: u64 = 64 * 1024 * 1024;

/// The first entry of a `.tar.gz` whose path `wanted` accepts, with the path it had.
pub fn tar_gz_entry(
    file: &Path,
    wanted: impl Fn(&[&str]) -> bool,
) -> Result<Option<(String, Vec<u8>)>> {
    let bad = |e: std::io::Error| {
        AkError::Usage(format!("{} isn't a readable .tar.gz: {e}", file.display()))
    };
    let opened = std::fs::File::open(file).map_err(bad)?;
    let mut archive = tar::Archive::new(GzDecoder::new(opened));
    for entry in archive.entries().map_err(bad)? {
        let entry = entry.map_err(bad)?;
        let path = entry.path().map_err(bad)?.to_string_lossy().to_string();
        let parts: Vec<&str> = path
            .split('/')
            .filter(|p| !p.is_empty() && *p != ".")
            .collect();
        if wanted(&parts) {
            let mut content = Vec::new();
            entry
                .take(MAX_ENTRY)
                .read_to_end(&mut content)
                .map_err(bad)?;
            return Ok(Some((path, content)));
        }
    }
    Ok(None)
}

/// The same for an entry that has to be there, for a clear error when it isn't.
pub fn require_tar_gz_entry(
    file: &Path,
    what: &str,
    wanted: impl Fn(&[&str]) -> bool,
) -> Result<Vec<u8>> {
    match tar_gz_entry(file, wanted)? {
        Some((_, content)) => Ok(content),
        None => Err(AkError::Usage(format!("{} has no {what}", file.display())).into()),
    }
}
