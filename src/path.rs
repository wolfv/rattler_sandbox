//! Path types used by the sandbox.
//!
//! Derived from `codex-rs/utils/absolute-path/`. Trimmed: dropped `schemars` /
//! `ts_rs` derives, dropped `~` home-directory expansion, dropped the
//! `AbsolutePathBufGuard` serde plumbing (callers always provide absolute
//! paths in practice).

use std::borrow::Cow;
use std::path::{Component, Path, PathBuf};

mod absolutize {
    // Adapted from path-absolutize 3.1.1:
    // Copyright (c) 2018 magiclen.org (Ron Li). MIT.
    use std::path::{Component, Path, PathBuf};

    pub(super) fn absolutize(path: &Path) -> std::io::Result<PathBuf> {
        if path.is_absolute() {
            return Ok(normalize_path(path));
        }
        Ok(absolutize_from(path, &std::env::current_dir()?))
    }

    pub(super) fn absolutize_from(path: &Path, base_path: &Path) -> PathBuf {
        normalize_path(&path_with_base(path, base_path))
    }

    fn normalize_path(path: &Path) -> PathBuf {
        let mut normalized = PathBuf::new();
        for component in path.components() {
            match component {
                Component::CurDir => {}
                Component::ParentDir => {
                    normalized.pop();
                }
                Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                    normalized.push(component.as_os_str());
                }
            }
        }
        if normalized.as_os_str().is_empty() {
            PathBuf::from(".")
        } else {
            normalized
        }
    }

    #[cfg(not(windows))]
    fn path_with_base(path: &Path, base_path: &Path) -> PathBuf {
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            base_path.join(path)
        }
    }

    #[cfg(windows)]
    fn path_with_base(path: &Path, base_path: &Path) -> PathBuf {
        if path.is_absolute() || path.has_root() {
            return base_path.join(path);
        }
        let mut components = path.components();
        let Some(Component::Prefix(prefix)) = components.next() else {
            return base_path.join(path);
        };
        let mut path = PathBuf::new();
        path.push(prefix.as_os_str());
        if components.clone().next().is_none() {
            path.push(std::path::MAIN_SEPARATOR_STR);
            return path;
        }
        let skip_base_prefix =
            matches!(base_path.components().next(), Some(Component::Prefix(_)));
        for component in base_path
            .components()
            .skip(usize::from(skip_base_prefix))
            .chain(components)
        {
            path.push(component.as_os_str());
        }
        path
    }
}

/// A path that is guaranteed to be absolute and normalized (though not
/// necessarily canonicalized or existing on disk).
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde::Serialize,
    serde::Deserialize,
)]
#[serde(transparent)]
pub struct AbsolutePathBuf(PathBuf);

impl AbsolutePathBuf {
    pub fn from_absolute_path<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        let normalized = normalize_path_for_platform(path.as_ref());
        Ok(Self(absolutize::absolutize(normalized.as_ref())?))
    }

    pub fn from_absolute_path_checked<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        let normalized = normalize_path_for_platform(path.as_ref());
        if !normalized.is_absolute() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("path is not absolute: {}", path.as_ref().display()),
            ));
        }
        Ok(Self(absolutize::absolutize_from(
            normalized.as_ref(),
            Path::new("/"),
        )))
    }

    pub fn resolve_path_against_base<P: AsRef<Path>, B: AsRef<Path>>(
        path: P,
        base_path: B,
    ) -> Self {
        let path = normalize_path_for_platform(path.as_ref());
        let base = normalize_path_for_platform(base_path.as_ref());
        Self(absolutize::absolutize_from(path.as_ref(), base.as_ref()))
    }

    pub fn current_dir() -> std::io::Result<Self> {
        Self::from_absolute_path(std::env::current_dir()?)
    }

    pub fn relative_to_current_dir<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        Ok(Self::resolve_path_against_base(path, std::env::current_dir()?))
    }

    pub fn join<P: AsRef<Path>>(&self, path: P) -> Self {
        Self::resolve_path_against_base(path, &self.0)
    }

    pub fn canonicalize(&self) -> std::io::Result<Self> {
        dunce::canonicalize(&self.0).map(Self)
    }

    pub fn parent(&self) -> Option<Self> {
        self.0.parent().map(|p| Self(p.to_path_buf()))
    }

    pub fn ancestors(&self) -> impl Iterator<Item = Self> + '_ {
        self.0.ancestors().map(|p| Self(p.to_path_buf()))
    }

    pub fn as_path(&self) -> &Path {
        &self.0
    }

    pub fn into_path_buf(self) -> PathBuf {
        self.0
    }

    pub fn to_path_buf(&self) -> PathBuf {
        self.0.clone()
    }

    pub fn to_string_lossy(&self) -> Cow<'_, str> {
        self.0.to_string_lossy()
    }

    pub fn display(&self) -> std::path::Display<'_> {
        self.0.display()
    }
}

impl AsRef<Path> for AbsolutePathBuf {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl std::ops::Deref for AbsolutePathBuf {
    type Target = Path;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<AbsolutePathBuf> for PathBuf {
    fn from(p: AbsolutePathBuf) -> Self {
        p.into_path_buf()
    }
}

impl TryFrom<&Path> for AbsolutePathBuf {
    type Error = std::io::Error;
    fn try_from(value: &Path) -> Result<Self, Self::Error> {
        Self::from_absolute_path_checked(value)
    }
}

impl TryFrom<PathBuf> for AbsolutePathBuf {
    type Error = std::io::Error;
    fn try_from(value: PathBuf) -> Result<Self, Self::Error> {
        Self::from_absolute_path_checked(&value)
    }
}

impl TryFrom<&str> for AbsolutePathBuf {
    type Error = std::io::Error;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::from_absolute_path_checked(Path::new(value))
    }
}

impl TryFrom<&PathBuf> for AbsolutePathBuf {
    type Error = std::io::Error;
    fn try_from(value: &PathBuf) -> Result<Self, Self::Error> {
        Self::from_absolute_path_checked(value)
    }
}

fn normalize_path_for_platform(path: &Path) -> Cow<'_, Path> {
    if cfg!(windows)
        && let Some(s) = path.to_str()
        && let Some(normalized) = normalize_windows_device_path(s)
    {
        return Cow::Owned(PathBuf::from(normalized));
    }
    Cow::Borrowed(path)
}

fn normalize_windows_device_path(path: &str) -> Option<String> {
    if let Some(unc) = path.strip_prefix(r"\\?\UNC\") {
        return Some(format!(r"\\{unc}"));
    }
    if let Some(unc) = path.strip_prefix(r"\\.\UNC\") {
        return Some(format!(r"\\{unc}"));
    }
    if let Some(p) = path.strip_prefix(r"\\?\")
        && is_windows_drive_absolute_path(p)
    {
        return Some(p.to_string());
    }
    if let Some(p) = path.strip_prefix(r"\\.\")
        && is_windows_drive_absolute_path(p)
    {
        return Some(p.to_string());
    }
    None
}

fn is_windows_drive_absolute_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'\\' | b'/')
}

/// Canonicalize a path when possible, but preserve the logical absolute path
/// whenever canonicalization would rewrite it through a nested symlink. Top-
/// level system aliases such as macOS `/var -> /private/var` still resolve
/// through canonicalization.
pub fn canonicalize_preserving_symlinks(path: &Path) -> std::io::Result<PathBuf> {
    let logical = AbsolutePathBuf::from_absolute_path(path)?.into_path_buf();
    let preserve = should_preserve_logical_path(&logical);
    match dunce::canonicalize(path) {
        Ok(canonical) if preserve && canonical != logical => Ok(logical),
        Ok(canonical) => Ok(canonical),
        Err(_) => Ok(logical),
    }
}

pub fn canonicalize_existing_preserving_symlinks(path: &Path) -> std::io::Result<PathBuf> {
    let logical = AbsolutePathBuf::from_absolute_path(path)?.into_path_buf();
    let canonical = dunce::canonicalize(path)?;
    if should_preserve_logical_path(&logical) && canonical != logical {
        Ok(logical)
    } else {
        Ok(canonical)
    }
}

fn should_preserve_logical_path(logical: &Path) -> bool {
    logical.ancestors().any(|ancestor| {
        let Ok(metadata) = std::fs::symlink_metadata(ancestor) else {
            return false;
        };
        metadata.file_type().is_symlink() && ancestor.parent().and_then(Path::parent).is_some()
    })
}

/// Helpers for constructing absolute paths in tests.
pub mod test_support {
    use super::AbsolutePathBuf;
    use std::path::{Path, PathBuf};

    pub fn test_path_buf(unix_path: &str) -> PathBuf {
        if cfg!(windows) {
            let mut path = PathBuf::from(r"C:\");
            path.extend(
                unix_path
                    .trim_start_matches('/')
                    .split('/')
                    .filter(|segment| !segment.is_empty())
                    .map(Path::new),
            );
            path
        } else {
            PathBuf::from(unix_path)
        }
    }

    pub fn test_absolute(unix_path: &str) -> AbsolutePathBuf {
        AbsolutePathBuf::from_absolute_path_checked(test_path_buf(unix_path))
            .expect("test path is absolute")
    }
}

// Silence warnings about unused Component import on platforms where the
// re-export above isn't currently exercised.
#[allow(dead_code)]
const _UNUSED: Option<Component<'_>> = None;
