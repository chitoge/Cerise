// Path safety for the Cerise file server: all RPC paths are
// relative to the served root. Absolute paths and any `..` component are rejected
// with INVALID_ARGUMENT so a client can never escape the root. Pure + std-only so it
// is unit-testable on the host (tests/ live-boot-independent).

/// The outcome of validating a client-supplied path.
#[derive(Debug, PartialEq, Eq)]
pub enum PathError {
    /// The path was absolute (started with `/`).
    Absolute,
    /// The path contained a `..` (parent) component.
    ParentTraversal,
}

/// Normalizes a client path into a sequence of safe components relative to the
/// served root. Returns `Err` if the path is absolute or contains any `..`.
///
/// `.` and empty components are dropped (harmless no-ops). The returned vector may
/// be empty (meaning "the root itself"), which callers treat as the root directory.
pub fn sanitize_relative(path: &str) -> Result<Vec<&str>, PathError> {
    if path.starts_with('/') {
        return Err(PathError::Absolute);
    }
    let mut out = Vec::new();
    for component in path.split('/') {
        match component {
            "" | "." => continue,
            ".." => return Err(PathError::ParentTraversal),
            other => out.push(other),
        }
    }
    Ok(out)
}

/// Returns whether mutating `components` could change a controller-owned
/// namespace.
///
/// The empty path is included because a recursive root mutation would contain
/// every protected namespace. Each namespace root is protected as a whole,
/// rather than only today's versioned child, so a generic client cannot rename
/// or replace the parent around the controller.
pub fn intersects_controller_namespace(components: &[&str]) -> bool {
    const CONTROLLER_ROOTS: &[&str] = &[
        "vm-events",
        "vm-images",
        "vm-manager",
        "vm-restore",
        "vm-state",
        "vm-swap",
    ];
    components.is_empty()
        || components
            .first()
            .is_some_and(|component| CONTROLLER_ROOTS.contains(component))
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

/// Returns whether the exact path is a published content address whose owning
/// protocol never replaces or truncates the file bound to that identity.
///
/// This is intentionally narrower than a namespace-prefix check. Temporary
/// publication files, mutable pointers, and restore staging remain ordinary
/// path-following reads even when they are adjacent to immutable objects.
pub fn is_published_content_address(components: &[&str]) -> bool {
    match components {
        ["vm-state", "v1", "objects" | "manifests", digest] => is_lower_sha256(digest),
        ["vm-images", "v1", "objects", "sha256", name] => name
            .strip_suffix(".cryostore")
            .is_some_and(is_lower_sha256),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_relative_path_splits_into_components() {
        assert_eq!(
            sanitize_relative("a/b/c.txt").unwrap(),
            vec!["a", "b", "c.txt"]
        );
    }

    #[test]
    fn empty_and_dot_components_are_dropped() {
        assert_eq!(
            sanitize_relative("./a//b/./c").unwrap(),
            vec!["a", "b", "c"]
        );
        assert!(sanitize_relative("").unwrap().is_empty());
        assert!(sanitize_relative(".").unwrap().is_empty());
    }

    #[test]
    fn absolute_paths_are_rejected() {
        assert_eq!(sanitize_relative("/etc/passwd"), Err(PathError::Absolute));
        assert_eq!(sanitize_relative("/"), Err(PathError::Absolute));
    }

    #[test]
    fn parent_traversal_is_rejected_anywhere() {
        assert_eq!(sanitize_relative(".."), Err(PathError::ParentTraversal));
        assert_eq!(sanitize_relative("a/../b"), Err(PathError::ParentTraversal));
        assert_eq!(sanitize_relative("a/b/.."), Err(PathError::ParentTraversal));
    }

    #[test]
    fn controller_namespaces_and_their_ancestors_are_protected() {
        for path in [
            "",
            "vm-events",
            "vm-events/v1/events",
            "vm-images/v1",
            "vm-manager/catalog.json",
            "vm-restore/v1/restore-1/catalog.json",
            "vm-state/v1/objects",
            "vm-swap/v2/boot",
        ] {
            let components = sanitize_relative(path).unwrap();
            assert!(
                intersects_controller_namespace(&components),
                "{path:?} was not protected"
            );
        }
        for path in ["operator", "images/guest.cryostore", "vm-stateful/file"] {
            let components = sanitize_relative(path).unwrap();
            assert!(
                !intersects_controller_namespace(&components),
                "{path:?} was over-protected"
            );
        }
    }

    #[test]
    fn only_exact_published_content_addresses_are_immutable_reads() {
        let digest = "0123456789abcdef".repeat(4);
        for path in [
            format!("vm-state/v1/objects/{digest}"),
            format!("vm-state/v1/manifests/{digest}"),
            format!("vm-images/v1/objects/sha256/{digest}.cryostore"),
        ] {
            let components = sanitize_relative(&path).unwrap();
            assert!(
                is_published_content_address(&components),
                "{path:?} was not recognized"
            );
        }

        for path in [
            "vm-state/v1/objects".to_owned(),
            format!("vm-state/v1/objects/{digest}.tmp"),
            format!("vm-state/v1/objects/{digest}/extra"),
            format!("vm-state/v1/objects/{}", digest.to_ascii_uppercase()),
            "vm-state/v1/objects/abc".to_owned(),
            format!("vm-state/v1/head/{digest}"),
            format!("vm-restore/v1/restore/files/vm-state/v1/objects/{digest}"),
            format!("vm-images/v1/imports/{digest}.part"),
            format!("vm-images/v1/objects/sha256/{digest}"),
            format!("vm-images/v1/objects/sha256/{digest}.cryostore.tmp"),
            format!("vm-swap/v2/{digest}"),
            format!("ordinary/{digest}"),
        ] {
            let components = sanitize_relative(&path).unwrap();
            assert!(
                !is_published_content_address(&components),
                "{path:?} was over-classified"
            );
        }
    }
}
