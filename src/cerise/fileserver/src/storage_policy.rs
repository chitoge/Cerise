//! Pure namespace policy for reconstructible, lazily durable writes.

/// Whether a generic FileServer write may defer the filesystem-wide barrier.
///
/// A successful rename is the publication barrier for every `.tmp` object.
/// The staging and swap namespaces are explicitly reconstructible.  Published
/// immutable releases, VM state, and ordinary user files are never accepted as
/// lazy writes.
pub fn allows_lazy_write(components: &[&str]) -> bool {
    let Some(name) = components.last() else {
        return false;
    };
    (name.ends_with(".tmp")
        && (components.starts_with(&["vm-state", "v1"])
            || components.starts_with(&["vm-events", "v1"])
            || components.starts_with(&["vm-manager"])
            || components.starts_with(&["web-ui", "v1"])))
        // A pool restore is unpublished until the controller verifies the
        // complete closure and atomically publishes the catalog. Its staging
        // files are discarded when the operation aborts.
        || matches!(components, ["vm-restore", "v1", _, "files", ..])
        || components.starts_with(&["web-ui", "v1", "staging"])
        // Boot-scoped spill is explicitly reconstructible and is cleared at
        // every host boot. Per-page device flushes would put an SSD barrier on
        // the VM memory-eviction hot path.
        || components.starts_with(&["vm-swap", "v2"])
}

pub fn allows_web_write(components: &[&str]) -> bool {
    if !components.starts_with(&["web-ui"]) {
        return true;
    }
    matches!(components, ["web-ui", "v1", "active.json.tmp"])
        || matches!(components, ["web-ui", "v1", "staging", name] if valid_staging_name(name))
}

pub fn allows_web_delete(components: &[&str]) -> bool {
    if !components.starts_with(&["web-ui"]) {
        return true;
    }
    matches!(components, ["web-ui", "v1", "active.json.tmp"])
        || matches!(components, ["web-ui", "v1", "staging", name] if valid_staging_name(name))
}

pub fn allows_web_mkdir(components: &[&str]) -> bool {
    if !components.starts_with(&["web-ui"]) {
        return true;
    }
    matches!(
        components,
        ["web-ui"]
            | ["web-ui", "v1"]
            | ["web-ui", "v1", "releases"]
            | ["web-ui", "v1", "releases", "sha256"]
            | ["web-ui", "v1", "staging"]
    )
}

pub fn allows_web_rename(from: &[&str], to: &[&str]) -> bool {
    if !from.starts_with(&["web-ui"]) && !to.starts_with(&["web-ui"]) {
        return true;
    }
    matches!(
        (from, to),
        (
            ["web-ui", "v1", "active.json.tmp"],
            ["web-ui", "v1", "active.json"]
        )
    ) || matches!(
        (from, to),
        (
            ["web-ui", "v1", "staging", staging],
            ["web-ui", "v1", "releases", "sha256", release]
        ) if valid_staging_name(staging) && valid_release_name(release)
    )
}

pub fn is_web_release(components: &[&str]) -> bool {
    matches!(
        components,
        ["web-ui", "v1", "releases", "sha256", release] if valid_release_name(release)
    )
}

pub fn is_web_staging(components: &[&str]) -> bool {
    matches!(components, ["web-ui", "v1", "staging", name] if valid_staging_name(name))
}

fn valid_staging_name(name: &str) -> bool {
    let Some(stem) = name.strip_suffix(".part") else {
        return false;
    };
    stem.len() == 32 && stem.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_release_name(name: &str) -> bool {
    let Some(digest) = name.strip_suffix(".cryoweb") else {
        return false;
    };
    digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn web_staging_and_atomic_pointer_temporary_are_lazy() {
        assert!(allows_lazy_write(&[
            "web-ui", "v1", "staging", "upload.part"
        ]));
        assert!(allows_lazy_write(&[
            "web-ui", "v1", "active.json.tmp"
        ]));
    }

    #[test]
    fn published_web_release_and_active_pointer_are_durable_only() {
        assert!(!allows_lazy_write(&[
            "web-ui",
            "v1",
            "releases",
            "sha256",
            "abc.cryoweb",
        ]));
        assert!(!allows_lazy_write(&["web-ui", "v1", "active.json"]));
    }

    #[test]
    fn staging_prefix_must_be_exact() {
        assert!(!allows_lazy_write(&[
            "web-ui", "v10", "staging", "upload.part"
        ]));
        assert!(!allows_lazy_write(&[
            "unmanaged", "web-ui", "v1", "staging", "upload.part"
        ]));
    }

    #[test]
    fn existing_atomic_and_boot_scoped_namespaces_remain_allowed() {
        assert!(allows_lazy_write(&["vm-state", "v1", "head.tmp"]));
        assert!(allows_lazy_write(&["vm-events", "v1", "events.tmp"]));
        assert!(allows_lazy_write(&["vm-manager", "catalog.tmp"]));
        assert!(allows_lazy_write(&[
            "vm-restore",
            "v1",
            "restore-123",
            "files",
            "vm-manager",
            "catalog.json",
        ]));
        assert!(allows_lazy_write(&["vm-swap", "v2", "boot", "page"]));
        assert!(!allows_lazy_write(&["vm-state", "v1", "head"]));
        assert!(!allows_lazy_write(&[
            "vm-restore",
            "v1",
            "restore-123",
            "published",
            "catalog.json",
        ]));
    }

    #[test]
    fn web_publication_is_the_only_mutating_path() {
        let staging = [
            "web-ui",
            "v1",
            "staging",
            "0123456789abcdef0123456789abcdef.part",
        ];
        let release = [
            "web-ui",
            "v1",
            "releases",
            "sha256",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.cryoweb",
        ];
        assert!(allows_web_write(&staging));
        assert!(allows_web_delete(&staging));
        assert!(allows_web_rename(&staging, &release));
        assert!(is_web_release(&release));
        assert!(!allows_web_write(&release));
        assert!(!allows_web_delete(&release));
        assert!(!allows_web_rename(&release, &staging));
        assert!(allows_web_write(&["web-ui", "v1", "active.json.tmp"]));
        assert!(allows_web_rename(
            &["web-ui", "v1", "active.json.tmp"],
            &["web-ui", "v1", "active.json"],
        ));
        assert!(!allows_web_write(&["web-ui", "v1", "active.json"]));
    }

    #[test]
    fn web_namespace_rejects_lookalikes_and_arbitrary_directories() {
        assert!(!allows_web_write(&[
            "web-ui",
            "v1",
            "staging",
            "../release.part",
        ]));
        assert!(!allows_web_mkdir(&["web-ui", "v1", "arbitrary"]));
        assert!(!is_web_release(&[
            "web-ui",
            "v1",
            "releases",
            "sha256",
            "ABC.cryoweb",
        ]));
        assert!(allows_web_write(&["unrelated", "file"]));
        assert!(allows_web_rename(&["unrelated", "from"], &["unrelated", "to"]));
    }
}
