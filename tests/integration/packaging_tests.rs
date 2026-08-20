//! Packaging guards for the files the `.deb` / `.rpm` install alongside the
//! binary.
//!
//! The asset lists in `Cargo.toml` are hand-maintained, so a file added under
//! `dist/` or `etc/` only ships if someone remembers to list it — twice, once
//! per package format. Nobody did for `etc/logrotate.d/siphon`: it sat in the
//! tree rotating `/var/log/siphon.log`, a path the sandboxed unit cannot write,
//! while being installed by no package at all. These tests fail the next time
//! the tree and the asset lists drift apart.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(relative: &str) -> String {
    std::fs::read_to_string(repo_root().join(relative))
        .unwrap_or_else(|error| panic!("cannot read {relative}: {error}"))
}

/// Text of the `[package.metadata.deb]` and `[package.metadata.generate-rpm]`
/// asset declarations.
fn package_asset_sections() -> (String, String) {
    let manifest = read("Cargo.toml");
    let deb_start = manifest
        .find("[package.metadata.deb]")
        .expect("Cargo.toml has no [package.metadata.deb]");
    let rpm_start = manifest
        .find("[package.metadata.generate-rpm]")
        .expect("Cargo.toml has no [package.metadata.generate-rpm]");
    let rpm_end = manifest
        .find("[package.metadata.generate-rpm.requires]")
        .expect("Cargo.toml has no [package.metadata.generate-rpm.requires]");

    (
        manifest[deb_start..rpm_start].to_string(),
        manifest[rpm_start..rpm_end].to_string(),
    )
}

/// Every packaged support file in the tree, relative to the repo root.
/// `dist/debian/` is excluded: cargo-deb picks those up through
/// `maintainer-scripts`, not through `assets`.
fn packaged_support_files() -> Vec<String> {
    fn walk(directory: &Path, root: &Path, found: &mut Vec<String>) {
        let entries = std::fs::read_dir(directory)
            .unwrap_or_else(|error| panic!("cannot list {}: {error}", directory.display()));
        for entry in entries {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(&path, root, found);
            } else if let Ok(relative) = path.strip_prefix(root) {
                found.push(relative.to_string_lossy().into_owned());
            }
        }
    }

    let root = repo_root();
    let mut found = Vec::new();
    walk(&root.join("dist"), &root, &mut found);
    walk(&root.join("etc"), &root, &mut found);
    found.retain(|path| !path.starts_with("dist/debian/"));
    found.sort();
    found
}

#[test]
fn every_support_file_ships_in_both_packages() {
    let (deb, rpm) = package_asset_sections();
    let files = packaged_support_files();
    assert!(
        files.contains(&"etc/logrotate.d/siphon".to_string()),
        "the walk found no logrotate config — did the tree move? found: {files:?}"
    );

    for file in files {
        // Match the asset entry itself, not any mention of the path: the deb
        // section also lists `/etc/logrotate.d/siphon` under `conf-files`, and
        // a conffile declaration for a file the package never installs is
        // exactly the drift this test exists to catch.
        assert!(
            deb.contains(&format!("[\"{file}\",")),
            "{file} is in the tree but not in the .deb assets in Cargo.toml"
        );
        assert!(
            rpm.contains(&format!("source = \"{file}\"")),
            "{file} is in the tree but not in the .rpm assets in Cargo.toml"
        );
    }
}

/// The release tarball is assembled by hand in the workflow, so it drifts the
/// same way the asset lists do.
#[test]
fn every_support_file_ships_in_the_release_tarball() {
    let workflow = read(".github/workflows/release.yaml");
    for file in packaged_support_files() {
        assert!(
            workflow.contains(&file),
            "{file} is in the tree but not in the release tarball built by release.yaml"
        );
    }
}

/// The sandboxed unit makes exactly one log directory writable. Rotation has
/// to name that directory, or it rotates nothing siphon ever writes.
#[test]
fn logrotate_targets_the_directory_the_unit_makes_writable() {
    let unit = read("dist/siphon.service");
    let logrotate = read("etc/logrotate.d/siphon");

    assert!(
        unit.contains("LogsDirectory=siphon"),
        "the unit no longer declares LogsDirectory=siphon"
    );
    assert!(
        logrotate.contains("/var/log/siphon/"),
        "logrotate does not rotate anything under /var/log/siphon"
    );
    for line in logrotate.lines() {
        let line = line.trim();
        if line.starts_with('/') {
            assert!(
                line.starts_with("/var/log/siphon/"),
                "logrotate rotates {line}, which is outside the only writable log \
                 directory the unit creates (/var/log/siphon)"
            );
        }
    }
}

/// CDRs are billing records: `copytruncate` copies and then truncates, and
/// anything written in between is gone. The CDR backend opens the file per
/// record, so it does not need `copytruncate` and must not get it.
#[test]
fn cdr_rotation_does_not_use_copytruncate() {
    let logrotate = read("etc/logrotate.d/siphon");
    let cdr_stanza = logrotate
        .split("/var/log/siphon/cdr.jsonl")
        .nth(1)
        .expect("logrotate has no cdr.jsonl stanza");
    let cdr_stanza = cdr_stanza
        .split('}')
        .next()
        .expect("cdr.jsonl stanza is not closed");

    assert!(
        !cdr_stanza.contains("copytruncate"),
        "the cdr.jsonl stanza uses copytruncate, which can drop a billing record"
    );
    assert!(
        cdr_stanza.contains("create "),
        "the cdr.jsonl stanza rotates by rename but does not re-create the file"
    );
}
