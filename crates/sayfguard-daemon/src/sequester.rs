//! Pre-write sequestration: copy-before-mutate for guarded paths.
//!
//! This is the module that actually satisfies "sequestered securely and
//! retrievable prior to any overwrite or edit" -- see ADR-001 for why this
//! must be a synchronous, lease-gated copy-before-mutate operation rather
//! than an asynchronous reaction to a filesystem watch event.
//!
//! Deliberately does NOT reuse kaptaind's `CaptureAction::Quarantine` name or
//! shape: that action only labels a file to exclude it from a git commit and
//! copies no bytes. Sequestration here always produces a retrievable,
//! encrypted, hash-identified copy. It also deliberately does not reuse
//! kaptaind's `EvidenceRecord` type name (`src/evidence.rs`), which means
//! release/supply-chain provenance in that project; the record type here is
//! `SequesteredArtifact` to avoid the collision.
//!
//! Phase 1 (see the technical directive's deployment-phasing table): invokes
//! an external backup engine -- `scripts/harvester-backup.py` for Combine
//! Harvester, or an equivalent already-verified engine for another protected
//! system -- rather than reimplementing encryption and integrity
//! verification here. `SequesterConfig` only assumes that engine accepts a
//! `backup --registry <path> --objects <path> [--chronology <path>]
//! --output <path> --passphrase-file <path>` invocation and writes a single
//! archive file to `--output`; nothing here is Combine-Harvester-specific
//! beyond that CLI shape.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

/// Everything `sequester` needs to produce one sequestered copy. Deliberately
/// flat rather than reading from a config file: Phase 1 is CLI-driven, and
/// every field here maps directly to a `sayfguard acquire` flag.
#[derive(Debug, Clone)]
pub struct SequesterConfig {
    /// Interpreter to run the backup engine with (e.g. `python3`).
    pub python: PathBuf,
    /// Path to the backup engine script (e.g. Combine Harvester's
    /// `scripts/harvester-backup.py`).
    pub backup_script: PathBuf,
    pub registry_path: PathBuf,
    pub objects_root: PathBuf,
    pub chronology_path: Option<PathBuf>,
    /// Directory sequestered archives and manifests are written into.
    pub sequester_root: PathBuf,
    pub passphrase_file: PathBuf,
    /// The guarded resource's name, used only to make archive filenames
    /// legible; not interpreted otherwise.
    pub resource: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SequesteredArtifact {
    /// SHA-256 of the encrypted archive itself, not of the plaintext source
    /// -- this is what "hash-identified" refers to in ADR-001: proof this
    /// exact archive was produced and hasn't been altered since, checkable
    /// without ever decrypting it.
    pub sha256: String,
    pub sequestered_at: u64,
    pub source_path: PathBuf,
    pub archive_path: PathBuf,
    pub manifest_path: PathBuf,
    /// Set when the owning case/task is marked complete; see ADR-002.
    /// Always `false` at sequestration time -- only `retention.rs` (Phase 2)
    /// updates it.
    pub task_complete: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum SequesterError {
    #[error("failed to launch backup engine {0}: {1}")]
    Spawn(PathBuf, #[source] std::io::Error),
    #[error("backup engine exited with {status}: {stderr}")]
    BackupFailed {
        status: std::process::ExitStatus,
        stderr: String,
    },
    #[error("backup engine reported success but did not write an archive to {0}")]
    ArchiveMissing(PathBuf),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to write sequestration manifest: {0}")]
    ManifestSerialize(#[from] serde_json::Error),
}

/// Synchronous copy-before-mutate. Called from `lease::LeaseStore::acquire`
/// before a lease is ever handed back to the caller (ADR-001) -- if this
/// returns `Err`, no lease is granted and the caller's mutation must not
/// proceed.
pub fn sequester(config: &SequesterConfig) -> Result<SequesteredArtifact, SequesterError> {
    fs::create_dir_all(&config.sequester_root)?;
    let now = now_unix();
    let archive_path = config
        .sequester_root
        .join(format!("{}-{now}.tar.gpg", sanitize(&config.resource)));

    let mut cmd = Command::new(&config.python);
    cmd.arg(&config.backup_script)
        .arg("backup")
        .arg("--registry")
        .arg(&config.registry_path)
        .arg("--objects")
        .arg(&config.objects_root)
        .arg("--output")
        .arg(&archive_path)
        .arg("--passphrase-file")
        .arg(&config.passphrase_file);
    if let Some(chronology) = &config.chronology_path {
        cmd.arg("--chronology").arg(chronology);
    }

    let output = cmd
        .output()
        .map_err(|e| SequesterError::Spawn(config.backup_script.clone(), e))?;
    if !output.status.success() {
        return Err(SequesterError::BackupFailed {
            status: output.status,
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }
    if !archive_path.is_file() {
        return Err(SequesterError::ArchiveMissing(archive_path));
    }

    let sha256 = hash_file(&archive_path)?;
    let manifest_path = archive_path.with_extension("manifest.json");
    let artifact = SequesteredArtifact {
        sha256,
        sequestered_at: now,
        source_path: config.registry_path.clone(),
        archive_path: archive_path.clone(),
        manifest_path: manifest_path.clone(),
        task_complete: false,
    };
    fs::write(&manifest_path, serde_json::to_string_pretty(&artifact)?)?;
    Ok(artifact)
}

fn hash_file(path: &Path) -> Result<String, std::io::Error> {
    let bytes = fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(hex::encode(hasher.finalize()))
}

fn sanitize(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect()
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    /// Writes a fake backup engine mimicking harvester-backup.py's CLI
    /// contract closely enough for these tests: it accepts the same flags
    /// and writes `payload` bytes to `--output`, without touching GPG or a
    /// real registry. Keeps sayfguard's own test suite independent of
    /// Combine Harvester's repo and of `gpg` being installed.
    fn write_fake_backup_engine(dir: &Path, payload: &[u8], exit_code: i32) -> PathBuf {
        let script_path = dir.join("fake-backup.py");
        let payload_hex: String = payload.iter().map(|b| format!("\\x{b:02x}")).collect();
        let script = format!(
            "#!/usr/bin/env python3\n\
             import sys\n\
             args = sys.argv[1:]\n\
             if args[0] != 'backup':\n\
             \traise SystemExit('unexpected command')\n\
             output = args[args.index('--output') + 1]\n\
             with open(output, 'wb') as f:\n\
             \tf.write(b'{payload_hex}')\n\
             sys.exit({exit_code})\n"
        );
        fs::write(&script_path, script).unwrap();
        let mut perms = fs::metadata(&script_path).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&script_path, perms).unwrap();
        script_path
    }

    fn base_config(temp: &TempDir, backup_script: PathBuf) -> SequesterConfig {
        SequesterConfig {
            python: PathBuf::from("python3"),
            backup_script,
            registry_path: temp.path().join("registry.db"),
            objects_root: temp.path().join("objects"),
            chronology_path: None,
            sequester_root: temp.path().join("sequester"),
            passphrase_file: temp.path().join("passphrase.txt"),
            resource: "case-AC".to_string(),
        }
    }

    #[test]
    fn sequesters_the_archive_the_backup_engine_produces() {
        let temp = TempDir::new().unwrap();
        let script = write_fake_backup_engine(temp.path(), b"encrypted-archive-bytes", 0);
        let config = base_config(&temp, script);

        let artifact = sequester(&config).unwrap();

        assert!(artifact.archive_path.is_file());
        assert_eq!(fs::read(&artifact.archive_path).unwrap(), b"encrypted-archive-bytes");
        assert!(artifact.manifest_path.is_file());
        assert!(!artifact.task_complete);
    }

    #[test]
    fn artifact_hash_matches_the_archive_bytes() {
        let temp = TempDir::new().unwrap();
        let script = write_fake_backup_engine(temp.path(), b"some archive content", 0);
        let config = base_config(&temp, script);

        let artifact = sequester(&config).unwrap();

        let mut hasher = Sha256::new();
        hasher.update(b"some archive content");
        assert_eq!(artifact.sha256, hex::encode(hasher.finalize()));
    }

    #[test]
    fn manifest_on_disk_matches_the_returned_artifact() {
        let temp = TempDir::new().unwrap();
        let script = write_fake_backup_engine(temp.path(), b"payload", 0);
        let config = base_config(&temp, script);

        let artifact = sequester(&config).unwrap();

        let manifest_raw = fs::read_to_string(&artifact.manifest_path).unwrap();
        let manifest: SequesteredArtifact = serde_json::from_str(&manifest_raw).unwrap();
        assert_eq!(manifest.sha256, artifact.sha256);
    }

    #[test]
    fn rejects_when_backup_engine_exits_nonzero() {
        let temp = TempDir::new().unwrap();
        let script = write_fake_backup_engine(temp.path(), b"unused", 1);
        let config = base_config(&temp, script);

        let error = sequester(&config).unwrap_err();
        assert!(matches!(error, SequesterError::BackupFailed { .. }));
    }

    #[test]
    fn rejects_when_the_interpreter_does_not_exist() {
        let temp = TempDir::new().unwrap();
        let mut config = base_config(&temp, temp.path().join("does-not-exist.py"));
        config.python = PathBuf::from("no-such-interpreter-binary");

        let error = sequester(&config).unwrap_err();
        assert!(matches!(error, SequesterError::Spawn(_, _)));
    }

    #[test]
    fn rejects_when_backup_engine_reports_success_but_writes_no_archive() {
        let temp = TempDir::new().unwrap();
        let script_path = temp.path().join("silent-success.py");
        fs::write(&script_path, "#!/usr/bin/env python3\nimport sys\nsys.exit(0)\n").unwrap();
        let mut perms = fs::metadata(&script_path).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&script_path, perms).unwrap();
        let config = base_config(&temp, script_path);

        let error = sequester(&config).unwrap_err();
        assert!(matches!(error, SequesterError::ArchiveMissing(_)));
    }
}
