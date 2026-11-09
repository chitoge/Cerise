//! Pure policy for update staging: operation state and cross-device selection.
//!
//! This module performs no I/O and has no FIDL dependency, so the two decisions
//! which gate destructive work are host-testable: which operation may advance,
//! and which exact GPT disk/ESP may receive the image.

use esp_locate::EspIdentity;
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::io::{Read, Seek};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateSource {
    pub base_url: String,
    pub socket_addr: String,
    pub manifest_path: String,
    pub image_path: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceError {
    BadBaseUrl,
    BadHost,
    BadPort,
    BadPath,
}

impl std::fmt::Display for SourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let detail = match self {
            SourceError::BadBaseUrl => "base URL must be bounded http://<IPv4>:<port>",
            SourceError::BadHost => "source host must be an IPv4 literal",
            SourceError::BadPort => "source port must be in 1..=65535",
            SourceError::BadPath => "source path must be a bounded absolute path",
        };
        f.write_str(detail)
    }
}

fn checked_path(path: Option<&str>, default: &str) -> Result<String, SourceError> {
    let path = path.unwrap_or(default);
    if path.is_empty()
        || path.len() > 256
        || !path.starts_with('/')
        || path.starts_with("//")
        || path.contains("..")
        || path.chars().any(|c| matches!(c, '?' | '#' | '\\'))
        || !path.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(SourceError::BadPath);
    }
    Ok(path.to_owned())
}

/// Parse the deliberately small source grammar used by the on-device HTTP client.
///
/// There is no redirect handling and no DNS/userinfo/path in the authority. This
/// keeps the caller-selected network destination explicit and prevents an input
/// from smuggling another request target into the HTTP request line.
pub fn parse_update_source(
    base_url: &str,
    manifest_path: Option<&str>,
    image_path: Option<&str>,
) -> Result<UpdateSource, SourceError> {
    if base_url.len() > 512 {
        return Err(SourceError::BadBaseUrl);
    }
    let authority = base_url
        .strip_prefix("http://")
        .ok_or(SourceError::BadBaseUrl)?;
    let authority = authority.strip_suffix('/').unwrap_or(authority);
    if authority.is_empty()
        || authority
            .chars()
            .any(|c| matches!(c, '/' | '@' | '?' | '#' | '[' | ']'))
        || authority.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return Err(SourceError::BadBaseUrl);
    }
    let (host, port) = authority.rsplit_once(':').ok_or(SourceError::BadPort)?;
    let host: std::net::Ipv4Addr = host.parse().map_err(|_| SourceError::BadHost)?;
    let port: u16 = port.parse().map_err(|_| SourceError::BadPort)?;
    if port == 0 {
        return Err(SourceError::BadPort);
    }
    Ok(UpdateSource {
        socket_addr: format!("{host}:{port}"),
        base_url: format!("http://{host}:{port}"),
        manifest_path: checked_path(manifest_path, "/manifest.json")?,
        image_path: checked_path(image_path, "/zbi")?,
    })
}

#[derive(Debug)]
pub enum SlotHashError {
    Empty,
    TooLarge { size: u64, limit: u64 },
    Io(std::io::Error),
    GrewDuringRead,
}

impl std::fmt::Display for SlotHashError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SlotHashError::Empty => f.write_str("active slot file is empty"),
            SlotHashError::TooLarge { size, limit } => {
                write!(
                    f,
                    "active slot is {size} bytes, over the {limit}-byte limit"
                )
            }
            SlotHashError::Io(error) => write!(f, "active-slot read failed: {error}"),
            SlotHashError::GrewDuringRead => {
                f.write_str("active slot grew after its bounded length was measured")
            }
        }
    }
}

impl From<std::io::Error> for SlotHashError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

/// Hash one exact seekable slot file without allocating an image-sized buffer.
///
/// The end seek bounds the amount read before hashing starts. `read_exact` proves
/// the file did not shrink, and the final one-byte read proves it did not grow.
pub fn hash_bounded_slot(
    reader: &mut (impl Read + Seek),
    max_bytes: u64,
) -> Result<(String, u64), SlotHashError> {
    let size = reader.seek(std::io::SeekFrom::End(0))?;
    if size == 0 {
        return Err(SlotHashError::Empty);
    }
    if size > max_bytes {
        return Err(SlotHashError::TooLarge {
            size,
            limit: max_bytes,
        });
    }
    reader.seek(std::io::SeekFrom::Start(0))?;
    let mut remaining = size;
    let mut chunk = [0u8; 64 * 1024];
    let mut hash = Sha256::new();
    while remaining != 0 {
        let want = std::cmp::min(remaining, chunk.len() as u64) as usize;
        reader.read_exact(&mut chunk[..want])?;
        hash.update(&chunk[..want]);
        remaining -= want as u64;
    }
    let mut extra = [0u8; 1];
    if reader.read(&mut extra)? != 0 {
        return Err(SlotHashError::GrewDuringRead);
    }
    let digest = hash.finalize();
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    Ok((encoded, size))
}

/// The 16-byte CABR record shared with the boot shim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Abr {
    pub active: u8,
    pub tries: [u8; 2],
    pub successful: [u8; 2],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AbrError;

impl Abr {
    /// Initial A/B state after migrating a verified legacy `bootx64.zbi`.
    ///
    /// Slot A is an already-successful byte-for-byte copy of the image that
    /// booted this system. Slot B remains absent and unbootable until the first
    /// staged update writes and verifies it.
    pub fn legacy_bootstrap() -> Self {
        Self {
            active: 0,
            tries: [0, 0],
            successful: [1, 0],
        }
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, AbrError> {
        if bytes.len() < 16 || &bytes[0..4] != b"CABR" || bytes[4] != 1 || bytes[5] > 1 {
            return Err(AbrError);
        }
        Ok(Self {
            active: bytes[5],
            tries: [bytes[6], bytes[7]],
            successful: [bytes[8], bytes[9]],
        })
    }

    pub fn to_bytes(self) -> [u8; 16] {
        let mut bytes = [0u8; 16];
        bytes[0..4].copy_from_slice(b"CABR");
        bytes[4] = 1;
        bytes[5] = self.active;
        bytes[6] = self.tries[0];
        bytes[7] = self.tries[1];
        bytes[8] = self.successful[0];
        bytes[9] = self.successful[1];
        bytes
    }

    pub fn inactive_slot(self) -> usize {
        (self.active as usize) ^ 1
    }

    pub fn mark_running_successful(&mut self) -> bool {
        let running = self.active as usize;
        let changed = self.successful[running] == 0;
        self.successful[running] = 1;
        changed
    }

    /// Create the activation record to write only after readback verification.
    ///
    /// Returning a copy keeps the pre-verification record unchanged; callers do
    /// not need to mutate their only in-memory representation before the image is
    /// proven durable.
    pub fn activation_for_inactive(self) -> (usize, Self) {
        let inactive = self.inactive_slot();
        let mut activated = self;
        activated.active = inactive as u8;
        activated.tries[inactive] = 3;
        activated.successful[inactive] = 0;
        (inactive, activated)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Idle,
    Downloading,
    Verified,
    LocatingDevice,
    WritingSlot,
    VerifyingSlot,
    CommittingActivation,
    Staged,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedMeta {
    pub operation_id: String,
    pub version: u32,
    pub sha256: String,
    pub size: u64,
    pub source_base_url: String,
    pub source_manifest_path: String,
    pub source_image_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedMeta {
    pub prepared: PreparedMeta,
    pub block_instance: String,
    pub disk_guid: [u8; 16],
    pub esp_guid: [u8; 16],
    pub slot: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationState {
    pub phase: Phase,
    pub operation_id: String,
    pub detail: String,
    pub prepared: Option<PreparedMeta>,
    pub staged: Option<StagedMeta>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BeginPrepare {
    Started,
    AlreadyPrepared,
    AlreadyStaged,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BeginStage {
    Started(PreparedMeta),
    AlreadyStaged(StagedMeta),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateError {
    InvalidOperationId,
    Busy,
    NotPrepared,
}

impl Default for OperationState {
    fn default() -> Self {
        Self {
            phase: Phase::Idle,
            operation_id: String::new(),
            detail: String::new(),
            prepared: None,
            staged: None,
        }
    }
}

impl OperationState {
    pub fn begin_prepare(&mut self, operation_id: &str) -> Result<BeginPrepare, StateError> {
        if operation_id.is_empty() || operation_id.len() > 128 {
            return Err(StateError::InvalidOperationId);
        }
        if let Some(staged) = &self.staged {
            return if staged.prepared.operation_id == operation_id {
                Ok(BeginPrepare::AlreadyStaged)
            } else {
                Err(StateError::Busy)
            };
        }
        if let Some(prepared) = &self.prepared {
            return if prepared.operation_id == operation_id {
                Ok(BeginPrepare::AlreadyPrepared)
            } else {
                Err(StateError::Busy)
            };
        }
        if matches!(
            self.phase,
            Phase::Downloading
                | Phase::LocatingDevice
                | Phase::WritingSlot
                | Phase::VerifyingSlot
                | Phase::CommittingActivation
        ) {
            return Err(StateError::Busy);
        }
        self.phase = Phase::Downloading;
        self.operation_id = operation_id.to_owned();
        self.detail.clear();
        Ok(BeginPrepare::Started)
    }

    pub fn finish_prepare(&mut self, prepared: PreparedMeta) {
        self.operation_id.clone_from(&prepared.operation_id);
        self.prepared = Some(prepared);
        self.phase = Phase::Verified;
        self.detail = "image signature, version, size and digest verified".to_owned();
    }

    pub fn begin_stage(&mut self, operation_id: &str) -> Result<BeginStage, StateError> {
        if let Some(staged) = &self.staged {
            return if staged.prepared.operation_id == operation_id {
                Ok(BeginStage::AlreadyStaged(staged.clone()))
            } else {
                Err(StateError::NotPrepared)
            };
        }
        let prepared = self.prepared.clone().ok_or(StateError::NotPrepared)?;
        if prepared.operation_id != operation_id {
            return Err(StateError::NotPrepared);
        }
        if matches!(
            self.phase,
            Phase::Downloading
                | Phase::LocatingDevice
                | Phase::WritingSlot
                | Phase::VerifyingSlot
                | Phase::CommittingActivation
        ) {
            return Err(StateError::Busy);
        }
        self.phase = Phase::LocatingDevice;
        self.detail = "surveying every published whole-disk block instance".to_owned();
        Ok(BeginStage::Started(prepared))
    }

    pub fn set_phase(&mut self, phase: Phase, detail: impl Into<String>) {
        self.phase = phase;
        self.detail = detail.into();
    }

    pub fn finish_stage(&mut self, staged: StagedMeta) {
        self.operation_id.clone_from(&staged.prepared.operation_id);
        self.prepared = None;
        self.staged = Some(staged);
        self.phase = Phase::Staged;
        self.detail =
            "inactive slot flushed and readback-verified; activation metadata committed".to_owned();
    }

    /// Record a failed phase. A prepared image remains available, allowing an
    /// idempotent disk-stage retry without downloading again.
    pub fn fail(&mut self, detail: impl Into<String>) {
        self.phase = Phase::Failed;
        self.detail = detail.into();
    }

    pub fn discard_prepared(&mut self, operation_id: &str) -> Result<(), StateError> {
        let prepared = self.prepared.as_ref().ok_or(StateError::NotPrepared)?;
        if prepared.operation_id != operation_id {
            return Err(StateError::NotPrepared);
        }
        if matches!(
            self.phase,
            Phase::Downloading
                | Phase::LocatingDevice
                | Phase::WritingSlot
                | Phase::VerifyingSlot
                | Phase::CommittingActivation
        ) {
            return Err(StateError::Busy);
        }
        self.prepared = None;
        self.phase = Phase::Idle;
        self.operation_id.clear();
        self.detail.clear();
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceEvidence {
    Found(EspIdentity),
    Absent(String),
    Inconclusive(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ExpectedDevice {
    pub disk_guid: Option<[u8; 16]>,
    pub esp_guid: Option<[u8; 16]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectedDevice {
    pub instance: String,
    pub identity: EspIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectError {
    NoInstances,
    NoneFound,
    Ambiguous(Vec<String>),
    ExpectedMismatch(Vec<String>),
    Inconclusive(Vec<(String, String)>),
}

fn matches_expected(identity: &EspIdentity, expected: ExpectedDevice) -> bool {
    expected
        .disk_guid
        .map(|g| identity.disk_guid == g)
        .unwrap_or(true)
        && expected
            .esp_guid
            .map(|g| identity.partition_guid == g)
            .unwrap_or(true)
}

/// Select exactly one boot target across the complete block-device survey.
///
/// With persistent expected GUIDs, unrelated ESPs may coexist. Without them,
/// exactly one ESP must exist and every sibling must be conclusively surveyed.
pub fn select_device(
    survey: &[(String, DeviceEvidence)],
    expected: ExpectedDevice,
) -> Result<SelectedDevice, SelectError> {
    if survey.is_empty() {
        return Err(SelectError::NoInstances);
    }
    let has_expected = expected.disk_guid.is_some() || expected.esp_guid.is_some();
    let mut matches = Vec::new();
    let mut other_esps = Vec::new();
    let mut inconclusive = Vec::new();
    for (instance, evidence) in survey {
        match evidence {
            DeviceEvidence::Found(identity) if matches_expected(identity, expected) => {
                matches.push(SelectedDevice {
                    instance: instance.clone(),
                    identity: *identity,
                });
            }
            DeviceEvidence::Found(_) => other_esps.push(instance.clone()),
            DeviceEvidence::Inconclusive(reason) => {
                inconclusive.push((instance.clone(), reason.clone()));
            }
            DeviceEvidence::Absent(_) => {}
        }
    }
    if matches.len() > 1 {
        return Err(SelectError::Ambiguous(
            matches.into_iter().map(|m| m.instance).collect(),
        ));
    }
    if let Some(selected) = matches.pop() {
        if !has_expected && !inconclusive.is_empty() {
            return Err(SelectError::Inconclusive(inconclusive));
        }
        return Ok(selected);
    }
    if !inconclusive.is_empty() {
        return Err(SelectError::Inconclusive(inconclusive));
    }
    if has_expected && !other_esps.is_empty() {
        return Err(SelectError::ExpectedMismatch(other_esps));
    }
    Err(SelectError::NoneFound)
}

#[cfg(test)]
mod tests {
    use super::*;
    use esp_locate::EspRange;

    fn identity(disk: u8, esp: u8) -> EspIdentity {
        EspIdentity {
            range: EspRange {
                offset: 4096,
                len: 8192,
            },
            disk_guid: [disk; 16],
            partition_guid: [esp; 16],
        }
    }

    #[test]
    fn source_is_explicit_canonical_and_bounded() {
        let source = parse_update_source("http://192.0.2.7:8080/", None, None).unwrap();
        assert_eq!(source.base_url, "http://192.0.2.7:8080");
        assert_eq!(source.socket_addr, "192.0.2.7:8080");
        assert_eq!(source.manifest_path, "/manifest.json");
        assert_eq!(source.image_path, "/zbi");

        assert_eq!(
            parse_update_source("https://192.0.2.7:8080", None, None),
            Err(SourceError::BadBaseUrl)
        );
        assert_eq!(
            parse_update_source("http://host.example:8080", None, None),
            Err(SourceError::BadHost)
        );
        assert_eq!(
            parse_update_source("http://192.0.2.7:0", None, None),
            Err(SourceError::BadPort)
        );
        assert_eq!(
            parse_update_source("http://192.0.2.7:8080", Some("/../manifest"), None),
            Err(SourceError::BadPath)
        );
        assert_eq!(
            parse_update_source("http://192.0.2.7:8080", Some("/x\r\nInjected: y"), None),
            Err(SourceError::BadPath)
        );
    }

    #[test]
    fn active_slot_hash_is_exact_streaming_and_bounded() {
        let bytes = b"the exact active slot bytes";
        let mut reader = std::io::Cursor::new(bytes.as_slice());
        let (digest, size) = hash_bounded_slot(&mut reader, 1024).unwrap();
        assert_eq!(size, bytes.len() as u64);
        assert_eq!(
            digest,
            "4138a08c9fbd9a06800ab5100e9ff5137b605e00f1c6052a63d47bb0c326ba3c"
        );

        let mut empty = std::io::Cursor::new(Vec::<u8>::new());
        assert!(matches!(
            hash_bounded_slot(&mut empty, 1024),
            Err(SlotHashError::Empty)
        ));
        let mut oversized = std::io::Cursor::new(vec![0u8; 17]);
        assert!(matches!(
            hash_bounded_slot(&mut oversized, 16),
            Err(SlotHashError::TooLarge {
                size: 17,
                limit: 16
            })
        ));
    }

    #[test]
    fn activation_is_a_separate_final_record() {
        let original = Abr {
            active: 0,
            tries: [3, 0],
            successful: [1, 1],
        };
        let (slot, activated) = original.activation_for_inactive();
        assert_eq!(slot, 1);
        assert_eq!(
            original.active, 0,
            "pre-verification record remains unchanged"
        );
        assert_eq!(activated.active, 1);
        assert_eq!(activated.tries[1], 3);
        assert_eq!(activated.successful[1], 0);
        assert_eq!(Abr::parse(&activated.to_bytes()), Ok(activated));
    }

    #[test]
    fn legacy_bootstrap_makes_only_verified_slot_a_bootable() {
        let abr = Abr::legacy_bootstrap();
        assert_eq!(abr.active, 0);
        assert_eq!(abr.tries, [0, 0]);
        assert_eq!(abr.successful, [1, 0]);
        assert_eq!(Abr::parse(&abr.to_bytes()), Ok(abr));
    }

    #[test]
    fn prepare_and_stage_are_two_explicit_phases() {
        let mut state = OperationState::default();
        assert_eq!(state.begin_prepare("op-1"), Ok(BeginPrepare::Started));
        assert_eq!(state.phase, Phase::Downloading);
        state.finish_prepare(PreparedMeta {
            operation_id: "op-1".into(),
            version: 2,
            sha256: "ab".repeat(32),
            size: 42,
            source_base_url: "http://192.0.2.1:8080".into(),
            source_manifest_path: "/manifest.json".into(),
            source_image_path: "/zbi".into(),
        });
        assert_eq!(state.phase, Phase::Verified);
        assert_eq!(
            state.begin_prepare("op-1"),
            Ok(BeginPrepare::AlreadyPrepared)
        );
        assert_eq!(state.begin_prepare("op-2"), Err(StateError::Busy));
        assert!(state.begin_stage("op-1").is_ok());
        assert_eq!(state.phase, Phase::LocatingDevice);
    }

    #[test]
    fn a_failed_disk_attempt_retains_the_verified_download_for_retry() {
        let mut state = OperationState::default();
        state.begin_prepare("op").unwrap();
        state.finish_prepare(PreparedMeta {
            operation_id: "op".into(),
            version: 2,
            sha256: "ab".repeat(32),
            size: 42,
            source_base_url: "http://192.0.2.1:8080".into(),
            source_manifest_path: "/manifest.json".into(),
            source_image_path: "/zbi".into(),
        });
        state.begin_stage("op").unwrap();
        state.fail("disk unavailable");
        assert!(state.prepared.is_some());
        assert!(state.begin_stage("op").is_ok());
    }

    #[test]
    fn successful_stage_is_idempotent_for_the_same_operation_only() {
        let prepared = PreparedMeta {
            operation_id: "op".into(),
            version: 2,
            sha256: "ab".repeat(32),
            size: 42,
            source_base_url: "http://192.0.2.1:8080".into(),
            source_manifest_path: "/manifest.json".into(),
            source_image_path: "/zbi".into(),
        };
        let staged = StagedMeta {
            prepared: prepared.clone(),
            block_instance: "opaque".into(),
            disk_guid: [1; 16],
            esp_guid: [2; 16],
            slot: 1,
        };
        let mut state = OperationState::default();
        state.begin_prepare("op").unwrap();
        state.finish_prepare(prepared);
        state.begin_stage("op").unwrap();
        state.finish_stage(staged.clone());

        assert_eq!(
            state.begin_stage("op"),
            Ok(BeginStage::AlreadyStaged(staged))
        );
        assert_eq!(state.begin_prepare("op"), Ok(BeginPrepare::AlreadyStaged));
        assert_eq!(state.begin_prepare("different"), Err(StateError::Busy));
        assert_eq!(state.begin_stage("different"), Err(StateError::NotPrepared));
    }

    #[test]
    fn aggregate_without_expected_identity_requires_one_conclusive_esp() {
        let selected = select_device(
            &[
                ("data".into(), DeviceEvidence::Absent("no ESP".into())),
                ("boot".into(), DeviceEvidence::Found(identity(1, 2))),
            ],
            ExpectedDevice::default(),
        )
        .unwrap();
        assert_eq!(selected.instance, "boot");

        assert!(matches!(
            select_device(
                &[
                    ("boot-a".into(), DeviceEvidence::Found(identity(1, 2))),
                    ("boot-b".into(), DeviceEvidence::Found(identity(3, 4))),
                ],
                ExpectedDevice::default(),
            ),
            Err(SelectError::Ambiguous(_))
        ));
        assert!(matches!(
            select_device(
                &[
                    ("boot".into(), DeviceEvidence::Found(identity(1, 2))),
                    (
                        "unknown".into(),
                        DeviceEvidence::Inconclusive("read failed".into())
                    ),
                ],
                ExpectedDevice::default(),
            ),
            Err(SelectError::Inconclusive(_))
        ));
    }

    #[test]
    fn persistent_identity_selects_the_expected_disk_among_multiple_esps() {
        let selected = select_device(
            &[
                ("other".into(), DeviceEvidence::Found(identity(9, 9))),
                ("boot".into(), DeviceEvidence::Found(identity(1, 2))),
            ],
            ExpectedDevice {
                disk_guid: Some([1; 16]),
                esp_guid: Some([2; 16]),
            },
        )
        .unwrap();
        assert_eq!(selected.instance, "boot");

        assert!(matches!(
            select_device(
                &[("other".into(), DeviceEvidence::Found(identity(9, 9)))],
                ExpectedDevice {
                    disk_guid: Some([1; 16]),
                    esp_guid: Some([2; 16]),
                },
            ),
            Err(SelectError::ExpectedMismatch(_))
        ));
    }
}
