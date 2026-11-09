//! Durable, exact-source mutation admission and drain state.
//!
//! This module is deliberately transport-neutral and dormant. It defines the
//! snapshots and ordering primitive that a later storage-backed coordinator
//! can persist; the live gRPC service does not yet activate this protocol. Its
//! authority gate, constructor, and persistence callbacks are module-private
//! until that coordinator owns their task and storage lifetime. Any ambiguous
//! persistence outcome terminally fences the gate until full shutdown/reload.

use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

pub const LEDGER_SCHEMA_VERSION: u16 = 1;
pub const MAX_LEDGER_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_SOURCES: usize = 4096;
/// Exact compaction replay is deliberately bounded. Once full, new
/// compactions fail closed while every retained request remains replayable;
/// resolving that liveness ceiling requires an explicit future schema rule.
pub const MAX_COMPACTION_RECEIPTS: usize = 512;
pub const MAX_PRINCIPAL_ID_BYTES: usize = 128;
pub const MAX_REQUEST_ID_BYTES: usize = 128;
pub const AUTHORITY_DOMAIN_HEX_BYTES: usize = 64;
pub const MAX_SERVER_OWNED_MUTATIONS: usize = 64;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceIdentity {
    pub authority_domain_id: String,
    pub boot_id: u64,
    pub generation: u64,
    pub principal_id: String,
}

impl SourceIdentity {
    pub fn validate(&self) -> Result<(), Error> {
        validate_authority_domain(&self.authority_domain_id)?;
        if self.boot_id == 0 {
            return Err(Error::Invalid("source boot_id must be nonzero".to_owned()));
        }
        if self.generation == 0 {
            return Err(Error::Invalid(
                "source generation must be nonzero".to_owned(),
            ));
        }
        validate_bounded_nonempty(
            &self.principal_id,
            "source principal_id",
            MAX_PRINCIPAL_ID_BYTES,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
pub enum LegacyAdmission {
    Open,
    Sealed { request_id: String },
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
pub enum SourcePhase {
    Open,
    Draining {
        drain_request_id: String,
    },
    Drained {
        drain_request_id: String,
        receipt_sha256: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceEntry {
    pub identity: SourceIdentity,
    pub open_request_id: String,
    pub state: SourcePhase,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompactionRecord {
    pub request_id: String,
    pub closed_through_generation: u64,
    pub committed_revision: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Ledger {
    pub schema_version: u16,
    pub revision: u64,
    pub authority_domain_id: Option<String>,
    /// Unknown source identities at or below this generation are permanently
    /// closed. Explicit lower-generation Open entries are exceptions and stay
    /// retained until their own terminal drain.
    pub closed_generation_floor: u64,
    pub legacy_admission: LegacyAdmission,
    pub compaction_receipts: Vec<CompactionRecord>,
    pub sources: Vec<SourceEntry>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiptPhase {
    Open,
    Draining,
    Drained,
    Retired,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceReceipt {
    pub source: SourceIdentity,
    pub open_request_id: String,
    pub drain_request_id: String,
    pub phase: ReceiptPhase,
    pub receipt_sha256: String,
    pub ledger_revision: u64,
    pub request_id: String,
    pub closed_generation_floor: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompactionReceipt {
    pub request_id: String,
    pub closed_through_generation: u64,
    pub committed_revision: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    Decode(String),
    UnsupportedSchema(u16),
    Invalid(String),
    Conflict(String),
    NotFound(String),
    Closed(String),
    Busy(String),
    Capacity(String),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(message) => {
                write!(formatter, "decoding mutation-source ledger: {message}")
            }
            Self::UnsupportedSchema(version) => {
                write!(
                    formatter,
                    "unsupported mutation-source ledger schema {version}"
                )
            }
            Self::Invalid(message) => formatter.write_str(message),
            Self::Conflict(message) => formatter.write_str(message),
            Self::NotFound(message) => formatter.write_str(message),
            Self::Closed(message) => formatter.write_str(message),
            Self::Busy(message) => formatter.write_str(message),
            Self::Capacity(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for Error {}

impl Default for Ledger {
    fn default() -> Self {
        Self {
            schema_version: LEDGER_SCHEMA_VERSION,
            revision: 0,
            authority_domain_id: None,
            closed_generation_floor: 0,
            legacy_admission: LegacyAdmission::Open,
            compaction_receipts: Vec::new(),
            sources: Vec::new(),
        }
    }
}

impl Ledger {
    pub fn validate(&self) -> Result<(), Error> {
        if self.schema_version != LEDGER_SCHEMA_VERSION {
            return Err(Error::UnsupportedSchema(self.schema_version));
        }
        if self.revision == 0 && self != &Self::default() {
            return Err(Error::Invalid(
                "revision zero is reserved for the empty default ledger".to_owned(),
            ));
        }
        if let Some(domain) = &self.authority_domain_id {
            validate_authority_domain(domain)?;
        } else if self.closed_generation_floor != 0
            || !self.compaction_receipts.is_empty()
            || !self.sources.is_empty()
        {
            return Err(Error::Invalid(
                "an uninitialized mutation-source ledger retains domain state".to_owned(),
            ));
        }
        if self.sources.len() > MAX_SOURCES {
            return Err(Error::Capacity(format!(
                "mutation-source ledger has {} entries; maximum is {MAX_SOURCES}",
                self.sources.len()
            )));
        }
        if let LegacyAdmission::Sealed { request_id } = &self.legacy_admission {
            validate_request_id(request_id)?;
        }
        if self.compaction_receipts.len() > MAX_COMPACTION_RECEIPTS {
            return Err(Error::Capacity(format!(
                "mutation-source ledger has {} compaction receipts; maximum is {MAX_COMPACTION_RECEIPTS}",
                self.compaction_receipts.len()
            )));
        }
        let mut prior_compaction_revision = 0;
        let mut prior_compaction_floor = 0;
        let mut compaction_requests = BTreeMap::new();
        for compaction in &self.compaction_receipts {
            validate_request_id(&compaction.request_id)?;
            if compaction.closed_through_generation > self.closed_generation_floor {
                return Err(Error::Invalid(
                    "compaction receipt exceeds the closed generation floor".to_owned(),
                ));
            }
            if compaction.committed_revision == 0
                || compaction.committed_revision > self.revision
                || compaction.committed_revision <= prior_compaction_revision
            {
                return Err(Error::Invalid(
                    "compaction receipt revisions are invalid or not strictly increasing"
                        .to_owned(),
                ));
            }
            if compaction.closed_through_generation < prior_compaction_floor {
                return Err(Error::Invalid(
                    "compaction receipt floors are not monotone".to_owned(),
                ));
            }
            if compaction_requests
                .insert(&compaction.request_id, compaction.closed_through_generation)
                .is_some()
            {
                return Err(Error::Invalid(
                    "compaction request identity is duplicated".to_owned(),
                ));
            }
            prior_compaction_revision = compaction.committed_revision;
            prior_compaction_floor = compaction.closed_through_generation;
        }
        if self.compaction_receipts.last().is_some_and(|receipt| {
            receipt.closed_through_generation != self.closed_generation_floor
        }) || (self.closed_generation_floor != 0 && self.compaction_receipts.is_empty())
        {
            return Err(Error::Invalid(
                "closed generation floor lacks its exact latest compaction receipt".to_owned(),
            ));
        }

        let mut prior: Option<&SourceIdentity> = None;
        let mut generations = BTreeMap::new();
        for entry in &self.sources {
            entry.identity.validate()?;
            validate_request_id(&entry.open_request_id)?;
            if Some(entry.identity.authority_domain_id.as_str())
                != self.authority_domain_id.as_deref()
            {
                return Err(Error::Invalid(
                    "source identity belongs to a different authority domain".to_owned(),
                ));
            }
            if prior.is_some_and(|previous| previous >= &entry.identity) {
                return Err(Error::Invalid(
                    "mutation-source ledger entries are duplicated or not strictly sorted"
                        .to_owned(),
                ));
            }
            prior = Some(&entry.identity);
            if let Some(other) = generations.insert(entry.identity.generation, &entry.identity) {
                if other != &entry.identity {
                    return Err(Error::Invalid(format!(
                        "source generation {} is bound to more than one identity",
                        entry.identity.generation
                    )));
                }
            }
            match &entry.state {
                SourcePhase::Open => {}
                SourcePhase::Draining { drain_request_id } => {
                    validate_request_id(drain_request_id)?;
                }
                SourcePhase::Drained {
                    drain_request_id,
                    receipt_sha256,
                } => {
                    validate_request_id(drain_request_id)?;
                    let expected = drain_receipt_digest(
                        &entry.identity,
                        &entry.open_request_id,
                        drain_request_id,
                    );
                    if receipt_sha256 != &expected {
                        return Err(Error::Invalid(format!(
                            "drained source generation {} has a noncanonical receipt digest",
                            entry.identity.generation
                        )));
                    }
                }
            }
        }
        Ok(())
    }

    pub fn open_source(
        &mut self,
        identity: SourceIdentity,
        request_id: &str,
    ) -> Result<SourceReceipt, Error> {
        let mut next = self.clone();
        let result = next.open_source_in_place(identity, request_id)?;
        next.validate()?;
        *self = next;
        Ok(result)
    }

    fn open_source_in_place(
        &mut self,
        identity: SourceIdentity,
        request_id: &str,
    ) -> Result<SourceReceipt, Error> {
        identity.validate()?;
        validate_request_id(request_id)?;
        if let Some(existing) = self.sources.iter().find(|entry| entry.identity == identity) {
            if existing.open_request_id != request_id {
                return Err(Error::Conflict(
                    "source identity is already bound to a different open request".to_owned(),
                ));
            }
            return Ok(receipt(existing, self.revision, request_id));
        }
        match &self.authority_domain_id {
            Some(domain) if domain != &identity.authority_domain_id => {
                return Err(Error::Conflict(
                    "source authority domain differs from the initialized ledger".to_owned(),
                ));
            }
            None => self.authority_domain_id = Some(identity.authority_domain_id.clone()),
            Some(_) => {}
        }
        if identity.generation <= self.closed_generation_floor {
            return Ok(retired_receipt(
                &identity,
                request_id,
                self.revision,
                self.closed_generation_floor,
            ));
        }
        if self
            .sources
            .iter()
            .any(|entry| entry.identity.generation == identity.generation)
        {
            return Err(Error::Conflict(format!(
                "source generation {} is already bound to another identity",
                identity.generation
            )));
        }
        if self.sources.len() >= MAX_SOURCES {
            return Err(Error::Capacity(format!(
                "at most {MAX_SOURCES} mutation sources may be retained"
            )));
        }
        self.bump_revision()?;
        self.sources.push(SourceEntry {
            identity: identity.clone(),
            open_request_id: request_id.to_owned(),
            state: SourcePhase::Open,
        });
        self.sources
            .sort_by(|left, right| left.identity.cmp(&right.identity));
        let entry = self
            .sources
            .iter()
            .find(|entry| entry.identity == identity)
            .expect("the source was just inserted");
        Ok(receipt(entry, self.revision, request_id))
    }

    pub fn begin_drain(
        &mut self,
        identity: &SourceIdentity,
        request_id: &str,
    ) -> Result<SourceReceipt, Error> {
        let mut next = self.clone();
        let result = next.begin_drain_in_place(identity, request_id)?;
        next.validate()?;
        *self = next;
        Ok(result)
    }

    fn begin_drain_in_place(
        &mut self,
        identity: &SourceIdentity,
        request_id: &str,
    ) -> Result<SourceReceipt, Error> {
        validate_request_id(request_id)?;
        let index = match self.source_index(identity) {
            Ok(index) => index,
            Err(Error::Closed(_)) => {
                return Ok(retired_receipt(
                    identity,
                    request_id,
                    self.revision,
                    self.closed_generation_floor,
                ));
            }
            Err(error) => return Err(error),
        };
        match self.sources[index].state.clone() {
            SourcePhase::Open => {
                self.bump_revision()?;
                self.sources[index].state = SourcePhase::Draining {
                    drain_request_id: request_id.to_owned(),
                };
            }
            SourcePhase::Draining { drain_request_id }
            | SourcePhase::Drained {
                drain_request_id, ..
            } if drain_request_id == request_id => {}
            SourcePhase::Draining { .. } | SourcePhase::Drained { .. } => {
                return Err(Error::Conflict(
                    "source is already bound to a different drain request".to_owned(),
                ));
            }
        }
        Ok(receipt(&self.sources[index], self.revision, request_id))
    }

    /// Records the terminal state after the caller has drained admitted tasks
    /// and successfully synchronized the backing store.
    pub fn record_drained_after_sync(
        &mut self,
        identity: &SourceIdentity,
        request_id: &str,
    ) -> Result<SourceReceipt, Error> {
        let mut next = self.clone();
        let result = next.record_drained_after_sync_in_place(identity, request_id)?;
        next.validate()?;
        *self = next;
        Ok(result)
    }

    fn record_drained_after_sync_in_place(
        &mut self,
        identity: &SourceIdentity,
        request_id: &str,
    ) -> Result<SourceReceipt, Error> {
        validate_request_id(request_id)?;
        let index = match self.source_index(identity) {
            Ok(index) => index,
            Err(Error::Closed(_)) => {
                return Ok(retired_receipt(
                    identity,
                    request_id,
                    self.revision,
                    self.closed_generation_floor,
                ));
            }
            Err(error) => return Err(error),
        };
        match self.sources[index].state.clone() {
            SourcePhase::Draining { drain_request_id } if drain_request_id == request_id => {
                let digest = drain_receipt_digest(
                    identity,
                    &self.sources[index].open_request_id,
                    request_id,
                );
                self.bump_revision()?;
                self.sources[index].state = SourcePhase::Drained {
                    drain_request_id: request_id.to_owned(),
                    receipt_sha256: digest,
                };
            }
            SourcePhase::Drained {
                drain_request_id, ..
            } if drain_request_id == request_id => {}
            SourcePhase::Open => {
                return Err(Error::Invalid(
                    "source drain was not begun before completion".to_owned(),
                ));
            }
            SourcePhase::Draining { .. } | SourcePhase::Drained { .. } => {
                return Err(Error::Conflict(
                    "source is bound to a different drain request".to_owned(),
                ));
            }
        }
        Ok(receipt(&self.sources[index], self.revision, request_id))
    }

    pub fn query_source(
        &self,
        identity: &SourceIdentity,
        request_id: &str,
    ) -> Result<SourceReceipt, Error> {
        validate_request_id(request_id)?;
        let entry = match self.source_index(identity) {
            Ok(index) => &self.sources[index],
            Err(Error::Closed(_)) => {
                return Ok(retired_receipt(
                    identity,
                    request_id,
                    self.revision,
                    self.closed_generation_floor,
                ));
            }
            Err(error) => return Err(error),
        };
        let matches = entry.open_request_id == request_id
            || match &entry.state {
                SourcePhase::Open => false,
                SourcePhase::Draining { drain_request_id }
                | SourcePhase::Drained {
                    drain_request_id, ..
                } => drain_request_id == request_id,
            };
        if !matches {
            return Err(Error::Conflict(
                "request identity does not match the retained source receipt".to_owned(),
            ));
        }
        Ok(receipt(entry, self.revision, request_id))
    }

    pub fn compact(
        &mut self,
        authority_domain_id: &str,
        closed_through_generation: u64,
        request_id: &str,
    ) -> Result<CompactionReceipt, Error> {
        let mut next = self.clone();
        let result =
            next.compact_in_place(authority_domain_id, closed_through_generation, request_id)?;
        next.validate()?;
        *self = next;
        Ok(result)
    }

    fn compact_in_place(
        &mut self,
        authority_domain_id: &str,
        closed_through_generation: u64,
        request_id: &str,
    ) -> Result<CompactionReceipt, Error> {
        validate_authority_domain(authority_domain_id)?;
        validate_request_id(request_id)?;
        if self.authority_domain_id.as_deref() != Some(authority_domain_id) {
            return Err(Error::Conflict(
                "compaction authority domain differs from the ledger".to_owned(),
            ));
        }
        if let Some(previous) = self
            .compaction_receipts
            .iter()
            .find(|receipt| receipt.request_id == request_id)
        {
            if previous.closed_through_generation == closed_through_generation {
                return Ok(CompactionReceipt {
                    request_id: previous.request_id.clone(),
                    closed_through_generation: previous.closed_through_generation,
                    committed_revision: previous.committed_revision,
                });
            }
            return Err(Error::Conflict(
                "compaction request is already bound to a different generation floor".to_owned(),
            ));
        }
        if closed_through_generation < self.closed_generation_floor {
            return Err(Error::Conflict(
                "closed generation floor cannot move backwards".to_owned(),
            ));
        }
        if self.compaction_receipts.len() >= MAX_COMPACTION_RECEIPTS {
            return Err(Error::Capacity(format!(
                "at most {MAX_COMPACTION_RECEIPTS} exact compaction receipts may be retained"
            )));
        }
        if self.sources.iter().any(|entry| {
            entry.identity.generation <= closed_through_generation
                && matches!(entry.state, SourcePhase::Draining { .. })
        }) {
            return Err(Error::Busy(
                "cannot compact across a source whose drain is incomplete".to_owned(),
            ));
        }
        self.bump_revision()?;
        self.closed_generation_floor = closed_through_generation;
        self.sources.retain(|entry| {
            entry.identity.generation > closed_through_generation
                || !matches!(entry.state, SourcePhase::Drained { .. })
        });
        let receipt = CompactionRecord {
            request_id: request_id.to_owned(),
            closed_through_generation,
            committed_revision: self.revision,
        };
        self.compaction_receipts.push(receipt.clone());
        Ok(CompactionReceipt {
            request_id: receipt.request_id,
            closed_through_generation: receipt.closed_through_generation,
            committed_revision: receipt.committed_revision,
        })
    }

    pub fn seal_legacy(&mut self, request_id: &str) -> Result<(), Error> {
        let mut next = self.clone();
        next.seal_legacy_in_place(request_id)?;
        next.validate()?;
        *self = next;
        Ok(())
    }

    fn seal_legacy_in_place(&mut self, request_id: &str) -> Result<(), Error> {
        validate_request_id(request_id)?;
        match &self.legacy_admission {
            LegacyAdmission::Open => {
                self.legacy_admission = LegacyAdmission::Sealed {
                    request_id: request_id.to_owned(),
                };
                self.bump_revision()
            }
            LegacyAdmission::Sealed {
                request_id: existing,
            } if existing == request_id => Ok(()),
            LegacyAdmission::Sealed { .. } => Err(Error::Conflict(
                "legacy admission was sealed by a different request".to_owned(),
            )),
        }
    }

    pub fn draining_sources(&self) -> Vec<(SourceIdentity, String)> {
        self.sources
            .iter()
            .filter_map(|entry| match &entry.state {
                SourcePhase::Draining { drain_request_id } => {
                    Some((entry.identity.clone(), drain_request_id.clone()))
                }
                SourcePhase::Open | SourcePhase::Drained { .. } => None,
            })
            .collect()
    }

    fn source_index(&self, identity: &SourceIdentity) -> Result<usize, Error> {
        identity.validate()?;
        self.sources
            .binary_search_by(|entry| entry.identity.cmp(identity))
            .map_err(|_| {
                if self.authority_domain_id.as_deref()
                    == Some(identity.authority_domain_id.as_str())
                    && identity.generation <= self.closed_generation_floor
                {
                    Error::Closed(
                        "mutation source is covered by the closed generation floor".to_owned(),
                    )
                } else {
                    Error::NotFound("mutation source is not registered".to_owned())
                }
            })
    }

    fn bump_revision(&mut self) -> Result<(), Error> {
        self.revision = self.revision.checked_add(1).ok_or_else(|| {
            Error::Capacity("mutation-source ledger revision exhausted".to_owned())
        })?;
        Ok(())
    }
}

pub fn encode(ledger: &Ledger) -> Result<Vec<u8>, Error> {
    ledger.validate()?;
    let bytes = serde_json::to_vec(ledger)
        .map_err(|error| Error::Decode(format!("encoding canonical ledger: {error}")))?;
    if bytes.len() > MAX_LEDGER_BYTES {
        return Err(Error::Capacity(format!(
            "encoded mutation-source ledger is {} bytes; maximum is {MAX_LEDGER_BYTES}",
            bytes.len()
        )));
    }
    Ok(bytes)
}

pub fn decode(bytes: &[u8]) -> Result<Ledger, Error> {
    if bytes.is_empty() || bytes.len() > MAX_LEDGER_BYTES {
        return Err(Error::Capacity(format!(
            "mutation-source ledger is {} bytes; valid range is 1..={MAX_LEDGER_BYTES}",
            bytes.len()
        )));
    }
    #[derive(Deserialize)]
    struct Envelope {
        schema_version: u16,
    }
    let envelope: Envelope = serde_json::from_slice(bytes)
        .map_err(|error| Error::Decode(format!("schema envelope: {error}")))?;
    if envelope.schema_version != LEDGER_SCHEMA_VERSION {
        return Err(Error::UnsupportedSchema(envelope.schema_version));
    }
    let ledger: Ledger = serde_json::from_slice(bytes)
        .map_err(|error| Error::Decode(format!("typed body: {error}")))?;
    ledger.validate()?;
    Ok(ledger)
}

fn receipt(entry: &SourceEntry, revision: u64, request_id: &str) -> SourceReceipt {
    let (phase, drain_request_id, receipt_sha256) = match &entry.state {
        SourcePhase::Open => (ReceiptPhase::Open, String::new(), String::new()),
        SourcePhase::Draining { drain_request_id } => (
            ReceiptPhase::Draining,
            drain_request_id.clone(),
            String::new(),
        ),
        SourcePhase::Drained {
            drain_request_id,
            receipt_sha256,
        } => (
            ReceiptPhase::Drained,
            drain_request_id.clone(),
            receipt_sha256.clone(),
        ),
    };
    SourceReceipt {
        source: entry.identity.clone(),
        open_request_id: entry.open_request_id.clone(),
        drain_request_id,
        phase,
        receipt_sha256,
        ledger_revision: revision,
        request_id: request_id.to_owned(),
        closed_generation_floor: 0,
    }
}

fn retired_receipt(
    source: &SourceIdentity,
    request_id: &str,
    revision: u64,
    closed_generation_floor: u64,
) -> SourceReceipt {
    SourceReceipt {
        source: source.clone(),
        open_request_id: String::new(),
        drain_request_id: String::new(),
        phase: ReceiptPhase::Retired,
        receipt_sha256: String::new(),
        ledger_revision: revision,
        request_id: request_id.to_owned(),
        closed_generation_floor,
    }
}

fn drain_receipt_digest(
    identity: &SourceIdentity,
    open_request_id: &str,
    drain_request_id: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"cerise.fileserver.mutation-source-drain.v1\0");
    for value in [
        identity.authority_domain_id.as_bytes(),
        identity.principal_id.as_bytes(),
        open_request_id.as_bytes(),
        drain_request_id.as_bytes(),
    ] {
        hasher.update((value.len() as u64).to_le_bytes());
        hasher.update(value);
    }
    hasher.update(identity.boot_id.to_le_bytes());
    hasher.update(identity.generation.to_le_bytes());
    let digest = hasher.finalize();
    let mut text = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut text, "{byte:02x}").expect("writing to String cannot fail");
    }
    text
}

fn validate_authority_domain(value: &str) -> Result<(), Error> {
    if value.len() != AUTHORITY_DOMAIN_HEX_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(Error::Invalid(
            "authority_domain_id must be exactly 64 lowercase hexadecimal bytes".to_owned(),
        ));
    }
    Ok(())
}

fn validate_request_id(value: &str) -> Result<(), Error> {
    validate_bounded_nonempty(value, "request_id", MAX_REQUEST_ID_BYTES)
}

fn validate_bounded_nonempty(value: &str, name: &str, max: usize) -> Result<(), Error> {
    if value.is_empty() || value.len() > max {
        return Err(Error::Invalid(format!(
            "{name} must contain between 1 and {max} bytes"
        )));
    }
    Ok(())
}

fn validate_successor(current: &Ledger, next: &Ledger) -> Result<(), Error> {
    current.validate()?;
    next.validate()?;
    if current == next {
        return Ok(());
    }
    if next.revision <= current.revision {
        return Err(Error::Conflict(
            "committed ledger revision must advance monotonically".to_owned(),
        ));
    }
    match (&current.authority_domain_id, &next.authority_domain_id) {
        (None, Some(_)) | (None, None) => {}
        (Some(current), Some(next)) if current == next => {}
        _ => {
            return Err(Error::Conflict(
                "committed authority domain cannot change or disappear".to_owned(),
            ));
        }
    }
    if next.closed_generation_floor < current.closed_generation_floor {
        return Err(Error::Conflict(
            "closed generation floor cannot move backwards".to_owned(),
        ));
    }
    if !next
        .compaction_receipts
        .starts_with(&current.compaction_receipts)
    {
        return Err(Error::Conflict(
            "committed compaction receipts cannot change or disappear".to_owned(),
        ));
    }
    if next.closed_generation_floor > current.closed_generation_floor
        && next.compaction_receipts.len() == current.compaction_receipts.len()
    {
        return Err(Error::Conflict(
            "advancing the closed generation floor requires an exact compaction receipt".to_owned(),
        ));
    }
    match (&current.legacy_admission, &next.legacy_admission) {
        (LegacyAdmission::Open, LegacyAdmission::Open)
        | (LegacyAdmission::Open, LegacyAdmission::Sealed { .. }) => {}
        (
            LegacyAdmission::Sealed {
                request_id: current,
            },
            LegacyAdmission::Sealed { request_id: next },
        ) if current == next => {}
        _ => {
            return Err(Error::Conflict(
                "legacy mutation admission cannot be reopened or rebound".to_owned(),
            ));
        }
    }

    let current_sources = current
        .sources
        .iter()
        .map(|entry| (&entry.identity, entry))
        .collect::<BTreeMap<_, _>>();
    let next_sources = next
        .sources
        .iter()
        .map(|entry| (&entry.identity, entry))
        .collect::<BTreeMap<_, _>>();
    for (identity, entry) in &current_sources {
        match next_sources.get(identity) {
            Some(next_entry) => {
                if entry.open_request_id != next_entry.open_request_id {
                    return Err(Error::Conflict(
                        "source open request identity cannot change".to_owned(),
                    ));
                }
                let phase_is_successor = match (&entry.state, &next_entry.state) {
                    (SourcePhase::Open, SourcePhase::Open)
                    | (SourcePhase::Open, SourcePhase::Draining { .. }) => true,
                    (
                        SourcePhase::Draining {
                            drain_request_id: current,
                        },
                        SourcePhase::Draining {
                            drain_request_id: next,
                        },
                    ) if current == next => true,
                    (
                        SourcePhase::Draining {
                            drain_request_id: current,
                        },
                        SourcePhase::Drained {
                            drain_request_id: next,
                            ..
                        },
                    ) if current == next => true,
                    (SourcePhase::Drained { .. }, SourcePhase::Drained { .. })
                        if entry.state == next_entry.state =>
                    {
                        true
                    }
                    _ => false,
                };
                if !phase_is_successor {
                    return Err(Error::Conflict(
                        "source phase cannot be reopened, skipped, or rebound".to_owned(),
                    ));
                }
            }
            None if matches!(entry.state, SourcePhase::Drained { .. })
                && identity.generation <= next.closed_generation_floor => {}
            None => {
                return Err(Error::Conflict(
                    "a source may be removed only after terminal drain and covering compaction"
                        .to_owned(),
                ));
            }
        }
    }
    for (identity, entry) in &next_sources {
        if !current_sources.contains_key(identity)
            && (!matches!(entry.state, SourcePhase::Open)
                || identity.generation <= next.closed_generation_floor)
        {
            return Err(Error::Conflict(
                "a newly committed source must begin Open above the closed generation floor"
                    .to_owned(),
            ));
        }
    }
    Ok(())
}

pub struct LedgerTransition<R> {
    expected_revision: u64,
    next: Ledger,
    result: R,
    lease: TransitionLease,
}

impl<R> LedgerTransition<R> {
    fn ledger(&self) -> &Ledger {
        &self.next
    }

    fn result(&self) -> &R {
        &self.result
    }
}

#[derive(Clone)]
struct SourceGate {
    inner: Arc<Mutex<GateState>>,
}

struct GateState {
    ledger: Ledger,
    active_sources: BTreeMap<SourceIdentity, u64>,
    active_legacy: u64,
    source_drain_wakers: BTreeMap<SourceIdentity, Vec<Waker>>,
    legacy_drain_wakers: Vec<Waker>,
    transition_in_flight: bool,
    pending_transition: Option<PersistenceTransition>,
    persistence_uncertain: bool,
}

#[derive(Clone)]
struct PersistenceTransition {
    prior: Ledger,
    candidate: Ledger,
}

impl SourceGate {
    /// Constructs a gate during startup, before any server-owned mutation task
    /// can hold a permit. No active or uncertain gate may be replaced in the
    /// same process because doing so would discard live permit counters.
    fn new(ledger: Ledger) -> Result<Self, Error> {
        ledger.validate()?;
        Ok(Self {
            inner: Arc::new(Mutex::new(GateState {
                ledger,
                active_sources: BTreeMap::new(),
                active_legacy: 0,
                source_drain_wakers: BTreeMap::new(),
                legacy_drain_wakers: Vec::new(),
                transition_in_flight: false,
                pending_transition: None,
                persistence_uncertain: false,
            })),
        })
    }

    fn state(&self) -> MutexGuard<'_, GateState> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Returns the process-local authoritative snapshot only while its durable
    /// persistence outcome is known. Diagnostic code must not mistake the
    /// conservative in-memory state after an ambiguous write for authority.
    fn snapshot(&self) -> Result<Ledger, Error> {
        let state = self.state();
        if state.transition_in_flight || state.persistence_uncertain {
            return Err(Error::Closed(
                "mutation-source authority is awaiting persistence or terminally uncertain"
                    .to_owned(),
            ));
        }
        Ok(state.ledger.clone())
    }

    #[cfg(test)]
    fn diagnostic_snapshot(&self) -> Ledger {
        self.state().ledger.clone()
    }

    /// Installs a snapshot only after the caller has durably persisted it.
    ///
    /// The expected revision is a process-local CAS guard. The successor
    /// validator independently prevents reopening admission, moving a floor
    /// backwards, losing exact receipts, or reversing a source transition.
    fn validate_transition_pre_persistence<R>(
        &self,
        transition: &LedgerTransition<R>,
    ) -> Result<(), Error> {
        if !Arc::ptr_eq(&self.inner, &transition.lease.gate.inner) {
            return Err(Error::Conflict(
                "ledger transition belongs to a different source gate".to_owned(),
            ));
        }
        let state = self.state();
        if state.persistence_uncertain {
            return Err(Error::Closed(
                "mutation-source persistence outcome is unresolved; authority is unavailable"
                    .to_owned(),
            ));
        }
        if !state.transition_in_flight || !transition.lease.active {
            return Err(Error::Conflict(
                "ledger transition no longer owns the persistence cut".to_owned(),
            ));
        }
        if state.ledger.revision != transition.expected_revision {
            return Err(Error::Conflict(
                "committed ledger changed after this transition was planned".to_owned(),
            ));
        }
        if !state.pending_transition.as_ref().is_some_and(|pending| {
            pending.prior == state.ledger && pending.candidate == transition.next
        }) {
            return Err(Error::Conflict(
                "ledger transition does not match the captured persistence attempt".to_owned(),
            ));
        }
        validate_successor(&state.ledger, &transition.next)
    }

    fn install_persisted_transition<R>(
        &self,
        mut transition: LedgerTransition<R>,
    ) -> Result<(), Error> {
        self.validate_transition_pre_persistence(&transition)?;
        let mut state = self.state();
        state.ledger = transition.next.clone();
        state.transition_in_flight = false;
        state.pending_transition = None;
        transition.lease.active = false;
        Ok(())
    }

    fn fail_stop_with_conservative_transition<R>(
        &self,
        mut transition: LedgerTransition<R>,
    ) -> Result<(), Error> {
        self.validate_transition_pre_persistence(&transition)?;
        let mut state = self.state();
        state
            .pending_transition
            .take()
            .expect("a validated transition retains its captured persistence attempt");
        state.ledger = transition.next.clone();
        state.transition_in_flight = false;
        state.persistence_uncertain = true;
        transition.lease.active = false;
        Ok(())
    }

    /// Serializes one planned transition through atomic persistence and
    /// process-local install. A second planner remains blocked for the entire
    /// persistence future, preventing disk and memory from choosing different
    /// successors of the same revision. This dormant, module-private seam must
    /// eventually be connected only to a supervised adapter that can write the
    /// supplied candidate and no other ledger.
    async fn persist_transition<R: Clone, E, F, Fut>(
        &self,
        transition: LedgerTransition<R>,
        persistence: F,
    ) -> Result<R, DrainCutError<E>>
    where
        F: FnOnce(Ledger) -> Fut,
        Fut: Future<Output = Result<(), E>>,
    {
        self.validate_transition_pre_persistence(&transition)
            .map_err(DrainCutError::State)?;
        let result = transition.result.clone();
        if let Err(error) = persistence(transition.next.clone()).await {
            return Err(DrainCutError::Persistence(error));
        }
        self.install_persisted_transition(transition)
            .map_err(DrainCutError::State)?;
        Ok(result)
    }

    fn plan<R>(
        &self,
        operation: impl FnOnce(&mut Ledger) -> Result<R, Error>,
    ) -> Result<LedgerTransition<R>, Error> {
        let mut state = self.state();
        if state.persistence_uncertain {
            return Err(Error::Closed(
                "mutation-source persistence outcome is unresolved; authority is unavailable"
                    .to_owned(),
            ));
        }
        if state.transition_in_flight {
            return Err(Error::Busy(
                "another durable ledger transition is awaiting persistence".to_owned(),
            ));
        }
        let mut next = state.ledger.clone();
        let result = operation(&mut next)?;
        state.transition_in_flight = true;
        state.pending_transition = Some(PersistenceTransition {
            prior: state.ledger.clone(),
            candidate: next.clone(),
        });
        Ok(LedgerTransition {
            expected_revision: state.ledger.revision,
            next,
            result,
            lease: TransitionLease {
                gate: self.clone(),
                active: true,
            },
        })
    }

    pub fn plan_open_source(
        &self,
        identity: SourceIdentity,
        request_id: &str,
    ) -> Result<LedgerTransition<SourceReceipt>, Error> {
        self.plan(|next| next.open_source(identity, request_id))
    }

    /// Plans the durable admission cut. Persist and install this transition
    /// before waiting for already-admitted server-owned mutations.
    pub fn plan_begin_drain(
        &self,
        identity: &SourceIdentity,
        request_id: &str,
    ) -> Result<DrainTransition, Error> {
        Ok(DrainTransition {
            transition: self.plan(|next| next.begin_drain(identity, request_id))?,
            source: identity.clone(),
            request_id: request_id.to_owned(),
        })
    }

    /// Persists and installs the source admission cut. Even an uncertain
    /// persistence failure installs the cut in memory, which is conservative;
    /// no continuation token is returned and the gate is terminally fenced.
    /// The dormant persistence seam is module-private until a supervised
    /// adapter supplies it.
    async fn persist_drain_cut<E, F, Fut>(
        &self,
        transition: DrainTransition,
        persistence: F,
    ) -> Result<InstalledDrain, DrainCutError<E>>
    where
        F: FnOnce(Ledger) -> Fut,
        Fut: Future<Output = Result<(), E>>,
    {
        self.validate_transition_pre_persistence(&transition.transition)
            .map_err(DrainCutError::State)?;
        let persistence_result = persistence(transition.transition.next.clone()).await;
        let source = transition.source.clone();
        let request_id = transition.request_id.clone();
        if let Err(error) = persistence_result {
            // Installing DRAINING is the conservative process-local cut, but
            // it is not proof that the durable replacement committed. Do not
            // advance it in this process. The gate is terminally fenced until
            // full task/process shutdown and startup reload durable state.
            self.fail_stop_with_conservative_transition(transition.transition)
                .map_err(DrainCutError::State)?;
            return Err(DrainCutError::Persistence(error));
        }
        self.install_persisted_transition(transition.transition)
            .map_err(DrainCutError::State)?;
        Ok(InstalledDrain {
            gate: self.clone(),
            source,
            request_id,
        })
    }

    /// Reconstructs the post-cut token after restart from an already-persisted
    /// DRAINING record. No admission can occur from that durable state.
    pub fn resume_persisted_drain(
        &self,
        source: &SourceIdentity,
        request_id: &str,
    ) -> Result<InstalledDrain, Error> {
        validate_request_id(request_id)?;
        let state = self.state();
        if state.persistence_uncertain {
            return Err(Error::Closed(
                "mutation-source persistence outcome is unresolved; authority is unavailable"
                    .to_owned(),
            ));
        }
        let index = state.ledger.source_index(source)?;
        match &state.ledger.sources[index].state {
            SourcePhase::Draining { drain_request_id } if drain_request_id == request_id => {
                Ok(InstalledDrain {
                    gate: self.clone(),
                    source: source.clone(),
                    request_id: request_id.to_owned(),
                })
            }
            SourcePhase::Draining { .. } | SourcePhase::Drained { .. } => Err(Error::Conflict(
                "persisted source is bound to a different or already-completed drain".to_owned(),
            )),
            SourcePhase::Open => Err(Error::Invalid(
                "persisted source has no drain cut to resume".to_owned(),
            )),
        }
    }

    async fn persist_terminal_drain<E, F, Fut>(
        &self,
        terminal: TerminalDrain,
        persistence: F,
    ) -> Result<SourceReceipt, DrainCutError<E>>
    where
        F: FnOnce(Ledger) -> Fut,
        Fut: Future<Output = Result<(), E>>,
    {
        self.validate_transition_pre_persistence(&terminal.transition)
            .map_err(DrainCutError::State)?;
        if let Err(error) = persistence(terminal.transition.next.clone()).await {
            return Err(DrainCutError::Persistence(error));
        }
        let receipt = terminal.transition.result().clone();
        self.install_persisted_transition(terminal.transition)
            .map_err(DrainCutError::State)?;
        Ok(receipt)
    }

    fn plan_compaction(
        &self,
        authority_domain_id: &str,
        closed_through_generation: u64,
        request_id: &str,
    ) -> Result<LedgerTransition<CompactionReceipt>, Error> {
        self.plan(|next| next.compact(authority_domain_id, closed_through_generation, request_id))
    }

    /// Plans the durable legacy admission cut. Persist and install it before
    /// waiting on [`wait_for_legacy_drain`](Self::wait_for_legacy_drain).
    pub fn plan_seal_legacy(&self, request_id: &str) -> Result<LegacySealTransition, Error> {
        Ok(LegacySealTransition {
            transition: self.plan(|next| {
                next.seal_legacy(request_id)?;
                Ok(next.revision)
            })?,
            request_id: request_id.to_owned(),
        })
    }

    /// Persists and installs the legacy admission cut. As with a source cut,
    /// an uncertain persistence error terminally fences process-local
    /// authority and returns no continuation token.
    async fn persist_legacy_seal<E, F, Fut>(
        &self,
        transition: LegacySealTransition,
        persistence: F,
    ) -> Result<InstalledLegacySeal, DrainCutError<E>>
    where
        F: FnOnce(Ledger) -> Fut,
        Fut: Future<Output = Result<(), E>>,
    {
        self.validate_transition_pre_persistence(&transition.transition)
            .map_err(DrainCutError::State)?;
        let persistence_result = persistence(transition.transition.next.clone()).await;
        let request_id = transition.request_id.clone();
        let ledger_revision = transition.revision();
        if let Err(error) = persistence_result {
            // The seal remains closed in this process, but its durable commit
            // is unknown. The gate remains terminally fenced until full
            // task/process shutdown and startup reload.
            self.fail_stop_with_conservative_transition(transition.transition)
                .map_err(DrainCutError::State)?;
            return Err(DrainCutError::Persistence(error));
        }
        self.install_persisted_transition(transition.transition)
            .map_err(DrainCutError::State)?;
        Ok(InstalledLegacySeal {
            gate: self.clone(),
            request_id,
            ledger_revision,
        })
    }

    pub fn begin_legacy_mutation(&self) -> Result<LegacyMutationPermit, Error> {
        let mut state = self.state();
        if state.persistence_uncertain {
            return Err(Error::Closed(
                "mutation-source persistence outcome is unresolved; authority is unavailable"
                    .to_owned(),
            ));
        }
        if !matches!(state.ledger.legacy_admission, LegacyAdmission::Open) {
            return Err(Error::Closed(
                "legacy mutation admission is permanently closed".to_owned(),
            ));
        }
        state.active_legacy = state
            .active_legacy
            .checked_add(1)
            .ok_or_else(|| Error::Capacity("legacy mutation permit count exhausted".to_owned()))?;
        Ok(LegacyMutationPermit {
            gate: self.clone(),
            active: true,
        })
    }

    pub fn begin_mutation(&self, identity: &SourceIdentity) -> Result<MutationPermit, Error> {
        let mut state = self.state();
        if state.persistence_uncertain {
            return Err(Error::Closed(
                "mutation-source persistence outcome is unresolved; authority is unavailable"
                    .to_owned(),
            ));
        }
        let index = state.ledger.source_index(identity)?;
        if !matches!(state.ledger.sources[index].state, SourcePhase::Open) {
            return Err(Error::Closed(
                "mutation source admission is permanently closed".to_owned(),
            ));
        }
        let count = state.active_sources.entry(identity.clone()).or_default();
        *count = count
            .checked_add(1)
            .ok_or_else(|| Error::Capacity("source mutation permit count exhausted".to_owned()))?;
        Ok(MutationPermit {
            gate: self.clone(),
            identity: identity.clone(),
            active: true,
        })
    }

    pub fn wait_for_drain(&self, identity: &SourceIdentity) -> DrainWait {
        DrainWait {
            gate: self.clone(),
            identity: identity.clone(),
        }
    }

    pub fn wait_for_legacy_drain(&self) -> LegacyDrainWait {
        LegacyDrainWait { gate: self.clone() }
    }
}

pub struct DrainTransition {
    transition: LedgerTransition<SourceReceipt>,
    source: SourceIdentity,
    request_id: String,
}

impl DrainTransition {
    fn ledger(&self) -> &Ledger {
        self.transition.ledger()
    }

    fn result(&self) -> &SourceReceipt {
        self.transition.result()
    }
}

pub struct LegacySealTransition {
    transition: LedgerTransition<u64>,
    request_id: String,
}

impl LegacySealTransition {
    fn revision(&self) -> u64 {
        *self.transition.result()
    }
}

#[derive(Debug)]
pub enum DrainCutError<E> {
    Persistence(E),
    State(Error),
}

pub struct InstalledDrain {
    gate: SourceGate,
    source: SourceIdentity,
    request_id: String,
}

impl InstalledDrain {
    /// Waits for every admitted server-owned mutation and then performs the
    /// caller-supplied backing-storage sync. Only success yields the token that
    /// can plan a terminal receipt.
    pub async fn wait_and_sync<E>(
        self,
        storage_sync: impl Future<Output = Result<(), E>>,
    ) -> Result<SyncedDrain, E> {
        self.gate.wait_for_drain(&self.source).await;
        storage_sync.await?;
        Ok(SyncedDrain {
            gate: self.gate,
            source: self.source,
            request_id: self.request_id,
        })
    }
}

pub struct SyncedDrain {
    gate: SourceGate,
    source: SourceIdentity,
    request_id: String,
}

impl SyncedDrain {
    /// Produces the terminal snapshot. The caller must persist this snapshot,
    /// install it, and only then return its receipt to the requester.
    pub fn plan_terminal(self) -> Result<TerminalDrain, Error> {
        let state = self.gate.state();
        if state.active_sources.get(&self.source).copied().unwrap_or(0) != 0 {
            return Err(Error::Busy(
                "source acquired a mutation permit after its durable cut".to_owned(),
            ));
        }
        drop(state);
        Ok(TerminalDrain {
            transition: self
                .gate
                .plan(|next| next.record_drained_after_sync(&self.source, &self.request_id))?,
        })
    }
}

pub struct TerminalDrain {
    transition: LedgerTransition<SourceReceipt>,
}

pub struct InstalledLegacySeal {
    gate: SourceGate,
    request_id: String,
    ledger_revision: u64,
}

impl InstalledLegacySeal {
    /// Waits for every legacy server-owned mutation and performs the final
    /// backing-storage sync required before acknowledging the seal.
    pub async fn wait_and_sync<E>(
        self,
        storage_sync: impl Future<Output = Result<(), E>>,
    ) -> Result<LegacySealReceipt, E> {
        self.gate.wait_for_legacy_drain().await;
        storage_sync.await?;
        Ok(LegacySealReceipt {
            request_id: self.request_id,
            ledger_revision: self.ledger_revision,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacySealReceipt {
    pub request_id: String,
    pub ledger_revision: u64,
}

struct TransitionLease {
    gate: SourceGate,
    active: bool,
}

impl Drop for TransitionLease {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        self.active = false;
        let mut state = self.gate.state();
        state.transition_in_flight = false;
        state
            .pending_transition
            .take()
            .expect("an active transition lease retains its captured persistence attempt");
        // The transition may have reached atomic persistence before its future
        // was cancelled, panicked, or returned an ambiguous error. No later
        // in-process transition can safely outrun a detached write, even when
        // the candidate bytes appear to match, so uncertainty is terminal.
        state.persistence_uncertain = true;
    }
}

pub struct MutationPermit {
    gate: SourceGate,
    identity: SourceIdentity,
    active: bool,
}

impl Drop for MutationPermit {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        self.active = false;
        let wakers = {
            let mut state = self.gate.state();
            let count = state
                .active_sources
                .get_mut(&self.identity)
                .expect("a live permit has an active source count");
            *count -= 1;
            if *count == 0 {
                state.active_sources.remove(&self.identity);
                state
                    .source_drain_wakers
                    .remove(&self.identity)
                    .unwrap_or_default()
            } else {
                Vec::new()
            }
        };
        for waker in wakers {
            waker.wake();
        }
    }
}

pub struct LegacyMutationPermit {
    gate: SourceGate,
    active: bool,
}

pub enum AdmissionPermit {
    Source(MutationPermit),
    Legacy(LegacyMutationPermit),
}

impl From<MutationPermit> for AdmissionPermit {
    fn from(permit: MutationPermit) -> Self {
        Self::Source(permit)
    }
}

impl From<LegacyMutationPermit> for AdmissionPermit {
    fn from(permit: LegacyMutationPermit) -> Self {
        Self::Legacy(permit)
    }
}

impl Drop for LegacyMutationPermit {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        self.active = false;
        let wakers = {
            let mut state = self.gate.state();
            state.active_legacy -= 1;
            if state.active_legacy == 0 {
                std::mem::take(&mut state.legacy_drain_wakers)
            } else {
                Vec::new()
            }
        };
        for waker in wakers {
            waker.wake();
        }
    }
}

pub struct DrainWait {
    gate: SourceGate,
    identity: SourceIdentity,
}

impl Future for DrainWait {
    type Output = ();

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let mut state = self.gate.state();
        if state
            .active_sources
            .get(&self.identity)
            .copied()
            .unwrap_or(0)
            == 0
        {
            Poll::Ready(())
        } else {
            let wakers = state
                .source_drain_wakers
                .entry(self.identity.clone())
                .or_default();
            if !wakers.iter().any(|waker| waker.will_wake(context.waker())) {
                wakers.push(context.waker().clone());
            }
            Poll::Pending
        }
    }
}

pub struct LegacyDrainWait {
    gate: SourceGate,
}

impl Future for LegacyDrainWait {
    type Output = ();

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let mut state = self.gate.state();
        if state.active_legacy == 0 {
            Poll::Ready(())
        } else {
            if !state
                .legacy_drain_wakers
                .iter()
                .any(|waker| waker.will_wake(context.waker()))
            {
                state.legacy_drain_wakers.push(context.waker().clone());
            }
            Poll::Pending
        }
    }
}

#[derive(Clone)]
pub struct TaskLimiter {
    inner: Arc<Mutex<TaskLimitState>>,
}

struct TaskLimitState {
    active: usize,
    maximum: usize,
}

impl TaskLimiter {
    pub fn new(maximum: usize) -> Self {
        assert!(maximum != 0, "server-owned task limit must be nonzero");
        Self {
            inner: Arc::new(Mutex::new(TaskLimitState { active: 0, maximum })),
        }
    }

    pub fn try_acquire(&self) -> Result<TaskSlot, Error> {
        let mut state = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.active >= state.maximum {
            return Err(Error::Capacity(format!(
                "at most {} server-owned mutations may run concurrently",
                state.maximum
            )));
        }
        state.active += 1;
        Ok(TaskSlot {
            limiter: self.clone(),
            active: true,
        })
    }

    #[cfg(test)]
    fn active(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .active
    }
}

pub struct TaskSlot {
    limiter: TaskLimiter,
    active: bool,
}

impl Drop for TaskSlot {
    fn drop(&mut self) {
        if self.active {
            self.active = false;
            let mut state = self
                .limiter
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.active -= 1;
        }
    }
}

struct CompletionState<T> {
    result: Option<T>,
    producer_alive: bool,
    waker: Option<Waker>,
}

pub struct OwnedMutation<T> {
    future: Pin<Box<dyn Future<Output = T> + 'static>>,
    permit: Option<AdmissionPermit>,
    slot: Option<TaskSlot>,
    completion: Arc<Mutex<CompletionState<T>>>,
    finished: bool,
}

pub struct MutationCompletion<T> {
    completion: Arc<Mutex<CompletionState<T>>>,
}

pub fn server_owned<T: 'static>(
    permit: Option<AdmissionPermit>,
    slot: TaskSlot,
    future: impl Future<Output = T> + 'static,
) -> (OwnedMutation<T>, MutationCompletion<T>) {
    let completion = Arc::new(Mutex::new(CompletionState {
        result: None,
        producer_alive: true,
        waker: None,
    }));
    (
        OwnedMutation {
            future: Box::pin(future),
            permit,
            slot: Some(slot),
            completion: completion.clone(),
            finished: false,
        },
        MutationCompletion { completion },
    )
}

impl<T> Future for OwnedMutation<T> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.as_mut().get_mut();
        match this.future.as_mut().poll(context) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                this.permit.take();
                this.slot.take();
                let waker = {
                    let mut completion = this
                        .completion
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    completion.result = Some(result);
                    completion.producer_alive = false;
                    completion.waker.take()
                };
                this.finished = true;
                if let Some(waker) = waker {
                    waker.wake();
                }
                Poll::Ready(())
            }
        }
    }
}

impl<T> Drop for OwnedMutation<T> {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        let waker = {
            let mut completion = self
                .completion
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            completion.producer_alive = false;
            completion.waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

impl<T> Future for MutationCompletion<T> {
    type Output = Result<T, OwnedMutationCanceled>;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let mut completion = self
            .completion
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(result) = completion.result.take() {
            Poll::Ready(Ok(result))
        } else if !completion.producer_alive {
            Poll::Ready(Err(OwnedMutationCanceled))
        } else {
            completion.waker = Some(context.waker().clone());
            Poll::Pending
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OwnedMutationCanceled;

impl fmt::Display for OwnedMutationCanceled {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("server-owned mutation task ended without a result")
    }
}

impl std::error::Error for OwnedMutationCanceled {}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::channel::oneshot;
    use futures::task::LocalSpawnExt as _;
    use std::sync::atomic::{AtomicBool, Ordering};

    fn source(generation: u64, principal: &str) -> SourceIdentity {
        SourceIdentity {
            authority_domain_id: "ab".repeat(32),
            boot_id: 19,
            generation,
            principal_id: principal.to_owned(),
        }
    }

    fn opened(generation: u64, principal: &str) -> Ledger {
        let mut ledger = Ledger::default();
        ledger
            .open_source(source(generation, principal), "open-1")
            .unwrap();
        ledger
    }

    fn persist_drain(gate: &SourceGate, transition: DrainTransition) -> InstalledDrain {
        futures::executor::block_on(
            gate.persist_drain_cut(transition, |_| futures::future::ready(Ok::<(), ()>(()))),
        )
        .unwrap()
    }

    fn finish_drain(gate: &SourceGate, installed: InstalledDrain) -> SourceReceipt {
        let synced =
            futures::executor::block_on(installed.wait_and_sync(futures::future::ready(Ok::<
                (),
                (),
            >(
                ()
            ))))
            .unwrap();
        let terminal = synced.plan_terminal().unwrap();
        futures::executor::block_on(
            gate.persist_terminal_drain(terminal, |_| futures::future::ready(Ok::<(), ()>(()))),
        )
        .unwrap()
    }

    #[test]
    fn admission_cut_waits_for_the_exact_preexisting_permit() {
        let identity = source(4, "alpha");
        let gate = SourceGate::new(opened(4, "alpha")).unwrap();
        let permit = gate.begin_mutation(&identity).unwrap();

        let transition = gate.plan_begin_drain(&identity, "drain-1").unwrap();
        assert_eq!(transition.result().phase, ReceiptPhase::Draining);
        assert!(gate.begin_mutation(&identity).is_ok());
        let installed = persist_drain(&gate, transition);
        assert!(matches!(
            gate.begin_mutation(&identity),
            Err(Error::Closed(_))
        ));

        let mut wait = Box::pin(gate.wait_for_drain(&identity));
        let waker = futures::task::noop_waker();
        let mut context = Context::from_waker(&waker);
        assert!(wait.as_mut().poll(&mut context).is_pending());
        drop(permit);
        assert!(wait.as_mut().poll(&mut context).is_ready());
        assert_eq!(finish_drain(&gate, installed).phase, ReceiptPhase::Drained);
    }

    #[test]
    fn dropped_handler_waiter_does_not_release_server_owned_permit() {
        let identity = source(5, "alpha");
        let gate = SourceGate::new(opened(5, "alpha")).unwrap();
        let permit = gate.begin_mutation(&identity).unwrap();
        let limiter = TaskLimiter::new(1);
        let slot = limiter.try_acquire().unwrap();
        let (release, released) = oneshot::channel::<()>();
        let (task, completion) = server_owned(Some(permit.into()), slot, async move {
            let _ = released.await;
            7u64
        });
        drop(completion);

        let mut pool = futures::executor::LocalPool::new();
        pool.spawner().spawn_local(task).unwrap();
        pool.run_until_stalled();
        assert_eq!(limiter.active(), 1);
        let transition = gate.plan_begin_drain(&identity, "drain-1").unwrap();
        let _installed = persist_drain(&gate, transition);
        let mut wait = Box::pin(gate.wait_for_drain(&identity));
        let waker = futures::task::noop_waker();
        let mut context = Context::from_waker(&waker);
        assert!(wait.as_mut().poll(&mut context).is_pending());

        release.send(()).unwrap();
        pool.run();
        assert_eq!(limiter.active(), 0);
        assert!(wait.as_mut().poll(&mut context).is_ready());
    }

    #[test]
    fn persisted_draining_reopens_closed_and_completes_after_restart() {
        let identity = source(6, "alpha");
        let gate = SourceGate::new(opened(6, "alpha")).unwrap();
        let transition = gate
            .plan_begin_drain(&identity, "drain-after-restart")
            .unwrap();
        let persisted = encode(transition.ledger()).unwrap();
        drop(transition);

        let recovered = SourceGate::new(decode(&persisted).unwrap()).unwrap();
        assert!(matches!(
            recovered.begin_mutation(&identity),
            Err(Error::Closed(_))
        ));
        let installed = recovered
            .resume_persisted_drain(&identity, "drain-after-restart")
            .unwrap();
        let receipt = finish_drain(&recovered, installed);
        assert_eq!(receipt.phase, ReceiptPhase::Drained);
        assert_eq!(receipt.receipt_sha256.len(), 64);
        assert_eq!(
            recovered
                .snapshot()
                .unwrap()
                .query_source(&identity, "drain-after-restart")
                .unwrap(),
            receipt
        );
    }

    #[test]
    fn codec_rejects_future_corrupt_duplicate_and_over_bound_ledgers() {
        let future = br#"{"schema_version":2,"incompatible":[1,2,3]}"#;
        assert_eq!(decode(future), Err(Error::UnsupportedSchema(2)));
        assert!(matches!(decode(b"not-json"), Err(Error::Decode(_))));

        let mut duplicate = opened(7, "alpha");
        duplicate.sources.push(duplicate.sources[0].clone());
        assert!(matches!(encode(&duplicate), Err(Error::Invalid(_))));

        let too_large = vec![b' '; MAX_LEDGER_BYTES + 1];
        assert!(matches!(decode(&too_large), Err(Error::Capacity(_))));

        let mut nondefault_zero = opened(7, "alpha");
        nondefault_zero.revision = 0;
        let bytes = serde_json::to_vec(&nondefault_zero).unwrap();
        assert!(matches!(decode(&bytes), Err(Error::Invalid(_))));

        let mut too_many = Ledger::default();
        too_many.revision = 1;
        too_many.authority_domain_id = Some("ab".repeat(32));
        too_many.sources = (1..=MAX_SOURCES + 1)
            .map(|generation| SourceEntry {
                identity: source(generation as u64, &format!("source-{generation}")),
                open_request_id: "open".to_owned(),
                state: SourcePhase::Open,
            })
            .collect();
        assert!(matches!(encode(&too_many), Err(Error::Capacity(_))));
    }

    #[test]
    fn compaction_floor_rejects_resurrection_but_retains_lower_open_exception() {
        let low = source(2, "long-lived");
        let retired = source(7, "retired");
        let mut ledger = Ledger::default();
        ledger.open_source(low.clone(), "open-low").unwrap();
        ledger.open_source(retired.clone(), "open-retired").unwrap();
        ledger.begin_drain(&retired, "drain-retired").unwrap();
        ledger
            .record_drained_after_sync(&retired, "drain-retired")
            .unwrap();
        ledger.compact(&"ab".repeat(32), 7, "compact-7").unwrap();

        assert!(ledger.sources.iter().any(|entry| entry.identity == low));
        assert!(!ledger.sources.iter().any(|entry| entry.identity == retired));
        assert_eq!(
            ledger
                .open_source(source(6, "resurrected"), "open-resurrected")
                .unwrap()
                .phase,
            ReceiptPhase::Retired
        );
        assert_eq!(
            ledger.open_source(low.clone(), "open-low").unwrap().phase,
            ReceiptPhase::Open
        );
        assert_eq!(
            ledger
                .open_source(source(8, "new"), "open-new")
                .unwrap()
                .phase,
            ReceiptPhase::Open
        );
        assert_eq!(decode(&encode(&ledger).unwrap()).unwrap(), ledger);
    }

    #[test]
    fn compaction_replay_survives_later_and_same_floor_compactions() {
        let mut ledger = opened(11, "long-lived");
        let first = ledger.compact(&"ab".repeat(32), 3, "compact-a").unwrap();
        let same_floor = ledger.compact(&"ab".repeat(32), 3, "compact-b").unwrap();
        let later = ledger.compact(&"ab".repeat(32), 9, "compact-c").unwrap();
        assert!(first.committed_revision < same_floor.committed_revision);
        assert!(same_floor.committed_revision < later.committed_revision);
        assert_eq!(
            ledger.compact(&"ab".repeat(32), 3, "compact-a").unwrap(),
            first
        );
        assert!(matches!(
            ledger.compact(&"ab".repeat(32), 4, "compact-a"),
            Err(Error::Conflict(_))
        ));
        assert_eq!(ledger.compaction_receipts.len(), 3);
    }

    #[test]
    fn bounded_compaction_receipt_exhaustion_fails_closed_but_exact_replay_lives() {
        let mut ledger = opened(600, "long-lived");
        for index in 0..MAX_COMPACTION_RECEIPTS {
            ledger
                .compact(&"ab".repeat(32), 0, &format!("compact-{index}"))
                .unwrap();
        }
        let before = serde_json::to_vec(&ledger).unwrap();
        assert!(matches!(
            ledger.compact(&"ab".repeat(32), 0, "one-too-many"),
            Err(Error::Capacity(_))
        ));
        assert_eq!(serde_json::to_vec(&ledger).unwrap(), before);
        assert_eq!(
            ledger
                .compact(&"ab".repeat(32), 0, "compact-0")
                .unwrap()
                .request_id,
            "compact-0"
        );
    }

    #[test]
    fn covered_eviction_is_distinct_from_an_unknown_future_source() {
        let retired = source(12, "retired");
        let mut ledger = Ledger::default();
        ledger.open_source(retired.clone(), "open-retired").unwrap();
        ledger.begin_drain(&retired, "drain-retired").unwrap();
        ledger
            .record_drained_after_sync(&retired, "drain-retired")
            .unwrap();
        ledger.compact(&"ab".repeat(32), 12, "compact-12").unwrap();
        let queried = ledger.query_source(&retired, "drain-retired").unwrap();
        assert_eq!(queried.phase, ReceiptPhase::Retired);
        assert_eq!(queried.request_id, "drain-retired");
        assert_eq!(queried.closed_generation_floor, 12);
        let drained = ledger.begin_drain(&retired, "different-request").unwrap();
        assert_eq!(drained.phase, ReceiptPhase::Retired);
        assert_eq!(drained.request_id, "different-request");
        let opened = ledger.open_source(retired, "different-open").unwrap();
        assert_eq!(opened.phase, ReceiptPhase::Retired);
        assert_eq!(opened.request_id, "different-open");
        assert!(matches!(
            ledger.query_source(&source(13, "unknown"), "unknown"),
            Err(Error::NotFound(_))
        ));
    }

    #[test]
    fn malformed_identities_never_receive_a_covering_floor_proof() {
        let retired = source(12, "retired");
        let mut ledger = Ledger::default();
        ledger.open_source(retired.clone(), "open-retired").unwrap();
        ledger.begin_drain(&retired, "drain-retired").unwrap();
        ledger
            .record_drained_after_sync(&retired, "drain-retired")
            .unwrap();
        ledger.compact(&"ab".repeat(32), 12, "compact-12").unwrap();

        let malformed = [
            SourceIdentity {
                authority_domain_id: "AB".repeat(32),
                ..source(9, "invalid-domain")
            },
            SourceIdentity {
                boot_id: 0,
                ..source(9, "zero-boot")
            },
            SourceIdentity {
                generation: 0,
                ..source(9, "zero-generation")
            },
            source(9, ""),
        ];
        for identity in malformed {
            let before = serde_json::to_vec(&ledger).unwrap();
            assert!(matches!(
                ledger.begin_drain(&identity, "drain"),
                Err(Error::Invalid(_))
            ));
            assert_eq!(serde_json::to_vec(&ledger).unwrap(), before);
            assert!(matches!(
                ledger.record_drained_after_sync(&identity, "drain"),
                Err(Error::Invalid(_))
            ));
            assert_eq!(serde_json::to_vec(&ledger).unwrap(), before);
            assert!(matches!(
                ledger.query_source(&identity, "query"),
                Err(Error::Invalid(_))
            ));

            let gate = SourceGate::new(ledger.clone()).unwrap();
            assert!(matches!(
                gate.begin_mutation(&identity),
                Err(Error::Invalid(_))
            ));
            assert!(matches!(
                gate.resume_persisted_drain(&identity, "drain"),
                Err(Error::Invalid(_))
            ));
            assert_eq!(gate.snapshot().unwrap(), ledger);
        }
    }

    #[test]
    fn every_failed_mutation_preserves_exact_ledger_bytes() {
        fn assert_unchanged(
            mut ledger: Ledger,
            operation: impl FnOnce(&mut Ledger) -> Result<(), Error>,
        ) {
            let before = serde_json::to_vec(&ledger).unwrap();
            assert!(operation(&mut ledger).is_err());
            assert_eq!(serde_json::to_vec(&ledger).unwrap(), before);
        }

        let mut open_max = opened(20, "alpha");
        open_max.revision = u64::MAX;
        assert_unchanged(open_max, |ledger| {
            ledger
                .open_source(source(21, "beta"), "open-beta")
                .map(drop)
        });

        let mut begin_max = opened(20, "alpha");
        begin_max.revision = u64::MAX;
        assert_unchanged(begin_max, |ledger| {
            ledger.begin_drain(&source(20, "alpha"), "drain").map(drop)
        });

        let mut complete_max = opened(20, "alpha");
        complete_max
            .begin_drain(&source(20, "alpha"), "drain")
            .unwrap();
        complete_max.revision = u64::MAX;
        assert_unchanged(complete_max, |ledger| {
            ledger
                .record_drained_after_sync(&source(20, "alpha"), "drain")
                .map(drop)
        });

        let mut compact_max = opened(20, "alpha");
        compact_max.revision = u64::MAX;
        assert_unchanged(compact_max, |ledger| {
            ledger.compact(&"ab".repeat(32), 1, "compact").map(drop)
        });

        let mut seal_max = opened(20, "alpha");
        seal_max.revision = u64::MAX;
        assert_unchanged(seal_max, |ledger| ledger.seal_legacy("seal"));
    }

    #[test]
    fn durable_successor_rejects_rollback_reopen_and_stale_install() {
        let identity = source(30, "alpha");
        let original = opened(30, "alpha");
        let gate = SourceGate::new(original.clone()).unwrap();
        let drain = gate.plan_begin_drain(&identity, "drain").unwrap();
        let _installed = persist_drain(&gate, drain);

        let invalid = gate
            .plan(|next| {
                next.revision += 1;
                next.sources[0].state = SourcePhase::Open;
                Ok(())
            })
            .unwrap();
        let before = gate.diagnostic_snapshot();
        assert!(matches!(
            gate.install_persisted_transition(invalid),
            Err(Error::Conflict(_))
        ));
        assert_eq!(gate.diagnostic_snapshot(), before);
        assert!(matches!(gate.snapshot(), Err(Error::Closed(_))));
        assert!(matches!(
            gate.begin_mutation(&identity),
            Err(Error::Closed(_))
        ));
    }

    #[test]
    fn durable_successor_rejects_revision_domain_floor_receipt_and_legacy_rollback() {
        let mut current = opened(90, "alpha");
        current
            .open_source(source(91, "beta"), "open-beta")
            .unwrap();

        let mut revision_rollback = current.clone();
        revision_rollback.revision -= 1;
        assert!(matches!(
            validate_successor(&current, &revision_rollback),
            Err(Error::Conflict(_))
        ));

        let mut changed_domain = current.clone();
        changed_domain.revision += 1;
        changed_domain.authority_domain_id = Some("cd".repeat(32));
        for entry in &mut changed_domain.sources {
            entry.identity.authority_domain_id = "cd".repeat(32);
        }
        assert!(matches!(
            validate_successor(&current, &changed_domain),
            Err(Error::Conflict(_))
        ));

        current.compact(&"ab".repeat(32), 5, "compact-5").unwrap();
        let mut floor_and_receipt_rollback = current.clone();
        floor_and_receipt_rollback.revision += 1;
        floor_and_receipt_rollback.closed_generation_floor = 4;
        floor_and_receipt_rollback.compaction_receipts[0].closed_through_generation = 4;
        assert!(matches!(
            validate_successor(&current, &floor_and_receipt_rollback),
            Err(Error::Conflict(_))
        ));

        current.seal_legacy("seal").unwrap();
        let mut legacy_reopen = current.clone();
        legacy_reopen.revision += 1;
        legacy_reopen.legacy_admission = LegacyAdmission::Open;
        assert!(matches!(
            validate_successor(&current, &legacy_reopen),
            Err(Error::Conflict(_))
        ));
    }

    #[test]
    fn durable_legacy_seal_cuts_admission_and_waits_existing_permits() {
        let gate = SourceGate::new(Ledger::default()).unwrap();
        let permit = gate.begin_legacy_mutation().unwrap();
        let seal = gate.plan_seal_legacy("seal-legacy").unwrap();
        assert!(gate.begin_legacy_mutation().is_ok());
        let installed = futures::executor::block_on(
            gate.persist_legacy_seal(seal, |_| futures::future::ready(Ok::<(), ()>(()))),
        )
        .unwrap();
        assert!(matches!(
            gate.begin_legacy_mutation(),
            Err(Error::Closed(_))
        ));
        let mut wait = Box::pin(gate.wait_for_legacy_drain());
        let waker = futures::task::noop_waker();
        let mut context = Context::from_waker(&waker);
        assert!(wait.as_mut().poll(&mut context).is_pending());
        drop(permit);
        assert!(wait.as_mut().poll(&mut context).is_ready());
        let receipt =
            futures::executor::block_on(installed.wait_and_sync(futures::future::ready(Ok::<
                (),
                (),
            >(
                ()
            ))))
            .unwrap();
        assert_eq!(receipt.request_id, "seal-legacy");
    }

    #[test]
    fn transition_lease_prevents_two_persisted_successors_from_diverging() {
        let gate = SourceGate::new(Ledger::default()).unwrap();
        let first = gate
            .plan_open_source(source(40, "first"), "open-first")
            .unwrap();
        assert!(matches!(
            gate.plan_open_source(source(41, "second"), "open-second"),
            Err(Error::Busy(_))
        ));

        let disk = Arc::new(Mutex::new(Vec::new()));
        let first_disk = disk.clone();
        futures::executor::block_on(gate.persist_transition(first, move |ledger| async move {
            *first_disk.lock().unwrap() = encode(&ledger).unwrap();
            Ok::<(), ()>(())
        }))
        .unwrap();
        let second = gate
            .plan_open_source(source(41, "second"), "open-second")
            .unwrap();
        let second_disk = disk.clone();
        futures::executor::block_on(gate.persist_transition(second, move |ledger| async move {
            *second_disk.lock().unwrap() = encode(&ledger).unwrap();
            Ok::<(), ()>(())
        }))
        .unwrap();
        let compaction = gate
            .plan_compaction(&"ab".repeat(32), 0, "compact-zero")
            .unwrap();
        let compaction_disk = disk.clone();
        futures::executor::block_on(gate.persist_transition(
            compaction,
            move |ledger| async move {
                *compaction_disk.lock().unwrap() = encode(&ledger).unwrap();
                Ok::<(), ()>(())
            },
        ))
        .unwrap();
        assert_eq!(
            *disk.lock().unwrap(),
            encode(&gate.snapshot().unwrap()).unwrap()
        );
    }

    #[test]
    fn cross_gate_transition_is_rejected_before_persistence() {
        let owner = SourceGate::new(Ledger::default()).unwrap();
        let wrong_gate = SourceGate::new(Ledger::default()).unwrap();
        let transition = owner
            .plan_open_source(source(42, "owned"), "open-owned")
            .unwrap();
        let persistence_called = Arc::new(AtomicBool::new(false));
        let called = persistence_called.clone();
        let result = futures::executor::block_on(wrong_gate.persist_transition(
            transition,
            move |_| async move {
                called.store(true, Ordering::SeqCst);
                Ok::<(), ()>(())
            },
        ));
        assert!(matches!(
            result,
            Err(DrainCutError::State(Error::Conflict(_)))
        ));
        assert!(!persistence_called.load(Ordering::SeqCst));
        assert_eq!(wrong_gate.snapshot().unwrap(), Ledger::default());
        assert!(wrong_gate
            .plan_open_source(source(43, "wrong-gate"), "open-wrong-gate")
            .is_ok());
        assert!(matches!(owner.snapshot(), Err(Error::Closed(_))));
    }

    #[test]
    fn staged_drain_orders_persistence_permits_sync_terminal_persistence_and_reply() {
        let identity = source(50, "alpha");
        let gate = SourceGate::new(opened(50, "alpha")).unwrap();
        let order = Arc::new(Mutex::new(Vec::new()));
        let transition = gate.plan_begin_drain(&identity, "drain-ordered").unwrap();
        let cut_order = order.clone();
        let installed = futures::executor::block_on(gate.persist_drain_cut(
            transition,
            move |ledger| async move {
                assert!(matches!(
                    ledger.sources[0].state,
                    SourcePhase::Draining { .. }
                ));
                cut_order.lock().unwrap().push("persist-draining");
                Ok::<(), ()>(())
            },
        ))
        .unwrap();
        let sync_order = order.clone();
        let synced = futures::executor::block_on(installed.wait_and_sync(async move {
            sync_order.lock().unwrap().push("storage-sync");
            Ok::<(), ()>(())
        }))
        .unwrap();
        let terminal = synced.plan_terminal().unwrap();
        let terminal_order = order.clone();
        let receipt = futures::executor::block_on(gate.persist_terminal_drain(
            terminal,
            move |ledger| async move {
                assert!(matches!(
                    ledger.sources[0].state,
                    SourcePhase::Drained { .. }
                ));
                terminal_order.lock().unwrap().push("persist-drained");
                Ok::<(), ()>(())
            },
        ))
        .unwrap();
        order.lock().unwrap().push("reply");
        assert_eq!(receipt.phase, ReceiptPhase::Drained);
        assert_eq!(
            *order.lock().unwrap(),
            vec![
                "persist-draining",
                "storage-sync",
                "persist-drained",
                "reply"
            ]
        );
    }

    #[test]
    fn uncertain_drain_is_terminal_even_when_candidate_bytes_match() {
        let identity = source(51, "alpha");
        let gate = SourceGate::new(opened(51, "alpha")).unwrap();
        let permit = gate.begin_mutation(&identity).unwrap();
        let transition = gate.plan_begin_drain(&identity, "drain-uncertain").unwrap();
        let disk = Arc::new(Mutex::new(Vec::new()));
        let write = disk.clone();
        let result = futures::executor::block_on(gate.persist_drain_cut(
            transition,
            move |ledger| async move {
                *write.lock().unwrap() = encode(&ledger).unwrap();
                Err::<(), _>("uncertain")
            },
        ));
        assert!(matches!(
            result,
            Err(DrainCutError::Persistence("uncertain"))
        ));
        assert!(matches!(
            gate.begin_mutation(&identity),
            Err(Error::Closed(_))
        ));
        assert!(matches!(
            gate.diagnostic_snapshot().sources[0].state,
            SourcePhase::Draining { .. }
        ));
        assert!(matches!(
            gate.resume_persisted_drain(&identity, "drain-uncertain"),
            Err(Error::Closed(_))
        ));
        assert!(matches!(
            gate.plan_open_source(source(52, "later"), "open-later"),
            Err(Error::Closed(_))
        ));
        assert!(matches!(gate.snapshot(), Err(Error::Closed(_))));

        let durable = decode(&disk.lock().unwrap()).unwrap();
        assert_eq!(durable, gate.diagnostic_snapshot());
        drop(permit);
        assert!(matches!(gate.snapshot(), Err(Error::Closed(_))));
        assert!(matches!(
            gate.resume_persisted_drain(&identity, "drain-uncertain"),
            Err(Error::Closed(_))
        ));
    }

    #[test]
    fn failed_storage_sync_retains_draining_for_exact_restart_resume() {
        let identity = source(53, "alpha");
        let gate = SourceGate::new(opened(53, "alpha")).unwrap();
        let transition = gate.plan_begin_drain(&identity, "drain-sync").unwrap();
        let installed = persist_drain(&gate, transition);
        let result =
            futures::executor::block_on(installed.wait_and_sync(futures::future::ready(Err::<
                (),
                _,
            >(
                "sync failed",
            ))));
        assert!(matches!(result, Err("sync failed")));
        assert!(matches!(
            gate.snapshot().unwrap().sources[0].state,
            SourcePhase::Draining { .. }
        ));
        let resumed = gate
            .resume_persisted_drain(&identity, "drain-sync")
            .unwrap();
        assert_eq!(finish_drain(&gate, resumed).phase, ReceiptPhase::Drained);
    }

    #[test]
    fn uncertain_terminal_drain_is_terminal_even_when_candidate_bytes_match() {
        let identity = source(55, "alpha");
        let gate = SourceGate::new(opened(55, "alpha")).unwrap();
        let permit = gate.begin_mutation(&identity).unwrap();
        let transition = gate
            .plan_begin_drain(&identity, "drain-terminal-uncertain")
            .unwrap();
        let installed = persist_drain(&gate, transition);
        let mut syncing =
            Box::pin(installed.wait_and_sync(futures::future::ready(Ok::<(), ()>(()))));
        let waker = futures::task::noop_waker();
        let mut context = Context::from_waker(&waker);
        assert!(syncing.as_mut().poll(&mut context).is_pending());
        drop(permit);
        let synced = match syncing.as_mut().poll(&mut context) {
            Poll::Ready(Ok(synced)) => synced,
            _ => panic!("storage sync did not follow the final admitted permit"),
        };
        let terminal = synced.plan_terminal().unwrap();
        let disk = Arc::new(Mutex::new(Vec::new()));
        let write = disk.clone();
        let result = futures::executor::block_on(gate.persist_terminal_drain(
            terminal,
            move |ledger| async move {
                *write.lock().unwrap() = encode(&ledger).unwrap();
                Err::<(), _>("terminal outcome unknown")
            },
        ));
        assert!(matches!(
            result,
            Err(DrainCutError::Persistence("terminal outcome unknown"))
        ));
        let candidate = decode(&disk.lock().unwrap()).unwrap();
        assert!(matches!(
            candidate.sources[0].state,
            SourcePhase::Drained { .. }
        ));
        assert!(matches!(
            gate.diagnostic_snapshot().sources[0].state,
            SourcePhase::Draining { .. }
        ));
        assert!(matches!(gate.snapshot(), Err(Error::Closed(_))));
        assert!(matches!(
            gate.begin_mutation(&identity),
            Err(Error::Closed(_))
        ));
        assert!(matches!(
            gate.plan_open_source(source(56, "later"), "open-later"),
            Err(Error::Closed(_))
        ));
        assert!(matches!(
            gate.resume_persisted_drain(&identity, "drain-terminal-uncertain"),
            Err(Error::Closed(_))
        ));
    }

    #[test]
    fn uncertain_legacy_seal_is_terminal_even_when_candidate_bytes_match() {
        let gate = SourceGate::new(Ledger::default()).unwrap();
        let permit = gate.begin_legacy_mutation().unwrap();
        let seal = gate.plan_seal_legacy("seal-uncertain").unwrap();
        let disk = Arc::new(Mutex::new(Vec::new()));
        let write = disk.clone();
        let result =
            futures::executor::block_on(gate.persist_legacy_seal(seal, move |ledger| async move {
                *write.lock().unwrap() = encode(&ledger).unwrap();
                Err::<(), _>("commit outcome unknown")
            }));
        assert!(matches!(
            result,
            Err(DrainCutError::Persistence("commit outcome unknown"))
        ));
        assert!(matches!(
            gate.diagnostic_snapshot().legacy_admission,
            LegacyAdmission::Sealed { .. }
        ));
        assert!(matches!(
            gate.begin_legacy_mutation(),
            Err(Error::Closed(_))
        ));
        assert!(matches!(
            gate.plan_open_source(source(54, "later"), "open-later"),
            Err(Error::Closed(_))
        ));
        assert!(matches!(gate.snapshot(), Err(Error::Closed(_))));

        let durable = decode(&disk.lock().unwrap()).unwrap();
        assert_eq!(durable, gate.diagnostic_snapshot());
        drop(permit);
        assert!(matches!(gate.snapshot(), Err(Error::Closed(_))));
        assert!(matches!(
            gate.plan_seal_legacy("seal-uncertain"),
            Err(Error::Closed(_))
        ));
    }

    #[test]
    fn persisted_then_error_is_terminal_even_when_candidate_bytes_match() {
        let existing = source(70, "existing");
        let gate = SourceGate::new(opened(70, "existing")).unwrap();
        let transition = gate
            .plan_open_source(source(71, "new"), "open-new")
            .unwrap();
        let disk = Arc::new(Mutex::new(Vec::new()));
        let write = disk.clone();
        let result = futures::executor::block_on(gate.persist_transition(
            transition,
            move |ledger| async move {
                *write.lock().unwrap() = encode(&ledger).unwrap();
                Err::<(), _>("commit outcome unknown")
            },
        ));
        assert!(matches!(
            result,
            Err(DrainCutError::Persistence("commit outcome unknown"))
        ));
        assert!(matches!(
            gate.begin_mutation(&existing),
            Err(Error::Closed(_))
        ));
        assert!(matches!(
            gate.begin_legacy_mutation(),
            Err(Error::Closed(_))
        ));
        assert!(matches!(
            gate.plan_open_source(source(72, "later"), "open-later"),
            Err(Error::Closed(_))
        ));
        assert!(matches!(gate.snapshot(), Err(Error::Closed(_))));
        let candidate = decode(&disk.lock().unwrap()).unwrap();
        assert!(candidate
            .sources
            .iter()
            .any(|entry| entry.identity == source(71, "new")));
        assert_ne!(candidate, gate.diagnostic_snapshot());
        assert!(matches!(
            gate.plan_open_source(source(71, "new"), "open-new"),
            Err(Error::Closed(_))
        ));
    }

    #[test]
    fn cancellation_after_persist_fail_stops_the_gate() {
        let existing = source(80, "existing");
        let gate = SourceGate::new(opened(80, "existing")).unwrap();
        let transition = gate
            .plan_open_source(source(81, "new"), "open-new")
            .unwrap();
        let disk = Arc::new(Mutex::new(Vec::new()));
        let write = disk.clone();
        let mut operation = Box::pin(gate.persist_transition(
            transition,
            move |ledger| async move {
                *write.lock().unwrap() = encode(&ledger).unwrap();
                futures::future::pending::<Result<(), ()>>().await
            },
        ));
        let waker = futures::task::noop_waker();
        let mut context = Context::from_waker(&waker);
        assert!(operation.as_mut().poll(&mut context).is_pending());
        assert!(!disk.lock().unwrap().is_empty());
        assert!(matches!(gate.snapshot(), Err(Error::Closed(_))));
        drop(operation);
        assert!(matches!(
            gate.begin_mutation(&existing),
            Err(Error::Closed(_))
        ));
        assert!(matches!(
            gate.plan_open_source(source(82, "later"), "open-later"),
            Err(Error::Closed(_))
        ));
        assert!(matches!(gate.snapshot(), Err(Error::Closed(_))));
    }

    #[test]
    fn panic_after_persist_fail_stops_the_gate() {
        let existing = source(83, "existing");
        let gate = SourceGate::new(opened(83, "existing")).unwrap();
        let transition = gate
            .plan_open_source(source(84, "new"), "open-new")
            .unwrap();
        let disk = Arc::new(Mutex::new(Vec::new()));
        let write = disk.clone();
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            futures::executor::block_on(gate.persist_transition(
                transition,
                move |ledger| async move {
                    *write.lock().unwrap() = encode(&ledger).unwrap();
                    panic!("after durable replacement");
                    #[allow(unreachable_code)]
                    Ok::<(), ()>(())
                },
            ))
        }));
        assert!(panic.is_err());
        assert!(!disk.lock().unwrap().is_empty());
        assert!(matches!(
            gate.begin_mutation(&existing),
            Err(Error::Closed(_))
        ));
        assert!(matches!(
            gate.plan_open_source(source(85, "later"), "open-later"),
            Err(Error::Closed(_))
        ));
        assert!(matches!(gate.snapshot(), Err(Error::Closed(_))));
    }

    #[test]
    fn exact_retry_and_query_reject_conflicting_request_identity() {
        let identity = source(9, "alpha");
        let mut ledger = opened(9, "alpha");
        let first = ledger.begin_drain(&identity, "drain-exact").unwrap();
        assert_eq!(ledger.begin_drain(&identity, "drain-exact").unwrap(), first);
        assert!(matches!(
            ledger.begin_drain(&identity, "drain-other"),
            Err(Error::Conflict(_))
        ));
        ledger
            .record_drained_after_sync(&identity, "drain-exact")
            .unwrap();
        assert_eq!(
            ledger.query_source(&identity, "drain-exact").unwrap().phase,
            ReceiptPhase::Drained
        );
        assert!(matches!(
            ledger.query_source(&identity, "unknown-request"),
            Err(Error::Conflict(_))
        ));
    }
}
