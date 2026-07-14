//! Pure namespace, inventory, and mode-transition policy.
//!
//! This module constructs paths only from [`CanonicalUsername`] values and
//! deliberately performs no filesystem access or mutation.

use std::path::{Path, PathBuf};

use crate::config::EmbeddingSecurityMode;
use crate::paths::{MODE1_MODELS_DIR, MODE2_MODELS_DIR, MODELS_DIR};

use super::{CanonicalUsername, StorageError};

/// Required mode for every directory in the enrollment namespace.
pub const STORAGE_DIRECTORY_MODE: u32 = 0o700;

/// Required mode for every enrollment record.
pub const STORAGE_RECORD_MODE: u32 = 0o600;

/// A supported enrollment-record namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum RecordNamespace {
    Plaintext = 0,
    AeadCached = 1,
    AeadEphemeral = 2,
}

/// Stable iteration order for supported record namespaces.
pub const ALL_RECORD_NAMESPACES: [RecordNamespace; 3] = [
    RecordNamespace::Plaintext,
    RecordNamespace::AeadCached,
    RecordNamespace::AeadEphemeral,
];

impl RecordNamespace {
    pub const fn identifier(self) -> u8 {
        self as u8
    }

    pub const fn security_mode(self) -> EmbeddingSecurityMode {
        match self {
            Self::Plaintext => EmbeddingSecurityMode::Plaintext,
            Self::AeadCached => EmbeddingSecurityMode::AeadCached,
            Self::AeadEphemeral => EmbeddingSecurityMode::AeadEphemeral,
        }
    }

    pub fn directory(self) -> &'static Path {
        Path::new(match self {
            Self::Plaintext => MODELS_DIR,
            Self::AeadCached => MODE1_MODELS_DIR,
            Self::AeadEphemeral => MODE2_MODELS_DIR,
        })
    }

    /// Construct every defined record path for a canonical username.
    ///
    /// Mode 0 has an authoritative `.bin` path and a read-only legacy `.json`
    /// fallback. Encrypted modes have only their authoritative `.hye` path.
    pub fn record_paths(self, username: &CanonicalUsername) -> NamespaceRecordPaths {
        let (extension, legacy_extension) = match self {
            Self::Plaintext => ("bin", Some("json")),
            Self::AeadCached | Self::AeadEphemeral => ("hye", None),
        };
        let authoritative =
            RecordPath::new(self, RecordPathKind::Authoritative, username, extension);
        let legacy_fallback = legacy_extension.map(|extension| {
            RecordPath::new(
                self,
                RecordPathKind::LegacyReadOnlyFallback,
                username,
                extension,
            )
        });
        NamespaceRecordPaths {
            authoritative,
            legacy_fallback,
        }
    }
}

impl TryFrom<EmbeddingSecurityMode> for RecordNamespace {
    type Error = StorageError;

    fn try_from(value: EmbeddingSecurityMode) -> Result<Self, Self::Error> {
        match value {
            EmbeddingSecurityMode::Plaintext => Ok(Self::Plaintext),
            EmbeddingSecurityMode::AeadCached => Ok(Self::AeadCached),
            EmbeddingSecurityMode::AeadEphemeral => Ok(Self::AeadEphemeral),
            EmbeddingSecurityMode::ReservedFuture => {
                Err(StorageError::UnsupportedNamespaceMode(value as u8))
            }
        }
    }
}

/// The role of one path inside its namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordPathKind {
    Authoritative,
    LegacyReadOnlyFallback,
}

/// An exact record path constructed from a canonical username.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RecordPath {
    namespace: RecordNamespace,
    kind: RecordPathKind,
    path: PathBuf,
}

impl RecordPath {
    fn new(
        namespace: RecordNamespace,
        kind: RecordPathKind,
        username: &CanonicalUsername,
        extension: &str,
    ) -> Self {
        let path = namespace
            .directory()
            .join(format!("{}.{extension}", username.as_str()));
        Self {
            namespace,
            kind,
            path,
        }
    }

    pub const fn namespace(&self) -> RecordNamespace {
        self.namespace
    }

    pub const fn kind(&self) -> RecordPathKind {
        self.kind
    }

    pub fn as_path(&self) -> &Path {
        &self.path
    }
}

/// All possible paths for one user in one namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceRecordPaths {
    authoritative: RecordPath,
    legacy_fallback: Option<RecordPath>,
}

impl NamespaceRecordPaths {
    pub fn authoritative(&self) -> &RecordPath {
        &self.authoritative
    }

    pub fn legacy_fallback(&self) -> Option<&RecordPath> {
        self.legacy_fallback.as_ref()
    }

    pub fn iter(&self) -> impl Iterator<Item = &RecordPath> {
        std::iter::once(&self.authoritative).chain(self.legacy_fallback.iter())
    }
}

/// Whether a namespace is selected for authentication or retained only for diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamespaceActivity {
    Active,
    InactiveDiagnosticOnly,
}

/// The selected namespace and the two inactive namespaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NamespaceSelection {
    active: RecordNamespace,
}

impl NamespaceSelection {
    pub const fn new(active: RecordNamespace) -> Self {
        Self { active }
    }

    pub const fn active(self) -> RecordNamespace {
        self.active
    }

    pub const fn inactive(self) -> [RecordNamespace; 2] {
        match self.active {
            RecordNamespace::Plaintext => {
                [RecordNamespace::AeadCached, RecordNamespace::AeadEphemeral]
            }
            RecordNamespace::AeadCached => {
                [RecordNamespace::Plaintext, RecordNamespace::AeadEphemeral]
            }
            RecordNamespace::AeadEphemeral => {
                [RecordNamespace::Plaintext, RecordNamespace::AeadCached]
            }
        }
    }

    pub const fn activity(self, namespace: RecordNamespace) -> NamespaceActivity {
        if self.active as u8 == namespace as u8 {
            NamespaceActivity::Active
        } else {
            NamespaceActivity::InactiveDiagnosticOnly
        }
    }

    /// Classify a discovered record without opening, changing, or deleting it.
    pub fn classify_record(
        self,
        record_path: RecordPath,
        condition: RecordCondition,
    ) -> RecordInventory {
        let activity = self.activity(record_path.namespace());
        RecordInventory {
            record_path,
            activity,
            condition,
        }
    }
}

impl TryFrom<EmbeddingSecurityMode> for NamespaceSelection {
    type Error = StorageError;

    fn try_from(value: EmbeddingSecurityMode) -> Result<Self, Self::Error> {
        RecordNamespace::try_from(value).map(Self::new)
    }
}

/// Why a present record cannot be activated under current policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordIncompatibility {
    ModelMismatch,
    KeyMismatch,
    InvalidRecord,
}

/// Diagnostic state of a possible record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordCondition {
    Absent,
    Compatible,
    Incompatible(RecordIncompatibility),
}

/// Pure inventory classification for doctor and explicit purge planning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordInventory {
    record_path: RecordPath,
    activity: NamespaceActivity,
    condition: RecordCondition,
}

impl RecordInventory {
    pub fn record_path(&self) -> &RecordPath {
        &self.record_path
    }

    pub const fn activity(&self) -> NamespaceActivity {
        self.activity
    }

    pub const fn condition(&self) -> RecordCondition {
        self.condition
    }

    /// Only a compatible record in the selected namespace may participate in authentication.
    pub const fn is_authentication_candidate(&self) -> bool {
        matches!(self.activity, NamespaceActivity::Active)
            && matches!(self.condition, RecordCondition::Compatible)
    }
}

/// An operator-selected scope for a future purge implementation.
///
/// This type only identifies inventory entries; it never removes anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PurgeTarget {
    Namespace(RecordNamespace),
    InactiveNamespaces,
}

impl PurgeTarget {
    pub fn for_mode(mode: EmbeddingSecurityMode) -> Result<Self, StorageError> {
        RecordNamespace::try_from(mode).map(Self::Namespace)
    }

    pub const fn selects(self, inventory: &RecordInventory) -> bool {
        match self {
            Self::Namespace(namespace) => inventory.record_path.namespace as u8 == namespace as u8,
            Self::InactiveNamespaces => {
                matches!(
                    inventory.activity,
                    NamespaceActivity::InactiveDiagnosticOnly
                )
            }
        }
    }
}

/// Result of selecting a mode relative to the previously selected mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitionActivation {
    RemainsSelected,
    ActivatesEmptyNamespace,
    ReactivatesCompatibleRecord,
    ActivatesIncompatibleRecord(RecordIncompatibility),
}

/// Frozen guarantee that selection never mutates enrollment files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransitionFilesystemEffects {
    pub imports: bool,
    pub deletes: bool,
    pub overwrites: bool,
}

impl TransitionFilesystemEffects {
    pub const NONE: Self = Self {
        imports: false,
        deletes: false,
        overwrites: false,
    };
}

/// Pure decision for a configuration mode transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransitionDecision {
    previous: RecordNamespace,
    selected: RecordNamespace,
    selected_condition: RecordCondition,
    activation: TransitionActivation,
}

impl TransitionDecision {
    pub const fn previous(self) -> RecordNamespace {
        self.previous
    }

    pub const fn selected(self) -> RecordNamespace {
        self.selected
    }

    pub const fn selected_condition(self) -> RecordCondition {
        self.selected_condition
    }

    pub const fn activation(self) -> TransitionActivation {
        self.activation
    }

    pub const fn resulting_selection(self) -> NamespaceSelection {
        NamespaceSelection::new(self.selected)
    }

    pub const fn filesystem_effects(self) -> TransitionFilesystemEffects {
        TransitionFilesystemEffects::NONE
    }
}

/// Select a namespace without importing, deleting, or overwriting any record.
pub fn decide_namespace_transition(
    previous: EmbeddingSecurityMode,
    selected: EmbeddingSecurityMode,
    selected_condition: RecordCondition,
) -> Result<TransitionDecision, StorageError> {
    let previous = RecordNamespace::try_from(previous)?;
    let selected = RecordNamespace::try_from(selected)?;
    let activation = if previous == selected {
        TransitionActivation::RemainsSelected
    } else {
        match selected_condition {
            RecordCondition::Absent => TransitionActivation::ActivatesEmptyNamespace,
            RecordCondition::Compatible => TransitionActivation::ReactivatesCompatibleRecord,
            RecordCondition::Incompatible(reason) => {
                TransitionActivation::ActivatesIncompatibleRecord(reason)
            }
        }
    };

    Ok(TransitionDecision {
        previous,
        selected,
        selected_condition,
        activation,
    })
}
