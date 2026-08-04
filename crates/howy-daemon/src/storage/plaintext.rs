use std::collections::HashSet;
use std::ffi::CString;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Weak};
use std::sync::{Mutex, RwLock, TryLockError};
use std::time::Duration;

#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};

use howy_common::paths::MODELS_DIR;
use howy_common::storage::{
    ABSENT_GENERATION, AppendAdmissionShape, AppendRequest, AppendResult, AuthModel,
    AuthenticationCachePromotion, AuthenticationLoad, BackendHealth, BudgetPermit, CachedAuthModel,
    CancellationSignal, CandidatePresence, CanonicalUsername, ClearRequest, ClearResult,
    DecodedPlaintextRecord, EnrollmentAdmission, EnrollmentRecord, IoOperation,
    LegacySourceEncoding, MAX_ENTRIES, MAX_PLAINTEXT_BYTES, MetadataList, ModelDigest, ModelLease,
    OsRandomSource, OuterRecordClassification, OuterRecordStatus, PlaintextAllocationEstimate,
    PlaintextBudget, PlaintextRecordFormat, PromptOpaqueIdentity, PromptStorageSnapshot,
    RandomSource, ReloadResult, RemoveRequest, RemoveResult, STORAGE_DIRECTORY_MODE,
    STORAGE_RECORD_MODE, StorageBackend, StorageBackendError, StorageError, StorageIoError,
    checked_next_generation, decode_plaintext_record, encode_howypln1,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::cache::{ModelCache, ModelCacheLimits, UserSerializers};

const TEMP_CREATE_ATTEMPTS: usize = 16;
const CANCELLATION_LOCK_POLL: Duration = Duration::from_millis(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlaintextStorageLimits {
    max_entries: usize,
    max_record_bytes: usize,
}

impl PlaintextStorageLimits {
    pub fn new(max_entries: u32, max_record_bytes: u64) -> Result<Self, StorageBackendError> {
        let max_entries = usize::try_from(max_entries)
            .map_err(|_| StorageBackendError::InvalidInput("entry count limit"))?;
        let max_record_bytes = usize::try_from(max_record_bytes)
            .map_err(|_| StorageBackendError::InvalidInput("record byte limit"))?;
        if max_entries == 0 || max_entries > MAX_ENTRIES {
            return Err(StorageBackendError::InvalidInput("entry count limit"));
        }
        if max_record_bytes == 0 || max_record_bytes > MAX_PLAINTEXT_BYTES {
            return Err(StorageBackendError::InvalidInput("record byte limit"));
        }
        Ok(Self {
            max_entries,
            max_record_bytes,
        })
    }

    pub const fn max_entries(self) -> usize {
        self.max_entries
    }

    pub const fn max_record_bytes(self) -> usize {
        self.max_record_bytes
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectoryBehavior {
    /// Create missing components and set the final namespace directory to 0700.
    CreateOrFix,
    /// Require an existing directory already owned and permissioned as configured.
    RequireExisting,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileOwnerPolicy {
    Root,
    EffectiveUser,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlaintextBackendOptions {
    root: PathBuf,
    directory_behavior: DirectoryBehavior,
    owner_policy: FileOwnerPolicy,
}

impl PlaintextBackendOptions {
    pub fn production() -> Self {
        Self {
            root: PathBuf::from(MODELS_DIR),
            directory_behavior: DirectoryBehavior::CreateOrFix,
            owner_policy: FileOwnerPolicy::Root,
        }
    }

    /// Explicit path override for tests and isolated tooling. This policy never
    /// requires UID 0 and therefore must not be used for production storage.
    pub fn path_override(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            directory_behavior: DirectoryBehavior::CreateOrFix,
            owner_policy: FileOwnerPolicy::EffectiveUser,
        }
    }

    pub fn with_directory_behavior(mut self, behavior: DirectoryBehavior) -> Self {
        self.directory_behavior = behavior;
        self
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}

pub struct PlaintextStorageBackend {
    root: PathBuf,
    directory: File,
    expected_owner: u32,
    recognizer_model: ModelDigest,
    limits: PlaintextStorageLimits,
    operation_reservation_bytes: usize,
    cache: Arc<ModelCache>,
    promotion_authority: Arc<PlaintextPromotionAuthority>,
    serializers: UserSerializers,
    reload_gate: RwLock<()>,
    random: Mutex<Box<dyn RandomSource + Send>>,
    prompt_backend_identity: PromptOpaqueIdentity,
    #[cfg(test)]
    load_count: AtomicUsize,
}

struct PlaintextPromotionAuthority {
    backend_identity: PromptOpaqueIdentity,
    cache: Weak<ModelCache>,
}

struct PlaintextCachePromotion {
    authority: Weak<PlaintextPromotionAuthority>,
    expected_backend_identity: PromptOpaqueIdentity,
    username: CanonicalUsername,
    expected_revision: u128,
    expected_generation: u64,
    model: CachedAuthModel,
}

impl AuthenticationCachePromotion for PlaintextCachePromotion {
    fn promote_if(
        self: Box<Self>,
        publish: &mut dyn FnMut() -> bool,
    ) -> Result<bool, StorageBackendError> {
        let Some(authority) = self.authority.upgrade() else {
            return Ok(false);
        };
        if authority.backend_identity != self.expected_backend_identity {
            return Ok(false);
        }
        let Some(cache) = authority.cache.upgrade() else {
            return Ok(false);
        };
        cache.insert_provisional_if_revision(
            self.username,
            self.expected_revision,
            self.expected_generation,
            self.model,
            publish,
        )
    }
}

impl std::fmt::Debug for PlaintextStorageBackend {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PlaintextStorageBackend")
            .field("root", &self.root)
            .field("expected_owner", &self.expected_owner)
            .field("recognizer_model", &self.recognizer_model)
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl PlaintextStorageBackend {
    pub fn production(
        recognizer_model: ModelDigest,
        limits: PlaintextStorageLimits,
        cache_limits: ModelCacheLimits,
        budget: PlaintextBudget,
    ) -> Result<Self, StorageBackendError> {
        Self::new(
            PlaintextBackendOptions::production(),
            recognizer_model,
            limits,
            cache_limits,
            budget,
        )
    }

    pub fn new(
        options: PlaintextBackendOptions,
        recognizer_model: ModelDigest,
        limits: PlaintextStorageLimits,
        cache_limits: ModelCacheLimits,
        budget: PlaintextBudget,
    ) -> Result<Self, StorageBackendError> {
        Self::new_with_random(
            options,
            recognizer_model,
            limits,
            cache_limits,
            budget,
            Box::new(OsRandomSource),
        )
    }

    fn new_with_random(
        options: PlaintextBackendOptions,
        recognizer_model: ModelDigest,
        limits: PlaintextStorageLimits,
        cache_limits: ModelCacheLimits,
        budget: PlaintextBudget,
        random: Box<dyn RandomSource + Send>,
    ) -> Result<Self, StorageBackendError> {
        if matches!(options.owner_policy, FileOwnerPolicy::Root)
            && options.root != Path::new(MODELS_DIR)
        {
            return Err(StorageBackendError::InvalidInput("production storage root"));
        }
        if matches!(options.directory_behavior, DirectoryBehavior::CreateOrFix) {
            let mut builder = DirBuilder::new();
            builder.recursive(true).mode(STORAGE_DIRECTORY_MODE);
            builder
                .create(&options.root)
                .map_err(|error| io_error(IoOperation::Create, error))?;
        }
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(&options.root)
            .map_err(|error| io_error(IoOperation::Open, error))?;
        if matches!(options.directory_behavior, DirectoryBehavior::CreateOrFix) {
            // SAFETY: directory is a live owned descriptor and mode has no pointer arguments.
            if unsafe { libc::fchmod(directory.as_raw_fd(), STORAGE_DIRECTORY_MODE) } != 0 {
                return Err(io_error(IoOperation::Create, io::Error::last_os_error()));
            }
        }
        let expected_owner = match options.owner_policy {
            FileOwnerPolicy::Root => 0,
            FileOwnerPolicy::EffectiveUser => {
                // SAFETY: geteuid has no arguments and no failure condition.
                unsafe { libc::geteuid() }
            }
        };
        validate_metadata(
            &directory
                .metadata()
                .map_err(|error| io_error(IoOperation::Inspect, error))?,
            true,
            expected_owner,
            STORAGE_DIRECTORY_MODE,
        )?;
        let operation_reservation_bytes = PlaintextAllocationEstimate::for_plaintext_limits(
            limits.max_record_bytes,
            limits.max_entries,
        )?
        .peak_bytes();
        let prompt_backend_identity = new_prompt_backend_identity()?;
        let cache = Arc::new(ModelCache::new(cache_limits, budget));
        let promotion_authority = Arc::new(PlaintextPromotionAuthority {
            backend_identity: prompt_backend_identity,
            cache: Arc::downgrade(&cache),
        });
        Ok(Self {
            root: options.root,
            directory,
            expected_owner,
            recognizer_model,
            limits,
            operation_reservation_bytes,
            cache,
            promotion_authority,
            serializers: UserSerializers::default(),
            reload_gate: RwLock::new(()),
            random: Mutex::new(random),
            prompt_backend_identity,
            #[cfg(test)]
            load_count: AtomicUsize::new(0),
        })
    }

    fn operation_permit(&self) -> Result<BudgetPermit, StorageBackendError> {
        self.cache
            .reserve_operation(self.operation_reservation_bytes)
    }

    #[cfg(test)]
    pub(crate) fn cached_generation_for_test(&self, username: &CanonicalUsername) -> Option<u64> {
        self.cache.get(username).map(|lease| lease.generation())
    }

    #[cfg(test)]
    pub(crate) fn load_count_for_test(&self) -> usize {
        self.load_count.load(Ordering::Relaxed)
    }

    fn cache_committed_model(
        &self,
        username: &CanonicalUsername,
        model: AuthModel,
        operation: BudgetPermit,
    ) {
        let bytes = model.plaintext_bytes();
        if let Ok(permit) = operation.shrink_to(bytes) {
            let _ = self.cache.insert(username.clone(), model, permit);
        }
    }

    fn filename(username: &CanonicalUsername, extension: &str) -> CString {
        CString::new(format!("{}.{extension}", username.as_str()))
            .expect("canonical usernames and static extensions contain no NUL")
    }

    fn open_record(&self, name: &CString) -> io::Result<File> {
        // SAFETY: the directory descriptor and NUL-terminated relative name are
        // live for the call. On success ownership of the new descriptor moves to File.
        let fd = unsafe {
            libc::openat(
                self.directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            // SAFETY: openat returned a new owned descriptor.
            Ok(unsafe { File::from_raw_fd(fd) })
        }
    }

    fn validate_record_file(&self, file: &File) -> Result<u64, StorageBackendError> {
        let metadata = file
            .metadata()
            .map_err(|error| io_error(IoOperation::Inspect, error))?;
        validate_metadata(&metadata, false, self.expected_owner, STORAGE_RECORD_MODE)?;
        if metadata.len() == 0
            || metadata.len()
                > u64::try_from(self.limits.max_record_bytes)
                    .map_err(|_| StorageBackendError::InvalidInput("record byte limit"))?
        {
            return Err(StorageBackendError::Corrupt);
        }
        Ok(metadata.len())
    }

    fn read_source(&self, file: File) -> Result<Zeroizing<Vec<u8>>, StorageBackendError> {
        let size = self.validate_record_file(&file)?;
        let capacity = usize::try_from(size).map_err(|_| StorageBackendError::Corrupt)?;
        let mut bytes = Zeroizing::new(Vec::new());
        bytes
            .try_reserve_exact(capacity)
            .map_err(|_| StorageBackendError::InvalidInput("record allocation"))?;
        let read_limit = u64::try_from(self.limits.max_record_bytes)
            .map_err(|_| StorageBackendError::InvalidInput("record byte limit"))?
            .saturating_add(1);
        file.take(read_limit)
            .read_to_end(&mut bytes)
            .map_err(|error| io_error(IoOperation::Read, error))?;
        if bytes.len() != capacity || bytes.len() > self.limits.max_record_bytes {
            return Err(StorageBackendError::Corrupt);
        }
        Ok(bytes)
    }

    fn read_source_cancellable(
        &self,
        mut file: File,
        cancellation: &dyn CancellationSignal,
    ) -> Result<Zeroizing<Vec<u8>>, StorageBackendError> {
        let size = self.validate_record_file(&file)?;
        let capacity = usize::try_from(size).map_err(|_| StorageBackendError::Corrupt)?;
        let mut bytes = Zeroizing::new(Vec::new());
        bytes
            .try_reserve_exact(capacity)
            .map_err(|_| StorageBackendError::InvalidInput("record allocation"))?;
        let mut chunk = [0u8; 8192];
        while bytes.len() < capacity {
            if cancellation.is_cancelled() {
                return Err(StorageBackendError::Unavailable);
            }
            let remaining = capacity - bytes.len();
            let amount = remaining.min(chunk.len());
            let read = file
                .read(&mut chunk[..amount])
                .map_err(|error| io_error(IoOperation::Read, error))?;
            if read == 0 {
                return Err(StorageBackendError::Corrupt);
            }
            bytes.extend_from_slice(&chunk[..read]);
        }
        if cancellation.is_cancelled() {
            return Err(StorageBackendError::Unavailable);
        }
        let mut extra = [0u8; 1];
        if file
            .read(&mut extra)
            .map_err(|error| io_error(IoOperation::Read, error))?
            != 0
        {
            return Err(StorageBackendError::Corrupt);
        }
        Ok(bytes)
    }

    fn load_record(
        &self,
        username: &CanonicalUsername,
    ) -> Result<DecodedPlaintextRecord, StorageBackendError> {
        #[cfg(test)]
        self.load_count.fetch_add(1, Ordering::Relaxed);
        let authoritative = Self::filename(username, "bin");
        let (file, encoding) = match self.open_record(&authoritative) {
            Ok(file) => (file, LegacySourceEncoding::BincodeThenJson),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let legacy = Self::filename(username, "json");
                match self.open_record(&legacy) {
                    Ok(file) => (file, LegacySourceEncoding::JsonOnly),
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        return Err(StorageBackendError::Absent);
                    }
                    Err(error) => return Err(io_error(IoOperation::Open, error)),
                }
            }
            Err(error) => return Err(io_error(IoOperation::Open, error)),
        };
        let bytes = self.read_source(file)?;
        decode_plaintext_record(
            &bytes,
            encoding,
            username,
            self.recognizer_model,
            self.limits.max_entries,
        )
        .map_err(map_storage_error)
    }

    fn load_record_cancellable(
        &self,
        username: &CanonicalUsername,
        cancellation: &dyn CancellationSignal,
    ) -> Result<DecodedPlaintextRecord, StorageBackendError> {
        if cancellation.is_cancelled() {
            return Err(StorageBackendError::Unavailable);
        }
        #[cfg(test)]
        self.load_count.fetch_add(1, Ordering::Relaxed);
        let authoritative = Self::filename(username, "bin");
        let (file, encoding) = match self.open_record(&authoritative) {
            Ok(file) => (file, LegacySourceEncoding::BincodeThenJson),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let legacy = Self::filename(username, "json");
                match self.open_record(&legacy) {
                    Ok(file) => (file, LegacySourceEncoding::JsonOnly),
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        return Err(StorageBackendError::Absent);
                    }
                    Err(error) => return Err(io_error(IoOperation::Open, error)),
                }
            }
            Err(error) => return Err(io_error(IoOperation::Open, error)),
        };
        let bytes = self.read_source_cancellable(file, cancellation)?;
        if cancellation.is_cancelled() {
            return Err(StorageBackendError::Unavailable);
        }
        let record = decode_plaintext_record(
            &bytes,
            encoding,
            username,
            self.recognizer_model,
            self.limits.max_entries,
        )
        .map_err(map_storage_error)?;
        if cancellation.is_cancelled() {
            Err(StorageBackendError::Unavailable)
        } else {
            Ok(record)
        }
    }

    fn inspect_prompt_candidate(
        &self,
        username: &CanonicalUsername,
    ) -> Result<CandidatePresence, StorageBackendError> {
        let authoritative = Self::filename(username, "bin");
        let (file, path_kind) = match self.open_record(&authoritative) {
            Ok(file) => (file, b"bin".as_slice()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let fallback = Self::filename(username, "json");
                match self.open_record(&fallback) {
                    Ok(file) => (file, b"json".as_slice()),
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        return Ok(CandidatePresence::Absent);
                    }
                    Err(error) => return Err(io_error(IoOperation::Open, error)),
                }
            }
            Err(error) => return Err(io_error(IoOperation::Open, error)),
        };
        self.validate_record_file(&file)?;
        let metadata = file
            .metadata()
            .map_err(|error| io_error(IoOperation::Inspect, error))?;

        // Prompt preflight deliberately does not read record bytes. Under the
        // production trust model only root can mutate these root-owned 0600
        // files, and root can bypass any file identity check anyway. An
        // unprivileged same-UID client cannot preserve this descriptor identity
        // while changing payload bytes. The selected path kind plus complete
        // descriptor metadata catches normal writes and path replacement while
        // retaining .bin preference and .json fallback.
        let generation = prompt_metadata_generation(
            path_kind,
            &metadata,
            self.prompt_backend_identity,
            self.recognizer_model,
        );
        Ok(CandidatePresence::Candidate { generation })
    }

    fn next_mutation_generation(
        loaded: &DecodedPlaintextRecord,
    ) -> Result<u64, StorageBackendError> {
        match loaded.format() {
            PlaintextRecordFormat::Legacy => Ok(1),
            PlaintextRecordFormat::HowyPln1 => {
                checked_next_generation(loaded.record().generation()).map_err(map_storage_error)
            }
        }
    }

    fn write_record(&self, record: &EnrollmentRecord) -> Result<(), StorageBackendError> {
        let encoded = encode_howypln1(record).map_err(map_storage_error)?;
        if encoded.len() > self.limits.max_record_bytes {
            return Err(StorageBackendError::InvalidInput("record byte length"));
        }
        let destination = Self::filename(record.username(), "bin");
        let mut last_collision = None;
        for _ in 0..TEMP_CREATE_ATTEMPTS {
            let suffix = self.random_temp_suffix()?;
            let temporary =
                CString::new(format!(".{}.tmp.{suffix}", destination.to_string_lossy()))
                    .expect("generated temporary name contains no NUL");
            match self.create_temp(&temporary) {
                Ok(mut file) => {
                    let result = (|| {
                        encoded
                            .write_to(&mut file)
                            .map_err(|error| io_error(IoOperation::Write, error))?;
                        file.sync_all()
                            .map_err(|error| io_error(IoOperation::Sync, error))?;
                        drop(file);
                        rename_at(self.directory.as_raw_fd(), &temporary, &destination)
                            .map_err(|error| io_error(IoOperation::Rename, error))?;
                        self.directory
                            .sync_all()
                            .map_err(|error| io_error(IoOperation::Sync, error))
                    })();
                    if result.is_err() {
                        let _ = unlink_at(self.directory.as_raw_fd(), &temporary);
                    }
                    return result;
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    last_collision = Some(error);
                }
                Err(error) => {
                    let _ = unlink_at(self.directory.as_raw_fd(), &temporary);
                    return Err(io_error(IoOperation::Create, error));
                }
            }
        }
        Err(io_error(
            IoOperation::Create,
            last_collision.unwrap_or_else(|| io::Error::from(io::ErrorKind::AlreadyExists)),
        ))
    }

    fn random_temp_suffix(&self) -> Result<String, StorageBackendError> {
        let mut nonce = [0u8; 16];
        {
            let mut random = self
                .random
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            random
                .fill_bytes(&mut nonce)
                .map_err(|_| StorageBackendError::Unavailable)?;
        }
        Ok(hex_lower(&nonce))
    }

    fn create_temp(&self, name: &CString) -> io::Result<File> {
        // SAFETY: arguments are valid and the returned descriptor is uniquely owned.
        let fd = unsafe {
            libc::openat(
                self.directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                STORAGE_RECORD_MODE,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: openat returned a new owned descriptor.
        let file = unsafe { File::from_raw_fd(fd) };
        // SAFETY: file is a live descriptor and fchmod has no pointer arguments.
        if unsafe { libc::fchmod(file.as_raw_fd(), STORAGE_RECORD_MODE) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let metadata = file.metadata()?;
        validate_metadata_io(&metadata, false, self.expected_owner, STORAGE_RECORD_MODE)?;
        Ok(file)
    }

    fn optional_valid_record(&self, name: &CString) -> Result<bool, StorageBackendError> {
        match self.open_record(name) {
            Ok(file) => {
                let metadata = file
                    .metadata()
                    .map_err(|error| io_error(IoOperation::Inspect, error))?;
                validate_metadata(&metadata, false, self.expected_owner, STORAGE_RECORD_MODE)?;
                Ok(true)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(io_error(IoOperation::Open, error)),
        }
    }

    fn append_with_operation(
        &self,
        request: AppendRequest<'_>,
        operation: BudgetPermit,
    ) -> Result<AppendResult, StorageBackendError> {
        self.append_with_operation_after_user(request, operation, || {})
    }

    fn append_with_operation_after_user(
        &self,
        request: AppendRequest<'_>,
        operation: BudgetPermit,
        after_user_lock: impl FnOnce(),
    ) -> Result<AppendResult, StorageBackendError> {
        if !self.cache.owns_permit(&operation)
            || operation.bytes() < self.operation_reservation_bytes
        {
            return Err(StorageBackendError::InvalidInput(
                "append operation reservation",
            ));
        }
        let _reload = self
            .reload_gate
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let serializer = self.serializers.for_user(request.username());
        let _user = serializer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        after_user_lock();
        self.cache.invalidate(request.username());
        let loaded = match self.load_record(request.username()) {
            Ok(loaded) => Some(loaded),
            Err(StorageBackendError::Absent) => None,
            Err(error) => return Err(error),
        };
        let current_generation = loaded
            .as_ref()
            .map_or(ABSENT_GENERATION, |value| value.record().generation());
        if current_generation != request.expected_generation() {
            return Err(StorageBackendError::Conflict { current_generation });
        }
        let total = loaded
            .as_ref()
            .map_or(0, |value| value.record().entries().len())
            .checked_add(request.entries().len())
            .ok_or(StorageBackendError::InvalidInput("entry count"))?;
        if total > self.limits.max_entries {
            return Err(StorageBackendError::InvalidInput("entry count"));
        }
        let generation = match loaded.as_ref() {
            Some(value) => Self::next_mutation_generation(value)?,
            None => 1,
        };
        let mut entries = loaded
            .map(|value| value.into_record().into_entries())
            .unwrap_or_default();
        entries.extend_from_slice(request.entries());
        let record = EnrollmentRecord::new(
            generation,
            self.recognizer_model,
            request.username().clone(),
            entries,
        )
        .map_err(map_mutation_record_error)?;
        let model = AuthModel::from_record(&record)?;
        self.write_record(&record)?;
        let result = AppendResult::new(generation, request.entries().len(), total);
        drop(record);
        self.cache_committed_model(request.username(), model, operation);
        Ok(result)
    }

    fn authenticate_after_reload(
        &self,
        username: &CanonicalUsername,
        after_reload_lock: impl FnOnce(),
    ) -> Result<ModelLease, StorageBackendError> {
        let _reload = self
            .reload_gate
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        after_reload_lock();
        if let Some(lease) = self.cache.get(username) {
            return Ok(lease);
        }
        let serializer = self.serializers.for_user(username);
        let _user = serializer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(lease) = self.cache.get(username) {
            return Ok(lease);
        }
        let operation = self.operation_permit()?;
        let loaded = self.load_record(username)?;
        if loaded.record().entries().is_empty() {
            return Err(StorageBackendError::Absent);
        }
        let model = AuthModel::from_record(loaded.record())?;
        let model_bytes = model.plaintext_bytes();
        drop(loaded);
        let permit = operation.shrink_to(model_bytes)?;
        self.cache.insert(username.clone(), model, permit)
    }
}

impl StorageBackend for PlaintextStorageBackend {
    fn prompt_snapshot(
        &self,
        username: &CanonicalUsername,
    ) -> Result<PromptStorageSnapshot, StorageBackendError> {
        let _reload = self
            .reload_gate
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let serializer = self.serializers.for_user(username);
        let _user = serializer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let candidate = self.inspect_prompt_candidate(username)?;
        Ok(PromptStorageSnapshot::new(
            BackendHealth::Ready,
            candidate,
            self.prompt_backend_identity,
            PromptOpaqueIdentity::new(self.recognizer_model.into_bytes()),
        ))
    }

    fn candidate_presence(
        &self,
        username: &CanonicalUsername,
    ) -> Result<CandidatePresence, StorageBackendError> {
        let _permit = self.operation_permit()?;
        match self.load_record(username) {
            Ok(loaded) if loaded.record().entries().is_empty() => Ok(CandidatePresence::Absent),
            Ok(loaded) => Ok(CandidatePresence::Candidate {
                generation: loaded.record().generation(),
            }),
            Err(StorageBackendError::Absent) => Ok(CandidatePresence::Absent),
            Err(error) => Err(error),
        }
    }

    fn authenticate(
        &self,
        username: &CanonicalUsername,
    ) -> Result<ModelLease, StorageBackendError> {
        self.authenticate_after_reload(username, || {})
    }

    fn authenticate_cancellable(
        &self,
        username: &CanonicalUsername,
        cancellation: &dyn CancellationSignal,
    ) -> Result<ModelLease, StorageBackendError> {
        let reload = loop {
            if cancellation.is_cancelled() {
                return Err(StorageBackendError::Unavailable);
            }
            match self.reload_gate.try_read() {
                Ok(guard) => break guard,
                Err(TryLockError::WouldBlock) => {
                    std::thread::sleep(CANCELLATION_LOCK_POLL);
                }
                Err(TryLockError::Poisoned(poisoned)) => break poisoned.into_inner(),
            }
        };
        if let Some(lease) = self.cache.get(username) {
            if cancellation.is_cancelled() {
                drop(lease);
                return Err(StorageBackendError::Unavailable);
            }
            return Ok(lease);
        }
        let serializer = self.serializers.for_user(username);
        let user = loop {
            if cancellation.is_cancelled() {
                return Err(StorageBackendError::Unavailable);
            }
            match serializer.try_lock() {
                Ok(guard) => break guard,
                Err(TryLockError::WouldBlock) => {
                    std::thread::sleep(CANCELLATION_LOCK_POLL);
                }
                Err(TryLockError::Poisoned(poisoned)) => break poisoned.into_inner(),
            }
        };
        if let Some(lease) = self.cache.get(username) {
            drop((user, reload));
            if cancellation.is_cancelled() {
                drop(lease);
                return Err(StorageBackendError::Unavailable);
            }
            return Ok(lease);
        }
        let operation = self.operation_permit()?;
        let loaded = self.load_record_cancellable(username, cancellation)?;
        if loaded.record().entries().is_empty() {
            return Err(StorageBackendError::Absent);
        }
        let model = AuthModel::from_record(loaded.record())?;
        let model_bytes = model.plaintext_bytes();
        drop(loaded);
        if cancellation.is_cancelled() {
            return Err(StorageBackendError::Unavailable);
        }
        let permit = operation.shrink_to(model_bytes)?;
        if cancellation.is_cancelled() {
            return Err(StorageBackendError::Unavailable);
        }
        let lease = self.cache.insert(username.clone(), model, permit)?;
        if cancellation.is_cancelled() {
            self.cache.invalidate(username);
            drop(lease);
            drop((user, reload));
            Err(StorageBackendError::Unavailable)
        } else {
            drop((user, reload));
            Ok(lease)
        }
    }

    fn authenticate_active(
        &self,
        username: &CanonicalUsername,
        cancellation: &dyn CancellationSignal,
    ) -> Result<AuthenticationLoad, StorageBackendError> {
        let reload = loop {
            if cancellation.is_cancelled() {
                return Err(StorageBackendError::Unavailable);
            }
            match self.reload_gate.try_read() {
                Ok(guard) => break guard,
                Err(TryLockError::WouldBlock) => {
                    std::thread::sleep(CANCELLATION_LOCK_POLL);
                }
                Err(TryLockError::Poisoned(poisoned)) => break poisoned.into_inner(),
            }
        };
        if let Some(lease) = self.cache.get(username) {
            if cancellation.is_cancelled() {
                drop(lease);
                return Err(StorageBackendError::Unavailable);
            }
            return Ok(AuthenticationLoad::committed(lease));
        }
        let serializer = self.serializers.for_user(username);
        let user = loop {
            if cancellation.is_cancelled() {
                return Err(StorageBackendError::Unavailable);
            }
            match serializer.try_lock() {
                Ok(guard) => break guard,
                Err(TryLockError::WouldBlock) => {
                    std::thread::sleep(CANCELLATION_LOCK_POLL);
                }
                Err(TryLockError::Poisoned(poisoned)) => break poisoned.into_inner(),
            }
        };
        if let Some(lease) = self.cache.get(username) {
            drop((user, reload));
            if cancellation.is_cancelled() {
                drop(lease);
                return Err(StorageBackendError::Unavailable);
            }
            return Ok(AuthenticationLoad::committed(lease));
        }

        let operation = self.operation_permit()?;
        let expected_revision = self.cache.revision();
        let loaded = self.load_record_cancellable(username, cancellation)?;
        if loaded.record().entries().is_empty() {
            return Err(StorageBackendError::Absent);
        }
        let model = AuthModel::from_record(loaded.record())?;
        let expected_generation = model.generation();
        let model_bytes = model.plaintext_bytes();
        drop(loaded);
        if cancellation.is_cancelled() {
            return Err(StorageBackendError::Unavailable);
        }
        let permit = operation.shrink_to(model_bytes)?;
        let provisional = CachedAuthModel::new(model, permit)?;
        let lease = provisional.lease();
        let promotion = Box::new(PlaintextCachePromotion {
            authority: Arc::downgrade(&self.promotion_authority),
            expected_backend_identity: self.prompt_backend_identity,
            username: username.clone(),
            expected_revision,
            expected_generation,
            model: provisional,
        });
        if cancellation.is_cancelled() {
            drop((promotion, lease, user, reload));
            return Err(StorageBackendError::Unavailable);
        }
        drop((user, reload));
        Ok(AuthenticationLoad::provisional(lease, promotion))
    }

    fn list_metadata(
        &self,
        username: &CanonicalUsername,
    ) -> Result<MetadataList, StorageBackendError> {
        let _permit = self.operation_permit()?;
        self.load_record(username)
            .map(|loaded| MetadataList::from_record(loaded.record()))
    }

    fn append(&self, request: AppendRequest<'_>) -> Result<AppendResult, StorageBackendError> {
        let operation = self.operation_permit()?;
        self.append_with_operation(request, operation)
    }

    fn admit_enrollment(
        &self,
        username: &CanonicalUsername,
        plaintext_bytes: usize,
        _append_shape: AppendAdmissionShape,
    ) -> Result<EnrollmentAdmission, StorageBackendError> {
        self.cache.reserve_enrollment_for_user(
            self.operation_reservation_bytes,
            plaintext_bytes,
            username,
        )
    }

    fn append_admitted(
        &self,
        request: AppendRequest<'_>,
        operation: BudgetPermit,
    ) -> Result<AppendResult, StorageBackendError> {
        self.append_with_operation(request, operation)
    }

    fn remove(&self, request: RemoveRequest<'_>) -> Result<RemoveResult, StorageBackendError> {
        let _reload = self
            .reload_gate
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let serializer = self.serializers.for_user(request.username());
        let _user = serializer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.cache.invalidate(request.username());
        let operation = self.operation_permit()?;
        let loaded = match self.load_record(request.username()) {
            Ok(loaded) => loaded,
            Err(StorageBackendError::Absent) => {
                return Err(StorageBackendError::Conflict {
                    current_generation: ABSENT_GENERATION,
                });
            }
            Err(error) => return Err(error),
        };
        if loaded.record().generation() != request.expected_generation() {
            return Err(StorageBackendError::Conflict {
                current_generation: loaded.record().generation(),
            });
        }
        let Some(index) = loaded
            .record()
            .entries()
            .iter()
            .position(|entry| entry.enrollment_id() == request.enrollment_id())
        else {
            return Err(StorageBackendError::Conflict {
                current_generation: loaded.record().generation(),
            });
        };
        let generation = Self::next_mutation_generation(&loaded)?;
        let mut entries = loaded.into_record().into_entries();
        entries.remove(index);
        let record = EnrollmentRecord::new(
            generation,
            self.recognizer_model,
            request.username().clone(),
            entries,
        )
        .map_err(map_mutation_record_error)?;
        let model = if record.entries().is_empty() {
            None
        } else {
            Some(AuthModel::from_record(&record)?)
        };
        self.write_record(&record)?;
        let result = RemoveResult::new(generation, request.enrollment_id());
        drop(record);
        if let Some(model) = model {
            self.cache_committed_model(request.username(), model, operation);
        }
        Ok(result)
    }

    fn clear(&self, request: ClearRequest<'_>) -> Result<ClearResult, StorageBackendError> {
        let _reload = self
            .reload_gate
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let serializer = self.serializers.for_user(request.username());
        let _user = serializer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.cache.invalidate(request.username());
        let _permit = self.operation_permit()?;
        let loaded = match self.load_record(request.username()) {
            Ok(loaded) => loaded,
            Err(StorageBackendError::Absent) => {
                return Err(StorageBackendError::Conflict {
                    current_generation: ABSENT_GENERATION,
                });
            }
            Err(error) => return Err(error),
        };
        if loaded.record().generation() != request.expected_generation() {
            return Err(StorageBackendError::Conflict {
                current_generation: loaded.record().generation(),
            });
        }
        let authoritative = Self::filename(request.username(), "bin");
        let fallback = Self::filename(request.username(), "json");
        let authoritative_exists = self.optional_valid_record(&authoritative)?;
        let fallback_exists = self.optional_valid_record(&fallback)?;
        clear_fallback_before_authoritative(
            fallback_exists,
            authoritative_exists,
            |is_fallback| {
                let name = if is_fallback {
                    &fallback
                } else {
                    &authoritative
                };
                unlink_at(self.directory.as_raw_fd(), name)
                    .map_err(|error| io_error(IoOperation::Remove, error))
            },
            || {
                self.directory
                    .sync_all()
                    .map_err(|error| io_error(IoOperation::Sync, error))
            },
        )?;
        Ok(ClearResult::new(loaded.record().entries().len()))
    }

    fn reload(&self) -> Result<ReloadResult, StorageBackendError> {
        let _reload = self
            .reload_gate
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.cache.clear();
        let mut usernames = HashSet::new();
        let entries =
            fs::read_dir(&self.root).map_err(|error| io_error(IoOperation::Read, error))?;
        for entry in entries {
            let entry = entry.map_err(|error| io_error(IoOperation::Read, error))?;
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            let username = name
                .strip_suffix(".bin")
                .or_else(|| name.strip_suffix(".json"));
            if let Some(username) = username.and_then(|value| CanonicalUsername::new(value).ok()) {
                usernames.insert(username);
            }
        }
        let mut records = Vec::with_capacity(usernames.len());
        for username in usernames {
            let _permit = self.operation_permit()?;
            let classification = match self.load_record(&username) {
                Ok(loaded) => OuterRecordClassification::Candidate {
                    generation: loaded.record().generation(),
                },
                Err(StorageBackendError::Absent) => continue,
                Err(StorageBackendError::ModelMismatch) => OuterRecordClassification::ModelMismatch,
                Err(_) => OuterRecordClassification::Corrupt,
            };
            records.push(OuterRecordStatus::new(username, classification));
        }
        records.sort_by(|left, right| left.username().as_str().cmp(right.username().as_str()));
        Ok(ReloadResult::new(BackendHealth::Ready, records))
    }

    fn health(&self) -> BackendHealth {
        BackendHealth::Ready
    }

    fn verify_record(
        &self,
        username: &CanonicalUsername,
    ) -> Result<MetadataList, StorageBackendError> {
        self.list_metadata(username)
    }
}

fn validate_metadata(
    metadata: &fs::Metadata,
    directory: bool,
    expected_owner: u32,
    expected_mode: u32,
) -> Result<(), StorageBackendError> {
    validate_metadata_io(metadata, directory, expected_owner, expected_mode)
        .map_err(|error| io_error(IoOperation::Inspect, error))
}

fn prompt_metadata_generation(
    path_kind: &[u8],
    metadata: &fs::Metadata,
    backend_identity: PromptOpaqueIdentity,
    recognizer_model: ModelDigest,
) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(b"howy-mode0-prompt-metadata-v1\0");
    hasher.update(b"plaintext\0");
    hasher.update((path_kind.len() as u64).to_le_bytes());
    hasher.update(path_kind);
    hasher.update(metadata.dev().to_le_bytes());
    hasher.update(metadata.ino().to_le_bytes());
    hasher.update(metadata.len().to_le_bytes());
    hasher.update(metadata.ctime().to_le_bytes());
    hasher.update(metadata.ctime_nsec().to_le_bytes());
    hasher.update(metadata.mtime().to_le_bytes());
    hasher.update(metadata.mtime_nsec().to_le_bytes());
    hasher.update(metadata.uid().to_le_bytes());
    hasher.update(metadata.gid().to_le_bytes());
    hasher.update(metadata.mode().to_le_bytes());
    hasher.update(backend_identity.into_bytes());
    hasher.update(recognizer_model.into_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    u64::from_le_bytes(bytes).max(1)
}

fn validate_metadata_io(
    metadata: &fs::Metadata,
    directory: bool,
    expected_owner: u32,
    expected_mode: u32,
) -> io::Result<()> {
    let correct_type = if directory {
        metadata.is_dir()
    } else {
        metadata.is_file()
    };
    if !correct_type
        || metadata.uid() != expected_owner
        || metadata.mode() & 0o7777 != expected_mode
    {
        return Err(io::Error::from(io::ErrorKind::PermissionDenied));
    }
    Ok(())
}

fn map_storage_error(error: StorageError) -> StorageBackendError {
    match error {
        StorageError::BindingMismatch("recognizer model") => StorageBackendError::ModelMismatch,
        StorageError::GenerationOverflow => StorageBackendError::GenerationOverflow,
        StorageError::AllocationFailed(_) => StorageBackendError::Unavailable,
        _ => StorageBackendError::Corrupt,
    }
}

fn map_mutation_record_error(error: StorageError) -> StorageBackendError {
    match error {
        StorageError::GenerationOverflow => StorageBackendError::GenerationOverflow,
        StorageError::AllocationFailed(_) => StorageBackendError::Unavailable,
        _ => StorageBackendError::InvalidInput("record"),
    }
}

fn io_error(operation: IoOperation, error: io::Error) -> StorageBackendError {
    StorageIoError::new(operation, &error).into()
}

fn new_prompt_backend_identity() -> Result<PromptOpaqueIdentity, StorageBackendError> {
    let mut random = OsRandomSource;
    for _ in 0..16 {
        let mut identity = [0u8; 32];
        random
            .fill_bytes(&mut identity)
            .map_err(|_| StorageBackendError::Unavailable)?;
        if identity.iter().any(|byte| *byte != 0) {
            return Ok(PromptOpaqueIdentity::new(identity));
        }
    }
    Err(StorageBackendError::Unavailable)
}

fn rename_at(directory: i32, old: &CString, new: &CString) -> io::Result<()> {
    // SAFETY: names are valid NUL-terminated relative paths and directory is live.
    if unsafe { libc::renameat(directory, old.as_ptr(), directory, new.as_ptr()) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn unlink_at(directory: i32, name: &CString) -> io::Result<()> {
    // SAFETY: name is a valid NUL-terminated relative path and directory is live.
    if unsafe { libc::unlinkat(directory, name.as_ptr(), 0) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn clear_fallback_before_authoritative<E>(
    fallback_exists: bool,
    authoritative_exists: bool,
    mut remove: impl FnMut(bool) -> Result<(), E>,
    mut sync_directory: impl FnMut() -> Result<(), E>,
) -> Result<(), E> {
    if fallback_exists {
        remove(true)?;
        sync_directory()?;
    }
    if authoritative_exists {
        remove(false)?;
        sync_directory()?;
    }
    Ok(())
}

fn hex_lower(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::fs::{self, OpenOptions, Permissions};
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink};
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier, mpsc};
    use std::time::Duration;
    use std::time::{SystemTime, UNIX_EPOCH};

    use howy_common::face::{FaceModel, UserModels};
    use howy_common::storage::{
        ABSENT_GENERATION, AppendRequest, CancellationSignal, CandidatePresence, ClearRequest,
        EMBEDDING_DIMENSION, EnrollmentEntry, EnrollmentId, EnrollmentRecord, IoOperation,
        LeaseKind, ModelDigest, OuterRecordClassification, RemoveRequest, StorageBackend,
        StorageBackendError, decode_howypln1, encode_howypln1, legacy_generation,
    };

    use super::*;

    static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TempRoot(PathBuf);

    impl TempRoot {
        fn new() -> Self {
            let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "howy-mode0-test-{}-{nanos}-{counter}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, Permissions::from_mode(0o700)).unwrap();
            assert!(!path.starts_with("/etc"));
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }

        fn file(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn username(value: &str) -> CanonicalUsername {
        CanonicalUsername::new(value).unwrap()
    }

    fn model() -> ModelDigest {
        ModelDigest::new([0x42; 32])
    }

    fn limits() -> PlaintextStorageLimits {
        PlaintextStorageLimits::new(8, 64 * 1024).unwrap()
    }

    fn cache_limits() -> ModelCacheLimits {
        ModelCacheLimits::new(8, 4 * 1024 * 1024).unwrap()
    }

    fn backend(root: &TempRoot, budget: PlaintextBudget) -> PlaintextStorageBackend {
        PlaintextStorageBackend::new(
            PlaintextBackendOptions::path_override(root.path()),
            model(),
            limits(),
            cache_limits(),
            budget,
        )
        .unwrap()
    }

    fn roomy_backend(root: &TempRoot) -> PlaintextStorageBackend {
        backend(root, PlaintextBudget::new(4 * 1024 * 1024).unwrap())
    }

    fn entry(id: u8, label: &str) -> EnrollmentEntry {
        let mut embedding = [0.0; EMBEDDING_DIMENSION];
        embedding[usize::from(id) % EMBEDDING_DIMENSION] = 1.0;
        EnrollmentEntry::new(
            EnrollmentId::new([id; 16]).unwrap(),
            1_700_000_000 + u64::from(id),
            label,
            embedding,
        )
        .unwrap()
    }

    fn legacy(username: &str, labels: &[&str]) -> UserModels {
        UserModels {
            username: username.to_owned(),
            models: labels
                .iter()
                .enumerate()
                .map(|(index, label)| {
                    let mut embedding = vec![0.0; EMBEDDING_DIMENSION];
                    embedding[index] = 1.0;
                    FaceModel {
                        label: (*label).to_owned(),
                        created: 1_600_000_000 + index as u64,
                        embedding,
                    }
                })
                .collect(),
        }
    }

    fn write_private(path: &Path, bytes: &[u8]) {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
        file.set_permissions(Permissions::from_mode(0o600)).unwrap();
    }

    fn write_legacy_bin(root: &TempRoot, value: &UserModels) -> Vec<u8> {
        let bytes = bincode::serialize(value).unwrap();
        write_private(&root.file("alice.bin"), &bytes);
        bytes
    }

    fn write_legacy_json(root: &TempRoot, value: &UserModels) -> Vec<u8> {
        let bytes = serde_json::to_vec(value).unwrap();
        write_private(&root.file("alice.json"), &bytes);
        bytes
    }

    struct CancelAfterCalls {
        calls: AtomicUsize,
        cancel_at: usize,
    }

    struct NeverCancelled;

    impl CancellationSignal for NeverCancelled {
        fn is_cancelled(&self) -> bool {
            false
        }
    }

    impl CancellationSignal for CancelAfterCalls {
        fn is_cancelled(&self) -> bool {
            self.calls.fetch_add(1, Ordering::SeqCst) + 1 >= self.cancel_at
        }
    }

    #[test]
    fn cancellable_authentication_never_retains_a_new_mode0_lease_after_cancellation() {
        for cancel_at in 1..=8 {
            let root = TempRoot::new();
            write_legacy_bin(&root, &legacy("alice", &["one"]));
            let budget = PlaintextBudget::new(4 * 1024 * 1024).unwrap();
            let backend = backend(&root, budget.clone());
            let alice = username("alice");
            let cancellation = CancelAfterCalls {
                calls: AtomicUsize::new(0),
                cancel_at,
            };
            let result = backend.authenticate_cancellable(&alice, &cancellation);
            if cancellation.is_cancelled() {
                assert!(result.is_err(), "cancel_at={cancel_at}");
                assert!(backend.cache.get(&alice).is_none(), "cancel_at={cancel_at}");
                assert_eq!(budget.used(), 0, "cancel_at={cancel_at}");
            } else {
                drop(result.unwrap());
            }
        }
    }

    #[test]
    fn active_mode0_cold_load_stays_private_until_explicit_promotion() {
        let root = TempRoot::new();
        write_legacy_bin(&root, &legacy("alice", &["one"]));
        let budget = PlaintextBudget::new(4 * 1024 * 1024).unwrap();
        let backend = backend(&root, budget.clone());
        let alice = username("alice");

        let private = backend
            .authenticate_active(&alice, &NeverCancelled)
            .unwrap();
        assert!(backend.cache.get(&alice).is_none());
        assert!(budget.used() > 0);
        drop(private);
        assert!(backend.cache.get(&alice).is_none());
        assert_eq!(budget.used(), 0);

        let mut accepted = backend
            .authenticate_active(&alice, &NeverCancelled)
            .unwrap();
        let promotion = accepted
            .take_promotion()
            .expect("cold active load must be provisional");
        drop(accepted);
        assert!(promotion.promote().unwrap());
        let cached = backend.cache.get(&alice).unwrap();
        assert_eq!(cached.labels().collect::<Vec<_>>(), ["one"]);
        drop(cached);
        assert!(budget.used() > 0);
    }

    #[test]
    fn active_mode0_promotion_cannot_overwrite_concurrent_reader_or_reload() {
        let root = TempRoot::new();
        write_legacy_bin(&root, &legacy("alice", &["one"]));
        let backend = roomy_backend(&root);
        let alice = username("alice");

        let mut private = backend
            .authenticate_active(&alice, &NeverCancelled)
            .unwrap();
        let stale = private.take_promotion().unwrap();
        let committed = backend.authenticate(&alice).unwrap();
        assert!(!stale.promote().unwrap());
        assert_eq!(
            backend
                .cache
                .get(&alice)
                .unwrap()
                .labels()
                .collect::<Vec<_>>(),
            ["one"]
        );
        drop((private, committed));

        backend.cache.invalidate(&alice);
        let mut private = backend
            .authenticate_active(&alice, &NeverCancelled)
            .unwrap();
        let stale = private.take_promotion().unwrap();
        backend.reload().unwrap();
        assert!(!stale.promote().unwrap());
        assert!(backend.cache.get(&alice).is_none());
    }

    #[test]
    fn directory_policy_is_explicit_and_never_uses_the_production_path_in_tests() {
        assert_eq!(
            PlaintextBackendOptions::production().root(),
            Path::new(MODELS_DIR)
        );
        let root = TempRoot::new();
        fs::set_permissions(root.path(), Permissions::from_mode(0o755)).unwrap();
        let required = PlaintextBackendOptions::path_override(root.path())
            .with_directory_behavior(DirectoryBehavior::RequireExisting);
        let error = PlaintextStorageBackend::new(
            required,
            model(),
            limits(),
            cache_limits(),
            PlaintextBudget::new(4 * 1024 * 1024).unwrap(),
        )
        .unwrap_err();
        assert!(
            matches!(error, StorageBackendError::Io(value) if value.operation() == IoOperation::Inspect)
        );

        let fixed = roomy_backend(&root);
        assert_eq!(fs::metadata(root.path()).unwrap().mode() & 0o7777, 0o700);
        drop(fixed);

        let target = TempRoot::new();
        let link = root.file("linked-root");
        symlink(target.path(), &link).unwrap();
        let error = PlaintextStorageBackend::new(
            PlaintextBackendOptions::path_override(&link),
            model(),
            limits(),
            cache_limits(),
            PlaintextBudget::new(4 * 1024 * 1024).unwrap(),
        )
        .unwrap_err();
        assert!(
            matches!(error, StorageBackendError::Io(value) if value.operation() == IoOperation::Open)
        );
    }

    #[test]
    fn howypln1_write_read_round_trip_and_all_read_operations() {
        let root = TempRoot::new();
        let backend = roomy_backend(&root);
        let alice = username("alice");
        let first = entry(1, "desk");

        assert_eq!(backend.health(), BackendHealth::Ready);
        assert_eq!(
            backend.candidate_presence(&alice).unwrap(),
            CandidatePresence::Absent
        );
        let result = backend
            .append(AppendRequest::new(&alice, ABSENT_GENERATION, &[first.clone()]).unwrap())
            .unwrap();
        assert_eq!(result, AppendResult::new(1, 1, 1));
        let bytes = fs::read(root.file("alice.bin")).unwrap();
        assert_eq!(&bytes[..8], b"HOWYPLN1");
        let decoded = decode_howypln1(&bytes, &alice, model()).unwrap();
        assert_eq!(decoded.generation(), 1);
        assert_eq!(decoded.entries(), &[first]);
        assert_eq!(
            fs::metadata(root.file("alice.bin")).unwrap().mode() & 0o7777,
            0o600
        );

        assert_eq!(
            backend.candidate_presence(&alice).unwrap(),
            CandidatePresence::Candidate { generation: 1 }
        );
        let listed = backend.list_metadata(&alice).unwrap();
        assert_eq!(listed.generation(), 1);
        assert_eq!(listed.entries()[0].label(), "desk");
        assert_eq!(backend.verify_record(&alice).unwrap(), listed);
        let lease = backend.authenticate(&alice).unwrap();
        assert_eq!(lease.kind(), LeaseKind::Cached);
        assert_eq!(lease.generation(), 1);
        assert_eq!(lease.entry_count(), 1);
    }

    #[test]
    fn prompt_snapshot_is_backend_stable_and_generation_linearized() {
        let root = TempRoot::new();
        let backend = roomy_backend(&root);
        let alice = username("alice");
        let absent = backend.prompt_snapshot(&alice).unwrap();
        assert_eq!(absent.health(), BackendHealth::Ready);
        assert_eq!(absent.candidate(), CandidatePresence::Absent);
        assert_eq!(
            absent.policy_generation(),
            PromptOpaqueIdentity::new(model().into_bytes())
        );

        backend
            .append(AppendRequest::new(&alice, 0, &[entry(1, "desk")]).unwrap())
            .unwrap();
        let first = backend.prompt_snapshot(&alice).unwrap();
        assert!(matches!(
            first.candidate(),
            CandidatePresence::Candidate { generation } if generation != 0
        ));
        assert_eq!(first.backend_identity(), absent.backend_identity());

        // `first` remains the valid pre-mutation linearization result. A later
        // append is logically after that snapshot and produces a new generation.
        backend
            .append(AppendRequest::new(&alice, 1, &[entry(2, "window")]).unwrap())
            .unwrap();
        let second = backend.prompt_snapshot(&alice).unwrap();
        assert_ne!(first.candidate(), second.candidate());
        assert_eq!(second.backend_identity(), first.backend_identity());
    }

    #[test]
    fn prompt_snapshot_uses_only_descriptor_metadata_without_decode_or_budget() {
        let root = TempRoot::new();
        let budget = PlaintextBudget::new(4 * 1024 * 1024).unwrap();
        let backend = backend(&root, budget.clone());
        let alice = username("alice");

        write_legacy_bin(&root, &legacy("alice", &["legacy"]));
        let first = backend.prompt_snapshot(&alice).unwrap();
        let second = backend.prompt_snapshot(&alice).unwrap();
        assert_eq!(first.candidate(), second.candidate());
        assert_eq!(backend.load_count.load(Ordering::Relaxed), 0);
        assert_eq!(budget.used(), 0);

        // Same-inode payload mutation changes ctime/mtime identity without a
        // pre-confirm payload read or legacy decoder invocation.
        let replacement = bincode::serialize(&legacy("alice", &["changed"])).unwrap();
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(root.file("alice.bin"))
            .unwrap();
        file.write_all(&replacement).unwrap();
        file.sync_all().unwrap();
        let changed = backend.prompt_snapshot(&alice).unwrap();
        assert_ne!(first.candidate(), changed.candidate());
        assert_eq!(backend.load_count.load(Ordering::Relaxed), 0);
        assert_eq!(budget.used(), 0);

        // Atomic path replacement changes device/inode identity even when size
        // and timestamps happen to be close.
        fs::remove_file(root.file("alice.bin")).unwrap();
        write_private(&root.file("alice.bin"), &replacement);
        let replaced = backend.prompt_snapshot(&alice).unwrap();
        assert_ne!(changed.candidate(), replaced.candidate());
        assert_eq!(backend.load_count.load(Ordering::Relaxed), 0);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn prompt_snapshot_rejects_empty_and_oversized_without_decoding_payload() {
        let root = TempRoot::new();
        let backend = roomy_backend(&root);
        let alice = username("alice");
        write_private(&root.file("alice.bin"), &[]);
        assert_eq!(
            backend.prompt_snapshot(&alice).unwrap_err(),
            StorageBackendError::Corrupt
        );

        fs::remove_file(root.file("alice.bin")).unwrap();
        write_private(
            &root.file("alice.bin"),
            &vec![0u8; limits().max_record_bytes() + 1],
        );
        assert_eq!(
            backend.prompt_snapshot(&alice).unwrap_err(),
            StorageBackendError::Corrupt
        );
        assert_eq!(backend.load_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn legacy_bincode_json_and_authoritative_preference_are_preserved() {
        let root = TempRoot::new();
        let bin = legacy("alice", &["from-bin"]);
        let json = legacy("alice", &["from-json"]);
        let bin_bytes = write_legacy_bin(&root, &bin);
        write_legacy_json(&root, &json);
        let backend = roomy_backend(&root);
        let alice = username("alice");
        let first = backend.list_metadata(&alice).unwrap();
        let second = backend.list_metadata(&alice).unwrap();
        assert_eq!(first.entries()[0].label(), "from-bin");
        assert_eq!(first, second);
        assert_eq!(first.generation(), legacy_generation(&bin_bytes).unwrap());

        fs::remove_file(root.file("alice.bin")).unwrap();
        let fallback = backend.list_metadata(&alice).unwrap();
        assert_eq!(fallback.entries()[0].label(), "from-json");

        fs::remove_file(root.file("alice.json")).unwrap();
        let json_at_bin = serde_json::to_vec(&json).unwrap();
        write_private(&root.file("alice.bin"), &json_at_bin);
        assert_eq!(
            backend.list_metadata(&alice).unwrap().entries()[0].label(),
            "from-json"
        );
    }

    #[test]
    fn legacy_ids_and_generation_are_deterministic_from_original_bytes_and_ordinals() {
        let root = TempRoot::new();
        let bytes = write_legacy_bin(&root, &legacy("alice", &["same", "same"]));
        let backend = roomy_backend(&root);
        let alice = username("alice");
        let first = backend.list_metadata(&alice).unwrap();
        let second = backend.list_metadata(&alice).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.generation(), legacy_generation(&bytes).unwrap());
        assert_ne!(
            first.entries()[0].enrollment_id(),
            first.entries()[1].enrollment_id()
        );
    }

    #[test]
    fn username_model_malformed_oversized_and_nonfinite_records_fail_closed() {
        let root = TempRoot::new();
        write_legacy_bin(&root, &legacy("bob", &["wrong-user"]));
        let backend = roomy_backend(&root);
        let alice = username("alice");
        assert_eq!(
            backend.list_metadata(&alice).unwrap_err(),
            StorageBackendError::Corrupt
        );

        fs::remove_file(root.file("alice.bin")).unwrap();
        let wrong_model =
            EnrollmentRecord::new(1, ModelDigest::new([9; 32]), alice.clone(), vec![]).unwrap();
        write_private(
            &root.file("alice.bin"),
            encode_howypln1(&wrong_model).unwrap().as_slice(),
        );
        assert_eq!(
            backend.list_metadata(&alice).unwrap_err(),
            StorageBackendError::ModelMismatch
        );

        fs::remove_file(root.file("alice.bin")).unwrap();
        write_private(&root.file("alice.bin"), b"not a record");
        assert_eq!(
            backend.list_metadata(&alice).unwrap_err(),
            StorageBackendError::Corrupt
        );

        fs::remove_file(root.file("alice.bin")).unwrap();
        let mut bad = legacy("alice", &["nonfinite"]);
        bad.models[0].embedding[0] = f32::NAN;
        write_legacy_bin(&root, &bad);
        assert_eq!(
            backend.list_metadata(&alice).unwrap_err(),
            StorageBackendError::Corrupt
        );

        fs::remove_file(root.file("alice.bin")).unwrap();
        let mut wrong_dimension = legacy("alice", &["wrong-dimension"]);
        wrong_dimension.models[0].embedding.pop();
        write_legacy_bin(&root, &wrong_dimension);
        assert_eq!(
            backend.list_metadata(&alice).unwrap_err(),
            StorageBackendError::Corrupt
        );

        fs::remove_file(root.file("alice.bin")).unwrap();
        let overlong_label = "x".repeat(howy_common::storage::MAX_LABEL_BYTES + 1);
        write_legacy_bin(&root, &legacy("alice", &[&overlong_label]));
        assert_eq!(
            backend.list_metadata(&alice).unwrap_err(),
            StorageBackendError::Corrupt
        );

        fs::remove_file(root.file("alice.bin")).unwrap();
        write_legacy_bin(&root, &legacy("alice", &["one", "two"]));
        let entry_limited = PlaintextStorageBackend::new(
            PlaintextBackendOptions::path_override(root.path()),
            model(),
            PlaintextStorageLimits::new(1, 64 * 1024).unwrap(),
            cache_limits(),
            PlaintextBudget::new(4 * 1024 * 1024).unwrap(),
        )
        .unwrap();
        assert_eq!(
            entry_limited.list_metadata(&alice).unwrap_err(),
            StorageBackendError::Corrupt
        );

        fs::remove_file(root.file("alice.bin")).unwrap();
        write_private(
            &root.file("alice.bin"),
            &vec![0u8; limits().max_record_bytes() + 1],
        );
        assert_eq!(
            backend.list_metadata(&alice).unwrap_err(),
            StorageBackendError::Corrupt
        );
    }

    #[test]
    fn first_legacy_append_converts_to_generation_one_then_cas_increments() {
        let root = TempRoot::new();
        let bytes = write_legacy_bin(&root, &legacy("alice", &["legacy"]));
        let token = legacy_generation(&bytes).unwrap();
        let backend = roomy_backend(&root);
        let alice = username("alice");

        assert_eq!(
            backend
                .append(AppendRequest::new(&alice, token, &[entry(4, "new")]).unwrap())
                .unwrap(),
            AppendResult::new(1, 1, 2)
        );
        assert_eq!(&fs::read(root.file("alice.bin")).unwrap()[..8], b"HOWYPLN1");
        assert_eq!(
            backend
                .append(AppendRequest::new(&alice, token, &[entry(5, "stale")]).unwrap())
                .unwrap_err(),
            StorageBackendError::Conflict {
                current_generation: 1
            }
        );
        assert_eq!(
            backend
                .append(AppendRequest::new(&alice, 1, &[entry(6, "next")]).unwrap())
                .unwrap(),
            AppendResult::new(2, 1, 3)
        );
    }

    #[test]
    fn legacy_remove_uses_stable_id_and_last_entry_leaves_versioned_empty_record() {
        let root = TempRoot::new();
        write_legacy_json(&root, &legacy("alice", &["only"]));
        let backend = roomy_backend(&root);
        let alice = username("alice");
        let listed = backend.list_metadata(&alice).unwrap();
        let id = listed.entries()[0].enrollment_id();
        assert_eq!(
            backend
                .remove(RemoveRequest::new(&alice, listed.generation(), id).unwrap())
                .unwrap(),
            RemoveResult::new(1, id)
        );
        let empty = backend.list_metadata(&alice).unwrap();
        assert_eq!(empty.generation(), 1);
        assert!(empty.entries().is_empty());
        assert_eq!(
            backend.candidate_presence(&alice).unwrap(),
            CandidatePresence::Absent
        );
        assert_eq!(
            backend.authenticate(&alice).unwrap_err(),
            StorageBackendError::Absent
        );
    }

    #[test]
    fn remove_conflicts_for_stale_generation_or_unknown_stable_id() {
        let root = TempRoot::new();
        let backend = roomy_backend(&root);
        let alice = username("alice");
        let first = entry(1, "one");
        backend
            .append(AppendRequest::new(&alice, 0, &[first.clone()]).unwrap())
            .unwrap();
        for request in [
            RemoveRequest::new(&alice, 2, first.enrollment_id()).unwrap(),
            RemoveRequest::new(&alice, 1, EnrollmentId::new([9; 16]).unwrap()).unwrap(),
        ] {
            assert_eq!(
                backend.remove(request).unwrap_err(),
                StorageBackendError::Conflict {
                    current_generation: 1
                }
            );
        }
    }

    #[test]
    fn clear_removes_only_selected_bin_and_json_then_reports_absent() {
        let root = TempRoot::new();
        let backend = roomy_backend(&root);
        let alice = username("alice");
        backend
            .append(AppendRequest::new(&alice, 0, &[entry(1, "one")]).unwrap())
            .unwrap();
        write_private(
            &root.file("alice.json"),
            &serde_json::to_vec(&legacy("alice", &["old"])).unwrap(),
        );
        write_private(&root.file("unrelated.txt"), b"keep");
        assert_eq!(
            backend
                .clear(ClearRequest::new(&alice, 1).unwrap())
                .unwrap(),
            ClearResult::new(1)
        );
        assert!(!root.file("alice.bin").exists());
        assert!(!root.file("alice.json").exists());
        assert_eq!(fs::read(root.file("unrelated.txt")).unwrap(), b"keep");
        assert_eq!(
            backend.candidate_presence(&alice).unwrap(),
            CandidatePresence::Absent
        );
        assert_eq!(
            backend
                .clear(ClearRequest::new(&alice, 1).unwrap())
                .unwrap_err(),
            StorageBackendError::Conflict {
                current_generation: ABSENT_GENERATION
            }
        );
    }

    #[test]
    fn clear_orders_and_syncs_fallback_before_authoritative() {
        let events = Mutex::new(Vec::new());
        clear_fallback_before_authoritative(
            true,
            true,
            |fallback| {
                events
                    .lock()
                    .unwrap()
                    .push(if fallback { "json" } else { "bin" });
                Ok::<_, ()>(())
            },
            || {
                events.lock().unwrap().push("sync");
                Ok::<_, ()>(())
            },
        )
        .unwrap();
        assert_eq!(*events.lock().unwrap(), ["json", "sync", "bin", "sync"]);

        let events = Mutex::new(Vec::new());
        let mut syncs = 0;
        let result = clear_fallback_before_authoritative(
            true,
            true,
            |fallback| {
                events
                    .lock()
                    .unwrap()
                    .push(if fallback { "json" } else { "bin" });
                Ok::<_, &'static str>(())
            },
            || {
                events.lock().unwrap().push("sync");
                syncs += 1;
                if syncs == 1 { Err("fault") } else { Ok(()) }
            },
        );
        assert_eq!(result, Err("fault"));
        assert_eq!(*events.lock().unwrap(), ["json", "sync"]);
    }

    #[test]
    fn symlinks_and_insecure_record_permissions_are_rejected_without_following() {
        let root = TempRoot::new();
        let target = root.file("target");
        write_private(&target, b"do not read or remove");
        symlink(&target, root.file("alice.bin")).unwrap();
        let backend = roomy_backend(&root);
        let alice = username("alice");
        let error = backend.list_metadata(&alice).unwrap_err();
        assert!(
            matches!(error, StorageBackendError::Io(value) if value.operation() == IoOperation::Open)
        );
        assert_eq!(fs::read(&target).unwrap(), b"do not read or remove");

        fs::remove_file(root.file("alice.bin")).unwrap();
        write_legacy_bin(&root, &legacy("alice", &["mode"]));
        fs::set_permissions(root.file("alice.bin"), Permissions::from_mode(0o644)).unwrap();
        let error = backend.list_metadata(&alice).unwrap_err();
        assert!(
            matches!(error, StorageBackendError::Io(value) if value.operation() == IoOperation::Inspect)
        );
    }

    struct SequenceRandom {
        values: VecDeque<[u8; 16]>,
        repeat: [u8; 16],
    }

    impl RandomSource for SequenceRandom {
        fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), String> {
            let value = self.values.pop_front().unwrap_or(self.repeat);
            destination.copy_from_slice(&value);
            Ok(())
        }
    }

    #[test]
    fn temp_collision_is_not_followed_or_overwritten_and_retry_commits_atomically() {
        let root = TempRoot::new();
        let collision = root.file(&format!(".alice.bin.tmp.{}", hex_lower(&[7; 16])));
        write_private(&collision, b"stale");
        let random = SequenceRandom {
            values: VecDeque::from([[7; 16], [8; 16]]),
            repeat: [8; 16],
        };
        let backend = PlaintextStorageBackend::new_with_random(
            PlaintextBackendOptions::path_override(root.path()),
            model(),
            limits(),
            cache_limits(),
            PlaintextBudget::new(4 * 1024 * 1024).unwrap(),
            Box::new(random),
        )
        .unwrap();
        let alice = username("alice");
        backend
            .append(AppendRequest::new(&alice, 0, &[entry(1, "one")]).unwrap())
            .unwrap();
        assert_eq!(fs::read(collision).unwrap(), b"stale");
        let bytes = fs::read(root.file("alice.bin")).unwrap();
        assert_eq!(&bytes[..8], b"HOWYPLN1");
        assert!(decode_howypln1(&bytes, &alice, model()).is_ok());
    }

    #[test]
    fn failed_replacement_preserves_the_complete_old_record() {
        let root = TempRoot::new();
        let initial = roomy_backend(&root);
        let alice = username("alice");
        initial
            .append(AppendRequest::new(&alice, 0, &[entry(1, "old")]).unwrap())
            .unwrap();
        let old = fs::read(root.file("alice.bin")).unwrap();
        drop(initial);

        let collision_name = format!(".alice.bin.tmp.{}", hex_lower(&[3; 16]));
        write_private(&root.file(&collision_name), b"occupied");
        let backend = PlaintextStorageBackend::new_with_random(
            PlaintextBackendOptions::path_override(root.path()),
            model(),
            limits(),
            cache_limits(),
            PlaintextBudget::new(4 * 1024 * 1024).unwrap(),
            Box::new(SequenceRandom {
                values: VecDeque::new(),
                repeat: [3; 16],
            }),
        )
        .unwrap();
        let error = backend
            .append(AppendRequest::new(&alice, 1, &[entry(2, "new")]).unwrap())
            .unwrap_err();
        assert!(
            matches!(error, StorageBackendError::Io(value) if value.operation() == IoOperation::Create)
        );
        assert_eq!(fs::read(root.file("alice.bin")).unwrap(), old);
        assert_eq!(backend.list_metadata(&alice).unwrap().entries().len(), 1);
    }

    #[test]
    fn budget_pressure_and_auth_lease_lifetime_release_every_permit() {
        let root = TempRoot::new();
        let bootstrap = roomy_backend(&root);
        let alice = username("alice");
        bootstrap
            .append(AppendRequest::new(&alice, 0, &[entry(1, "one")]).unwrap())
            .unwrap();
        drop(bootstrap);

        let probe_budget = PlaintextBudget::new(4 * 1024 * 1024).unwrap();
        let probe = backend(&root, probe_budget.clone());
        let operation = probe.operation_reservation_bytes;
        let model_bytes = {
            let lease = probe.authenticate(&alice).unwrap();
            lease.plaintext_bytes()
        };
        drop(probe);
        assert_eq!(probe_budget.used(), 0);

        let budget = PlaintextBudget::new(operation).unwrap();
        let constrained = backend(&root, budget.clone());
        let first = constrained.authenticate(&alice).unwrap();
        assert_eq!(budget.used(), model_bytes);
        constrained.cache.invalidate(&alice);
        assert!(matches!(
            constrained.authenticate(&alice),
            Err(StorageBackendError::MemoryBudgetExceeded { .. })
        ));
        assert_eq!(budget.used(), model_bytes);
        drop(first);
        assert_eq!(budget.used(), 0);
        let reloaded = constrained.authenticate(&alice).unwrap();
        assert_eq!(budget.used(), model_bytes);
        drop(reloaded);
        assert_eq!(budget.used(), model_bytes);
        constrained.cache.invalidate(&alice);
        assert_eq!(budget.used(), 0);

        let too_small = PlaintextBudget::new(operation - 1).unwrap();
        let backend = backend(&root, too_small.clone());
        assert!(matches!(
            backend.candidate_presence(&alice),
            Err(StorageBackendError::MemoryBudgetExceeded { .. })
        ));
        assert_eq!(too_small.used(), 0);
    }

    #[test]
    fn enrollment_admission_atomically_covers_input_and_commit() {
        let root = TempRoot::new();
        let probe = roomy_backend(&root);
        let operation = probe.operation_reservation_bytes;
        drop(probe);

        let input = size_of::<EnrollmentEntry>() + 32;
        let budget = PlaintextBudget::new(operation + input).unwrap();
        let admitted_backend = backend(&root, budget.clone());
        let alice = username("alice");
        let admission = admitted_backend
            .admit_enrollment(&alice, input, AppendAdmissionShape::new(1, 1).unwrap())
            .unwrap();
        assert_eq!(budget.used(), operation + input);
        let (operation_permit, input_permit) = admission.into_parts();
        admitted_backend
            .append_admitted(
                AppendRequest::new(&alice, 0, &[entry(1, "one")]).unwrap(),
                operation_permit,
            )
            .unwrap();
        assert!(budget.used() >= input);
        drop(input_permit);
        admitted_backend.cache.invalidate(&alice);
        assert_eq!(budget.used(), 0);

        let too_small = PlaintextBudget::new(operation + input - 1).unwrap();
        let constrained = backend(&root, too_small.clone());
        assert!(matches!(
            constrained.admit_enrollment(&alice, input, AppendAdmissionShape::new(1, 1).unwrap(),),
            Err(StorageBackendError::MemoryBudgetExceeded { .. })
        ));
        assert_eq!(too_small.used(), 0);
    }

    #[test]
    fn durable_mutation_succeeds_and_invalidates_when_replacement_exceeds_cache_limit() {
        let root = TempRoot::new();
        let backend = PlaintextStorageBackend::new(
            PlaintextBackendOptions::path_override(root.path()),
            model(),
            limits(),
            ModelCacheLimits::new(1, 1).unwrap(),
            PlaintextBudget::new(4 * 1024 * 1024).unwrap(),
        )
        .unwrap();
        let alice = username("alice");
        assert_eq!(
            backend
                .append(AppendRequest::new(&alice, 0, &[entry(1, "committed")]).unwrap())
                .unwrap()
                .generation(),
            1
        );
        assert!(backend.cache.get(&alice).is_none());
        assert_eq!(backend.list_metadata(&alice).unwrap().generation(), 1);
        assert!(matches!(
            backend.authenticate(&alice),
            Err(StorageBackendError::MemoryBudgetExceeded { .. })
        ));
        assert!(backend.cache.get(&alice).is_none());
    }

    #[test]
    fn warm_authentication_loads_once_without_reopening_the_record() {
        let root = TempRoot::new();
        let bootstrap = roomy_backend(&root);
        let alice = username("alice");
        bootstrap
            .append(AppendRequest::new(&alice, 0, &[entry(1, "one")]).unwrap())
            .unwrap();
        drop(bootstrap);

        let backend = roomy_backend(&root);
        assert_eq!(backend.load_count.load(Ordering::Relaxed), 0);
        let first = backend.authenticate(&alice).unwrap();
        assert_eq!(backend.load_count.load(Ordering::Relaxed), 1);
        let second = backend.authenticate(&alice).unwrap();
        assert_eq!(backend.load_count.load(Ordering::Relaxed), 1);
        assert_eq!(first.generation(), second.generation());
        assert_eq!(first.kind(), LeaseKind::Cached);
        assert_eq!(second.kind(), LeaseKind::Cached);
    }

    #[test]
    fn committed_mutations_replace_or_invalidate_cached_generations() {
        let root = TempRoot::new();
        let backend = roomy_backend(&root);
        let alice = username("alice");
        let first = entry(1, "one");
        backend
            .append(AppendRequest::new(&alice, 0, &[first.clone()]).unwrap())
            .unwrap();
        let old_generation = backend.authenticate(&alice).unwrap();
        assert_eq!(old_generation.generation(), 1);

        backend
            .append(AppendRequest::new(&alice, 1, &[entry(2, "two")]).unwrap())
            .unwrap();
        let appended = backend.authenticate(&alice).unwrap();
        assert_eq!(old_generation.generation(), 1);
        assert_eq!(appended.generation(), 2);
        assert_eq!(appended.entry_count(), 2);

        backend
            .remove(RemoveRequest::new(&alice, 2, first.enrollment_id()).unwrap())
            .unwrap();
        let removed = backend.authenticate(&alice).unwrap();
        assert_eq!(removed.generation(), 3);
        assert_eq!(removed.labels().collect::<Vec<_>>(), ["two"]);

        backend
            .clear(ClearRequest::new(&alice, 3).unwrap())
            .unwrap();
        assert_eq!(
            backend.authenticate(&alice).unwrap_err(),
            StorageBackendError::Absent
        );
    }

    #[test]
    fn external_changes_are_hidden_until_reload_then_refreshed() {
        let root = TempRoot::new();
        let backend = roomy_backend(&root);
        let alice = username("alice");
        backend
            .append(AppendRequest::new(&alice, 0, &[entry(1, "cached")]).unwrap())
            .unwrap();
        let warm = backend.authenticate(&alice).unwrap();
        assert_eq!(warm.generation(), 1);
        drop(warm);

        let external =
            EnrollmentRecord::new(9, model(), alice.clone(), vec![entry(9, "external")]).unwrap();
        let encoded = encode_howypln1(&external).unwrap();
        fs::write(root.file("alice.bin"), encoded.as_slice()).unwrap();
        assert_eq!(
            backend
                .authenticate(&alice)
                .unwrap()
                .labels()
                .collect::<Vec<_>>(),
            ["cached"]
        );

        let reload = backend.reload().unwrap();
        assert_eq!(
            reload.records()[0].classification(),
            OuterRecordClassification::Candidate { generation: 9 }
        );
        let refreshed = backend.authenticate(&alice).unwrap();
        assert_eq!(refreshed.generation(), 9);
        assert_eq!(refreshed.labels().collect::<Vec<_>>(), ["external"]);
    }

    #[test]
    fn warm_cache_lookup_waits_for_reload_write_barrier() {
        let root = TempRoot::new();
        let backend = Arc::new(roomy_backend(&root));
        let alice = username("alice");
        backend
            .append(AppendRequest::new(&alice, 0, &[entry(1, "cached")]).unwrap())
            .unwrap();
        assert_eq!(backend.authenticate(&alice).unwrap().generation(), 1);

        let reload = backend.reload_gate.write().unwrap();
        let worker_backend = Arc::clone(&backend);
        let worker_alice = alice.clone();
        let (sent, received) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            sent.send(
                worker_backend
                    .authenticate(&worker_alice)
                    .unwrap()
                    .generation(),
            )
            .unwrap();
        });
        assert!(matches!(
            received.recv_timeout(Duration::from_millis(30)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));

        let replacement =
            EnrollmentRecord::new(9, model(), alice, vec![entry(9, "reloaded")]).unwrap();
        let bytes = encode_howypln1(&replacement).unwrap();
        fs::write(root.file("alice.bin"), bytes.as_slice()).unwrap();
        backend.cache.clear();
        drop(reload);

        assert_eq!(received.recv_timeout(Duration::from_secs(1)).unwrap(), 9);
        worker.join().unwrap();
    }

    #[test]
    fn reload_auth_and_mutation_share_one_deadlock_free_lock_hierarchy() {
        let root = TempRoot::new();
        let backend = Arc::new(roomy_backend(&root));
        let alice = username("alice");
        backend
            .append(AppendRequest::new(&alice, 0, &[entry(1, "initial")]).unwrap())
            .unwrap();
        backend.cache.invalidate(&alice);

        let operation = backend.operation_permit().unwrap();
        let (mutation_locked_tx, mutation_locked_rx) = mpsc::channel();
        let (release_mutation_tx, release_mutation_rx) = mpsc::channel();
        let (mutation_done_tx, mutation_done_rx) = mpsc::channel();
        let mutation_backend = Arc::clone(&backend);
        let mutation_alice = alice.clone();
        let mutation = std::thread::spawn(move || {
            let added = entry(2, "mutation");
            let result = mutation_backend.append_with_operation_after_user(
                AppendRequest::new(&mutation_alice, 1, std::slice::from_ref(&added)).unwrap(),
                operation,
                || {
                    mutation_locked_tx.send(()).unwrap();
                    release_mutation_rx.recv().unwrap();
                },
            );
            mutation_done_tx.send(result.unwrap().generation()).unwrap();
        });
        mutation_locked_rx
            .recv_timeout(Duration::from_secs(1))
            .unwrap();

        let (auth_read_tx, auth_read_rx) = mpsc::channel();
        let (auth_done_tx, auth_done_rx) = mpsc::channel();
        let auth_backend = Arc::clone(&backend);
        let auth_alice = alice.clone();
        let auth = std::thread::spawn(move || {
            let lease = auth_backend
                .authenticate_after_reload(&auth_alice, || auth_read_tx.send(()).unwrap())
                .unwrap();
            auth_done_tx.send(lease.generation()).unwrap();
        });
        auth_read_rx.recv_timeout(Duration::from_secs(1)).unwrap();

        let (reload_started_tx, reload_started_rx) = mpsc::channel();
        let (reload_done_tx, reload_done_rx) = mpsc::channel();
        let reload_backend = Arc::clone(&backend);
        let reload = std::thread::spawn(move || {
            reload_started_tx.send(()).unwrap();
            let result = reload_backend.reload().unwrap();
            reload_done_tx.send(result.records().len()).unwrap();
        });
        reload_started_rx
            .recv_timeout(Duration::from_secs(1))
            .unwrap();
        assert!(matches!(
            reload_done_rx.recv_timeout(Duration::from_millis(30)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));

        release_mutation_tx.send(()).unwrap();
        assert_eq!(
            mutation_done_rx
                .recv_timeout(Duration::from_secs(2))
                .unwrap(),
            2
        );
        assert_eq!(
            auth_done_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            2
        );
        assert_eq!(
            reload_done_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            1
        );
        mutation.join().unwrap();
        auth.join().unwrap();
        reload.join().unwrap();
    }

    #[test]
    fn concurrent_same_user_auth_loads_once_and_other_user_mutation_does_not_block() {
        let root = TempRoot::new();
        let alice = username("alice");
        let bob = username("bob");
        for (name, record) in [
            (
                "alice.bin",
                EnrollmentRecord::new(1, model(), alice.clone(), vec![entry(1, "alice")]).unwrap(),
            ),
            (
                "bob.bin",
                EnrollmentRecord::new(1, model(), bob.clone(), vec![entry(2, "bob")]).unwrap(),
            ),
        ] {
            write_private(
                &root.file(name),
                encode_howypln1(&record).unwrap().as_slice(),
            );
        }
        let backend = Arc::new(roomy_backend(&root));
        let barrier = Arc::new(Barrier::new(9));
        let mut workers = Vec::new();
        for _ in 0..8 {
            let backend = Arc::clone(&backend);
            let barrier = Arc::clone(&barrier);
            let alice = alice.clone();
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                backend.authenticate(&alice).unwrap().generation()
            }));
        }
        barrier.wait();
        for worker in workers {
            assert_eq!(worker.join().unwrap(), 1);
        }
        assert_eq!(backend.load_count.load(Ordering::Relaxed), 1);

        backend.cache.clear();
        backend.load_count.store(0, Ordering::Relaxed);
        let alice_serializer = backend.serializers.for_user(&alice);
        let alice_guard = alice_serializer.lock().unwrap();
        let blocked_backend = Arc::clone(&backend);
        let blocked_alice = alice.clone();
        let blocked = std::thread::spawn(move || {
            blocked_backend
                .authenticate(&blocked_alice)
                .unwrap()
                .generation()
        });

        let (sent, received) = mpsc::channel();
        let bob_backend = Arc::clone(&backend);
        let bob_worker = std::thread::spawn(move || {
            let result = bob_backend
                .append(AppendRequest::new(&bob, 1, &[entry(3, "new")]).unwrap())
                .unwrap();
            sent.send(result.generation()).unwrap();
        });
        assert_eq!(received.recv_timeout(Duration::from_secs(2)).unwrap(), 2);
        drop(alice_guard);
        assert_eq!(blocked.join().unwrap(), 1);
        bob_worker.join().unwrap();
    }

    #[test]
    fn poisoned_user_serializer_recovers_and_releases_operation_budget() {
        let root = TempRoot::new();
        let bootstrap = roomy_backend(&root);
        let alice = username("alice");
        bootstrap
            .append(AppendRequest::new(&alice, 0, &[entry(1, "one")]).unwrap())
            .unwrap();
        drop(bootstrap);

        let budget = PlaintextBudget::new(4 * 1024 * 1024).unwrap();
        let backend = Arc::new(backend(&root, budget.clone()));
        let serializer = backend.serializers.for_user(&alice);
        let poison = Arc::clone(&serializer);
        let _ = std::thread::spawn(move || {
            let _guard = poison.lock().unwrap();
            panic!("poison per-user serializer");
        })
        .join();

        let lease = backend.authenticate(&alice).unwrap();
        assert_eq!(lease.generation(), 1);
        drop(lease);
        backend.cache.invalidate(&alice);
        assert_eq!(budget.used(), 0);
        drop(serializer);
    }

    #[test]
    fn reload_classifies_candidates_model_mismatch_and_corruption() {
        let root = TempRoot::new();
        let alice = username("alice");
        let valid =
            EnrollmentRecord::new(4, model(), alice.clone(), vec![entry(1, "one")]).unwrap();
        write_private(
            &root.file("alice.bin"),
            encode_howypln1(&valid).unwrap().as_slice(),
        );
        let bob = username("bob");
        let wrong = EnrollmentRecord::new(2, ModelDigest::new([9; 32]), bob, vec![]).unwrap();
        write_private(
            &root.file("bob.bin"),
            encode_howypln1(&wrong).unwrap().as_slice(),
        );
        write_private(&root.file("carol.bin"), b"broken");
        write_private(&root.file("ignored.txt"), b"not a record");
        let backend = roomy_backend(&root);
        let reload = backend.reload().unwrap();
        assert_eq!(reload.records().len(), 3);
        assert_eq!(
            reload.records()[0].classification(),
            OuterRecordClassification::Candidate { generation: 4 }
        );
        assert_eq!(
            reload.records()[1].classification(),
            OuterRecordClassification::ModelMismatch
        );
        assert_eq!(
            reload.records()[2].classification(),
            OuterRecordClassification::Corrupt
        );
    }
}
