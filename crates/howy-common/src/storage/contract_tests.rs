use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard};

use super::*;

#[derive(Debug, Clone, Copy)]
enum MockLeaseMode {
    Cached,
    Ephemeral,
}

struct MockState {
    records: HashMap<CanonicalUsername, EnrollmentRecord>,
    cache: HashMap<CanonicalUsername, CachedAuthModel>,
    health: BackendHealth,
}

/// Deterministic contract backend: no filesystem, cryptography, or authorization.
struct MockStorageBackend {
    model: ModelDigest,
    lease_mode: MockLeaseMode,
    budget: PlaintextBudget,
    state: Mutex<MockState>,
}

impl MockStorageBackend {
    fn new(lease_mode: MockLeaseMode, budget_bytes: usize) -> Self {
        Self {
            model: model_digest(),
            lease_mode,
            budget: PlaintextBudget::new(budget_bytes).unwrap(),
            state: Mutex::new(MockState {
                records: HashMap::new(),
                cache: HashMap::new(),
                health: BackendHealth::Ready,
            }),
        }
    }

    fn state(&self) -> MutexGuard<'_, MockState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn ensure_ready(&self) -> Result<(), StorageBackendError> {
        match self.state().health {
            BackendHealth::Ready => Ok(()),
            BackendHealth::Unavailable(_) => Err(StorageBackendError::Unavailable),
        }
    }

    fn set_health(&self, health: BackendHealth) {
        self.state().health = health;
    }

    fn evict(&self, username: &CanonicalUsername) {
        self.state().cache.remove(username);
    }

    fn insert_record(&self, record: EnrollmentRecord) {
        self.state()
            .records
            .insert(record.username().clone(), record);
    }

    fn checked_generation(generation: u64) -> Result<u64, StorageBackendError> {
        checked_next_generation(generation).map_err(|error| match error {
            StorageError::GenerationOverflow => StorageBackendError::GenerationOverflow,
            _ => StorageBackendError::InvalidInput("generation"),
        })
    }

    fn build_model(record: &EnrollmentRecord) -> Result<AuthModel, StorageBackendError> {
        if record.entries().is_empty() {
            return Err(StorageBackendError::Absent);
        }
        AuthModel::from_record(record)
    }

    fn invalidate(state: &mut MockState, username: &CanonicalUsername) {
        state.cache.remove(username);
    }
}

impl StorageBackend for MockStorageBackend {
    fn prompt_snapshot(
        &self,
        username: &CanonicalUsername,
    ) -> Result<PromptStorageSnapshot, StorageBackendError> {
        let state = self.state();
        let candidate = state
            .records
            .get(username)
            .map_or(CandidatePresence::Absent, |record| {
                CandidatePresence::Candidate {
                    generation: record.generation(),
                }
            });
        Ok(PromptStorageSnapshot::new(
            state.health,
            candidate,
            PromptOpaqueIdentity::new([0x41; 32]),
            PromptOpaqueIdentity::new(self.model.into_bytes()),
        ))
    }

    fn candidate_presence(
        &self,
        username: &CanonicalUsername,
    ) -> Result<CandidatePresence, StorageBackendError> {
        self.ensure_ready()?;
        Ok(match self.state().records.get(username) {
            Some(record) => CandidatePresence::Candidate {
                generation: record.generation(),
            },
            None => CandidatePresence::Absent,
        })
    }

    fn authenticate(
        &self,
        username: &CanonicalUsername,
    ) -> Result<ModelLease, StorageBackendError> {
        self.ensure_ready()?;
        let mut state = self.state();
        if matches!(self.lease_mode, MockLeaseMode::Cached) {
            if let Some(model) = state.cache.get(username) {
                return Ok(model.lease());
            }
        }
        let model = Self::build_model(
            state
                .records
                .get(username)
                .ok_or(StorageBackendError::Absent)?,
        )?;
        let permit = self.budget.reserve(model.plaintext_bytes())?;
        match self.lease_mode {
            MockLeaseMode::Cached => {
                let cached = CachedAuthModel::new(model, permit)?;
                let lease = cached.lease();
                state.cache.insert(username.clone(), cached);
                Ok(lease)
            }
            MockLeaseMode::Ephemeral => ModelLease::ephemeral(model, permit),
        }
    }

    fn list_metadata(
        &self,
        username: &CanonicalUsername,
    ) -> Result<MetadataList, StorageBackendError> {
        self.ensure_ready()?;
        self.state()
            .records
            .get(username)
            .map(MetadataList::from_record)
            .ok_or(StorageBackendError::Absent)
    }

    fn append(&self, request: AppendRequest<'_>) -> Result<AppendResult, StorageBackendError> {
        self.ensure_ready()?;
        let mut state = self.state();
        let current_generation = state
            .records
            .get(request.username())
            .map_or(ABSENT_GENERATION, EnrollmentRecord::generation);
        if current_generation != request.expected_generation() {
            return Err(StorageBackendError::Conflict { current_generation });
        }

        let mut entries = state
            .records
            .get(request.username())
            .map_or_else(Vec::new, |record| record.entries().to_vec());
        if entries.len().saturating_add(request.entries().len()) > MAX_ENTRIES {
            return Err(StorageBackendError::InvalidInput("entry count"));
        }
        let mut ids: HashSet<_> = entries.iter().map(EnrollmentEntry::enrollment_id).collect();
        if request
            .entries()
            .iter()
            .any(|entry| !ids.insert(entry.enrollment_id()))
        {
            return Err(StorageBackendError::InvalidInput("duplicate enrollment ID"));
        }
        entries.extend_from_slice(request.entries());
        let total_entries = entries.len();
        let generation = Self::checked_generation(current_generation)?;
        let record =
            EnrollmentRecord::new(generation, self.model, request.username().clone(), entries)
                .map_err(|_| StorageBackendError::InvalidInput("record"))?;
        state.records.insert(request.username().clone(), record);
        Self::invalidate(&mut state, request.username());
        Ok(AppendResult::new(
            generation,
            request.entries().len(),
            total_entries,
        ))
    }

    fn admit_enrollment(
        &self,
        _username: &CanonicalUsername,
        plaintext_bytes: usize,
        _append_shape: AppendAdmissionShape,
    ) -> Result<EnrollmentAdmission, StorageBackendError> {
        self.budget.reserve_enrollment(1, plaintext_bytes)
    }

    fn append_admitted(
        &self,
        request: AppendRequest<'_>,
        operation: BudgetPermit,
    ) -> Result<AppendResult, StorageBackendError> {
        drop(operation);
        self.append(request)
    }

    fn remove(&self, request: RemoveRequest<'_>) -> Result<RemoveResult, StorageBackendError> {
        self.ensure_ready()?;
        let mut state = self.state();
        let Some(record) = state.records.get(request.username()) else {
            return Err(StorageBackendError::Conflict {
                current_generation: ABSENT_GENERATION,
            });
        };
        if record.generation() != request.expected_generation() {
            return Err(StorageBackendError::Conflict {
                current_generation: record.generation(),
            });
        }
        let Some(index) = record
            .entries()
            .iter()
            .position(|entry| entry.enrollment_id() == request.enrollment_id())
        else {
            return Err(StorageBackendError::Conflict {
                current_generation: record.generation(),
            });
        };
        let generation = Self::checked_generation(record.generation())?;
        let mut entries = record.entries().to_vec();
        entries.remove(index);
        let replacement =
            EnrollmentRecord::new(generation, self.model, request.username().clone(), entries)
                .map_err(|_| StorageBackendError::InvalidInput("record"))?;
        state
            .records
            .insert(request.username().clone(), replacement);
        Self::invalidate(&mut state, request.username());
        Ok(RemoveResult::new(generation, request.enrollment_id()))
    }

    fn clear(&self, request: ClearRequest<'_>) -> Result<ClearResult, StorageBackendError> {
        self.ensure_ready()?;
        let mut state = self.state();
        let Some(record) = state.records.get(request.username()) else {
            return Err(StorageBackendError::Conflict {
                current_generation: ABSENT_GENERATION,
            });
        };
        if record.generation() != request.expected_generation() {
            return Err(StorageBackendError::Conflict {
                current_generation: record.generation(),
            });
        }
        let removed = record.entries().len();
        state.records.remove(request.username());
        Self::invalidate(&mut state, request.username());
        Ok(ClearResult::new(removed))
    }

    fn reload(&self) -> Result<ReloadResult, StorageBackendError> {
        self.ensure_ready()?;
        let mut state = self.state();
        state.cache.clear();
        let mut records: Vec<_> = state
            .records
            .values()
            .map(|record| {
                OuterRecordStatus::new(
                    record.username().clone(),
                    OuterRecordClassification::Candidate {
                        generation: record.generation(),
                    },
                )
            })
            .collect();
        records.sort_by(|left, right| left.username().as_str().cmp(right.username().as_str()));
        Ok(ReloadResult::new(state.health, records))
    }

    fn health(&self) -> BackendHealth {
        self.state().health
    }

    fn verify_record(
        &self,
        username: &CanonicalUsername,
    ) -> Result<MetadataList, StorageBackendError> {
        self.ensure_ready()?;
        self.state()
            .records
            .get(username)
            .map(MetadataList::from_record)
            .ok_or(StorageBackendError::Absent)
    }
}

#[test]
fn prompt_snapshot_captures_health_generation_and_opaque_identity_together() {
    let backend = MockStorageBackend::new(MockLeaseMode::Cached, 8 * 1024 * 1024);
    let alice = username("alice");
    let absent = backend.prompt_snapshot(&alice).unwrap();
    assert_eq!(absent.health(), BackendHealth::Ready);
    assert_eq!(absent.candidate(), CandidatePresence::Absent);
    assert_eq!(
        absent.backend_identity(),
        PromptOpaqueIdentity::new([0x41; 32])
    );
    assert_eq!(
        absent.policy_generation(),
        PromptOpaqueIdentity::new(model_digest().into_bytes())
    );

    backend.insert_record(
        EnrollmentRecord::new(7, model_digest(), alice.clone(), vec![entry(1, "desk")]).unwrap(),
    );
    let candidate = backend.prompt_snapshot(&alice).unwrap();
    assert_eq!(
        candidate.candidate(),
        CandidatePresence::Candidate { generation: 7 }
    );
    backend.set_health(BackendHealth::Unavailable(
        BackendUnavailable::KeyUnavailable,
    ));
    let unavailable = backend.prompt_snapshot(&alice).unwrap();
    assert_eq!(
        unavailable.health(),
        BackendHealth::Unavailable(BackendUnavailable::KeyUnavailable)
    );
}

fn username(value: &str) -> CanonicalUsername {
    CanonicalUsername::new(value).unwrap()
}

fn model_digest() -> ModelDigest {
    ModelDigest::new([0x42; 32])
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

fn auth_model(entries: &[EnrollmentEntry]) -> AuthModel {
    let record =
        EnrollmentRecord::new(1, model_digest(), username("alice"), entries.to_vec()).unwrap();
    AuthModel::from_record(&record).unwrap()
}

#[test]
fn mock_backend_exercises_all_operations_and_cas_semantics() {
    let backend = MockStorageBackend::new(MockLeaseMode::Cached, 1_000_000);
    let alice = username("alice");
    let first = entry(1, "desk");
    let second = entry(2, "laptop");

    assert_eq!(backend.health(), BackendHealth::Ready);
    assert_eq!(
        backend.candidate_presence(&alice).unwrap(),
        CandidatePresence::Absent
    );
    assert_eq!(
        backend.authenticate(&alice).unwrap_err(),
        StorageBackendError::Absent
    );
    assert_eq!(
        backend.list_metadata(&alice).unwrap_err(),
        StorageBackendError::Absent
    );
    assert_eq!(
        backend.verify_record(&alice).unwrap_err(),
        StorageBackendError::Absent
    );

    let append = backend
        .append(AppendRequest::new(&alice, ABSENT_GENERATION, &[first.clone(), second]).unwrap())
        .unwrap();
    assert_eq!(append, AppendResult::new(1, 2, 2));
    assert_eq!(
        backend
            .append(AppendRequest::new(&alice, ABSENT_GENERATION, &[entry(3, "stale")]).unwrap())
            .unwrap_err(),
        StorageBackendError::Conflict {
            current_generation: 1
        }
    );
    assert_eq!(
        backend.candidate_presence(&alice).unwrap(),
        CandidatePresence::Candidate { generation: 1 }
    );

    let metadata = backend.list_metadata(&alice).unwrap();
    assert_eq!(metadata.generation(), 1);
    assert_eq!(metadata.entries().len(), 2);
    assert_eq!(metadata.entries()[0].enrollment_id(), first.enrollment_id());
    assert_eq!(metadata.entries()[0].label(), "desk");
    assert_eq!(metadata.entries()[0].generation(), 1);
    assert_eq!(backend.verify_record(&alice).unwrap(), metadata);

    let lease = backend.authenticate(&alice).unwrap();
    assert_eq!(lease.kind(), LeaseKind::Cached);
    assert_eq!(lease.generation(), 1);
    assert_eq!(lease.dimension(), EMBEDDING_DIMENSION);
    assert_eq!(lease.entry_count(), 2);
    assert_eq!(lease.labels().collect::<Vec<_>>(), ["desk", "laptop"]);
    assert_eq!(lease.flat_embeddings().len(), 2 * EMBEDDING_DIMENSION);

    assert_eq!(
        backend
            .remove(RemoveRequest::new(&alice, 1, EnrollmentId::new([9; 16]).unwrap()).unwrap())
            .unwrap_err(),
        StorageBackendError::Conflict {
            current_generation: 1
        }
    );
    let removed = backend
        .remove(RemoveRequest::new(&alice, 1, first.enrollment_id()).unwrap())
        .unwrap();
    assert_eq!(removed, RemoveResult::new(2, first.enrollment_id()));
    assert_eq!(backend.list_metadata(&alice).unwrap().entries().len(), 1);

    let reload = backend.reload().unwrap();
    assert_eq!(reload.health(), BackendHealth::Ready);
    assert_eq!(reload.records().len(), 1);
    assert_eq!(
        reload.records()[0].classification(),
        OuterRecordClassification::Candidate { generation: 2 }
    );

    assert_eq!(
        backend
            .clear(ClearRequest::new(&alice, 1).unwrap())
            .unwrap_err(),
        StorageBackendError::Conflict {
            current_generation: 2
        }
    );
    let cleared = backend
        .clear(ClearRequest::new(&alice, 2).unwrap())
        .unwrap();
    assert_eq!(cleared.generation(), ABSENT_GENERATION);
    assert_eq!(cleared.removed(), 1);
    assert_eq!(
        backend.candidate_presence(&alice).unwrap(),
        CandidatePresence::Absent
    );

    backend.set_health(BackendHealth::Unavailable(
        BackendUnavailable::KeyUnavailable,
    ));
    assert_eq!(
        backend.health(),
        BackendHealth::Unavailable(BackendUnavailable::KeyUnavailable)
    );
    assert_eq!(
        backend.candidate_presence(&alice).unwrap_err(),
        StorageBackendError::Unavailable
    );
}

#[test]
fn cached_arc_clones_share_one_permit_until_cache_and_leases_drop() {
    let model = auth_model(&[entry(1, "desk")]);
    let bytes = model.plaintext_bytes();
    let budget = PlaintextBudget::new(bytes).unwrap();
    let cached = CachedAuthModel::new(model, budget.reserve(bytes).unwrap()).unwrap();
    let first = cached.lease();
    let second = cached.lease();
    assert_eq!(budget.used(), bytes);
    assert!(matches!(
        budget.reserve(1),
        Err(StorageBackendError::MemoryBudgetExceeded {
            requested: 1,
            available: 0
        })
    ));

    drop(cached);
    drop(first);
    assert_eq!(budget.used(), bytes);
    drop(second);
    assert_eq!(budget.used(), 0);
}

#[test]
fn mock_cached_eviction_and_ephemeral_requests_have_distinct_lease_lifetimes() {
    let alice = username("alice");
    let record =
        EnrollmentRecord::new(1, model_digest(), alice.clone(), vec![entry(1, "desk")]).unwrap();

    let cached = MockStorageBackend::new(MockLeaseMode::Cached, 1_000_000);
    cached.insert_record(record.clone());
    let lease = cached.authenticate(&alice).unwrap();
    let charged = cached.budget.used();
    assert!(charged > 0);
    cached.evict(&alice);
    assert_eq!(cached.budget.used(), charged);
    drop(lease);
    assert_eq!(cached.budget.used(), 0);

    let ephemeral = MockStorageBackend::new(MockLeaseMode::Ephemeral, 1_000_000);
    ephemeral.insert_record(record);
    let first = ephemeral.authenticate(&alice).unwrap();
    let one_lease = ephemeral.budget.used();
    assert_eq!(first.kind(), LeaseKind::Ephemeral);
    let second = ephemeral.authenticate(&alice).unwrap();
    assert_eq!(ephemeral.budget.used(), one_lease * 2);
    drop(first);
    assert_eq!(ephemeral.budget.used(), one_lease);
    drop(second);
    assert_eq!(ephemeral.budget.used(), 0);
}

#[test]
fn budget_counts_transient_and_lease_reservations_and_recovers_after_pressure() {
    let budget = PlaintextBudget::new(100).unwrap();
    let transient = budget.reserve(60).unwrap();
    assert_eq!(budget.available(), 40);
    assert_eq!(
        budget.reserve(41).unwrap_err(),
        StorageBackendError::MemoryBudgetExceeded {
            requested: 41,
            available: 40
        }
    );
    let operation = budget.reserve(40).unwrap();
    assert_eq!(budget.used(), 100);
    drop(transient);
    assert_eq!(budget.used(), 40);
    drop(operation);
    assert_eq!(budget.used(), 0);
}

#[test]
fn budget_permit_shrink_transfers_transient_accounting_without_a_gap() {
    let budget = PlaintextBudget::new(100).unwrap();
    let permit = budget.reserve(100).unwrap();
    let permit = permit.shrink_to(35).unwrap();
    assert_eq!(permit.bytes(), 35);
    assert_eq!(budget.used(), 35);
    assert_eq!(
        permit.shrink_to(36).unwrap_err(),
        StorageBackendError::InvalidInput("permit shrink size")
    );
    assert_eq!(budget.used(), 0);
}

#[test]
fn enrollment_admission_is_atomic_and_both_raii_parts_remain_charged() {
    let budget = PlaintextBudget::new(100).unwrap();
    let admission = budget.reserve_enrollment(60, 40).unwrap();
    assert_eq!(budget.used(), 100);
    let (operation, input) = admission.into_parts();
    assert_eq!((operation.bytes(), input.bytes()), (60, 40));
    drop(operation);
    assert_eq!(budget.used(), 40);
    drop(input);
    assert_eq!(budget.used(), 0);

    assert!(matches!(
        budget.reserve_enrollment(61, 40),
        Err(StorageBackendError::MemoryBudgetExceeded { .. })
    ));
    assert_eq!(budget.used(), 0);
}

#[test]
fn plaintext_estimate_accounts_for_payload_record_and_flat_model_peak() {
    let record = EnrollmentRecord::new(
        1,
        model_digest(),
        username("alice"),
        vec![entry(1, "desk"), entry(2, "laptop")],
    )
    .unwrap();
    let estimate = PlaintextAllocationEstimate::for_record(&record).unwrap();
    let label_bytes = "desk".len() + "laptop".len();
    let expected_payload =
        CANONICAL_PAYLOAD_FIXED_BYTES + 2 * CANONICAL_ENTRY_FIXED_BYTES + label_bytes;
    let expected_staging = expected_payload + GCM_TAG_BYTES;
    let expected_record = 2 * size_of::<EnrollmentEntry>() + label_bytes;
    let expected_model = 2 * EMBEDDING_DIMENSION * size_of::<f32>()
        + 2 * size_of::<EnrollmentId>()
        + 2 * size_of::<zeroize::Zeroizing<Box<str>>>()
        + label_bytes;
    assert_eq!(estimate.encoded_payload_bytes(), expected_payload);
    assert_eq!(estimate.aead_staging_bytes(), expected_staging);
    assert_eq!(estimate.decoded_record_bytes(), expected_record);
    assert_eq!(estimate.flat_auth_model_bytes(), expected_model);
    assert_eq!(record.plaintext_allocation_bytes(), expected_record);
    let flattened = AuthModel::from_record(&record).unwrap();
    assert_eq!(flattened.plaintext_bytes(), expected_model);
    assert_eq!(
        estimate.cold_load_peak_bytes(),
        (expected_staging + expected_record).max(expected_record + expected_model)
    );
    assert_eq!(
        estimate.mutation_peak_bytes(),
        estimate.encoded_payload_bytes()
            + estimate.aead_staging_bytes()
            + estimate.decoded_record_bytes()
            + estimate.flat_auth_model_bytes()
    );
    assert_eq!(estimate.peak_bytes(), estimate.mutation_peak_bytes());

    let budget = PlaintextBudget::new(estimate.mutation_peak_bytes()).unwrap();
    let reservation = budget.reserve(estimate.mutation_peak_bytes()).unwrap();
    assert_eq!(budget.available(), 0);
    drop(reservation);
    assert_eq!(budget.used(), 0);
}

#[test]
fn plaintext_estimate_accepts_the_exact_payload_maximum_and_rejects_larger_shapes() {
    let mut encoded = vec![0u8; 88 + "alice".len() + MAX_PLAINTEXT_BYTES + GCM_TAG_BYTES];
    encoded[..8].copy_from_slice(b"HOWYENC1");
    encoded[8..10].copy_from_slice(&1u16.to_le_bytes());
    encoded[10..12].copy_from_slice(&1u16.to_le_bytes());
    encoded[12] = StorageMode::AeadCached.identifier();
    encoded[14..16].copy_from_slice(&(93u16).to_le_bytes());
    encoded[16..24].copy_from_slice(&1u64.to_le_bytes());
    encoded[24..32].copy_from_slice(&1u64.to_le_bytes());
    encoded[32..36].copy_from_slice(&(MAX_PLAINTEXT_BYTES as u32).to_le_bytes());
    encoded[36..40].copy_from_slice(&(MAX_ENTRIES as u32).to_le_bytes());
    encoded[40..42].copy_from_slice(&(EMBEDDING_DIMENSION as u16).to_le_bytes());
    encoded[42..44].copy_from_slice(&5u16.to_le_bytes());
    encoded[88..93].copy_from_slice(b"alice");

    let header = inspect_howyenc1(&encoded).unwrap();
    let estimate = PlaintextAllocationEstimate::for_encrypted_header(&header).unwrap();
    assert_eq!(estimate.encoded_payload_bytes(), MAX_PLAINTEXT_BYTES);
    assert_eq!(
        estimate.aead_staging_bytes(),
        MAX_PLAINTEXT_BYTES + GCM_TAG_BYTES
    );
    assert_eq!(
        estimate.peak_bytes(),
        estimate.encoded_payload_bytes()
            + estimate.aead_staging_bytes()
            + estimate.decoded_record_bytes()
            + estimate.flat_auth_model_bytes()
    );

    encoded[32..36].copy_from_slice(&((MAX_PLAINTEXT_BYTES as u32) + 1).to_le_bytes());
    assert!(matches!(
        inspect_howyenc1(&encoded),
        Err(StorageError::LimitExceeded {
            field: "HOWYENC1 plaintext"
        })
    ));
}

#[test]
fn auth_model_and_append_debug_never_format_biometrics() {
    let sensitive = entry(1, "sensitive-label-that-must-not-be-formatted");
    let model = auth_model(std::slice::from_ref(&sensitive));
    let debug = format!("{model:?}");
    assert!(!debug.contains("sensitive-label"));
    assert!(!debug.contains("embedding"));

    let alice = username("alice");
    let entries = [sensitive];
    let request = AppendRequest::new(&alice, ABSENT_GENERATION, &entries).unwrap();
    let debug = format!("{request:?}");
    assert!(debug.contains("entry_count"));
    assert!(!debug.contains("sensitive-label"));
    assert!(!debug.contains("embedding"));

    let metadata = MetadataList::from_record(
        &EnrollmentRecord::new(
            1,
            model_digest(),
            username("alice"),
            vec![entries[0].clone()],
        )
        .unwrap(),
    );
    let debug = format!("{metadata:?}");
    assert!(debug.contains("label_bytes"));
    assert!(!debug.contains("sensitive-label"));
}

#[test]
fn mock_backend_rejects_authentication_when_model_exceeds_budget() {
    let alice = username("alice");
    let record =
        EnrollmentRecord::new(1, model_digest(), alice.clone(), vec![entry(1, "desk")]).unwrap();
    let required = AuthModel::from_record(&record).unwrap().plaintext_bytes();
    let backend = MockStorageBackend::new(MockLeaseMode::Ephemeral, required - 1);
    backend.insert_record(record);
    assert_eq!(
        backend.authenticate(&alice).unwrap_err(),
        StorageBackendError::MemoryBudgetExceeded {
            requested: required,
            available: required - 1
        }
    );
    assert_eq!(backend.budget.used(), 0);
}

#[test]
fn auth_model_validation_is_exact_and_finite() {
    let id = EnrollmentId::new([1; 16]).unwrap();
    let valid = vec![0.0; EMBEDDING_DIMENSION];
    for (dimension, ids, labels, embeddings, expected) in [
        (
            EMBEDDING_DIMENSION - 1,
            vec![id],
            vec!["x".to_owned()],
            valid.clone(),
            "embedding dimension",
        ),
        (
            EMBEDDING_DIMENSION,
            vec![id],
            Vec::new(),
            valid.clone(),
            "model metadata count",
        ),
        (
            EMBEDDING_DIMENSION,
            vec![id],
            vec!["x".to_owned()],
            valid[..EMBEDDING_DIMENSION - 1].to_vec(),
            "flat embedding length",
        ),
    ] {
        assert_eq!(
            AuthModel::new(1, model_digest(), dimension, ids, labels, embeddings).unwrap_err(),
            StorageBackendError::InvalidInput(expected)
        );
    }

    let mut non_finite = valid;
    non_finite[4] = f32::NAN;
    assert_eq!(
        AuthModel::new(
            1,
            model_digest(),
            EMBEDDING_DIMENSION,
            vec![id],
            vec!["x".to_owned()],
            non_finite,
        )
        .unwrap_err(),
        StorageBackendError::InvalidInput("non-finite embedding")
    );
}

#[test]
fn generation_overflow_and_absent_generation_requests_fail_closed() {
    let alice = username("alice");
    assert_eq!(
        RemoveRequest::new(
            &alice,
            ABSENT_GENERATION,
            EnrollmentId::new([1; 16]).unwrap()
        )
        .unwrap_err(),
        StorageBackendError::InvalidInput("remove generation")
    );
    assert_eq!(
        ClearRequest::new(&alice, ABSENT_GENERATION).unwrap_err(),
        StorageBackendError::InvalidInput("clear generation")
    );

    let backend = MockStorageBackend::new(MockLeaseMode::Cached, 1_000_000);
    backend.insert_record(
        EnrollmentRecord::new(
            u64::MAX,
            model_digest(),
            alice.clone(),
            vec![entry(1, "desk")],
        )
        .unwrap(),
    );
    assert_eq!(
        backend
            .append(AppendRequest::new(&alice, u64::MAX, &[entry(2, "new")]).unwrap())
            .unwrap_err(),
        StorageBackendError::GenerationOverflow
    );
}

#[test]
fn io_errors_are_sanitized_and_error_classifications_are_distinct() {
    let source = std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        "secret path /etc/howy/models/alice.bin",
    );
    let error = StorageIoError::new(IoOperation::Open, &source);
    let displayed = error.to_string();
    assert_eq!(error.operation(), IoOperation::Open);
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(!displayed.contains("alice"));
    assert!(!displayed.contains("/etc"));

    let classifications = [
        StorageBackendError::Absent,
        StorageBackendError::Conflict {
            current_generation: 7,
        },
        StorageBackendError::ModeMismatch,
        StorageBackendError::KeyMismatch,
        StorageBackendError::ModelMismatch,
        StorageBackendError::Corrupt,
        StorageBackendError::AuthenticationFailed,
        StorageBackendError::Unavailable,
        StorageBackendError::MemoryBudgetExceeded {
            requested: 2,
            available: 1,
        },
        StorageBackendError::InvalidInput("field"),
        StorageBackendError::Io(error),
    ];
    assert_eq!(classifications.len(), 11);
}

#[test]
fn backend_contract_is_send_sync_and_object_safe() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<MockStorageBackend>();
    let backend: Arc<dyn StorageBackend> =
        Arc::new(MockStorageBackend::new(MockLeaseMode::Ephemeral, 1_000_000));
    assert_eq!(backend.health(), BackendHealth::Ready);
}

#[test]
fn operation_and_outer_status_contracts_cover_all_variants() {
    let operations = [
        StorageOperation::CandidatePresence,
        StorageOperation::Authenticate,
        StorageOperation::ListMetadata,
        StorageOperation::Append,
        StorageOperation::Remove,
        StorageOperation::Clear,
        StorageOperation::Reload,
        StorageOperation::Health,
        StorageOperation::VerifyRecord,
    ];
    assert_eq!(operations.len(), 9);

    let classifications = [
        OuterRecordClassification::Candidate { generation: 1 },
        OuterRecordClassification::ModeMismatch,
        OuterRecordClassification::KeyMismatch,
        OuterRecordClassification::ModelMismatch,
        OuterRecordClassification::Corrupt,
    ];
    assert_eq!(classifications.len(), 5);
}
