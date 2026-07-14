use std::collections::{HashSet, VecDeque};

use super::crypto::MAX_ENCRYPTIONS_PER_KEY_V1;
use super::*;
use zeroize::Zeroize;

const GOLDEN_PLAIN: &str = concat!(
    "484f5759504c4e31010000000900000000000000",
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "0500616c696365",
    "0100000000000000",
);
const GOLDEN_ENCRYPTED: &str = concat!(
    "484f5759454e43310100010001005d0007000000000000000900000000000000",
    "080000000000000000020500",
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "a0a1a2a3a4a5a6a7a8a9aaab",
    "616c696365",
    "e7187c2d45cb02bf45dfcf6c2fc5006f8e44f2b9176fe922",
);
const ENTRY_TEST_FIXED_BYTES: usize = 16 + 8 + 2 + 2 + EMBEDDING_DIMENSION * 4;

fn from_hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(text, 16).unwrap()
        })
        .collect()
}

fn username() -> CanonicalUsername {
    CanonicalUsername::new("alice").unwrap()
}

fn model() -> ModelDigest {
    ModelDigest::new(std::array::from_fn(|index| index as u8))
}

fn key() -> Aes256Key {
    std::array::from_fn(|index| index as u8)
}

fn empty_record() -> EnrollmentRecord {
    EnrollmentRecord::new(9, model(), username(), Vec::new()).unwrap()
}

fn sample_entry(id_byte: u8, label: &str) -> EnrollmentEntry {
    let mut embedding = [0.0; EMBEDDING_DIMENSION];
    embedding[0] = -1.25;
    embedding[1] = 0.5;
    embedding[511] = 3.0;
    EnrollmentEntry::new(
        EnrollmentId::new([id_byte; 16]).unwrap(),
        1_700_000_123,
        label,
        embedding,
    )
    .unwrap()
}

fn populated_record() -> EnrollmentRecord {
    EnrollmentRecord::new(
        3,
        model(),
        username(),
        vec![sample_entry(1, "desk"), sample_entry(2, "laptop")],
    )
    .unwrap()
}

fn encode_with_nonce(
    record: &EnrollmentRecord,
    mode: StorageMode,
    epoch: u64,
    nonce: GcmNonce,
) -> Result<Vec<u8>, StorageError> {
    let source = SequenceSource::new([Ok(nonce.to_vec())]);
    let mut generator = NonceGenerator::from_source(source);
    encode_howyenc1(record, mode, epoch, &key(), &mut generator)
}

fn reauthenticate_payload(encrypted: &[u8], payload: &[u8]) -> Vec<u8> {
    let inspected = inspect_howyenc1(encrypted).unwrap();
    let mut header = encrypted[..inspected.header_length()].to_vec();
    header[32..36].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    let (ciphertext, tag) =
        encrypt_aes_256_gcm(&key(), &inspected.nonce(), &header, payload).unwrap();
    header.extend_from_slice(&ciphertext);
    header.extend_from_slice(&tag);
    header
}

#[test]
fn canonical_username_accepts_only_frozen_ascii_grammar() {
    for valid in ["a", "first..last", "Alice-01_test.name", &"x".repeat(64)] {
        assert!(CanonicalUsername::new(valid).is_ok(), "{valid:?}");
    }
    for invalid in [
        "",
        &"x".repeat(65),
        "a/b",
        "..\\root",
        "has space",
        "josé",
        "line\nfeed",
    ] {
        assert_eq!(
            CanonicalUsername::new(invalid).unwrap_err(),
            StorageError::InvalidUsername
        );
    }
}

#[test]
fn namespace_paths_are_exact_and_permissions_are_frozen() {
    let username = CanonicalUsername::new("Alice-01_test.name").unwrap();
    let expected = [
        (
            RecordNamespace::Plaintext,
            "/etc/howy/models",
            "/etc/howy/models/Alice-01_test.name.bin",
            Some("/etc/howy/models/Alice-01_test.name.json"),
        ),
        (
            RecordNamespace::AeadCached,
            "/etc/howy/models/mode1",
            "/etc/howy/models/mode1/Alice-01_test.name.hye",
            None,
        ),
        (
            RecordNamespace::AeadEphemeral,
            "/etc/howy/models/mode2",
            "/etc/howy/models/mode2/Alice-01_test.name.hye",
            None,
        ),
    ];

    assert_eq!(STORAGE_DIRECTORY_MODE, 0o700);
    assert_eq!(STORAGE_RECORD_MODE, 0o600);
    for (namespace, directory, authoritative, legacy) in expected {
        assert_eq!(namespace.directory(), std::path::Path::new(directory));
        let paths = namespace.record_paths(&username);
        assert_eq!(
            paths.authoritative().as_path(),
            std::path::Path::new(authoritative)
        );
        assert_eq!(
            paths.legacy_fallback().map(RecordPath::as_path),
            legacy.map(std::path::Path::new)
        );
        assert_eq!(paths.iter().count(), 1 + usize::from(legacy.is_some()));
    }
}

#[test]
fn namespace_paths_require_a_traversal_safe_canonical_username() {
    for invalid in [
        "../root",
        "root/child",
        "root\\child",
        "/root",
        "root\0suffix",
    ] {
        assert_eq!(
            CanonicalUsername::new(invalid).unwrap_err(),
            StorageError::InvalidUsername
        );
    }

    let username = CanonicalUsername::new("..hidden").unwrap();
    let path = RecordNamespace::Plaintext.record_paths(&username);
    assert_eq!(
        path.authoritative().as_path().parent(),
        Some(std::path::Path::new(crate::paths::MODELS_DIR))
    );
}

#[test]
fn namespace_selection_marks_only_the_selected_mode_active() {
    let username = username();
    for selected in ALL_RECORD_NAMESPACES {
        let selection = NamespaceSelection::new(selected);
        assert_eq!(selection.active(), selected);
        assert!(!selection.inactive().contains(&selected));

        for namespace in ALL_RECORD_NAMESPACES {
            let inventory = selection.classify_record(
                namespace.record_paths(&username).authoritative().clone(),
                RecordCondition::Compatible,
            );
            if namespace == selected {
                assert_eq!(inventory.activity(), NamespaceActivity::Active);
                assert!(inventory.is_authentication_candidate());
            } else {
                assert_eq!(
                    inventory.activity(),
                    NamespaceActivity::InactiveDiagnosticOnly
                );
                assert!(!inventory.is_authentication_candidate());
            }
        }
    }
}

#[test]
fn all_supported_mode_transitions_preserve_frozen_selection_semantics() {
    let modes = [
        EmbeddingSecurityMode::Plaintext,
        EmbeddingSecurityMode::AeadCached,
        EmbeddingSecurityMode::AeadEphemeral,
    ];

    for previous in modes {
        for selected in modes {
            let decision =
                decide_namespace_transition(previous, selected, RecordCondition::Compatible)
                    .unwrap();
            assert_eq!(decision.previous().security_mode(), previous);
            assert_eq!(decision.selected().security_mode(), selected);
            assert_eq!(
                decision.activation(),
                if previous == selected {
                    TransitionActivation::RemainsSelected
                } else {
                    TransitionActivation::ReactivatesCompatibleRecord
                }
            );
            assert_eq!(
                decision.filesystem_effects(),
                TransitionFilesystemEffects::NONE
            );
            assert_eq!(
                decision.resulting_selection().active().security_mode(),
                selected
            );
        }
    }
}

#[test]
fn transitions_classify_empty_and_incompatible_target_namespaces() {
    let cases = [
        (
            RecordCondition::Absent,
            TransitionActivation::ActivatesEmptyNamespace,
        ),
        (
            RecordCondition::Incompatible(RecordIncompatibility::ModelMismatch),
            TransitionActivation::ActivatesIncompatibleRecord(RecordIncompatibility::ModelMismatch),
        ),
        (
            RecordCondition::Incompatible(RecordIncompatibility::KeyMismatch),
            TransitionActivation::ActivatesIncompatibleRecord(RecordIncompatibility::KeyMismatch),
        ),
        (
            RecordCondition::Incompatible(RecordIncompatibility::InvalidRecord),
            TransitionActivation::ActivatesIncompatibleRecord(RecordIncompatibility::InvalidRecord),
        ),
    ];

    for (condition, expected) in cases {
        let decision = decide_namespace_transition(
            EmbeddingSecurityMode::Plaintext,
            EmbeddingSecurityMode::AeadCached,
            condition,
        )
        .unwrap();
        assert_eq!(decision.selected_condition(), condition);
        assert_eq!(decision.activation(), expected);
        assert_eq!(
            decision.filesystem_effects(),
            TransitionFilesystemEffects::NONE
        );
    }
}

#[test]
fn reserved_mode_has_no_namespace_or_transition() {
    assert_eq!(
        RecordNamespace::try_from(EmbeddingSecurityMode::ReservedFuture).unwrap_err(),
        StorageError::UnsupportedNamespaceMode(3)
    );
    assert_eq!(
        NamespaceSelection::try_from(EmbeddingSecurityMode::ReservedFuture).unwrap_err(),
        StorageError::UnsupportedNamespaceMode(3)
    );
    for (previous, selected) in [
        (
            EmbeddingSecurityMode::ReservedFuture,
            EmbeddingSecurityMode::Plaintext,
        ),
        (
            EmbeddingSecurityMode::Plaintext,
            EmbeddingSecurityMode::ReservedFuture,
        ),
    ] {
        assert_eq!(
            decide_namespace_transition(previous, selected, RecordCondition::Absent).unwrap_err(),
            StorageError::UnsupportedNamespaceMode(3)
        );
    }
}

#[test]
fn explicit_purge_targets_only_selected_inventory() {
    let username = username();
    let selection = NamespaceSelection::new(RecordNamespace::AeadCached);
    let active = selection.classify_record(
        RecordNamespace::AeadCached
            .record_paths(&username)
            .authoritative()
            .clone(),
        RecordCondition::Compatible,
    );
    let inactive = selection.classify_record(
        RecordNamespace::Plaintext
            .record_paths(&username)
            .authoritative()
            .clone(),
        RecordCondition::Compatible,
    );

    assert!(PurgeTarget::InactiveNamespaces.selects(&inactive));
    assert!(!PurgeTarget::InactiveNamespaces.selects(&active));
    let plaintext = PurgeTarget::for_mode(EmbeddingSecurityMode::Plaintext).unwrap();
    assert!(plaintext.selects(&inactive));
    assert!(!plaintext.selects(&active));
    assert_eq!(
        PurgeTarget::for_mode(EmbeddingSecurityMode::ReservedFuture).unwrap_err(),
        StorageError::UnsupportedNamespaceMode(3)
    );
}

#[test]
fn recognizer_digest_hashes_exact_bytes() {
    let digest = recognizer_model_digest(b"recognizer-model-exact-bytes\0\xff");
    assert_eq!(
        digest.as_bytes(),
        &<[u8; 32]>::try_from(from_hex(
            "e001e36f7134990328d7d056b7324cbe1ebce79aa0db4f692f93f4425f1c42e0"
        ))
        .unwrap()
    );
    assert_ne!(
        digest,
        recognizer_model_digest(b"recognizer-model-exact-bytes")
    );
}

#[test]
fn manually_fixed_howypln1_golden_vector_matches() {
    let golden = from_hex(GOLDEN_PLAIN);
    assert_eq!(
        encode_howypln1(&empty_record()).unwrap().as_slice(),
        golden.as_slice()
    );
    assert_eq!(
        decode_howypln1(&golden, &username(), model()).unwrap(),
        empty_record()
    );
}

#[test]
fn manually_fixed_howyenc1_golden_vector_matches() {
    let golden = from_hex(GOLDEN_ENCRYPTED);
    let nonce = std::array::from_fn(|index| 0xa0 + index as u8);
    assert_eq!(
        encode_with_nonce(&empty_record(), StorageMode::AeadCached, 7, nonce).unwrap(),
        golden
    );
    let header = inspect_howyenc1(&golden).unwrap();
    assert_eq!(header.header_length(), 93);
    assert_eq!(header.plaintext_length(), 8);
    assert_eq!(header.entry_count(), 0);
    assert_eq!(header.nonce(), nonce);
    assert_eq!(
        decode_howyenc1(
            &golden,
            &key(),
            StorageMode::AeadCached,
            7,
            &username(),
            model(),
        )
        .unwrap(),
        empty_record()
    );
}

#[test]
fn canonical_payload_and_both_records_round_trip_entries() {
    let record = populated_record();
    let payload = encode_canonical_payload(&record).unwrap();
    assert_eq!(
        decode_canonical_payload(payload.as_slice()).unwrap(),
        record.entries()
    );

    let plain = encode_howypln1(&record).unwrap();
    assert_eq!(
        decode_howypln1(plain.as_slice(), &username(), model()).unwrap(),
        record
    );

    let encrypted = encode_with_nonce(&record, StorageMode::AeadEphemeral, 11, [7; 12]).unwrap();
    assert_eq!(
        decode_howyenc1(
            &encrypted,
            &key(),
            StorageMode::AeadEphemeral,
            11,
            &username(),
            model(),
        )
        .unwrap(),
        record
    );
}

#[test]
fn manually_constructed_nonempty_payload_fixes_entry_offsets() {
    let entry = EnrollmentEntry::new(
        EnrollmentId::new([0x11; 16]).unwrap(),
        0x0102_0304_0506_0708,
        "x",
        [0.0; EMBEDDING_DIMENSION],
    )
    .unwrap();
    let record = EnrollmentRecord::new(1, model(), username(), vec![entry]).unwrap();
    let mut expected = from_hex(concat!(
        "0100000001000000",
        "11111111111111111111111111111111",
        "0807060504030201",
        "01000000",
        "78",
    ));
    expected.resize(expected.len() + EMBEDDING_DIMENSION * 4, 0);
    assert_eq!(
        encode_canonical_payload(&record).unwrap().as_slice(),
        expected.as_slice()
    );
    assert_eq!(
        decode_canonical_payload(&expected).unwrap(),
        record.entries()
    );
}

#[test]
fn nist_aes_256_gcm_vectors_match() {
    let zero_key = [0u8; 32];
    let zero_nonce = [0u8; 12];
    let (ciphertext, tag) = encrypt_aes_256_gcm(&zero_key, &zero_nonce, b"", b"").unwrap();
    assert!(ciphertext.is_empty());
    assert_eq!(tag.as_slice(), from_hex("530f8afbc74536b9a963b4f1c4cb738b"));
    assert_eq!(
        decrypt_aes_256_gcm(&zero_key, &zero_nonce, b"", &ciphertext, &tag)
            .unwrap()
            .as_slice(),
        b""
    );

    let plaintext = [0u8; 16];
    let (ciphertext, tag) = encrypt_aes_256_gcm(&zero_key, &zero_nonce, b"", &plaintext).unwrap();
    assert_eq!(ciphertext, from_hex("cea7403d4d606b6e074ec5d3baf39d18"));
    assert_eq!(tag.as_slice(), from_hex("d0d1c8a799996bf0265b98b5d48ab919"));
    assert_eq!(
        decrypt_aes_256_gcm(&zero_key, &zero_nonce, b"", &ciphertext, &tag)
            .unwrap()
            .as_slice(),
        plaintext
    );
}

#[test]
fn rfc_8452_appendix_a_ghash_vector_matches() {
    use ghash::{GHash, universal_hash::UniversalHash};

    let h: [u8; 16] = from_hex("25629347589242761d31f826ba4b757b")
        .try_into()
        .unwrap();
    let x_1: [u8; 16] = from_hex("4f4f95668c83dfb6401762bb2d01a262")
        .try_into()
        .unwrap();
    let x_2: [u8; 16] = from_hex("d1a24ddd2721d006bbe45f20d3c9f362")
        .try_into()
        .unwrap();
    let expected = from_hex("bd9b3997046731fb96251b91f9c99d7a");
    let mut ghash = GHash::new(&h.into());
    ghash.update(&[x_1.into(), x_2.into()]);
    assert_eq!(ghash.finalize().as_slice(), expected);
}

#[test]
fn pinned_rustcrypto_zeroize_contracts_and_local_patches_are_active() {
    fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}

    // The pinned aes feature provides a drop implementation for every
    // runtime-selected expanded-key backend.
    assert_zeroize_on_drop::<aes::Aes256>();

    // Keep compile-time retained-schedule coverage plus source/provenance
    // tripwires beside runtime vector tests. Vendored crate unit tests provide
    // the stronger forced-unwind/runtime wipe instrumentation.
    let workspace = include_str!("../../../../Cargo.toml");
    assert!(workspace.contains(
        "aes-gcm = { version = \"=0.11.0\", default-features = false, features = [\"aes\", \"alloc\", \"zeroize\"] }"
    ));
    assert!(workspace.contains(
        "aes = { version = \"=0.9.1\", default-features = false, features = [\"zeroize\"] }"
    ));
    assert!(workspace.contains(
        "ghash = { version = \"=0.6.0\", default-features = false, features = [\"zeroize\"] }"
    ));
    assert!(workspace.contains("ghash = { path = \"vendor/ghash-0.6.0\" }"));
    assert!(workspace.contains("aes = { path = \"vendor/aes-0.9.1\" }"));
    assert!(workspace.contains("aes-gcm = { path = \"vendor/aes-gcm-0.11.0\" }"));
    assert!(workspace.contains("polyval = { path = \"vendor/polyval-0.7.2\" }"));

    let ghash = include_str!("../../../../vendor/ghash-0.6.0/src/lib.rs");
    assert!(ghash.contains("let h_reversed = howy_zeroize::Guard::new"));
    assert!(ghash.contains("let h_mulx = howy_zeroize::Guard::new"));
    let ghash_manifest = include_str!("../../../../vendor/ghash-0.6.0/Cargo.toml");
    assert!(
        ghash_manifest
            .contains("zeroize = [\"polyval/zeroize\", \"dep:crypto-common\", \"dep:zeroize\"]")
    );

    let aes = include_str!("../../../../vendor/aes-0.9.1/src/x86/ni/expand.rs");
    assert!(aes.contains("crate::howy_zeroize::Guard::new"));
    let aes_soft = include_str!("../../../../vendor/aes-0.9.1/src/soft/fixslice64.rs");
    assert!(aes_soft.contains("rkeys.take()"));

    let aes_gcm = include_str!("../../../../vendor/aes-gcm-0.11.0/src/lib.rs");
    assert!(aes_gcm.contains("let mut tag_mask = howy_zeroize::Guard::new"));
    assert!(aes_gcm.contains("let mut tag = howy_zeroize::Guard::new"));

    let polyval = include_str!("../../../../vendor/polyval-0.7.2/src/backend/intrinsics.rs");
    assert!(polyval.contains("let mut expanded_key = crate::howy_zeroize::Guard::new"));
    assert!(core::mem::needs_drop::<ghash::GHash>());
}

#[test]
fn aes_gcm_rejects_wrong_key_aad_and_tag() {
    let (ciphertext, tag) = encrypt_aes_256_gcm(&key(), &[4; 12], b"header", b"secret").unwrap();
    for result in [
        decrypt_aes_256_gcm(&[9; 32], &[4; 12], b"header", &ciphertext, &tag),
        decrypt_aes_256_gcm(&key(), &[4; 12], b"wrong", &ciphertext, &tag),
        {
            let mut bad_tag = tag;
            bad_tag[0] ^= 1;
            decrypt_aes_256_gcm(&key(), &[4; 12], b"header", &ciphertext, &bad_tag)
        },
    ] {
        assert_eq!(result.unwrap_err(), StorageError::AuthenticationFailed);
    }
}

#[test]
fn encrypted_record_rejects_wrong_key_and_authenticated_header_changes() {
    let golden = from_hex(GOLDEN_ENCRYPTED);
    assert_eq!(
        decode_howyenc1(
            &golden,
            &[9; 32],
            StorageMode::AeadCached,
            7,
            &username(),
            model(),
        )
        .unwrap_err(),
        StorageError::AuthenticationFailed
    );

    let mut changed = golden;
    changed[88] = b'A';
    assert_eq!(
        decode_howyenc1(
            &changed,
            &key(),
            StorageMode::AeadCached,
            7,
            &CanonicalUsername::new("Alice").unwrap(),
            model(),
        )
        .unwrap_err(),
        StorageError::AuthenticationFailed
    );
}

#[test]
fn strict_bindings_cover_mode_epoch_username_and_model() {
    let encrypted = from_hex(GOLDEN_ENCRYPTED);
    let cases = [
        decode_howyenc1(
            &encrypted,
            &key(),
            StorageMode::AeadEphemeral,
            7,
            &username(),
            model(),
        ),
        decode_howyenc1(
            &encrypted,
            &key(),
            StorageMode::AeadCached,
            8,
            &username(),
            model(),
        ),
        decode_howyenc1(
            &encrypted,
            &key(),
            StorageMode::AeadCached,
            7,
            &CanonicalUsername::new("bob").unwrap(),
            model(),
        ),
        decode_howyenc1(
            &encrypted,
            &key(),
            StorageMode::AeadCached,
            7,
            &username(),
            ModelDigest::new([9; 32]),
        ),
    ];
    for result in cases {
        assert!(matches!(result, Err(StorageError::BindingMismatch(_))));
    }

    let plain = from_hex(GOLDEN_PLAIN);
    assert!(matches!(
        decode_howypln1(&plain, &CanonicalUsername::new("bob").unwrap(), model()),
        Err(StorageError::BindingMismatch("username"))
    ));
    assert!(matches!(
        decode_howypln1(&plain, &username(), ModelDigest::new([9; 32])),
        Err(StorageError::BindingMismatch("recognizer model"))
    ));
}

#[test]
fn record_usernames_must_be_canonical_ascii_utf8() {
    let mut plain = from_hex(GOLDEN_PLAIN);
    plain[54] = 0xff;
    assert_eq!(
        decode_howypln1(&plain, &username(), model()).unwrap_err(),
        StorageError::InvalidUsername
    );

    let mut encrypted = from_hex(GOLDEN_ENCRYPTED);
    encrypted[88] = 0xff;
    assert_eq!(
        inspect_howyenc1(&encrypted).unwrap_err(),
        StorageError::InvalidUsername
    );
}

#[test]
fn encrypted_header_rejects_unknown_fields_and_zero_epoch_generation() {
    let golden = from_hex(GOLDEN_ENCRYPTED);
    for (offset, replacement, expected) in [
        (8, [2, 0], "version"),
        (10, [2, 0], "algorithm"),
        (12, [3, 0], "mode"),
        (13, [1, 0], "flags"),
        (40, [0, 0], "dimension"),
    ] {
        let mut value = golden.clone();
        value[offset] = replacement[0];
        if offset != 12 && offset != 13 {
            value[offset + 1] = replacement[1];
        }
        let error = inspect_howyenc1(&value).unwrap_err();
        match expected {
            "version" => assert!(matches!(error, StorageError::UnsupportedVersion { .. })),
            "algorithm" => assert_eq!(error, StorageError::UnsupportedAlgorithm(2)),
            "mode" => assert_eq!(error, StorageError::UnsupportedMode(3)),
            "flags" => assert!(matches!(error, StorageError::UnknownFlags { .. })),
            "dimension" => assert_eq!(error, StorageError::InvalidEmbeddingDimension(0)),
            _ => unreachable!(),
        }
    }

    for range in [16..24, 24..32] {
        let mut value = golden.clone();
        value[range].fill(0);
        assert!(matches!(
            inspect_howyenc1(&value),
            Err(StorageError::InvalidEpoch | StorageError::InvalidGeneration)
        ));
    }
}

#[test]
fn plaintext_rejects_unknown_version_flags_and_zero_generation() {
    let golden = from_hex(GOLDEN_PLAIN);
    for (range, expected) in [
        (8..10, "version"),
        (10..12, "flags"),
        (12..20, "generation"),
    ] {
        let mut value = golden.clone();
        value[range.clone()].fill(0);
        if expected != "generation" {
            value[range.start] = 2;
        }
        let error = decode_howypln1(&value, &username(), model()).unwrap_err();
        match expected {
            "version" => assert!(matches!(error, StorageError::UnsupportedVersion { .. })),
            "flags" => assert!(matches!(error, StorageError::UnknownFlags { .. })),
            "generation" => assert_eq!(error, StorageError::InvalidGeneration),
            _ => unreachable!(),
        }
    }
}

#[test]
fn representative_truncations_and_trailing_bytes_are_rejected() {
    let encrypted = from_hex(GOLDEN_ENCRYPTED);
    for end in [
        0,
        7,
        8,
        9,
        12,
        15,
        44,
        76,
        87,
        88,
        92,
        93,
        100,
        encrypted.len() - 1,
    ] {
        assert!(inspect_howyenc1(&encrypted[..end]).is_err(), "cut at {end}");
    }
    let mut trailing = encrypted.clone();
    trailing.push(0);
    assert!(inspect_howyenc1(&trailing).is_err());

    let plain = from_hex(GOLDEN_PLAIN);
    for end in [0, 7, 8, 9, 11, 19, 51, 53, 54, 58, plain.len() - 1] {
        assert!(
            decode_howypln1(&plain[..end], &username(), model()).is_err(),
            "cut at {end}"
        );
    }
    trailing = plain;
    trailing.push(0);
    assert!(decode_howypln1(&trailing, &username(), model()).is_err());
}

#[test]
fn payload_rejects_unknown_fields_bounds_utf8_ids_and_nonfinite_values() {
    let payload = encode_canonical_payload(
        &EnrollmentRecord::new(1, model(), username(), vec![sample_entry(1, "x")]).unwrap(),
    )
    .unwrap();

    let mut changed = payload.as_slice().to_vec();
    changed[0] = 2;
    assert!(matches!(
        decode_canonical_payload(&changed),
        Err(StorageError::UnsupportedVersion { .. })
    ));
    changed = payload.as_slice().to_vec();
    changed[2] = 1;
    assert!(matches!(
        decode_canonical_payload(&changed),
        Err(StorageError::InvalidReserved { .. })
    ));
    changed = payload.as_slice().to_vec();
    changed[34] = 1;
    assert!(matches!(
        decode_canonical_payload(&changed),
        Err(StorageError::InvalidReserved { .. })
    ));
    changed = payload.as_slice().to_vec();
    changed[8..24].fill(0);
    assert_eq!(
        decode_canonical_payload(&changed).unwrap_err(),
        StorageError::ZeroEnrollmentId
    );
    changed = payload.as_slice().to_vec();
    changed[36] = 0xff;
    assert_eq!(
        decode_canonical_payload(&changed).unwrap_err(),
        StorageError::InvalidLabelUtf8
    );
    for bits in [f32::NAN.to_bits(), f32::INFINITY.to_bits()] {
        changed = payload.as_slice().to_vec();
        changed[37..41].copy_from_slice(&bits.to_le_bytes());
        assert_eq!(
            decode_canonical_payload(&changed).unwrap_err(),
            StorageError::NonFiniteEmbedding
        );
    }

    let mut too_many = vec![0u8; 8];
    too_many[..2].copy_from_slice(&1u16.to_le_bytes());
    too_many[4..8].copy_from_slice(&1_001u32.to_le_bytes());
    assert!(matches!(
        decode_canonical_payload(&too_many),
        Err(StorageError::LimitExceeded {
            field: "entry count"
        })
    ));

    let mut overlong_label = vec![0u8; 8 + 16 + 8 + 2 + 2 + EMBEDDING_DIMENSION * 4 + 257];
    overlong_label[..2].copy_from_slice(&1u16.to_le_bytes());
    overlong_label[4..8].copy_from_slice(&1u32.to_le_bytes());
    overlong_label[8..24].fill(1);
    overlong_label[32..34].copy_from_slice(&257u16.to_le_bytes());
    assert!(matches!(
        decode_canonical_payload(&overlong_label),
        Err(StorageError::LimitExceeded { field: "label" })
    ));

    let two_entry_record = EnrollmentRecord::new(
        1,
        model(),
        username(),
        vec![sample_entry(1, ""), sample_entry(2, "")],
    )
    .unwrap();
    changed = encode_canonical_payload(&two_entry_record)
        .unwrap()
        .as_slice()
        .to_vec();
    let second_id_offset = 8 + ENTRY_TEST_FIXED_BYTES;
    changed[second_id_offset..second_id_offset + 16].fill(1);
    assert_eq!(
        decode_canonical_payload(&changed).unwrap_err(),
        StorageError::DuplicateEnrollmentId
    );
}

#[test]
fn duplicate_ids_and_header_payload_count_mismatch_are_rejected() {
    assert_eq!(
        EnrollmentRecord::new(
            1,
            model(),
            username(),
            vec![sample_entry(1, "a"), sample_entry(1, "b")],
        )
        .unwrap_err(),
        StorageError::DuplicateEnrollmentId
    );

    let record = EnrollmentRecord::new(1, model(), username(), vec![sample_entry(1, "a")]).unwrap();
    let encrypted = encode_with_nonce(&record, StorageMode::AeadCached, 1, [3; 12]).unwrap();
    let header_length = inspect_howyenc1(&encrypted).unwrap().header_length();
    let mut changed_header = encrypted[..header_length].to_vec();
    changed_header[36..40].copy_from_slice(&0u32.to_le_bytes());
    let payload = encode_canonical_payload(&record).unwrap();
    let (ciphertext, tag) =
        encrypt_aes_256_gcm(&key(), &[3; 12], &changed_header, payload.as_slice()).unwrap();
    changed_header.extend_from_slice(&ciphertext);
    changed_header.extend_from_slice(&tag);
    assert_eq!(
        decode_howyenc1(
            &changed_header,
            &key(),
            StorageMode::AeadCached,
            1,
            &username(),
            model(),
        )
        .unwrap_err(),
        StorageError::EntryCountMismatch
    );
}

#[test]
fn header_length_plaintext_length_and_entry_bounds_fail_before_decrypt() {
    let golden = from_hex(GOLDEN_ENCRYPTED);
    let mut changed = golden.clone();
    changed[14..16].copy_from_slice(&88u16.to_le_bytes());
    assert!(matches!(
        inspect_howyenc1(&changed),
        Err(StorageError::InvalidLength { .. })
    ));
    changed = golden.clone();
    changed[32..36].copy_from_slice(&((MAX_PLAINTEXT_BYTES as u32) + 1).to_le_bytes());
    assert!(matches!(
        inspect_howyenc1(&changed),
        Err(StorageError::LimitExceeded { .. })
    ));
    changed = golden;
    changed[36..40].copy_from_slice(&1_001u32.to_le_bytes());
    assert!(matches!(
        inspect_howyenc1(&changed),
        Err(StorageError::LimitExceeded {
            field: "entry count"
        })
    ));
}

#[test]
fn bounded_encrypted_header_inspection_validates_public_bindings_without_ciphertext() {
    let encrypted = from_hex(GOLDEN_ENCRYPTED);
    let header_length = inspect_howyenc1(&encrypted).unwrap().header_length();
    let prefix = &encrypted[..header_length];
    let inspected = inspect_howyenc1_metadata(
        prefix,
        encrypted.len(),
        StorageMode::AeadCached,
        7,
        &username(),
        model(),
        MAX_ENTRIES,
        MAX_PLAINTEXT_BYTES,
    )
    .unwrap();
    assert_eq!(inspected.record_generation(), 9);
    assert_eq!(inspected.entry_count(), 0);

    for result in [
        inspect_howyenc1_metadata(
            prefix,
            encrypted.len(),
            StorageMode::AeadEphemeral,
            7,
            &username(),
            model(),
            MAX_ENTRIES,
            MAX_PLAINTEXT_BYTES,
        ),
        inspect_howyenc1_metadata(
            prefix,
            encrypted.len(),
            StorageMode::AeadCached,
            8,
            &username(),
            model(),
            MAX_ENTRIES,
            MAX_PLAINTEXT_BYTES,
        ),
        inspect_howyenc1_metadata(
            prefix,
            encrypted.len(),
            StorageMode::AeadCached,
            7,
            &CanonicalUsername::new("bob").unwrap(),
            model(),
            MAX_ENTRIES,
            MAX_PLAINTEXT_BYTES,
        ),
        inspect_howyenc1_metadata(
            prefix,
            encrypted.len(),
            StorageMode::AeadCached,
            7,
            &username(),
            ModelDigest::new([9; 32]),
            MAX_ENTRIES,
            MAX_PLAINTEXT_BYTES,
        ),
    ] {
        assert!(matches!(result, Err(StorageError::BindingMismatch(_))));
    }
    assert!(
        inspect_howyenc1_metadata(
            &prefix[..prefix.len() - 1],
            encrypted.len(),
            StorageMode::AeadCached,
            7,
            &username(),
            model(),
            MAX_ENTRIES,
            MAX_PLAINTEXT_BYTES,
        )
        .is_err()
    );
    assert!(
        inspect_howyenc1_metadata(
            prefix,
            encrypted.len() + 1,
            StorageMode::AeadCached,
            7,
            &username(),
            model(),
            MAX_ENTRIES,
            MAX_PLAINTEXT_BYTES,
        )
        .is_err()
    );
}

#[test]
fn deterministic_legacy_hash_framing_matches_fixed_vectors() {
    let embedding = [0.0; EMBEDDING_DIMENSION];
    assert_eq!(
        legacy_enrollment_id(&username(), 3, 42, "desk", &embedding)
            .unwrap()
            .as_bytes(),
        &<[u8; 16]>::try_from(from_hex("01c4332d7f56218a0a5141af28602165")).unwrap()
    );
    assert_eq!(
        legacy_generation(b"\0\xfflegacy").unwrap(),
        7_575_850_539_303_761_401
    );
    assert_ne!(
        legacy_generation(b"legacy\0\xff").unwrap(),
        legacy_generation(b"\0\xfflegacy").unwrap()
    );
    assert_ne!(
        legacy_enrollment_id(
            &CanonicalUsername::new("Alice").unwrap(),
            3,
            42,
            "desk",
            &embedding,
        )
        .unwrap(),
        legacy_enrollment_id(&username(), 3, 42, "desk", &embedding).unwrap()
    );
}

#[test]
fn generation_helper_is_checked() {
    assert_eq!(checked_next_generation(0).unwrap(), 1);
    assert_eq!(checked_next_generation(41).unwrap(), 42);
    assert_eq!(
        checked_next_generation(u64::MAX).unwrap_err(),
        StorageError::GenerationOverflow
    );
}

struct SequenceSource {
    values: VecDeque<Result<Vec<u8>, String>>,
}

impl SequenceSource {
    fn new(values: impl IntoIterator<Item = Result<Vec<u8>, String>>) -> Self {
        Self {
            values: values.into_iter().collect(),
        }
    }
}

impl RandomSource for SequenceSource {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), String> {
        let value = self
            .values
            .pop_front()
            .unwrap_or_else(|| Err("source exhausted".into()))?;
        if value.len() != destination.len() {
            return Err("wrong test value length".into());
        }
        destination.copy_from_slice(&value);
        Ok(())
    }
}

#[test]
fn nonce_generator_reports_source_failure_duplicate_and_write_ceiling() {
    let source = SequenceSource::new([
        Ok(vec![1; 12]),
        Ok(vec![1; 12]),
        Err("rng unavailable".into()),
    ]);
    let mut generator = NonceGenerator::from_source(source);
    assert_eq!(generator.generate().unwrap(), [1; 12]);
    assert_eq!(
        generator.generate().unwrap_err(),
        StorageError::DuplicateNonce
    );
    assert_eq!(
        generator.generate().unwrap_err(),
        StorageError::RandomSource("rng unavailable".into())
    );
    assert_eq!(generator.accepted_count(), 1);

    let source = SequenceSource::new([Ok(vec![1; 12]), Ok(vec![2; 12])]);
    let mut generator = NonceGenerator::from_source(source);
    assert_eq!(generator.generate().unwrap(), [1; 12]);
    assert_eq!(generator.generate().unwrap(), [2; 12]);
    assert_eq!(generator.accepted_count(), 2);

    let source = SequenceSource::new([Ok(vec![3; 12]), Ok(vec![4; 12])]);
    let mut generator = NonceGenerator::from_source_with_ceiling(source, 1).unwrap();
    assert_eq!(generator.generate().unwrap(), [3; 12]);
    assert_eq!(
        generator.generate().unwrap_err(),
        StorageError::NonceWriteLimitExceeded
    );
    assert_eq!(generator.accepted_count(), 1);
    assert_eq!(
        NonceGenerator::from_source_with_ceiling(
            SequenceSource::new(std::iter::empty::<Result<Vec<u8>, String>>()),
            0,
        )
        .err(),
        Some(StorageError::InvalidNonceCeiling)
    );
}

#[test]
fn nonce_tracker_has_a_fixed_process_lifetime_allocation_and_ceiling() {
    let values = (0..MAX_ENCRYPTIONS_PER_KEY_V1).map(|value| {
        let mut nonce = vec![0u8; 12];
        nonce[..8].copy_from_slice(&value.to_le_bytes());
        Ok(nonce)
    });
    let source = SequenceSource::new(values);
    let mut generator = NonceGenerator::from_source(source);

    generator.generate().unwrap();
    let fixed_capacity = generator.tracker_capacity();
    assert!(fixed_capacity >= MAX_ENCRYPTIONS_PER_KEY_V1 as usize);
    assert!(fixed_capacity <= 2 * MAX_ENCRYPTIONS_PER_KEY_V1 as usize);

    for _ in 1..MAX_ENCRYPTIONS_PER_KEY_V1 {
        generator.generate().unwrap();
        assert_eq!(generator.tracker_capacity(), fixed_capacity);
    }
    assert_eq!(generator.accepted_count(), MAX_ENCRYPTIONS_PER_KEY_V1);
    assert_eq!(
        generator.generate().unwrap_err(),
        StorageError::NonceWriteLimitExceeded
    );
    assert_eq!(generator.tracker_capacity(), fixed_capacity);
}

#[test]
fn accepted_nonce_survives_failed_attempt_and_tracker_reset_is_restart_scoped() {
    let failed_nonce = vec![0x5a; 12];
    let source = SequenceSource::new([Ok(failed_nonce.clone()), Ok(failed_nonce.clone())]);
    let mut process = NonceGenerator::from_source(source);

    // Generation is the acceptance point. A later durable-write failure must
    // not and cannot remove this nonce from the process-lifetime tracker.
    assert_eq!(process.generate().unwrap(), [0x5a; 12]);
    assert_eq!(
        process.generate().unwrap_err(),
        StorageError::DuplicateNonce
    );
    assert_eq!(process.accepted_count(), 1);

    // A fresh generator models daemon restart: v1 intentionally has no durable
    // nonce ledger, and the new process independently accepts OS output.
    let mut restarted = NonceGenerator::from_source(SequenceSource::new([Ok(failed_nonce)]));
    assert_eq!(restarted.generate().unwrap(), [0x5a; 12]);
    assert_eq!(restarted.accepted_count(), 1);
}

#[test]
fn enrollment_id_generation_rejects_failure_zero_and_duplicates() {
    let mut existing = HashSet::new();
    existing.insert(EnrollmentId::new([7; 16]).unwrap());
    for (value, expected) in [
        (Ok(vec![0; 16]), StorageError::ZeroEnrollmentId),
        (Ok(vec![7; 16]), StorageError::DuplicateEnrollmentId),
        (
            Err("rng unavailable".into()),
            StorageError::RandomSource("rng unavailable".into()),
        ),
    ] {
        let mut source = SequenceSource::new([value]);
        assert_eq!(
            generate_enrollment_id(&mut source, &existing).unwrap_err(),
            expected
        );
    }
    let mut source = SequenceSource::new([Ok(vec![8; 16])]);
    assert_eq!(
        generate_enrollment_id(&mut source, &existing).unwrap(),
        EnrollmentId::new([8; 16]).unwrap()
    );
}

#[test]
fn generated_nonce_is_wired_into_the_encrypted_record() {
    let source = SequenceSource::new([Ok(vec![6; 12])]);
    let mut generator = NonceGenerator::from_source(source);
    let encoded = encode_howyenc1(
        &empty_record(),
        StorageMode::AeadCached,
        1,
        &key(),
        &mut generator,
    )
    .unwrap();
    assert_eq!(inspect_howyenc1(&encoded).unwrap().nonce(), [6; 12]);
}

#[test]
fn invalid_constructor_inputs_are_rejected() {
    assert_eq!(
        EnrollmentRecord::new(0, model(), username(), Vec::new()).unwrap_err(),
        StorageError::InvalidGeneration
    );
    assert!(matches!(
        EnrollmentEntry::new(
            EnrollmentId::new([1; 16]).unwrap(),
            0,
            "x".repeat(MAX_LABEL_BYTES + 1),
            [0.0; EMBEDDING_DIMENSION],
        ),
        Err(StorageError::LimitExceeded { field: "label" })
    ));
    let mut embedding = [0.0; EMBEDDING_DIMENSION];
    embedding[4] = f32::NEG_INFINITY;
    assert_eq!(
        EnrollmentEntry::new(EnrollmentId::new([1; 16]).unwrap(), 0, "", embedding).unwrap_err(),
        StorageError::NonFiniteEmbedding
    );
    assert_eq!(
        encode_with_nonce(&empty_record(), StorageMode::AeadCached, 0, [0; 12]).unwrap_err(),
        StorageError::InvalidEpoch
    );
}

#[test]
fn entry_and_record_zeroize_clear_sensitive_fields() {
    let mut entry = sample_entry(1, "sensitive label");
    entry.zeroize();
    assert!(entry.label().as_bytes().iter().all(|byte| *byte == 0));
    assert!(entry.embedding().iter().all(|value| *value == 0.0));

    let mut record = populated_record();
    record.zeroize();
    assert!(record.entries().iter().all(|entry| {
        entry.label().as_bytes().iter().all(|byte| *byte == 0)
            && entry.embedding().iter().all(|value| *value == 0.0)
    }));
}

#[test]
fn sensitive_storage_debug_is_metadata_only() {
    let entry = sample_entry(1, "sensitive-label-that-must-not-be-formatted");
    let entry_debug = format!("{entry:?}");
    assert!(!entry_debug.contains("entry_count"));
    assert!(entry_debug.contains("label_bytes"));
    assert!(!entry_debug.contains("sensitive-label"));
    assert!(!entry_debug.contains("-1.25"));

    let record = EnrollmentRecord::new(3, model(), username(), vec![entry]).unwrap();
    let record_debug = format!("{record:?}");
    assert!(record_debug.contains("entry_count"));
    assert!(!record_debug.contains("sensitive-label"));
    assert!(!record_debug.contains("embedding"));
}

#[test]
fn serialized_plaintext_debug_is_length_only_and_explicit_bytes_still_match() {
    let record = populated_record();
    let payload = encode_canonical_payload(&record).unwrap();
    let payload_debug = format!("{payload:?}");
    assert_eq!(
        payload_debug,
        format!("SensitiveBytes {{ len: {} }}", payload.len())
    );

    let plain = encode_howypln1(&record).unwrap();
    let plain_debug = format!("{plain:?}");
    assert_eq!(
        plain_debug,
        format!("SensitiveBytes {{ len: {} }}", plain.len())
    );

    for debug in [&payload_debug, &plain_debug] {
        assert!(!debug.contains("desk"));
        assert!(!debug.contains("-1.25"));
        assert!(!debug.contains("100, 101, 115, 107"));
        assert!(!debug.contains("0, 0, 160, 191"));
    }

    let golden = from_hex(GOLDEN_PLAIN);
    let golden_plain = encode_howypln1(&empty_record()).unwrap();
    assert_eq!(golden_plain.as_slice(), golden.as_slice());
}

#[test]
fn sensitive_bytes_consuming_write_preserves_wire_bytes() {
    let plain = encode_howypln1(&empty_record()).unwrap();
    assert!(!plain.is_empty());
    let expected_len = plain.len();
    let mut written = Vec::new();
    plain.write_to(&mut written).unwrap();
    assert_eq!(written.len(), expected_len);
    assert_eq!(written, from_hex(GOLDEN_PLAIN));
}

#[test]
fn public_encrypted_encoder_uses_its_backend_nonce_generator() {
    let mut generator = NonceGenerator::new();
    let first = encode_howyenc1(
        &empty_record(),
        StorageMode::AeadCached,
        1,
        &key(),
        &mut generator,
    )
    .unwrap();
    let second = encode_howyenc1(
        &empty_record(),
        StorageMode::AeadCached,
        1,
        &key(),
        &mut generator,
    )
    .unwrap();
    assert_ne!(
        inspect_howyenc1(&first).unwrap().nonce(),
        inspect_howyenc1(&second).unwrap().nonce()
    );
}

#[test]
fn valid_record_derived_structured_header_mutations_are_rejected() {
    let encrypted =
        encode_with_nonce(&populated_record(), StorageMode::AeadCached, 7, [0x55; 12]).unwrap();
    let mutations: &[(std::ops::Range<usize>, &[u8])] = &[
        (8..10, &2u16.to_le_bytes()),
        (10..12, &2u16.to_le_bytes()),
        (12..13, &[3]),
        (13..14, &[1]),
        (14..16, &88u16.to_le_bytes()),
        (16..24, &0u64.to_le_bytes()),
        (24..32, &0u64.to_le_bytes()),
        (32..36, &0u32.to_le_bytes()),
        (36..40, &1_001u32.to_le_bytes()),
        (40..42, &511u16.to_le_bytes()),
        (42..44, &0u16.to_le_bytes()),
    ];
    for (range, replacement) in mutations {
        let mut changed = encrypted.clone();
        changed[range.clone()].copy_from_slice(replacement);
        assert!(inspect_howyenc1(&changed).is_err(), "range {range:?}");
    }

    for end in [87, 88, 92, encrypted.len() - 17, encrypted.len() - 1] {
        assert!(inspect_howyenc1(&encrypted[..end]).is_err(), "cut {end}");
    }
    let mut trailing = encrypted;
    trailing.push(0);
    assert!(inspect_howyenc1(&trailing).is_err());
}

#[test]
fn authenticated_malformed_payload_mutations_reach_semantic_decoder() {
    let record = EnrollmentRecord::new(1, model(), username(), vec![sample_entry(1, "x")]).unwrap();
    let encrypted = encode_with_nonce(&record, StorageMode::AeadCached, 1, [0x66; 12]).unwrap();
    let payload = encode_canonical_payload(&record).unwrap();

    let mut cases = Vec::new();
    let mut changed = payload.as_slice().to_vec();
    changed[0] = 2;
    cases.push((changed, "version"));
    let mut changed = payload.as_slice().to_vec();
    changed[2] = 1;
    cases.push((changed, "reserved"));
    let mut changed = payload.as_slice().to_vec();
    changed[4..8].copy_from_slice(&0u32.to_le_bytes());
    cases.push((changed, "count"));
    let mut changed = payload.as_slice().to_vec();
    changed[8..24].fill(0);
    cases.push((changed, "zero id"));
    let mut changed = payload.as_slice().to_vec();
    changed[36] = 0xff;
    cases.push((changed, "utf8"));
    let mut changed = payload.as_slice().to_vec();
    changed[37..41].copy_from_slice(&f32::NAN.to_bits().to_le_bytes());
    cases.push((changed, "nonfinite"));
    cases.push((
        payload.as_slice()[..payload.len() - 1].to_vec(),
        "truncated",
    ));
    let mut changed = payload.as_slice().to_vec();
    changed.push(0);
    cases.push((changed, "trailing"));

    for (changed_payload, name) in cases {
        let changed = reauthenticate_payload(&encrypted, &changed_payload);
        let error = decode_howyenc1(
            &changed,
            &key(),
            StorageMode::AeadCached,
            1,
            &username(),
            model(),
        )
        .unwrap_err();
        assert_ne!(error, StorageError::AuthenticationFailed, "case {name}");
    }
}

#[test]
fn duplicate_id_validation_paths_allocate_no_hash_tables() {
    for source in [
        include_str!("codec.rs"),
        include_str!("contracts.rs"),
        include_str!("mod.rs"),
    ] {
        assert!(!source.contains("HashSet"));
    }
}

#[test]
fn bound_adjacent_values_round_trip_and_outer_binding_mismatches_precede_aead() {
    let boundary_username = CanonicalUsername::new("x".repeat(64)).unwrap();
    let record = EnrollmentRecord::new(
        u64::MAX,
        model(),
        boundary_username.clone(),
        vec![sample_entry(1, &"l".repeat(MAX_LABEL_BYTES))],
    )
    .unwrap();
    let encrypted =
        encode_with_nonce(&record, StorageMode::AeadEphemeral, u64::MAX, [0x77; 12]).unwrap();
    assert_eq!(
        decode_howyenc1(
            &encrypted,
            &key(),
            StorageMode::AeadEphemeral,
            u64::MAX,
            &boundary_username,
            model(),
        )
        .unwrap(),
        record
    );

    // A deliberately wrong key still yields binding errors: all public outer
    // bindings are checked immediately after inspection and before AEAD work.
    for result in [
        decode_howyenc1(
            &encrypted,
            &[0xff; 32],
            StorageMode::AeadCached,
            u64::MAX,
            &boundary_username,
            model(),
        ),
        decode_howyenc1(
            &encrypted,
            &[0xff; 32],
            StorageMode::AeadEphemeral,
            u64::MAX - 1,
            &boundary_username,
            model(),
        ),
        decode_howyenc1(
            &encrypted,
            &[0xff; 32],
            StorageMode::AeadEphemeral,
            u64::MAX,
            &username(),
            model(),
        ),
        decode_howyenc1(
            &encrypted,
            &[0xff; 32],
            StorageMode::AeadEphemeral,
            u64::MAX,
            &boundary_username,
            ModelDigest::new([9; 32]),
        ),
    ] {
        assert!(matches!(result, Err(StorageError::BindingMismatch(_))));
    }
}

#[test]
fn corpus_style_decoder_inputs_never_panic() {
    let expected_username = username();
    let expected_model = model();
    let key = key();
    let mut state = 0x9e37_79b9u32;
    for length in 0..512usize {
        let mut input = vec![0u8; length];
        for byte in &mut input {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            *byte = state as u8;
        }
        let result = std::panic::catch_unwind(|| {
            let _ = decode_canonical_payload(&input);
            let _ = inspect_howyenc1(&input);
            let _ = decode_howypln1(&input, &expected_username, expected_model);
            let _ = decode_howyenc1(
                &input,
                &key,
                StorageMode::AeadCached,
                1,
                &expected_username,
                expected_model,
            );
        });
        assert!(result.is_ok(), "decoder panicked for length {length}");
    }
}
