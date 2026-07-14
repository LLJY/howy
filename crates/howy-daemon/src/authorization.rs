//! Exhaustive daemon request authorization and canonical NSS identity resolution.

use howy_common::paths;

const DEFAULT_NSS_BUFFER_SIZE: usize = 16 * 1024;
const MAX_NSS_BUFFER_SIZE: usize = 1024 * 1024;

/// Canonical identity returned by NSS for an authorized target.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalIdentity {
    username: String,
    uid: u32,
}

impl CanonicalIdentity {
    pub fn new(username: impl Into<String>, uid: u32) -> Self {
        Self {
            username: username.into(),
            uid,
        }
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub const fn uid(&self) -> u32 {
        self.uid
    }
}

/// NSS failures are deliberately opaque to request handlers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityLookupError {
    System(i32),
    InvalidRecord,
    BufferLimit,
}

/// Injectable identity lookup boundary used by the pure policy and its tests.
pub trait IdentityResolver {
    fn resolve(
        &self,
        requested_username: &str,
    ) -> Result<Option<CanonicalIdentity>, IdentityLookupError>;
}

/// Production resolver backed by the thread-safe `getpwnam_r` interface.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemIdentityResolver;

impl IdentityResolver for SystemIdentityResolver {
    fn resolve(
        &self,
        requested_username: &str,
    ) -> Result<Option<CanonicalIdentity>, IdentityLookupError> {
        let requested = std::ffi::CString::new(requested_username)
            .map_err(|_| IdentityLookupError::InvalidRecord)?;
        let suggested = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
        let mut buffer_size = if suggested > 0 {
            usize::try_from(suggested)
                .unwrap_or(MAX_NSS_BUFFER_SIZE)
                .clamp(1, MAX_NSS_BUFFER_SIZE)
        } else {
            DEFAULT_NSS_BUFFER_SIZE
        };

        loop {
            let mut buffer = vec![0_u8; buffer_size];
            let mut passwd = unsafe { std::mem::zeroed::<libc::passwd>() };
            let mut result = std::ptr::null_mut::<libc::passwd>();
            let status = unsafe {
                libc::getpwnam_r(
                    requested.as_ptr(),
                    &mut passwd,
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    &mut result,
                )
            };

            if status == libc::EINTR {
                continue;
            }
            if status == libc::ERANGE {
                if buffer_size == MAX_NSS_BUFFER_SIZE {
                    return Err(IdentityLookupError::BufferLimit);
                }
                buffer_size = buffer_size.saturating_mul(2).min(MAX_NSS_BUFFER_SIZE);
                continue;
            }
            if status != 0 {
                return Err(IdentityLookupError::System(status));
            }
            if result.is_null() {
                return Ok(None);
            }

            let buffer_start = buffer.as_ptr() as usize;
            let buffer_end = buffer_start.saturating_add(buffer.len());
            let name_start = passwd.pw_name as usize;
            if name_start < buffer_start || name_start >= buffer_end {
                return Err(IdentityLookupError::InvalidRecord);
            }
            let name_offset = name_start - buffer_start;
            let bounded_name = &buffer[name_offset..];
            let name_length = bounded_name
                .iter()
                .position(|byte| *byte == 0)
                .ok_or(IdentityLookupError::InvalidRecord)?;
            let canonical = std::str::from_utf8(&bounded_name[..name_length])
                .map_err(|_| IdentityLookupError::InvalidRecord)?;

            return Ok(Some(CanonicalIdentity::new(canonical, passwd.pw_uid)));
        }
    }
}

/// Connection state needed by future prompt commit/cancel authorization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConnectionPhase {
    Initial,
    PendingAuth {
        peer_uid: u32,
        target: CanonicalIdentity,
    },
    Finished,
}

/// Inputs shared by every authorization decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationContext {
    pub peer_uid: u32,
    pub confirmation_required: bool,
    pub connection_phase: ConnectionPhase,
}

impl AuthorizationContext {
    pub const fn initial(peer_uid: u32, confirmation_required: bool) -> Self {
        Self {
            peer_uid,
            confirmation_required,
            connection_phase: ConnectionPhase::Initial,
        }
    }
}

/// Current and planned daemon operations. Planned operations remain policy-only.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation<'a> {
    Ping,
    PublicInfo,
    Authenticate { target: &'a str },
    BeginAuth { target: &'a str },
    CommitAuth,
    CancelAuth,
    EnrollmentPresence { target: &'a str },
    CheckCredential { target: &'a str },
    RevokeCredential { target: &'a str },
    Enroll { target: &'a str },
    EnrollBatch { target: &'a str },
    Detect,
    ListEnrollments { target: &'a str },
    RemoveEnrollment { target: &'a str },
    ClearEnrollments { target: &'a str },
    SecurityInfo,
    Reload,
    Shutdown,
    Unknown,
    WrongPhase,
}

impl<'a> Operation<'a> {
    fn target(self) -> Option<&'a str> {
        match self {
            Self::Authenticate { target }
            | Self::BeginAuth { target }
            | Self::EnrollmentPresence { target }
            | Self::CheckCredential { target }
            | Self::RevokeCredential { target }
            | Self::Enroll { target }
            | Self::EnrollBatch { target }
            | Self::ListEnrollments { target }
            | Self::RemoveEnrollment { target }
            | Self::ClearEnrollments { target } => Some(target),
            Self::Ping
            | Self::PublicInfo
            | Self::CommitAuth
            | Self::CancelAuth
            | Self::Detect
            | Self::SecurityInfo
            | Self::Reload
            | Self::Shutdown
            | Self::Unknown
            | Self::WrongPhase => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DenialReason {
    InvalidTarget,
    UnknownTarget,
    NonCanonicalTarget,
    IdentityLookupFailed,
    PermissionDenied,
    ConfirmationRequired,
    WrongPhase,
    UnknownOperation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Authorization {
    canonical_target: Option<CanonicalIdentity>,
}

impl Authorization {
    pub fn canonical_target(&self) -> Option<&CanonicalIdentity> {
        self.canonical_target.as_ref()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Decision {
    Allow(Authorization),
    Deny(DenialReason),
}

/// Resolve any target first, then apply the exhaustive operation policy.
pub fn authorize<R: IdentityResolver>(
    resolver: &R,
    operation: Operation<'_>,
    context: &AuthorizationContext,
) -> Decision {
    if operation == Operation::Unknown {
        return Decision::Deny(DenialReason::UnknownOperation);
    }
    if operation == Operation::WrongPhase {
        return Decision::Deny(DenialReason::WrongPhase);
    }

    let requested_target = match operation {
        Operation::CommitAuth | Operation::CancelAuth => match &context.connection_phase {
            ConnectionPhase::PendingAuth { target, .. } => Some(target.username()),
            ConnectionPhase::Initial | ConnectionPhase::Finished => {
                return Decision::Deny(DenialReason::WrongPhase);
            }
        },
        _ => operation.target(),
    };
    let canonical_target = match requested_target {
        Some(target) => match resolve_canonical_target(resolver, target) {
            Ok(identity) => Some(identity),
            Err(reason) => return Decision::Deny(reason),
        },
        None => None,
    };

    let target = canonical_target.as_ref();
    let allowed = match operation {
        Operation::Ping | Operation::PublicInfo => true,
        Operation::Authenticate { .. } => {
            if context.confirmation_required {
                return Decision::Deny(DenialReason::ConfirmationRequired);
            }
            target.is_some_and(|target| peer_may_target(context.peer_uid, target))
        }
        Operation::BeginAuth { .. } => {
            if !context.confirmation_required {
                return Decision::Deny(DenialReason::WrongPhase);
            }
            target.is_some_and(|target| peer_may_target(context.peer_uid, target))
        }
        Operation::EnrollmentPresence { .. }
        | Operation::CheckCredential { .. }
        | Operation::RevokeCredential { .. } => {
            target.is_some_and(|target| peer_may_target(context.peer_uid, target))
        }
        Operation::CommitAuth | Operation::CancelAuth => {
            if !context.confirmation_required {
                return Decision::Deny(DenialReason::WrongPhase);
            }
            target.is_some_and(|target| {
                peer_may_target(context.peer_uid, target) && connection_is_bound(context, target)
            })
        }
        Operation::Enroll { .. }
        | Operation::EnrollBatch { .. }
        | Operation::ListEnrollments { .. }
        | Operation::RemoveEnrollment { .. }
        | Operation::ClearEnrollments { .. } => context.peer_uid == 0 && target.is_some(),
        Operation::Detect | Operation::SecurityInfo | Operation::Reload | Operation::Shutdown => {
            context.peer_uid == 0
        }
        Operation::Unknown | Operation::WrongPhase => false,
    };

    if allowed {
        Decision::Allow(Authorization { canonical_target })
    } else if matches!(operation, Operation::CommitAuth | Operation::CancelAuth) {
        Decision::Deny(DenialReason::WrongPhase)
    } else {
        Decision::Deny(DenialReason::PermissionDenied)
    }
}

/// Execute a request body only after an allow decision.
pub fn authorize_and_then<R, T>(
    resolver: &R,
    operation: Operation<'_>,
    context: &AuthorizationContext,
    run: impl FnOnce(Authorization) -> T,
) -> Result<T, DenialReason>
where
    R: IdentityResolver,
{
    match authorize(resolver, operation, context) {
        Decision::Allow(authorization) => Ok(run(authorization)),
        Decision::Deny(reason) => Err(reason),
    }
}

fn resolve_canonical_target<R: IdentityResolver>(
    resolver: &R,
    requested: &str,
) -> Result<CanonicalIdentity, DenialReason> {
    if !paths::validate_username(requested) {
        return Err(DenialReason::InvalidTarget);
    }
    let resolved = resolver
        .resolve(requested)
        .map_err(|_| DenialReason::IdentityLookupFailed)?
        .ok_or(DenialReason::UnknownTarget)?;
    if !paths::validate_username(resolved.username()) || requested != resolved.username() {
        return Err(DenialReason::NonCanonicalTarget);
    }
    Ok(resolved)
}

fn peer_may_target(peer_uid: u32, target: &CanonicalIdentity) -> bool {
    peer_uid == 0 || peer_uid == target.uid()
}

fn connection_is_bound(context: &AuthorizationContext, target: &CanonicalIdentity) -> bool {
    matches!(
        &context.connection_phase,
        ConnectionPhase::PendingAuth {
            peer_uid,
            target: pending_target,
        } if *peer_uid == context.peer_uid && pending_target == target
    )
}

#[cfg(test)]
mod tests {
    use super::{
        AuthorizationContext, CanonicalIdentity, ConnectionPhase, Decision, DenialReason,
        IdentityLookupError, IdentityResolver, Operation, SystemIdentityResolver, authorize,
        authorize_and_then,
    };
    use std::cell::Cell;

    const ROOT_UID: u32 = 0;
    const ALICE_UID: u32 = 1000;
    const OTHER_UID: u32 = 1001;

    #[derive(Default)]
    struct MockResolver {
        calls: Cell<usize>,
    }

    impl IdentityResolver for MockResolver {
        fn resolve(
            &self,
            requested_username: &str,
        ) -> Result<Option<CanonicalIdentity>, IdentityLookupError> {
            self.calls.set(self.calls.get() + 1);
            match requested_username {
                "alice" => Ok(Some(CanonicalIdentity::new("alice", ALICE_UID))),
                "root" => Ok(Some(CanonicalIdentity::new("root", ROOT_UID))),
                "alias" => Ok(Some(CanonicalIdentity::new("alice", ALICE_UID))),
                "lookup-error" => Err(IdentityLookupError::System(libc::EIO)),
                _ => Ok(None),
            }
        }
    }

    #[derive(Clone, Copy)]
    struct MatrixCase {
        name: &'static str,
        operation: fn(&'static str) -> Operation<'static>,
        matching_allowed: bool,
        root_allowed: bool,
        other_allowed: bool,
        connection_bound: bool,
    }

    fn target_cases() -> [MatrixCase; 10] {
        [
            MatrixCase {
                name: "authenticate",
                operation: |target| Operation::Authenticate { target },
                matching_allowed: true,
                root_allowed: true,
                other_allowed: false,
                connection_bound: false,
            },
            MatrixCase {
                name: "begin_auth",
                operation: |target| Operation::BeginAuth { target },
                matching_allowed: true,
                root_allowed: true,
                other_allowed: false,
                connection_bound: false,
            },
            MatrixCase {
                name: "enrollment_presence",
                operation: |target| Operation::EnrollmentPresence { target },
                matching_allowed: true,
                root_allowed: true,
                other_allowed: false,
                connection_bound: false,
            },
            MatrixCase {
                name: "check_credential",
                operation: |target| Operation::CheckCredential { target },
                matching_allowed: true,
                root_allowed: true,
                other_allowed: false,
                connection_bound: false,
            },
            MatrixCase {
                name: "revoke_credential",
                operation: |target| Operation::RevokeCredential { target },
                matching_allowed: true,
                root_allowed: true,
                other_allowed: false,
                connection_bound: false,
            },
            MatrixCase {
                name: "enroll",
                operation: |target| Operation::Enroll { target },
                matching_allowed: false,
                root_allowed: true,
                other_allowed: false,
                connection_bound: false,
            },
            MatrixCase {
                name: "enroll_batch",
                operation: |target| Operation::EnrollBatch { target },
                matching_allowed: false,
                root_allowed: true,
                other_allowed: false,
                connection_bound: false,
            },
            MatrixCase {
                name: "list_enrollments",
                operation: |target| Operation::ListEnrollments { target },
                matching_allowed: false,
                root_allowed: true,
                other_allowed: false,
                connection_bound: false,
            },
            MatrixCase {
                name: "remove_enrollment",
                operation: |target| Operation::RemoveEnrollment { target },
                matching_allowed: false,
                root_allowed: true,
                other_allowed: false,
                connection_bound: false,
            },
            MatrixCase {
                name: "clear_enrollments",
                operation: |target| Operation::ClearEnrollments { target },
                matching_allowed: false,
                root_allowed: true,
                other_allowed: false,
                connection_bound: false,
            },
        ]
    }

    fn context(peer_uid: u32, connection_bound: bool) -> AuthorizationContext {
        let connection_phase = if connection_bound {
            ConnectionPhase::PendingAuth {
                peer_uid,
                target: CanonicalIdentity::new("alice", ALICE_UID),
            }
        } else {
            ConnectionPhase::Initial
        };
        AuthorizationContext {
            peer_uid,
            confirmation_required: false,
            connection_phase,
        }
    }

    fn is_allowed(decision: Decision) -> bool {
        matches!(decision, Decision::Allow(_))
    }

    #[test]
    fn authorization_target_matrix_is_exhaustive() {
        let resolver = MockResolver::default();
        for case in target_cases() {
            for (role, peer_uid, expected) in [
                ("matching", ALICE_UID, case.matching_allowed),
                ("root", ROOT_UID, case.root_allowed),
                ("other", OTHER_UID, case.other_allowed),
            ] {
                let mut authorization_context = context(peer_uid, case.connection_bound);
                authorization_context.confirmation_required = case.name == "begin_auth";
                let decision =
                    authorize(&resolver, (case.operation)("alice"), &authorization_context);
                assert_eq!(is_allowed(decision), expected, "{} for {role}", case.name);
            }
        }
    }

    #[test]
    fn authorization_targetless_matrix_is_exhaustive() {
        let resolver = MockResolver::default();
        let cases = [
            ("ping", Operation::Ping, true, true, true),
            ("public_info", Operation::PublicInfo, true, true, true),
            ("detect", Operation::Detect, false, true, false),
            ("security_info", Operation::SecurityInfo, false, true, false),
            ("reload", Operation::Reload, false, true, false),
            ("shutdown", Operation::Shutdown, false, true, false),
            ("unknown", Operation::Unknown, false, false, false),
            ("wrong_phase", Operation::WrongPhase, false, false, false),
        ];
        for (name, operation, matching, root, other) in cases {
            for (role, uid, expected) in [
                ("matching", ALICE_UID, matching),
                ("root", ROOT_UID, root),
                ("other", OTHER_UID, other),
            ] {
                assert_eq!(
                    is_allowed(authorize(&resolver, operation, &context(uid, false))),
                    expected,
                    "{name} for {role}"
                );
            }
        }
        assert_eq!(resolver.calls.get(), 0);
    }

    #[test]
    fn every_target_operation_rejects_unknown_and_noncanonical_users() {
        let resolver = MockResolver::default();
        for case in target_cases() {
            for (target, expected) in [
                ("missing", DenialReason::UnknownTarget),
                ("alias", DenialReason::NonCanonicalTarget),
                ("../alice", DenialReason::InvalidTarget),
            ] {
                assert_eq!(
                    authorize(
                        &resolver,
                        (case.operation)(target),
                        &context(ROOT_UID, case.connection_bound),
                    ),
                    Decision::Deny(expected),
                    "{} with {target}",
                    case.name
                );
            }
        }
        for operation in [Operation::CommitAuth, Operation::CancelAuth] {
            for (target, expected) in [
                (
                    CanonicalIdentity::new("missing", ALICE_UID),
                    DenialReason::UnknownTarget,
                ),
                (
                    CanonicalIdentity::new("alias", ALICE_UID),
                    DenialReason::NonCanonicalTarget,
                ),
                (
                    CanonicalIdentity::new("../alice", ALICE_UID),
                    DenialReason::InvalidTarget,
                ),
            ] {
                assert_eq!(
                    authorize(
                        &resolver,
                        operation,
                        &AuthorizationContext {
                            peer_uid: ROOT_UID,
                            confirmation_required: true,
                            connection_phase: ConnectionPhase::PendingAuth {
                                peer_uid: ROOT_UID,
                                target,
                            },
                        },
                    ),
                    Decision::Deny(expected),
                    "{operation:?}"
                );
            }
        }
    }

    #[test]
    fn root_target_requests_still_require_nss_resolution() {
        let resolver = MockResolver::default();
        assert!(is_allowed(authorize(
            &resolver,
            Operation::Enroll { target: "alice" },
            &context(ROOT_UID, false),
        )));
        assert_eq!(resolver.calls.get(), 1);
        assert_eq!(
            authorize(
                &resolver,
                Operation::Enroll { target: "missing" },
                &context(ROOT_UID, false),
            ),
            Decision::Deny(DenialReason::UnknownTarget)
        );
    }

    #[test]
    fn confirmation_requires_begin_auth_instead_of_one_shot_authenticate() {
        let resolver = MockResolver::default();
        for peer_uid in [ROOT_UID, ALICE_UID] {
            assert_eq!(
                authorize(
                    &resolver,
                    Operation::Authenticate { target: "alice" },
                    &AuthorizationContext::initial(peer_uid, true),
                ),
                Decision::Deny(DenialReason::ConfirmationRequired)
            );
            assert!(is_allowed(authorize(
                &resolver,
                Operation::BeginAuth { target: "alice" },
                &AuthorizationContext::initial(peer_uid, true),
            )));
            assert_eq!(
                authorize(
                    &resolver,
                    Operation::BeginAuth { target: "alice" },
                    &AuthorizationContext::initial(peer_uid, false),
                ),
                Decision::Deny(DenialReason::WrongPhase)
            );
        }
    }

    #[test]
    fn commit_and_cancel_are_bound_to_connection_peer_and_target() {
        let resolver = MockResolver::default();
        for operation in [Operation::CommitAuth, Operation::CancelAuth] {
            assert_eq!(
                authorize(
                    &resolver,
                    operation,
                    &AuthorizationContext {
                        peer_uid: ALICE_UID,
                        confirmation_required: false,
                        connection_phase: ConnectionPhase::PendingAuth {
                            peer_uid: ALICE_UID,
                            target: CanonicalIdentity::new("alice", ALICE_UID),
                        },
                    },
                ),
                Decision::Deny(DenialReason::WrongPhase)
            );
            for (role, peer_uid, expected) in [
                ("matching", ALICE_UID, true),
                ("root", ROOT_UID, true),
                ("other", OTHER_UID, false),
            ] {
                assert_eq!(
                    is_allowed(authorize(
                        &resolver,
                        operation,
                        &AuthorizationContext {
                            peer_uid,
                            confirmation_required: true,
                            connection_phase: ConnectionPhase::PendingAuth {
                                peer_uid,
                                target: CanonicalIdentity::new("alice", ALICE_UID),
                            },
                        },
                    )),
                    expected,
                    "{operation:?} for {role}"
                );
            }
            assert_eq!(
                authorize(
                    &resolver,
                    operation,
                    &AuthorizationContext::initial(ALICE_UID, true),
                ),
                Decision::Deny(DenialReason::WrongPhase)
            );
            assert_eq!(
                authorize(
                    &resolver,
                    operation,
                    &AuthorizationContext {
                        peer_uid: ALICE_UID,
                        confirmation_required: true,
                        connection_phase: ConnectionPhase::Finished,
                    },
                ),
                Decision::Deny(DenialReason::WrongPhase)
            );
            assert_eq!(
                authorize(
                    &resolver,
                    operation,
                    &AuthorizationContext {
                        peer_uid: ALICE_UID,
                        confirmation_required: true,
                        connection_phase: ConnectionPhase::PendingAuth {
                            peer_uid: OTHER_UID,
                            target: CanonicalIdentity::new("alice", ALICE_UID),
                        },
                    },
                ),
                Decision::Deny(DenialReason::WrongPhase)
            );
            assert_eq!(
                authorize(
                    &resolver,
                    operation,
                    &AuthorizationContext {
                        peer_uid: ALICE_UID,
                        confirmation_required: true,
                        connection_phase: ConnectionPhase::PendingAuth {
                            peer_uid: ALICE_UID,
                            target: CanonicalIdentity::new("root", ROOT_UID),
                        },
                    },
                ),
                Decision::Deny(DenialReason::WrongPhase)
            );
        }
    }

    #[test]
    fn denied_requests_do_not_run_side_effect_body() {
        let resolver = MockResolver::default();
        let storage_calls = Cell::new(0_u32);
        let credential_calls = Cell::new(0_u32);
        let inference_calls = Cell::new(0_u32);
        let camera_calls = Cell::new(0_u32);
        for operation in [
            Operation::Authenticate { target: "alice" },
            Operation::EnrollmentPresence { target: "alice" },
            Operation::Enroll { target: "alice" },
            Operation::EnrollBatch { target: "alice" },
            Operation::ListEnrollments { target: "alice" },
            Operation::RemoveEnrollment { target: "alice" },
            Operation::ClearEnrollments { target: "alice" },
            Operation::Reload,
            Operation::SecurityInfo,
            Operation::Detect,
            Operation::CheckCredential { target: "alice" },
            Operation::RevokeCredential { target: "alice" },
            Operation::Shutdown,
            Operation::Unknown,
        ] {
            let result =
                authorize_and_then(&resolver, operation, &context(OTHER_UID, false), |_| {
                    storage_calls.set(storage_calls.get() + 1);
                    credential_calls.set(credential_calls.get() + 1);
                    inference_calls.set(inference_calls.get() + 1);
                    camera_calls.set(camera_calls.get() + 1);
                });
            assert!(result.is_err(), "{operation:?}");
        }
        assert_eq!(storage_calls.get(), 0);
        assert_eq!(credential_calls.get(), 0);
        assert_eq!(inference_calls.get(), 0);
        assert_eq!(camera_calls.get(), 0);
    }

    #[test]
    fn allowed_decision_returns_only_the_canonical_target() {
        let resolver = MockResolver::default();
        let Decision::Allow(authorization) = authorize(
            &resolver,
            Operation::Authenticate { target: "alice" },
            &context(ALICE_UID, false),
        ) else {
            panic!("matching user should be authorized");
        };
        assert_eq!(
            authorization.canonical_target(),
            Some(&CanonicalIdentity::new("alice", ALICE_UID))
        );
    }

    #[test]
    fn nss_failure_is_fail_closed() {
        let resolver = MockResolver::default();
        assert_eq!(
            authorize(
                &resolver,
                Operation::Authenticate {
                    target: "lookup-error",
                },
                &context(ALICE_UID, false),
            ),
            Decision::Deny(DenialReason::IdentityLookupFailed)
        );
    }

    #[test]
    fn system_nss_resolver_returns_the_exact_root_identity() {
        let root = SystemIdentityResolver.resolve("root").unwrap().unwrap();
        assert_eq!(root, CanonicalIdentity::new("root", ROOT_UID));
    }
}
