//! ============================================================================
//! ciel-keychaind - Access Control Policy Engine
//!
//! Evaluates and enforces per-application security decisions:
//! - Determines whether a caller (identified by binary path, PID, and UID) is
//!   authorized to access or modify a secret.
//! - Caches runtime user approvals (`AllowAlways`, `AllowOnce`).
//! - Dispatches interactive confirmation requests to the prompter UI when
//!   an untrusted or unrecognized application requests secrets.
//! ============================================================================

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

use crate::config::AccessPolicyDefault;
use crate::dbus::caller::CallerIdentity;

/// Result of evaluating an access policy for a specific caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessDecision {
    /// Access is permanently or persistently permitted.
    Allow,
    /// Access is permitted for the current transaction only.
    AllowOnce,
    /// Interactive user prompt is required to authorize the caller.
    PromptRequired,
    /// Access is explicitly denied.
    Deny,
}

/// Key identifying an application binary rule.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ApplicationKey {
    uid: u32,
    binary_path: Option<PathBuf>,
}

/// Access control engine evaluating caller credentials against cached policies.
pub struct PolicyEngine {
    default_policy: AccessPolicyDefault,
    persistent_rules: Arc<RwLock<HashMap<ApplicationKey, AccessDecision>>>,
}

impl PolicyEngine {
    /// Creates a new policy engine configured with system defaults.
    pub fn new(default_policy: AccessPolicyDefault) -> Self {
        Self {
            default_policy,
            persistent_rules: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Evaluates access for a given caller.
    pub async fn evaluate_access(&self, caller: &CallerIdentity) -> AccessDecision {
        let key = ApplicationKey {
            uid: caller.uid,
            binary_path: caller.binary_path.clone(),
        };

        let rules = self.persistent_rules.read().await;
        if let Some(&decision) = rules.get(&key) {
            debug!(
                "Policy matched cached rule {:?} for {:?}",
                decision,
                caller.display_label()
            );
            return decision;
        }

        // Apply default configuration behavior
        match self.default_policy {
            AccessPolicyDefault::Allow => AccessDecision::Allow,
            AccessPolicyDefault::Deny => AccessDecision::Deny,
            AccessPolicyDefault::Prompt => AccessDecision::PromptRequired,
        }
    }

    /// Records a user's decision for future requests from the same binary.
    pub async fn record_decision(&self, caller: &CallerIdentity, decision: AccessDecision) {
        if decision == AccessDecision::AllowOnce {
            // AllowOnce is not stored in persistent rules
            return;
        }

        let key = ApplicationKey {
            uid: caller.uid,
            binary_path: caller.binary_path.clone(),
        };

        let mut rules = self.persistent_rules.write().await;
        info!(
            "Recording policy decision {:?} for caller {:?}",
            decision,
            caller.display_label()
        );
        rules.insert(key, decision);
    }
}
