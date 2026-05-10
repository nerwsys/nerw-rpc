//! Method registry — text canonical names → handler dispatch.
//!
//! Per design D7, method-id is the **text canonical name**
//! `package[@version]/interface/method` (e.g. `tolki:chat@1.0.0/chat/send-message`).
//! The registry stores handlers keyed by their fully-qualified canonical
//! name (with version) and resolves version-omitted lookups к the highest
//! registered semver under the same `package/interface/method` triple.
//!
//! Phase 1 ships the core types and dispatch table. Phase 2 wires the
//! registry into the iroh accept loop and serves the mandatory schema
//! discoverability method (`tolki:schema@1.0.0/schema/get`).

use crate::context::RpcContext;
use crate::error::RpcResult;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;

/// Trait для method handlers — application code implements this for each
/// RPC method.
///
/// The transport layer hands the handler a [`RpcContext`] (peer identity,
/// timing, auth, …) and the postcard-encoded request bytes. The handler
/// returns postcard-encoded response bytes (or an [`crate::error::RpcError`]
/// — typically wrapping a domain error in [`crate::error::RpcError::Handler`]).
///
/// Codec calls live at the caller boundary, not inside the handler trait,
/// so the registry stays generic over arbitrary request/response shapes.
#[async_trait]
pub trait MethodHandler: Send + Sync + 'static {
    /// Handle a request — bytes in, bytes out.
    async fn handle(&self, ctx: RpcContext, request_bytes: &[u8]) -> RpcResult<Vec<u8>>;
}

/// Parsed canonical method name `package[@version]/interface/method`.
///
/// Examples:
/// - `"tolki:chat@1.0.0/chat/send-message"` — pinned version
/// - `"tolki:chat/chat/send-message"`        — version omitted (latest)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MethodName {
    /// Package identifier — e.g. `"tolki:chat"`. WIT-style `namespace:name`.
    pub package: String,

    /// Optional pinned version — e.g. `Some("1.0.0")`. `None` means
    /// "give me the latest semver".
    pub version: Option<String>,

    /// Interface name — e.g. `"chat"`.
    pub interface: String,

    /// Method name — e.g. `"send-message"`.
    pub method: String,
}

impl MethodName {
    /// Parse the canonical text method-id.
    ///
    /// Returns `None` if the input doesn't match the
    /// `package[@version]/interface/method` grammar (any empty segment
    /// is rejected).
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        let mut parts = s.splitn(3, '/');
        let pkg_part = parts.next()?;
        let interface = parts.next()?.to_string();
        let method = parts.next()?.to_string();

        if pkg_part.is_empty() || interface.is_empty() || method.is_empty() {
            return None;
        }

        let (package, version) = match pkg_part.find('@') {
            Some(idx) => {
                let pkg = pkg_part[..idx].to_string();
                let ver = pkg_part[idx + 1..].to_string();
                if pkg.is_empty() || ver.is_empty() {
                    return None;
                }
                (pkg, Some(ver))
            }
            None => (pkg_part.to_string(), None),
        };

        Some(MethodName {
            package,
            version,
            interface,
            method,
        })
    }

    /// Reconstruct the canonical text representation.
    #[must_use]
    pub fn to_canonical(&self) -> String {
        match &self.version {
            Some(v) => format!("{}@{}/{}/{}", self.package, v, self.interface, self.method),
            None => format!("{}/{}/{}", self.package, self.interface, self.method),
        }
    }
}

/// Method dispatch registry.
///
/// Keyed by **fully-qualified canonical name** (with version) —
/// e.g. `"tolki:chat@1.0.0/chat/send-message"`. Lookups for the
/// version-omitted form resolve to the lexicographically largest
/// registered version under the same `package/interface/method` triple.
///
/// Phase 1 uses lexicographic ordering, which is correct for semver
/// strings only when each component is a single digit. Phase 2 will
/// upgrade the resolver to use a real semver parser.
#[derive(Default)]
pub struct MethodRegistry {
    handlers: HashMap<String, Arc<dyn MethodHandler>>,
}

impl MethodRegistry {
    /// Build an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a handler under its canonical name.
    ///
    /// # Panics
    ///
    /// Panics if `canonical_name` is malformed or lacks `@version` —
    /// registered handlers must always pin a concrete version so version
    /// resolution at lookup time is unambiguous.
    #[allow(clippy::panic, clippy::missing_panics_doc)]
    pub fn register(&mut self, canonical_name: &str, handler: Arc<dyn MethodHandler>) {
        let Some(parsed) = MethodName::parse(canonical_name) else {
            panic!("invalid method name: {canonical_name}");
        };
        assert!(
            parsed.version.is_some(),
            "registered handlers must include version: got {canonical_name}"
        );
        self.handlers.insert(canonical_name.to_string(), handler);
    }

    /// Lookup a handler by canonical name.
    ///
    /// Supports version-omitted form (`"package/iface/method"`) — resolves
    /// to the largest registered version under the same triple.
    #[must_use]
    pub fn lookup(&self, name: &str) -> Option<Arc<dyn MethodHandler>> {
        // Exact match first — pinned version case.
        if let Some(h) = self.handlers.get(name) {
            return Some(Arc::clone(h));
        }

        // Try version-omitted resolution.
        let parsed = MethodName::parse(name)?;
        if parsed.version.is_some() {
            // Caller pinned a version that doesn't exist — no fallback.
            return None;
        }

        let prefix = format!("{}@", parsed.package);
        let suffix = format!("/{}/{}", parsed.interface, parsed.method);
        let max = self
            .handlers
            .keys()
            .filter(|k| k.starts_with(&prefix) && k.ends_with(&suffix))
            .max()?;
        self.handlers.get(max).map(Arc::clone)
    }

    /// `true` if no handlers are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.handlers.is_empty()
    }

    /// Number of registered handlers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.handlers.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::PeerMetadata;

    #[test]
    fn parse_pinned_method_name() {
        let n = MethodName::parse("tolki:chat@1.0.0/chat/send-message").expect("parse");
        assert_eq!(n.package, "tolki:chat");
        assert_eq!(n.version, Some("1.0.0".to_string()));
        assert_eq!(n.interface, "chat");
        assert_eq!(n.method, "send-message");
    }

    #[test]
    fn parse_unpinned_method_name() {
        let n = MethodName::parse("tolki:chat/chat/send-message").expect("parse");
        assert_eq!(n.package, "tolki:chat");
        assert_eq!(n.version, None);
        assert_eq!(n.interface, "chat");
        assert_eq!(n.method, "send-message");
    }

    #[test]
    fn parse_rejects_malformed() {
        assert!(MethodName::parse("").is_none());
        assert!(MethodName::parse("tolki:chat").is_none());
        assert!(MethodName::parse("tolki:chat/chat").is_none());
        // Empty package before `@`.
        assert!(MethodName::parse("@1.0.0/chat/send-message").is_none());
        // Empty version after `@`.
        assert!(MethodName::parse("tolki:chat@/chat/send-message").is_none());
        // Empty interface segment.
        assert!(MethodName::parse("tolki:chat//send-message").is_none());
        // Empty method segment.
        assert!(MethodName::parse("tolki:chat/chat/").is_none());
    }

    #[test]
    fn canonical_roundtrip_pinned() {
        let canon = "tolki:chat@1.0.0/chat/send-message";
        let parsed = MethodName::parse(canon).expect("parse");
        assert_eq!(parsed.to_canonical(), canon);
    }

    #[test]
    fn canonical_roundtrip_unpinned() {
        let canon = "tolki:chat/chat/send-message";
        let parsed = MethodName::parse(canon).expect("parse");
        assert_eq!(parsed.to_canonical(), canon);
    }

    struct EchoHandler;

    #[async_trait]
    impl MethodHandler for EchoHandler {
        async fn handle(&self, _ctx: RpcContext, request_bytes: &[u8]) -> RpcResult<Vec<u8>> {
            Ok(request_bytes.to_vec())
        }
    }

    #[test]
    fn registry_exact_lookup() {
        let mut reg = MethodRegistry::new();
        reg.register("tolki:chat@1.0.0/chat/send-message", Arc::new(EchoHandler));
        assert_eq!(reg.len(), 1);
        assert!(!reg.is_empty());
        assert!(reg.lookup("tolki:chat@1.0.0/chat/send-message").is_some());
    }

    #[test]
    fn registry_version_resolution_picks_max() {
        let mut reg = MethodRegistry::new();
        reg.register("tolki:chat@1.0.0/chat/send-message", Arc::new(EchoHandler));
        reg.register("tolki:chat@1.1.0/chat/send-message", Arc::new(EchoHandler));
        // Unpinned lookup → must resolve.
        assert!(reg.lookup("tolki:chat/chat/send-message").is_some());
    }

    #[test]
    fn registry_pinned_miss_no_fallback() {
        let mut reg = MethodRegistry::new();
        reg.register("tolki:chat@1.0.0/chat/send-message", Arc::new(EchoHandler));
        // Pinned to a version that doesn't exist — must NOT fall back.
        assert!(reg.lookup("tolki:chat@2.0.0/chat/send-message").is_none());
    }

    #[test]
    fn registry_lookup_unknown() {
        let reg = MethodRegistry::new();
        assert!(reg.lookup("nope:nope@1.0.0/x/y").is_none());
        assert!(reg.is_empty());
    }

    #[tokio::test]
    async fn handler_invocation_roundtrip() {
        let h: Arc<dyn MethodHandler> = Arc::new(EchoHandler);
        let ctx = RpcContext::minimal(PeerMetadata::loopback());
        let out = h.handle(ctx, b"hello").await.expect("handler ok");
        assert_eq!(out, b"hello");
    }

    #[test]
    #[should_panic(expected = "registered handlers must include version")]
    fn registry_register_without_version_panics() {
        let mut reg = MethodRegistry::new();
        reg.register("tolki:chat/chat/send-message", Arc::new(EchoHandler));
    }

    #[test]
    #[should_panic(expected = "invalid method name")]
    fn registry_register_malformed_panics() {
        let mut reg = MethodRegistry::new();
        reg.register("not-a-valid-name", Arc::new(EchoHandler));
    }
}
