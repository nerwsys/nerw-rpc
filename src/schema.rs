//! Built-in `schema_get` method — registry self-description.
//!
//! Per Pavel ratify `feedback_pavel_schema_get_in_nerw_rpc` (2026-05-11):
//! every nerw-rpc server exposes a mandatory built-in method that
//! returns the canonical names of all currently-registered methods.
//! Operators и tooling can call this к discover what а remote node
//! supports без out-of-band documentation.
//!
//! ## Wire contract
//!
//! - **Method:** `nerw:schema@1.0.0/schema/get`
//! - **Request:**  empty `()` (no fields — encoded as а zero-byte
//!   postcard payload).
//! - **Response:** [`SchemaResponse`] — single `methods: Vec<String>`
//!   field with every registered method's canonical name в
//!   lexicographic order.
//!
//! ## Hybrid return (Pavel ratify
//! `feedback_pavel_schema_get_hybrid_return`, 2026-05-11)
//!
//! Phase 1 ships the method-list slice only. Adding а
//! `wit_source: Option<String>` field is а forward-compatible
//! postcard extension — old clients keep parsing the existing fields
//! when newer servers start emitting WIT source.

use crate::context::RpcContext;
use crate::error::{RpcError, RpcResult};
use crate::method::MethodHandler;
use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::sync::Weak;

use crate::method::MethodRegistry;

/// Canonical name of the built-in `schema_get` method.
///
/// Pinned as а constant so daemon code, CLI code, и tests share one
/// source of truth — а rename anywhere would otherwise silently
/// partition the discovery surface.
pub const METHOD_SCHEMA_GET: &str = "nerw:schema@1.0.0/schema/get";

/// Response payload for `schema_get`.
///
/// `methods` is the list of canonical method names registered on the
/// responding node, sorted ascending. An empty list means the responder
/// has registered no application methods (the built-in `schema_get`
/// always shows up if the method is reachable, so an empty list is
/// observable only via direct registry introspection).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SchemaResponse {
    /// Sorted ascending list of registered canonical method names.
    pub methods: Vec<String>,
}

/// [`MethodHandler`] implementation for `schema_get`.
///
/// Holds a [`Weak`] reference to the [`MethodRegistry`] so that
/// registering the handler doesn't form a strong reference cycle
/// (`Arc<MethodRegistry>` owns the `Arc<dyn MethodHandler>` which would
/// own а strong `Arc<MethodRegistry>` back).
pub struct SchemaHandler {
    /// Weak handle so the registry can free even while а dispatch
    /// loop holds the handler `Arc`.
    registry: Weak<MethodRegistry>,
}

impl SchemaHandler {
    /// Wrap а weak handle to the registry. Caller is expected to
    /// `register_schema_method(&registry)` after this so the registry
    /// itself owns the handler.
    #[must_use]
    pub const fn new(registry: Weak<MethodRegistry>) -> Self {
        Self { registry }
    }
}

#[async_trait]
impl MethodHandler for SchemaHandler {
    async fn handle(&self, _ctx: RpcContext, _request: Bytes) -> RpcResult<Bytes> {
        let methods = match self.registry.upgrade() {
            Some(r) => r.method_names(),
            // Registry has been dropped — surface as а handler error so
            // the caller observes а typed failure rather than а deadlock.
            None => {
                return Err(RpcError::Handler(Box::new(SchemaError::RegistryGone)));
            }
        };
        let response = SchemaResponse { methods };
        let bytes = postcard::to_allocvec(&response).map_err(RpcError::Codec)?;
        Ok(Bytes::from(bytes))
    }
}

/// Errors surfaced by [`SchemaHandler`].
#[derive(Debug, thiserror::Error)]
pub enum SchemaError {
    /// The [`MethodRegistry`] this handler observes has been dropped.
    ///
    /// In production this should never happen: the server owns the
    /// registry and tears it down only at process shutdown. Tests that
    /// drop the registry while а call is in-flight surface this variant
    /// as а typed error rather than panicking.
    #[error("method registry has been dropped")]
    RegistryGone,
}

/// Register the built-in [`SchemaHandler`] on `registry`.
///
/// Use [`MethodRegistry::new`] + [`Arc::new_cyclic`] так that the
/// schema handler can observe its parent registry via а [`Weak`]
/// without forming а cycle:
///
/// ```no_run
/// # use std::sync::Arc;
/// # use nerw_rpc::{MethodRegistry, register_schema_method};
/// let registry = Arc::new_cyclic(|weak| {
///     let mut reg = MethodRegistry::new();
///     // register application methods…
///     register_schema_method(&mut reg, weak.clone());
///     reg
/// });
/// ```
pub fn register_schema_method(
    registry: &mut MethodRegistry,
    weak: std::sync::Weak<MethodRegistry>,
) {
    registry.register(METHOD_SCHEMA_GET, Arc::new(SchemaHandler::new(weak)));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::PeerMetadata;

    #[tokio::test]
    async fn schema_returns_registered_method_names() {
        struct EchoHandler;
        #[async_trait]
        impl MethodHandler for EchoHandler {
            async fn handle(&self, _ctx: RpcContext, req: Bytes) -> RpcResult<Bytes> {
                Ok(req)
            }
        }

        let registry: Arc<MethodRegistry> = Arc::new_cyclic(|weak| {
            let mut reg = MethodRegistry::new();
            reg.register("foo:app@1.0.0/iface/echo", Arc::new(EchoHandler));
            reg.register("bar:app@1.0.0/iface/echo", Arc::new(EchoHandler));
            register_schema_method(&mut reg, weak.clone());
            reg
        });

        let handler = registry.lookup(METHOD_SCHEMA_GET).expect("registered");
        let ctx = RpcContext::minimal(PeerMetadata::loopback());
        let out = handler.handle(ctx, Bytes::new()).await.expect("ok");
        let decoded: SchemaResponse = postcard::from_bytes(&out).expect("decode");
        // 3 methods registered: foo, bar, schema_get itself.
        assert_eq!(decoded.methods.len(), 3);
        assert!(decoded.methods.contains(&METHOD_SCHEMA_GET.to_owned()));
        assert!(
            decoded
                .methods
                .contains(&"foo:app@1.0.0/iface/echo".to_owned())
        );
        assert!(
            decoded
                .methods
                .contains(&"bar:app@1.0.0/iface/echo".to_owned())
        );
        // Sorted ascending.
        let mut sorted = decoded.methods.clone();
        sorted.sort();
        assert_eq!(decoded.methods, sorted);
    }

    #[test]
    fn schema_response_roundtrips_via_postcard() {
        let original = SchemaResponse {
            methods: vec![
                "nerw:schema@1.0.0/schema/get".to_owned(),
                "nerw:supervisor@1.0.0/agents/list".to_owned(),
            ],
        };
        let bytes = postcard::to_allocvec(&original).expect("encode");
        let decoded: SchemaResponse = postcard::from_bytes(&bytes).expect("decode");
        assert_eq!(decoded, original);
    }

    #[test]
    fn method_name_constant_parses() {
        use crate::method::MethodName;
        let parsed = MethodName::parse(METHOD_SCHEMA_GET).expect("canonical");
        assert_eq!(parsed.package, "nerw:schema");
        assert_eq!(parsed.interface, "schema");
        assert_eq!(parsed.method, "get");
    }
}
