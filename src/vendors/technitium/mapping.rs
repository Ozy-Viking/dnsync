//! Technitium-specific type and parameter mapping.
//!
//! Technitium uses form-encoded HTTP POST parameters (`(&str, &str)` pairs)
//! rather than JSON request bodies for most endpoints. Record-type-specific
//! parameters are produced by [`core::dns::records::RecordData::to_api_params()`];
//! zone/cache/stats/access-list parameters are constructed inline in the
//! service trait implementations.
//!
//! When a feature requires Technitium-specific type conversions (e.g., mapping
//! Technitium's JSON response fields to core domain types), the conversion
//! logic belongs here.
