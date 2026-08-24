//! fb-weights — the hotswappable-model runtime (hotswap v4 spec §3–§6).
//!
//! The model is optional-tenant DATA on a dedicated weights partition, integrity-enforced by
//! RUNTIME dm-verity (via [`fb_verity_rt`]-extracted primitives), trust-anchored by a persisted
//! operator-signed weights manifest (`Purpose::Weights`) with a co-located anti-rollback floor.
//!
//! - [`stores`] — the `/persist/weights/` record: one atomically-written file holding
//!   {floor, manifest bytes, 254-byte signature bundle}; strict fail-closed reads; the writer
//!   never lowers the floor. (Task 3.)
//! - [`setup`] — the boot-time weights-verity-setup: clock-free verify (Rider 1) → PARTUUID
//!   resolve → runtime dm-verity (EIO) → `/models` RO mount; s6-scoped fail-closed. (Task 4.)
//! - [`swap`] — the flocked, fail-closed swap sequencer: clocked preflight → supervised stop →
//!   teardown → stream-verified raw write → verity+mount → real-inference health → the atomic
//!   commit LAST. (Task 5; host-tested over the ops seam.)
//! - [`boxops`] — the real box-side ops (`s6-svc`, the raw-partition writer, the loopback health
//!   probe) + the baked engine/health config readers.

#![forbid(unsafe_code)]
                                                                                                     
                                                                                                  
                                                
#![cfg_attr(not(test), deny(clippy::unwrap_used))]

pub mod boxops;
pub mod setup;
pub mod stores;
pub mod swap;
