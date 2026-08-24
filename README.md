# Fruit Basket

A single-purpose, immutable, integrity-enforcing Linux appliance OS: it hosts exactly one
web-exposed application on a rented virtual machine — beside the appliance's own supporting
services (TLS edge, ACME, SSH, backup, monitoring, time) — and makes the machine as close to
incorruptible as the substrate allows.

> [!WARNING]
> Every line of code and documentation in this repository is LLM output, written end to end by
> Claude (Anthropic) under the direction and review of a human operator. Read and reuse it with
> that provenance in mind.

There is no package manager, no runtime configuration surface, and no shell-reachable path that
mutates the running system. The image that leaves the build pipeline is, byte for byte, the
system that runs, and the kernel enforces that equivalence continuously:

- a read-only squashfs rootfs under **dm-verity** (corrupt block → reboot);
- **IMA/EVM appraisal** — every `execve` and executable `mmap` of a root-owned file must carry a
  valid signature chained to the operator's CA, which is embedded at kernel build;
- `CONFIG_MODULES=n`, lockdown in integrity mode, all writable mounts `noexec,nosuid,nodev`;
- two purpose-built Rust PID-1 programs (`initramfs-init` for verified early boot and
  installation, `box-init` for bootstrap and supervision hand-off), `panic=abort`, no shell
  fallback, every failure path enumerated;
- A/B slots, offline crash recovery, a recovery-key rescue surface, derived (precomputable) SSH
  host keys, and operator-pulled, signature-verified backups.

The full design — threat model, boot chain, integrity architecture, init and supervision,
networking, persistence and recovery, the reproducible build pipeline, and the accepted
limitations — is in **[WHITEPAPER.md](WHITEPAPER.md)**.

## Components

| Crate | Role |
|---|---|
| `crates/box-init` | runtime PID 1: bootstrap one-shots, network bring-up, services-vs-rescue branch, supervision hand-off |
| `crates/initramfs-init` | early-boot PID 1: cmdline contract, dm-verity setup, IMA policy load, `switch_root`; doubles as the copy-only installer |
| `crates/rambutan` | the hand-rolled UEFI Secure Boot loader (the operator-enrolled-keys arm) |
| `crates/fb-acme` | ACME HTTP-01 challenge server + certificate renewal client |
| `crates/fb-backup`, `crates/fb-cert-check` | daily snapshot; daily certificate-expiry alarm |
| `crates/fb-oneshots` | the in-image bootstrap one-shot binary |
| `crates/fb-update`, `crates/fb-weights` | A/B update tooling and the sealed-data-volume tooling |
| `crates/fb-manifest` | the validated service-manifest / topology schema |
| `crates/fb-verity-rt`, `crates/quince` | dm-verity runtime plumbing; shared support |

## About this repository

This is the published export of a private canonical repository, produced by an
equivalence-gated release tool:

- **Complete for reading, not for standalone building.** Several manifests carry path
  dependencies on an unpublished sibling library repository, and the build/deploy factory, the
  payload application, and the signing pipeline live in further unpublished repositories, so
  `cargo build` will not resolve here as checked out. The release gate proves that this exact
  source builds the shipped binaries inside the pinned build container with the sibling present.
- **Working comments are padded out, not deleted.** Internal non-doc comments are replaced with
  same-length whitespace so the published source builds byte-identical binaries; runs of
  trailing spaces and blank-looking lines are that padding. Doc comments publish as written.
- **Every release commit carries its proof.** The commit message records the canonical commit id
  and a gate witness list: per-file token-stream identity, doc-comment byte-identity,
  byte-identical built binaries for all nine shipped programs, per-workspace compile checks, and
  a content tripwire over every published byte.

Extracted from a private monorepo in June 2026; the pre-split history stays in the private
archive. Verification runs in the canonical repository: fmt + clippy + the workspace and
standalone test suites + the supply-chain locks (the CRUX "box never signs" lock, the
cmdline-namespace lock, the crypto sentry).

## License

`GPL-2.0-only` — see [`COPYING`](COPYING). Fruit Basket is the OS, and the OS is copyleft: a distributed derivative stays open. GPLv2 **specifically** (not v3/AGPL) because the signed, verified-boot model — a loader that refuses unsigned code — is exactly the "tivoization" GPLv3's anti-tivoization clause forbids; v2 is also what the kernel + busybox it ships beside use. `-only` (not `-or-later`) so no future GPL revision can retroactively add v3-style terms to the boot chain.

The copyleft is a floor the system sits on, not a solvent:
- **Bundled third-party components** (Linux kernel, busybox, haproxy, nftables, e2fsprogs, …) keep their own licenses — shipping them in the image is mere aggregation, not relicensing.
- **Apps that run on the box** (separate binaries talking via the service manifest / sockets / exec) keep their own licenses — same as userspace on the GPLv2 kernel. Only *statically linking* an FB GPL-2.0 crate into an app's binary pulls that app under GPLv2.
- **Reusable library crates** live in the sibling ecosystem repos under their own permissive (MIT/Apache) terms.
