# Fruit Basket

A single-purpose, immutable Linux appliance OS that enforces its own integrity. It hosts exactly
one web-exposed application on a rented virtual machine, beside the appliance's supporting services
(TLS edge, ACME, SSH, backup, monitoring, time), and hardens the machine as far as the substrate
allows.

> [!WARNING]
> Every line of code and documentation in this repository is LLM output, written end to end by
> Claude (Anthropic) under the direction and review of a human operator. Read and reuse it with
> that provenance in mind.

The system has no package manager, no runtime configuration surface, and no shell-reachable path
that mutates it. The running system is byte for byte the image the build pipeline produced, and the
kernel enforces that equivalence while it runs:

- a read-only squashfs rootfs under dm-verity (a corrupt block triggers a reboot);
- IMA/EVM appraisal: every `execve` and executable `mmap` of a root-owned file must carry a valid
  signature chained to the operator's CA, which is embedded at kernel build;
- `CONFIG_MODULES=n`, lockdown in integrity mode, and `noexec,nosuid,nodev` on all writable mounts;
- two purpose-built Rust PID-1 programs (`initramfs-init` for verified early boot and installation,
  `box-init` for bootstrap and supervision hand-off), built with `panic=abort`, with no shell
  fallback and every failure path enumerated;
- A/B slots, offline crash recovery, a recovery-key rescue surface, derived (precomputable) SSH
  host keys, and operator-pulled, signature-verified backups.

[WHITEPAPER.md](WHITEPAPER.md) covers the full design: threat model, boot chain, integrity
architecture, init and supervision, networking, persistence and recovery, the reproducible build
pipeline, and the accepted limitations. A rendered version is at
<https://fruitvibes123.github.io/fruit-basket/>. The UEFI Secure Boot loader has its own paper:
[Rambutan](https://fruitvibes123.github.io/fruit-basket/rambutan-whitepaper.html).

## Components

| Crate | Role |
|---|---|
| `crates/box-init` | runtime PID 1: bootstrap one-shots, network bring-up, services-vs-rescue branch, supervision hand-off |
| `crates/initramfs-init` | early-boot PID 1: cmdline contract, dm-verity setup, IMA policy load, `switch_root`; doubles as the copy-only installer |
| `crates/rambutan` | the hand-rolled UEFI Secure Boot loader (the operator-enrolled-keys arm; [its whitepaper](https://fruitvibes123.github.io/fruit-basket/rambutan-whitepaper.html)) |
| `crates/fb-acme` | ACME HTTP-01 challenge server and certificate renewal client |
| `crates/fb-backup`, `crates/fb-cert-check` | daily snapshot; daily certificate-expiry alarm |
| `crates/fb-oneshots` | the in-image bootstrap one-shot binary |
| `crates/fb-update`, `crates/fb-weights` | A/B update tooling and the sealed-data-volume tooling |
| `crates/fb-manifest` | the validated service-manifest and topology schema |
| `crates/fb-verity-rt`, `crates/quince` | dm-verity runtime plumbing; shared support |

## About this repository

An equivalence-gated release tool produces this repository from a private canonical repository.

- Several manifests carry path dependencies on the sibling library repository
  [seed-vault](https://github.com/fruitvibes123/seed-vault). Clone it beside this checkout and the
  workspaces resolve. [orchard](https://github.com/fruitvibes123/orchard) is the build/deploy
  factory that turns this source into a bootable image; its guide walks the whole path (container,
  keys, artifact store, bake, boot). The payload application and the signing pipeline are
  unpublished; bring your own application per the `fb-manifest` service-manifest schema. The
  release gate proves that this source builds the shipped binaries inside the pinned build
  container with the sibling present.
- Internal non-doc comments are replaced with whitespace of the same length, so the published
  source builds byte-identical binaries. Runs of trailing spaces and blank-looking lines are that
  padding. Doc comments publish as written.
- Each release commit message records the canonical commit id and a gate witness list: per-file
  token-stream identity, doc-comment byte-identity, byte-identical built binaries for all nine
  shipped programs, per-workspace compile checks, and a content tripwire over every published byte.

The code was extracted from a private monorepo in June 2026; the pre-split history stays in the
private archive. Verification runs in the canonical repository: fmt, clippy, the workspace and
standalone test suites, and the supply-chain locks (the CRUX "box never signs" lock, the
cmdline-namespace lock, the crypto sentry).

## License

`GPL-2.0-only`; the text is in [`COPYING`](COPYING). The OS is copyleft, so a distributed
derivative stays open. GPLv3's anti-tivoization clause forbids "tivoization", and the signed
verified-boot model, a loader that refuses unsigned code, is tivoization; the license is therefore
GPLv2, not v3 or AGPL. The kernel and busybox that ship beside it are also GPLv2. The `-only`
suffix keeps a future GPL revision from adding v3-style terms to the boot chain.

The copyleft leaves these licenses in place:

- Shipping bundled third-party components (Linux kernel, busybox, haproxy, nftables, e2fsprogs, …)
  in the image is mere aggregation, so they keep their own licenses.
- Apps that run on the box (separate binaries talking via the service manifest, sockets or exec)
  keep their own licenses, as userspace does on the GPLv2 kernel. Only statically linking an FB
  GPL-2.0 crate into an app's binary puts that app under GPLv2.
- Reusable library crates live in the sibling ecosystem repositories under their own permissive
  (MIT/Apache) terms. Six seed-vault crates are on crates.io:
  [dragonfruit](https://crates.io/crates/dragonfruit) (GPL-2.0-only),
  [pomelo-guard](https://crates.io/crates/pomelo-guard),
  [coconut-fs](https://crates.io/crates/coconut-fs),
  [pomegranate](https://crates.io/crates/pomegranate),
  [durian-throttle](https://crates.io/crates/durian-throttle), and
  [grape-hostkey](https://crates.io/crates/grape-hostkey).
