#!/usr/bin/env bash
#
# THE ENGINE'S OWN WITNESS CALL, MADE REACHABLE (#213).
#
# #188 patched one line inside `railgun::circuit::witness::calculate_witness`
# so a physical iOS device proves under wasmer's interpreter instead of a JIT
# it is not allowed to run (rust-lib/patch-kohaku-witness-backend.sh, which
# runs before this script and is the only thing that changes BEHAVIOUR).
#
# THAT LINE HAD NEVER EXECUTED. `mod circuit` is private at the engine crate's
# root, so no consumer can call `calculate_witness` at all: this module could
# only REPLICATE it (rust-lib/src/witness_circuit.rs -- same artifact, same
# `ark_circom::WitnessCalculator`, same backend), and a replica beside a
# patched function is not the patched function. The presence of the patch in an
# iOS image was provable with `strings`; which branch RAN was not provable at
# all, because nothing reached either.
#
# This script opens exactly the seam that fixes that, and nothing else:
#
#   pub mod logos_engine_seam {
#       pub use crate::circuit::remote_artifact_loader::RemoteArtifactLoader;
#       pub use crate::circuit::witness::calculate_witness;
#   }
#
# IT IS A RE-EXPORT OF ITEMS THAT ARE ALREADY `pub`; what it adds is a path.
# Two edits make that path exist, and they are the smallest pair that does:
#
#   src/circuit/mod.rs   mod witness;                -> pub(crate) mod witness;
#                        mod remote_artifact_loader; -> pub(crate) mod ...;
#   src/lib.rs           + pub mod logos_engine_seam { pub use ...; }
#
# `pub(crate)` and not `pub`: a private module is visible in the module that
# declares it and its DESCENDANTS, and the facade is a sibling of `circuit`
# rather than a child -- so `pub use crate::circuit::witness::calculate_witness`
# from lib.rs is `error[E0603]: module `witness` is private` without it
# (measured). Crate-visible is all the facade needs, and it leaves the engine's
# published surface to the one `pub mod` below.
#
# NOT `pub mod circuit;`, which was the smaller-looking edit: that publishes
# `TransactCircuitInputs`, whose `pub` fields are typed by the PRIVATE
# `merkle_tree` module, so it trades a two-line visibility change for a
# private-type-in-public-interface lint across a dependency nobody here owns.
#
# AND THE CALLER IS TURNED ON IN THE SAME BREATH. `proof_circuit::engine_witness`
# is compiled under this crate's `engine_seam` feature, which is NOT in
# `default` as the repo carries it -- a plain `cargo build`/`cargo test` has no
# patched vendor directory, and a crate that could only be compiled inside its
# own nix build would be a bad trade for a probe. So the same script that
# creates the seam adds the feature that uses it: they land together or not at
# all, and the desktop keeps a working `cargo test`.
#
# DELIVERY is metadata.json's `nix.rust.env.postPatch`, exactly as for #188's
# script and for the same reason -- logos-module-builder passes `nix.rust.env`
# to every leg including the mobile cross archives, and stdenv's `patchPhase`
# evals it after `cargoSetupPostUnpackHook` has exported `$cargoDepsCopy`.
#
# IT FAILS THE BUILD RATHER THAN THE DEVICE. The vendored crate, both target
# files, the two module paths it re-exports and this crate's own `default`
# feature line are each asserted, and the seam is refused if it is already
# there (a kohaku that grew one means this script is obsolete, not idempotent).
set -euo pipefail

say() { echo "patch-kohaku-engine-seam: $*"; }
die() { echo "patch-kohaku-engine-seam: ERROR: $*" >&2; exit 1; }

vendor="${cargoDepsCopy:-}"
[ -n "$vendor" ] || die "\$cargoDepsCopy is not set -- this must run in postPatch \
of a buildRustPackage whose deps are vendored (cargoSetupPostUnpackHook exports it)."
[ -d "$vendor" ] || die "\$cargoDepsCopy ($vendor) is not a directory"

shopt -s nullglob
dirs=("$vendor"/railgun-*/)
shopt -u nullglob
[ ${#dirs[@]} -eq 1 ] || die "expected exactly one vendored 'railgun-*' crate in $vendor, found ${#dirs[@]}: ${dirs[*]:-none}"
crate="${dirs[0]}"

lib="${crate}src/lib.rs"
circuit_mod="${crate}src/circuit/mod.rs"
for f in "$lib" "$circuit_mod" "${crate}src/circuit/witness.rs" \
         "${crate}src/circuit/remote_artifact_loader.rs"; do
  [ -f "$f" ] || die "$f does not exist -- kohaku moved the witness path; this script, \
rust-lib/src/proof_circuit.rs and patch-kohaku-witness-backend.sh need updating together."
done

grep -q -x -F 'mod circuit;' "$lib" || die "'mod circuit;' is not in $lib -- the engine crate's \
module layout changed; re-read it before re-anchoring (#213)."

grep -q 'logos_engine_seam' "$lib" && die "$lib already declares logos_engine_seam -- \
kohaku grew a seam of its own; use it and delete this script."

# ── the two inner modules, widened to crate-visible ───────────────────────
# Matched whole-line and EXACTLY once each, so a kohaku that has already
# widened one (or that declares it somewhere else) stops the build rather than
# leaving a half-applied seam.
for m in witness remote_artifact_loader; do
  found=$(grep -c -x -F "mod $m;" "$circuit_mod" || true)
  [ "$found" = 1 ] || die "expected exactly one 'mod $m;' in $circuit_mod, found $found"
  awk -v line="mod $m;" '
    $0 == line { print "pub(crate) " line; patched++; next }
    { print }
    END { if (patched != 1) { print "patch-kohaku-engine-seam: ERROR: widened " patched " lines, expected 1" > "/dev/stderr"; exit 1 } }
  ' "$circuit_mod" > "$circuit_mod.patched"
  mv -f "$circuit_mod.patched" "$circuit_mod"
  grep -q -x -F "pub(crate) mod $m;" "$circuit_mod" || die "post-condition failed: 'mod $m;' is not crate-visible in $circuit_mod"
done

cat >> "$lib" <<'RUST'

// ── #213: the engine's own witness call, made reachable ───────────────────
// Appended at build time by logos-evm-railgun-module
// (rust-lib/patch-kohaku-engine-seam.sh). `mod circuit` is private at this
// crate's root, so `calculate_witness` -- the function #188's sibling patch
// rewrote to choose the witness store's backend -- cannot be called by any
// consumer, and had therefore never run on a device. Both items below are
// already `pub` in their own modules; this only adds a path to them, so no
// signature changes and no private type is exposed.
#[doc(hidden)]
pub mod logos_engine_seam {
    pub use crate::circuit::remote_artifact_loader::{
        RemoteArtifactLoader, RemoteArtifactLoaderError,
    };
    pub use crate::circuit::witness::{calculate_witness, CalculateWitnessError};
}
RUST

grep -q 'pub mod logos_engine_seam' "$lib" || die "post-condition failed: the seam is not in $lib"

# ── and the caller, in this crate's own manifest ──────────────────────────
# `./` in postPatch is the crate source root (metadata.json's `codegen.rust.crate`
# is `rust-lib`, which is what the rust leg builds), so this is our Cargo.toml.
manifest="./Cargo.toml"
[ -f "$manifest" ] || die "$manifest does not exist -- postPatch did not run in the crate root"

anchor='default = ["logos_module"]'
found=$(grep -c -x -F "$anchor" "$manifest" || true)
[ "$found" = 1 ] || die "expected exactly one '$anchor' in $manifest, found $found"
awk -v anchor="$anchor" '
  $0 == anchor { print "default = [\"logos_module\", \"engine_seam\"]"; patched++; next }
  { print }
  END { if (patched != 1) { print "patch-kohaku-engine-seam: ERROR: enabled the feature on " patched " lines, expected 1" > "/dev/stderr"; exit 1 } }
' "$manifest" > "$manifest.patched"
mv -f "$manifest.patched" "$manifest"
grep -q -x -F 'default = ["logos_module", "engine_seam"]' "$manifest" || die "post-condition failed: engine_seam is not in $manifest's default features"

say "seam appended to ${crate}src/lib.rs (two modules widened to pub(crate)) and engine_seam enabled -- proof_circuit can call the engine's own calculate_witness"
