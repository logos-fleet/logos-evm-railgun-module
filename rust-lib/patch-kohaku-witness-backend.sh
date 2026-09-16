#!/usr/bin/env bash
#
# THE WITNESS BACKEND IS CHOSEN, NOT DEFAULTED (#188).
#
# Every RAILGUN proof starts with a witness, and the witness comes out of the
# circuit's `.wasm` run under `wasmer` by
# `railgun::circuit::witness::calculate_witness`, which builds its store with
#
#     let mut store = Store::default();
#
# `Store::default()` answers `BackendKind::default()`, and that answers the
# cranelift JIT for as long as ANYTHING in the graph asks wasmer for
# `sys-default` -- `ark-circom` does, cargo unions features, and no line in this
# crate's manifest can subtract it. On a physical iPad Air (4th generation) the
# JIT is `signal 9` the instant it enters emitted code: iOS denies a third-party
# app the dynamic-codesigning entitlement (measured in #188, PR #200).
#
# So the one line above is the defect, it is in a dependency, and this script is
# the smallest change that fixes it: a build-time patch of the VENDORED kohaku
# source, carried in this repo rather than in a fork of anything.
#
# WHY A `postPatch` AND NOT A FORK. The engine crate is a git dependency
# (`railgun = { git = "https://github.com/ethereum/kohaku" }`) whose
# `mod witness` and `mod remote_artifact_loader` are private and whose
# `Groth16Prover` exposes no store seam, so there is nothing to override from
# the outside. Forking kohaku (or `ark-circom`) would move one line into a repo
# that then has to be tracked; the nix build already vendors the git deps into
# `$cargoDepsCopy`, so a patch applied there reaches the SAME source cargo
# compiles, for every target, with no second repository in the picture.
#
# WHY THE cfg, and why exactly this one. #202 measured the JIT RUNNING on a
# physical Samsung SM-G990B -- `witness_engine_probe` reaches `call` under
# cranelift and answers 42 -- so Android must keep it: `wasmi` is an interpreter
# and pointing a phone that can JIT at it would be a large, unmeasured
# regression. The cfg below is character-for-character the one that gates the
# `wasmi` FEATURE in Cargo.toml (inverted): the interpreter is in the image on
# everything except Android and the iOS simulator, so asking for
# `wasmer::wasmi` anywhere else would not compile.
#
#   physical iOS  (target_os = "ios", target_abi != "sim")  -> wasmi, no JIT
#   everything else                                         -> Store::default()
#
# HOW IT IS DELIVERED. `metadata.json`'s `nix.rust.env.postPatch` names this
# script; logos-module-builder passes `nix.rust.env` to the `buildRustPackage`
# of EVERY leg -- desktop, `web`, and the mobile cross archives -- and stdenv's
# `patchPhase` evals `$postPatch` after the vendor directory has been unpacked
# and made writable (`cargoSetupPostUnpackHook` exports `$cargoDepsCopy`) and
# before `cargoSetupPostPatchHook` runs. The mobile leg reads `nix.rust.env`
# ONLY -- the flake's `rustEnv` argument does not reach it -- which is why this
# is declared in metadata.json rather than in flake.nix.
#
# A vendored git dependency's `.cargo-checksum.json` carries `"files": {}`
# (nixpkgs' `importCargoLock` writes it that way), so cargo verifies no
# per-file hash here and nothing has to be recomputed after the edit.
#
# IT FAILS THE BUILD RATHER THAN THE DEVICE. Every assumption it makes is
# asserted: the vendored crate is there, the file is there, the anchor line
# appears EXACTLY once, and the result contains the cfg. A kohaku bump that
# moves that line stops the build with a message naming this script, instead of
# quietly shipping an image that dies on a phone the way the unpatched one did.
set -euo pipefail

say() { echo "patch-kohaku-witness-backend: $*"; }
die() { echo "patch-kohaku-witness-backend: ERROR: $*" >&2; exit 1; }

vendor="${cargoDepsCopy:-}"
[ -n "$vendor" ] || die "\$cargoDepsCopy is not set -- this must run in postPatch \
of a buildRustPackage whose deps are vendored (cargoSetupPostUnpackHook exports it)."
[ -d "$vendor" ] || die "\$cargoDepsCopy ($vendor) is not a directory"

# The vendored git dep is `<name>-<version>`. Globbed rather than spelled, so a
# version bump does not need an edit here -- but matched exactly once, so a
# second copy is an error rather than a coin toss.
shopt -s nullglob
dirs=("$vendor"/railgun-*/)
shopt -u nullglob
[ ${#dirs[@]} -eq 1 ] || die "expected exactly one vendored 'railgun-*' crate in $vendor, found ${#dirs[@]}: ${dirs[*]:-none}"

target="${dirs[0]}src/circuit/witness.rs"
[ -f "$target" ] || die "$target does not exist -- kohaku moved calculate_witness; \
this script and the note in rust-lib/src/witness_engine.rs need updating together."

anchor='    let mut store = Store::default();'
found=$(grep -c -x -F "$anchor" "$target" || true)
[ "$found" = 1 ] || die "expected exactly one '$anchor' in $target, found $found. \
kohaku changed the witness backend line; re-read it before re-anchoring (#188)."

awk -v anchor="$anchor" '
  $0 == anchor {
    print "    // ── #188: the witness backend is CHOSEN here ──────────────────────"
    print "    // Patched at build time by logos-evm-railgun-module"
    print "    // (rust-lib/patch-kohaku-witness-backend.sh). `Store::default()` is"
    print "    // the cranelift JIT, and a physical iOS device kills the process the"
    print "    // instant it enters emitted code. `wasmi` is wasmer'\''s pure-Rust"
    print "    // interpreter: no emitted code, nothing for the platform to refuse."
    print "    // Android JITs fine (measured), so only iOS-the-device is diverted."
    print "    //"
    print "    // Each branch announces ITSELF, and the two texts differ on purpose:"
    print "    // the iOS one is the only string in the image that can only come from"
    print "    // the interpreter branch, so `strings <the iOS Bare framework>` proves"
    print "    // which branch was compiled in without running anything -- and on a"
    print "    // device it is the console line beside a witness, whose failure mode"
    print "    // is the process disappearing before it can report."
    print "    #[cfg(all(target_os = \"ios\", not(target_abi = \"sim\")))]"
    print "    let mut store = {"
    print "        let s = Store::new(wasmer::wasmi::Wasmi::new());"
    print "        eprintln!("
    print "            \"railgun: witness store backend = {} (#188 iOS: the interpreter, no JIT)\","
    print "            s.engine().deterministic_id()"
    print "        );"
    print "        s"
    print "    };"
    print "    #[cfg(not(all(target_os = \"ios\", not(target_abi = \"sim\"))))]"
    print "    let mut store = {"
    print "        let s = Store::default();"
    print "        eprintln!("
    print "            \"railgun: witness store backend = {} (#188: the platform default)\","
    print "            s.engine().deterministic_id()"
    print "        );"
    print "        s"
    print "    };"
    patched++
    next
  }
  { print }
  END {
    if (patched != 1) {
      print "patch-kohaku-witness-backend: ERROR: replaced " patched " lines, expected 1" > "/dev/stderr"
      exit 1
    }
  }
' "$target" > "$target.patched"

mv -f "$target.patched" "$target"

grep -q 'target_abi = "sim"' "$target" || die "post-condition failed: the cfg is not in $target"
say "patched ${dirs[0]}src/circuit/witness.rs -- physical iOS proves under wasmi, every other target under Store::default()"
