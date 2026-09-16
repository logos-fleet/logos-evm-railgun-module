//! How LONG does a witness take here?
//!
//! [`crate::witness_engine`] answered the first question — MAY the witness
//! generator run on this device — over a 41-byte wasm module, and the answer on
//! a physical iPad was no for the cranelift JIT and yes for the `wasmi`
//! interpreter (#188). That is why the engine's witness store is patched to
//! `wasmi` there (`rust-lib/patch-kohaku-witness-backend.sh`).
//!
//! IT IS NOT THE FINISH LINE. `wasmi` emits no machine code precisely because
//! it interprets, and interpreting is the slow way to run the millions of field
//! operations a RAILGUN circuit's witness takes. "It no longer crashes" with no
//! number attached changes nothing a user would notice; the number decides
//! whether a private send is a button or a background job. So this probe runs
//! the REAL circuit — the same `.wasm` the engine downloads, under the same
//! `ark_circom::WitnessCalculator` the engine drives, on every backend in the
//! image — and reports milliseconds.
//!
//! ## What it is faithful about, and what it is not
//!
//! FAITHFUL: the artifact (fetched from the engine's own artifact base, same
//! URL shape, brotli-decompressed the same way), the calculator, the store, the
//! backend, the signal set, and the device.
//!
//! NOT FAITHFUL: the input VALUES. Building a valid RAILGUN witness input needs
//! a shielded note, a merkle proof over a tree that contains it and an EdDSA
//! signature over the public hash — i.e. a funded wallet and a synced chain —
//! and every type that would build one (`circuit`, `merkle_tree`, `note`) is
//! private in the engine crate, so this module could not construct one even
//! with a chain. It feeds the right SHAPE with placeholder field elements and
//! turns circom's sanity check off ([`SANITY_CHECK`]).
//!
//! That costs the measurement nothing, and the reason is structural: a circom
//! witness calculator is straight-line code over a fixed circuit. Every signal
//! is computed for every input, the number of field operations does not depend
//! on their values, and the only thing the sanity check adds is the assertions
//! that would reject these placeholders. What it CANNOT tell you is whether a
//! proof verifies — that is `prove_transact`'s business and needs the chain.
//!
//! ## The shape is checked against the circuit, not assumed
//!
//! A circom witness calculator does not fail when you feed it too few signals:
//! the computation is triggered by the LAST input arriving, so a short input
//! set means the circuit never runs and `getWitness` answers instantly with
//! nothing in it — a fast, wrong, entirely plausible-looking measurement. So
//! every signal this probe intends to write is first put to the circuit's own
//! `getInputSignalSize`, and a mismatch is reported (and the run refused)
//! rather than timed. [`Probe::signals`] carries what each answered.
//!
//! ## Order is load-bearing, again
//!
//! The backends run in [`crate::witness_engine::PROBE_ORDER`] — the engine's
//! own (cranelift, on a platform that still has it) LAST, because a backend the
//! platform kills the process over takes every answer that would have come
//! after it. Each backend's result is also printed as it completes, so a run
//! that ends in a `SIGKILL` still leaves the earlier numbers on the console.

use std::collections::HashMap;
use std::time::Instant;

use ark_circom::{Wasm, WitnessCalculator};
use num_bigint::BigInt;
use wasmer::{Module, Value};

use crate::witness_engine::Backend;

/// Where the engine fetches its circuit artifacts
/// (`railgun::circuit::remote_artifact_loader::RemoteArtifactLoader::default`).
/// Spelled here rather than borrowed because that type is private to the engine
/// crate — if it moves, this probe measures the wrong artifact and the note in
/// `docs/specs.md` is the place that says so.
pub const ARTIFACT_BASE: &str =
    "https://github.com/Robert-MacWha/privacy-protocol-artifacts/raw/refs/heads/main/artifacts";

/// The smallest transact circuit RAILGUN ships: one note in, two out (a
/// recipient and the change) — the shape an ordinary private transfer takes,
/// and the floor for what a user would wait for.
pub const DEFAULT_CIRCUIT: &str = "01x02";

/// The UTXO merkle tree's depth (`railgun::merkle_tree::TREE_DEPTH`), which is
/// how many elements each input note's `pathElements` carries.
pub const TREE_DEPTH: usize = 16;

/// Circom's own assertions, OFF. See this module's docs: the inputs are
/// shaped-but-not-valid, and the assertions are exactly the part that would
/// reject them. The arithmetic they guard runs either way.
pub const SANITY_CHECK: bool = false;

/// A placeholder field element. Not 0: a zero input is the one value that can
/// short-circuit a multiplication chain in a way a real one would not, and it
/// is also what an unwritten signal already holds.
const FILLER: u32 = 7;

/// `NNxMM` — the transact circuit for NN nullifiers (notes spent) and MM output
/// commitments. The engine builds the same name in `Groth16Prover::prove_transact`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Shape {
    pub nullifiers: usize,
    pub commitments: usize,
}

impl Shape {
    /// Parse `"01x02"`. Returns `None` for anything else — including a POI
    /// circuit name, which has a different signal set and would be measured
    /// wrongly rather than refused.
    pub fn parse(name: &str) -> Option<Shape> {
        let (n, m) = name.split_once('x')?;
        Some(Shape {
            nullifiers: n.parse().ok().filter(|v| *v > 0)?,
            commitments: m.parse().ok().filter(|v| *v > 0)?,
        })
    }

    /// Every input signal of the transact circuit and how many field elements
    /// it takes, in the order `TransactCircuitInputs::to_circuit_signals`
    /// builds them (that function is the contract; it is private, so this is a
    /// copy checked against the circuit at run time — see the module docs).
    pub fn signals(&self) -> Vec<(&'static str, usize)> {
        vec![
            ("merkleRoot", 1),
            ("boundParamsHash", 1),
            ("nullifiers", self.nullifiers),
            ("commitmentsOut", self.commitments),
            ("token", 1),
            ("publicKey", 2),
            ("signature", 3),
            ("randomIn", self.nullifiers),
            ("valueIn", self.nullifiers),
            ("pathElements", self.nullifiers * TREE_DEPTH),
            ("leavesIndices", self.nullifiers),
            ("nullifyingKey", 1),
            ("npkOut", self.commitments),
            ("valueOut", self.commitments),
        ]
    }

    /// The signal set as the calculator takes it.
    pub fn inputs(&self) -> HashMap<String, Vec<BigInt>> {
        self.signals()
            .into_iter()
            .map(|(name, n)| (name.to_string(), vec![BigInt::from(FILLER); n]))
            .collect()
    }
}

/// FNV-1a over a signal name, split high/low — how circom addresses an input
/// signal (`getInputSignalSize` / `setInputSignal` take the two halves).
/// `ark_circom`'s own copy is `pub(crate)`.
fn fnv(name: &str) -> (u32, u32) {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in name.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    ((h >> 32) as u32, h as u32)
}

/// What one signal's declared size turned out to be.
#[derive(Debug, Clone)]
pub struct SignalCheck {
    pub name: String,
    /// What this probe intends to write.
    pub expected: usize,
    /// What the circuit says it takes. `None` when the circuit does not export
    /// `getInputSignalSize` at all (older circom), in which case nothing is
    /// checked and the probe says so rather than pretending.
    pub declared: Option<i64>,
}

impl SignalCheck {
    pub fn ok(&self) -> bool {
        match self.declared {
            Some(d) => d == self.expected as i64,
            None => true,
        }
    }
}

/// The stages, in order. `reached` is the last one that completed.
pub mod stage {
    /// The backend exists and the artifact is in memory.
    pub const ENGINE: &str = "engine";
    /// `Module::new` — the circuit's ~3 MB of wasm compiled (and, under a JIT,
    /// EMITTED and published: this is where a platform first refuses).
    pub const COMPILE: &str = "compile";
    /// The calculator's runtime is wired.
    pub const INSTANTIATE: &str = "instantiate";
    /// Every signal this probe writes matches the circuit's declared size.
    pub const SIGNALS: &str = "signals";
    /// The witness came back. THIS is the number the issue asked for.
    pub const WITNESS: &str = "witness";
}

/// One backend's run over the real circuit.
#[derive(Debug, Clone)]
pub struct Probe {
    pub requested: &'static str,
    /// wasmer's own id for the engine that was built (`cranelift`, `wasmi`…).
    pub backend: String,
    pub reached: &'static str,
    pub compile_ms: Option<u128>,
    pub instantiate_ms: Option<u128>,
    /// Wall clock for `calculate_witness` alone — no download, no compile.
    pub witness_ms: Option<u128>,
    /// How many field elements came back. A transact witness is tens of
    /// thousands of them; a handful means the circuit never ran.
    pub witness_len: Option<usize>,
    /// How many of them are non-zero. An all-zero witness is the other way a
    /// "fast" run can be an empty one.
    pub witness_nonzero: Option<usize>,
    pub signals: Vec<SignalCheck>,
    pub error: Option<String>,
}

impl Probe {
    pub fn ok(&self) -> bool {
        self.reached == stage::WITNESS && self.witness_nonzero.unwrap_or(0) > 0
    }
}

/// Everything one call measured.
#[derive(Debug, Clone)]
pub struct Run {
    pub circuit: String,
    pub artifact_url: String,
    /// Fetching and decompressing the circuit `.wasm`: once, shared by every
    /// backend, and NOT part of any `witness_ms`.
    pub download_ms: u128,
    pub wasm_bytes: usize,
    pub probes: Vec<Probe>,
    pub error: Option<String>,
}

/// Announce a stage BEFORE entering it, for the reason `witness_engine` gives
/// where it does the same: on a platform that kills the process there is no
/// reply to read, only the last line printed.
fn entering(backend: Backend, circuit: &str, what: &str) {
    eprintln!(
        "railgun_module: witness-circuit probe [{}] {circuit}: entering {what}",
        backend.requested()
    );
}

/// Fetch and decompress one circuit's `.wasm`, the way the engine's
/// `RemoteArtifactLoader::load_wasm` does (`<base>/railgun/<name>/wasm.br`,
/// brotli). Async because that is what `reqwest` is; the caller drives it on
/// the module's per-call runtime.
pub async fn fetch_wasm(circuit: &str) -> Result<(String, Vec<u8>), String> {
    let url = format!("{ARTIFACT_BASE}/railgun/{circuit}/wasm.br");
    let compressed = reqwest::Client::new()
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("fetch {url}: {e}"))?
        .error_for_status()
        .map_err(|e| format!("fetch {url}: {e}"))?
        .bytes()
        .await
        .map_err(|e| format!("read {url}: {e}"))?;
    let mut wasm = Vec::new();
    brotli::BrotliDecompress(&mut &compressed[..], &mut wasm)
        .map_err(|e| format!("decompress {url}: {e}"))?;
    Ok((url, wasm))
}

/// Measure `backends` over `circuit`, downloading the artifact once.
///
/// The download is deliberately outside the per-backend timing: it is the
/// network's number, not the witness generator's, and it is the same artifact
/// every backend then runs.
pub fn run(circuit: &str, backends: &[Backend], wasm: &[u8], url: String, download_ms: u128) -> Run {
    let mut out = Run {
        circuit: circuit.to_string(),
        artifact_url: url,
        download_ms,
        wasm_bytes: wasm.len(),
        probes: Vec::new(),
        error: None,
    };
    let Some(shape) = Shape::parse(circuit) else {
        out.error = Some(format!(
            "'{circuit}' is not a transact circuit name (expected NNxMM, e.g. {DEFAULT_CIRCUIT})"
        ));
        return out;
    };
    out.probes = backends
        .iter()
        .map(|b| probe_backend(*b, circuit, shape, wasm))
        .collect();
    out
}

/// One backend, announced and reported as it happens — an earlier backend's
/// number survives a later one's death.
pub fn probe_backend(which: Backend, circuit: &str, shape: Shape, wasm: &[u8]) -> Probe {
    let p = one(which, circuit, shape, wasm);
    eprintln!(
        "railgun_module: witness-circuit probe [{}] {circuit}: {} (backend={} reached={} \
         compile={:?}ms instantiate={:?}ms witness={:?}ms len={:?} nonzero={:?} error={:?})",
        p.requested,
        if p.ok() { "GENERATED A WITNESS" } else { "DID NOT" },
        p.backend,
        p.reached,
        p.compile_ms,
        p.instantiate_ms,
        p.witness_ms,
        p.witness_len,
        p.witness_nonzero,
        p.error
    );
    p
}

fn one(which: Backend, circuit: &str, shape: Shape, wasm: &[u8]) -> Probe {
    entering(which, circuit, stage::ENGINE);
    let mut store = which.store();
    let mut out = Probe {
        requested: which.requested(),
        backend: store.engine().deterministic_id(),
        reached: stage::ENGINE,
        compile_ms: None,
        instantiate_ms: None,
        witness_ms: None,
        witness_len: None,
        witness_nonzero: None,
        signals: Vec::new(),
        error: None,
    };

    entering(which, circuit, stage::COMPILE);
    let t = Instant::now();
    let module = match Module::new(&store, wasm) {
        Ok(m) => m,
        Err(e) => {
            out.error = Some(format!("compile: {e}"));
            return out;
        }
    };
    out.compile_ms = Some(t.elapsed().as_millis());
    out.reached = stage::COMPILE;

    entering(which, circuit, stage::INSTANTIATE);
    let t = Instant::now();
    let runtime = match WitnessCalculator::make_wasm_runtime(&mut store, module) {
        Ok(w) => w,
        Err(e) => {
            out.error = Some(format!("instantiate: {e}"));
            return out;
        }
    };

    // THE SHAPE CHECK, before the calculator takes the runtime: this is the
    // one moment the circuit itself can be asked what it expects.
    entering(which, circuit, stage::SIGNALS);
    out.signals = check_signals(&runtime, &mut store, shape);
    if let Some(bad) = out.signals.iter().find(|s| !s.ok()) {
        out.error = Some(format!(
            "signal '{}': this probe writes {} element(s), the circuit declares {:?} -- \
             refusing to time a run the circuit would not complete",
            bad.name, bad.expected, bad.declared
        ));
        return out;
    }

    let mut calculator = match WitnessCalculator::new_from_wasm(&mut store, runtime) {
        Ok(c) => c,
        Err(e) => {
            out.error = Some(format!("instantiate: {e}"));
            return out;
        }
    };
    out.instantiate_ms = Some(t.elapsed().as_millis());
    out.reached = stage::INSTANTIATE;
    if out.signals.iter().all(|s| s.declared.is_some()) {
        out.reached = stage::SIGNALS;
    }

    entering(which, circuit, stage::WITNESS);
    let t = Instant::now();
    match calculator.calculate_witness(&mut store, shape.inputs(), SANITY_CHECK) {
        Ok(w) => {
            out.witness_ms = Some(t.elapsed().as_millis());
            let zero = BigInt::from(0u32);
            out.witness_nonzero = Some(w.iter().filter(|v| **v != zero).count());
            out.witness_len = Some(w.len());
            out.reached = stage::WITNESS;
        }
        Err(e) => out.error = Some(format!("witness: {e}")),
    }
    out
}

/// Ask the circuit how big each signal it is about to be fed really is.
/// `getInputSignalSize` is a circom 2 export; a circuit without it yields
/// `declared: None` everywhere, which [`SignalCheck::ok`] treats as unchecked
/// rather than as agreement.
fn check_signals(runtime: &Wasm, store: &mut wasmer::Store, shape: Shape) -> Vec<SignalCheck> {
    let f = runtime.instance.exports.get_function("getInputSignalSize").ok();
    shape
        .signals()
        .into_iter()
        .map(|(name, expected)| {
            let (msb, lsb) = fnv(name);
            let declared = f.and_then(|f| {
                f.call(store, &[Value::I32(msb as i32), Value::I32(lsb as i32)])
                    .ok()
                    .and_then(|r| r.first().and_then(|v| v.i32()).map(|v| v as i64))
            });
            SignalCheck {
                name: name.to_string(),
                expected,
                declared,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_transact_circuit_name_gives_the_signal_set() {
        let s = Shape::parse("01x02").expect("01x02 parses");
        assert_eq!(s.nullifiers, 1);
        assert_eq!(s.commitments, 2);
        let sigs: HashMap<_, _> = s.signals().into_iter().collect();
        // The four that vary with the shape, and the one that scales with the
        // tree — the rest are fixed-width and checked against the circuit at
        // run time.
        assert_eq!(sigs["nullifiers"], 1);
        assert_eq!(sigs["commitmentsOut"], 2);
        assert_eq!(sigs["pathElements"], TREE_DEPTH);
        assert_eq!(sigs["valueOut"], 2);
        assert_eq!(s.inputs().len(), 14);
    }

    #[test]
    fn a_name_that_is_not_a_transact_circuit_is_refused() {
        assert_eq!(Shape::parse("poi/01x02"), None);
        assert_eq!(Shape::parse("00x02"), None);
        assert_eq!(Shape::parse(""), None);
    }

    // The addressing circom uses for a signal name. Pinned against a value
    // computed independently (FNV-1a 64 of "merkleRoot"), because a wrong hash
    // does not fail loudly — it addresses a signal that does not exist and the
    // circuit simply never runs.
    #[test]
    fn signal_names_hash_the_way_circom_addresses_them() {
        let (msb, lsb) = fnv("merkleRoot");
        let h = ((msb as u64) << 32) | lsb as u64;
        let mut expect: u64 = 0xcbf2_9ce4_8422_2325;
        for b in b"merkleRoot" {
            expect ^= *b as u64;
            expect = expect.wrapping_mul(0x100_0000_01b3);
        }
        assert_eq!(h, expect);
        assert_ne!(fnv("merkleRoot"), fnv("boundParamsHash"));
    }

    // THE WHOLE THING, over the real artifact. `#[ignore]` because it needs
    // the network and ~900 KB of download, not because it is optional: it is
    // the only test that proves the signal SHAPES above match the circuit the
    // engine proves with, and a wrong shape is the failure that reads as a
    // wonderfully fast measurement. Run it before trusting a device number:
    //
    //   cargo test --no-default-features -- --ignored --nocapture
    //
    // On a desktop every backend in the image runs, so it is also the
    // calibration a handset's number is read against.
    #[test]
    #[ignore = "needs the network (~900 KB artifact); run with --ignored"]
    fn the_real_circuit_generates_a_witness_on_every_backend() {
        let circuit = DEFAULT_CIRCUIT;
        let started = Instant::now();
        let (url, wasm) = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(fetch_wasm(circuit))
            .expect("the circuit artifact downloads");
        let download_ms = started.elapsed().as_millis();
        let out = run(
            circuit,
            crate::witness_engine::PROBE_ORDER,
            &wasm,
            url,
            download_ms,
        );
        assert!(out.error.is_none(), "{:?}", out.error);
        assert!(out.wasm_bytes > 1_000_000, "a RAILGUN circuit is megabytes, got {}", out.wasm_bytes);
        for p in &out.probes {
            assert!(
                p.signals.iter().all(|s| s.ok()),
                "[{}] the circuit sizes a signal differently: {:?}",
                p.requested,
                p.signals.iter().filter(|s| !s.ok()).collect::<Vec<_>>()
            );
            assert!(p.ok(), "[{}] no witness: {:?}", p.requested, p);
            // A transact witness is tens of thousands of field elements. A
            // handful would mean the circuit never ran -- the exact failure
            // the signal check exists to catch, asserted again on the result.
            assert!(
                p.witness_len.unwrap_or(0) > 1000,
                "[{}] witness is {:?} elements -- the circuit did not run",
                p.requested,
                p.witness_len
            );
        }
        // Every backend must agree on the witness LENGTH: they ran the same
        // circuit, so a different length means one of them ran something else.
        let lens: Vec<_> = out.probes.iter().map(|p| p.witness_len).collect();
        assert!(lens.windows(2).all(|w| w[0] == w[1]), "backends disagree: {lens:?}");
    }

    // A short input set is the failure this probe exists to not have: the
    // circuit would never run and the run would look FAST.
    #[test]
    fn a_signal_the_circuit_sizes_differently_is_not_ok() {
        assert!(
            !SignalCheck {
                name: "pathElements".into(),
                expected: 16,
                declared: Some(32),
            }
            .ok()
        );
        assert!(
            SignalCheck {
                name: "pathElements".into(),
                expected: 16,
                declared: Some(16),
            }
            .ok()
        );
        // Unchecked is not disagreement.
        assert!(
            SignalCheck {
                name: "pathElements".into(),
                expected: 16,
                declared: None,
            }
            .ok()
        );
    }
}
