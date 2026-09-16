//! A witness is not a proof. What does the PROOF cost here?
//!
//! [`crate::witness_engine`] asked whether a wasm backend may run on this
//! device at all, and [`crate::witness_circuit`] timed the witness the real
//! circuit produces — **817 ms** for `railgun/01x02` on the venue's physical
//! iPad Air (4th generation), under `wasmi` (#188). Neither is the number a
//! user waits for. `Groth16Prover::prove_transact` downloads a ~3 MB proving
//! key and ~140 KB of constraint matrices, generates the witness, runs
//! arkworks Groth16 over it and verifies the result; RAILGUN quotes "1-2
//! minutes on mobile" for that, and nobody has measured it on a handset.
//!
//! This module measures it, stage by stage, over the SAME artifacts the engine
//! downloads and through the SAME arkworks calls `Groth16Prover::prove` makes
//! (#213).
//!
//! THE ANSWER, on the venue's physical iPad Air (4th generation), iOS 26.5.2,
//! the shipped release build, for `railgun/01x02`:
//!
//! ```text
//! railgun: witness store backend = wasmi (#188 iOS: the interpreter, no JIT)
//! proving-key 1509ms/3341841B  matrices 744ms/141046B  engine-wasm 975ms
//! engine-witness 892ms  prove 383ms  verify 2ms  verified=false  total 4509ms
//! ```
//!
//! **The proof is 383 ms** — not the minute RAILGUN's published figure would
//! lead you to budget for, and not the dominant cost either. The whole compute
//! half (witness + proof + verify) is about 1.3 s on an A14; what a FIRST
//! private send waits for is 3.5 MB of artifact (≈3.2 s cold, ≈1.6 s warm),
//! which is cacheable and is the network's number. A private send on iOS needs
//! neither a background job nor a cancel path.
//!
//! And the line above it is the one this module was written for: it is printed
//! from inside the ENGINE's own `calculate_witness`, by the branch #188's patch
//! compiled in for physical iOS, and before #213 nothing had ever reached it.
//!
//! ## The three things it is faithful about
//!
//! ARTIFACTS. `proving_key.bin.br` and `matrices.bin.br` come from the engine's
//! own artifact base under the engine's own names, are brotli-decompressed the
//! same way and are deserialized by the same two calls — `ProvingKey::<Bn254>`
//! uncompressed-unchecked, and the engine's own public
//! [`SerializableNpIndex`](railgun::crypto::serializable_np_index::SerializableNpIndex),
//! which is the type `load_matrices` answers with. `RemoteArtifactLoader`
//! itself is private to the engine crate, so the fetch is spelled here; the
//! type it produces is not.
//!
//! PROVING. [`prove`] is `Groth16Prover::prove`'s tail, copied statement for
//! statement: `create_proof_with_reduction_and_matrices` over `[a, b]` with the
//! matrices' own `num_instance_variables` / `num_constraints`, then
//! `prepare_verifying_key` + `verify_proof` over `witness[1..num_instance]`.
//!
//! THE WITNESS ITSELF is [`crate::witness_circuit`]'s, generated on the backend
//! the engine proves with on this platform ([`ENGINE_BACKEND`]) — and, where
//! the build carries the seam below, the ENGINE'S OWN `calculate_witness`.
//!
//! ## And the one thing it is not
//!
//! THE VALUES. Building a valid RAILGUN witness input needs a shielded note, a
//! merkle proof over a tree that contains it and an EdDSA signature over the
//! public hash — a funded wallet and a synced chain. So the inputs are the
//! circuit's real shape filled with placeholders, exactly as
//! [`crate::witness_circuit`] describes, and **the proof does not verify**:
//! `verified: false` is the expected answer here and is reported rather than
//! hidden. What that costs the measurement is nothing, and the reason is the
//! same one that holds for the witness: Groth16 proving is a fixed number of
//! multi-scalar multiplications and FFTs over the circuit's matrices. The
//! number of group operations is a property of the CIRCUIT, not of the values,
//! so the milliseconds are the milliseconds a real send pays. What it cannot
//! tell you is whether a proof would be ACCEPTED, which is the chain's business.
//!
//! ## The engine's own witness call, where the seam is in the build
//!
//! `railgun::circuit::witness::calculate_witness` is the function #188's
//! build-time patch rewrote, and until now nothing had ever called it on a
//! device: `mod circuit` is private at the engine crate's root, so this module
//! could only REPLICATE it. `rust-lib/patch-kohaku-engine-seam.sh` adds a
//! `pub use` facade to the vendored engine source and turns on the
//! `engine_seam` feature that this module's [`engine_witness`] is compiled
//! under, so every image the nix build produces can call the real thing.
//!
//! It is called with the same placeholder inputs, and `calculate_witness`
//! hard-codes circom's sanity check ON — so it may well fail at an assertion
//! those placeholders do not satisfy. THAT IS STILL THE ANSWER THE ISSUE
//! ASKED FOR: reaching the call means the patched line ran, and the patched
//! line announces which backend it chose:
//!
//! ```text
//! railgun: witness store backend = wasmi (#188 iOS: the interpreter, no JIT)
//! ```
//!
//! So the leg reports what it reached either way, and the proof is run over
//! whichever witness came back — the engine's if it produced one, the
//! replica's otherwise, named in [`Run::witness_source`].

use std::collections::HashMap;
use std::io::Cursor;
use std::time::Instant;

use ark_bn254::{Bn254, Fr};
use ark_circom::index::NPIndex;
use ark_circom::CircomReduction;
use ark_groth16::{prepare_verifying_key, Groth16, ProvingKey};
use ark_serialize::CanonicalDeserialize;
use railgun::crypto::serializable_np_index::SerializableNpIndex;
use ruint::aliases::U256;

use crate::witness_circuit::{self, Shape, ARTIFACT_BASE, DEFAULT_CIRCUIT};
use crate::witness_engine::Backend;

/// The backend the ENGINE proves with on this platform.
///
/// Character for character the cfg `rust-lib/patch-kohaku-witness-backend.sh`
/// writes into the vendored `calculate_witness`, and for the same reason: a
/// proof's cost on a device is the cost on the backend that device actually
/// uses, and on a physical iOS device that is the interpreter because the JIT
/// is refused there (#188).
#[cfg(all(target_os = "ios", not(target_abi = "sim")))]
pub const ENGINE_BACKEND: Backend = Backend::Wasmi;
/// See the physical-iOS arm above: everywhere else the engine builds its store
/// with `Store::default()`, which is the JIT.
#[cfg(not(all(target_os = "ios", not(target_abi = "sim"))))]
pub const ENGINE_BACKEND: Backend = Backend::EngineDefault;

/// The engine's circuit NAME, as `Groth16Prover::prove_transact` builds it from
/// the input shape: `railgun/01x02`. [`crate::witness_circuit`] takes the bare
/// `01x02` because that is what a caller names; the artifact path needs both.
pub fn engine_circuit_name(circuit: &str) -> String {
    format!("railgun/{circuit}")
}

/// `<base>/railgun/<circuit>/<file>` — the URL shape
/// `RemoteArtifactLoader::load_*` builds. That type is private to the engine
/// crate (`mod remote_artifact_loader`), so the three names are spelled here;
/// if they move, this probe measures the wrong artifact and the note in
/// `docs/specs.md` is the place that says so.
pub fn artifact_url(circuit: &str, file: &str) -> String {
    format!("{ARTIFACT_BASE}/{}/{file}", engine_circuit_name(circuit))
}

/// The proving key: ~3.3 MB brotli, and the single biggest thing a first
/// private send downloads.
pub const PROVING_KEY_FILE: &str = "proving_key.bin.br";
/// The constraint matrices: ~140 KB brotli.
pub const MATRICES_FILE: &str = "matrices.bin.br";

/// One measured step. `bytes` is the compressed size where the step was a
/// download, so the network figure and the size it moved are one row.
#[derive(Debug, Clone)]
pub struct Leg {
    pub name: &'static str,
    pub ms: Option<u128>,
    pub bytes: Option<usize>,
    pub error: Option<String>,
}

impl Leg {
    pub fn ok(&self) -> bool {
        self.error.is_none()
    }
}

/// Everything one [`run`] measured.
#[derive(Debug, Clone)]
pub struct Run {
    pub circuit: String,
    /// Which backend generated the witness — the engine's own choice on this
    /// platform, see [`ENGINE_BACKEND`].
    pub backend: &'static str,
    /// Whether this image carries the engine seam (see the module docs), i.e.
    /// whether [`engine_witness`] could be called at all.
    pub engine_seam: bool,
    pub legs: Vec<Leg>,
    /// `"engine"` when the ENGINE's own `calculate_witness` produced the
    /// witness that was proven over, `"probe"` when the replica's did.
    pub witness_source: Option<&'static str>,
    pub witness_len: Option<usize>,
    /// The matrices' own account of the circuit, and the shape a witness has
    /// to match before a proof over it means anything.
    pub num_instance_variables: Option<usize>,
    pub num_witness_variables: Option<usize>,
    pub num_constraints: Option<usize>,
    /// Whether the proof verified. `Some(false)` is the EXPECTED answer over
    /// placeholder inputs — see the module docs.
    pub verified: Option<bool>,
    pub total_ms: u128,
    pub error: Option<String>,
}

impl Run {
    /// A run is `ok` when every leg it ran completed. NOT when the proof
    /// verified: over placeholder inputs it cannot, and making that the
    /// success condition would turn the one honest result into a red one.
    pub fn ok(&self) -> bool {
        self.error.is_none() && !self.legs.is_empty() && self.legs.iter().all(Leg::ok)
    }

    pub fn leg(&self, name: &str) -> Option<&Leg> {
        self.legs.iter().find(|l| l.name == name)
    }
}

/// Announce a stage BEFORE entering it, for the reason
/// [`crate::witness_engine`] gives where it does the same: on a platform that
/// kills the process there is no reply to read, only the last line printed.
fn entering(circuit: &str, what: &str) {
    eprintln!("railgun_module: proof-circuit probe {circuit}: entering {what}");
}

/// Fetch one artifact, brotli-decompressed, reporting the COMPRESSED size —
/// which is what the device's network moved.
async fn fetch(url: &str) -> Result<(Vec<u8>, usize), String> {
    let compressed = reqwest::Client::new()
        .get(url)
        .send()
        .await
        .map_err(|e| format!("fetch {url}: {e}"))?
        .error_for_status()
        .map_err(|e| format!("fetch {url}: {e}"))?
        .bytes()
        .await
        .map_err(|e| format!("read {url}: {e}"))?;
    let mut out = Vec::new();
    brotli::BrotliDecompress(&mut &compressed[..], &mut out)
        .map_err(|e| format!("decompress {url}: {e}"))?;
    Ok((out, compressed.len()))
}

/// `RemoteArtifactLoader::load_proving_key`, spelled here: fetch, brotli,
/// `ProvingKey::<Bn254>::deserialize_uncompressed_unchecked`.
pub async fn load_proving_key(circuit: &str) -> Result<(ProvingKey<Bn254>, usize), String> {
    let url = artifact_url(circuit, PROVING_KEY_FILE);
    let (bytes, compressed) = fetch(&url).await?;
    let pk = ProvingKey::<Bn254>::deserialize_uncompressed_unchecked(Cursor::new(bytes))
        .map_err(|e| format!("deserialize {url}: {e}"))?;
    Ok((pk, compressed))
}

/// `RemoteArtifactLoader::load_matrices`, spelled here — through the engine's
/// OWN `SerializableNpIndex`, which is public, so the wire format is the
/// engine's rather than a second reading of it.
pub async fn load_matrices(circuit: &str) -> Result<(NPIndex<Fr>, usize), String> {
    let url = artifact_url(circuit, MATRICES_FILE);
    let (bytes, compressed) = fetch(&url).await?;
    let m = SerializableNpIndex::<Fr>::deserialize_uncompressed_unchecked(Cursor::new(bytes))
        .map_err(|e| format!("deserialize {url}: {e}"))?;
    Ok((m.into(), compressed))
}

/// The placeholder signal set in the type the ENGINE's `calculate_witness`
/// takes (`ruint` `U256`; [`Shape::inputs`] is the `num_bigint` one the
/// calculator takes directly).
pub fn engine_inputs(shape: Shape) -> HashMap<String, Vec<U256>> {
    shape
        .signals()
        .into_iter()
        .map(|(name, n)| (name.to_string(), vec![U256::from(witness_circuit::FILLER); n]))
        .collect()
}

/// A witness as the engine hands it on: `ruint` `U256` → `Fr`, exactly the
/// conversion `Groth16Prover::prove` makes.
fn to_field(witness: &[U256]) -> Vec<Fr> {
    witness
        .iter()
        .map(|x| Fr::from(ark_ff::BigInt::from(*x)))
        .collect()
}

/// What the engine's own witness path cost, split at the download boundary.
#[derive(Debug)]
pub struct EngineWitness {
    /// `RemoteArtifactLoader::load_wasm` — the circuit `.wasm` fetched and
    /// brotli-decompressed by the ENGINE's own loader. Timed separately (and
    /// first) because it also warms that loader's cache, so [`Self::witness_ms`]
    /// below is compute and not network.
    pub load_wasm_ms: Option<u128>,
    /// `calculate_witness` itself: the store (the patched line), the compile,
    /// the instantiate and the circuit.
    pub witness_ms: Option<u128>,
    pub witness: Result<Vec<U256>, String>,
}

/// THE ENGINE'S OWN `calculate_witness`, where the build carries the seam.
///
/// Returns the witness it produced, or the error it failed with — and either
/// way the call happened, which is what puts the patched store-selection line
/// (and therefore the backend it chose) on the console. See the module docs.
///
/// `calculate_witness` hard-codes circom's sanity check ON, so unlike
/// [`crate::witness_circuit`] this runs the circuit's own assertions over the
/// placeholders too.
#[cfg(feature = "engine_seam")]
pub async fn engine_witness(circuit: &str, shape: Shape) -> EngineWitness {
    let name = engine_circuit_name(circuit);
    let loader = railgun::logos_engine_seam::RemoteArtifactLoader::default();

    let t = Instant::now();
    if let Err(e) = loader.load_wasm(&name).await {
        return EngineWitness {
            load_wasm_ms: None,
            witness_ms: None,
            witness: Err(format!("engine load_wasm: {e}")),
        };
    }
    let load_wasm_ms = Some(t.elapsed().as_millis());

    let t = Instant::now();
    let witness =
        railgun::logos_engine_seam::calculate_witness(&loader, &name, engine_inputs(shape))
            .await
            .map_err(|e| e.to_string());
    EngineWitness {
        load_wasm_ms,
        witness_ms: Some(t.elapsed().as_millis()),
        witness,
    }
}

/// Without the seam there is no engine call to make — `mod circuit` is private
/// at the engine crate's root. A plain `cargo` build is this arm; every image
/// the nix build produces is the one above.
#[cfg(not(feature = "engine_seam"))]
pub async fn engine_witness(_circuit: &str, _shape: Shape) -> EngineWitness {
    EngineWitness {
        load_wasm_ms: None,
        witness_ms: None,
        witness: Err("this build carries no engine seam \
                      (rust-lib/patch-kohaku-engine-seam.sh is applied by the nix build's \
                      postPatch, not by cargo)"
            .to_string()),
    }
}

/// Whether [`engine_witness`] can do anything but refuse.
pub const ENGINE_SEAM: bool = cfg!(feature = "engine_seam");

/// How long a witness for these matrices is: the zkey's `n_vars`.
///
/// NOT `num_instance_variables + num_witness_variables`, which is one MORE —
/// and the off-by-one is ark-circom's, not a mistake to correct here. Its zkey
/// reader (`ZkeyHeaderReader::matrices`) sets
///
/// ```text
/// num_instance_variables = n_public + 1     // the public signals, plus the constant wire
/// num_witness_variables  = n_vars - n_public // which counts that same wire again
/// ```
///
/// while the proving key's `l_query` — the bases the prover's auxiliary MSM
/// runs against — is read at `n_vars - n_public - 1`. So `n_vars` is the
/// length that makes the prover's slices line up, and it is exactly what the
/// circuit's `.wasm` produces (measured: 10 190 for `railgun/01x02`, against
/// 6 + 10 185 declared).
pub fn expected_witness_len(matrices: &NPIndex<Fr>) -> usize {
    matrices.num_instance_variables + matrices.num_witness_variables - 1
}

/// A SHORT WITNESS IS THE FAILURE THAT READS AS A FAST PROOF — the same one
/// [`crate::witness_circuit`] checks every signal size against the circuit
/// for, asserted once more on the other side. And it does not fail loudly on
/// its own: `create_proof_with_reduction_and_matrices` zips the assignment
/// against the proving key's bases, so a short witness silently proves over
/// fewer of them. So [`prove`] checks the length rather than trusting it, and
/// before it touches the proving key.
pub fn witness_len_check(matrices: &NPIndex<Fr>, len: usize) -> Result<(), String> {
    let expected = expected_witness_len(matrices);
    if len == expected {
        return Ok(());
    }
    Err(format!(
        "witness is {len} field elements, the matrices declare {expected} ({} instance + {} \
         witness - 1) -- refusing to time a proof over a witness the circuit did not produce",
        matrices.num_instance_variables, matrices.num_witness_variables
    ))
}

/// `Groth16Prover::prove`'s tail: create the proof over `[a, b]`, then verify
/// it. Returns the two timings and the verdict.
pub fn prove(
    pk: &ProvingKey<Bn254>,
    matrices: NPIndex<Fr>,
    witness: &[Fr],
) -> Result<(u128, u128, bool), String> {
    witness_len_check(&matrices, witness.len())?;
    let num_instance = matrices.num_instance_variables;
    let num_constraints = matrices.num_constraints;

    let t = Instant::now();
    let proof = Groth16::<Bn254, CircomReduction>::create_proof_with_reduction_and_matrices(
        pk,
        ark_std::rand::random(),
        ark_std::rand::random(),
        &[matrices.a, matrices.b],
        num_instance,
        num_constraints,
        witness,
    )
    .map_err(|e| format!("prove: {e}"))?;
    let prove_ms = t.elapsed().as_millis();

    let t = Instant::now();
    let pvk = prepare_verifying_key(&pk.vk);
    let verified = Groth16::<Bn254, CircomReduction>::verify_proof(&pvk, &proof, &witness[1..num_instance])
        .map_err(|e| format!("verify: {e}"))?;
    Ok((prove_ms, t.elapsed().as_millis(), verified))
}

/// The whole measurement, in the order a private send pays for it.
pub async fn run(circuit: &str) -> Run {
    let started = Instant::now();
    let mut out = Run {
        circuit: circuit.to_string(),
        backend: ENGINE_BACKEND.requested(),
        engine_seam: ENGINE_SEAM,
        legs: Vec::new(),
        witness_source: None,
        witness_len: None,
        num_instance_variables: None,
        num_witness_variables: None,
        num_constraints: None,
        verified: None,
        total_ms: 0,
        error: None,
    };
    let Some(shape) = Shape::parse(circuit) else {
        out.error = Some(format!(
            "'{circuit}' is not a transact circuit name (expected NNxMM, e.g. {DEFAULT_CIRCUIT})"
        ));
        out.total_ms = started.elapsed().as_millis();
        return out;
    };

    // ── the artifacts, which is where the user's wait starts ──────────────
    entering(circuit, "proving-key");
    let t = Instant::now();
    let pk = match load_proving_key(circuit).await {
        Ok((pk, bytes)) => {
            out.legs.push(Leg {
                name: "proving-key",
                ms: Some(t.elapsed().as_millis()),
                bytes: Some(bytes),
                error: None,
            });
            pk
        }
        Err(e) => {
            out.legs.push(Leg { name: "proving-key", ms: None, bytes: None, error: Some(e) });
            out.total_ms = started.elapsed().as_millis();
            return out;
        }
    };

    entering(circuit, "matrices");
    let t = Instant::now();
    let matrices = match load_matrices(circuit).await {
        Ok((m, bytes)) => {
            out.legs.push(Leg {
                name: "matrices",
                ms: Some(t.elapsed().as_millis()),
                bytes: Some(bytes),
                error: None,
            });
            m
        }
        Err(e) => {
            out.legs.push(Leg { name: "matrices", ms: None, bytes: None, error: Some(e) });
            out.total_ms = started.elapsed().as_millis();
            return out;
        }
    };
    out.num_instance_variables = Some(matrices.num_instance_variables);
    out.num_witness_variables = Some(matrices.num_witness_variables);
    out.num_constraints = Some(matrices.num_constraints);

    // ── the ENGINE'S OWN witness call, which is what #213 asked for ───────
    entering(circuit, "engine-witness");
    let engine = engine_witness(circuit, shape).await;
    if let Some(ms) = engine.load_wasm_ms {
        out.legs.push(Leg { name: "engine-wasm", ms: Some(ms), bytes: None, error: None });
    }
    let witness: Option<Vec<Fr>> = match &engine.witness {
        Ok(w) => {
            out.legs.push(Leg {
                name: "engine-witness",
                ms: engine.witness_ms,
                bytes: None,
                error: None,
            });
            out.witness_source = Some("engine");
            out.witness_len = Some(w.len());
            Some(to_field(w))
        }
        Err(e) => {
            // NOT fatal, and not silent. `calculate_witness` runs circom's
            // sanity check, which the placeholder inputs may not satisfy — and
            // a build with no seam refuses here by construction. Either way
            // the leg records what happened and the replica takes over, so the
            // proof is still measured.
            out.legs.push(Leg {
                name: "engine-witness",
                ms: engine.witness_ms,
                bytes: None,
                error: Some(e.clone()),
            });
            None
        }
    };

    // ── the replica, when the engine's own call did not produce one ───────
    let witness = match witness {
        Some(w) => w,
        None => {
            entering(circuit, "probe-witness");
            let wasm = match witness_circuit::fetch_wasm(circuit).await {
                Ok((_, wasm)) => wasm,
                Err(e) => {
                    out.legs.push(Leg { name: "probe-witness", ms: None, bytes: None, error: Some(e) });
                    out.total_ms = started.elapsed().as_millis();
                    return out;
                }
            };
            let (probe, values) = witness_circuit::measure_witness(ENGINE_BACKEND, circuit, shape, &wasm);
            match values {
                Some(values) => {
                    out.legs.push(Leg {
                        name: "probe-witness",
                        ms: probe.witness_ms,
                        bytes: None,
                        error: None,
                    });
                    out.witness_source = Some("probe");
                    out.witness_len = Some(values.len());
                    to_field(&values.iter().map(|v| U256::from(v.clone())).collect::<Vec<_>>())
                }
                None => {
                    out.legs.push(Leg {
                        name: "probe-witness",
                        ms: None,
                        bytes: None,
                        error: probe.error.clone().or(Some(format!("reached {}", probe.reached))),
                    });
                    out.total_ms = started.elapsed().as_millis();
                    return out;
                }
            }
        }
    };

    // ── the proof, which is the number this module exists for ─────────────
    entering(circuit, "prove");
    match prove(&pk, matrices, &witness) {
        Ok((prove_ms, verify_ms, verified)) => {
            out.legs.push(Leg { name: "prove", ms: Some(prove_ms), bytes: None, error: None });
            out.legs.push(Leg { name: "verify", ms: Some(verify_ms), bytes: None, error: None });
            out.verified = Some(verified);
        }
        Err(e) => out.legs.push(Leg { name: "prove", ms: None, bytes: None, error: Some(e) }),
    }

    out.total_ms = started.elapsed().as_millis();
    report(&out);
    out
}

/// Print the result as it completes, for the reason
/// [`crate::witness_circuit::probe_backend`] does the same: on a platform that
/// kills the process the console line is the only thing that survives.
pub fn report(r: &Run) {
    let leg = |n: &str| r.leg(n).and_then(|l| l.ms);
    eprintln!(
        "railgun_module: proof-circuit probe {} [{}]: {} (seam={} witness={:?}/{:?} \
         provingKey={:?}ms matrices={:?}ms engineWasm={:?}ms engineWitness={:?}ms \
         probeWitness={:?}ms prove={:?}ms verify={:?}ms verified={:?} total={}ms)",
        r.circuit,
        r.backend,
        if r.ok() { "PROVED" } else { "DID NOT" },
        r.engine_seam,
        r.witness_source,
        r.witness_len,
        leg("proving-key"),
        leg("matrices"),
        leg("engine-wasm"),
        leg("engine-witness"),
        leg("probe-witness"),
        leg("prove"),
        leg("verify"),
        r.verified,
        r.total_ms,
    );
    for l in r.legs.iter().filter(|l| !l.ok()) {
        eprintln!("railgun_module: proof-circuit probe {}: {} -> {:?}", r.circuit, l.name, l.error);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The three artifact names and the directory they hang off, pinned
    // against literals. They are a COPY of a private type's behaviour
    // (`RemoteArtifactLoader`), so nothing but a literal can catch a drift.
    #[test]
    fn the_artifact_urls_are_the_ones_the_engine_builds() {
        assert_eq!(engine_circuit_name("01x02"), "railgun/01x02");
        assert_eq!(
            artifact_url("01x02", PROVING_KEY_FILE),
            "https://github.com/Robert-MacWha/privacy-protocol-artifacts/raw/refs/heads/main/\
             artifacts/railgun/01x02/proving_key.bin.br"
        );
        assert_eq!(
            artifact_url("01x02", MATRICES_FILE),
            "https://github.com/Robert-MacWha/privacy-protocol-artifacts/raw/refs/heads/main/\
             artifacts/railgun/01x02/matrices.bin.br"
        );
    }

    #[test]
    fn the_engine_takes_the_same_fourteen_signals_the_calculator_does() {
        let shape = Shape::parse(DEFAULT_CIRCUIT).expect("01x02 parses");
        let engine = engine_inputs(shape);
        let calculator = shape.inputs();
        assert_eq!(engine.len(), 14);
        assert_eq!(engine.len(), calculator.len());
        for (name, values) in &calculator {
            assert_eq!(
                engine.get(name).map(Vec::len),
                Some(values.len()),
                "signal '{name}' differs between the engine's input map and the calculator's"
            );
        }
    }

    // A name that is not a transact circuit must be refused BEFORE anything is
    // downloaded -- a POI circuit has a different signal set and would be
    // measured wrongly rather than refused.
    #[test]
    fn a_name_that_is_not_a_transact_circuit_never_reaches_the_network() {
        let out = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(run("poi/01x02"));
        assert!(out.legs.is_empty(), "it downloaded something: {:?}", out.legs);
        assert!(out.error.unwrap_or_default().contains("not a transact circuit"));
    }

    // THE SHAPE GUARD, which is what stops a fast-and-empty proof from being
    // reported as a measurement. Asserted without the network: a witness one
    // element short of what the matrices declare must be refused.
    #[test]
    fn a_witness_the_matrices_do_not_size_is_refused() {
        let matrices = NPIndex::<Fr> {
            num_instance_variables: 2,
            num_witness_variables: 3,
            num_constraints: 4,
            a_num_non_zero: 0,
            b_num_non_zero: 0,
            c_num_non_zero: 0,
            a: Vec::new(),
            b: Vec::new(),
            c: Vec::new(),
        };
        let pk = ProvingKey::<Bn254>::deserialize_uncompressed_unchecked(Cursor::new(Vec::new()));
        assert!(pk.is_err(), "an empty proving key must not deserialize");
        // `prove` checks the witness length before it touches the key, which
        // is why this can be asserted without one.
        // `n_vars` = 2 + 3 - 1: see `expected_witness_len` for why the
        // declared pair is one more than a witness ever is.
        assert_eq!(expected_witness_len(&matrices), 4);
        assert!(witness_len_check(&matrices, 4).is_ok());
        let e = witness_len_check(&matrices, 3).expect_err("3 is one short of n_vars");
        assert!(e.contains("witness is 3 field elements"), "got {e}");
        // And one element too MANY is refused as well -- it would mean the
        // matrices and the wasm came from different circuits.
        assert!(witness_len_check(&matrices, 5).is_err());
    }

    // THE WHOLE THING, over the real artifacts. `#[ignore]` because it needs
    // the network and ~3.5 MB of download, not because it is optional: it is
    // the only test that proves the proving key, the matrices and the witness
    // agree on one circuit. Run it before trusting a device number:
    //
    //   cargo test --no-default-features -- --ignored --nocapture
    #[test]
    #[ignore = "needs the network (~3.5 MB of artifacts); run with --ignored"]
    fn the_real_circuit_proves_on_this_host() {
        let out = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(run(DEFAULT_CIRCUIT));
        report(&out);
        assert!(out.ok(), "{out:?}");
        // A transact witness is tens of thousands of field elements, and the
        // matrices must agree with it -- `prove` refuses otherwise, so this is
        // the assertion that the two artifacts belong to one circuit.
        assert_eq!(
            out.witness_len,
            Some(out.num_instance_variables.unwrap() + out.num_witness_variables.unwrap() - 1)
        );
        assert!(out.leg("prove").and_then(|l| l.ms).is_some(), "no proof was timed");
        // Placeholder inputs cannot satisfy the constraints, so a proof that
        // VERIFIED would mean the verifier was not run over this circuit.
        assert_eq!(out.verified, Some(false));
    }
}
