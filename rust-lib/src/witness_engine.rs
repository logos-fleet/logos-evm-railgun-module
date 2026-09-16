//! Can the witness generator RUN here?
//!
//! Every RAILGUN proof this module produces starts with a witness, and the
//! witness comes out of the circuit's `.wasm` executed under `wasmer`
//! (`ark_circom::WitnessCalculator`, driven by the engine's
//! `railgun::circuit::witness::calculate_witness`). The only `wasmer` backend
//! in this crate's dependency graph is **cranelift**, a JIT: it maps a page
//! writable, emits aarch64 machine code into it, remaps it executable and
//! jumps in.
//!
//! THAT LAST STEP IS A PLATFORM PERMISSION, not a property of this code. iOS
//! refuses `PROT_EXEC` on a page an app has written to unless the app holds the
//! `dynamic-codesigning` entitlement, which no third-party app gets. So a
//! module that links, loads and answers metadata perfectly can still die on its
//! first proof — and nothing in a desktop test, or in a simulator (whose pages
//! are macOS pages, where RWX is allowed), can tell you which.
//!
//! [`probe`] is that question asked directly, on whatever device is running it.
//! It is the SAME four steps `calculate_witness` takes, in the same order, over
//! a wasm module small enough to carry inside this crate:
//!
//! 1. `engine`      — build the backend (`Store::default()`, i.e. cranelift).
//! 2. `compile`     — `Module::new`, which emits native code and publishes it
//!                    to executable memory. This is where an `mprotect` denial
//!                    surfaces as a `CompileError`.
//! 3. `instantiate` — `Instance::new`, which wires memory and imports.
//! 4. `call`        — enter the emitted code and come back with its answer.
//!                    Only reaching THIS proves the JIT ran.
//!
//! The reply names the last stage reached, so a failure says where it stopped
//! rather than only that it stopped. A hard denial the kernel turns into a
//! `SIGKILL` cannot be reported from in here at all — the process is gone
//! before the reply is built — so each stage is ALSO announced on stderr
//! before it is entered ([`entering`]). The last line printed is then the
//! stage the silence began in, which is the only thing a device console can
//! still tell you once the process has been killed.
//!
//! AND THE WAY OUT IS MEASURED IN THE SAME BREATH. Wasmer 6 carries backends
//! that are not JITs, and `wasmi` is one of them: a pure-Rust interpreter that
//! never emits a byte of machine code and so has nothing for a platform to
//! refuse. It is compiled into this image beside cranelift ([`Backend`]) and
//! probed in the same call — because the useful answer to "the JIT is refused
//! here" is "and this is what works instead", measured on the same device in
//! the same process rather than hoped for in a follow-up.
//!
//! EXCEPT WHERE IT IS NOT IN THE IMAGE AT ALL (#202). `wasmi` is asked for only
//! under `cfg(not(any(target_os = "android", target_abi = "sim")))`, because
//! wasmer's build script generates its C-API bindings with bindgen and a Logos
//! cross build configures bindgen for neither the Android NDK sysroot nor the
//! `-sim` triple — see the note on that section in `rust-lib/Cargo.toml` for
//! both diagnostics and the conditions for widening it back.
//!
//! It costs this probe nothing it was asked for. The interpreter answers "the
//! JIT is refused here, and this is what works instead", which is a question
//! about a PHYSICAL iOS device — where it is still compiled in, and where #188
//! measured. Android executes emitted code freely (measured: `call` reached
//! under cranelift on a handset), and a simulator's pages are macOS pages where
//! RWX is allowed, so neither has the question. There [`PROBE_ORDER`] is simply
//! the engine's own backend on its own; every consumer reads the order rather
//! than assuming a length, so such a reply carries no `alternatives` instead of
//! carrying a wrong one.
//!
//! IT IS NOT THE BACKEND THE ENGINE USES, and this probe cannot make it one.
//! `railgun::circuit::witness::calculate_witness` builds its store with
//! `Store::default()`, which resolves to cranelift for as long as anything in
//! the graph asks wasmer for `sys-default` — `ark-circom` does, in a
//! third-party fork this repo consumes, and cargo unions features, so no line
//! in this crate's manifest can subtract it. Swapping the engine's backend is
//! a change to `ark-circom` (or a witness hook in `railgun`); what is settled
//! here is whether that change has a destination.
//!
//! ORDER IS LOAD-BEARING: the alternatives run BEFORE the default one. A
//! backend that gets the process killed takes every answer that would have
//! come after it, so the one under suspicion goes last.
//!
//! Deliberately NOT the RAILGUN circuit: the circuit's `.wasm` is fetched from
//! a remote artifact store and is megabytes, so a probe over it would measure
//! the network and the download cache as well. The permission under test is
//! per-process, not per-module: one JIT-emitted function that returns the right
//! number proves the same page transition every RAILGUN witness needs.

use wasmer::{imports, Instance, Module, Store};

/// The stages of [`probe`], in the order it takes them. `reached` is the last
/// one that completed — always at least [`ENGINE`](stage::ENGINE), since
/// building the store cannot fail politely.
pub mod stage {
    /// `Store::default()` returned: the backend exists.
    pub const ENGINE: &str = "engine";
    /// `Module::new` returned: native code was emitted AND published.
    pub const COMPILE: &str = "compile";
    /// `Instance::new` returned: memory and imports are wired.
    pub const INSTANTIATE: &str = "instantiate";
    /// The emitted code ran and answered. The JIT works on this device.
    pub const CALL: &str = "call";
}

/// The smallest wasm module that proves emitted code executed:
///
/// ```wat
/// (module
///   (func (export "add") (param i32 i32) (result i32)
///     local.get 0
///     local.get 1
///     i32.add))
/// ```
///
/// Written as BYTES rather than `wat` text so the probe depends on no optional
/// `wasmer` feature — `wat` is in `sys-default` today and the probe must not be
/// the thing that breaks if a backend swap (#188) changes that set.
const ADD_WASM: &[u8] = &[
    0x00, 0x61, 0x73, 0x6d, // magic  "\0asm"
    0x01, 0x00, 0x00, 0x00, // version 1
    // type section: one func type (i32, i32) -> i32
    0x01, 0x07, 0x01, 0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f,
    // function section: one function, of type 0
    0x03, 0x02, 0x01, 0x00,
    // export section: "add" -> func 0
    0x07, 0x07, 0x01, 0x03, 0x61, 0x64, 0x64, 0x00, 0x00,
    // code section: local.get 0; local.get 1; i32.add; end
    0x0a, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x20, 0x01, 0x6a, 0x0b,
];

/// The two operands [`probe`] feeds the emitted function, and what it must
/// answer. Not 0 and 0: a page that was never written to would answer 0 too.
const LHS: i32 = 40;
const RHS: i32 = 2;
/// `LHS + RHS`, and the only answer that proves the emitted `i32.add` ran.
pub const EXPECTED: i32 = 42;

/// A wasm backend compiled into this image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// Whatever `Store::default()` resolves to — and therefore the one the
    /// RAILGUN engine actually proves with, since `calculate_witness` builds
    /// its store exactly that way. Cranelift today.
    EngineDefault,
    /// wasmer's `wasmi` interpreter. Emits no machine code, so there is no
    /// page for a platform to refuse. Present here to be MEASURED, not used:
    /// see this module's docs for why the engine cannot be pointed at it from
    /// this crate.
    ///
    /// Absent on Android and on the iOS simulator, where the backend is not in
    /// the image (#202).
    #[cfg(not(any(target_os = "android", target_abi = "sim")))]
    Wasmi,
}

impl Backend {
    /// What the probe calls this backend. Distinct from [`Probe::backend`],
    /// which is what wasmer answers once the engine exists — `EngineDefault`
    /// is a request, `cranelift` is the answer to it.
    pub fn requested(self) -> &'static str {
        match self {
            Backend::EngineDefault => "engine-default",
            #[cfg(not(any(target_os = "android", target_abi = "sim")))]
            Backend::Wasmi => "wasmi",
        }
    }

    /// The store this backend builds. `pub(crate)` because
    /// [`crate::witness_circuit`] measures the SAME backends over the real
    /// circuit: one list of what is in the image, two questions asked of it.
    pub(crate) fn store(self) -> Store {
        match self {
            Backend::EngineDefault => Store::default(),
            #[cfg(not(any(target_os = "android", target_abi = "sim")))]
            Backend::Wasmi => Store::new(wasmer::wasmi::Wasmi::new()),
        }
    }
}

/// Every backend [`probe_all`] measures, in the order it measures them. The
/// engine's own is LAST: a backend the platform kills the process over ends
/// the run, and an answer that never arrives is worth less than one that does.
///
/// A slice rather than a fixed-size array because the set is not the same
/// everywhere: Android and the iOS simulator have no `wasmi` in their image
/// (#202), so there the order is one entry long and `probe_all` answers about
/// the engine's backend alone.
#[cfg(not(any(target_os = "android", target_abi = "sim")))]
pub const PROBE_ORDER: &[Backend] = &[Backend::Wasmi, Backend::EngineDefault];

/// Where `wasmi` is not compiled in: the engine's own backend, and nothing
/// beside it. See [`Backend::Wasmi`].
#[cfg(any(target_os = "android", target_abi = "sim"))]
pub const PROBE_ORDER: &[Backend] = &[Backend::EngineDefault];

/// What the probe found.
#[derive(Debug, Clone)]
pub struct Probe {
    /// Which backend was asked for — [`Backend::requested`].
    pub requested: &'static str,
    /// The wasmer engine's own id — names the compiler that was used
    /// (`cranelift`…), so a report says which backend was measured rather than
    /// which one the reader assumed. Empty if the engine could not be built.
    pub backend: String,
    /// The last [`stage`] that completed.
    pub reached: &'static str,
    /// What the emitted function answered, if it was reached.
    pub answer: Option<i32>,
    /// Why it stopped, if it stopped early.
    pub error: Option<String>,
}

impl Probe {
    /// The witness generator can run here: emitted code executed and was right.
    pub fn ok(&self) -> bool {
        self.reached == stage::CALL && self.answer == Some(EXPECTED)
    }
}

/// Announce a stage BEFORE entering it, on stderr.
///
/// Not logging for its own sake: the failure this probe exists to find need not
/// be one it can return. A platform that refuses the page transition may reject
/// it politely (an `Err`, which [`Probe`] reports) or may kill the process for
/// a code-signing violation — and a `SIGKILL` leaves no reply at all, only the
/// absence of one. These lines are what says WHICH stage the silence began in,
/// on a device console that is the only instrument there is.
fn entering(backend: Backend, what: &str) {
    eprintln!(
        "railgun_module: witness-engine probe [{}]: entering {what}",
        backend.requested()
    );
}

/// Measure every backend in [`PROBE_ORDER`]. Short of the process being killed,
/// this always returns one [`Probe`] per backend, in that order.
pub fn probe_all() -> Vec<Probe> {
    PROBE_ORDER.iter().map(|b| probe_backend(*b)).collect()
}

/// Measure the backend the RAILGUN engine itself proves with.
pub fn probe() -> Probe {
    probe_backend(Backend::EngineDefault)
}

/// Run the four stages on one backend. Never panics and never returns early
/// without saying where it got to.
///
/// The outcome is ALSO printed, for the reason [`entering`] gives in reverse:
/// this function's answer travels home inside one reply built after every
/// backend has run, so a backend that kills the process destroys the answers
/// of the ones before it too. Printed as it happens, an earlier backend's
/// result survives a later one's death — which is exactly the case this probe
/// exists for, the interpreter measured on a device that then kills the JIT.
pub fn probe_backend(which: Backend) -> Probe {
    let p = run(which);
    eprintln!(
        "railgun_module: witness-engine probe [{}]: {} (backend={} reached={} answer={:?} error={:?})",
        p.requested,
        if p.ok() { "RAN THE EMITTED CODE" } else { "DID NOT RUN" },
        p.backend,
        p.reached,
        p.answer,
        p.error
    );
    p
}

fn run(which: Backend) -> Probe {
    entering(which, stage::ENGINE);
    let mut store = which.store();
    let mut out = Probe {
        requested: which.requested(),
        backend: store.engine().deterministic_id(),
        reached: stage::ENGINE,
        answer: None,
        error: None,
    };

    // THE PAGE TRANSITION. `Module::new` compiles and publishes; on a platform
    // that refuses `PROT_EXEC` this is the first thing that can fail.
    entering(which, stage::COMPILE);
    let module = match Module::new(&store, ADD_WASM) {
        Ok(m) => m,
        Err(e) => {
            out.error = Some(format!("compile: {e}"));
            return out;
        }
    };
    out.reached = stage::COMPILE;

    entering(which, stage::INSTANTIATE);
    let instance = match Instance::new(&mut store, &module, &imports! {}) {
        Ok(i) => i,
        Err(e) => {
            out.error = Some(format!("instantiate: {e}"));
            return out;
        }
    };
    out.reached = stage::INSTANTIATE;

    let add = match instance
        .exports
        .get_typed_function::<(i32, i32), i32>(&store, "add")
    {
        Ok(f) => f,
        Err(e) => {
            out.error = Some(format!("export add: {e}"));
            return out;
        }
    };
    entering(which, stage::CALL);
    match add.call(&mut store, LHS, RHS) {
        Ok(v) => {
            out.reached = stage::CALL;
            out.answer = Some(v);
            if v != EXPECTED {
                out.error = Some(format!("emitted add answered {v}, expected {EXPECTED}"));
            }
        }
        Err(e) => out.error = Some(format!("call: {e}")),
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // A desktop (or simulator) is a platform where RWX is ALLOWED, so this is
    // the positive control: it pins the probe's own correctness — the embedded
    // wasm bytes, the export name, the arithmetic — so that a negative result
    // on a handset can only mean the platform refused.
    #[test]
    fn probe_runs_emitted_code_where_the_platform_allows_it() {
        let p = probe();
        assert!(
            p.ok(),
            "probe did not reach the emitted code: reached={} answer={:?} error={:?} backend={}",
            p.reached,
            p.answer,
            p.error,
            p.backend
        );
        assert_eq!(p.answer, Some(EXPECTED));
    }

    // The backend is REPORTED, not assumed. `Store::default()` resolves to
    // cranelift while `sys-default` is in the feature set (wasmer's
    // `BackendKind::default()`), which is what makes the JIT question the
    // question — and is exactly what a backend swap would change.
    #[test]
    fn probe_names_the_backend_it_measured() {
        let p = probe();
        assert!(!p.backend.is_empty(), "no backend id");
        assert!(
            p.backend.contains("cranelift"),
            "expected the cranelift JIT, got {:?} -- if this changed on purpose, \
             the JIT question in this module's docs changed with it",
            p.backend
        );
    }

    // THE WAY OUT IS REAL CODE, not a plan: the interpreter is in this image
    // and it runs the same wasm to the same answer. A device where the default
    // backend is killed and this one is not is the whole argument for the swap.
    //
    // This runs on a desktop, where `wasmi` is always compiled in — the cfg is
    // what keeps it compiling if these tests are ever built for a target where
    // it is not (#202).
    #[cfg(not(any(target_os = "android", target_abi = "sim")))]
    #[test]
    fn the_interpreter_backend_runs_the_same_wasm() {
        let p = probe_backend(Backend::Wasmi);
        assert_eq!(p.backend, "wasmi", "not the interpreter: {:?}", p.backend);
        assert!(
            p.ok(),
            "interpreter did not reach the code: reached={} answer={:?} error={:?}",
            p.reached,
            p.answer,
            p.error
        );
    }

    // The engine's own backend goes LAST. On a platform that kills the process
    // for executing emitted code, anything probed after it is never measured —
    // so the ordering is part of the contract, not an implementation detail.
    #[test]
    fn the_engines_own_backend_is_probed_last() {
        assert_eq!(*PROBE_ORDER.last().unwrap(), Backend::EngineDefault);
        assert!(!PROBE_ORDER.is_empty());
        let all = probe_all();
        assert_eq!(all.len(), PROBE_ORDER.len());
        assert_eq!(all.last().unwrap().requested, "engine-default");
        assert!(all.iter().all(|p| p.ok()), "on a desktop every backend runs: {all:?}");
    }
}
