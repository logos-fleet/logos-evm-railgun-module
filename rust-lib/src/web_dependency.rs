//! Can a NATIVE module reach a `web` dependency, on a handset?
//!
//! `keystore_module` reaches a phone as a `web` (wasm) variant: a page in the
//! Shell's container, not a library in this process and not a subprocess. This
//! module is native, Bare, cross-compiled and in-process, and it declares that
//! page as a dependency — so every signing path here crosses a seam that,
//! until this probe, had only ever been driven the OTHER way round (a page
//! calling a native module, logos-workspace#113/#129).
//!
//! The host's claim is that the direction does not matter
//! (`logos-liblogos/src/logos_core/web_module_glue.h`: "every existing consumer
//! — core_service, capability_module, another module, the CLI — reaches a Web
//! module exactly as it reaches a subprocess one"). ADR 0010 — a Bundled member
//! may depend on the image's web half — rests on that claim, and this module's
//! catalog membership rests on ADR 0010. [`probe`] is the claim asked directly,
//! on whatever device is running it.
//!
//! THREE LEGS, AND THE MIDDLE ONE IS WHY IT IS THREE:
//!
//! 1. `caller_identity` — crosses, and says WHO the page thinks is calling.
//! 2. `list_accounts`   — an ordinary contract read with a real reply, so the
//!                        seam is measured carrying data rather than a
//!                        one-field diagnostic.
//! 3. `caller_identity` — again. One crossing can be luck; a second one AFTER a
//!                        method with a body is what says the transport is
//!                        still usable, and that nothing is left parked on the
//!                        thread that has to deliver the next answer.
//!
//! WHAT EACH LEG CAN TELL YOU APART:
//!
//! * **It answered at all.** A `web` module's end of the transport is its page,
//!   which the container brings up asynchronously; a native caller that gets in
//!   before that fails outright rather than waiting
//!   (`WebModuleGlue::pageIsServing`). `ms` per leg is what separates "the page
//!   was not ready" from "the page is slow".
//! * **Who it thinks called.** A page cannot tell two callers apart by token —
//!   the container relays the module's own root credential — so the identity
//!   travels beside it as data. Before logos-workspace#129 a `web` module
//!   answered its OWN name to every caller, and every name-gated method on it
//!   then refused everybody. That defect was fixed and measured in the `web` →
//!   `web` direction; this is the native → `web` one, which has never been
//!   asked. [`Probe::identity_is_this_module`] is the whole of that question.
//! * **Whether it blocks.** A Bare module never dispatches on the thread the
//!   call arrived on — `BareModuleGlue` marshals every dispatch onto the glue's
//!   own worker — while a page answers on the host's Qt main thread. So the
//!   thread that waits here must NOT be the thread that has to deliver, and
//!   [`Probe::thread`] is what says which one it was. A `single` module that
//!   waited on the delivering thread is the deadlock shape uniswap_module hit
//!   on the `multi` side, and it would present as a leg that never returns.
//!
//! THE CALLS ARE UNTYPED, deliberately. The generated `modules().keystore_module`
//! client would be the idiomatic spelling, and it is *literally* this — a
//! LIDL-generated wrapper is `proxy.call_json(method, args)` and nothing else.
//! Going through the proxy directly costs nothing in fidelity and buys two
//! things a probe wants: it measures the TRANSPORT rather than this module's
//! generated copy of the dependency's contract, and it keeps asking the same
//! question against a pin of `keystore_module` whose LIDL predates
//! `caller_identity`. See `glue.rs` for the one adapter that implements it.
//!
//! Nothing here touches the RAILGUN engine, a chain, a key or a balance: the
//! seam under test is the module bus, so the probe is safe to call on a device
//! before `init` and leaves no state behind.

use std::time::Instant;

/// The module this probe expects a correctly-identified caller to be named as.
pub const THIS_MODULE: &str = "railgun_module";
/// The dependency it crosses to — the one that is a page on a phone.
pub const TARGET: &str = "keystore_module";

/// The dependency, as the probe needs it. Implemented over the module bus in
/// `glue.rs`; implemented over plain values in this module's tests.
pub trait Dependency {
    /// `{ ok, kind, identity, … }` — what the dependency currently sees as its
    /// caller. Ungated and side-effect-free on `keystore_module`.
    fn caller_identity(&mut self) -> Result<String, String>;
    /// `{ ok, accounts: [...] }` — an ordinary read, for a leg with a body.
    fn list_accounts(&mut self) -> Result<String, String>;
}

/// One outbound call, and what became of it.
#[derive(Debug, Clone)]
pub struct Leg {
    /// The method asked for.
    pub method: &'static str,
    /// Wall-clock milliseconds the call took, answered or not. The first leg
    /// carries the page's warm-up; a later one that is still slow is the page
    /// itself rather than the seam.
    pub ms: u128,
    /// What came back, verbatim.
    pub reply: Option<String>,
    /// Why nothing came back.
    pub error: Option<String>,
}

impl Leg {
    /// The call crossed and the dependency answered.
    pub fn ok(&self) -> bool {
        self.error.is_none()
    }
}

/// What the probe found.
#[derive(Debug, Clone)]
pub struct Probe {
    /// The dependency that was called.
    pub target: &'static str,
    /// The thread the probe — and therefore this module's dispatch — ran on.
    pub thread: String,
    /// Every leg, in the order they were made. Always [`LEGS`] long: a leg that
    /// fails does not end the probe, because "the first call failed" and "the
    /// transport is gone" are different findings.
    pub legs: Vec<Leg>,
    /// `kind` out of the LAST `caller_identity` that answered.
    pub saw_kind: Option<String>,
    /// `identity` out of the LAST `caller_identity` that answered. This is the
    /// name the page believes called it.
    pub saw_identity: Option<String>,
}

/// What [`probe`] calls, in order.
pub const LEGS: [&str; 3] = ["caller_identity", "list_accounts", "caller_identity"];

impl Probe {
    /// A native module can call a `web` module here, AND is correctly named as
    /// the caller. Both halves: a crossing that arrives under the wrong name
    /// admits nobody through a name-gated method, so it is not a pass.
    pub fn ok(&self) -> bool {
        self.legs.len() == LEGS.len()
            && self.legs.iter().all(Leg::ok)
            && self.identity_is_this_module()
    }

    /// The dependency named THIS module as its caller.
    pub fn identity_is_this_module(&self) -> bool {
        self.saw_identity.as_deref() == Some(THIS_MODULE)
    }
}

/// Announce a leg BEFORE it is made, on stderr.
///
/// The failure mode this probe is most exposed to cannot be returned: a wait on
/// the thread that must deliver the answer does not come back at all, and a
/// device console is then the only instrument there is. The last line printed
/// names the leg the silence began in. Same reason `witness_engine` announces
/// its stages, and the same shape.
fn entering(method: &str) {
    eprintln!("railgun_module: web-dependency probe [{TARGET}]: entering {method}");
}

/// `kind` and `identity` out of a `caller_identity` reply.
///
/// Tolerant of the reply being the document, or a JSON string CONTAINING the
/// document: `caller_identity` returns a `String` over the bus, and whether the
/// transport hands that back already unwrapped is a property of the transport
/// rather than of the answer. A probe that reported "no identity" for a
/// well-formed reply it merely failed to unwrap twice would be measuring itself.
fn identity_of(reply: &str) -> (Option<String>, Option<String>) {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(reply) else {
        return (None, None);
    };
    let value = match value.as_str() {
        Some(inner) => serde_json::from_str::<serde_json::Value>(inner).unwrap_or_default(),
        None => value,
    };
    let field = |k: &str| value.get(k).and_then(|v| v.as_str()).map(str::to_string);
    (field("kind"), field("identity"))
}

/// Cross to the dependency three times and report what happened, whatever
/// happened. Never panics; never returns early.
pub fn probe(dep: &mut impl Dependency) -> Probe {
    let mut out = Probe {
        target: TARGET,
        thread: thread_name(),
        legs: Vec::with_capacity(LEGS.len()),
        saw_kind: None,
        saw_identity: None,
    };

    for method in LEGS {
        entering(method);
        let started = Instant::now();
        let answer = match method {
            "list_accounts" => dep.list_accounts(),
            _ => dep.caller_identity(),
        };
        let ms = started.elapsed().as_millis();

        let leg = match answer {
            Ok(reply) => {
                if method == "caller_identity" {
                    let (kind, identity) = identity_of(&reply);
                    out.saw_kind = kind;
                    out.saw_identity = identity;
                }
                Leg { method, ms, reply: Some(reply), error: None }
            }
            Err(e) => Leg { method, ms, reply: None, error: Some(e) },
        };
        eprintln!(
            "railgun_module: web-dependency probe [{TARGET}]: {method} {} in {ms} ms ({})",
            if leg.ok() { "ANSWERED" } else { "FAILED" },
            leg.error.as_deref().or(leg.reply.as_deref()).unwrap_or("")
        );
        out.legs.push(leg);
    }

    eprintln!(
        "railgun_module: web-dependency probe [{TARGET}]: {} (thread={} caller-kind={:?} caller-identity={:?})",
        if out.ok() { "REACHED IT, CORRECTLY NAMED" } else { "DID NOT" },
        out.thread,
        out.saw_kind,
        out.saw_identity
    );
    out
}

/// The thread the probe is running on, named if it has a name and identified
/// if it has not. `BareModuleGlue` names its worker `logos-inproc-<module>`, so
/// a named answer here is itself the evidence that the dispatch left the
/// delivering thread.
fn thread_name() -> String {
    let t = std::thread::current();
    match t.name() {
        Some(name) => format!("{name} {:?}", t.id()),
        None => format!("{:?}", t.id()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A dependency that answers the way the `web` keystore does.
    struct Fake {
        identity: String,
        accounts: Result<String, String>,
        identity_answer: Option<Result<String, String>>,
        seen: Vec<&'static str>,
    }

    impl Fake {
        fn answering(identity: &str) -> Self {
            Self {
                identity: identity.to_string(),
                accounts: Ok(r#"{"ok":true,"accounts":[]}"#.to_string()),
                identity_answer: None,
                seen: Vec::new(),
            }
        }
    }

    impl Dependency for Fake {
        fn caller_identity(&mut self) -> Result<String, String> {
            self.seen.push("caller_identity");
            self.identity_answer.clone().unwrap_or_else(|| {
                Ok(format!(
                    r#"{{"ok":true,"kind":"module","identity":"{}"}}"#,
                    self.identity
                ))
            })
        }
        fn list_accounts(&mut self) -> Result<String, String> {
            self.seen.push("list_accounts");
            self.accounts.clone()
        }
    }

    // The finding the issue asks for: the call crossed, and the dependency
    // named THIS module rather than itself.
    #[test]
    fn a_dependency_that_answers_and_names_this_module_is_ok() {
        let mut dep = Fake::answering(THIS_MODULE);
        let p = probe(&mut dep);
        assert!(p.ok(), "{p:?}");
        assert_eq!(p.saw_kind.as_deref(), Some("module"));
        assert_eq!(p.saw_identity.as_deref(), Some(THIS_MODULE));
        assert!(p.legs.iter().all(Leg::ok), "{p:?}");
    }

    // Identity, an ordinary read, identity again — and in that order.
    #[test]
    fn the_probe_crosses_three_times_identity_read_identity() {
        let mut dep = Fake::answering(THIS_MODULE);
        let p = probe(&mut dep);
        assert_eq!(dep.seen, LEGS.to_vec());
        assert_eq!(p.legs.len(), LEGS.len());
        assert_eq!(p.target, TARGET);
    }

    // The defect this direction has never been checked for: the page answers
    // its OWN name for every caller (logos-workspace#129, in the `web` → `web`
    // direction). Every leg crossed, so a report can tell this apart from a
    // seam that does not work at all — but it is not a pass.
    #[test]
    fn a_dependency_that_names_itself_is_not_ok() {
        let mut dep = Fake::answering(TARGET);
        let p = probe(&mut dep);
        assert!(!p.ok(), "a self-named caller must not read as a pass");
        assert!(!p.identity_is_this_module());
        assert_eq!(p.saw_identity.as_deref(), Some(TARGET));
        assert!(p.legs.iter().all(Leg::ok), "{p:?}");
    }

    // A leg that fails is named, and the legs behind it are still made: "the
    // first call was refused" and "the transport is gone" are different
    // findings and a probe that stopped could not tell them apart.
    #[test]
    fn a_leg_that_fails_is_named_and_the_rest_still_run() {
        let mut dep = Fake::answering(THIS_MODULE);
        dep.accounts = Err("not authorized".to_string());
        let p = probe(&mut dep);
        assert!(!p.ok());
        assert_eq!(p.legs.len(), LEGS.len());
        assert!(p.legs[0].ok());
        assert!(!p.legs[1].ok());
        assert_eq!(p.legs[1].error.as_deref(), Some("not authorized"));
        assert_eq!(p.legs[1].method, "list_accounts");
        assert!(p.legs[2].ok(), "a failed leg must not end the probe");
    }

    // The blocking question is a thread question, so the thread is reported.
    #[test]
    fn the_probe_names_the_thread_it_ran_on() {
        let mut dep = Fake::answering(THIS_MODULE);
        let p = probe(&mut dep);
        assert!(!p.thread.is_empty(), "no thread recorded");
    }

    // `caller_identity` answers a String over the bus, and a transport may hand
    // that back as the document or as a JSON string containing it. Both are the
    // same finding.
    #[test]
    fn a_double_encoded_identity_reply_is_still_read() {
        let mut dep = Fake::answering(THIS_MODULE);
        dep.identity_answer = Some(Ok(serde_json::to_string(
            &format!(r#"{{"ok":true,"kind":"module","identity":"{THIS_MODULE}"}}"#),
        )
        .unwrap()));
        let p = probe(&mut dep);
        assert_eq!(p.saw_identity.as_deref(), Some(THIS_MODULE));
        assert!(p.ok(), "{p:?}");
    }

    // A reply that is not the document the probe expects leaves the identity
    // unknown rather than inventing one — and unknown is not a pass.
    #[test]
    fn an_unreadable_identity_reply_is_not_a_pass() {
        let mut dep = Fake::answering(THIS_MODULE);
        dep.identity_answer = Some(Ok("not json at all".to_string()));
        let p = probe(&mut dep);
        assert_eq!(p.saw_identity, None);
        assert_eq!(p.saw_kind, None);
        assert!(!p.ok());
        assert_eq!(p.legs.len(), LEGS.len());
        assert!(p.legs.iter().all(Leg::ok), "the legs still crossed: {p:?}");
    }
}
